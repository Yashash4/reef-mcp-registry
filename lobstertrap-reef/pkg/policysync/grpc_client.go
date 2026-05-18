// Package policysync — gRPC client for the TerraFabric-shaped Reef Policy Bus.
//
// The client is the literal missing wire between Lobster Trap edge nodes and
// the Veea TerraFabric control plane. It opens a long-lived Subscribe stream
// at startup, verifies each pushed SignedBundle via the cosign-style verifier
// (`pkg/policysync/cosign.go` — A-6 deliverable), and acks the outcome.
//
// Fail-closed contract:
//
//   - Stream drop  → exponential-backoff reconnect (capped at 30s). The node
//     keeps its currently-active policy on disk; nothing degrades.
//   - Bad signature → ack "verify_failed", keep old policy active. The bus
//     records the rejection in its audit log so operators can investigate.
//   - Apply error  → ack "policy_parse_failed" or "kept_old_active", keep
//     old policy active.
//
// Scope filter: the bus already filters bundles by scope before pushing. We
// do not re-filter locally — the bus is the authority on hierarchy.
//
// The applier interface (PolicyApplier) is the seam cmd/serve.go uses to wire
// the actual hot-reload path. v1 ships a no-op applier for the integration
// tests + a real applier for production.
package policysync

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
	policybuspb "github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync/proto"
)

// AckStatus enumerates the apply outcomes we ack back to the bus. Stable
// strings so audit consumers can grep on them.
type AckStatus string

const (
	AckApplied            AckStatus = "applied"
	AckVerifyFailed       AckStatus = "verify_failed"
	AckPolicyParseFailed  AckStatus = "policy_parse_failed"
	AckKeptOldActive      AckStatus = "kept_old_active"
	AckScopeMismatch      AckStatus = "scope_mismatch"
)

// PolicyApplier is the seam the gRPC client uses to hand a verified bundle
// to the hot-reload path. Returning an error tells the client to ack
// "policy_parse_failed" + keep the previous policy active.
type PolicyApplier interface {
	Apply(ctx context.Context, bundleID, version string, bundleYAML []byte) error
}

// PolicyApplierFunc adapts a function value to PolicyApplier.
type PolicyApplierFunc func(ctx context.Context, bundleID, version string, bundleYAML []byte) error

// Apply implements PolicyApplier.
func (f PolicyApplierFunc) Apply(ctx context.Context, bundleID, version string, bundleYAML []byte) error {
	return f(ctx, bundleID, version, bundleYAML)
}

// Logger is the structured logger contract the client emits into. Compatible
// with zerolog adapters; cmd/serve.go wires a zerolog adapter at construction.
type Logger interface {
	Info(msg string, kv ...any)
	Warn(msg string, kv ...any)
	Error(msg string, err error, kv ...any)
}

// nopLogger discards everything. Default when no logger is supplied.
type nopLogger struct{}

func (nopLogger) Info(string, ...any)         {}
func (nopLogger) Warn(string, ...any)         {}
func (nopLogger) Error(string, error, ...any) {}

// NodeIdentity addresses a Lobster Trap node in the TerraFabric hierarchy.
// Read from REEF_FLEET_ID / REEF_REGION_ID / REEF_SITE_ID / REEF_NODE_ID env.
type NodeIdentity struct {
	FleetID     string
	RegionID    string
	SiteID      string
	NodeID      string
	SVIDSubject string
}

func (n NodeIdentity) toPB() *policybuspb.NodeIdentity {
	return &policybuspb.NodeIdentity{
		FleetId:     n.FleetID,
		RegionId:    n.RegionID,
		SiteId:      n.SiteID,
		NodeId:      n.NodeID,
		SvidSubject: n.SVIDSubject,
	}
}

// Config configures the gRPC policy-bus client.
type Config struct {
	// Endpoint is the bus's gRPC host:port. Defaults to "localhost:50051" if
	// empty. Set from REEF_POLICY_BUS_GRPC_URL by cmd/serve.go.
	Endpoint string

	// Identity is who this client claims to be on Subscribe.
	Identity NodeIdentity

	// Verifier verifies the detached signature on each pushed bundle. Must
	// be non-nil — fail-closed: a nil verifier rejects everything.
	Verifier Verifier

	// Applier is called after a successful signature verify. Errors from
	// Apply degrade to AckPolicyParseFailed with the previous policy
	// remaining active.
	Applier PolicyApplier

	// Logger receives structured events. Nil falls back to a no-op.
	Logger Logger

	// InitialBackoff is the first reconnect delay after a stream drop.
	// Default 500ms.
	InitialBackoff time.Duration
	// MaxBackoff caps the exponential reconnect delay. Default 30s.
	MaxBackoff time.Duration

	// Dialer overrides the default insecure gRPC dial. Tests inject a
	// bufconn-backed dialer here.
	Dialer func(ctx context.Context, endpoint string) (*grpc.ClientConn, error)
}

// Client subscribes to the Reef Policy Bus and reloads policy on each
// verified bundle.
type Client struct {
	cfg     Config
	mu      sync.Mutex
	conn    *grpc.ClientConn

	// stats
	bundlesReceived atomic.Uint64
	bundlesApplied  atomic.Uint64
	bundlesRejected atomic.Uint64
	streamRestarts  atomic.Uint64

	// currentVersion is the version we ack'd as applied — the bus uses this
	// to skip re-sending. We never roll back, so a verify_failed leaves it
	// untouched.
	currentVersion atomic.Value // string
}

// NewClient validates the config and constructs a Client. Returns
// ErrNoTrustRoot when no verifier is supplied.
func NewClient(cfg Config) (*Client, error) {
	if cfg.Verifier == nil {
		return nil, fmt.Errorf("policysync: %w (verifier required)", ErrNoTrustRoot)
	}
	if cfg.Applier == nil {
		return nil, fmt.Errorf("policysync: PolicyApplier required")
	}
	if cfg.Identity.FleetID == "" || cfg.Identity.RegionID == "" ||
		cfg.Identity.SiteID == "" || cfg.Identity.NodeID == "" {
		return nil, fmt.Errorf(
			"policysync: NodeIdentity must have non-empty fleet/region/site/node",
		)
	}
	if cfg.Endpoint == "" {
		cfg.Endpoint = defaults.DefaultPolicyBusGRPCURL
	}
	if cfg.Logger == nil {
		cfg.Logger = nopLogger{}
	}
	if cfg.InitialBackoff <= 0 {
		cfg.InitialBackoff = defaults.PolicyBusReconnectMin
	}
	if cfg.MaxBackoff <= 0 {
		cfg.MaxBackoff = defaults.PolicyBusReconnectMax
	}
	c := &Client{cfg: cfg}
	c.currentVersion.Store("")
	return c, nil
}

// CurrentVersion returns the policy version the client has acked as applied.
// Used by tests + cmd/serve.go's status surface.
func (c *Client) CurrentVersion() string {
	if v, ok := c.currentVersion.Load().(string); ok {
		return v
	}
	return ""
}

// Stats returns a snapshot of the client's counters for tests + observability.
func (c *Client) Stats() Stats {
	return Stats{
		BundlesReceived: c.bundlesReceived.Load(),
		BundlesApplied:  c.bundlesApplied.Load(),
		BundlesRejected: c.bundlesRejected.Load(),
		StreamRestarts:  c.streamRestarts.Load(),
	}
}

// Stats is a snapshot of client-side counters.
type Stats struct {
	BundlesReceived uint64
	BundlesApplied  uint64
	BundlesRejected uint64
	StreamRestarts  uint64
}

// dial returns a gRPC connection using the configured dialer (or the default
// insecure dialer). Called once per reconnect attempt.
func (c *Client) dial(ctx context.Context) (*grpc.ClientConn, error) {
	if c.cfg.Dialer != nil {
		return c.cfg.Dialer(ctx, c.cfg.Endpoint)
	}
	return grpc.NewClient(
		c.cfg.Endpoint,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// Run opens the Subscribe stream and runs the verify+apply+ack loop until ctx
// is cancelled. On stream drop, Run reconnects with exponential backoff (up
// to MaxBackoff) until ctx is done.
//
// Run is the long-lived entrypoint cmd/serve.go calls in a background
// goroutine when --enable-reef is on.
func (c *Client) Run(ctx context.Context) error {
	backoff := c.cfg.InitialBackoff
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		err := c.runOnce(ctx)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if err != nil {
			// EOF on a server-streaming call is a clean stream close. We
			// reconnect on EOF too — the bus may have been restarted.
			if errors.Is(err, io.EOF) {
				c.cfg.Logger.Info(
					"policysync: subscribe stream closed by server, reconnecting",
					"backoff_ms", backoff.Milliseconds(),
				)
			} else if grpcCode(err) == codes.Unavailable {
				c.cfg.Logger.Warn(
					"policysync: bus unavailable, reconnecting",
					"endpoint", c.cfg.Endpoint,
					"backoff_ms", backoff.Milliseconds(),
				)
			} else {
				c.cfg.Logger.Warn(
					"policysync: subscribe stream errored, reconnecting",
					"err", err.Error(),
					"backoff_ms", backoff.Milliseconds(),
				)
			}
		}
		c.streamRestarts.Add(1)
		// Sleep with cancellation.
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return ctx.Err()
		}
		// Exponential backoff with cap.
		backoff *= 2
		if backoff > c.cfg.MaxBackoff {
			backoff = c.cfg.MaxBackoff
		}
	}
}

// runOnce dials, opens the stream, and pumps messages until either the stream
// closes or ctx is cancelled. Returns the terminating error.
func (c *Client) runOnce(ctx context.Context) error {
	conn, err := c.dial(ctx)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	c.mu.Lock()
	c.conn = conn
	c.mu.Unlock()
	defer func() {
		c.mu.Lock()
		_ = conn.Close()
		c.conn = nil
		c.mu.Unlock()
	}()

	client := policybuspb.NewPolicyBusClient(conn)
	subReq := &policybuspb.SubscribeRequest{
		Node:                  c.cfg.Identity.toPB(),
		CurrentPolicyVersion:  c.CurrentVersion(),
	}
	stream, err := client.Subscribe(ctx, subReq)
	if err != nil {
		return fmt.Errorf("subscribe: %w", err)
	}
	c.cfg.Logger.Info(
		"policysync: subscribed to bus",
		"endpoint", c.cfg.Endpoint,
		"fleet", c.cfg.Identity.FleetID,
		"region", c.cfg.Identity.RegionID,
		"site", c.cfg.Identity.SiteID,
		"node", c.cfg.Identity.NodeID,
		"current_version", c.CurrentVersion(),
	)

	for {
		bundle, err := stream.Recv()
		if err != nil {
			return err
		}
		if bundle.GetIsHeartbeat() {
			// Heartbeat: no action. Could update a "last_seen" gauge here
			// later.
			continue
		}
		c.bundlesReceived.Add(1)
		c.handleBundle(ctx, client, bundle)
	}
}

// handleBundle is the verify+apply+ack codepath for a single bundle. It does
// NOT return errors — every error path lands as an Ack with the appropriate
// status (the bus is the source of truth on the outcome).
func (c *Client) handleBundle(
	ctx context.Context,
	client policybuspb.PolicyBusClient,
	b *policybuspb.SignedBundle,
) {
	// 1) Verify the detached signature.
	if verr := c.cfg.Verifier.VerifyBundle(b.BundleYaml, b.Signature); verr != nil {
		c.bundlesRejected.Add(1)
		c.cfg.Logger.Warn(
			"policysync: bundle signature verify failed — keeping old policy active",
			"bundle_id", b.BundleId,
			"version", b.Version,
			"signer_key_id", b.SignerKeyId,
			"err", verr.Error(),
		)
		c.sendAck(ctx, client, b, AckVerifyFailed, verr.Error())
		return
	}

	// 2) Hand to the applier.
	applyErr := c.cfg.Applier.Apply(ctx, b.BundleId, b.Version, b.BundleYaml)
	if applyErr != nil {
		c.bundlesRejected.Add(1)
		c.cfg.Logger.Warn(
			"policysync: bundle apply failed — keeping old policy active",
			"bundle_id", b.BundleId,
			"version", b.Version,
			"err", applyErr.Error(),
		)
		c.sendAck(ctx, client, b, AckPolicyParseFailed, applyErr.Error())
		return
	}

	// 3) Success — bump current version + ack.
	c.bundlesApplied.Add(1)
	c.currentVersion.Store(b.Version)
	c.cfg.Logger.Info(
		"policysync: bundle applied",
		"bundle_id", b.BundleId,
		"version", b.Version,
		"signer_key_id", b.SignerKeyId,
	)
	c.sendAck(ctx, client, b, AckApplied, "")
}

// sendAck is a non-fatal helper — if the Ack RPC fails we log and move on;
// the bus will see the next applied version on the node's next Subscribe.
func (c *Client) sendAck(
	ctx context.Context,
	client policybuspb.PolicyBusClient,
	b *policybuspb.SignedBundle,
	status AckStatus,
	detail string,
) {
	ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := client.Ack(ackCtx, &policybuspb.AckRequest{
		Node:            c.cfg.Identity.toPB(),
		BundleId:        b.BundleId,
		AppliedVersion:  b.Version,
		AckStatus:       string(status),
		Detail:          detail,
	})
	if err != nil {
		c.cfg.Logger.Warn(
			"policysync: ack send failed",
			"bundle_id", b.BundleId,
			"status", string(status),
			"err", err.Error(),
		)
	}
}

// grpcCode unwraps an error to the gRPC status code or codes.Unknown.
func grpcCode(err error) codes.Code {
	if err == nil {
		return codes.OK
	}
	if s, ok := status.FromError(err); ok {
		return s.Code()
	}
	return codes.Unknown
}
