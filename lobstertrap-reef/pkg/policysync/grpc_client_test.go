package policysync_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/test/bufconn"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync"
	policybuspb "github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/policysync/proto"
)

// fakeBusServer is a minimal in-process PolicyBus server we can drive
// deterministically from tests. It pushes preconfigured bundles + records
// the acks the client sends back.
type fakeBusServer struct {
	policybuspb.UnimplementedPolicyBusServer

	mu              sync.Mutex
	queuedBundles   []*policybuspb.SignedBundle
	streamOpened    chan struct{}
	streamClosed    chan struct{}
	receivedAcks    []*policybuspb.AckRequest
	dropAfterCount  atomic.Int32 // drop the stream after N bundles
	bundlesSent     atomic.Int32
	subscribeCalls  atomic.Int32
}

func newFakeBusServer() *fakeBusServer {
	return &fakeBusServer{
		streamOpened: make(chan struct{}, 8),
		streamClosed: make(chan struct{}, 8),
	}
}

func (s *fakeBusServer) queue(bundle *policybuspb.SignedBundle) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.queuedBundles = append(s.queuedBundles, bundle)
}

func (s *fakeBusServer) Subscribe(req *policybuspb.SubscribeRequest, stream policybuspb.PolicyBus_SubscribeServer) error {
	s.subscribeCalls.Add(1)
	select {
	case s.streamOpened <- struct{}{}:
	default:
	}
	defer func() {
		select {
		case s.streamClosed <- struct{}{}:
		default:
		}
	}()

	// Send all currently-queued bundles.
	s.mu.Lock()
	pending := make([]*policybuspb.SignedBundle, len(s.queuedBundles))
	copy(pending, s.queuedBundles)
	// Reset queued bundles after one drain so a second Subscribe (after a
	// drop) doesn't re-deliver.
	s.queuedBundles = nil
	s.mu.Unlock()

	for _, b := range pending {
		if err := stream.Send(b); err != nil {
			return err
		}
		sent := s.bundlesSent.Add(1)
		// Optionally drop the stream after N bundles to exercise reconnect.
		if drop := s.dropAfterCount.Load(); drop > 0 && sent >= drop {
			return fmt.Errorf("simulated stream drop after %d bundles", sent)
		}
	}

	// Block on context cancel so the stream stays open for client-driven
	// teardown.
	<-stream.Context().Done()
	return nil
}

func (s *fakeBusServer) Ack(ctx context.Context, req *policybuspb.AckRequest) (*policybuspb.AckResponse, error) {
	s.mu.Lock()
	s.receivedAcks = append(s.receivedAcks, req)
	s.mu.Unlock()
	return &policybuspb.AckResponse{AuditId: "audit-test-ack"}, nil
}

func (s *fakeBusServer) Publish(ctx context.Context, req *policybuspb.PublishRequest) (*policybuspb.PublishResponse, error) {
	return &policybuspb.PublishResponse{BundleId: req.Bundle.BundleId}, nil
}

func (s *fakeBusServer) Healthz(ctx context.Context, req *policybuspb.HealthzRequest) (*policybuspb.HealthzResponse, error) {
	return &policybuspb.HealthzResponse{Status: "ok"}, nil
}

func (s *fakeBusServer) acks() []*policybuspb.AckRequest {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*policybuspb.AckRequest, len(s.receivedAcks))
	copy(out, s.receivedAcks)
	return out
}

// bufconnHarness boots the fake bus in-process on a bufconn listener and
// returns the dialer the client should use + a teardown.
type bufconnHarness struct {
	server *grpc.Server
	bus    *fakeBusServer
	lis    *bufconn.Listener
}

func startBufconnBus(t *testing.T) *bufconnHarness {
	t.Helper()
	lis := bufconn.Listen(1 << 20)
	gs := grpc.NewServer()
	bus := newFakeBusServer()
	policybuspb.RegisterPolicyBusServer(gs, bus)
	go func() {
		_ = gs.Serve(lis)
	}()
	t.Cleanup(func() {
		gs.GracefulStop()
		_ = lis.Close()
	})
	return &bufconnHarness{server: gs, bus: bus, lis: lis}
}

func (h *bufconnHarness) dialer(ctx context.Context, _ string) (*grpc.ClientConn, error) {
	return grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return h.lis.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
}

// recordingApplier captures every bundle the client tries to apply + lets
// tests inject errors.
type recordingApplier struct {
	mu          sync.Mutex
	applied     []appliedBundle
	failNext    bool
	failNextErr error
}

type appliedBundle struct {
	BundleID string
	Version  string
	YAML     []byte
}

func (a *recordingApplier) Apply(_ context.Context, bid, version string, yaml []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.failNext {
		a.failNext = false
		return a.failNextErr
	}
	a.applied = append(a.applied, appliedBundle{
		BundleID: bid,
		Version:  version,
		YAML:     append([]byte(nil), yaml...),
	})
	return nil
}

func (a *recordingApplier) Snapshot() []appliedBundle {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]appliedBundle, len(a.applied))
	copy(out, a.applied)
	return out
}

// testVerifier wraps an ed25519 keypair so we can sign bundles in tests.
type testVerifier struct {
	priv    ed25519.PrivateKey
	wrapped policysync.Verifier
}

func newTestVerifier(t *testing.T) *testVerifier {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	v, err := policysync.NewCosignVerifierWithKeys(pub)
	if err != nil {
		t.Fatalf("new verifier: %v", err)
	}
	return &testVerifier{priv: priv, wrapped: v}
}

func (v *testVerifier) VerifyBundle(bundle, sig []byte) error {
	return v.wrapped.VerifyBundle(bundle, sig)
}

func (v *testVerifier) signBundle(yaml []byte) []byte {
	hash := sha256.Sum256(yaml)
	sig := ed25519.Sign(v.priv, hash[:])
	out := make([]byte, base64.StdEncoding.EncodedLen(len(sig)))
	base64.StdEncoding.Encode(out, sig)
	return out
}

func defaultIdentity() policysync.NodeIdentity {
	return policysync.NodeIdentity{
		FleetID:     "prod-fleet",
		RegionID:    "us-east",
		SiteID:      "site-01",
		NodeID:      "node-01-01",
		SVIDSubject: "spiffe://reef/prod-fleet/us-east/site-01/node-01-01",
	}
}

// waitFor polls cond until true or timeout.
func waitFor(t *testing.T, timeout time.Duration, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("waitFor: condition never satisfied within %s", timeout)
}

// ---- Tests --------------------------------------------------------------

func TestClient_RejectsNilVerifier(t *testing.T) {
	_, err := policysync.NewClient(policysync.Config{
		Endpoint: "localhost:50051",
		Identity: defaultIdentity(),
		Applier:  policysync.PolicyApplierFunc(func(context.Context, string, string, []byte) error { return nil }),
	})
	if err == nil {
		t.Fatal("expected error when verifier is nil")
	}
}

func TestClient_RejectsIncompleteIdentity(t *testing.T) {
	tv := newTestVerifier(t)
	_, err := policysync.NewClient(policysync.Config{
		Endpoint: "localhost:50051",
		Identity: policysync.NodeIdentity{
			FleetID: "prod-fleet",
			// region/site/node missing
		},
		Verifier: tv,
		Applier:  policysync.PolicyApplierFunc(func(context.Context, string, string, []byte) error { return nil }),
	})
	if err == nil {
		t.Fatal("expected error when identity is incomplete")
	}
}

func TestClient_SignedBundleAppliedAndAcked(t *testing.T) {
	h := startBufconnBus(t)
	tv := newTestVerifier(t)
	applier := &recordingApplier{}

	yaml := []byte("version: '1.0'\npolicy_name: 'test'\n")
	sig := tv.signBundle(yaml)
	h.bus.queue(&policybuspb.SignedBundle{
		BundleId:        "b1",
		Version:         "v1",
		ScopeFleetId:    "prod-fleet",
		BundleYaml:      yaml,
		Signature:       sig,
		SignerKeyId:     "test-signer",
		PublishedAtUnix: time.Now().Unix(),
	})

	c, err := policysync.NewClient(policysync.Config{
		Endpoint:       "bufnet",
		Identity:       defaultIdentity(),
		Verifier:       tv,
		Applier:        applier,
		Dialer:         h.dialer,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		_ = c.Run(ctx)
		close(done)
	}()

	waitFor(t, 3*time.Second, func() bool {
		return len(applier.Snapshot()) == 1
	})
	snap := applier.Snapshot()
	if snap[0].BundleID != "b1" || snap[0].Version != "v1" {
		t.Fatalf("unexpected applied bundle: %+v", snap[0])
	}

	waitFor(t, 3*time.Second, func() bool {
		return len(h.bus.acks()) >= 1
	})
	acks := h.bus.acks()
	if acks[0].AckStatus != "applied" {
		t.Fatalf("ack status = %q, want applied", acks[0].AckStatus)
	}
	if acks[0].BundleId != "b1" {
		t.Fatalf("ack bundle_id = %q, want b1", acks[0].BundleId)
	}
	if c.CurrentVersion() != "v1" {
		t.Fatalf("CurrentVersion = %q, want v1", c.CurrentVersion())
	}
	stats := c.Stats()
	if stats.BundlesApplied != 1 {
		t.Fatalf("Stats.BundlesApplied = %d, want 1", stats.BundlesApplied)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("client did not exit on cancel")
	}
}

func TestClient_TamperedBundleAckedVerifyFailed(t *testing.T) {
	h := startBufconnBus(t)
	tv := newTestVerifier(t)
	applier := &recordingApplier{}

	yaml := []byte("version: '1.0'\n")
	sig := tv.signBundle(yaml)
	// Publish with TAMPERED body — the signature won't verify against the
	// modified bytes.
	h.bus.queue(&policybuspb.SignedBundle{
		BundleId:        "b1",
		Version:         "v1",
		BundleYaml:      []byte("TAMPERED PAYLOAD"),
		Signature:       sig,
		SignerKeyId:     "test-signer",
		PublishedAtUnix: time.Now().Unix(),
	})

	c, err := policysync.NewClient(policysync.Config{
		Endpoint:       "bufnet",
		Identity:       defaultIdentity(),
		Verifier:       tv,
		Applier:        applier,
		Dialer:         h.dialer,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		_ = c.Run(ctx)
	}()

	waitFor(t, 3*time.Second, func() bool {
		return len(h.bus.acks()) >= 1
	})
	acks := h.bus.acks()
	if acks[0].AckStatus != "verify_failed" {
		t.Fatalf("ack status = %q, want verify_failed", acks[0].AckStatus)
	}
	if len(applier.Snapshot()) != 0 {
		t.Fatalf("applier was called with tampered bundle: %+v", applier.Snapshot())
	}
	if c.CurrentVersion() != "" {
		t.Fatalf("CurrentVersion was bumped despite verify failure: %q", c.CurrentVersion())
	}
	if c.Stats().BundlesRejected != 1 {
		t.Fatalf("Stats.BundlesRejected = %d, want 1", c.Stats().BundlesRejected)
	}
}

func TestClient_ApplyErrorAckedPolicyParseFailed(t *testing.T) {
	h := startBufconnBus(t)
	tv := newTestVerifier(t)
	applier := &recordingApplier{
		failNext:    true,
		failNextErr: errors.New("policy parse: yaml syntax error at line 12"),
	}

	yaml := []byte("invalid: -yaml-\n  not real\n")
	sig := tv.signBundle(yaml)
	h.bus.queue(&policybuspb.SignedBundle{
		BundleId:        "b1",
		Version:         "v1",
		BundleYaml:      yaml,
		Signature:       sig,
		SignerKeyId:     "test-signer",
		PublishedAtUnix: time.Now().Unix(),
	})

	c, err := policysync.NewClient(policysync.Config{
		Endpoint:       "bufnet",
		Identity:       defaultIdentity(),
		Verifier:       tv,
		Applier:        applier,
		Dialer:         h.dialer,
		InitialBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	waitFor(t, 3*time.Second, func() bool {
		return len(h.bus.acks()) >= 1
	})
	acks := h.bus.acks()
	if acks[0].AckStatus != "policy_parse_failed" {
		t.Fatalf("ack status = %q, want policy_parse_failed", acks[0].AckStatus)
	}
	if c.CurrentVersion() != "" {
		t.Fatalf("CurrentVersion bumped despite apply failure: %q", c.CurrentVersion())
	}
	if c.Stats().BundlesRejected != 1 {
		t.Fatalf("Stats.BundlesRejected = %d, want 1", c.Stats().BundlesRejected)
	}
}

func TestClient_ReconnectsAfterStreamDrop(t *testing.T) {
	h := startBufconnBus(t)
	tv := newTestVerifier(t)
	applier := &recordingApplier{}

	// Queue one bundle and configure the fake bus to drop the stream after
	// sending exactly one bundle. The client should reconnect and the
	// subscribeCalls counter should reach 2.
	yaml := []byte("version: '1.0'\n")
	sig := tv.signBundle(yaml)
	h.bus.queue(&policybuspb.SignedBundle{
		BundleId:        "b1",
		Version:         "v1",
		BundleYaml:      yaml,
		Signature:       sig,
		SignerKeyId:     "test-signer",
		PublishedAtUnix: time.Now().Unix(),
	})
	h.bus.dropAfterCount.Store(1)

	c, err := policysync.NewClient(policysync.Config{
		Endpoint:       "bufnet",
		Identity:       defaultIdentity(),
		Verifier:       tv,
		Applier:        applier,
		Dialer:         h.dialer,
		InitialBackoff: 50 * time.Millisecond,
		MaxBackoff:     200 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	waitFor(t, 5*time.Second, func() bool {
		return h.bus.subscribeCalls.Load() >= 2
	})
	if c.Stats().StreamRestarts == 0 {
		t.Fatalf("expected StreamRestarts > 0, got %d", c.Stats().StreamRestarts)
	}
}

func TestClient_HeartbeatsIgnored(t *testing.T) {
	h := startBufconnBus(t)
	tv := newTestVerifier(t)
	applier := &recordingApplier{}

	// Pure heartbeat frame — no body, no signature.
	h.bus.queue(&policybuspb.SignedBundle{
		BundleId:    "heartbeat",
		IsHeartbeat: true,
	})

	c, err := policysync.NewClient(policysync.Config{
		Endpoint:       "bufnet",
		Identity:       defaultIdentity(),
		Verifier:       tv,
		Applier:        applier,
		Dialer:         h.dialer,
		InitialBackoff: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = c.Run(ctx) }()

	time.Sleep(300 * time.Millisecond)

	if got := c.Stats().BundlesReceived; got != 0 {
		t.Fatalf("heartbeat bumped BundlesReceived: got=%d", got)
	}
	if len(applier.Snapshot()) != 0 {
		t.Fatalf("heartbeat reached applier: %+v", applier.Snapshot())
	}
	if len(h.bus.acks()) != 0 {
		t.Fatalf("heartbeat was acked: %+v", h.bus.acks())
	}
}
