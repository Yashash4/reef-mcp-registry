// Package defaults centralises the magic numbers, default ports, and
// timeout constants that show up in three or more files across the Reef
// fork. Centralising them here keeps cmd/serve.go, internal/engine/actions/*,
// internal/pipeline/pipeline.go, pkg/mcpsupply/registry.go,
// pkg/policysync/grpc_client.go, pkg/session/ewma.go, and pkg/ratelimit/per_identity.go
// from drifting silently.
//
// Behaviour is preserved verbatim — every constant below matches the
// previously-inline literal it replaces. Operators who override a value via
// policy YAML or environment variable still get their override; these are
// only the fallbacks.
//
// Refinement R-B5 (Phase B Round 1 Batch B) introduced this package.
package defaults

import "time"

// Network + HTTP server defaults.
const (
	// DefaultListenAddr is the address the proxy listens on when no
	// --listen flag is supplied. Matches `cmd/serve.go` historical default.
	DefaultListenAddr = ":8080"

	// DefaultBackendURL is the default LLM backend. Matches the Ollama
	// out-of-the-box port and the historical --backend default.
	DefaultBackendURL = "http://localhost:11434"

	// DefaultMCPRegistryURL is the Atlas (MCP signature registry) URL when
	// REEF_MCP_REGISTRY_URL is unset. Matches docker-compose service name.
	DefaultMCPRegistryURL = "http://localhost:8080"

	// DefaultPolicyBusGRPCURL is the gRPC endpoint of the Reef policy bus.
	DefaultPolicyBusGRPCURL = "localhost:50051"

	// DefaultRedirectFallback is the redirect target when REEF_REDIRECT_TARGET
	// is unset. Phase 2 swaps this for a real Gemma sidecar.
	DefaultRedirectFallback = "http://localhost:8765/gemma-stub"
)

// Reef fleet identity defaults — used when the matching REEF_*_ID env var is
// unset.
const (
	DefaultFleetID  = "demo-fleet"
	DefaultRegionID = "demo-region"
	DefaultSiteID   = "demo-site"
	DefaultNodeID   = "node-1"
)

// HTTP server timeouts — Slowloris-resistant defaults applied to the public
// http.Server in cmd/serve.go (refinement R-B1).
const (
	// HTTPReadHeaderTimeout is the deadline for reading request headers off
	// the wire. Five seconds is well under any legitimate client's needs and
	// closes the Slowloris-style header-feed attack window.
	HTTPReadHeaderTimeout = 5 * time.Second

	// HTTPReadTimeout is the deadline for reading the request body.
	HTTPReadTimeout = 30 * time.Second

	// HTTPWriteTimeout is the deadline for writing the response to the wire.
	HTTPWriteTimeout = 30 * time.Second

	// HTTPIdleTimeout is the keep-alive idle deadline.
	HTTPIdleTimeout = 120 * time.Second
)

// Graceful shutdown.
const (
	// GracefulShutdownTimeout caps how long `srv.Shutdown` waits for in-flight
	// requests to drain before the listener is closed forcibly.
	GracefulShutdownTimeout = 10 * time.Second
)

// Notifications / human-review action defaults.
const (
	// HumanReviewWebhookTimeout caps the POST to the human-review webhook in
	// internal/engine/actions/human_review.go. Failure → DENY (fail-closed).
	HumanReviewWebhookTimeout = 1500 * time.Millisecond

	// HumanReviewRetryAfter is the Retry-After header value the proxy emits
	// when the action returns HUMAN_REVIEW.
	HumanReviewRetryAfter = 30 * time.Second
)

// Merkle audit log.
const (
	// MerkleSignedRootInterval is how often the merkle goroutine in
	// cmd/serve.go exports a signed root. Configurable via
	// policy.reef.audit.sign_root_interval_seconds.
	MerkleSignedRootInterval = 60 * time.Second

	// AuditBodyTruncationBytes is the maximum number of bytes from the
	// request/response body that contribute to the merkle leaf's body_hash.
	// Bodies larger than this are truncated and the leaf is marked with
	// body_truncated:true (refinement R-B6).
	AuditBodyTruncationBytes = 4096
)

// Policy bus reconnect backoff (used by pkg/policysync/grpc_client.go when
// policy.reef.policy_bus.retry_backoff_seconds is unset).
const (
	PolicyBusReconnectMin = 500 * time.Millisecond
	PolicyBusReconnectMax = 30 * time.Second
)

// MCP registry sidecar.
const (
	// MCPRegistryRequestTimeout is the default deadline for the Atlas /verify
	// HTTP call from pkg/mcpsupply/registry.go.
	MCPRegistryRequestTimeout = 1500 * time.Millisecond

	// MCPVerifyContextTimeout caps the context the pipeline uses for the
	// Atlas verify call (separate from the HTTP client's own timeout so a
	// caller-supplied ctx.Cancel still wins).
	MCPVerifyContextTimeout = 2 * time.Second
)

// LRU bounds.
const (
	// LRURateLimitCapacity caps how many distinct SVID subjects the per-identity
	// rate limiter remembers before LRU-evicting the least-recently-seen.
	LRURateLimitCapacity = 10_000

	// LRUEWMACapacity caps how many distinct SVID subjects the EWMA tracker
	// remembers. Same bound as the rate limiter.
	LRUEWMACapacity = 10_000
)
