// Package mcpsupply implements the Reef MCP signature registry sidecar
// verifier. The verifier is the client half of the contract owned by the
// Reef Atlas service (reef/control-plane/atlas/). Lobster Trap calls into
// this package BEFORE the rule table runs whenever pipeline metadata names
// a target MCP server (see internal/pipeline/pipeline.go for the integration
// point and internal/inspector/inspector.go for the metadata field
// MCPBindTarget).
//
// Fail-closed contract: any failure to reach Atlas, any 5xx, any timeout,
// any malformed response — caller MUST receive Decision == "deny". A silent
// allow on registry failure would defeat the centerpiece block.
//
// See docs/24-GROUNDING.md Part 3 for the six capabilities Atlas enforces
// over the wire.
package mcpsupply

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Decision values mirror the JSON returned by Atlas /verify.
const (
	DecisionAllow  = "allow"
	DecisionDeny   = "deny"
	DecisionReview = "review"
)

// VerifyRequest is the wire payload the sidecar POSTs to /verify.
// Field names match the FastAPI route's pydantic model exactly so
// encoding/json marshalling produces the right keys.
type VerifyRequest struct {
	MCPName               string   `json:"mcpName"`
	Version               string   `json:"version"`
	Transport             string   `json:"transport"`
	ClaimedSignature      string   `json:"claimed_signature,omitempty"`
	AgentID               string   `json:"agent_id,omitempty"`
	RequestID             string   `json:"request_id,omitempty"`
	ClaimedEntrypointHash string   `json:"claimed_entrypoint_hash,omitempty"`
	ClaimedSDKVersion     string   `json:"claimed_sdk_version,omitempty"`
	ClaimedTools          []string `json:"claimed_tools,omitempty"`
}

// VerifyResponse is the wire payload Atlas returns from /verify.
type VerifyResponse struct {
	Decision            string      `json:"decision"`
	Reason              string      `json:"reason"`
	RegistryID          string      `json:"registry_id,omitempty"`
	MatchedCapabilities []string    `json:"matched_capabilities,omitempty"`
	Violations          []Violation `json:"violations,omitempty"`
	AuditID             string      `json:"audit_id"`
}

// Violation surfaces a structured policy violation with a stable code +
// human-readable detail. The MCP-RCE-26.04 code is the OX Security disclosure
// identifier; downstream consumers can grep audit logs against this string.
type Violation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Verifier is the contract Lobster Trap calls into. Implementations are
// expected to fail closed: any unreachable / 5xx / timeout produces
// Decision="deny" with a violation describing the transport failure rather
// than a Go error. Returning a Go error is reserved for caller programming
// errors (empty mcpName, invalid configuration).
type Verifier interface {
	Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error)
}

// HTTPVerifier is the production Verifier. It calls the Atlas /verify HTTP
// endpoint with a configured timeout and translates transport failures into
// fail-closed deny responses.
type HTTPVerifier struct {
	endpoint string
	client   *http.Client
}

// NewHTTPVerifier returns an HTTPVerifier targeting the given Atlas endpoint
// (e.g. "http://localhost:8080"). The timeout is applied to the entire
// HTTP round-trip — when it elapses, Verify returns a deny outcome marked
// with code "REGISTRY_TIMEOUT". The endpoint MUST be non-empty; passing
// empty returns a verifier that always denies with code "REGISTRY_MISCONFIG".
//
// Reef wires this from cmd/serve.go using the REEF_MCP_REGISTRY_URL env var
// (default http://localhost:8080).
func NewHTTPVerifier(endpoint string, timeout time.Duration) Verifier {
	if timeout <= 0 {
		timeout = 1500 * time.Millisecond
	}
	return &HTTPVerifier{
		endpoint: strings.TrimRight(endpoint, "/"),
		client: &http.Client{
			Timeout: timeout,
		},
	}
}

// Verify implements Verifier. See the package docstring for the fail-closed
// contract this enforces.
func (v *HTTPVerifier) Verify(ctx context.Context, req VerifyRequest) (*VerifyResponse, error) {
	if req.MCPName == "" {
		return nil, errors.New("mcpsupply: VerifyRequest.MCPName must not be empty")
	}
	if req.Version == "" {
		return nil, errors.New("mcpsupply: VerifyRequest.Version must not be empty")
	}
	if req.Transport == "" {
		return nil, errors.New("mcpsupply: VerifyRequest.Transport must not be empty")
	}
	if v.endpoint == "" {
		return failClosed(req, "REGISTRY_MISCONFIG",
			"Reef MCP registry endpoint is not configured. Refusing handshake.",
		), nil
	}

	body, err := json.Marshal(req)
	if err != nil {
		return failClosed(req, "REGISTRY_CLIENT_ERROR",
			fmt.Sprintf("could not marshal verify request: %v", err),
		), nil
	}

	httpReq, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		v.endpoint+"/verify",
		bytes.NewReader(body),
	)
	if err != nil {
		return failClosed(req, "REGISTRY_CLIENT_ERROR",
			fmt.Sprintf("could not build verify request: %v", err),
		), nil
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Accept", "application/json")

	resp, err := v.client.Do(httpReq)
	if err != nil {
		// Transport failures (unreachable host, DNS, timeout, TLS) — fail
		// closed. The deny response includes the original error so audit
		// logs surface the cause.
		code := "REGISTRY_UNREACHABLE"
		if errors.Is(err, context.DeadlineExceeded) ||
			strings.Contains(err.Error(), "Client.Timeout") ||
			strings.Contains(err.Error(), "context deadline") {
			code = "REGISTRY_TIMEOUT"
		}
		return failClosed(req, code,
			fmt.Sprintf(
				"Reef MCP registry verify call failed (%s). Fail-closed: deny. cause=%v",
				code, err,
			),
		), nil
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return failClosed(req, "REGISTRY_READ_ERROR",
			fmt.Sprintf("could not read verify response body: %v", err),
		), nil
	}

	if resp.StatusCode >= 500 {
		return failClosed(req, "REGISTRY_5XX",
			fmt.Sprintf(
				"Reef MCP registry returned %d. Fail-closed: deny. body=%q",
				resp.StatusCode, truncate(respBody, 512),
			),
		), nil
	}
	if resp.StatusCode >= 400 {
		return failClosed(req, "REGISTRY_4XX",
			fmt.Sprintf(
				"Reef MCP registry rejected verify request with %d. body=%q",
				resp.StatusCode, truncate(respBody, 512),
			),
		), nil
	}

	var parsed VerifyResponse
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return failClosed(req, "REGISTRY_BAD_RESPONSE",
			fmt.Sprintf("could not parse verify response: %v; body=%q",
				err, truncate(respBody, 512)),
		), nil
	}

	switch parsed.Decision {
	case DecisionAllow, DecisionDeny, DecisionReview:
		// ok — pass through to caller verbatim
	default:
		return failClosed(req, "REGISTRY_BAD_DECISION",
			fmt.Sprintf(
				"Reef MCP registry returned unknown decision %q. Fail-closed: deny.",
				parsed.Decision,
			),
		), nil
	}
	return &parsed, nil
}

// failClosed builds a synthetic deny outcome for transport / parsing failures.
// The decision field is always "deny"; the violation carries the failure code
// so audit consumers can distinguish a "registry unreachable" deny from a
// "MCP-RCE-26.04" deny.
func failClosed(req VerifyRequest, code, detail string) *VerifyResponse {
	return &VerifyResponse{
		Decision: DecisionDeny,
		Reason:   detail,
		Violations: []Violation{{
			Code:   code,
			Detail: detail,
		}},
		AuditID: "audit-local-failclosed-" + req.RequestID,
	}
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "...(truncated)"
}
