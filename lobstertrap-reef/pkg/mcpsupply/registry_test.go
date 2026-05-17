package mcpsupply

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestHTTPVerifier_TableDriven(t *testing.T) {
	type tc struct {
		name           string
		req            VerifyRequest
		serverHandler  http.HandlerFunc
		wantDecision   string
		wantViolation  string // substring of any violation Code; "" = no requirement
		wantErrSubstr  string // substring of returned Go error; "" = expect no error
		wantClosedTrip bool   // when true, no HTTP call must occur (e.g. validation error)
	}

	allowResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Decision:   DecisionAllow,
			Reason:     "manifest matches signed entry",
			RegistryID: "reg-0001",
			AuditID:    "audit-allow-1",
		})
	}
	denyResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Decision: DecisionDeny,
			Reason:   "SDK on April 2026 vulnerable list",
			Violations: []Violation{{
				Code:   "MCP-RCE-26.04",
				Detail: "OX Security disclosure April 2026",
			}},
			AuditID: "audit-deny-1",
		})
	}
	reviewResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Decision: DecisionReview,
			Reason:   "publisher key rotated",
			AuditID:  "audit-review-1",
		})
	}
	fiveXXResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"detail":"boom"}`))
	}
	fourXXResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"detail":"missing field"}`))
	}
	badJSONResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{not json`))
	}
	badDecisionResponse := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Decision: "maybe",
			Reason:   "ambiguous",
			AuditID:  "audit-bad-1",
		})
	}

	baseReq := VerifyRequest{
		MCPName:   "com.example/weather-mcp",
		Version:   "1.2.3",
		Transport: "http",
		AgentID:   "spiffe://example/agent-1",
		RequestID: "req-test-1",
	}

	cases := []tc{
		{
			name:          "allow",
			req:           baseReq,
			serverHandler: allowResponse,
			wantDecision:  DecisionAllow,
		},
		{
			name:          "deny with MCP-RCE-26.04",
			req:           baseReq,
			serverHandler: denyResponse,
			wantDecision:  DecisionDeny,
			wantViolation: "MCP-RCE-26.04",
		},
		{
			name:          "review",
			req:           baseReq,
			serverHandler: reviewResponse,
			wantDecision:  DecisionReview,
		},
		{
			name:          "5xx fails closed to deny",
			req:           baseReq,
			serverHandler: fiveXXResponse,
			wantDecision:  DecisionDeny,
			wantViolation: "REGISTRY_5XX",
		},
		{
			name:          "4xx fails closed to deny",
			req:           baseReq,
			serverHandler: fourXXResponse,
			wantDecision:  DecisionDeny,
			wantViolation: "REGISTRY_4XX",
		},
		{
			name:          "bad json fails closed to deny",
			req:           baseReq,
			serverHandler: badJSONResponse,
			wantDecision:  DecisionDeny,
			wantViolation: "REGISTRY_BAD_RESPONSE",
		},
		{
			name:          "unknown decision fails closed to deny",
			req:           baseReq,
			serverHandler: badDecisionResponse,
			wantDecision:  DecisionDeny,
			wantViolation: "REGISTRY_BAD_DECISION",
		},
		{
			name: "empty mcpname is a programmer error",
			req: VerifyRequest{
				Version:   "1.0.0",
				Transport: "http",
			},
			serverHandler:  allowResponse,
			wantErrSubstr:  "MCPName must not be empty",
			wantClosedTrip: true,
		},
		{
			name: "empty version is a programmer error",
			req: VerifyRequest{
				MCPName:   "com.example/weather-mcp",
				Transport: "http",
			},
			serverHandler:  allowResponse,
			wantErrSubstr:  "Version must not be empty",
			wantClosedTrip: true,
		},
		{
			name: "empty transport is a programmer error",
			req: VerifyRequest{
				MCPName: "com.example/weather-mcp",
				Version: "1.0.0",
			},
			serverHandler:  allowResponse,
			wantErrSubstr:  "Transport must not be empty",
			wantClosedTrip: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var hits atomic.Int32
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				hits.Add(1)
				if r.URL.Path != "/verify" {
					t.Errorf("unexpected path %q", r.URL.Path)
				}
				if r.Method != http.MethodPost {
					t.Errorf("method = %s, want POST", r.Method)
				}
				if r.Header.Get("Content-Type") != "application/json" {
					t.Errorf("Content-Type = %q, want application/json",
						r.Header.Get("Content-Type"))
				}
				c.serverHandler(w, r)
			}))
			defer srv.Close()

			v := NewHTTPVerifier(srv.URL, 2*time.Second)
			resp, err := v.Verify(context.Background(), c.req)
			if c.wantErrSubstr != "" {
				if err == nil || !strings.Contains(err.Error(), c.wantErrSubstr) {
					t.Fatalf("err = %v, want substring %q", err, c.wantErrSubstr)
				}
				if c.wantClosedTrip && hits.Load() != 0 {
					t.Errorf("HTTP hits = %d, want 0 (programmer error must not call the registry)", hits.Load())
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if resp == nil {
				t.Fatalf("nil response")
			}
			if resp.Decision != c.wantDecision {
				t.Errorf("Decision = %q, want %q (reason=%q)", resp.Decision, c.wantDecision, resp.Reason)
			}
			if c.wantViolation != "" {
				found := false
				for _, vio := range resp.Violations {
					if strings.Contains(vio.Code, c.wantViolation) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected violation code containing %q, got %+v",
						c.wantViolation, resp.Violations)
				}
			}
		})
	}
}

func TestHTTPVerifier_TimeoutFailsClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		// Sleep longer than the verifier timeout so we hit the
		// Client.Timeout branch.
		time.Sleep(300 * time.Millisecond)
		_, _ = w.Write([]byte(`{"decision":"allow","reason":"too late","audit_id":"a"}`))
	}))
	defer srv.Close()

	v := NewHTTPVerifier(srv.URL, 50*time.Millisecond)
	resp, err := v.Verify(context.Background(), VerifyRequest{
		MCPName:   "com.example/weather-mcp",
		Version:   "1.0.0",
		Transport: "http",
		RequestID: "req-timeout-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q on timeout", resp.Decision, DecisionDeny)
	}
	if len(resp.Violations) == 0 {
		t.Fatalf("expected at least one violation")
	}
	if !strings.Contains(resp.Violations[0].Code, "REGISTRY") {
		t.Errorf("expected REGISTRY_* violation code, got %q", resp.Violations[0].Code)
	}
}

func TestHTTPVerifier_UnreachableHostFailsClosed(t *testing.T) {
	// Point at an unroutable address. ::1:1 is loopback IPv6 — we use a
	// non-listening port via httptest.NewServer then close immediately.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	addr := srv.URL
	srv.Close()

	v := NewHTTPVerifier(addr, 200*time.Millisecond)
	resp, err := v.Verify(context.Background(), VerifyRequest{
		MCPName:   "com.example/weather-mcp",
		Version:   "1.0.0",
		Transport: "http",
		RequestID: "req-unreach-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q on unreachable host", resp.Decision, DecisionDeny)
	}
	if len(resp.Violations) == 0 || !strings.Contains(resp.Violations[0].Code, "REGISTRY") {
		t.Errorf("expected REGISTRY_* violation, got %+v", resp.Violations)
	}
}

func TestHTTPVerifier_EmptyEndpointDeniesWithoutCall(t *testing.T) {
	v := NewHTTPVerifier("", time.Second)
	resp, err := v.Verify(context.Background(), VerifyRequest{
		MCPName:   "com.example/weather-mcp",
		Version:   "1.0.0",
		Transport: "http",
		RequestID: "req-empty-1",
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if resp.Decision != DecisionDeny {
		t.Errorf("Decision = %q, want %q", resp.Decision, DecisionDeny)
	}
	if len(resp.Violations) == 0 || resp.Violations[0].Code != "REGISTRY_MISCONFIG" {
		t.Errorf("expected REGISTRY_MISCONFIG, got %+v", resp.Violations)
	}
}

func TestHTTPVerifier_PayloadFieldsRoundTrip(t *testing.T) {
	var captured VerifyRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Fatalf("decode: %v", err)
		}
		_ = json.NewEncoder(w).Encode(VerifyResponse{
			Decision: DecisionAllow,
			AuditID:  "a",
		})
	}))
	defer srv.Close()

	v := NewHTTPVerifier(srv.URL, time.Second)
	req := VerifyRequest{
		MCPName:               "com.example/weather-mcp",
		Version:               "1.0.0",
		Transport:             "stdio",
		AgentID:               "spiffe://example/agent",
		RequestID:             "req-payload-1",
		ClaimedEntrypointHash: "sha256:" + strings.Repeat("a", 64),
		ClaimedSDKVersion:     "@modelcontextprotocol/sdk@1.29.0",
		ClaimedTools:          []string{"get_weather"},
	}
	if _, err := v.Verify(context.Background(), req); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if captured.MCPName != req.MCPName ||
		captured.Version != req.Version ||
		captured.Transport != req.Transport ||
		captured.AgentID != req.AgentID ||
		captured.RequestID != req.RequestID ||
		captured.ClaimedEntrypointHash != req.ClaimedEntrypointHash ||
		captured.ClaimedSDKVersion != req.ClaimedSDKVersion ||
		len(captured.ClaimedTools) != 1 ||
		captured.ClaimedTools[0] != "get_weather" {
		t.Errorf("payload round-trip mismatch:\nwant=%+v\ngot=%+v", req, captured)
	}
}
