package pipeline

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply"
)

// TestPipeline_MCPBindIntegration_VictimUnsignedDenies is the canonical
// cold-open demo flow. The prompt names an unsigned MCP server (the victim
// app's identifier), the inspector extracts the bind target, the
// pre-ingress hook calls a stub Atlas service, Atlas denies (BIND_DENIED),
// and the pipeline records the ingress action with the verbatim violation
// code.
func TestPipeline_MCPBindIntegration_VictimUnsignedDenies(t *testing.T) {
	atlas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/verify" {
			t.Errorf("expected /verify, got %s", r.URL.Path)
		}
		var req mcpsupply.VerifyRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatalf("decode: %v", err)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcpsupply.VerifyResponse{
			Decision: mcpsupply.DecisionDeny,
			Reason:   "No signed registry entry for victim-mcp-server@1.0.4. (D-020)",
			Violations: []mcpsupply.Violation{{
				Code:   "BIND_DENIED",
				Detail: "victim app is unsigned per D-020",
			}},
			AuditID: "audit-stub-1",
		})
	}))
	defer atlas.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "mcp-bind-integration",
		DefaultAction: policy.ActionAllow,
	}
	store, _ := quarantine.NewStore(t.TempDir())
	dispatcher, _ := actions.NewDispatcher(actions.DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: noopLogger{},
	})
	pipe := NewWithReef(pol, audit.NopLogger(), dispatcher, true).
		WithMCPVerifier(mcpsupply.NewHTTPVerifier(atlas.URL, 2*time.Second))

	pr := pipe.ProcessIngress("please bind to MCP server victim-mcp-server and summarise my inbox", nil)
	if pr.IngressResult == nil {
		t.Fatal("nil ingress result")
	}
	if pr.IngressResult.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY", pr.IngressResult.Action)
	}
	if pr.IngressResult.RuleName != ReasonMCPBindDenied {
		t.Errorf("RuleName = %s, want %s", pr.IngressResult.RuleName, ReasonMCPBindDenied)
	}
	if !strings.Contains(pr.DenyMessage, "BIND_DENIED") {
		t.Errorf("DenyMessage missing BIND_DENIED token: %q", pr.DenyMessage)
	}
	if pr.IngressMetadata.MCPBindTarget != "victim-mcp-server" {
		t.Errorf("MCPBindTarget = %q, want victim-mcp-server", pr.IngressMetadata.MCPBindTarget)
	}
	if pr.IngressMetadata.MCPBindDecision != "deny" {
		t.Errorf("MCPBindDecision = %q, want deny", pr.IngressMetadata.MCPBindDecision)
	}
	if !pr.Blocked {
		t.Error("Blocked = false, want true")
	}
}

// TestPipeline_MCPBindIntegration_PoisonedReturnsMcpRceCode targets the
// poisoned seed entry's deny path so the demo arc has the verbatim
// MCP-RCE-26.04 citation in the deny message.
func TestPipeline_MCPBindIntegration_PoisonedReturnsMcpRceCode(t *testing.T) {
	atlas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcpsupply.VerifyResponse{
			Decision: mcpsupply.DecisionDeny,
			Reason:   "poisoned: SDK on April 2026 vulnerable list",
			Violations: []mcpsupply.Violation{{
				Code:   "MCP-RCE-26.04",
				Detail: "OX Security disclosure April 2026 — STDIO command-execution RCE class",
			}},
			AuditID: "audit-stub-poison-1",
		})
	}))
	defer atlas.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "mcp-bind-integration-poison",
		DefaultAction: policy.ActionAllow,
	}
	store, _ := quarantine.NewStore(t.TempDir())
	dispatcher, _ := actions.NewDispatcher(actions.DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: noopLogger{},
	})
	pipe := NewWithReef(pol, audit.NopLogger(), dispatcher, true).
		WithMCPVerifier(mcpsupply.NewHTTPVerifier(atlas.URL, 2*time.Second))

	prompt := `bind_mcp("com.attacker-example/evil-server", "0.5.0", "stdio")`
	pr := pipe.ProcessIngress(prompt, nil)
	if pr.IngressResult.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY", pr.IngressResult.Action)
	}
	if !strings.Contains(pr.DenyMessage, "MCP-RCE-26.04") {
		t.Errorf("DenyMessage missing MCP-RCE-26.04 citation: %q", pr.DenyMessage)
	}
	if pr.IngressMetadata.MCPBindTarget != "com.attacker-example/evil-server" {
		t.Errorf("MCPBindTarget = %q", pr.IngressMetadata.MCPBindTarget)
	}
	if pr.IngressMetadata.MCPBindVersion != "0.5.0" {
		t.Errorf("MCPBindVersion = %q, want 0.5.0", pr.IngressMetadata.MCPBindVersion)
	}
	if pr.IngressMetadata.MCPBindTransport != "stdio" {
		t.Errorf("MCPBindTransport = %q, want stdio", pr.IngressMetadata.MCPBindTransport)
	}
	if len(pr.IngressMetadata.MCPBindViolations) == 0 ||
		pr.IngressMetadata.MCPBindViolations[0].Code != "MCP-RCE-26.04" {
		t.Errorf("missing MCP-RCE-26.04 violation; got %+v", pr.IngressMetadata.MCPBindViolations)
	}
}

// TestPipeline_MCPBindIntegration_ReviewDispatchesHumanReview proves that a
// review decision from Atlas (quarantined entry) routes through the
// HUMAN_REVIEW action dispatcher.
func TestPipeline_MCPBindIntegration_ReviewDispatchesHumanReview(t *testing.T) {
	atlas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(mcpsupply.VerifyResponse{
			Decision: mcpsupply.DecisionReview,
			Reason:   "publisher key rotated mid-flight — pending re-issue",
			AuditID:  "audit-stub-review-1",
		})
	}))
	defer atlas.Close()

	webhookHits := 0
	webhook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		webhookHits++
		w.WriteHeader(http.StatusAccepted)
	}))
	defer webhook.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "mcp-bind-integration-review",
		DefaultAction: policy.ActionAllow,
		Notifications: policy.Notifications{
			HumanReviewWebhook:           webhook.URL,
			HumanReviewRetryAfterSeconds: 15,
		},
	}
	store, _ := quarantine.NewStore(t.TempDir())
	dispatcher, _ := actions.NewDispatcher(actions.DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: noopLogger{},
	})
	pipe := NewWithReef(pol, audit.NopLogger(), dispatcher, true).
		WithMCPVerifier(mcpsupply.NewHTTPVerifier(atlas.URL, 2*time.Second))

	pr := pipe.ProcessIngress(`bind_mcp("com.example/keyrotation-mcp", "0.4.1")`, nil)
	if pr.IngressResult.Action != policy.ActionHumanReview {
		t.Errorf("Action = %s, want HUMAN_REVIEW", pr.IngressResult.Action)
	}
	if pr.IngressAction == nil || pr.IngressAction.Action != policy.ActionHumanReview {
		t.Fatalf("IngressAction = %+v, want HUMAN_REVIEW", pr.IngressAction)
	}
	if !strings.HasPrefix(pr.IngressAction.ReviewID, "r-") {
		t.Errorf("ReviewID = %q, want r- prefix", pr.IngressAction.ReviewID)
	}
	if webhookHits != 1 {
		t.Errorf("webhookHits = %d, want 1", webhookHits)
	}
	if pr.IngressMetadata.MCPBindDecision != "review" {
		t.Errorf("MCPBindDecision = %q, want review", pr.IngressMetadata.MCPBindDecision)
	}
}

// TestPipeline_MCPBindIntegration_RegistryUnreachableFailsClosed proves the
// fail-closed contract: when Atlas is down, the pipeline DENIES the bind.
// This is non-negotiable per the spec — a silent allow would defeat the
// centerpiece block.
func TestPipeline_MCPBindIntegration_RegistryUnreachableFailsClosed(t *testing.T) {
	// Start + immediately close a server so the URL points at a dead port.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	dead := srv.URL
	srv.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "mcp-bind-failclosed",
		DefaultAction: policy.ActionAllow,
	}
	store, _ := quarantine.NewStore(t.TempDir())
	dispatcher, _ := actions.NewDispatcher(actions.DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: noopLogger{},
	})
	pipe := NewWithReef(pol, audit.NopLogger(), dispatcher, true).
		WithMCPVerifier(mcpsupply.NewHTTPVerifier(dead, 200*time.Millisecond))

	pr := pipe.ProcessIngress("bind to MCP server com.example/weather-mcp@1.2.3", nil)
	if pr.IngressResult.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY on unreachable registry", pr.IngressResult.Action)
	}
	if pr.IngressMetadata.MCPBindDecision != "deny" {
		t.Errorf("MCPBindDecision = %q, want deny", pr.IngressMetadata.MCPBindDecision)
	}
	hadRegistryViolation := false
	for _, v := range pr.IngressMetadata.MCPBindViolations {
		if strings.HasPrefix(v.Code, "REGISTRY") {
			hadRegistryViolation = true
			break
		}
	}
	if !hadRegistryViolation {
		t.Errorf("expected REGISTRY_* violation, got %+v", pr.IngressMetadata.MCPBindViolations)
	}
}

// TestPipeline_MCPBindIntegration_VerifierNotCalledOnBenignPrompt proves the
// pre-ingress hook is dormant for prompts that don't mention an MCP bind.
// This keeps benign requests cheap (no registry round-trip).
func TestPipeline_MCPBindIntegration_VerifierNotCalledOnBenignPrompt(t *testing.T) {
	hits := 0
	atlas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(mcpsupply.VerifyResponse{
			Decision: mcpsupply.DecisionAllow,
			AuditID:  "a",
		})
	}))
	defer atlas.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "benign",
		DefaultAction: policy.ActionAllow,
	}
	store, _ := quarantine.NewStore(t.TempDir())
	dispatcher, _ := actions.NewDispatcher(actions.DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: noopLogger{},
	})
	pipe := NewWithReef(pol, audit.NopLogger(), dispatcher, true).
		WithMCPVerifier(mcpsupply.NewHTTPVerifier(atlas.URL, time.Second))

	_ = pipe.ProcessIngress("Hello, please summarise my inbox.", nil)
	if hits != 0 {
		t.Errorf("registry hits = %d on benign prompt, want 0", hits)
	}
}

// TestPipeline_MCPBindIntegration_FlagOffSkipsRegistry proves --enable-reef=off
// disables the pre-ingress hook entirely, even when an MCP bind target is
// detected. Required for the upstream PR shape.
func TestPipeline_MCPBindIntegration_FlagOffSkipsRegistry(t *testing.T) {
	hits := 0
	atlas := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		_ = json.NewEncoder(w).Encode(mcpsupply.VerifyResponse{
			Decision: mcpsupply.DecisionDeny,
			AuditID:  "a",
		})
	}))
	defer atlas.Close()

	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "off",
		DefaultAction: policy.ActionAllow,
	}
	pipe := New(pol, audit.NopLogger()).WithMCPVerifier(mcpsupply.NewHTTPVerifier(atlas.URL, time.Second))

	pr := pipe.ProcessIngress(`bind_mcp("victim-mcp-server")`, nil)
	if hits != 0 {
		t.Errorf("registry hits = %d with Reef off, want 0", hits)
	}
	if pr.IngressResult.Action == policy.ActionDeny {
		t.Errorf("Action = DENY with Reef off; should pass through")
	}
}
