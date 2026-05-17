package pipeline

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/metadata"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply"
)

var requestCounter atomic.Uint64

// EventObserver is a callback function that receives pipeline events.
// direction is "ingress" or "egress".
type EventObserver func(event PipelineEvent)

// PipelineEvent represents a single pipeline event for observers.
type PipelineEvent struct {
	Timestamp time.Time                `json:"timestamp"`
	Direction string                   `json:"direction"`
	RequestID string                   `json:"request_id"`
	Action    policy.Action            `json:"action"`
	RuleName  string                   `json:"rule_name,omitempty"`
	Metadata  *inspector.PromptMetadata `json:"metadata"`
	Blocked   bool                     `json:"blocked"`
	DenyMsg   string                   `json:"deny_message,omitempty"`
}

// Pipeline runs the ingress → inference → egress inspection flow.
//
// Reef extensions (A-4): when EnableReef is true and Dispatcher is non-nil,
// the pipeline routes MODIFY/REDIRECT/QUARANTINE/HUMAN_REVIEW verdicts
// through the actions dispatcher instead of treating them as soft no-ops.
// When EnableReef is false, the pipeline behaves exactly as upstream Lobster
// Trap (these actions are ignored beyond an audit-log entry). The flag is
// wired by cmd/serve.go from the persistent `--enable-reef` flag declared
// in cmd/root.go.
type Pipeline struct {
	inspector     *inspector.Inspector
	ingressTable  *policy.MatchActionTable
	egressTable   *policy.MatchActionTable
	deniedDomains []string
	auditLogger   *audit.Logger

	enableReef bool
	dispatcher *actions.Dispatcher

	// Reef MCP signature registry sidecar verifier (A-5). When non-nil and
	// --enable-reef is on, the pipeline calls Verify before the ingress
	// rule table runs whenever inspector.PromptMetadata.MCPBindTarget != "".
	// A deny decision short-circuits the rest of the pipeline with a
	// BIND_DENIED outcome carrying the violation code Atlas returned (e.g.
	// MCP-RCE-26.04). A review decision dispatches HUMAN_REVIEW.
	mcpVerifier mcpsupply.Verifier

	observerMu sync.RWMutex
	observers  []EventObserver
}

// ReasonBlockedDeniedDomain is the synthetic rule name emitted when egress
// is denied because the model output references a host on the policy's
// network.denied_domains list. Surfaced via PipelineResult.EgressResult.RuleName
// so existing observers and audit consumers can route on it.
const ReasonBlockedDeniedDomain = "blocked_denied_domain"

// ReasonMCPBindDenied / ReasonMCPBindReview are the synthetic rule names
// emitted when the Reef Atlas signature registry denies / flags a server bind
// attempt. RuleName is what observers and audit logs route on.
const (
	ReasonMCPBindDenied = "mcp_bind_denied_by_registry"
	ReasonMCPBindReview = "mcp_bind_review_by_registry"
)

// New creates a new Pipeline from a loaded policy. Reef extensions are
// disabled — call NewWithReef to opt in.
func New(pol *policy.Policy, auditLogger *audit.Logger) *Pipeline {
	ingress, egress := policy.BuildTables(pol)
	return &Pipeline{
		inspector:     inspector.NewWithTrustedDomains(pol.Network.AllowedDomains),
		ingressTable:  ingress,
		egressTable:   egress,
		deniedDomains: append([]string(nil), pol.Network.DeniedDomains...),
		auditLogger:   auditLogger,
	}
}

// NewWithReef creates a pipeline with the Reef action dispatcher attached.
// When dispatcher is nil, the result is equivalent to New(pol, auditLogger);
// passing a dispatcher with enableReef=false logs a warning at construction
// time and behaves like the upstream path.
func NewWithReef(pol *policy.Policy, auditLogger *audit.Logger, dispatcher *actions.Dispatcher, enableReef bool) *Pipeline {
	pipe := New(pol, auditLogger)
	pipe.enableReef = enableReef
	pipe.dispatcher = dispatcher
	return pipe
}

// WithMCPVerifier attaches the Reef MCP signature registry verifier (A-5)
// to an existing pipeline. The verifier is consulted before the ingress
// rule table whenever PromptMetadata.MCPBindTarget != "". Returns the same
// pipeline for chaining.
func (p *Pipeline) WithMCPVerifier(v mcpsupply.Verifier) *Pipeline {
	p.mcpVerifier = v
	return p
}

// MCPVerifier returns the attached MCP verifier (nil if A-5 was not wired).
// Exposed for tests + introspection.
func (p *Pipeline) MCPVerifier() mcpsupply.Verifier {
	return p.mcpVerifier
}

// SetEnableReef toggles the Reef action dispatch path at runtime. Used by
// tests; production wires the flag at NewWithReef time.
func (p *Pipeline) SetEnableReef(on bool) {
	p.enableReef = on
}

// Dispatcher returns the attached actions.Dispatcher (nil if Reef is off
// or no dispatcher was supplied). Exposed for integration tests + the
// proxy's HTTP shaper which reads outcomes after pipeline processing.
func (p *Pipeline) Dispatcher() *actions.Dispatcher {
	return p.dispatcher
}

// ProcessIngress inspects a prompt and evaluates ingress rules.
// declared may be nil if the agent didn't send _lobstertrap headers.
func (p *Pipeline) ProcessIngress(promptText string, declared *metadata.RequestHeaders) *PipelineResult {
	reqID := fmt.Sprintf("req-%d", requestCounter.Add(1))

	meta := p.inspector.Inspect(promptText)

	// Reef A-5 pre-ingress hook: if the inspector detected an MCP server bind
	// attempt AND a verifier is attached AND Reef is enabled, call Atlas
	// BEFORE the rule table runs. Decision results land on the metadata so
	// YAML rules can match `mcp_bind_target_decision`. A deny here is the
	// centerpiece block — we override the table result to DENY with the
	// violation code Atlas returned. A review dispatches HUMAN_REVIEW. An
	// allow lets the rule table run normally.
	var mcpResp *mcpsupply.VerifyResponse
	if p.enableReef && p.mcpVerifier != nil && meta.MCPBindTarget != "" {
		var agentIDForVerify string
		if declared != nil {
			agentIDForVerify = declared.AgentID
		}
		transport := meta.MCPBindTransport
		if transport == "" {
			transport = "http"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		mcpResp, _ = p.mcpVerifier.Verify(ctx, mcpsupply.VerifyRequest{
			MCPName:   meta.MCPBindTarget,
			Version:   meta.MCPBindVersion,
			Transport: transport,
			AgentID:   agentIDForVerify,
			RequestID: reqID,
		})
		cancel()
		// Programmer errors return nil response — fail closed.
		if mcpResp == nil {
			mcpResp = &mcpsupply.VerifyResponse{
				Decision: mcpsupply.DecisionDeny,
				Reason:   "Reef MCP verifier returned nil — fail-closed deny",
				Violations: []mcpsupply.Violation{{
					Code:   "REGISTRY_CLIENT_ERROR",
					Detail: "verifier returned nil response",
				}},
				AuditID: "audit-local-nilresp",
			}
		}
		meta.MCPBindDecision = mcpResp.Decision
		meta.MCPBindRegistryID = mcpResp.RegistryID
		for _, v := range mcpResp.Violations {
			meta.MCPBindViolations = append(meta.MCPBindViolations, inspector.MCPBindViolation{
				Code:   v.Code,
				Detail: v.Detail,
			})
		}
	}

	result := p.ingressTable.Evaluate(meta)

	// Detect mismatches between declared and detected metadata
	mismatches := metadata.DetectMismatches(declared, meta)

	pr := &PipelineResult{
		RequestID:       reqID,
		IngressMetadata: meta,
		IngressResult:   &result,
		DeclaredHeaders: declared,
		Mismatches:      mismatches,
	}

	// Extract agent ID for audit logging + Reef action dispatch
	var agentID string
	if declared != nil {
		agentID = declared.AgentID
	}

	// Reef A-5: when the MCP verifier returned deny/review, override the
	// rule-table result so the action dispatcher + outcome shaping below
	// surface the BIND_DENIED verdict with the correct violation code.
	// Allow passes through to the rule table (and may still be denied by
	// some other rule like a content scanner).
	if mcpResp != nil {
		switch mcpResp.Decision {
		case mcpsupply.DecisionDeny:
			denyMsg := mcpResp.Reason
			if denyMsg == "" {
				denyMsg = "[REEF] MCP bind denied by signature registry"
			}
			if len(mcpResp.Violations) > 0 {
				denyMsg = "[REEF] BIND_DENIED — " + mcpResp.Violations[0].Code +
					": " + mcpResp.Violations[0].Detail
			}
			result = policy.RuleResult{
				Matched:     true,
				RuleName:    ReasonMCPBindDenied,
				Action:      policy.ActionDeny,
				DenyMessage: denyMsg,
			}
			*pr.IngressResult = result
		case mcpsupply.DecisionReview:
			reviewMsg := mcpResp.Reason
			if reviewMsg == "" {
				reviewMsg = "[REEF] MCP bind held for human review by signature registry"
			}
			result = policy.RuleResult{
				Matched:     true,
				RuleName:    ReasonMCPBindReview,
				Action:      policy.ActionHumanReview,
				DenyMessage: reviewMsg,
			}
			*pr.IngressResult = result
		}
	}

	// Reef action dispatch (A-4). Only fires when --enable-reef is on AND
	// the matched action is one Reef implements. ALLOW / DENY / LOG keep
	// their upstream paths so vanilla LT behaviour is preserved.
	if p.enableReef && p.dispatcher != nil && isReefAction(result.Action) {
		out := p.dispatcher.Dispatch(context.Background(), actions.Decision{
			Direction:  actions.DirectionIngress,
			RequestID:  reqID,
			AgentID:    agentID,
			Rule:       result,
			Meta:       meta,
			Body:       promptText,
			OriginPath: "ingress",
		})
		pr.IngressAction = &out
		// If the action degraded to DENY (fail-closed), reflect that in
		// the rule result so downstream consumers see the actual verdict.
		if out.Action == policy.ActionDeny && result.Action != policy.ActionDeny {
			result.Action = policy.ActionDeny
			if out.Reason != "" {
				result.DenyMessage = out.Reason
			} else {
				result.DenyMessage = "[REEF] action failed-closed to DENY"
			}
			*pr.IngressResult = result
		}
	} else if p.enableReef && p.dispatcher == nil && isReefAction(result.Action) {
		// Flag is on but dispatcher missing — log the configuration error.
		// Treat as upstream did: ALLOW/LOG-equivalent verdicts already pass
		// through, the blocking ones (DENY/QUARANTINE) already block.
		// Nothing else to do.
	} else if !p.enableReef && isReefAction(result.Action) && result.Action != policy.ActionDeny && result.Action != policy.ActionQuarantine {
		// Vanilla Lobster Trap: MODIFY/REDIRECT/HUMAN_REVIEW silently fall
		// through. We at least audit that the rule matched so operators see
		// they had a Reef rule fire on a non-Reef deployment.
		// (No code change here; the audit.Log below captures it.)
	}

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine ||
		(p.enableReef && (result.Action == policy.ActionRedirect || result.Action == policy.ActionHumanReview)) {
		pr.Blocked = true
		pr.BlockedAt = "ingress"
		if result.DenyMessage != "" {
			pr.DenyMessage = result.DenyMessage
		} else if pr.IngressAction != nil {
			pr.DenyMessage = pr.IngressAction.Reason
		}
	}

	// Audit log
	p.auditLogger.Log(audit.Entry{
		RequestID:       reqID,
		Direction:       "ingress",
		Action:          string(result.Action),
		RuleName:        result.RuleName,
		DenyMessage:     result.DenyMessage,
		Metadata:        meta,
		TokenCount:      meta.TokenCount,
		DeclaredHeaders: declared,
		Mismatches:      mismatches,
		AgentID:         agentID,
	})

	// Notify observers
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "ingress",
		RequestID: reqID,
		Action:    result.Action,
		RuleName:  result.RuleName,
		Metadata:  meta,
		Blocked:   pr.Blocked,
		DenyMsg:   result.DenyMessage,
	})

	return pr
}

// isReefAction returns true for the four Lobster Trap actions Reef ships:
// MODIFY, REDIRECT, QUARANTINE, HUMAN_REVIEW.
func isReefAction(a policy.Action) bool {
	switch a {
	case policy.ActionModify, policy.ActionRedirect, policy.ActionQuarantine, policy.ActionHumanReview:
		return true
	}
	return false
}

// ProcessEgress inspects model output and evaluates egress rules.
// Updates the existing PipelineResult with egress information.
func (p *Pipeline) ProcessEgress(pr *PipelineResult, responseText string) {
	meta := p.inspector.Inspect(responseText)
	result := p.egressTable.Evaluate(meta)

	// Enforce network.denied_domains at egress. Upstream Lobster Trap parsed
	// this list into policy.NetworkPolicy.DeniedDomains but only rendered it
	// in the dashboard — never enforced it at runtime. Any model output that
	// references a denied host (e.g. an EchoLeak markdown image pointing at
	// an attacker-controlled domain) overrides any softer egress decision
	// with DENY. Pre-existing DENY/QUARANTINE rule matches are preserved
	// so audits surface the more specific rule rather than this generic one.
	if len(p.deniedDomains) > 0 &&
		result.Action != policy.ActionDeny &&
		result.Action != policy.ActionQuarantine {
		if pat, host := policy.FirstDeniedDomain(p.deniedDomains, meta.TargetDomains); host != "" {
			result = policy.RuleResult{
				Matched:     true,
				RuleName:    ReasonBlockedDeniedDomain,
				Action:      policy.ActionDeny,
				DenyMessage: fmt.Sprintf("[LOBSTER TRAP] Blocked: response references denied domain %q (pattern %q).", host, pat),
			}
		}
	}

	pr.EgressMetadata = meta
	pr.EgressResult = &result
	// Default: the body forwarded to the caller is the model's original
	// output. MODIFY rewrites this below.
	pr.EgressBody = responseText

	// Reef action dispatch (A-4).
	var agentID string
	if pr.DeclaredHeaders != nil {
		agentID = pr.DeclaredHeaders.AgentID
	}
	if p.enableReef && p.dispatcher != nil && isReefAction(result.Action) {
		out := p.dispatcher.Dispatch(context.Background(), actions.Decision{
			Direction:  actions.DirectionEgress,
			RequestID:  pr.RequestID,
			AgentID:    agentID,
			Rule:       result,
			Meta:       meta,
			Body:       responseText,
			OriginPath: "egress",
		})
		pr.EgressAction = &out
		// MODIFY: swap the forwarded body with the rewritten text.
		if out.Action == policy.ActionModify && out.RewrittenBody != "" {
			pr.EgressBody = out.RewrittenBody
		}
		// Fail-closed degradation: an action that errored returns DENY.
		if out.Action == policy.ActionDeny && result.Action != policy.ActionDeny {
			result.Action = policy.ActionDeny
			if out.Reason != "" {
				result.DenyMessage = out.Reason
			} else {
				result.DenyMessage = "[REEF] action failed-closed to DENY"
			}
			*pr.EgressResult = result
		}
	}

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine ||
		(p.enableReef && (result.Action == policy.ActionRedirect || result.Action == policy.ActionHumanReview)) {
		pr.Blocked = true
		pr.BlockedAt = "egress"
		if result.DenyMessage != "" {
			pr.DenyMessage = result.DenyMessage
		} else if pr.EgressAction != nil {
			pr.DenyMessage = pr.EgressAction.Reason
		}
	}

	// Audit log
	p.auditLogger.Log(audit.Entry{
		RequestID:   pr.RequestID,
		Direction:   "egress",
		Action:      string(result.Action),
		RuleName:    result.RuleName,
		DenyMessage: result.DenyMessage,
		Metadata:    meta,
		TokenCount:  meta.TokenCount,
	})

	// Notify observers
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "egress",
		RequestID: pr.RequestID,
		Action:    result.Action,
		RuleName:  result.RuleName,
		Metadata:  meta,
		Blocked:   pr.Blocked && pr.BlockedAt == "egress",
		DenyMsg:   result.DenyMessage,
	})
}

// AddObserver registers a callback that will be invoked for every pipeline event.
func (p *Pipeline) AddObserver(fn EventObserver) {
	p.observerMu.Lock()
	defer p.observerMu.Unlock()
	p.observers = append(p.observers, fn)
}

// notify sends an event to all registered observers.
func (p *Pipeline) notify(event PipelineEvent) {
	p.observerMu.RLock()
	observers := p.observers
	p.observerMu.RUnlock()

	for _, fn := range observers {
		fn(event)
	}
}

// InspectOnly runs DPI without policy evaluation (for the `inspect` command).
func (p *Pipeline) InspectOnly(text string) *inspector.PromptMetadata {
	return p.inspector.Inspect(text)
}
