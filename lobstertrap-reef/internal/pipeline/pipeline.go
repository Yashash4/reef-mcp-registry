package pipeline

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/metadata"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/identity"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/mcpsupply"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/otel"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/ratelimit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/session"
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
	policy        *policy.Policy

	enableReef bool
	dispatcher *actions.Dispatcher

	// Reef MCP signature registry sidecar verifier (A-5). When non-nil and
	// --enable-reef is on, the pipeline calls Verify before the ingress
	// rule table runs whenever inspector.PromptMetadata.MCPBindTarget != "".
	mcpVerifier mcpsupply.Verifier

	// Reef A-6 surfaces. nil-safe — when --enable-reef is off OR the
	// individual component wasn't wired, the pipeline behaves as if it
	// weren't present.
	svidVerifier identity.Verifier
	rateLimiter  ratelimit.Limiter
	ewmaTracker  *session.Tracker
	merkleTree   *audit.Tree
	otelExporter otel.Exporter

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

// Reef A-6 synthetic rule names for SVID + rate-limit denials. The pipeline
// short-circuits to a DENY with one of these as the RuleName so audit
// consumers can grep on stable strings.
const (
	ReasonSVIDInvalid        = "svid_invalid"
	ReasonSVIDExpired        = "svid_expired"
	ReasonSVIDMissing        = "svid_missing"
	ReasonRateLimitPerIdent  = "rate_limited_per_identity"
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
		policy:        pol,
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

// WithSVIDVerifier attaches the Reef SVID JWT verifier (A-6). When set, the
// pipeline calls VerifySVID with the inbound Authorization header before
// running the rule table. Returns the same pipeline for chaining.
func (p *Pipeline) WithSVIDVerifier(v identity.Verifier) *Pipeline {
	p.svidVerifier = v
	return p
}

// WithRateLimiter attaches a per-identity rate limiter (A-6).
func (p *Pipeline) WithRateLimiter(l ratelimit.Limiter) *Pipeline {
	p.rateLimiter = l
	return p
}

// WithEWMATracker attaches the OWASP ASI category EWMA tracker (A-6).
func (p *Pipeline) WithEWMATracker(t *session.Tracker) *Pipeline {
	p.ewmaTracker = t
	return p
}

// WithMerkleTree attaches the audit Merkle tree (A-6). Every action verdict
// appends a leaf with the request context.
func (p *Pipeline) WithMerkleTree(t *audit.Tree) *Pipeline {
	p.merkleTree = t
	return p
}

// WithOTelExporter attaches the OpenTelemetry exporter (A-6). Every ingress
// + egress call is wrapped in a span carrying the meta + verdict.
func (p *Pipeline) WithOTelExporter(e otel.Exporter) *Pipeline {
	p.otelExporter = e
	return p
}

// MerkleTree exposes the attached Merkle tree (nil if not wired). Used by
// integration tests + the verifier CLI.
func (p *Pipeline) MerkleTree() *audit.Tree { return p.merkleTree }

// SVIDVerifier exposes the attached SVID verifier (nil if not wired).
func (p *Pipeline) SVIDVerifier() identity.Verifier { return p.svidVerifier }

// EWMATracker exposes the attached EWMA tracker (nil if not wired).
func (p *Pipeline) EWMATracker() *session.Tracker { return p.ewmaTracker }

// RateLimiter exposes the attached rate limiter (nil if not wired).
func (p *Pipeline) RateLimiter() ratelimit.Limiter { return p.rateLimiter }

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
	return p.ProcessIngressWithAuth(promptText, declared, "")
}

// ProcessIngressWithAuth is the SVID-aware ingress entrypoint. authToken is
// the raw value of the Authorization header (with or without "Bearer "
// prefix). When --enable-reef is on and a verifier is attached, the token
// is verified BEFORE inspector inspection — invalid SVIDs cause an early
// DENY when the policy's RequireSVID flag is set.
func (p *Pipeline) ProcessIngressWithAuth(promptText string, declared *metadata.RequestHeaders, authToken string) *PipelineResult {
	reqID := fmt.Sprintf("req-%d", requestCounter.Add(1))

	// OTel span lifecycle. Span attributes are populated as the pipeline
	// makes decisions; on End the latency is captured below.
	var span otel.Span
	ctx := context.Background()
	startedAt := time.Now()
	if p.enableReef && p.otelExporter != nil {
		ctx, span = p.otelExporter.Start(ctx, "reef.pipeline.ingress")
		span.SetAttribute("request.id", reqID)
		defer func() {
			span.SetAttribute("latency_ms", time.Since(startedAt).Milliseconds())
			span.End()
		}()
	}

	meta := p.inspector.Inspect(promptText)

	// Reef A-6 SVID verification.
	var svid *identity.SVID
	if p.enableReef && p.svidVerifier != nil {
		if authToken == "" {
			meta.SVIDError = "ErrEmptyToken"
			if p.policy != nil && p.policy.Reef.RequireSVID {
				return p.dispatchSVIDDeny(reqID, ctx, span, meta, declared, ReasonSVIDMissing, "SVID_INVALID — missing Authorization header")
			}
		} else {
			parsed, err := p.svidVerifier.VerifySVID(authToken)
			if err != nil {
				meta.SVIDError = errorSentinel(err)
				if p.policy != nil && p.policy.Reef.RequireSVID {
					rule := ReasonSVIDInvalid
					msg := "SVID_INVALID — " + err.Error()
					if errors.Is(err, identity.ErrExpired) {
						rule = ReasonSVIDExpired
						msg = "SVID_EXPIRED — " + err.Error()
					}
					return p.dispatchSVIDDeny(reqID, ctx, span, meta, declared, rule, msg)
				}
			} else {
				svid = parsed
				meta.AgentIdentityVerified = true
				meta.SVIDSubject = svid.Subject
				if span != nil {
					span.SetAttribute("svid.subject", svid.Subject)
					span.SetAttribute("svid.issuer", svid.Issuer)
				}
			}
		}
	}

	// Reef A-6 per-identity rate limit. Skip if no limiter or no subject.
	if p.enableReef && p.rateLimiter != nil && meta.SVIDSubject != "" {
		if !p.rateLimiter.Allow(meta.SVIDSubject) {
			meta.RateLimited = true
			if span != nil {
				span.SetAttribute("rate_limited", true)
				span.AddEvent("rate_limited_per_identity")
			}
			return p.dispatchRateLimited(reqID, ctx, meta, declared)
		}
	}

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

	// Reef A-6: declared-vs-detected intent mismatch (only meaningful with a
	// valid SVID).
	if p.enableReef && svid != nil {
		meta.IntentMismatchScore = identity.IntentMismatch(svid.Scope, identity.DetectedIntent{
			IntentCategory: meta.IntentCategory,
			Tools:          extractTools(meta),
			Domains:        meta.TargetDomains,
		})
		if span != nil {
			span.SetAttribute("intent_mismatch_score", meta.IntentMismatchScore)
		}
	}

	// Reef A-6: EWMA over OWASP ASI categories. The classifier maps the
	// inspector's signals onto the canonical ASI labels.
	if p.enableReef && p.ewmaTracker != nil {
		subject := meta.SVIDSubject
		if subject == "" && declared != nil {
			subject = declared.AgentID
		}
		if subject != "" {
			hits := classifyASICategories(meta)
			meta.AsiCategoryEwma = p.ewmaTracker.Update(subject, hits)
			if span != nil {
				span.SetAttribute("asi_category_ewma", meta.AsiCategoryEwma)
				if len(hits) > 0 {
					span.SetAttribute("asi_hits", hits)
				}
			}
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

	// Reef A-6: append to the Merkle audit tree. Each ALLOW/DENY/MODIFY/
	// REDIRECT/QUARANTINE/HUMAN_REVIEW verdict becomes a tamper-evident leaf.
	p.appendMerkleLeaf(reqID, "ingress", meta, result, promptText)

	if span != nil {
		span.SetAttribute("action", string(result.Action))
		if result.RuleName != "" {
			span.SetAttribute("policy.rule_id", result.RuleName)
		}
		span.AddEvent("verdict." + string(result.Action))
	}

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

// dispatchSVIDDeny short-circuits the pipeline to a DENY when SVID validation
// fails AND the policy requires SVIDs. Records the audit leaf + OTel event.
func (p *Pipeline) dispatchSVIDDeny(reqID string, ctx context.Context, span otel.Span, meta *inspector.PromptMetadata, declared *metadata.RequestHeaders, ruleName, denyMsg string) *PipelineResult {
	result := policy.RuleResult{
		Matched:     true,
		RuleName:    ruleName,
		Action:      policy.ActionDeny,
		DenyMessage: denyMsg,
	}
	pr := &PipelineResult{
		RequestID:       reqID,
		IngressMetadata: meta,
		IngressResult:   &result,
		DeclaredHeaders: declared,
		Blocked:         true,
		BlockedAt:       "ingress",
		DenyMessage:     denyMsg,
	}
	var agentID string
	if declared != nil {
		agentID = declared.AgentID
	}
	p.auditLogger.Log(audit.Entry{
		RequestID:   reqID,
		Direction:   "ingress",
		Action:      string(policy.ActionDeny),
		RuleName:    ruleName,
		DenyMessage: denyMsg,
		Metadata:    meta,
		AgentID:     agentID,
	})
	p.appendMerkleLeaf(reqID, "ingress", meta, result, "")
	if span != nil {
		span.SetAttribute("action", "DENY")
		span.SetAttribute("policy.rule_id", ruleName)
		span.AddEvent("svid.deny")
	}
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "ingress",
		RequestID: reqID,
		Action:    policy.ActionDeny,
		RuleName:  ruleName,
		Metadata:  meta,
		Blocked:   true,
		DenyMsg:   denyMsg,
	})
	return pr
}

// dispatchRateLimited short-circuits the pipeline with a synthetic DENY when
// the per-identity bucket runs dry.
func (p *Pipeline) dispatchRateLimited(reqID string, ctx context.Context, meta *inspector.PromptMetadata, declared *metadata.RequestHeaders) *PipelineResult {
	msg := fmt.Sprintf("RATE_LIMITED_PER_IDENTITY — subject=%q exceeded its token bucket", meta.SVIDSubject)
	result := policy.RuleResult{
		Matched:     true,
		RuleName:    ReasonRateLimitPerIdent,
		Action:      policy.ActionDeny,
		DenyMessage: msg,
	}
	pr := &PipelineResult{
		RequestID:       reqID,
		IngressMetadata: meta,
		IngressResult:   &result,
		DeclaredHeaders: declared,
		Blocked:         true,
		BlockedAt:       "ingress",
		DenyMessage:     msg,
	}
	var agentID string
	if declared != nil {
		agentID = declared.AgentID
	}
	p.auditLogger.Log(audit.Entry{
		RequestID:   reqID,
		Direction:   "ingress",
		Action:      string(policy.ActionDeny),
		RuleName:    ReasonRateLimitPerIdent,
		DenyMessage: msg,
		Metadata:    meta,
		AgentID:     agentID,
	})
	p.appendMerkleLeaf(reqID, "ingress", meta, result, "")
	p.notify(PipelineEvent{
		Timestamp: time.Now().UTC(),
		Direction: "ingress",
		RequestID: reqID,
		Action:    policy.ActionDeny,
		RuleName:  ReasonRateLimitPerIdent,
		Metadata:  meta,
		Blocked:   true,
		DenyMsg:   msg,
	})
	return pr
}

// appendMerkleLeaf records the verdict into the tamper-evident tree.
// nil-safe (the tree may not be wired).
func (p *Pipeline) appendMerkleLeaf(reqID, direction string, meta *inspector.PromptMetadata, result policy.RuleResult, body string) {
	if p.merkleTree == nil {
		return
	}
	bodyHash := ""
	if body != "" {
		// Only hash bodies up to a sane cap; otherwise we'd bloat audit
		// payloads. The hash is still tamper-evident for the visible portion.
		const max = 4096
		if len(body) > max {
			body = body[:max]
		}
		sum := sha256.Sum256([]byte(body))
		bodyHash = hex.EncodeToString(sum[:])
	}
	_, _ = p.merkleTree.Append(audit.AuditEvent{
		Timestamp:   time.Now().UTC(),
		Direction:   direction,
		RequestID:   reqID,
		SVIDSubject: meta.SVIDSubject,
		RuleID:      result.RuleName,
		Action:      string(result.Action),
		DenyMsg:     result.DenyMessage,
		BodyHash:    bodyHash,
		Metadata: map[string]any{
			"intent_category":         meta.IntentCategory,
			"risk_score":              meta.RiskScore,
			"agent_identity_verified": meta.AgentIdentityVerified,
			"intent_mismatch_score":   meta.IntentMismatchScore,
			"asi_category_ewma":       meta.AsiCategoryEwma,
		},
	})
}

// errorSentinel returns the stable error sentinel name (e.g. "ErrExpired")
// for the SVID error. Falls back to the error message when no sentinel
// matches.
func errorSentinel(err error) string {
	switch {
	case errors.Is(err, identity.ErrExpired):
		return "ErrExpired"
	case errors.Is(err, identity.ErrEmptyToken):
		return "ErrEmptyToken"
	case errors.Is(err, identity.ErrTokenMalformed):
		return "ErrTokenMalformed"
	case errors.Is(err, identity.ErrUnsupportedAlg):
		return "ErrUnsupportedAlg"
	case errors.Is(err, identity.ErrSignatureInvalid):
		return "ErrSignatureInvalid"
	case errors.Is(err, identity.ErrWrongAudience):
		return "ErrWrongAudience"
	case errors.Is(err, identity.ErrMissingClaim):
		return "ErrMissingClaim"
	case errors.Is(err, identity.ErrNotYetValid):
		return "ErrNotYetValid"
	case errors.Is(err, identity.ErrNoIssuerKeys):
		return "ErrNoIssuerKeys"
	default:
		return err.Error()
	}
}

// extractTools returns the set of "tool" names DPI saw the request exercise.
// For v1 this is the union of detected commands + MCP bind target +
// (when present) the heuristic intent label. Empty for benign prompts.
func extractTools(meta *inspector.PromptMetadata) []string {
	tools := make([]string, 0, len(meta.TargetCommands)+1)
	tools = append(tools, meta.TargetCommands...)
	if meta.MCPBindTarget != "" {
		tools = append(tools, "mcp:"+meta.MCPBindTarget)
	}
	return tools
}

// classifyASICategories maps PromptMetadata signals onto OWASP "Top 10 for
// Agentic Applications" categories. The full taxonomy lives in
// docs/30-GLOSSARY.md; this is the v1 heuristic mapping the EWMA tracker
// consumes. The mapping is permissive — multiple categories may fire on a
// single prompt.
func classifyASICategories(meta *inspector.PromptMetadata) []string {
	var cats []string
	if meta.ContainsInjectionPatterns {
		cats = append(cats, "ASI01") // Memory Poisoning (prompt-injection adjacent)
	}
	if meta.ContainsRoleImpersonation {
		cats = append(cats, "ASI07") // Identity Spoofing
		cats = append(cats, "ASI04") // Privilege Compromise
	}
	if meta.ContainsExfiltration || meta.ContainsMarkdownImageWithExternalURL {
		cats = append(cats, "ASI06") // Tool Misuse
	}
	if meta.ContainsCredentials || meta.ContainsPII {
		cats = append(cats, "ASI10") // Capability Abuse / sensitive data
	}
	if meta.ContainsSystemCommands || meta.ContainsMalwareRequest {
		cats = append(cats, "ASI08") // Resource Hijacking
	}
	if meta.MCPBindDecision == mcpsupply.DecisionDeny {
		cats = append(cats, "ASI03") // Cascading Failures (supply chain breach)
	}
	return cats
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
	var span otel.Span
	startedAt := time.Now()
	if p.enableReef && p.otelExporter != nil {
		_, span = p.otelExporter.Start(context.Background(), "reef.pipeline.egress")
		span.SetAttribute("request.id", pr.RequestID)
		defer func() {
			span.SetAttribute("latency_ms", time.Since(startedAt).Milliseconds())
			span.End()
		}()
	}

	meta := p.inspector.Inspect(responseText)
	// Carry the verified SVID subject onto the egress meta so audit + Merkle
	// leaves capture which agent produced the output.
	if pr.IngressMetadata != nil {
		meta.SVIDSubject = pr.IngressMetadata.SVIDSubject
		meta.AgentIdentityVerified = pr.IngressMetadata.AgentIdentityVerified
		meta.AsiCategoryEwma = pr.IngressMetadata.AsiCategoryEwma
		meta.IntentMismatchScore = pr.IngressMetadata.IntentMismatchScore
	}
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

	// Reef A-6: Merkle audit append on egress.
	p.appendMerkleLeaf(pr.RequestID, "egress", meta, result, responseText)

	if span != nil {
		span.SetAttribute("action", string(result.Action))
		if result.RuleName != "" {
			span.SetAttribute("policy.rule_id", result.RuleName)
		}
		span.AddEvent("verdict." + string(result.Action))
	}

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
