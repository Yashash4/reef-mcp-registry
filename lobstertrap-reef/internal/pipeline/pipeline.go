package pipeline

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/metadata"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
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
type Pipeline struct {
	inspector     *inspector.Inspector
	ingressTable  *policy.MatchActionTable
	egressTable   *policy.MatchActionTable
	deniedDomains []string
	auditLogger   *audit.Logger

	observerMu sync.RWMutex
	observers  []EventObserver
}

// ReasonBlockedDeniedDomain is the synthetic rule name emitted when egress
// is denied because the model output references a host on the policy's
// network.denied_domains list. Surfaced via PipelineResult.EgressResult.RuleName
// so existing observers and audit consumers can route on it.
const ReasonBlockedDeniedDomain = "blocked_denied_domain"

// New creates a new Pipeline from a loaded policy.
func New(pol *policy.Policy, auditLogger *audit.Logger) *Pipeline {
	ingress, egress := policy.BuildTables(pol)
	return &Pipeline{
		inspector:     inspector.New(),
		ingressTable:  ingress,
		egressTable:   egress,
		deniedDomains: append([]string(nil), pol.Network.DeniedDomains...),
		auditLogger:   auditLogger,
	}
}

// ProcessIngress inspects a prompt and evaluates ingress rules.
// declared may be nil if the agent didn't send _lobstertrap headers.
func (p *Pipeline) ProcessIngress(promptText string, declared *metadata.RequestHeaders) *PipelineResult {
	reqID := fmt.Sprintf("req-%d", requestCounter.Add(1))

	meta := p.inspector.Inspect(promptText)
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

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine {
		pr.Blocked = true
		pr.BlockedAt = "ingress"
		pr.DenyMessage = result.DenyMessage
	}

	// Extract agent ID for audit logging
	var agentID string
	if declared != nil {
		agentID = declared.AgentID
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

	if result.Action == policy.ActionDeny || result.Action == policy.ActionQuarantine {
		pr.Blocked = true
		pr.BlockedAt = "egress"
		pr.DenyMessage = result.DenyMessage
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
