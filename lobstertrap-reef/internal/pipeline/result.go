package pipeline

import (
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/engine/actions"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/metadata"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// PipelineResult captures the full decision chain for a single request.
//
// Reef extensions (A-4): IngressAction / EgressAction carry the structured
// outcome of the Reef action dispatcher. They are nil when Reef is off or
// the matching rule's action was ALLOW/DENY/LOG. The proxy layer reads these
// to shape the HTTP response (rewrite body, 307, 451, 202) — the pipeline
// itself only records the outcome and updates the audit log.
type PipelineResult struct {
	RequestID       string                   `json:"request_id"`
	IngressMetadata *inspector.PromptMetadata `json:"ingress_metadata,omitempty"`
	IngressResult   *policy.RuleResult       `json:"ingress_result"`
	IngressAction   *actions.Outcome         `json:"ingress_action,omitempty"`
	EgressMetadata  *inspector.PromptMetadata `json:"egress_metadata,omitempty"`
	EgressResult    *policy.RuleResult       `json:"egress_result,omitempty"`
	EgressAction    *actions.Outcome         `json:"egress_action,omitempty"`
	Blocked         bool                     `json:"blocked"`
	BlockedAt       string                   `json:"blocked_at,omitempty"` // "ingress" or "egress"
	DenyMessage     string                   `json:"deny_message,omitempty"`
	// EgressBody is the (possibly rewritten) text the proxy should forward
	// to the caller. Populated by ProcessEgress; ALLOW/LOG verdicts leave it
	// equal to the original response. MODIFY verdicts replace it with the
	// rewritten body.
	EgressBody      string                   `json:"egress_body,omitempty"`
	DeclaredHeaders *metadata.RequestHeaders `json:"declared_headers,omitempty"`
	Mismatches      []metadata.Mismatch      `json:"mismatches,omitempty"`
}

// IsBlocked returns true if the request was blocked at any stage.
func (r *PipelineResult) IsBlocked() bool {
	return r.Blocked
}

// ShouldForward returns true if the request should be forwarded to the backend.
// REDIRECT and QUARANTINE and HUMAN_REVIEW all short-circuit the upstream call;
// only ALLOW / LOG / MODIFY continue to the model.
func (r *PipelineResult) ShouldForward() bool {
	if r.IngressResult == nil {
		return true
	}
	switch r.IngressResult.Action {
	case policy.ActionDeny, policy.ActionQuarantine, policy.ActionRedirect, policy.ActionHumanReview:
		return false
	}
	return true
}

// NeedsHumanReview returns true if any stage flagged HUMAN_REVIEW.
func (r *PipelineResult) NeedsHumanReview() bool {
	if r.IngressResult != nil && r.IngressResult.Action == policy.ActionHumanReview {
		return true
	}
	if r.EgressResult != nil && r.EgressResult.Action == policy.ActionHumanReview {
		return true
	}
	return false
}

// IsRedirected reports whether either stage emitted a REDIRECT outcome.
func (r *PipelineResult) IsRedirected() bool {
	if r.IngressAction != nil && r.IngressAction.Action == policy.ActionRedirect {
		return true
	}
	if r.EgressAction != nil && r.EgressAction.Action == policy.ActionRedirect {
		return true
	}
	return false
}

// IsQuarantined reports whether either stage emitted a QUARANTINE outcome
// with a non-empty quarantine ID.
func (r *PipelineResult) IsQuarantined() bool {
	if r.IngressAction != nil && r.IngressAction.QuarantineID != "" {
		return true
	}
	if r.EgressAction != nil && r.EgressAction.QuarantineID != "" {
		return true
	}
	return false
}

// BuildResponseHeaders assembles the full Lobster Trap response headers
// from this pipeline result.
func (r *PipelineResult) BuildResponseHeaders() *metadata.ResponseHeaders {
	rh := &metadata.ResponseHeaders{
		RequestID: r.RequestID,
		Verdict:   r.overallVerdict(),
	}

	// Ingress report
	if r.IngressResult != nil {
		rh.Ingress = &metadata.IngressReport{
			Declared:   r.DeclaredHeaders,
			Detected:   r.IngressMetadata,
			Mismatches: r.Mismatches,
			Action:     r.IngressResult.Action,
			RuleName:   r.IngressResult.RuleName,
		}
		if rh.Ingress.Mismatches == nil {
			rh.Ingress.Mismatches = []metadata.Mismatch{}
		}
	}

	// Egress report
	if r.EgressResult != nil {
		rh.Egress = &metadata.EgressReport{
			Detected: r.EgressMetadata,
			Action:   r.EgressResult.Action,
			RuleName: r.EgressResult.RuleName,
		}
	}

	return rh
}

// overallVerdict returns the top-level verdict string.
func (r *PipelineResult) overallVerdict() string {
	if r.Blocked {
		return "DENY"
	}
	if r.NeedsHumanReview() {
		return "HUMAN_REVIEW"
	}
	return "ALLOW"
}
