package actions

import (
	"context"
	"fmt"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine"
)

// runQuarantine persists the request/response pair to the JSONL store and
// returns a structured outcome with the quarantine ID. The proxy reads the
// outcome and:
//   - Emits HTTP 451 Unavailable For Legal Reasons (semantically apt — the
//     conversation is being held for a human reviewer's adjudication)
//   - Adds `Quarantine-ID: <id>` header
//   - Returns a JSON envelope explaining the hold + how to query status
//
// The action never silently swallows persistence errors; if the store can't
// be written to, the outcome carries the error and the pipeline falls back
// to DENY so the conversation doesn't proceed unaudited.
func (d *Dispatcher) runQuarantine(_ context.Context, dec Decision) Outcome {
	out := Outcome{Action: policy.ActionQuarantine, StatusCode: 451}

	if d.store == nil {
		// Defensive — NewDispatcher rejects nil stores, but keep the guard.
		out.Err = fmt.Errorf("actions/quarantine: no store configured (rule=%q)", dec.Rule.RuleName)
		out.Action = policy.ActionDeny
		out.Reason = "quarantine store unavailable; failing closed"
		return out
	}

	ev := quarantine.Event{
		AgentID:        dec.AgentID,
		ConversationID: dec.ConvID,
		PolicyRuleID:   dec.Rule.RuleName,
		Reason:         buildQuarantineReason(dec),
		Status:         quarantine.StatusPending,
	}
	// One body is always present — ingress holds the prompt, egress holds
	// the response. We populate both fields so reviewers see whichever leg
	// fired without ambiguity.
	if dec.Direction == DirectionIngress {
		ev.RequestBody = dec.Body
	} else {
		ev.ResponseBody = dec.Body
	}

	persisted, err := d.store.Persist(ev)
	if err != nil {
		d.logger.Error("quarantine_persist_failed", err,
			"rule", dec.Rule.RuleName,
			"request_id", dec.RequestID,
		)
		out.Err = fmt.Errorf("actions/quarantine: persist: %w", err)
		out.Action = policy.ActionDeny
		out.Reason = fmt.Sprintf("quarantine persist failed: %v", err)
		return out
	}

	out.QuarantineID = persisted.ID
	out.QuarantineEvent = &persisted
	out.Reason = fmt.Sprintf("rule=%q quarantined event=%s direction=%s", dec.Rule.RuleName, persisted.ID, dec.Direction)

	d.logger.Info("quarantine_held",
		"rule", dec.Rule.RuleName,
		"quarantine_id", persisted.ID,
		"direction", string(dec.Direction),
		"request_id", dec.RequestID,
	)
	return out
}

func buildQuarantineReason(dec Decision) string {
	if dec.Rule.DenyMessage != "" {
		return dec.Rule.DenyMessage
	}
	return fmt.Sprintf("policy rule %q triggered QUARANTINE on %s", dec.Rule.RuleName, dec.Direction)
}
