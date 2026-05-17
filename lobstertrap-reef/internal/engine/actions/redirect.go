package actions

import (
	"context"
	"fmt"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// runRedirect resolves the matched rule's redirect band against
// policy.Network.RedirectTargets and emits an Outcome with the upstream URL
// the proxy should route to.
//
// Fallback rules (in order):
//  1. Rule's RedirectTargetBand → policy.Network.RedirectTargets[band]
//  2. Rule's RedirectTargetBand == "" but Dispatcher.redirectFallback set →
//     use the fallback URL (env-supplied REEF_REDIRECT_TARGET)
//  3. Neither configured → return DENY outcome with a clear reason. We do
//     NOT silently allow — a misconfigured REDIRECT rule must visibly fail.
//
// The action emits HTTP 307 Temporary Redirect; the proxy writes a Location
// header to the resolved target. The audit log captures the original target
// (request path) + the redirect target so the Stage UI can render both.
func (d *Dispatcher) runRedirect(_ context.Context, dec Decision) Outcome {
	out := Outcome{Action: policy.ActionRedirect}

	band := dec.Rule.RedirectTargetBand
	target := ""

	if band != "" && d.policy != nil {
		if t, ok := d.policy.Network.RedirectTargets[band]; ok && t != "" {
			target = t
		}
	}
	if target == "" && d.redirectFallback != "" {
		target = d.redirectFallback
		if band == "" {
			band = "fallback"
		}
	}

	if target == "" {
		reason := fmt.Sprintf("rule %q REDIRECT could not resolve a target (band=%q, fallback empty); failing closed to DENY",
			dec.Rule.RuleName, dec.Rule.RedirectTargetBand)
		d.logger.Warn("redirect_no_target",
			"rule", dec.Rule.RuleName,
			"band", dec.Rule.RedirectTargetBand,
			"request_id", dec.RequestID,
		)
		// Fail closed. A REDIRECT without a target is configuration-broken;
		// the safest fallback is DENY so the agent doesn't reach the real
		// upstream with a verdict the policy intended to side-step.
		return Outcome{
			Action:     policy.ActionDeny,
			StatusCode: 451,
			Reason:     reason,
			Err:        fmt.Errorf("redirect: %s", reason),
		}
	}

	out.RedirectTarget = target
	out.RedirectBand = band
	out.StatusCode = 307
	out.Reason = fmt.Sprintf("rule=%q redirected from %q to band=%q target=%q",
		dec.Rule.RuleName, dec.OriginPath, band, target)

	d.logger.Info("redirect_applied",
		"rule", dec.Rule.RuleName,
		"band", band,
		"target", target,
		"origin_path", dec.OriginPath,
		"request_id", dec.RequestID,
	)
	return out
}
