package actions

import (
	"context"
	"fmt"
	"strings"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// Recognised modify strategies. Documented in the policy YAML schema:
//
//   - StrategyStripMarkdownImagesToUntrustedDomains — runs the markdown-exfil
//     heuristic against the egress body, strips every markdown image whose
//     destination host is not in policy.Network.AllowedDomains, replacing
//     the image with a `[REDACTED: ...]` marker. Mirrors the reference
//     implementation at victim/app/lib/exfil.ts.
//
//   - StrategyRedactBareURLsWithSecretFragments — runs the same heuristic
//     but only acts on bare URLs whose query string contains a credential
//     fragment (sk-, api_key=, ghp_, JWT-shape, etc.). Leaves markdown
//     images alone.
//
// Unknown strategies degrade to LOG with a structured warning rather than
// silently passing the body through (would mask a misconfiguration) or
// silently rewriting under a default strategy (would surprise operators).
const (
	StrategyStripMarkdownImagesToUntrustedDomains = "strip_markdown_images_to_untrusted_domains"
	StrategyRedactBareURLsWithSecretFragments     = "redact_bare_urls_with_secret_fragments"
)

// runModify applies the rule's modify_strategy to the body and returns the
// rewritten text. The pipeline replaces the egress body with this and forwards
// the (rewritten) response to the caller.
//
// MODIFY never short-circuits the response — even when no edits land, the
// outcome's Action remains MODIFY so the audit log records WHY the rule
// matched. Edits=0 + Modified=false is a legitimate "matched but found
// nothing to rewrite" outcome.
func (d *Dispatcher) runModify(_ context.Context, dec Decision) Outcome {
	out := Outcome{
		Action: policy.ActionModify,
	}
	if dec.Direction != DirectionEgress {
		// MODIFY on ingress is conceptually valid (e.g., redacting a PII
		// substring from a prompt before it reaches the model) but is not
		// in A-4's scope. We surface an explicit error so policies that
		// declare a MODIFY ingress rule today are visible in audits rather
		// than silently no-op'ing.
		out.Err = fmt.Errorf("actions/modify: ingress MODIFY not supported in A-4 scope (rule=%q)", dec.Rule.RuleName)
		return out
	}

	strategy := dec.Rule.ModifyStrategy
	if strategy == "" {
		strategy = StrategyStripMarkdownImagesToUntrustedDomains
	}

	candidates := d.modifyCandidatesFor(strategy, dec)

	if len(candidates) == 0 {
		// No matching candidates — the rule matched on a soft predicate that
		// the heuristic doesn't endorse. Audit captures the rule + zero
		// edits and the body is returned unchanged.
		d.logger.Info("modify_no_candidates",
			"rule", dec.Rule.RuleName,
			"strategy", strategy,
			"request_id", dec.RequestID,
		)
		out.RewrittenBody = dec.Body
		out.Reason = fmt.Sprintf("matched rule %q with strategy %q but heuristic found no candidates", dec.Rule.RuleName, strategy)
		out.ModificationReason = out.Reason
		return out
	}

	rewritten, edits := inspector.StripMarkdownExfil(dec.Body, candidates)
	out.RewrittenBody = rewritten
	out.Edits = edits
	out.Modified = edits > 0
	out.ModificationReason = buildModificationReason(dec.Rule.RuleName, strategy, candidates, edits)
	out.Reason = out.ModificationReason

	d.logger.Info("modify_applied",
		"rule", dec.Rule.RuleName,
		"strategy", strategy,
		"request_id", dec.RequestID,
		"edits", edits,
	)
	return out
}

// modifyCandidatesFor returns the subset of inspector candidates the chosen
// strategy is responsible for stripping. The inspector pre-populates
// dec.Meta.ExfilCandidates for the default heuristic; we may need to re-run
// the heuristic with caller-supplied extra secret literals so the MODIFY
// action sees them even when the global Inspector instance didn't.
func (d *Dispatcher) modifyCandidatesFor(strategy string, dec Decision) []inspector.ExfilCandidate {
	all := dec.Meta.ExfilCandidates
	if len(d.modifyExtraSecrets) > 0 {
		// Re-run with the extras so caller-known secrets get flagged even
		// when the inspector wasn't pre-configured with them.
		all = inspector.DetectMarkdownExfil(dec.Body, inspector.MarkdownExfilOptions{
			TrustedDomains:       d.policy.Network.AllowedDomains,
			ExtraSecretFragments: d.modifyExtraSecrets,
		})
	}

	switch strategy {
	case StrategyStripMarkdownImagesToUntrustedDomains:
		var out []inspector.ExfilCandidate
		for _, c := range all {
			if c.IsMarkdownImage {
				out = append(out, c)
			}
		}
		return out
	case StrategyRedactBareURLsWithSecretFragments:
		var out []inspector.ExfilCandidate
		for _, c := range all {
			if !c.IsMarkdownImage && c.MatchedFragment != "" {
				out = append(out, c)
			}
		}
		return out
	default:
		// Unknown strategy — surface in logs but do not rewrite. Keeps
		// audits honest; operators see a real warning, not a silent skip.
		d.logger.Warn("modify_unknown_strategy",
			"rule", dec.Rule.RuleName,
			"strategy", strategy,
		)
		return nil
	}
}

// buildModificationReason returns a single human-readable string that
// summarises every edit performed. The shape is `strategy=X edits=N hosts=[a,b]`.
// Mirrored into the audit entry's deny_message field so the Stage UI can
// surface it without parsing structured fields.
func buildModificationReason(ruleName, strategy string, cs []inspector.ExfilCandidate, edits int) string {
	hosts := make([]string, 0, len(cs))
	seen := make(map[string]struct{})
	for _, c := range cs {
		if _, dup := seen[c.Host]; dup {
			continue
		}
		seen[c.Host] = struct{}{}
		if c.Host == "" {
			hosts = append(hosts, "unknown")
		} else {
			hosts = append(hosts, c.Host)
		}
	}
	return fmt.Sprintf("rule=%q strategy=%q edits=%d hosts=[%s]", ruleName, strategy, edits, strings.Join(hosts, ","))
}
