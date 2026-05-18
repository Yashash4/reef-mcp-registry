package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// stubLogger is a no-op actions.Logger for the test surface.
type stubLogger struct{}

func (stubLogger) Warn(string, ...any)         {}
func (stubLogger) Info(string, ...any)         {}
func (stubLogger) Error(string, error, ...any) {}

func TestPolicyApplier_HotReloadSwapsRules(t *testing.T) {
	initial := &policy.Policy{
		Version:    "1.0",
		PolicyName: "initial",
		DefaultAction: policy.ActionAllow,
		IngressRules: []policy.GuardRule{
			{
				Name:     "rule-a",
				Priority: 1,
				Action:   policy.ActionLog,
				Conditions: []policy.MatchCondition{
					{Field: "intent_category", MatchType: policy.MatchContains, Value: "code"},
				},
			},
		},
	}
	app := newPolicyApplier(initial, stubLogger{})

	newYAML := []byte(`version: "1.0"
policy_name: "hot-reloaded"
default_action: ALLOW
ingress_rules:
  - name: block_magic_word
    description: "test magic word"
    priority: 999
    action: DENY
    deny_message: "[REEF] magic word blocked"
    conditions:
      - field: intent_category
        match_type: contains
        value: "magic_word_xyz"
`)
	if err := app.Apply(context.Background(), "bundle-1", "v2", newYAML); err != nil {
		t.Fatalf("Apply failed: %v", err)
	}
	if app.AppliedCount() != 1 {
		t.Fatalf("AppliedCount = %d, want 1", app.AppliedCount())
	}
	if initial.PolicyName != "hot-reloaded" {
		t.Fatalf("PolicyName not swapped: %s", initial.PolicyName)
	}
	if len(initial.IngressRules) != 1 || initial.IngressRules[0].Name != "block_magic_word" {
		t.Fatalf("rule swap failed: %+v", initial.IngressRules)
	}
}

func TestPolicyApplier_RejectsEmptyYAML(t *testing.T) {
	p := &policy.Policy{Version: "1.0", PolicyName: "n"}
	app := newPolicyApplier(p, stubLogger{})
	err := app.Apply(context.Background(), "bundle-1", "v1", []byte{})
	if err == nil {
		t.Fatal("expected error for empty YAML")
	}
	if !strings.Contains(err.Error(), "empty") {
		t.Fatalf("expected 'empty' in error, got: %v", err)
	}
	if app.AppliedCount() != 0 {
		t.Fatalf("AppliedCount = %d, want 0", app.AppliedCount())
	}
}

func TestPolicyApplier_RejectsMalformedYAML(t *testing.T) {
	p := &policy.Policy{Version: "1.0", PolicyName: "n"}
	app := newPolicyApplier(p, stubLogger{})
	// Missing required version + policy_name fields. The loader's validate
	// step rejects this, so Apply must surface the error and NOT swap the
	// active policy.
	bad := []byte("ingress_rules: not-a-list\n")
	err := app.Apply(context.Background(), "bundle-1", "v1", bad)
	if err == nil {
		t.Fatal("expected error for malformed YAML")
	}
	if app.AppliedCount() != 0 {
		t.Fatalf("AppliedCount = %d, want 0", app.AppliedCount())
	}
}

func TestPolicyApplier_OnApplyHookFires(t *testing.T) {
	p := &policy.Policy{Version: "1.0", PolicyName: "n", DefaultAction: policy.ActionAllow}
	app := newPolicyApplier(p, stubLogger{})
	var seenVersion string
	app.SetOnApply(func(v string) { seenVersion = v })
	yaml := []byte(`version: "1.0"
policy_name: "n2"
default_action: ALLOW
`)
	if err := app.Apply(context.Background(), "bundle-1", "v9", yaml); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	if seenVersion != "v9" {
		t.Fatalf("hook saw %q, want v9", seenVersion)
	}
}
