package pipeline

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// Refinement R-B6 (Phase B Round 1 Batch B):
// Bodies larger than defaults.AuditBodyTruncationBytes are clipped before
// the body_hash is computed, and the leaf MUST carry body_truncated:true
// so downstream verifiers know the hash only covers a prefix.
//
// The two tests below drive the Merkle tree through ProcessIngressWithAuth
// with a sub-cap and a super-cap body and assert the persisted JSONL leaf
// reflects the correct flag.

const minimalPolicyYAML = `
version: "1.0"
policy_name: "body-truncated-test"
default_action: ALLOW
ingress_rules:
  - name: dummy_log
    description: dummy
    priority: 1
    action: LOG
    conditions:
      - field: token_count
        match_type: threshold
        value: 0
`

func TestBodyTruncated_FlagSetForLargeBody(t *testing.T) {
	pol, perr := policy.Parse([]byte(minimalPolicyYAML))
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	t.Cleanup(func() { _ = tree.Close() })

	pipe := NewWithReef(pol, audit.NopLogger(), nil, true).WithMerkleTree(tree)

	// Build a body larger than the truncation cap.
	body := strings.Repeat("A", defaults.AuditBodyTruncationBytes+512)
	_ = pipe.ProcessIngressWithAuth(context.Background(), body, nil, "")

	leaves := readLeaves(t, dir)
	if len(leaves) == 0 {
		t.Fatal("expected at least one Merkle leaf")
	}
	last := leaves[len(leaves)-1]
	if !last.BodyTruncated {
		t.Errorf("expected body_truncated=true on leaf with %d-byte body; got false", len(body))
	}
	if last.BodyHash == "" {
		t.Errorf("expected body_hash to be populated even after truncation")
	}
}

func TestBodyTruncated_FlagAbsentForSmallBody(t *testing.T) {
	pol, perr := policy.Parse([]byte(minimalPolicyYAML))
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	t.Cleanup(func() { _ = tree.Close() })

	pipe := NewWithReef(pol, audit.NopLogger(), nil, true).WithMerkleTree(tree)

	body := "hello reef"
	_ = pipe.ProcessIngressWithAuth(context.Background(), body, nil, "")

	leaves := readLeaves(t, dir)
	if len(leaves) == 0 {
		t.Fatal("expected at least one Merkle leaf")
	}
	last := leaves[len(leaves)-1]
	if last.BodyTruncated {
		t.Errorf("expected body_truncated=false on small body, got true")
	}
}

// readLeaves reads every JSONL leaf written by the Merkle tree under dir
// and returns them in append order.
func readLeaves(t *testing.T, dir string) []audit.AuditEvent {
	t.Helper()
	path := filepath.Join(dir, "events.jsonl")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read events.jsonl: %v", err)
	}
	var out []audit.AuditEvent
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		if line == "" {
			continue
		}
		var ev audit.AuditEvent
		if uerr := json.Unmarshal([]byte(line), &ev); uerr != nil {
			t.Fatalf("unmarshal leaf %q: %v", line, uerr)
		}
		out = append(out, ev)
	}
	return out
}
