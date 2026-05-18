package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// TestMerkleIntegration_AppendAndProve drives a couple of pipeline calls and
// then proves the inclusion of the first verdict's leaf against the signed
// root. End-to-end exercise of A-6 deliverable 4.
func TestMerkleIntegration_AppendAndProve(t *testing.T) {
	src := `
version: "1.0"
policy_name: "merkle-integration"
default_action: ALLOW
ingress_rules:
  - name: dummy
    description: dummy
    priority: 1
    action: LOG
    conditions:
      - field: token_count
        match_type: threshold
        value: 0
`
	pol, _ := policy.Parse([]byte(src))

	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	defer tree.Close()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tree.SetRootSigner(priv)

	pipe := NewWithReef(pol, audit.NopLogger(), nil, true).WithMerkleTree(tree)

	// 3 ingress calls + 1 egress call → 4 leaves.
	ctx := context.Background()
	pr1 := pipe.ProcessIngressWithAuth(ctx, "hello reef", nil, "")
	pipe.ProcessEgress(ctx, pr1, "hi, how can I help?")
	pipe.ProcessIngressWithAuth(ctx, "how are you?", nil, "")
	pipe.ProcessIngressWithAuth(ctx, "thanks!", nil, "")

	if got := tree.Count(); got != 4 {
		t.Errorf("Count=%d want 4", got)
	}

	// Find the first leaf's eventID (it was generated server-side).
	root, sig, count, _ := tree.SignedRoot()
	if sig == "" {
		t.Error("expected signed root")
	}
	if count != 4 {
		t.Errorf("signed count=%d", count)
	}

	// Verify the signature against the public key.
	if err := audit.VerifySignedRoot(root, sig, pub); err != nil {
		t.Errorf("VerifySignedRoot: %v", err)
	}

	// Pull an inclusion proof for leaf 0 and verify it rebuilds the root.
	proof, leafHash, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatalf("InclusionProof: %v", err)
	}
	if err := audit.VerifyInclusionProof(leafHash, proof, root); err != nil {
		t.Errorf("VerifyInclusionProof: %v", err)
	}
}
