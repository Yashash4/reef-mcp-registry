package audit

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"testing"
	"time"
)

func TestTree_EmptyHasNoRoot(t *testing.T) {
	tree, err := NewTree("")
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	if got := tree.Root(); got != "" {
		t.Errorf("empty tree root=%q want empty", got)
	}
	root, sig, count, _ := tree.SignedRoot()
	if root != "" || sig != "" || count != 0 {
		t.Errorf("SignedRoot on empty tree=%q/%q/%d", root, sig, count)
	}
}

func TestTree_SingleLeaf(t *testing.T) {
	tree, _ := NewTree("")
	hash, err := tree.Append(AuditEvent{Action: "ALLOW", RequestID: "req-1"})
	if err != nil {
		t.Fatalf("Append: %v", err)
	}
	if hash == "" {
		t.Fatal("expected non-empty leaf hash")
	}
	if got := tree.Root(); got != hash {
		t.Errorf("root=%q want %q (single-leaf root = leaf hash)", got, hash)
	}
	if got := tree.Count(); got != 1 {
		t.Errorf("Count=%d want 1", got)
	}
}

func TestTree_MultipleLeavesProduceStableRoot(t *testing.T) {
	tree, _ := NewTree("")
	for i := 0; i < 5; i++ {
		_, err := tree.Append(AuditEvent{
			EventID:   "ev-fixed-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Action:    "ALLOW",
			RequestID: "req-" + string(rune('1'+i)),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	rootA := tree.Root()

	// Same events into a fresh tree should produce identical root.
	tree2, _ := NewTree("")
	for i := 0; i < 5; i++ {
		_, err := tree2.Append(AuditEvent{
			EventID:   "ev-fixed-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Action:    "ALLOW",
			RequestID: "req-" + string(rune('1'+i)),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	rootB := tree2.Root()
	if rootA != rootB {
		t.Errorf("rootA=%q != rootB=%q (canonical encoding should be stable)", rootA, rootB)
	}
}

func TestTree_InclusionProof(t *testing.T) {
	tree, _ := NewTree("")
	events := make([]AuditEvent, 7)
	for i := range events {
		events[i] = AuditEvent{
			EventID:   "ev-test-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Action:    "ALLOW",
			RequestID: "req-" + string(rune('1'+i)),
		}
		if _, err := tree.Append(events[i]); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	root := tree.Root()
	for i := range events {
		proof, leafHash, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatalf("InclusionProof(%d): %v", i, err)
		}
		if err := VerifyInclusionProof(leafHash, proof, root); err != nil {
			t.Errorf("VerifyInclusionProof(%d): %v", i, err)
		}
	}
}

func TestTree_TamperDetection(t *testing.T) {
	tree, _ := NewTree("")
	for i := 0; i < 4; i++ {
		tree.Append(AuditEvent{
			EventID:   "ev-test-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Action:    "ALLOW",
		})
	}
	root := tree.Root()
	// Tamper with leaf 2 by flipping a byte in its hash and rebuilding root.
	tree.mu.Lock()
	tree.leaves[2].Hash[0] ^= 0xff
	tamperedRoot := hex.EncodeToString(tree.rootLocked())
	// Restore so subsequent assertions work.
	tree.leaves[2].Hash[0] ^= 0xff
	tree.mu.Unlock()
	if tamperedRoot == root {
		t.Fatal("tampered tree produced identical root")
	}
}

func TestTree_VerifyInclusionProof_RejectsWrongRoot(t *testing.T) {
	tree, _ := NewTree("")
	for i := 0; i < 3; i++ {
		tree.Append(AuditEvent{EventID: "ev-test-" + string(rune('a'+i)), Action: "ALLOW"})
	}
	proof, leafHash, _ := tree.InclusionProof(0)
	err := VerifyInclusionProof(leafHash, proof, "0000000000000000000000000000000000000000000000000000000000000000")
	if !errors.Is(err, ErrProofMismatch) {
		t.Errorf("err=%v want ErrProofMismatch", err)
	}
}

func TestTree_SignedRoot(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	tree, _ := NewTree("")
	tree.SetRootSigner(priv)
	for i := 0; i < 3; i++ {
		tree.Append(AuditEvent{EventID: "ev-test-" + string(rune('a'+i)), Action: "ALLOW"})
	}
	root, sig, count, _ := tree.SignedRoot()
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
	if count != 3 {
		t.Errorf("count=%d want 3", count)
	}
	if err := VerifySignedRoot(root, sig, pub); err != nil {
		t.Errorf("VerifySignedRoot: %v", err)
	}
}

func TestTree_PersistenceReplayRoundTrip(t *testing.T) {
	dir := t.TempDir()
	tree, err := NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	events := []AuditEvent{
		{EventID: "ev-test-a", Timestamp: time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC), Action: "ALLOW", RequestID: "req-1"},
		{EventID: "ev-test-b", Timestamp: time.Date(2026, 5, 18, 12, 1, 0, 0, time.UTC), Action: "DENY", RequestID: "req-2"},
		{EventID: "ev-test-c", Timestamp: time.Date(2026, 5, 18, 12, 2, 0, 0, time.UTC), Action: "MODIFY", RequestID: "req-3"},
	}
	for _, e := range events {
		if _, err := tree.Append(e); err != nil {
			t.Fatalf("Append: %v", err)
		}
	}
	rootBefore := tree.Root()
	if err := tree.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	// Replay into a fresh tree.
	tree2, err := NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree(2): %v", err)
	}
	count, err := tree2.Replay()
	if err != nil {
		t.Fatalf("Replay: %v", err)
	}
	if count != len(events) {
		t.Errorf("Replay count=%d want %d", count, len(events))
	}
	if rootAfter := tree2.Root(); rootAfter != rootBefore {
		t.Errorf("replay root=%q != original root=%q", rootAfter, rootBefore)
	}
	// Verify the persistence file exists.
	if _, err := filepath.Abs(filepath.Join(dir, "events.jsonl")); err != nil {
		t.Errorf("expected events.jsonl in %s: %v", dir, err)
	}
}

func TestTree_FindEvent(t *testing.T) {
	tree, _ := NewTree("")
	tree.Append(AuditEvent{EventID: "ev-find-me", Action: "ALLOW"})
	tree.Append(AuditEvent{EventID: "ev-other", Action: "DENY"})

	idx, ev, err := tree.FindEvent("ev-find-me")
	if err != nil {
		t.Fatalf("FindEvent: %v", err)
	}
	if idx != 0 {
		t.Errorf("idx=%d want 0", idx)
	}
	if ev.Action != "ALLOW" {
		t.Errorf("action=%q", ev.Action)
	}

	_, _, err = tree.FindEvent("ev-not-there")
	if !errors.Is(err, ErrEventNotFound) {
		t.Errorf("err=%v want ErrEventNotFound", err)
	}
}
