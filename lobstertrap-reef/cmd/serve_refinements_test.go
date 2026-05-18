package cmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/rs/zerolog"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
)

// Refinement R-B3: boot-time SVID verifier construction.
//
// The unit tests below exercise the buildSVIDVerifier helper that runServe
// uses to decide whether a node can boot when policy.reef.require_svid=true.
// The runServe-level fail-closed test lives in TestServe_RequireSVID_FailClosedBoot.

func TestBuildSVIDVerifier_MissingDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	v, wired, err := buildSVIDVerifier(dir, "lobstertrap-reef")
	if wired {
		t.Fatalf("expected wired=false for missing dir, got verifier=%v", v)
	}
	if err == nil {
		t.Fatal("expected error for missing issuer keys directory")
	}
	if !strings.Contains(err.Error(), "cannot stat") {
		t.Errorf("error %q should mention 'cannot stat'", err.Error())
	}
}

func TestBuildSVIDVerifier_EmptyConfigDir(t *testing.T) {
	v, wired, err := buildSVIDVerifier("", "lobstertrap-reef")
	if wired {
		t.Fatalf("expected wired=false for empty dir, got verifier=%v", v)
	}
	if err == nil {
		t.Fatal("expected error for empty issuer keys directory")
	}
}

func TestBuildSVIDVerifier_EmptyDirectory(t *testing.T) {
	dir := t.TempDir()
	v, wired, err := buildSVIDVerifier(dir, "lobstertrap-reef")
	if wired {
		t.Fatalf("expected wired=false for empty dir, got verifier=%v", v)
	}
	if err == nil {
		t.Fatal("expected error when directory contains no issuer keys")
	}
}

func TestBuildSVIDVerifier_LoadsRealKey(t *testing.T) {
	dir := t.TempDir()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	pemBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pub}
	pemBytes := pem.EncodeToMemory(pemBlock)
	keyPath := filepath.Join(dir, "issuer-1.pem")
	if err := os.WriteFile(keyPath, pemBytes, 0o644); err != nil {
		t.Fatalf("write key: %v", err)
	}

	v, wired, err := buildSVIDVerifier(dir, "lobstertrap-reef")
	if err != nil {
		t.Fatalf("buildSVIDVerifier: %v", err)
	}
	if !wired {
		t.Fatal("expected wired=true for valid issuer key directory")
	}
	if v == nil {
		t.Fatal("expected verifier")
	}
	if got := v.KeyIDs(); len(got) == 0 {
		t.Errorf("expected at least one loaded key, got %v", got)
	}
}

// Refinement R-B4: ticker goroutine respects ctx.Done().
//
// We start the merkle ticker against a tree (no signing key — so no signing
// happens) with a short interval, cancel the context, and assert the
// goroutine exits within a generous deadline.

func TestRunMerkleSignedRootExport_RespectsContextCancel(t *testing.T) {
	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	defer tree.Close()

	ctx, cancel := context.WithCancel(context.Background())
	logger := zerolog.Nop()

	done := make(chan struct{})
	go func() {
		runMerkleSignedRootExport(ctx, tree, 25*time.Millisecond, logger)
		close(done)
	}()

	// Let one tick happen, then cancel and expect return inside the deadline.
	time.Sleep(60 * time.Millisecond)
	cancel()

	select {
	case <-done:
		// goroutine exited cleanly on ctx cancel — refinement R-B4 verified.
	case <-time.After(500 * time.Millisecond):
		t.Fatal("merkle ticker did not exit within 500ms of context cancellation")
	}
}
