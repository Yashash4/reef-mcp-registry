package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
)

// seedAuditDir lays down N audit events into a fresh JSONL log so the
// signed-root subcommand has real leaves to hash. Returns the dir and the
// current Merkle root for assertions.
func seedAuditDir(t *testing.T, n int) (string, string) {
	t.Helper()
	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	for i := 0; i < n; i++ {
		_, err := tree.Append(audit.AuditEvent{
			EventID:   "ev-root-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 0, i, 0, 0, time.UTC),
			Action:    "ALLOW",
			RequestID: "req-" + string(rune('1'+i)),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	root := tree.Root()
	if err := tree.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return dir, root
}

// writePrivKeyPEM writes a freshly-generated ed25519 private key as a PEM
// block of raw seed bytes — matches the seed-byte parser path in
// policysync.ParsePrivateKey. Returns the path + the public key.
func writePrivKeyPEM(t *testing.T, dir string) (string, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	path := filepath.Join(dir, "audit-signer.key")
	// Write raw private key bytes base64-encoded — also a parser-supported
	// path (Seed or full key).
	b64 := base64.StdEncoding.EncodeToString(priv)
	if err := os.WriteFile(path, []byte(b64), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path, pub
}

func resetAuditRootFlags() {
	auditRootDir = ""
	auditRootPrivKeyPath = ""
	auditRootIndent = false
}

func runAuditSignedRootInTest(t *testing.T) map[string]any {
	t.Helper()
	var buf bytes.Buffer
	cmd := auditRootCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := runAuditSignedRoot(cmd, nil); err != nil {
		t.Fatalf("runAuditSignedRoot: %v\n%s", err, buf.String())
	}
	var out map[string]any
	if err := json.Unmarshal(buf.Bytes(), &out); err != nil {
		t.Fatalf("unmarshal output: %v\nraw: %s", err, buf.String())
	}
	return out
}

func TestAuditSignedRoot_UnsignedWhenNoKey(t *testing.T) {
	resetAuditRootFlags()
	dir, expectedRoot := seedAuditDir(t, 5)
	auditRootDir = dir
	auditRootPrivKeyPath = ""
	// Make sure env vars don't leak in.
	t.Setenv("REEF_AUDIT_SIGNER_PRIV_KEY", "")
	t.Setenv("REEF_POLICY_SIGNER_PRIV_KEY", "")

	out := runAuditSignedRootInTest(t)

	if out["root"].(string) != expectedRoot {
		t.Fatalf("root mismatch: got %v want %v", out["root"], expectedRoot)
	}
	if sig, ok := out["signature"].(string); !ok || sig != "" {
		t.Fatalf("expected empty signature; got %v", out["signature"])
	}
	if signed, ok := out["signed"].(bool); !ok || signed {
		t.Fatalf("expected signed=false; got %v", out["signed"])
	}
	if count, ok := out["count"].(float64); !ok || int(count) != 5 {
		t.Fatalf("expected count=5; got %v", out["count"])
	}
}

func TestAuditSignedRoot_SignedWithKey(t *testing.T) {
	resetAuditRootFlags()
	dir, expectedRoot := seedAuditDir(t, 3)
	keyDir := t.TempDir()
	keyPath, pub := writePrivKeyPEM(t, keyDir)

	auditRootDir = dir
	auditRootPrivKeyPath = keyPath
	t.Setenv("REEF_AUDIT_SIGNER_PRIV_KEY", "")
	t.Setenv("REEF_POLICY_SIGNER_PRIV_KEY", "")

	out := runAuditSignedRootInTest(t)

	if out["root"].(string) != expectedRoot {
		t.Fatalf("root mismatch: got %v want %v", out["root"], expectedRoot)
	}
	sig, ok := out["signature"].(string)
	if !ok || sig == "" {
		t.Fatalf("expected non-empty signature; got %v", out["signature"])
	}
	if signed, _ := out["signed"].(bool); !signed {
		t.Fatalf("expected signed=true; got %v", out["signed"])
	}
	// Verify the signature against the raw decoded root.
	rootBytes, err := hex.DecodeString(expectedRoot)
	if err != nil {
		t.Fatalf("hex decode root: %v", err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(sig)
	if err != nil {
		t.Fatalf("base64 decode sig: %v", err)
	}
	if !ed25519.Verify(pub, rootBytes, sigBytes) {
		t.Fatalf("signature did not verify against the public key")
	}
}

func TestAuditSignedRoot_PicksUpEnvVar(t *testing.T) {
	resetAuditRootFlags()
	dir, expectedRoot := seedAuditDir(t, 2)
	keyDir := t.TempDir()
	keyPath, pub := writePrivKeyPEM(t, keyDir)

	auditRootDir = dir
	auditRootPrivKeyPath = ""
	t.Setenv("REEF_AUDIT_SIGNER_PRIV_KEY", keyPath)
	t.Setenv("REEF_POLICY_SIGNER_PRIV_KEY", "") // ensure precedence is REEF_AUDIT first

	out := runAuditSignedRootInTest(t)

	if out["root"].(string) != expectedRoot {
		t.Fatalf("root mismatch: got %v want %v", out["root"], expectedRoot)
	}
	sig := out["signature"].(string)
	if sig == "" {
		t.Fatalf("expected non-empty signature via env var")
	}
	rootBytes, _ := hex.DecodeString(expectedRoot)
	sigBytes, _ := base64.StdEncoding.DecodeString(sig)
	if !ed25519.Verify(pub, rootBytes, sigBytes) {
		t.Fatalf("env-supplied key did not verify the signature")
	}
}

func TestAuditSignedRoot_EmptyTreeReturnsEmptyRoot(t *testing.T) {
	resetAuditRootFlags()
	dir := t.TempDir()
	auditRootDir = dir
	auditRootPrivKeyPath = ""
	t.Setenv("REEF_AUDIT_SIGNER_PRIV_KEY", "")
	t.Setenv("REEF_POLICY_SIGNER_PRIV_KEY", "")

	out := runAuditSignedRootInTest(t)

	if root, _ := out["root"].(string); root != "" {
		t.Fatalf("expected empty root for empty tree; got %q", root)
	}
	if count, _ := out["count"].(float64); int(count) != 0 {
		t.Fatalf("expected count=0; got %v", out["count"])
	}
}

func TestAuditSignedRoot_BadKeyPath(t *testing.T) {
	resetAuditRootFlags()
	dir, _ := seedAuditDir(t, 1)
	auditRootDir = dir
	auditRootPrivKeyPath = "/this/path/does/not/exist.key"

	var buf bytes.Buffer
	cmd := auditRootCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := runAuditSignedRoot(cmd, nil); err == nil {
		t.Fatalf("expected error for missing key path; got nil")
	}
}
