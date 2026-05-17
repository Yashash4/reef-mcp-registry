package cmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
)

func setupAuditDir(t *testing.T) (string, string, string) {
	t.Helper()
	dir := t.TempDir()
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	defer tree.Close()

	for i := 0; i < 5; i++ {
		_, err := tree.Append(audit.AuditEvent{
			EventID:   "ev-cli-" + string(rune('a'+i)),
			Timestamp: time.Date(2026, 5, 18, 12, i, 0, 0, time.UTC),
			Action:    "ALLOW",
			RequestID: "req-" + string(rune('1'+i)),
		})
		if err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
	}
	return dir, tree.Root(), "ev-cli-c"
}

func TestAuditVerifyCmd_ValidProof(t *testing.T) {
	dir, root, eventID := setupAuditDir(t)
	// Reset CLI flags between runs (cobra holds state across tests).
	auditVerifyEventID = eventID
	auditVerifyRoot = root
	auditVerifyDir = dir
	auditVerifySignature = ""
	auditVerifyPubKeyPath = ""

	var buf bytes.Buffer
	cmd := auditVerifyCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	if err := runAuditVerify(cmd, nil); err != nil {
		t.Fatalf("runAuditVerify: %v", err)
	}
	var report map[string]any
	if err := json.Unmarshal(buf.Bytes(), &report); err != nil {
		t.Fatalf("output is not JSON: %v\n%s", err, buf.String())
	}
	if got, _ := report["verified"].(bool); !got {
		t.Errorf("verified=%v want true", report["verified"])
	}
	if got, _ := report["event_id"].(string); got != eventID {
		t.Errorf("event_id=%q want %q", got, eventID)
	}
}

func TestAuditVerifyCmd_EventNotFound(t *testing.T) {
	dir, _, _ := setupAuditDir(t)
	auditVerifyEventID = "ev-does-not-exist"
	auditVerifyRoot = ""
	auditVerifyDir = dir
	auditVerifySignature = ""
	auditVerifyPubKeyPath = ""
	err := runAuditVerify(auditVerifyCmd, nil)
	if err == nil {
		t.Fatal("expected error for missing event")
	}
	if !strings.Contains(err.Error(), "finding event") {
		t.Errorf("error message=%q", err.Error())
	}
}

func TestAuditVerifyCmd_WrongRootFails(t *testing.T) {
	dir, _, eventID := setupAuditDir(t)
	auditVerifyEventID = eventID
	auditVerifyRoot = "0000000000000000000000000000000000000000000000000000000000000000"
	auditVerifyDir = dir
	auditVerifySignature = ""
	auditVerifyPubKeyPath = ""
	err := runAuditVerify(auditVerifyCmd, nil)
	if err == nil {
		t.Fatal("expected error for wrong root")
	}
	if !strings.Contains(err.Error(), "inclusion proof failed") {
		t.Errorf("error=%q", err.Error())
	}
}

func TestAuditVerifyCmd_WithSignedRoot(t *testing.T) {
	dir, _, eventID := setupAuditDir(t)
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	// Sign the tree's root via a fresh tree (replay).
	tree, err := audit.NewTree(dir)
	if err != nil {
		t.Fatalf("NewTree: %v", err)
	}
	defer tree.Close()
	if _, err := tree.Replay(); err != nil {
		t.Fatalf("Replay: %v", err)
	}
	tree.SetRootSigner(priv)
	root, sig, _, _ := tree.SignedRoot()

	// Write the pub key to a file.
	pubPath := filepath.Join(dir, "signer.pub")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0644); err != nil {
		t.Fatalf("write pub key: %v", err)
	}

	auditVerifyEventID = eventID
	auditVerifyRoot = root
	auditVerifyDir = dir
	auditVerifySignature = sig
	auditVerifyPubKeyPath = pubPath
	var buf bytes.Buffer
	cmd := auditVerifyCmd
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	if err := runAuditVerify(cmd, nil); err != nil {
		t.Fatalf("runAuditVerify: %v\n%s", err, buf.String())
	}
}
