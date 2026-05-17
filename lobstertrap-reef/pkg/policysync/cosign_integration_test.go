package policysync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"testing"
)

// TestCosignIntegration_KeyOnDiskRoundTrip exercises the full operator
// workflow: a policy bundle is written to disk, the operator signs it with a
// private key, the verifier loads its trust-rooted public key from disk and
// validates the signature. This is the path cmd/serve.go's hot-reload uses.
func TestCosignIntegration_KeyOnDiskRoundTrip(t *testing.T) {
	dir := t.TempDir()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)

	// Write the public key (PEM-less, raw base64) to disk.
	pubPath := filepath.Join(dir, "policy-signer.pub")
	if err := os.WriteFile(pubPath, []byte(base64.StdEncoding.EncodeToString(pub)), 0644); err != nil {
		t.Fatalf("write pub: %v", err)
	}

	// Write a policy bundle and sign it.
	bundle := []byte(`version: "1.0"
policy_name: "demo"
default_action: ALLOW
ingress_rules:
  - name: block_injection
    priority: 100
    action: DENY
    conditions:
      - field: contains_injection_patterns
        match_type: boolean
        value: true
`)
	bundlePath := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(bundlePath, bundle, 0644); err != nil {
		t.Fatalf("write bundle: %v", err)
	}
	sigB64, err := SignBundle(priv, bundle)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}
	sigPath := bundlePath + ".sig"
	if err := os.WriteFile(sigPath, []byte(sigB64), 0644); err != nil {
		t.Fatalf("write sig: %v", err)
	}

	// Build a verifier from the on-disk pub key and verify the bundle.
	v, err := NewCosignVerifier(pubPath)
	if err != nil {
		t.Fatalf("NewCosignVerifier: %v", err)
	}
	loadedBundle, err := os.ReadFile(bundlePath)
	if err != nil {
		t.Fatalf("read bundle: %v", err)
	}
	loadedSig, err := os.ReadFile(sigPath)
	if err != nil {
		t.Fatalf("read sig: %v", err)
	}
	if err := v.VerifyBundle(loadedBundle, loadedSig); err != nil {
		t.Errorf("VerifyBundle on-disk: %v", err)
	}

	// Tamper with the bundle on disk and re-verify → ErrSignatureMismatch.
	tampered := append([]byte(nil), loadedBundle...)
	tampered[0] ^= 0xff
	if err := v.VerifyBundle(tampered, loadedSig); err == nil {
		t.Errorf("tampered bundle verified — invariant violation")
	}
}
