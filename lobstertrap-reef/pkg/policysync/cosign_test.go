package policysync

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"testing"
)

func TestVerifyBundle(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen other: %v", err)
	}

	bundle := []byte(`{"version":"1.0","policy_name":"default","ingress_rules":[{"name":"block_credentials"}]}`)
	sigB64, err := SignBundle(priv, bundle)
	if err != nil {
		t.Fatalf("SignBundle: %v", err)
	}

	t.Run("valid_signature_passes", func(t *testing.T) {
		v, err := NewCosignVerifierWithKeys(pub)
		if err != nil {
			t.Fatalf("NewCosignVerifier: %v", err)
		}
		if err := v.VerifyBundle(bundle, []byte(sigB64)); err != nil {
			t.Errorf("VerifyBundle valid: %v", err)
		}
	})

	t.Run("tampered_bundle_fails", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(pub)
		tampered := append([]byte(nil), bundle...)
		tampered[0] ^= 0xff
		err := v.VerifyBundle(tampered, []byte(sigB64))
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("err=%v want ErrSignatureMismatch", err)
		}
	})

	t.Run("untrusted_key_fails", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(otherPub)
		err := v.VerifyBundle(bundle, []byte(sigB64))
		if !errors.Is(err, ErrSignatureMismatch) {
			t.Errorf("err=%v want ErrSignatureMismatch (signature is well-formed but no trusted key matches)", err)
		}
	})

	t.Run("malformed_signature_fails", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(pub)
		err := v.VerifyBundle(bundle, []byte("@@not-base64@@"))
		if !errors.Is(err, ErrBundleParse) {
			t.Errorf("err=%v want ErrBundleParse", err)
		}
	})

	t.Run("empty_bundle_fails", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(pub)
		err := v.VerifyBundle(nil, []byte(sigB64))
		if !errors.Is(err, ErrBundleParse) {
			t.Errorf("err=%v want ErrBundleParse", err)
		}
	})

	t.Run("multi_key_trust_root_matches_any", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(otherPub, pub)
		if err := v.VerifyBundle(bundle, []byte(sigB64)); err != nil {
			t.Errorf("multi-key verify: %v", err)
		}
	})

	t.Run("raw_64_byte_signature_accepted", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(pub)
		rawSig, err := base64.StdEncoding.DecodeString(sigB64)
		if err != nil {
			t.Fatalf("decode sigB64: %v", err)
		}
		if err := v.VerifyBundle(bundle, rawSig); err != nil {
			t.Errorf("VerifyBundle raw: %v", err)
		}
	})

	t.Run("nil_signature_fails", func(t *testing.T) {
		v, _ := NewCosignVerifierWithKeys(pub)
		err := v.VerifyBundle(bundle, nil)
		if !errors.Is(err, ErrBundleParse) {
			t.Errorf("err=%v want ErrBundleParse", err)
		}
	})
}

func TestNewCosignVerifier_NoKeysErrors(t *testing.T) {
	_, err := NewCosignVerifierWithKeys()
	if !errors.Is(err, ErrNoTrustRoot) {
		t.Errorf("err=%v want ErrNoTrustRoot", err)
	}
}

func TestParsePublicKey_PEMAndRawBase64(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	// Raw base64.
	b64 := base64.StdEncoding.EncodeToString(pub)
	got, err := ParsePublicKey([]byte(b64))
	if err != nil {
		t.Fatalf("ParsePublicKey base64: %v", err)
	}
	if string(got) != string(pub) {
		t.Errorf("ParsePublicKey base64 mismatch")
	}
}

func TestParsePrivateKey_RawSeed(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	seedB64 := base64.StdEncoding.EncodeToString(priv.Seed())
	got, err := ParsePrivateKey([]byte(seedB64))
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	if string(got) != string(priv) {
		t.Errorf("ParsePrivateKey roundtrip mismatch")
	}
}
