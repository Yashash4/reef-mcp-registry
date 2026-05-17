// Package policysync — Sigstore-cosign-style offline verification for signed
// policy bundles.
//
// Reef operators sign policy bundles offline with ed25519 (D-010 — no live
// Rekor anchoring in v1). Reef nodes verify the bundle's detached signature
// against a trust-rooted public key before applying.
//
// Wire format: signature is the ed25519 raw 64-byte sign over SHA-256 of the
// bundle bytes (matching `cosign sign-blob --key ed25519` semantics). We use
// SHA-256 instead of signing the bundle bytes directly so the operator can
// hand operators an out-of-band hash to compare against without needing the
// full bundle.
//
// The cosign CLI's signature subcommand emits the signature as a single
// base64-encoded line. We accept either raw 64-byte ed25519 signatures or
// base64-encoded ones — operators sometimes copy/paste through Slack and
// the bytes get re-encoded.
//
// Fail-closed contract:
//   - Untrusted key → ErrUntrustedKey
//   - Signature mismatch → ErrSignatureMismatch
//   - Malformed signature/bundle → ErrBundleParse
//
// The cmd/serve.go hot-reload path is required to KEEP the old policy active
// if VerifyBundle returns any error. The CLI subcommand `lobstertrap policy
// sign` (sibling file audit_verify.go in cmd/lobstertrap/) signs bundles
// using REEF_POLICY_SIGNER_PRIV_KEY for the operator workflow demo.
package policysync

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"strings"
)

// Errors returned by VerifyBundle. Stable values for tests + audit grep.
var (
	ErrSignatureMismatch = errors.New("policysync: bundle signature does not verify against trusted key")
	ErrUntrustedKey      = errors.New("policysync: signer's public key is not in the trust root")
	ErrBundleParse       = errors.New("policysync: bundle or signature could not be parsed")
	ErrNoTrustRoot       = errors.New("policysync: no trusted public key loaded")
)

// Verifier is the contract callers (cmd/serve.go's hot-reload watcher) use.
type Verifier interface {
	VerifyBundle(bundle []byte, signature []byte) error
}

// CosignVerifier is the production verifier. It holds the operator's trusted
// public key (loaded from REEF_POLICY_SIGNER_PUB_KEY at startup) and verifies
// detached signatures against the SHA-256 hash of the bundle bytes.
//
// Multiple trusted keys are supported via TrustedKeys() — a signature is
// accepted if it verifies against any of them. Useful for key rotation
// without downtime.
type CosignVerifier struct {
	trusted []ed25519.PublicKey
}

// NewCosignVerifier builds a verifier from one or more PEM-encoded public
// keys read from disk. At least one key MUST load successfully.
func NewCosignVerifier(keyPaths ...string) (*CosignVerifier, error) {
	if len(keyPaths) == 0 {
		return nil, ErrNoTrustRoot
	}
	v := &CosignVerifier{}
	for _, p := range keyPaths {
		data, err := os.ReadFile(p)
		if err != nil {
			return nil, fmt.Errorf("policysync: read key %q: %w", p, err)
		}
		pub, err := ParsePublicKey(data)
		if err != nil {
			return nil, fmt.Errorf("policysync: parse key %q: %w", p, err)
		}
		v.trusted = append(v.trusted, pub)
	}
	return v, nil
}

// NewCosignVerifierWithKeys builds a verifier from in-memory ed25519 public
// keys. Used by tests.
func NewCosignVerifierWithKeys(keys ...ed25519.PublicKey) (*CosignVerifier, error) {
	if len(keys) == 0 {
		return nil, ErrNoTrustRoot
	}
	v := &CosignVerifier{}
	v.trusted = append(v.trusted, keys...)
	return v, nil
}

// VerifyBundle checks that the signature was produced by one of the trust-
// rooted keys over the SHA-256 of the bundle.
//
// The implementation is purposefully simple: hash, verify, return. The
// "signature is over the SHA-256 hash" choice matches `cosign sign-blob`
// semantics for detached blob signatures. The signature input may be either
// raw 64-byte ed25519 or base64-encoded — both shapes appear in operator
// workflows.
func (v *CosignVerifier) VerifyBundle(bundle []byte, signature []byte) error {
	if len(v.trusted) == 0 {
		return ErrNoTrustRoot
	}
	if len(bundle) == 0 {
		return fmt.Errorf("%w: empty bundle", ErrBundleParse)
	}
	sig, err := decodeSignature(signature)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrBundleParse, err)
	}
	if len(sig) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature has %d bytes (expected %d)", ErrBundleParse, len(sig), ed25519.SignatureSize)
	}
	hash := sha256.Sum256(bundle)
	for _, pub := range v.trusted {
		if ed25519.Verify(pub, hash[:], sig) {
			return nil
		}
	}
	// If we can decode the signature but no trusted key verifies it, this is
	// either a tampered bundle (signature was computed for different bytes)
	// or a signature from an untrusted key. Distinguish by checking whether
	// the signature is well-formed but just doesn't match: ErrSignatureMismatch
	// covers both — the operator action is the same (refuse the bundle).
	return ErrSignatureMismatch
}

// TrustedKeys returns a snapshot of the trust root for diagnostics.
func (v *CosignVerifier) TrustedKeys() []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(v.trusted))
	copy(out, v.trusted)
	return out
}

// decodeSignature normalises the input as raw ed25519 bytes.
func decodeSignature(sig []byte) ([]byte, error) {
	if len(sig) == ed25519.SignatureSize {
		return sig, nil
	}
	// Trim trailing whitespace from base64 payloads.
	trimmed := strings.TrimSpace(string(sig))
	if trimmed == "" {
		return nil, fmt.Errorf("empty signature")
	}
	if decoded, err := base64.StdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawStdEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	if decoded, err := base64.RawURLEncoding.DecodeString(trimmed); err == nil {
		return decoded, nil
	}
	return nil, fmt.Errorf("signature is %d bytes, not %d, and not valid base64", len(sig), ed25519.SignatureSize)
}

// ParsePublicKey accepts PEM-encoded ed25519 keys (PKIX) or base64 raw 32
// bytes. Identical to the identity package's parser; duplicated here so the
// two packages don't have to share internals.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ek, ok := pub.(ed25519.PublicKey); ok {
				return ek, nil
			}
			return nil, fmt.Errorf("PEM block is not ed25519 (type=%T)", pub)
		}
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
		return nil, fmt.Errorf("PEM block could not be parsed as ed25519")
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty key payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("not PEM and not base64: %v", err)
		}
	}
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	if pub, err := x509.ParsePKIXPublicKey(decoded); err == nil {
		if ek, ok := pub.(ed25519.PublicKey); ok {
			return ek, nil
		}
	}
	return nil, fmt.Errorf("decoded key has size %d (expected %d)", len(decoded), ed25519.PublicKeySize)
}

// ParsePrivateKey accepts PEM-encoded ed25519 private keys (PKCS#8) or
// raw-bytes seed (32 or 64 bytes) base64-encoded. Used by the CLI sign
// subcommand.
func ParsePrivateKey(data []byte) (ed25519.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		if priv, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
			if ek, ok := priv.(ed25519.PrivateKey); ok {
				return ek, nil
			}
			return nil, fmt.Errorf("PEM block is not ed25519 private key (type=%T)", priv)
		}
		// Raw key seed (32 bytes) or expanded key (64 bytes) in a PEM block.
		switch len(block.Bytes) {
		case ed25519.SeedSize:
			return ed25519.NewKeyFromSeed(block.Bytes), nil
		case ed25519.PrivateKeySize:
			return ed25519.PrivateKey(block.Bytes), nil
		}
		return nil, fmt.Errorf("PEM block could not be parsed as ed25519 private key")
	}
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty key payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		decoded, err = base64.RawURLEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("not PEM and not base64: %v", err)
		}
	}
	switch len(decoded) {
	case ed25519.SeedSize:
		return ed25519.NewKeyFromSeed(decoded), nil
	case ed25519.PrivateKeySize:
		return ed25519.PrivateKey(decoded), nil
	}
	return nil, fmt.Errorf("decoded private key has size %d (expected %d or %d)",
		len(decoded), ed25519.SeedSize, ed25519.PrivateKeySize)
}

// SignBundle is the operator-facing helper used by `lobstertrap policy sign`.
// Returns a base64-encoded ed25519 signature over SHA-256(bundle).
func SignBundle(priv ed25519.PrivateKey, bundle []byte) (string, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return "", fmt.Errorf("policysync: private key has %d bytes (expected %d)", len(priv), ed25519.PrivateKeySize)
	}
	hash := sha256.Sum256(bundle)
	sig := ed25519.Sign(priv, hash[:])
	return base64.StdEncoding.EncodeToString(sig), nil
}
