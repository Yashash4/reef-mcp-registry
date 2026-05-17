package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func mustKeyPair(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519 keygen: %v", err)
	}
	return pub, priv
}

func makeClaims(now time.Time, overrides map[string]any) map[string]any {
	base := map[string]any{
		"iss": "reef-fleet/region-us-east/site-corp-hq",
		"sub": "spiffe://reef.local/finance/contracts-summarizer-v3",
		"aud": "lobstertrap-reef",
		"exp": now.Add(15 * time.Minute).Unix(),
		"iat": now.Unix(),
		"scope": map[string]any{
			"declared_intent":  "read+summarize",
			"declared_tools":   []string{"docs.read", "summary.write"},
			"declared_domains": []string{"intra.corp"},
		},
	}
	for k, v := range overrides {
		if v == nil {
			delete(base, k)
		} else {
			base[k] = v
		}
	}
	return base
}

func TestVerifySVID(t *testing.T) {
	now := time.Date(2026, 5, 18, 12, 0, 0, 0, time.UTC)
	pub, priv := mustKeyPair(t)
	otherPub, _ := mustKeyPair(t)

	v, err := NewJWTVerifierWithKeys("lobstertrap-reef", map[string]ed25519.PublicKey{
		"primary": pub,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifierWithKeys: %v", err)
	}
	v.SetClock(func() time.Time { return now })

	signWith := func(p ed25519.PrivateKey, kid string, claims map[string]any) string {
		token, err := SignSVID(p, kid, claims)
		if err != nil {
			t.Fatalf("SignSVID: %v", err)
		}
		return token
	}

	t.Run("valid_token_returns_svid", func(t *testing.T) {
		token := signWith(priv, "primary", makeClaims(now, nil))
		svid, err := v.VerifySVID(token)
		if err != nil {
			t.Fatalf("VerifySVID: unexpected error %v", err)
		}
		if svid.Subject != "spiffe://reef.local/finance/contracts-summarizer-v3" {
			t.Errorf("subject=%q", svid.Subject)
		}
		if svid.KeyID != "primary" {
			t.Errorf("key id=%q want primary", svid.KeyID)
		}
		if got := svid.Scope.DeclaredIntent; got != "read+summarize" {
			t.Errorf("declared_intent=%q", got)
		}
		if len(svid.Scope.DeclaredTools) != 2 {
			t.Errorf("declared_tools=%v", svid.Scope.DeclaredTools)
		}
	})

	t.Run("expired_token_rejected", func(t *testing.T) {
		expired := makeClaims(now, map[string]any{
			"exp": now.Add(-1 * time.Minute).Unix(),
		})
		token := signWith(priv, "primary", expired)
		_, err := v.VerifySVID(token)
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("err=%v want ErrExpired", err)
		}
	})

	t.Run("wrong_audience_rejected", func(t *testing.T) {
		bad := makeClaims(now, map[string]any{"aud": "wrong-audience"})
		token := signWith(priv, "primary", bad)
		_, err := v.VerifySVID(token)
		if !errors.Is(err, ErrWrongAudience) {
			t.Fatalf("err=%v want ErrWrongAudience", err)
		}
	})

	t.Run("signature_tamper_rejected", func(t *testing.T) {
		token := signWith(priv, "primary", makeClaims(now, nil))
		// Flip a byte in the signature segment.
		parts := strings.Split(token, ".")
		if len(parts) != 3 {
			t.Fatalf("token split %v", parts)
		}
		sigBytes, _ := base64.RawURLEncoding.DecodeString(parts[2])
		sigBytes[0] ^= 0xff
		parts[2] = base64.RawURLEncoding.EncodeToString(sigBytes)
		tampered := strings.Join(parts, ".")
		_, err := v.VerifySVID(tampered)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("err=%v want ErrSignatureInvalid", err)
		}
	})

	t.Run("foreign_key_rejected", func(t *testing.T) {
		// Build a verifier that only trusts otherPub; sign with priv.
		other, err := NewJWTVerifierWithKeys("lobstertrap-reef", map[string]ed25519.PublicKey{
			"other": otherPub,
		})
		if err != nil {
			t.Fatalf("NewJWTVerifierWithKeys: %v", err)
		}
		other.SetClock(func() time.Time { return now })
		token := signWith(priv, "primary", makeClaims(now, nil))
		_, err = other.VerifySVID(token)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("err=%v want ErrSignatureInvalid", err)
		}
	})

	t.Run("missing_scope_claim_rejected", func(t *testing.T) {
		claims := makeClaims(now, map[string]any{"scope": nil})
		token := signWith(priv, "primary", claims)
		_, err := v.VerifySVID(token)
		if !errors.Is(err, ErrMissingClaim) {
			t.Fatalf("err=%v want ErrMissingClaim", err)
		}
	})

	t.Run("missing_iss_claim_rejected", func(t *testing.T) {
		claims := makeClaims(now, map[string]any{"iss": nil})
		token := signWith(priv, "primary", claims)
		_, err := v.VerifySVID(token)
		if !errors.Is(err, ErrMissingClaim) {
			t.Fatalf("err=%v want ErrMissingClaim", err)
		}
	})

	t.Run("alg_hs256_rejected", func(t *testing.T) {
		// Hand-build a token with alg=HS256 — this is the classic alg-
		// confusion attack. Our verifier must reject before any signature
		// check happens.
		header := map[string]string{"alg": "HS256", "typ": "JWT"}
		hb, _ := json.Marshal(header)
		cb, _ := json.Marshal(makeClaims(now, nil))
		body := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
		token := body + "." + base64.RawURLEncoding.EncodeToString([]byte("not-a-real-signature"))
		_, err := v.VerifySVID(token)
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatalf("err=%v want ErrUnsupportedAlg", err)
		}
	})

	t.Run("malformed_token_rejected", func(t *testing.T) {
		_, err := v.VerifySVID("not.a.valid.jwt.too.many.dots")
		if !errors.Is(err, ErrTokenMalformed) {
			t.Fatalf("err=%v want ErrTokenMalformed", err)
		}
	})

	t.Run("empty_token_rejected", func(t *testing.T) {
		_, err := v.VerifySVID("")
		if !errors.Is(err, ErrEmptyToken) {
			t.Fatalf("err=%v want ErrEmptyToken", err)
		}
	})

	t.Run("bearer_prefix_stripped", func(t *testing.T) {
		token := signWith(priv, "primary", makeClaims(now, nil))
		bearer := "Bearer " + token
		svid, err := v.VerifySVID(bearer)
		if err != nil {
			t.Fatalf("VerifySVID(bearer): %v", err)
		}
		if svid.Subject == "" {
			t.Errorf("expected subject populated")
		}
	})

	t.Run("audience_array_accepts_match", func(t *testing.T) {
		claims := makeClaims(now, map[string]any{
			"aud": []string{"some-other-aud", "lobstertrap-reef"},
		})
		token := signWith(priv, "primary", claims)
		svid, err := v.VerifySVID(token)
		if err != nil {
			t.Fatalf("VerifySVID: %v", err)
		}
		if svid.Subject == "" {
			t.Errorf("subject missing")
		}
	})
}

func TestNewJWTVerifier_LoadsKeysFromDir(t *testing.T) {
	dir := t.TempDir()
	pub, _ := mustKeyPair(t)
	// Write the key as base64 (raw 32 bytes).
	keyB64 := base64.StdEncoding.EncodeToString(pub)
	if err := os.WriteFile(filepath.Join(dir, "ops-team.pub"), []byte(keyB64), 0644); err != nil {
		t.Fatalf("write key: %v", err)
	}
	// Add a non-key file to verify it's ignored.
	if err := os.WriteFile(filepath.Join(dir, "README.txt"), []byte("not a key"), 0644); err != nil {
		t.Fatalf("write readme: %v", err)
	}
	v, err := NewJWTVerifier(VerifierConfig{
		ExpectedAudience: "lobstertrap-reef",
		IssuerKeysDir:    dir,
	})
	if err != nil {
		t.Fatalf("NewJWTVerifier: %v", err)
	}
	ids := v.KeyIDs()
	if len(ids) != 1 || ids[0] != "ops-team" {
		t.Errorf("KeyIDs=%v", ids)
	}
}

func TestNewJWTVerifier_EmptyDirErrors(t *testing.T) {
	dir := t.TempDir()
	_, err := NewJWTVerifier(VerifierConfig{
		ExpectedAudience: "lobstertrap-reef",
		IssuerKeysDir:    dir,
	})
	if !errors.Is(err, ErrKeyringEmpty) {
		t.Fatalf("err=%v want ErrKeyringEmpty", err)
	}
}

func TestNewJWTVerifier_MissingDirErrors(t *testing.T) {
	_, err := NewJWTVerifier(VerifierConfig{
		ExpectedAudience: "lobstertrap-reef",
		IssuerKeysDir:    "/no/such/dir/exists/reef-svid",
	})
	if err == nil {
		t.Fatal("expected error for missing dir")
	}
}
