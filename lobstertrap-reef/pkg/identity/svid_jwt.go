// Package identity implements SVID JWT verification for agent authentication.
//
// Reef simplifies SPIFFE/SPIRE (see D-009) by accepting JWT-shaped SVIDs
// signed with ed25519. Every Reef-protected agent presents a signed JWT in
// the `Authorization: Bearer <SVID>` header. The JWT claims SPIFFE-shaped
// fields:
//
//	{
//	  "iss": "reef-fleet/region-us-east/site-corp-hq",
//	  "sub": "spiffe://reef.local/finance/contracts-summarizer-v3",
//	  "aud": "lobstertrap-reef",
//	  "exp": <unix seconds>,
//	  "iat": <unix seconds>,
//	  "scope": {
//	    "declared_intent": "read+summarize",
//	    "declared_tools":  ["docs.read", "summary.write"],
//	    "declared_domains":["intra.corp"]
//	  }
//	}
//
// Trust roots are ed25519 public keys living under REEF_SVID_ISSUER_KEYS_DIR
// (default ./keys/svid-issuers/). Each *.pub or *.pem file in the directory
// is loaded at startup. A JWT is accepted only if its signature verifies
// against one of the trusted keys AND its `aud`+`exp` are valid.
//
// Hard rules:
//   - Fail closed. No insecure default — an unsigned or malformed JWT MUST
//     never produce a *SVID.
//   - Algorithm pin: we only accept "EdDSA" (ed25519). HS256/RS256/etc are
//     rejected to avoid the classic JWT alg-confusion attack.
//   - Required claims: iss, sub, aud, exp, iat, scope.
package identity

import (
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Algorithm constants for the JWT "alg" header. Only EdDSA is accepted.
const (
	AlgEdDSA = "EdDSA"
)

// Errors returned by Verify. Stable strings so tests + audit log filters
// can grep on them.
var (
	ErrTokenMalformed     = errors.New("svid: token is malformed (expect three dot-separated base64 segments)")
	ErrUnsupportedAlg     = errors.New("svid: only EdDSA is accepted as the JWT signing algorithm")
	ErrSignatureInvalid   = errors.New("svid: signature does not verify against any trusted issuer key")
	ErrExpired            = errors.New("svid: token has expired (exp claim is in the past)")
	ErrNotYetValid        = errors.New("svid: token is not yet valid (iat claim is in the future)")
	ErrWrongAudience      = errors.New("svid: token audience does not match expected audience")
	ErrMissingClaim       = errors.New("svid: required claim is missing")
	ErrNoIssuerKeys       = errors.New("svid: no issuer keys loaded — verifier cannot verify any token")
	ErrEmptyToken         = errors.New("svid: token is empty")
	ErrKeyringEmpty       = errors.New("svid: issuer keyring is empty after scanning directory")
)

// Scope is the SPIFFE-shaped declared envelope on the SVID.
type Scope struct {
	DeclaredIntent  string   `json:"declared_intent"`
	DeclaredTools   []string `json:"declared_tools"`
	DeclaredDomains []string `json:"declared_domains"`
}

// SVID is the parsed + verified result of a successful JWT verification.
// Callers (the Lobster Trap pipeline) treat this as proof of identity.
type SVID struct {
	Issuer    string    `json:"iss"`
	Subject   string    `json:"sub"`
	Audience  string    `json:"aud"`
	IssuedAt  time.Time `json:"iat"`
	ExpiresAt time.Time `json:"exp"`
	Scope     Scope     `json:"scope"`
	// KeyID is the file basename (sans extension) of the issuer public key
	// that verified this token. Useful for audit log correlation.
	KeyID string `json:"key_id"`
}

// Verifier is the contract Reef's pipeline calls into. Implementations parse
// a JWT, verify signature + claims, and return a populated *SVID.
type Verifier interface {
	// VerifySVID validates the token and returns the parsed SVID on success.
	// On any failure it returns nil + a stable sentinel error.
	VerifySVID(token string) (*SVID, error)
}

// JWTVerifier is the production ed25519 JWT verifier.
type JWTVerifier struct {
	expectedAudience string
	clock            func() time.Time

	mu   sync.RWMutex
	keys map[string]ed25519.PublicKey // keyID -> public key
}

// VerifierConfig wires the dependencies a JWTVerifier needs.
type VerifierConfig struct {
	// ExpectedAudience is the value the JWT's `aud` claim MUST equal. Empty
	// means "accept any audience" — only useful for tests, never production.
	ExpectedAudience string
	// IssuerKeysDir is the directory containing trusted issuer public keys
	// (*.pub or *.pem files holding ed25519 public keys in PKIX form, or
	// the legacy raw 32-byte format). Each file's basename (sans extension)
	// becomes the KeyID.
	IssuerKeysDir string
	// Clock lets tests inject a frozen time. Nil falls back to time.Now.
	Clock func() time.Time
}

// NewJWTVerifier builds a JWTVerifier by scanning the configured directory
// and loading every key file it finds. Returns ErrKeyringEmpty when the
// directory is missing or contains no usable keys — callers MUST treat that
// as fatal when REEF requires SVIDs.
func NewJWTVerifier(cfg VerifierConfig) (*JWTVerifier, error) {
	if cfg.IssuerKeysDir == "" {
		return nil, fmt.Errorf("svid: VerifierConfig.IssuerKeysDir is required")
	}
	v := &JWTVerifier{
		expectedAudience: cfg.ExpectedAudience,
		clock:            cfg.Clock,
		keys:             map[string]ed25519.PublicKey{},
	}
	if v.clock == nil {
		v.clock = time.Now
	}
	if err := v.loadKeysFromDir(cfg.IssuerKeysDir); err != nil {
		return nil, fmt.Errorf("svid: loading issuer keys from %q: %w", cfg.IssuerKeysDir, err)
	}
	if len(v.keys) == 0 {
		return nil, fmt.Errorf("svid: directory %q held no issuer keys: %w", cfg.IssuerKeysDir, ErrKeyringEmpty)
	}
	return v, nil
}

// NewJWTVerifierWithKeys builds a verifier from an in-memory keyring. Used
// by tests + the integration suite. Returns an error if no keys are passed.
func NewJWTVerifierWithKeys(expectedAudience string, keys map[string]ed25519.PublicKey) (*JWTVerifier, error) {
	if len(keys) == 0 {
		return nil, ErrKeyringEmpty
	}
	cp := make(map[string]ed25519.PublicKey, len(keys))
	for k, v := range keys {
		cp[k] = v
	}
	return &JWTVerifier{
		expectedAudience: expectedAudience,
		clock:            time.Now,
		keys:             cp,
	}, nil
}

// SetClock lets tests freeze time.
func (v *JWTVerifier) SetClock(c func() time.Time) {
	v.clock = c
}

// KeyIDs returns the set of issuer keys this verifier trusts. Useful for
// startup log lines and tests.
func (v *JWTVerifier) KeyIDs() []string {
	v.mu.RLock()
	defer v.mu.RUnlock()
	out := make([]string, 0, len(v.keys))
	for k := range v.keys {
		out = append(out, k)
	}
	return out
}

// loadKeysFromDir scans the directory and populates v.keys. Files that fail
// to parse are logged via error return (after collecting the rest) so a
// single bad key doesn't kill the whole keyring — but at least one key must
// load or NewJWTVerifier fails.
func (v *JWTVerifier) loadKeysFromDir(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("read dir: %w", err)
	}
	var loadErrors []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		ext := strings.ToLower(filepath.Ext(name))
		if ext != ".pub" && ext != ".pem" && ext != ".key" {
			continue
		}
		path := filepath.Join(dir, name)
		data, err := os.ReadFile(path)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		pub, err := parseEd25519PublicKey(data)
		if err != nil {
			loadErrors = append(loadErrors, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		keyID := strings.TrimSuffix(name, ext)
		v.mu.Lock()
		v.keys[keyID] = pub
		v.mu.Unlock()
	}
	if len(loadErrors) > 0 && len(v.keys) == 0 {
		return fmt.Errorf("failed to load any keys: %s", strings.Join(loadErrors, "; "))
	}
	return nil
}

// parseEd25519PublicKey accepts PEM-encoded PKIX ed25519 keys or a raw
// 32-byte base64 (single-line) representation. Anything else is rejected.
func parseEd25519PublicKey(data []byte) (ed25519.PublicKey, error) {
	// Try PEM first.
	block, _ := pem.Decode(data)
	if block != nil {
		// PKIX-form ed25519 public key.
		if pub, err := x509.ParsePKIXPublicKey(block.Bytes); err == nil {
			if ek, ok := pub.(ed25519.PublicKey); ok {
				return ek, nil
			}
			return nil, fmt.Errorf("PEM block contained non-ed25519 key (type=%T)", pub)
		}
		// Raw 32-byte payload in a PEM block (some tooling emits this).
		if len(block.Bytes) == ed25519.PublicKeySize {
			return ed25519.PublicKey(block.Bytes), nil
		}
		return nil, fmt.Errorf("PEM block could not be parsed as ed25519 public key")
	}
	// Try base64 (one or more lines).
	trimmed := strings.TrimSpace(string(data))
	if trimmed == "" {
		return nil, fmt.Errorf("empty key payload")
	}
	decoded, err := base64.StdEncoding.DecodeString(trimmed)
	if err != nil {
		// Try URL-safe base64 too.
		decoded, err = base64.RawURLEncoding.DecodeString(trimmed)
		if err != nil {
			return nil, fmt.Errorf("not a PEM and not base64: %v", err)
		}
	}
	if len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	// Last chance — maybe it's a base64-encoded PKIX form (rare).
	if pub, err := x509.ParsePKIXPublicKey(decoded); err == nil {
		if ek, ok := pub.(ed25519.PublicKey); ok {
			return ek, nil
		}
	}
	return nil, fmt.Errorf("decoded key has size %d (expected %d) and is not PKIX", len(decoded), ed25519.PublicKeySize)
}

// jwtHeader is the minimal JWT header we parse.
type jwtHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// rawClaims is the JWT body we parse. Audience accepts both string and
// []string per RFC 7519; we normalise on parse.
type rawClaims struct {
	Iss   string          `json:"iss"`
	Sub   string          `json:"sub"`
	Aud   json.RawMessage `json:"aud"`
	Exp   int64           `json:"exp"`
	Iat   int64           `json:"iat"`
	Nbf   int64           `json:"nbf,omitempty"`
	Scope *Scope          `json:"scope"`
}

// VerifySVID parses the JWT, verifies the signature against the configured
// issuer keys, validates audience + expiry, and returns the populated SVID.
func (v *JWTVerifier) VerifySVID(token string) (*SVID, error) {
	if token == "" {
		return nil, ErrEmptyToken
	}
	// Strip optional "Bearer " prefix.
	if len(token) > 7 && strings.EqualFold(token[:7], "Bearer ") {
		token = token[7:]
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, ErrTokenMalformed
	}
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("%w: header is not base64url: %v", ErrTokenMalformed, err)
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload is not base64url: %v", ErrTokenMalformed, err)
	}
	sigBytes, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("%w: signature is not base64url: %v", ErrTokenMalformed, err)
	}

	var h jwtHeader
	if err := json.Unmarshal(headerBytes, &h); err != nil {
		return nil, fmt.Errorf("%w: header is not JSON: %v", ErrTokenMalformed, err)
	}
	if h.Alg != AlgEdDSA {
		return nil, fmt.Errorf("%w: alg=%q", ErrUnsupportedAlg, h.Alg)
	}

	// Signed message is the concatenation of header.payload (the two base64
	// segments as they appear in the token, joined with a literal '.').
	signedMessage := []byte(parts[0] + "." + parts[1])

	// Try the kid-hinted key first, then fall back to scanning the keyring.
	v.mu.RLock()
	defer v.mu.RUnlock()
	if len(v.keys) == 0 {
		return nil, ErrNoIssuerKeys
	}
	var verifiedKeyID string
	if h.Kid != "" {
		if pub, ok := v.keys[h.Kid]; ok && ed25519.Verify(pub, signedMessage, sigBytes) {
			verifiedKeyID = h.Kid
		}
	}
	if verifiedKeyID == "" {
		for kid, pub := range v.keys {
			if ed25519.Verify(pub, signedMessage, sigBytes) {
				verifiedKeyID = kid
				break
			}
		}
	}
	if verifiedKeyID == "" {
		return nil, ErrSignatureInvalid
	}

	var c rawClaims
	if err := json.Unmarshal(payloadBytes, &c); err != nil {
		return nil, fmt.Errorf("%w: payload is not JSON: %v", ErrTokenMalformed, err)
	}

	if c.Iss == "" {
		return nil, fmt.Errorf("%w: iss", ErrMissingClaim)
	}
	if c.Sub == "" {
		return nil, fmt.Errorf("%w: sub", ErrMissingClaim)
	}
	if c.Exp == 0 {
		return nil, fmt.Errorf("%w: exp", ErrMissingClaim)
	}
	if c.Iat == 0 {
		return nil, fmt.Errorf("%w: iat", ErrMissingClaim)
	}
	if c.Scope == nil {
		return nil, fmt.Errorf("%w: scope", ErrMissingClaim)
	}

	audience, err := normaliseAudience(c.Aud)
	if err != nil {
		return nil, fmt.Errorf("%w: aud parse: %v", ErrMissingClaim, err)
	}
	if audience == "" {
		return nil, fmt.Errorf("%w: aud", ErrMissingClaim)
	}
	if v.expectedAudience != "" && !audienceMatches(audience, v.expectedAudience) {
		return nil, fmt.Errorf("%w: got %q, want %q", ErrWrongAudience, audience, v.expectedAudience)
	}

	now := v.clock()
	exp := time.Unix(c.Exp, 0)
	iat := time.Unix(c.Iat, 0)
	if now.After(exp) {
		return nil, ErrExpired
	}
	// 60s clock-skew tolerance on iat.
	if iat.After(now.Add(60 * time.Second)) {
		return nil, ErrNotYetValid
	}

	return &SVID{
		Issuer:    c.Iss,
		Subject:   c.Sub,
		Audience:  audience,
		IssuedAt:  iat.UTC(),
		ExpiresAt: exp.UTC(),
		Scope:     *c.Scope,
		KeyID:     verifiedKeyID,
	}, nil
}

// normaliseAudience extracts a single audience string from the raw aud claim,
// which may be a JSON string or a JSON array of strings (RFC 7519 §4.1.3).
func normaliseAudience(raw json.RawMessage) (string, error) {
	if len(raw) == 0 {
		return "", nil
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, nil
	}
	var arr []string
	if err := json.Unmarshal(raw, &arr); err == nil {
		if len(arr) == 0 {
			return "", nil
		}
		// Return the first audience; audienceMatches will look for the
		// expected audience across all entries via the joined-comma string.
		return strings.Join(arr, ","), nil
	}
	return "", fmt.Errorf("aud is neither string nor array of strings")
}

// audienceMatches accepts comma-joined audiences and looks for an exact match.
func audienceMatches(got, expected string) bool {
	if got == expected {
		return true
	}
	for _, a := range strings.Split(got, ",") {
		if strings.TrimSpace(a) == expected {
			return true
		}
	}
	return false
}

// SignSVID is a test/operator helper that produces a valid Reef SVID for
// development use. NOT used in production; production SVIDs are minted by an
// external issuer service. Returns the compact JWT serialisation.
func SignSVID(priv ed25519.PrivateKey, keyID string, claims map[string]any) (string, error) {
	header := jwtHeader{Alg: AlgEdDSA, Kid: keyID, Typ: "JWT"}
	hb, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	cb, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	signed := base64.RawURLEncoding.EncodeToString(hb) + "." + base64.RawURLEncoding.EncodeToString(cb)
	sig := ed25519.Sign(priv, []byte(signed))
	return signed + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}
