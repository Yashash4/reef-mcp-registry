package pipeline

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"strings"
	"testing"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/identity"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/pkg/ratelimit"
)

func TestRateLimitIntegration_TripsAfterBurst(t *testing.T) {
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	src := `
version: "1.0"
policy_name: "ratelimit-integration"
default_action: ALLOW
ingress_rules:
  - name: dummy_log
    description: dummy
    priority: 1
    action: LOG
    conditions:
      - field: token_count
        match_type: threshold
        value: 0
reef:
  require_svid: true
  rate_limit:
    rate_per_second: 1
    burst: 3
`
	pol, err := policy.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	v, _ := identity.NewJWTVerifierWithKeys("lobstertrap-reef", map[string]ed25519.PublicKey{"ops": pub})
	lim, err := ratelimit.New(ratelimit.Config{Rate: 1, Burst: 3})
	if err != nil {
		t.Fatalf("ratelimit: %v", err)
	}
	pipe := NewWithReef(pol, audit.NopLogger(), nil, true).
		WithSVIDVerifier(v).
		WithRateLimiter(lim)

	now := time.Now()
	tok, err := identity.SignSVID(priv, "ops", map[string]any{
		"iss": "reef-fleet/region-us-east",
		"sub": "spiffe://reef/burst-agent",
		"aud": "lobstertrap-reef",
		"exp": now.Add(10 * time.Minute).Unix(),
		"iat": now.Unix(),
		"scope": map[string]any{
			"declared_intent":  "read",
			"declared_tools":   []string{},
			"declared_domains": []string{},
		},
	})
	if err != nil {
		t.Fatalf("SignSVID: %v", err)
	}

	// First 3 requests should pass.
	for i := 0; i < 3; i++ {
		pr := pipe.ProcessIngressWithAuth(context.Background(), "hello", nil, tok)
		if pr.Blocked {
			t.Errorf("request %d blocked unexpectedly: %s", i+1, pr.DenyMessage)
		}
	}
	// 4th should be rate-limited.
	pr := pipe.ProcessIngressWithAuth(context.Background(), "hello", nil, tok)
	if !pr.Blocked {
		t.Fatal("expected rate-limit DENY on burst-overflow")
	}
	if pr.IngressResult.RuleName != ReasonRateLimitPerIdent {
		t.Errorf("rule=%q want %q", pr.IngressResult.RuleName, ReasonRateLimitPerIdent)
	}
	if !strings.Contains(pr.DenyMessage, "RATE_LIMITED_PER_IDENTITY") {
		t.Errorf("deny msg=%q want RATE_LIMITED_PER_IDENTITY", pr.DenyMessage)
	}
}
