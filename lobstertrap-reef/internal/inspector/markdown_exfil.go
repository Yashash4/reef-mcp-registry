package inspector

import (
	"net/url"
	"regexp"
	"strings"
)

// ExfilCandidate is a single URL extracted from a response that the heuristic
// considers a likely exfil vector. It carries enough context for the MODIFY
// action to rewrite the response and for the audit log to explain WHY the URL
// was redacted.
type ExfilCandidate struct {
	// Raw is the URL substring exactly as it appeared in the response,
	// including any markdown framing around it (for replacement purposes).
	Raw string `json:"raw"`
	// URL is the cleaned URL (trailing punctuation stripped).
	URL string `json:"url"`
	// Host is the parsed hostname (lower-cased) or empty if unparseable.
	Host string `json:"host"`
	// IsMarkdownImage is true if the URL was extracted from a `![alt](url)`
	// markdown image syntax. Bare URLs set this to false.
	IsMarkdownImage bool `json:"is_markdown_image"`
	// MarkdownMatch holds the full `![...](...)` substring (for whole-element
	// replacement). Empty for bare-URL candidates.
	MarkdownMatch string `json:"markdown_match,omitempty"`
	// MatchedFragment is the credential/PII-shaped substring found inside the
	// URL (path or query) — e.g. "sk-acme-internal", "api_key=AKIA…".
	MatchedFragment string `json:"matched_fragment,omitempty"`
	// Reason is a structured tag explaining why this candidate was flagged.
	Reason string `json:"reason"`
}

// markdownImageRE captures `![alt text](URL)` from prose. The URL group is
// non-greedy and excludes whitespace, `)`, and `(` so nested parens don't
// trip the match. Mirrors victim/app/lib/exfil.ts MARKDOWN_IMAGE_RE.
var markdownImageRE = regexp.MustCompile(`!\[[^\]]*]\(([^)\s]+)\)`)

// bareURLRE captures unwrapped `http(s)://...` URLs from prose. Mirrors
// victim/app/lib/exfil.ts BARE_URL_RE; trailing punctuation is trimmed below.
var bareURLRE = regexp.MustCompile(`https?://[^\s)\]]+`)

// secretFragmentRE is a deliberately broad set of telltale credential-shaped
// substrings that indicate an outbound URL is leaking a secret. It is wider
// than the upstream CredentialPatterns regex because URLs URL-encode and
// truncate values; we want to catch the *fragment*, not require the full
// credential intact. Keep this aligned with the patterns documented in
// victim/app/lib/exfil.ts (sk-acme-internal is the canonical demo secret;
// the others are general indicators).
var secretFragmentRE = regexp.MustCompile(
	`(?i)(sk-[a-z0-9_-]{3,}` +
		`|sk_live_[a-z0-9_-]{3,}` +
		`|sk_test_[a-z0-9_-]{3,}` +
		`|api[_-]?key=[^&\s]{4,}` +
		`|apikey=[^&\s]{4,}` +
		`|access[_-]?token=[^&\s]{4,}` +
		`|bearer[%20\s+]+[a-z0-9_\-.]{8,}` +
		`|password=[^&\s]{2,}` +
		`|secret=[^&\s]{4,}` +
		`|aws_secret_access_key=[^&\s]{4,}` +
		`|ghp_[a-z0-9]{12,}` +
		`|eyj[a-z0-9_-]{8,}\.eyj[a-z0-9_-]{4,}` +
		`)`,
)

// trailingPunctRE strips trailing punctuation that prose typically appends
// to URLs ("see https://x.com/?q=1.").
var trailingPunctRE = regexp.MustCompile(`[)\].,;:!?]+$`)

// MarkdownExfilOptions configures the heuristic.
//
// TrustedDomains is a list of host patterns (same semantics as
// policy.DomainMatches) that should NEVER be flagged as exfil candidates.
// Typically passed as policy.Network.AllowedDomains.
//
// ExtraSecretFragments is an optional list of literal substrings that should
// also count as "this URL leaks a secret" — supplied by callers that hold a
// known secret (the victim app, for instance). Match is case-sensitive
// against both the raw and URL-decoded URL.
type MarkdownExfilOptions struct {
	TrustedDomains       []string
	ExtraSecretFragments []string
}

// DetectMarkdownExfil scans text for markdown-image-with-external-URL exfil
// patterns and bare URLs containing credential-shaped fragments. It returns
// the set of candidates the MODIFY action should rewrite.
//
// The heuristic mirrors victim/app/lib/exfil.ts so the demo's "Reef OFF"
// banner detection and the firewall's "Reef ON" rewrite agree on what
// counts as exfil.
func DetectMarkdownExfil(text string, opts MarkdownExfilOptions) []ExfilCandidate {
	if text == "" {
		return nil
	}

	trusted := normalizeTrusted(opts.TrustedDomains)

	var out []ExfilCandidate
	seen := make(map[string]struct{}) // dedupe by raw match string

	// Markdown image candidates first — `![alt](url)`.
	for _, m := range markdownImageRE.FindAllStringSubmatchIndex(text, -1) {
		fullStart, fullEnd := m[0], m[1]
		urlStart, urlEnd := m[2], m[3]
		full := text[fullStart:fullEnd]
		raw := text[urlStart:urlEnd]
		cleaned := trailingPunctRE.ReplaceAllString(raw, "")
		host := safeHost(cleaned)
		if !isExternal(host) {
			continue
		}
		if isTrusted(host, trusted) {
			continue
		}
		// Markdown images to external untrusted hosts are flagged regardless
		// of secret fragments — the egress channel itself is the risk.
		key := "md|" + full
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ExfilCandidate{
			Raw:             raw,
			URL:             cleaned,
			Host:            host,
			IsMarkdownImage: true,
			MarkdownMatch:   full,
			MatchedFragment: findFragment(cleaned, opts.ExtraSecretFragments),
			Reason:          markdownReason(cleaned, opts.ExtraSecretFragments),
		})
	}

	// Bare URLs that contain credential-shaped fragments OR the caller's
	// explicit secret strings.
	for _, raw := range bareURLRE.FindAllString(text, -1) {
		cleaned := trailingPunctRE.ReplaceAllString(raw, "")
		// Skip URLs already captured as markdown-image targets.
		if isInsideMarkdownImage(text, cleaned) {
			continue
		}
		host := safeHost(cleaned)
		if !isExternal(host) {
			continue
		}
		if isTrusted(host, trusted) {
			continue
		}
		frag := findFragment(cleaned, opts.ExtraSecretFragments)
		if frag == "" {
			continue
		}
		key := "bare|" + cleaned
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, ExfilCandidate{
			Raw:             raw,
			URL:             cleaned,
			Host:            host,
			IsMarkdownImage: false,
			MatchedFragment: frag,
			Reason:          "bare_url_with_secret_fragment",
		})
	}

	return out
}

// findFragment returns the secret-shaped substring detected in URL, preferring
// the caller-supplied extras (which carry exact-match semantics) over the
// generic regex. The returned fragment is suitable for audit logging — it is
// the *needle*, not the whole haystack.
//
// Match precedence (highest to lowest):
//  1. extras against raw URL (exact match wins, no decode required)
//  2. extras against URL-decoded URL (handles `%2D` etc.)
//  3. generic credential-shape regex against raw URL
//  4. generic credential-shape regex against decoded URL
//
// The decoded-extras pass must run BEFORE the generic regex against the raw
// URL — otherwise URL-encoded versions of the caller's known secret get
// reported as the generic regex's (shorter) match, which loses the precise
// fragment text the audit log expects.
func findFragment(rawURL string, extra []string) string {
	// Pass 1: extras against raw URL (zero-cost when no encoding involved).
	for _, frag := range extra {
		if frag == "" {
			continue
		}
		if strings.Contains(rawURL, frag) {
			return frag
		}
	}
	// Pass 2: extras against decoded URL. We use QueryUnescape (handles
	// `%2D`, `+` as space inside queries) — failures fall through cleanly.
	if decoded, derr := url.QueryUnescape(rawURL); derr == nil && decoded != rawURL {
		for _, frag := range extra {
			if frag == "" {
				continue
			}
			if strings.Contains(decoded, frag) {
				return frag
			}
		}
	}
	// Pass 3: generic credential-shape regex on the raw URL.
	if m := secretFragmentRE.FindString(rawURL); m != "" {
		return m
	}
	// Pass 4: generic regex on decoded URL.
	if decoded, derr := url.QueryUnescape(rawURL); derr == nil && decoded != rawURL {
		if m := secretFragmentRE.FindString(decoded); m != "" {
			return m
		}
	}
	return ""
}

// markdownReason classifies a markdown-image exfil match: if the URL also
// contains a credential fragment, the reason names it; otherwise the reason
// is the bare external-image risk.
func markdownReason(rawURL string, extra []string) string {
	if findFragment(rawURL, extra) != "" {
		return "markdown_image_with_secret_fragment"
	}
	return "markdown_image_to_external_host"
}

// isInsideMarkdownImage returns true if `target` appears as the URL portion
// of a `![alt](target)` markdown image in `text`. Used to suppress the bare
// URL pass from re-matching URLs we already captured as markdown images.
func isInsideMarkdownImage(text, target string) bool {
	if target == "" {
		return false
	}
	// Cheap structural check: look for `](<target>` substring.
	return strings.Contains(text, "]("+target)
}

// safeHost parses a URL and returns its host (lower-cased). Falls back to a
// regex scrape if url.Parse rejects the input.
func safeHost(u string) string {
	if u == "" {
		return ""
	}
	parsed, err := url.Parse(u)
	if err == nil && parsed.Host != "" {
		return strings.ToLower(parsed.Hostname())
	}
	// Fallback — extract host between scheme and first `/?#`.
	if m := regexp.MustCompile(`^https?://([^/?#]+)`).FindStringSubmatch(u); m != nil {
		return strings.ToLower(stripPort(m[1]))
	}
	return ""
}

func stripPort(host string) string {
	if i := strings.IndexByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}

// isExternal returns true for any absolute hostname; relative/empty hosts and
// loopback addresses are treated as internal.
func isExternal(host string) bool {
	if host == "" {
		return false
	}
	switch host {
	case "localhost", "127.0.0.1", "0.0.0.0", "::1":
		return false
	}
	return true
}

// normalizeTrusted lower-cases trusted patterns so isTrusted can use the same
// matching rules as policy.DomainMatches without re-allocating per check.
func normalizeTrusted(trusted []string) []string {
	if len(trusted) == 0 {
		return nil
	}
	out := make([]string, 0, len(trusted))
	for _, t := range trusted {
		t = strings.ToLower(strings.TrimSpace(t))
		if t != "" {
			out = append(out, t)
		}
	}
	return out
}

// isTrusted applies the same wildcard semantics as policy.DomainMatches:
// `example.com` matches the exact host, `*.example.com` matches subdomains
// (not the apex). We re-implement the small matcher here so this package
// stays free of an import cycle with internal/policy.
func isTrusted(host string, trusted []string) bool {
	if host == "" || len(trusted) == 0 {
		return false
	}
	h := strings.ToLower(host)
	for _, p := range trusted {
		if strings.HasPrefix(p, "*.") {
			if strings.HasSuffix(h, p[1:]) {
				return true
			}
			continue
		}
		if p == h {
			return true
		}
	}
	return false
}

// StripMarkdownExfil rewrites text by removing every markdown image and bare
// URL named in `candidates`, replacing each with a redacted marker that names
// the destination host. Returns the rewritten text and the count of edits
// performed. Body order is preserved (replacements are positional).
//
// The marker shape — `[REDACTED: markdown image to HOST stripped by Reef
// MODIFY]` or `[REDACTED: url to HOST stripped by Reef MODIFY]` — is part of
// the audit contract; the Stage UI and RIA generator key off these strings.
func StripMarkdownExfil(text string, candidates []ExfilCandidate) (string, int) {
	if len(candidates) == 0 || text == "" {
		return text, 0
	}
	rewritten := text
	edits := 0
	for _, c := range candidates {
		if c.IsMarkdownImage {
			marker := "[REDACTED: markdown image to " + safeMarkerHost(c.Host) + " stripped by Reef MODIFY]"
			if c.MarkdownMatch != "" && strings.Contains(rewritten, c.MarkdownMatch) {
				rewritten = strings.Replace(rewritten, c.MarkdownMatch, marker, 1)
				edits++
				continue
			}
			// Markdown match string was lost (shouldn't happen) — fall through
			// to URL-level replacement so we still strip the destination.
		}
		marker := "[REDACTED: url to " + safeMarkerHost(c.Host) + " stripped by Reef MODIFY]"
		// Prefer the cleaned URL; fall back to the raw form (with punctuation).
		if c.URL != "" && strings.Contains(rewritten, c.URL) {
			rewritten = strings.Replace(rewritten, c.URL, marker, 1)
			edits++
			continue
		}
		if c.Raw != "" && strings.Contains(rewritten, c.Raw) {
			rewritten = strings.Replace(rewritten, c.Raw, marker, 1)
			edits++
		}
	}
	return rewritten, edits
}

func safeMarkerHost(h string) string {
	if h == "" {
		return "unknown"
	}
	return h
}
