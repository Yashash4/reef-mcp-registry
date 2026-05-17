package policy

import "strings"

// DomainMatches reports whether host matches pattern using the same semantics
// the dashboard's denied-domains list implies and that operators expect:
//
//   - "example.com"  matches the exact host "example.com" (case-insensitive).
//   - "*.example.com" matches any subdomain of example.com but NOT the apex,
//     e.g. "a.example.com" and "x.y.example.com" match, "example.com" does not.
//   - "*.onion"      matches any host ending in ".onion" (e.g. "abc.onion").
//
// Empty pattern or empty host returns false.
func DomainMatches(pattern, host string) bool {
	if pattern == "" || host == "" {
		return false
	}
	p := strings.ToLower(strings.TrimSpace(pattern))
	h := strings.ToLower(strings.TrimSpace(host))
	if strings.HasPrefix(p, "*.") {
		suffix := p[1:] // ".example.com" or ".onion"
		return strings.HasSuffix(h, suffix)
	}
	return p == h
}

// FirstDeniedDomain returns the first (pattern, host) pair where host
// matches a denied-domain pattern, or empty strings if none match.
func FirstDeniedDomain(deniedPatterns, hosts []string) (pattern, host string) {
	for _, h := range hosts {
		for _, pat := range deniedPatterns {
			if DomainMatches(pat, h) {
				return pat, h
			}
		}
	}
	return "", ""
}
