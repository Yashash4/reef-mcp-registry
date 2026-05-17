package policy

import "testing"

func TestDomainMatches(t *testing.T) {
	cases := []struct {
		name    string
		pattern string
		host    string
		want    bool
	}{
		{"exact match", "pastebin.com", "pastebin.com", true},
		{"exact match case insensitive", "Pastebin.com", "pastebin.COM", true},
		{"exact mismatch", "pastebin.com", "evil.com", false},
		{"exact does not match subdomain", "pastebin.com", "raw.pastebin.com", false},
		{"wildcard tld onion", "*.onion", "abc.onion", true},
		{"wildcard tld onion deep", "*.onion", "x.y.onion", true},
		{"wildcard does not match apex", "*.example.com", "example.com", false},
		{"wildcard subdomain matches", "*.example.com", "a.example.com", true},
		{"wildcard subdomain matches deep", "*.example.com", "x.y.example.com", true},
		{"empty pattern", "", "example.com", false},
		{"empty host", "example.com", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := DomainMatches(tc.pattern, tc.host)
			if got != tc.want {
				t.Errorf("DomainMatches(%q, %q) = %v, want %v", tc.pattern, tc.host, got, tc.want)
			}
		})
	}
}

func TestFirstDeniedDomain(t *testing.T) {
	denied := []string{"*.onion", "pastebin.com", "*.attacker.example.com"}
	cases := []struct {
		name        string
		hosts       []string
		wantPattern string
		wantHost    string
	}{
		{"no match", []string{"api.openai.com", "github.com"}, "", ""},
		{"exact match", []string{"pastebin.com"}, "pastebin.com", "pastebin.com"},
		{"wildcard onion", []string{"abc.onion"}, "*.onion", "abc.onion"},
		{"wildcard subdomain", []string{"c2.attacker.example.com"}, "*.attacker.example.com", "c2.attacker.example.com"},
		{"first match wins (host order)", []string{"safe.com", "pastebin.com", "abc.onion"}, "pastebin.com", "pastebin.com"},
		{"empty inputs", nil, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			pat, h := FirstDeniedDomain(denied, tc.hosts)
			if pat != tc.wantPattern || h != tc.wantHost {
				t.Errorf("FirstDeniedDomain(%v) = (%q, %q), want (%q, %q)",
					tc.hosts, pat, h, tc.wantPattern, tc.wantHost)
			}
		})
	}
}
