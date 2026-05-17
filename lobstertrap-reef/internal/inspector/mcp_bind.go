package inspector

import (
	"regexp"
	"strings"
)

// DetectMCPBind extracts an MCP server bind target from a prompt or response
// body. Returns (mcpName, version, transport, found). When found == false,
// the other return values are empty.
//
// Heuristics (ordered by specificity):
//
//  1. `bind_mcp(<mcpName>[, <version>[, <transport>]])` — explicit tool call
//     shape (most common when an agent's planner orchestrates MCP server
//     bindings programmatically).
//  2. `mcp://<mcpName>[@<version>]` — URI scheme convention used by the
//     Anthropic reference clients.
//  3. `Bind to MCP server <mcpName>` / `connect to MCP server <mcpName>` —
//     free-text natural language pattern that appears in prompts asking the
//     model to bind a specific MCP server. Lower precision but still useful
//     for the cold-open demo where the prompt is plain English.
//
// The mcpName is normalised to lowercase. Version + transport stay as-is.
// Transport defaults to empty unless the prompt explicitly says "stdio" or
// "http"; pipeline then asks Atlas with a transport hint where available.
func DetectMCPBind(text string) (mcpName, version, transport string, found bool) {
	if text == "" {
		return "", "", "", false
	}

	if name, ver, tr, ok := matchBindMCPCall(text); ok {
		return strings.ToLower(name), ver, tr, true
	}
	if name, ver, ok := matchMCPURI(text); ok {
		return strings.ToLower(name), ver, "", true
	}
	if name, ok := matchNaturalLanguageBind(text); ok {
		return strings.ToLower(name), "", "", true
	}
	return "", "", "", false
}

// `bind_mcp("io.github.modelcontextprotocol/server-filesystem", "0.6.3", "stdio")`
// `bind_mcp("com.example/weather-mcp", "1.2.3")`
// `bind_mcp("victim-mcp-server")`
var bindMCPCallRE = regexp.MustCompile(
	`(?i)bind_mcp\s*\(\s*["']?([A-Za-z0-9._\-/]+)["']?` +
		`(?:\s*,\s*["']?([A-Za-z0-9._\-+]+)["']?` +
		`(?:\s*,\s*["']?(stdio|http)["']?)?)?\s*\)`,
)

func matchBindMCPCall(text string) (string, string, string, bool) {
	m := bindMCPCallRE.FindStringSubmatch(text)
	if m == nil {
		return "", "", "", false
	}
	return m[1], m[2], m[3], true
}

// `mcp://com.example/weather-mcp@1.2.3`
// `mcp://com.example/weather-mcp`
//
// We use a greedy character class terminated by whitespace, end-of-string,
// or the @version separator. The `\b` boundary doesn't work here because
// `.` ends a word boundary in Go's regexp engine, so a lazy match would
// stop at the first dot.
var mcpURIRE = regexp.MustCompile(
	`(?i)mcp://([A-Za-z0-9._\-/]+?)(?:@([A-Za-z0-9.\-+]+))?(?:\s|$|["',)\]}<>])`,
)

func matchMCPURI(text string) (string, string, bool) {
	// We need to match the URI then trim the trailing terminator from the
	// extracted group. Easier: append a sentinel space and pin the match.
	if !regexp.MustCompile(`(?i)mcp://`).MatchString(text) {
		return "", "", false
	}
	// Find the URI and split out version manually.
	loc := regexp.MustCompile(`(?i)mcp://[A-Za-z0-9._\-/@+]+`).FindStringIndex(text)
	if loc == nil {
		return "", "", false
	}
	uri := text[loc[0]:loc[1]]
	uri = uri[len("mcp://"):]
	// Strip trailing punctuation that shouldn't be part of the URI.
	uri = trimRightAny(uri, ".,;:!?)]}>'\"")
	at := indexLast(uri, '@')
	if at >= 0 {
		return uri[:at], uri[at+1:], true
	}
	return uri, "", true
}

func trimRightAny(s, cutset string) string {
	for len(s) > 0 {
		c := s[len(s)-1]
		found := false
		for i := 0; i < len(cutset); i++ {
			if cutset[i] == c {
				found = true
				break
			}
		}
		if !found {
			return s
		}
		s = s[:len(s)-1]
	}
	return s
}

func indexLast(s string, c byte) int {
	for i := len(s) - 1; i >= 0; i-- {
		if s[i] == c {
			return i
		}
	}
	return -1
}

// Free-text patterns. We require reverse-DNS shape (at least one dot in the
// namespace) so generic English sentences like "bind to MCP server X" don't
// over-trigger.
var nlBindRE = regexp.MustCompile(
	`(?i)(?:bind|connect|attach|register)(?:\s+(?:to|the))?\s+(?:mcp\s+server\s+)?` +
		`([a-zA-Z0-9._\-]+(?:\.[a-zA-Z0-9._\-]+)+(?:/[A-Za-z0-9._\-]+)?)`,
)

// Names like victim-mcp-server (no dot) are caught by a secondary pattern
// because the victim app uses that exact identifier. We keep this list
// narrow so it doesn't drift into false positives.
var nlBindBareNamesRE = regexp.MustCompile(
	`(?i)\b(victim-mcp-server)\b`,
)

func matchNaturalLanguageBind(text string) (string, bool) {
	if m := nlBindRE.FindStringSubmatch(text); m != nil {
		return m[1], true
	}
	if m := nlBindBareNamesRE.FindStringSubmatch(text); m != nil {
		return m[1], true
	}
	return "", false
}
