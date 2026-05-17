// Package identity declared-intent extraction + comparison against DPI-detected
// intent. Produces a 0.0–1.0 mismatch score the pipeline puts on
// PromptMetadata.IntentMismatchScore. YAML rules then match on the score with
// `match_type: threshold` to dispatch HUMAN_REVIEW for misbehaving agents.
//
// Scoring model:
//   - declared_intent vs detected_intent (binary): contributes 1/3 if they
//     differ, 0 if they match. "general" / empty detected counts as no
//     mismatch (DPI couldn't classify confidently).
//   - declared_tools vs detected_tools (Jaccard distance over normalised
//     sets): contributes 1/3 weighted by Jaccard distance.
//   - declared_domains vs detected_domains (Jaccard distance): contributes
//     1/3 weighted by Jaccard distance.
//
// The total is clamped to [0.0, 1.0]. 0.0 = perfect match / declared envelope
// fully contains detected, 1.0 = completely disjoint.
//
// Why Jaccard: it's symmetric, bounded in [0, 1], and gives smooth gradient
// rather than a binary mismatch flag. Operators can tune the threshold via
// YAML without rewriting the scorer.
package identity

import (
	"strings"
)

// DetectedIntent captures the DPI inspector's view of an agent's actual
// behaviour on a given request. Populated by the inspector + the pipeline
// from PromptMetadata before calling IntentMismatch.
type DetectedIntent struct {
	IntentCategory string
	// Tools is the set of tool / capability names the request appears to be
	// exercising. For the v1 pipeline this is best-effort — populated from
	// MCP bind targets, recognised command verbs, and (when wired) function-
	// call arguments. Empty means DPI did not detect any tool usage.
	Tools []string
	// Domains is the set of network destinations referenced in the request
	// (PromptMetadata.TargetDomains). Used to detect "declared intra-corp
	// only" but actually-touching-pastebin behaviours.
	Domains []string
}

// IntentMismatch returns a score in [0.0, 1.0]:
//   - 0.0  →  declared envelope contains detected (no mismatch)
//   - 1.0  →  declared and detected are completely disjoint
//   - in-between → partial overlap, smooth interpolation
//
// Empty declared sets do NOT score as 0.0 automatically — an agent that
// declares nothing but acts broadly should be flagged. The "empty declared"
// case scores like "declared = {}" so any non-empty detected raises the
// score. Empty detected, on the other hand, scores 0.0 (the agent didn't
// actually do anything to mismatch).
func IntentMismatch(declared Scope, detected DetectedIntent) float64 {
	const (
		weightIntent  = 1.0 / 3.0
		weightTools   = 1.0 / 3.0
		weightDomains = 1.0 / 3.0
	)

	// Component 1: intent label.
	intentScore := 0.0
	if detected.IntentCategory != "" &&
		detected.IntentCategory != "general" &&
		declared.DeclaredIntent != "" &&
		!intentLabelMatches(declared.DeclaredIntent, detected.IntentCategory) {
		intentScore = 1.0
	}

	// Component 2: tools Jaccard distance. An empty detected set means DPI
	// saw no tool usage — that's NOT a mismatch (the agent isn't actually
	// trying to do anything yet). Only score when detected has activity.
	toolsScore := 0.0
	detectedTools := normaliseSet(detected.Tools)
	if len(detectedTools) > 0 {
		toolsScore = jaccardDistance(
			normaliseSet(declared.DeclaredTools),
			detectedTools,
		)
	}

	// Component 3: domains Jaccard distance — same empty-detected semantics.
	domainsScore := 0.0
	detectedDomains := normaliseSet(detected.Domains)
	if len(detectedDomains) > 0 {
		domainsScore = jaccardDistance(
			normaliseSet(declared.DeclaredDomains),
			detectedDomains,
		)
	}

	score := weightIntent*intentScore + weightTools*toolsScore + weightDomains*domainsScore
	if score < 0 {
		return 0
	}
	if score > 1 {
		return 1
	}
	return score
}

// jaccardDistance returns 1 - |A ∩ B| / |A ∪ B|. Distance is 0 for identical
// sets and 1 for disjoint sets.
//
// Edge cases:
//   - Both empty → 0 (no information, no mismatch).
//   - One side empty, the other not → 1 (declared envelope says nothing but
//     detected has activity, or vice versa — both are mismatch signals).
func jaccardDistance(a, b map[string]struct{}) float64 {
	if len(a) == 0 && len(b) == 0 {
		return 0
	}
	if len(a) == 0 || len(b) == 0 {
		return 1
	}
	intersect := 0
	for k := range a {
		if _, ok := b[k]; ok {
			intersect++
		}
	}
	union := len(a) + len(b) - intersect
	if union == 0 {
		return 0
	}
	similarity := float64(intersect) / float64(union)
	return 1 - similarity
}

// normaliseSet lowercases + trims + dedupes a string slice into a set.
func normaliseSet(items []string) map[string]struct{} {
	out := make(map[string]struct{}, len(items))
	for _, it := range items {
		k := strings.TrimSpace(strings.ToLower(it))
		if k == "" {
			continue
		}
		out[k] = struct{}{}
	}
	return out
}

// intentLabelMatches compares a declared intent label (free-form, e.g.
// "read+summarize", "fetch_url") against a DPI-detected category
// ("communication", "file_io", "code_execution", etc.).
//
// The mapping is intentionally permissive: declared labels frequently contain
// "+", "_", "/", or hyphenated tokens that should each be considered against
// the detected category. We pass the comparison if any normalised declared
// token is contained-by or contains the detected category, or vice versa.
func intentLabelMatches(declared, detected string) bool {
	d := strings.ToLower(strings.TrimSpace(declared))
	t := strings.ToLower(strings.TrimSpace(detected))
	if d == "" || t == "" {
		return true
	}
	if d == t {
		return true
	}
	// Split declared on common separators and check each token.
	seps := []string{"+", ",", "/", "|", " ", "-"}
	rawTokens := []string{d}
	for _, s := range seps {
		var next []string
		for _, tok := range rawTokens {
			for _, p := range strings.Split(tok, s) {
				p = strings.TrimSpace(p)
				if p != "" {
					next = append(next, p)
				}
			}
		}
		rawTokens = next
	}
	// Build the synonym envelope for the detected category. A category like
	// "communication" should match declared "send", "email", "message", etc.
	envelope := categorySynonyms(t)
	for _, tok := range rawTokens {
		if tok == t {
			return true
		}
		if _, ok := envelope[tok]; ok {
			return true
		}
		// Substring fall-back: declared "summarize" should match category
		// "data_access" (no), but declared "data_access" should match itself.
		if strings.Contains(t, tok) || strings.Contains(tok, t) {
			return true
		}
	}
	return false
}

// categorySynonyms returns the small synonym set for a DPI category label so
// declared free-form intents map onto detected categories smoothly.
func categorySynonyms(category string) map[string]struct{} {
	switch category {
	case "communication":
		return map[string]struct{}{
			"send": {}, "message": {}, "email": {}, "notify": {}, "post": {}, "publish": {},
		}
	case "data_access":
		return map[string]struct{}{
			"read": {}, "fetch": {}, "get": {}, "load": {}, "open": {}, "query": {},
			"summarize": {}, "summarise": {}, "ingest": {},
		}
	case "code_execution":
		return map[string]struct{}{
			"execute": {}, "run": {}, "eval": {}, "exec": {}, "compile": {}, "build": {},
		}
	case "file_io":
		return map[string]struct{}{
			"read": {}, "write": {}, "create": {}, "delete": {}, "move": {}, "copy": {},
		}
	case "network":
		return map[string]struct{}{
			"fetch": {}, "http": {}, "request": {}, "download": {}, "upload": {},
		}
	case "credential_access":
		return map[string]struct{}{
			"secret": {}, "key": {}, "token": {}, "password": {}, "credential": {},
		}
	case "system":
		return map[string]struct{}{
			"shell": {}, "exec": {}, "system": {}, "kernel": {},
		}
	}
	return map[string]struct{}{}
}
