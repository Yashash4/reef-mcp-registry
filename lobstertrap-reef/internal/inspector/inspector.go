package inspector

import "strings"

// PromptMetadata holds all extracted metadata from a prompt or response text.
type PromptMetadata struct {
	IntentCategory            string   `json:"intent_category"`
	IntentConfidence          float64  `json:"intent_confidence"`
	RiskScore                 float64  `json:"risk_score"`
	ContainsCode              bool     `json:"contains_code"`
	ContainsCredentials       bool     `json:"contains_credentials"`
	ContainsPII               bool     `json:"contains_pii"`
	ContainsPIIRequest        bool     `json:"contains_pii_request"`
	ContainsSystemCommands    bool     `json:"contains_system_commands"`
	ContainsMalwareRequest    bool     `json:"contains_malware_request"`
	ContainsPhishingPatterns  bool     `json:"contains_phishing_patterns"`
	ContainsRoleImpersonation bool     `json:"contains_role_impersonation"`
	ContainsExfiltration      bool     `json:"contains_exfiltration"`
	ContainsHarmPatterns      bool     `json:"contains_harm_patterns"`
	ContainsObfuscation       bool     `json:"contains_obfuscation"`
	ContainsInjectionPatterns bool     `json:"contains_injection_patterns"`
	ContainsFilePaths         bool     `json:"contains_file_paths"`
	ContainsSensitivePaths    bool     `json:"contains_sensitive_paths"`
	ContainsURLs              bool     `json:"contains_urls"`
	TargetPaths               []string `json:"target_paths"`
	TargetDomains             []string `json:"target_domains"`
	TargetCommands            []string `json:"target_commands"`
	TokenCount                int      `json:"token_count"`

	// Reef-only signals (populated regardless of --enable-reef; consumed by
	// the Reef action dispatch and policy match-table when the flag is on).
	// These mirror the heuristic from victim/app/lib/exfil.ts so the YAML
	// rule `contains_markdown_image_with_external_url` can express the
	// EchoLeak markdown-image-exfil pattern.
	ContainsMarkdownImageWithExternalURL bool             `json:"contains_markdown_image_with_external_url,omitempty"`
	MarkdownImageURLs                    []string         `json:"markdown_image_urls,omitempty"`
	BareURLs                             []string         `json:"bare_urls,omitempty"`
	ExfilCandidates                      []ExfilCandidate `json:"exfil_candidates,omitempty"`

	// Reef agent/session fields — declared in A-4, populated by A-6
	// (SVID/EWMA package). Default zero-value until A-6 lands. Exposed here
	// so YAML rules can already match on them today.
	AgentIdentityVerified bool    `json:"agent_identity_verified,omitempty"`
	IntentMismatchScore   float64 `json:"intent_mismatch_score,omitempty"`
	AsiCategoryEwma       float64 `json:"asi_category_ewma,omitempty"`

	// Reef MCP supply-chain field (A-5). When the prompt mentions an MCP
	// server bind attempt (regex-heuristic — `mcp://`, `bind_mcp(name,...)`,
	// or a literal MCP manifest reference), MCPBindTarget carries the
	// (mcpName, version) tuple the pipeline forwards to the Reef Atlas
	// signature registry. Empty string => no bind detected; pipeline skips
	// the registry call. MCPBindVersion may be empty when the prompt didn't
	// specify a version; Atlas treats missing as the canonical pinned key
	// miss (BIND_DENIED).
	MCPBindTarget    string `json:"mcp_bind_target,omitempty"`
	MCPBindVersion   string `json:"mcp_bind_version,omitempty"`
	MCPBindTransport string `json:"mcp_bind_transport,omitempty"`

	// MCPBindDecision is populated by the pre-ingress verifier hook in the
	// pipeline after it calls the Reef Atlas registry. Values: "allow",
	// "deny", "review", or "" when the inspector didn't detect a bind
	// attempt. Exposed so YAML rules can match `mcp_bind_target_decision`.
	MCPBindDecision  string `json:"mcp_bind_target_decision,omitempty"`
	// MCPBindRegistryID is the registry_id Atlas returned (empty on deny).
	MCPBindRegistryID string `json:"mcp_bind_registry_id,omitempty"`
	// MCPBindViolations is the violation code/detail list from Atlas. The
	// first entry's Code is mirrored into the rule's DenyMessage so audit
	// logs and the proxy response carry the citation (MCP-RCE-26.04, etc.).
	MCPBindViolations []MCPBindViolation `json:"mcp_bind_violations,omitempty"`
}

// MCPBindViolation mirrors mcpsupply.Violation without a cross-package
// dependency. The pipeline copies values into this struct after each Atlas
// /verify call.
type MCPBindViolation struct {
	Code   string `json:"code"`
	Detail string `json:"detail"`
}

// Inspector is the DPI engine. It extracts structured metadata from text
// using compiled regex patterns — no LLM call involved.
//
// Reef extensions (A-4): the inspector additionally runs the markdown-exfil
// heuristic ported from victim/app/lib/exfil.ts so the YAML rule
// `contains_markdown_image_with_external_url` can match without any extra
// caller plumbing. The trusted-domain list (policy.Network.AllowedDomains)
// is passed via WithTrustedDomains so detection respects the operator's
// allowlist — markdown images to api.openai.com don't get flagged.
type Inspector struct {
	trustedDomains       []string
	extraSecretFragments []string
}

// New creates a new Inspector with no trusted-domain context. Used by the
// `inspect` CLI command and by tests that don't load a full policy.
func New() *Inspector {
	return &Inspector{}
}

// NewWithTrustedDomains creates an Inspector that won't flag markdown images
// pointing at any of the listed hosts (same wildcard semantics as
// policy.DomainMatches). Passing nil/empty is equivalent to New().
func NewWithTrustedDomains(trusted []string) *Inspector {
	return &Inspector{trustedDomains: append([]string(nil), trusted...)}
}

// WithExtraSecretFragments lets callers (the victim app in tests, the audit
// integration in production) provide known-secret literals so the heuristic
// flags any URL containing them even when the credential-shape regex doesn't
// trigger.
func (ins *Inspector) WithExtraSecretFragments(fragments []string) *Inspector {
	out := *ins
	out.extraSecretFragments = append([]string(nil), fragments...)
	return &out
}

// Inspect extracts metadata from the given text.
func (ins *Inspector) Inspect(text string) *PromptMetadata {
	meta := &PromptMetadata{}

	// Boolean signals
	meta.ContainsCredentials = CredentialPatterns.MatchAny(text)
	meta.ContainsPII = PIIPatterns.MatchAny(text)
	meta.ContainsPIIRequest = PIIRequestPatterns.MatchAny(text)
	meta.ContainsMalwareRequest = MalwareRequestPatterns.MatchAny(text)
	meta.ContainsPhishingPatterns = PhishingPatterns.MatchAny(text)
	meta.ContainsRoleImpersonation = RoleImpersonationPatterns.MatchAny(text)
	meta.ContainsExfiltration = ExfiltrationPatterns.MatchAny(text)
	meta.ContainsHarmPatterns = HarmPatterns.MatchAny(text)
	meta.ContainsObfuscation = ObfuscationPatterns.MatchAny(text)
	meta.ContainsInjectionPatterns = InjectionPatterns.MatchAny(text)
	meta.ContainsSystemCommands = ShellCommandPatterns.MatchAny(text)
	meta.ContainsCode = CodePatterns.MatchAny(text)
	meta.ContainsURLs = URLPatterns.MatchAny(text)

	// Extract file paths
	meta.TargetPaths = FilePathPatterns.FindAll(text)
	meta.ContainsFilePaths = len(meta.TargetPaths) > 0

	// Check for sensitive paths
	hasSensitivePaths := SensitivePathPatterns.MatchAny(text)
	meta.ContainsSensitivePaths = hasSensitivePaths

	// Extract domains from URLs
	if matches := DomainExtractPattern.FindAllStringSubmatch(text, -1); len(matches) > 0 {
		seen := make(map[string]struct{})
		for _, m := range matches {
			if len(m) > 1 {
				domain := strings.ToLower(m[1])
				if _, ok := seen[domain]; !ok {
					seen[domain] = struct{}{}
					meta.TargetDomains = append(meta.TargetDomains, domain)
				}
			}
		}
	}

	// Extract commands
	meta.TargetCommands = CommandExtractPatterns.FindAll(text)

	// Reef markdown-exfil heuristic. Mirrors victim/app/lib/exfil.ts so the
	// MODIFY action's rewrite recipe and the YAML signal
	// `contains_markdown_image_with_external_url` agree on what counts as
	// exfil. The trusted-domain list suppresses false positives for legit
	// hosts (api.openai.com, the company's own CDN, etc).
	candidates := DetectMarkdownExfil(text, MarkdownExfilOptions{
		TrustedDomains:       ins.trustedDomains,
		ExtraSecretFragments: ins.extraSecretFragments,
	})
	if len(candidates) > 0 {
		meta.ExfilCandidates = candidates
		for _, c := range candidates {
			if c.IsMarkdownImage {
				meta.ContainsMarkdownImageWithExternalURL = true
				meta.MarkdownImageURLs = append(meta.MarkdownImageURLs, c.URL)
			} else {
				meta.BareURLs = append(meta.BareURLs, c.URL)
			}
		}
	}

	// Reef A-5: detect MCP server bind attempts so the pipeline can call
	// the Atlas signature registry BEFORE the rule table evaluates. The
	// extractor recognises bind_mcp() tool calls, mcp:// URIs, and the
	// natural-language patterns the cold-open demo uses. Empty mcpName
	// means "no bind attempt detected" — the pipeline skips the verifier
	// in that case (no perf cost on benign prompts).
	if name, ver, tr, ok := DetectMCPBind(text); ok {
		meta.MCPBindTarget = name
		meta.MCPBindVersion = ver
		meta.MCPBindTransport = tr
	}

	// Classify intent
	classification := Classify(text)
	meta.IntentCategory = string(classification.Category)
	meta.IntentConfidence = classification.Confidence

	// Compute risk score
	meta.RiskScore = ComputeRisk(RiskSignals{
		ContainsCredentials:       meta.ContainsCredentials,
		ContainsPII:               meta.ContainsPII,
		ContainsPIIRequest:        meta.ContainsPIIRequest,
		ContainsMalwareRequest:    meta.ContainsMalwareRequest,
		ContainsPhishingPatterns:  meta.ContainsPhishingPatterns,
		ContainsRoleImpersonation: meta.ContainsRoleImpersonation,
		ContainsExfiltration:      meta.ContainsExfiltration,
		ContainsHarmPatterns:      meta.ContainsHarmPatterns,
		ContainsObfuscation:       meta.ContainsObfuscation,
		ContainsInjectionPatterns: meta.ContainsInjectionPatterns,
		ContainsSystemCommands:    meta.ContainsSystemCommands,
		ContainsFilePaths:         meta.ContainsFilePaths,
		ContainsURLs:              meta.ContainsURLs,
		ContainsCode:              meta.ContainsCode,
		HasSensitivePaths:         hasSensitivePaths,
		Intent:                    classification.Category,
		IntentConfidence:          classification.Confidence,
	})

	// Rough token estimate (~4 chars per token)
	meta.TokenCount = estimateTokens(text)

	return meta
}

// estimateTokens gives a rough token count (~4 chars per token for English).
func estimateTokens(text string) int {
	if len(text) == 0 {
		return 0
	}
	// Rough heuristic: ~4 characters per token
	tokens := len(text) / 4
	if tokens == 0 {
		tokens = 1
	}
	return tokens
}
