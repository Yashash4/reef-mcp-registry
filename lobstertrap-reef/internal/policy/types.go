package policy

// Action represents the action to take when a rule matches.
type Action string

const (
	ActionAllow       Action = "ALLOW"
	ActionDeny        Action = "DENY"
	ActionLog         Action = "LOG"
	ActionModify      Action = "MODIFY"
	ActionQuarantine  Action = "QUARANTINE"
	ActionHumanReview Action = "HUMAN_REVIEW"
	ActionRateLimit   Action = "RATE_LIMIT"
	ActionRedirect    Action = "REDIRECT"
)

// MatchType represents the type of match operation for a condition.
type MatchType string

const (
	MatchExact     MatchType = "exact"
	MatchPrefix    MatchType = "prefix"
	MatchGlob      MatchType = "glob"
	MatchRegex     MatchType = "regex"
	MatchRange     MatchType = "range"
	MatchContains  MatchType = "contains"
	MatchBoolean   MatchType = "boolean"
	MatchThreshold MatchType = "threshold"
)

// MatchCondition is a single match predicate in a rule.
type MatchCondition struct {
	Field     string    `yaml:"field" json:"field"`
	MatchType MatchType `yaml:"match_type" json:"match_type"`
	Value     any       `yaml:"value" json:"value"`
	Negate    bool      `yaml:"negate,omitempty" json:"negate,omitempty"`
}

// GuardRule is a single firewall-style rule with priority, conditions, and action.
type GuardRule struct {
	Name        string           `yaml:"name" json:"name"`
	Description string           `yaml:"description" json:"description"`
	Priority    int              `yaml:"priority" json:"priority"`
	Action      Action           `yaml:"action" json:"action"`
	DenyMessage string           `yaml:"deny_message,omitempty" json:"deny_message,omitempty"`
	Conditions  []MatchCondition `yaml:"conditions" json:"conditions"`

	// ModifyStrategy names the inline-rewrite recipe the MODIFY action runs
	// when this rule matches. Recognised values (A-4):
	//   - "strip_markdown_images_to_untrusted_domains"
	//   - "redact_bare_urls_with_secret_fragments"
	// Other values are logged and treated as a no-op (the action degrades to
	// LOG with a structured warning so audits never silently swallow them).
	ModifyStrategy string `yaml:"modify_strategy,omitempty" json:"modify_strategy,omitempty"`

	// RedirectTargetBand selects an entry from policy.Network.RedirectTargets
	// for the REDIRECT action. Conventional bands are "low" / "medium" / "high"
	// but the value is opaque — any key present in the map is accepted.
	RedirectTargetBand string `yaml:"redirect_target_band,omitempty" json:"redirect_target_band,omitempty"`
}

// RateLimits configures rate limiting thresholds.
type RateLimits struct {
	RequestsPerMinute int `yaml:"requests_per_minute" json:"requests_per_minute"`
	RequestsPerHour   int `yaml:"requests_per_hour" json:"requests_per_hour"`
	BurstThreshold    int `yaml:"burst_threshold" json:"burst_threshold"`
}

// NetworkPolicy configures allowed/denied domains and (Reef-only) the
// per-risk-band redirect targets used by the REDIRECT action.
type NetworkPolicy struct {
	EgressPolicy   string   `yaml:"egress_policy" json:"egress_policy"`
	AllowedDomains []string `yaml:"allowed_domains" json:"allowed_domains"`
	DeniedDomains  []string `yaml:"denied_domains" json:"denied_domains"`

	// RedirectTargets maps a risk-band label (e.g. "low", "medium", "high")
	// to an upstream URL that the REDIRECT action will route to. Populated by
	// policy YAML; when --enable-reef is off this field is parsed but ignored
	// by the engine. Added by A-4 to back the REDIRECT action contract.
	RedirectTargets map[string]string `yaml:"redirect_targets,omitempty" json:"redirect_targets,omitempty"`
}

// Notifications configures the outbound webhook surface used by Reef
// actions that hand off to a human review or alerting queue. Populated by
// policy YAML; --enable-reef must be on for the dispatcher to use these.
type Notifications struct {
	// HumanReviewWebhook is the URL the HUMAN_REVIEW action POSTs to with
	// the request payload and a callback URL the approval UI can hit to
	// release or deny. Phase 2 hardens this with mTLS + signing; v1 ships
	// the JSON envelope only.
	HumanReviewWebhook string `yaml:"human_review_webhook,omitempty" json:"human_review_webhook,omitempty"`
	// HumanReviewTimeoutMs is the dial+request timeout for the webhook.
	// Zero falls back to a 1500ms default (DialContext + ResponseHeaderTimeout).
	HumanReviewTimeoutMs int `yaml:"human_review_timeout_ms,omitempty" json:"human_review_timeout_ms,omitempty"`
	// HumanReviewRetryAfterSeconds is echoed back to the caller in the
	// Retry-After header so the agent (or its scheduler) knows when to poll.
	HumanReviewRetryAfterSeconds int `yaml:"human_review_retry_after_seconds,omitempty" json:"human_review_retry_after_seconds,omitempty"`
}

// FilesystemPolicy configures allowed/denied file paths.
type FilesystemPolicy struct {
	DeniedPaths       []string `yaml:"denied_paths" json:"denied_paths"`
	AllowedReadPaths  []string `yaml:"allowed_read_paths" json:"allowed_read_paths"`
	AllowedWritePaths []string `yaml:"allowed_write_paths" json:"allowed_write_paths"`
}

// Policy is the top-level policy configuration loaded from YAML.
type Policy struct {
	Version       string           `yaml:"version" json:"version"`
	PolicyName    string           `yaml:"policy_name" json:"policy_name"`
	DefaultAction Action           `yaml:"default_action" json:"default_action"`
	IngressRules  []GuardRule      `yaml:"ingress_rules" json:"ingress_rules"`
	EgressRules   []GuardRule      `yaml:"egress_rules" json:"egress_rules"`
	RateLimits    RateLimits       `yaml:"rate_limits" json:"rate_limits"`
	Network       NetworkPolicy    `yaml:"network" json:"network"`
	Filesystem    FilesystemPolicy `yaml:"filesystem" json:"filesystem"`
	Notifications Notifications    `yaml:"notifications,omitempty" json:"notifications,omitempty"`
}

// MatchActionTable holds a sorted list of rules and a default action.
type MatchActionTable struct {
	Rules         []GuardRule
	DefaultAction Action
}

// RuleResult captures which rule matched and what action was taken.
type RuleResult struct {
	Matched     bool   `json:"matched"`
	RuleName    string `json:"rule_name,omitempty"`
	Action      Action `json:"action"`
	DenyMessage string `json:"deny_message,omitempty"`

	// ModifyStrategy is propagated from the matched rule so the Reef action
	// dispatcher knows which rewrite recipe to apply.
	ModifyStrategy string `json:"modify_strategy,omitempty"`
	// RedirectTargetBand is propagated from the matched rule so the Reef
	// REDIRECT action can resolve to the correct upstream URL.
	RedirectTargetBand string `json:"redirect_target_band,omitempty"`
}
