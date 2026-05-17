// Package actions implements the four Lobster Trap actions that ship as the
// Reef extension surface: MODIFY, REDIRECT, QUARANTINE, HUMAN_REVIEW.
//
// Upstream Lobster Trap declared these as enum constants in
// internal/policy/types.go but never wired any runtime behaviour — the
// pipeline simply ignored anything other than ALLOW/DENY. Reef plugs each
// action into a Dispatcher that the pipeline calls AFTER the existing
// match-action table runs.
//
// Architectural contract:
//   - The Dispatcher is constructed at pipeline init and passed in.
//   - The pipeline calls `Dispatch(ctx, decision)` for every non-ALLOW
//     non-DENY non-LOG verdict. ALLOW/DENY/LOG keep their upstream paths.
//   - Each action returns an `Outcome` that the pipeline + proxy use to
//     decide the HTTP shape (rewrite body, 307/451/202, etc.) and the
//     audit trail (modification_reason, quarantine_id, review_id).
//   - --enable-reef gates the whole package: the dispatcher is only built
//     when the flag is on. When the flag is off, MODIFY/REDIRECT/QUARANTINE
//     /HUMAN_REVIEW verdicts log a structured warning and fall back to
//     vanilla Lobster Trap behaviour (LOG-only, with a denied or allowed
//     outcome depending on the action's safety stance).
//
// This file holds the cross-cutting types (Decision, Outcome, Direction,
// Dispatcher) used by every action. Per-action behaviour lives in its own
// file alongside its tests.
package actions

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine"
)

// Direction names which leg of the pipeline produced the decision.
type Direction string

const (
	DirectionIngress Direction = "ingress"
	DirectionEgress  Direction = "egress"
)

// Decision is the input each action handler receives. It bundles the rule
// that matched, the inspected metadata, and the body the action may rewrite
// (egress) or capture for review (ingress).
type Decision struct {
	Direction  Direction
	RequestID  string
	AgentID    string
	ConvID     string // optional, set when the proxy can recover a conversation ID
	Rule       policy.RuleResult
	Meta       *inspector.PromptMetadata
	Body       string // egress: response text; ingress: prompt text
	OriginPath string // request path that triggered this decision (REDIRECT audit)
}

// Outcome is the structured result the action emits. Exactly one of
// (RewrittenBody, RedirectTarget, QuarantineID, ReviewID) is populated
// per action kind — never multiple.
type Outcome struct {
	Action policy.Action

	// MODIFY
	RewrittenBody     string
	Modified          bool
	ModificationReason string
	Edits             int

	// REDIRECT
	RedirectTarget string
	RedirectBand   string

	// QUARANTINE
	QuarantineID    string
	QuarantineEvent *quarantine.Event

	// HUMAN_REVIEW
	ReviewID            string
	ReviewWebhookURL    string
	ReviewRetryAfterSec int

	// Common
	StatusCode int    // HTTP status code the proxy should emit; 0 = upstream default
	Reason     string // human-readable explanation, mirrored into audit log
	Err        error  // non-nil if the action couldn't run; pipeline must fall back to DENY
}

// Logger is the minimal logging surface actions use. zerolog satisfies this
// via zerolog.Logger.{Warn,Info,Error}().Msg pattern — we accept the small
// interface so tests can pass a fake logger.
type Logger interface {
	Warn(msg string, kv ...any)
	Info(msg string, kv ...any)
	Error(msg string, err error, kv ...any)
}

// Dispatcher coordinates the four Reef actions. It owns the dependencies
// each action needs (policy reference for REDIRECT targets + HUMAN_REVIEW
// webhook, quarantine store, HTTP client for webhook posts).
type Dispatcher struct {
	policy          *policy.Policy
	store           *quarantine.Store
	webhookClient   webhookPoster
	redirectFallback string
	logger          Logger

	// modifyExtraSecrets is an optional list of secret literals the MODIFY
	// action's heuristic should also flag (set by the integration test +
	// the production audit hook).
	modifyExtraSecrets []string
}

// DispatcherConfig wires the dependencies a Dispatcher needs. All fields
// are required except ModifyExtraSecrets; nil RedirectFallback is OK (the
// REDIRECT action degrades to DENY when neither a band-specific target nor
// a fallback is configured).
type DispatcherConfig struct {
	Policy             *policy.Policy
	Store              *quarantine.Store
	WebhookClient      *http.Client
	RedirectFallback   string
	Logger             Logger
	ModifyExtraSecrets []string
}

// NewDispatcher builds a Dispatcher. Returns an error if required fields
// are nil — a Reef-enabled pipeline can't run without a quarantine store
// or a policy reference, so we fail fast at construction time.
func NewDispatcher(cfg DispatcherConfig) (*Dispatcher, error) {
	if cfg.Policy == nil {
		return nil, errors.New("actions: policy required")
	}
	if cfg.Store == nil {
		return nil, errors.New("actions: quarantine store required")
	}
	if cfg.Logger == nil {
		return nil, errors.New("actions: logger required")
	}
	client := cfg.WebhookClient
	if client == nil {
		client = http.DefaultClient
	}
	return &Dispatcher{
		policy:             cfg.Policy,
		store:              cfg.Store,
		webhookClient:      &httpPoster{client: client},
		redirectFallback:   cfg.RedirectFallback,
		logger:             cfg.Logger,
		modifyExtraSecrets: append([]string(nil), cfg.ModifyExtraSecrets...),
	}, nil
}

// SetWebhookClient lets tests inject a mock webhook poster. Not exported
// outside the package outside of test files.
func (d *Dispatcher) setWebhookClient(p webhookPoster) {
	d.webhookClient = p
}

// Dispatch routes the decision to the correct action handler. The pipeline
// is responsible for only calling Dispatch on actions Reef owns
// (MODIFY/REDIRECT/QUARANTINE/HUMAN_REVIEW). ALLOW/DENY/LOG remain on the
// upstream path.
func (d *Dispatcher) Dispatch(ctx context.Context, dec Decision) Outcome {
	switch dec.Rule.Action {
	case policy.ActionModify:
		return d.runModify(ctx, dec)
	case policy.ActionRedirect:
		return d.runRedirect(ctx, dec)
	case policy.ActionQuarantine:
		return d.runQuarantine(ctx, dec)
	case policy.ActionHumanReview:
		return d.runHumanReview(ctx, dec)
	default:
		// Not a Reef-owned action — the pipeline should not have called us.
		// Return a structured error so the caller can fall back cleanly.
		return Outcome{
			Action: dec.Rule.Action,
			Err:    fmt.Errorf("actions: Dispatch called with non-Reef action %q", dec.Rule.Action),
		}
	}
}

// Policy returns the policy this Dispatcher was built with. Exposed for
// tests + the integration tests' assertions on REDIRECT target resolution.
func (d *Dispatcher) Policy() *policy.Policy {
	return d.policy
}

// Store returns the quarantine store. Exposed for tests + the Stage UI
// review queue (Phase 2) so it can poll events.
func (d *Dispatcher) Store() *quarantine.Store {
	return d.store
}
