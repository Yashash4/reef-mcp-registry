package actions

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// HumanReviewPayload is the JSON envelope POSTed to the approval webhook.
// The Stage UI (Phase 2) hosts the matching receiver; v1 ships the contract
// only. The CallbackURL field is left empty in v1 — the Stage UI will fill
// it in when it's online. Keep the schema stable across versions: existing
// audit consumers depend on it.
type HumanReviewPayload struct {
	ReviewID       string         `json:"review_id"`
	Timestamp      time.Time      `json:"timestamp"`
	RequestID      string         `json:"request_id"`
	AgentID        string         `json:"agent_id,omitempty"`
	ConversationID string         `json:"conversation_id,omitempty"`
	Rule           string         `json:"rule"`
	Direction      string         `json:"direction"`
	Body           string         `json:"body"`
	Metadata       map[string]any `json:"metadata"`
	CallbackURL    string         `json:"callback_url,omitempty"`
}

// webhookPoster abstracts the HTTP POST so tests can inject a fake. The
// production implementation is httpPoster (defined below).
type webhookPoster interface {
	Post(ctx context.Context, url string, payload HumanReviewPayload, timeout time.Duration) (*http.Response, error)
}

// httpPoster is the production webhookPoster — a thin wrapper around an
// http.Client that JSON-encodes the payload.
type httpPoster struct {
	client *http.Client
}

func (h *httpPoster) Post(ctx context.Context, url string, payload HumanReviewPayload, timeout time.Duration) (*http.Response, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("human_review: marshal payload: %w", err)
	}
	if timeout <= 0 {
		timeout = defaults.HumanReviewWebhookTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("human_review: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Reef-Review-ID", payload.ReviewID)
	return h.client.Do(req)
}

// runHumanReview POSTs the request/response to the configured webhook and
// returns a 202 Accepted outcome with the review ID. The caller (proxy) then
// emits Retry-After + Review-ID headers.
//
// Failure modes (5xx, timeout, missing webhook) do NOT silently allow the
// request through — they degrade to DENY with a structured reason. Phase 2
// adds an in-memory pending-review queue so the conversation can resume
// when the approver clicks "release"; v1 records the attempt + denies.
func (d *Dispatcher) runHumanReview(ctx context.Context, dec Decision) Outcome {
	out := Outcome{Action: policy.ActionHumanReview, StatusCode: 202}

	webhook := d.policy.Notifications.HumanReviewWebhook
	if webhook == "" {
		// No webhook configured — fail closed. Operators who declare a
		// HUMAN_REVIEW rule MUST configure a webhook target; otherwise the
		// rule's effect is "deny silently" which is dishonest in audits.
		reason := fmt.Sprintf("rule %q HUMAN_REVIEW has no notifications.human_review_webhook configured; failing closed",
			dec.Rule.RuleName)
		d.logger.Warn("human_review_no_webhook",
			"rule", dec.Rule.RuleName,
			"request_id", dec.RequestID,
		)
		return Outcome{
			Action:     policy.ActionDeny,
			StatusCode: 451,
			Reason:     reason,
			Err:        fmt.Errorf("human_review: %s", reason),
		}
	}

	reviewID := newReviewID()
	timeoutMs := d.policy.Notifications.HumanReviewTimeoutMs
	if timeoutMs <= 0 {
		timeoutMs = int(defaults.HumanReviewWebhookTimeout / time.Millisecond)
	}
	retryAfter := d.policy.Notifications.HumanReviewRetryAfterSeconds
	if retryAfter <= 0 {
		// Default Retry-After: let the agent back off (see defaults pkg).
		retryAfter = int(defaults.HumanReviewRetryAfter / time.Second)
	}

	payload := HumanReviewPayload{
		ReviewID:       reviewID,
		Timestamp:      time.Now().UTC(),
		RequestID:      dec.RequestID,
		AgentID:        dec.AgentID,
		ConversationID: dec.ConvID,
		Rule:           dec.Rule.RuleName,
		Direction:      string(dec.Direction),
		Body:           dec.Body,
		Metadata: map[string]any{
			"intent_category":          dec.Meta.IntentCategory,
			"risk_score":               dec.Meta.RiskScore,
			"asi_category_ewma":        dec.Meta.AsiCategoryEwma,
			"intent_mismatch_score":    dec.Meta.IntentMismatchScore,
			"agent_identity_verified":  dec.Meta.AgentIdentityVerified,
			"contains_markdown_image":  dec.Meta.ContainsMarkdownImageWithExternalURL,
			"contains_credentials":     dec.Meta.ContainsCredentials,
			"contains_pii":             dec.Meta.ContainsPII,
		},
	}

	resp, err := d.webhookClient.Post(ctx, webhook, payload, time.Duration(timeoutMs)*time.Millisecond)
	if err != nil {
		reason := fmt.Sprintf("rule %q HUMAN_REVIEW webhook POST failed: %v", dec.Rule.RuleName, err)
		d.logger.Error("human_review_webhook_failed", err,
			"rule", dec.Rule.RuleName,
			"webhook", webhook,
			"request_id", dec.RequestID,
		)
		return Outcome{
			Action:     policy.ActionDeny,
			StatusCode: 451,
			Reason:     reason,
			Err:        fmt.Errorf("human_review: %w", err),
		}
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 500 {
		reason := fmt.Sprintf("rule %q HUMAN_REVIEW webhook returned %d; failing closed", dec.Rule.RuleName, resp.StatusCode)
		d.logger.Error("human_review_webhook_5xx", fmt.Errorf("status %d", resp.StatusCode),
			"rule", dec.Rule.RuleName,
			"webhook", webhook,
			"request_id", dec.RequestID,
		)
		return Outcome{
			Action:     policy.ActionDeny,
			StatusCode: 451,
			Reason:     reason,
		}
	}

	out.ReviewID = reviewID
	out.ReviewWebhookURL = webhook
	out.ReviewRetryAfterSec = retryAfter
	out.Reason = fmt.Sprintf("rule=%q HUMAN_REVIEW posted to %s review_id=%s", dec.Rule.RuleName, webhook, reviewID)

	d.logger.Info("human_review_queued",
		"rule", dec.Rule.RuleName,
		"webhook", webhook,
		"review_id", reviewID,
		"request_id", dec.RequestID,
	)
	return out
}

// newReviewID returns a `r-<32-hex-chars>` review identifier. The `r-` prefix
// makes review IDs visually distinct from request IDs and quarantine IDs.
func newReviewID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return fmt.Sprintf("r-fallback-%d", time.Now().UnixNano())
	}
	return "r-" + hex.EncodeToString(b[:])
}
