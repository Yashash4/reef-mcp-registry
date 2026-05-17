package actions

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

func TestHumanReview_PostsPayloadAndReturns202(t *testing.T) {
	var captured atomic.Value // *HumanReviewPayload
	srvURL := liveTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("expected application/json content type, got %q", r.Header.Get("Content-Type"))
		}
		var p HumanReviewPayload
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &p); err != nil {
			t.Errorf("payload not valid JSON: %v", err)
		}
		captured.Store(&p)
		w.WriteHeader(http.StatusAccepted)
	})

	pol := &policy.Policy{
		Version:    "test",
		PolicyName: "hr",
		Notifications: policy.Notifications{
			HumanReviewWebhook:           srvURL,
			HumanReviewRetryAfterSeconds: 17,
		},
	}
	d := newTestDispatcher(t, pol)

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		RequestID: "req-HR",
		AgentID:   "agent-7",
		ConvID:    "conv-22",
		Rule: policy.RuleResult{
			Matched:  true,
			Action:   policy.ActionHumanReview,
			RuleName: "human_review_novel_attack_pattern",
		},
		Meta: stubMeta(),
		Body: "novel attack body",
	})

	if out.Err != nil {
		t.Fatalf("Err: %v", out.Err)
	}
	if out.Action != policy.ActionHumanReview {
		t.Errorf("Action = %s, want HUMAN_REVIEW", out.Action)
	}
	if out.StatusCode != 202 {
		t.Errorf("StatusCode = %d, want 202", out.StatusCode)
	}
	if !strings.HasPrefix(out.ReviewID, "r-") {
		t.Errorf("ReviewID = %q, want r- prefix", out.ReviewID)
	}
	if out.ReviewRetryAfterSec != 17 {
		t.Errorf("ReviewRetryAfterSec = %d, want 17", out.ReviewRetryAfterSec)
	}

	got := captured.Load()
	if got == nil {
		t.Fatal("webhook never received the payload")
	}
	p := got.(*HumanReviewPayload)
	if p.ReviewID != out.ReviewID {
		t.Errorf("payload ReviewID %q != outcome ReviewID %q", p.ReviewID, out.ReviewID)
	}
	if p.AgentID != "agent-7" {
		t.Errorf("payload AgentID = %q, want agent-7", p.AgentID)
	}
	if p.Rule != "human_review_novel_attack_pattern" {
		t.Errorf("payload Rule = %q, want human_review_novel_attack_pattern", p.Rule)
	}
	if p.Body != "novel attack body" {
		t.Errorf("payload Body = %q", p.Body)
	}
	if p.Direction != string(DirectionIngress) {
		t.Errorf("payload Direction = %q, want ingress", p.Direction)
	}
}

func TestHumanReview_NoWebhookFailsClosed(t *testing.T) {
	pol := &policy.Policy{Version: "test", PolicyName: "hr"}
	d := newTestDispatcher(t, pol)

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		Rule: policy.RuleResult{
			Action:   policy.ActionHumanReview,
			RuleName: "no_webhook",
		},
		Meta: stubMeta(),
	})

	if out.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY (fail-closed)", out.Action)
	}
	if out.Err == nil {
		t.Error("expected Err set")
	}
}

func TestHumanReview_WebhookTimeoutFailsClosed(t *testing.T) {
	pol := &policy.Policy{
		Version:    "test",
		PolicyName: "hr",
		Notifications: policy.Notifications{
			HumanReviewWebhook: "http://example.invalid",
		},
	}
	d := newTestDispatcher(t, pol)
	// Inject a poster that always errors.
	mp := &mockWebhookPoster{err: errors.New("simulated timeout")}
	d.setWebhookClient(mp)

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		Rule:      policy.RuleResult{Action: policy.ActionHumanReview, RuleName: "r"},
		Meta:      stubMeta(),
	})
	if out.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY", out.Action)
	}
	if out.Err == nil {
		t.Error("expected Err set on timeout")
	}
	if mp.count != 1 {
		t.Errorf("expected 1 webhook attempt, got %d", mp.count)
	}
}

func TestHumanReview_Webhook5xxFailsClosed(t *testing.T) {
	srvURL := liveTestServer(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	})
	pol := &policy.Policy{
		Version:    "test",
		PolicyName: "hr",
		Notifications: policy.Notifications{
			HumanReviewWebhook: srvURL,
		},
	}
	d := newTestDispatcher(t, pol)

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		Rule:      policy.RuleResult{Action: policy.ActionHumanReview, RuleName: "r"},
		Meta:      stubMeta(),
	})
	if out.Action != policy.ActionDeny {
		t.Errorf("Action = %s, want DENY on 5xx", out.Action)
	}
	if !strings.Contains(out.Reason, "500") {
		t.Errorf("Reason should mention status 500: %s", out.Reason)
	}
}

func TestHumanReview_PayloadIncludesAgentIdentityFields(t *testing.T) {
	var captured atomic.Value
	srvURL := liveTestServer(t, func(w http.ResponseWriter, r *http.Request) {
		var p HumanReviewPayload
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &p)
		captured.Store(&p)
		w.WriteHeader(http.StatusAccepted)
	})

	pol := &policy.Policy{
		Version:    "test",
		PolicyName: "hr",
		Notifications: policy.Notifications{
			HumanReviewWebhook: srvURL,
		},
	}
	d := newTestDispatcher(t, pol)

	meta := stubMeta()
	meta.AsiCategoryEwma = 0.81
	meta.IntentMismatchScore = 0.42
	meta.AgentIdentityVerified = true

	out := d.Dispatch(context.Background(), Decision{
		Direction: DirectionIngress,
		Rule:      policy.RuleResult{Action: policy.ActionHumanReview, RuleName: "hr"},
		Meta:      meta,
	})
	if out.Err != nil {
		t.Fatalf("Err: %v", out.Err)
	}
	got := captured.Load().(*HumanReviewPayload)
	if got.Metadata["asi_category_ewma"].(float64) != 0.81 {
		t.Errorf("metadata.asi_category_ewma missing/wrong: %v", got.Metadata)
	}
	if got.Metadata["intent_mismatch_score"].(float64) != 0.42 {
		t.Errorf("metadata.intent_mismatch_score missing/wrong: %v", got.Metadata)
	}
	if got.Metadata["agent_identity_verified"].(bool) != true {
		t.Errorf("metadata.agent_identity_verified missing/wrong: %v", got.Metadata)
	}
}
