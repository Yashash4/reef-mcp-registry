package otel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"go.opentelemetry.io/otel/attribute"
)

func TestNew_NoneIsAlwaysSafe(t *testing.T) {
	exp, err := New(Config{Kind: ExporterNone})
	if err != nil {
		t.Fatalf("New(none): %v", err)
	}
	if exp.Kind() != ExporterNone {
		t.Errorf("kind=%v want none", exp.Kind())
	}
	// Start + End is safe even with no real exporter.
	ctx, span := exp.Start(context.Background(), "test.span", attribute.String("foo", "bar"))
	span.SetAttribute("policy.rule_id", "deny_invalid_svid")
	span.AddEvent("verdict.DENY", attribute.String("reason", "SVID_INVALID"))
	span.End()
	_ = ctx
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestNew_StdoutEmitsSpans(t *testing.T) {
	exp, err := New(Config{Kind: ExporterStdout, ServiceName: "test"})
	if err != nil {
		t.Fatalf("New(stdout): %v", err)
	}
	_, span := exp.Start(context.Background(), "test.stdout-span",
		attribute.String("agent.id", "spiffe://reef/test"),
	)
	span.End()
	// Force flush.
	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
}

func TestNew_OTLPHTTPSendsToMockCollector(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		w.Header().Set("Content-Type", "application/x-protobuf")
		w.WriteHeader(http.StatusOK)
		// OTLP response is an empty protobuf message; an empty body is acceptable
		// for the collector to ack receipt.
	}))
	defer server.Close()

	endpoint := strings.TrimPrefix(server.URL, "http://")
	exp, err := New(Config{
		Kind:        ExporterOTLPHTTP,
		Endpoint:    endpoint,
		ServiceName: "test",
		Insecure:    true,
	})
	if err != nil {
		t.Fatalf("New(otlp-http): %v", err)
	}

	_, span := exp.Start(context.Background(), "test.otlp-span",
		attribute.String("agent.id", "spiffe://reef/test"),
	)
	span.SetAttribute("policy.action", "ALLOW")
	span.End()

	if err := exp.Shutdown(context.Background()); err != nil {
		t.Errorf("Shutdown: %v", err)
	}
	if received.Load() == 0 {
		t.Errorf("mock collector never received any traces")
	}
}

func TestNew_InvalidKindReturnsNoOp(t *testing.T) {
	exp, err := New(Config{Kind: "garbage", ServiceName: "test"})
	if err == nil {
		t.Fatal("expected error for invalid kind")
	}
	if exp.Kind() != ExporterNone {
		t.Errorf("kind=%v want none (fall-back)", exp.Kind())
	}
}

func TestFromEnv_DefaultsToStdout(t *testing.T) {
	t.Setenv("REEF_OTEL_EXPORTER", "")
	exp := FromEnv()
	if exp.Kind() != ExporterStdout {
		t.Errorf("kind=%v want stdout", exp.Kind())
	}
	exp.Shutdown(context.Background())
}

func TestFromEnv_NoneRespected(t *testing.T) {
	t.Setenv("REEF_OTEL_EXPORTER", "none")
	exp := FromEnv()
	if exp.Kind() != ExporterNone {
		t.Errorf("kind=%v want none", exp.Kind())
	}
}

func TestAttrsFromKV(t *testing.T) {
	attrs := AttrsFromKV(map[string]any{
		"agent.id":         "spiffe://reef/test",
		"policy.action":    "DENY",
		"latency_ms":       42,
		"risk_score":       0.7,
		"identity.verified": true,
		"ignored":          nil,
	})
	if len(attrs) != 5 {
		t.Errorf("attrs len=%d want 5 (nil should be skipped)", len(attrs))
	}
}
