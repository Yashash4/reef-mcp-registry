// Package otel — OpenTelemetry exporter wiring for Reef pipeline events.
//
// Every Reef decision emits an OTel span. Default exporter is OTLP-HTTP to
// localhost:4318 (the Jaeger Collector / OpenTelemetry Collector default).
// Operators override via REEF_OTEL_EXPORTER:
//
//	otlp-http  → OTLP over HTTP/protobuf (default)
//	stdout     → write spans to stdout as JSON (demo / debugging)
//	none       → no-op exporter (CI, smoke tests, integration test isolation)
//
// Spans include attributes for every meta field (agent.id, policy.rule_id,
// action, latency_ms, intent_category, risk_score, asi_category_ewma,
// agent_identity_verified, intent_mismatch_score, etc). Action verdicts
// become span events.
//
// Fail-policy: exporter setup failures degrade to the no-op exporter and
// log a warning. The Reef pipeline must NEVER block on telemetry — agents
// keep flowing even if the collector is down.
package otel

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/exporters/stdout/stdouttrace"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// ExporterKind names the available exporter back-ends.
type ExporterKind string

const (
	ExporterStdout  ExporterKind = "stdout"
	ExporterOTLPHTTP ExporterKind = "otlp-http"
	ExporterNone    ExporterKind = "none"
)

// Config wires the dependencies an Exporter needs.
type Config struct {
	// Kind selects the back-end. Default = ExporterOTLPHTTP.
	Kind ExporterKind
	// Endpoint is the OTLP collector host:port (e.g. "localhost:4318"). Only
	// consumed by ExporterOTLPHTTP.
	Endpoint string
	// ServiceName is added to every span. Default "lobstertrap-reef".
	ServiceName string
	// Insecure controls whether OTLP-HTTP runs without TLS. Default true (the
	// hackathon demo points at a localhost collector with no TLS).
	Insecure bool
}

// Errors returned by New.
var (
	ErrInvalidKind = errors.New("otel: invalid exporter kind")
)

// Exporter wraps a TracerProvider for lifecycle management.
type Exporter interface {
	Start(ctx context.Context, spanName string, attrs ...attribute.KeyValue) (context.Context, Span)
	Shutdown(ctx context.Context) error
	// Tracer returns the underlying OTel Tracer for advanced callers.
	Tracer() trace.Tracer
	// Kind returns the configured exporter kind.
	Kind() ExporterKind
}

// Span is the minimal lifecycle surface callers use. Implementations wrap
// trace.Span so we don't leak the OTel interface across package boundaries.
type Span interface {
	End()
	SetAttribute(key string, value any)
	AddEvent(name string, attrs ...attribute.KeyValue)
	RecordError(err error)
}

// otelSpan adapts trace.Span to our minimal Span interface.
type otelSpan struct {
	inner trace.Span
}

func (s *otelSpan) End() { s.inner.End() }

func (s *otelSpan) SetAttribute(key string, value any) {
	switch v := value.(type) {
	case string:
		s.inner.SetAttributes(attribute.String(key, v))
	case bool:
		s.inner.SetAttributes(attribute.Bool(key, v))
	case int:
		s.inner.SetAttributes(attribute.Int(key, v))
	case int64:
		s.inner.SetAttributes(attribute.Int64(key, v))
	case float64:
		s.inner.SetAttributes(attribute.Float64(key, v))
	case []string:
		s.inner.SetAttributes(attribute.StringSlice(key, v))
	default:
		s.inner.SetAttributes(attribute.String(key, fmt.Sprintf("%v", v)))
	}
}

func (s *otelSpan) AddEvent(name string, attrs ...attribute.KeyValue) {
	s.inner.AddEvent(name, trace.WithAttributes(attrs...))
}

func (s *otelSpan) RecordError(err error) {
	s.inner.RecordError(err)
}

// reefExporter is the concrete Exporter implementation.
type reefExporter struct {
	kind     ExporterKind
	tp       *sdktrace.TracerProvider
	tracer   trace.Tracer
	shutdown func(context.Context) error
}

// New builds an Exporter from config. Falls back to the no-op exporter on
// any setup failure so the pipeline can keep running.
func New(cfg Config) (Exporter, error) {
	if cfg.ServiceName == "" {
		cfg.ServiceName = "lobstertrap-reef"
	}
	if cfg.Kind == "" {
		cfg.Kind = ExporterOTLPHTTP
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(cfg.ServiceName),
			attribute.String("reef.layer", "lobstertrap"),
		),
	)
	if err != nil {
		return newNoOp(cfg.ServiceName), fmt.Errorf("otel: resource merge: %w", err)
	}

	switch cfg.Kind {
	case ExporterNone:
		return newNoOp(cfg.ServiceName), nil
	case ExporterStdout:
		exp, err := stdouttrace.New(stdouttrace.WithPrettyPrint())
		if err != nil {
			return newNoOp(cfg.ServiceName), fmt.Errorf("otel: stdout exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
		return &reefExporter{
			kind:     cfg.Kind,
			tp:       tp,
			tracer:   tp.Tracer(cfg.ServiceName),
			shutdown: tp.Shutdown,
		}, nil
	case ExporterOTLPHTTP:
		opts := []otlptracehttp.Option{}
		if cfg.Endpoint != "" {
			opts = append(opts, otlptracehttp.WithEndpoint(cfg.Endpoint))
		}
		if cfg.Insecure {
			opts = append(opts, otlptracehttp.WithInsecure())
		}
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		exp, err := otlptracehttp.New(ctx, opts...)
		if err != nil {
			return newNoOp(cfg.ServiceName), fmt.Errorf("otel: otlp-http exporter: %w", err)
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(exp),
			sdktrace.WithResource(res),
		)
		return &reefExporter{
			kind:     cfg.Kind,
			tp:       tp,
			tracer:   tp.Tracer(cfg.ServiceName),
			shutdown: tp.Shutdown,
		}, nil
	default:
		return newNoOp(cfg.ServiceName), fmt.Errorf("%w: %q", ErrInvalidKind, cfg.Kind)
	}
}

// FromEnv reads REEF_OTEL_EXPORTER (+ REEF_OTEL_ENDPOINT) and builds an
// Exporter accordingly. Returns the no-op exporter when no env var is set.
func FromEnv() Exporter {
	kind := strings.ToLower(strings.TrimSpace(os.Getenv("REEF_OTEL_EXPORTER")))
	if kind == "" {
		kind = "stdout"
	}
	endpoint := os.Getenv("REEF_OTEL_ENDPOINT")
	if endpoint == "" {
		endpoint = "localhost:4318"
	}
	exp, err := New(Config{
		Kind:        ExporterKind(kind),
		Endpoint:    endpoint,
		ServiceName: "lobstertrap-reef",
		Insecure:    true,
	})
	if err != nil {
		// We already fell back to no-op in New; log to stderr so operators see it.
		fmt.Fprintf(os.Stderr, "[reef.otel] exporter setup failed (%s): %v — falling back to no-op\n", kind, err)
	}
	otel.SetTracerProvider(noopOrTP(exp))
	return exp
}

// Start opens a new span and returns a child context + Span handle.
func (r *reefExporter) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, Span) {
	ctx, sp := r.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, &otelSpan{inner: sp}
}

func (r *reefExporter) Shutdown(ctx context.Context) error {
	if r.shutdown == nil {
		return nil
	}
	return r.shutdown(ctx)
}

func (r *reefExporter) Tracer() trace.Tracer { return r.tracer }
func (r *reefExporter) Kind() ExporterKind   { return r.kind }

// --- no-op exporter ---

type noOpExporter struct {
	tracer trace.Tracer
}

func newNoOp(serviceName string) *noOpExporter {
	tp := sdktrace.NewTracerProvider() // no batcher → spans are dropped
	return &noOpExporter{tracer: tp.Tracer(serviceName)}
}

func (n *noOpExporter) Start(ctx context.Context, name string, attrs ...attribute.KeyValue) (context.Context, Span) {
	ctx, sp := n.tracer.Start(ctx, name, trace.WithAttributes(attrs...))
	return ctx, &otelSpan{inner: sp}
}

func (n *noOpExporter) Shutdown(ctx context.Context) error { return nil }
func (n *noOpExporter) Tracer() trace.Tracer               { return n.tracer }
func (n *noOpExporter) Kind() ExporterKind                  { return ExporterNone }

// noopOrTP picks the TracerProvider to register globally. For the no-op
// path we register a fresh empty TP so the global tracer continues to work.
func noopOrTP(e Exporter) trace.TracerProvider {
	if r, ok := e.(*reefExporter); ok {
		return r.tp
	}
	// noOpExporter — leave global default in place (otel SDK ships a noop).
	return otel.GetTracerProvider()
}

// AttrsFromKV builds OTel attributes from a Go map. Skips nil values.
// Convenience helper for the pipeline's per-decision span attrs.
func AttrsFromKV(kv map[string]any) []attribute.KeyValue {
	out := make([]attribute.KeyValue, 0, len(kv))
	for k, v := range kv {
		if v == nil {
			continue
		}
		out = append(out, kvToAttr(k, v))
	}
	// Make iteration order deterministic for tests.
	syncSortAttrs(out)
	return out
}

func kvToAttr(k string, v any) attribute.KeyValue {
	switch val := v.(type) {
	case string:
		return attribute.String(k, val)
	case bool:
		return attribute.Bool(k, val)
	case int:
		return attribute.Int(k, val)
	case int64:
		return attribute.Int64(k, val)
	case float64:
		return attribute.Float64(k, val)
	case []string:
		return attribute.StringSlice(k, val)
	default:
		return attribute.String(k, fmt.Sprintf("%v", v))
	}
}

var sortMu sync.Mutex

func syncSortAttrs(a []attribute.KeyValue) {
	sortMu.Lock()
	defer sortMu.Unlock()
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j-1].Key > a[j].Key; j-- {
			a[j-1], a[j] = a[j], a[j-1]
		}
	}
}
