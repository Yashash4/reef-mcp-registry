package actions

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/inspector"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/quarantine"
)

func mkdirAllImpl(path string) error { return os.MkdirAll(path, 0o755) }

// testLogger is a Logger implementation that records every event for test
// assertion. It's intentionally minimal — we don't try to match zerolog's
// API surface, just satisfy the actions.Logger interface.
type testLogger struct {
	mu     sync.Mutex
	events []logEntry
}

type logEntry struct {
	level string
	msg   string
	err   error
	kv    []any
}

func newTestLogger() *testLogger {
	return &testLogger{}
}

func (l *testLogger) Warn(msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, logEntry{level: "warn", msg: msg, kv: kv})
}

func (l *testLogger) Info(msg string, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, logEntry{level: "info", msg: msg, kv: kv})
}

func (l *testLogger) Error(msg string, err error, kv ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, logEntry{level: "error", msg: msg, err: err, kv: kv})
}

func (l *testLogger) findEvent(msg string) *logEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	for i := range l.events {
		if l.events[i].msg == msg {
			return &l.events[i]
		}
	}
	return nil
}

func newTestDispatcher(t *testing.T, pol *policy.Policy, opts ...func(*DispatcherConfig)) *Dispatcher {
	t.Helper()
	store, err := quarantine.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("quarantine.NewStore: %v", err)
	}
	cfg := DispatcherConfig{
		Policy: pol,
		Store:  store,
		Logger: newTestLogger(),
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	d, err := NewDispatcher(cfg)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	return d
}

func TestNewDispatcher_RejectsMissingDeps(t *testing.T) {
	store, err := quarantine.NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("quarantine.NewStore: %v", err)
	}
	pol := &policy.Policy{Version: "1", PolicyName: "p"}
	cases := []struct {
		name string
		cfg  DispatcherConfig
	}{
		{
			name: "missing policy",
			cfg:  DispatcherConfig{Store: store, Logger: newTestLogger()},
		},
		{
			name: "missing store",
			cfg:  DispatcherConfig{Policy: pol, Logger: newTestLogger()},
		},
		{
			name: "missing logger",
			cfg:  DispatcherConfig{Policy: pol, Store: store},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewDispatcher(tc.cfg); err == nil {
				t.Fatal("expected error, got nil")
			}
		})
	}
}

func TestDispatch_UnknownAction(t *testing.T) {
	d := newTestDispatcher(t, &policy.Policy{Version: "1", PolicyName: "p"})
	out := d.Dispatch(context.Background(), Decision{
		Rule: policy.RuleResult{Action: policy.ActionLog},
	})
	if out.Err == nil {
		t.Fatal("expected error for non-Reef action, got nil")
	}
}

// mockWebhookPoster captures the last POST so HUMAN_REVIEW tests can assert
// on the payload. The constructor lets the caller set a fixed response.
type mockWebhookPoster struct {
	mu          sync.Mutex
	lastURL     string
	lastPayload HumanReviewPayload
	lastTimeout time.Duration
	resp        *http.Response
	err         error
	count       int
}

func (m *mockWebhookPoster) Post(_ context.Context, url string, payload HumanReviewPayload, timeout time.Duration) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastURL = url
	m.lastPayload = payload
	m.lastTimeout = timeout
	m.count++
	if m.err != nil {
		return nil, m.err
	}
	return m.resp, nil
}

// liveTestServer spins up a real httptest.Server that records POST bodies.
// Used by tests that want to exercise the real httpPoster path (not the
// mock) — proves the production webhook code is transport-honest.
func liveTestServer(t *testing.T, handler http.HandlerFunc) string {
	t.Helper()
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv.URL
}

// stubMeta builds a non-nil PromptMetadata so action code paths that read
// inspector fields don't NPE in tests that don't care about DPI.
func stubMeta() *inspector.PromptMetadata {
	return &inspector.PromptMetadata{
		IntentCategory: "general",
	}
}

// osMkdirAll is wrapped so the quarantine-failure test can build a dir at
// the JSONL path (forcing Persist's OpenFile to fail). Kept as a tiny
// indirection so the test file doesn't carry an os/* import just for one
// call.
var osMkdirAll = func(path string) error {
	return mkdirAllImpl(path)
}
