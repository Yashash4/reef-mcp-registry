// Package quarantine implements a file-backed JSON-Lines event store for
// requests/responses captured by the Lobster Trap QUARANTINE action.
//
// Design notes (A-4):
//   - One event per line (JSONL) so external tools (`jq`, `tail -F`,
//     awk-driven dashboards) can stream the store without parsing a big
//     JSON document.
//   - File-level mutex serialises concurrent writes so the JSONL file never
//     gets interleaved partial lines. The mutex is on the Store value, not
//     the file handle, so multiple goroutines sharing one Store coordinate
//     correctly without OS-level fcntl.
//   - Each event gets a UUID-shaped ID (`q-<hex16>`) that is also returned
//     to the caller as the Quarantine-ID HTTP header so a human reviewer
//     can grep for it later.
//   - `REEF_QUARANTINE_DIR` overrides the default `./quarantine/` directory.
//
// Phase 2 hardens this with a sqlite backend + the Stage UI review queue;
// the JSONL contract stays the same so the v1 audit reader keeps working.
package quarantine

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Status models the human-review state of a quarantined event.
type Status string

const (
	StatusPending  Status = "pending"
	StatusReviewed Status = "reviewed"
	StatusReleased Status = "released"
	StatusDenied   Status = "denied"
)

// Event is the JSON shape persisted to disk for every quarantined request.
type Event struct {
	ID             string    `json:"id"`
	Timestamp      time.Time `json:"timestamp"`
	AgentID        string    `json:"agent_id,omitempty"`
	ConversationID string    `json:"conversation_id,omitempty"`
	RequestBody    string    `json:"request_body,omitempty"`
	ResponseBody   string    `json:"response_body,omitempty"`
	PolicyRuleID   string    `json:"policy_rule_id,omitempty"`
	Reason         string    `json:"reason,omitempty"`
	Status         Status    `json:"status"`
}

// Store is a thread-safe JSONL appender for quarantined events.
type Store struct {
	dir string
	mu  sync.Mutex
}

// NewStore creates a Store rooted at `dir`. If `dir` is empty, the
// REEF_QUARANTINE_DIR env var is consulted; if that is also empty, the
// default `./quarantine` is used. The directory is created if missing.
func NewStore(dir string) (*Store, error) {
	if dir == "" {
		dir = os.Getenv("REEF_QUARANTINE_DIR")
	}
	if dir == "" {
		dir = "./quarantine"
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("quarantine: creating dir %q: %w", dir, err)
	}
	return &Store{dir: dir}, nil
}

// Dir returns the directory the store writes to. Useful for tests + audit.
func (s *Store) Dir() string {
	return s.dir
}

// NewEvent fills in a fresh ID, timestamp, and pending status. Callers pass
// the body fields to Persist. Separated so tests can construct deterministic
// events without writing to disk.
func NewEvent() Event {
	return Event{
		ID:        newID(),
		Timestamp: time.Now().UTC(),
		Status:    StatusPending,
	}
}

// Persist writes an event to the JSONL file as a single line. If the event
// has no ID/timestamp/status set, they are populated to safe defaults before
// writing — so callers can pass partial events without ceremony.
func (s *Store) Persist(ev Event) (Event, error) {
	if ev.ID == "" {
		ev.ID = newID()
	}
	if ev.Timestamp.IsZero() {
		ev.Timestamp = time.Now().UTC()
	}
	if ev.Status == "" {
		ev.Status = StatusPending
	}

	line, err := json.Marshal(ev)
	if err != nil {
		return ev, fmt.Errorf("quarantine: marshalling event: %w", err)
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	path := filepath.Join(s.dir, "events.jsonl")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return ev, fmt.Errorf("quarantine: opening %q: %w", path, err)
	}
	defer f.Close()

	if _, err := f.Write(line); err != nil {
		return ev, fmt.Errorf("quarantine: writing event: %w", err)
	}
	return ev, nil
}

// Path returns the JSONL file path. Exposed for audit consumers + tests.
func (s *Store) Path() string {
	return filepath.Join(s.dir, "events.jsonl")
}

// LoadAll reads every event from the JSONL file. Used by Phase 2's review
// queue + by tests that assert on store contents.
func (s *Store) LoadAll() ([]Event, error) {
	path := s.Path()
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("quarantine: opening %q: %w", path, err)
	}
	defer f.Close()

	dec := json.NewDecoder(f)
	var events []Event
	for {
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			if err.Error() == "EOF" {
				break
			}
			return events, fmt.Errorf("quarantine: decoding event: %w", err)
		}
		events = append(events, ev)
	}
	return events, nil
}

// newID returns a `q-<32-hex-chars>` identifier. The "q-" prefix makes
// quarantine IDs visually distinct from request IDs in the audit log.
func newID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failure is catastrophic; fall back to a timestamp-based
		// ID so we never return an empty quarantine ID to the caller.
		return fmt.Sprintf("q-fallback-%d", time.Now().UnixNano())
	}
	return "q-" + hex.EncodeToString(b[:])
}
