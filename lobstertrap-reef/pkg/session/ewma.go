// Package session — EWMA ASI-category tracker for multi-turn risk
// accumulation.
//
// Mechanism: each request is classified into a subset of OWASP "Top 10 for
// Agentic Applications" categories (ASI01–ASI10). The tracker maintains an
// exponentially-weighted moving average per agent identity over a sliding
// window of observations. When the EWMA crosses a configured threshold,
// the policy rule `asi_category_ewma: { gt: <threshold> }` fires
// HUMAN_REVIEW (default at 0.4).
//
// Formula:
//
//	ewma_t = alpha * x_t + (1 - alpha) * ewma_{t-1}
//
// where x_t is 1.0 if any of the tracked categories was hit on this
// observation, 0.0 otherwise. Alpha controls how aggressively recent
// observations dominate (default 0.3 → ~3-observation half-life).
//
// Why this:
//   - It's a real named technique (D-005). EWMA control charts are textbook
//     time-series anomaly detection.
//   - One float per identity. Bounded memory under LRU eviction.
//   - Naturally decays: an agent that hit ASI06 ten turns ago is no longer
//     elevated today.
//
// Concurrency: a sync.Mutex guards the LRU. Score and Update are safe for
// concurrent use from multiple pipeline goroutines.
package session

import (
	"container/list"
	"errors"
	"strings"
	"sync"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
)

// DefaultCapacity caps tracked identities. Re-exported from
// internal/defaults so external callers don't need to know about the
// internal package.
const DefaultCapacity = defaults.LRUEWMACapacity

// Errors.
var (
	ErrInvalidAlpha    = errors.New("session: Alpha must be in (0, 1]")
	ErrInvalidCategory = errors.New("session: at least one tracked category is required")
)

// TrackerConfig wires tracker parameters.
type TrackerConfig struct {
	// Alpha is the exponential weight on the most-recent observation. Must
	// satisfy 0 < Alpha <= 1. Default 0.3 (~3-obs half-life). Alpha=1 means
	// "no memory, last observation only"; Alpha approaching 0 means "infinite
	// memory, slow to react".
	Alpha float64
	// Categories is the set of ASI categories the tracker watches (e.g.
	// "ASI01", "ASI06"). Comparison is case-insensitive after normalisation.
	Categories []string
	// Capacity is the LRU cap; 0 falls back to DefaultCapacity.
	Capacity int
}

// Tracker holds the per-subject EWMA state.
type Tracker struct {
	alpha      float64
	categories map[string]struct{}
	capacity   int

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = most recent
}

type ewmaEntry struct {
	subject string
	value   float64
}

// NewTracker builds a Tracker. Returns an error for invalid Alpha or empty
// categories — silent defaults would defeat the operator's intent.
func NewTracker(cfg TrackerConfig) (*Tracker, error) {
	if cfg.Alpha <= 0 || cfg.Alpha > 1 {
		return nil, ErrInvalidAlpha
	}
	if len(cfg.Categories) == 0 {
		return nil, ErrInvalidCategory
	}
	cat := make(map[string]struct{}, len(cfg.Categories))
	for _, c := range cfg.Categories {
		n := normaliseCategory(c)
		if n != "" {
			cat[n] = struct{}{}
		}
	}
	if len(cat) == 0 {
		return nil, ErrInvalidCategory
	}
	cap := cfg.Capacity
	if cap <= 0 {
		cap = DefaultCapacity
	}
	return &Tracker{
		alpha:      cfg.Alpha,
		categories: cat,
		capacity:   cap,
		entries:    map[string]*list.Element{},
		order:      list.New(),
	}, nil
}

// Update folds the new observation into the subject's EWMA and returns the
// updated score. An observation "hits" (x_t = 1.0) when any of the supplied
// categories overlaps the tracker's watched set; otherwise x_t = 0.0.
//
// Updates also serve as touches in the LRU — the most-recently-updated
// subjects survive eviction.
func (t *Tracker) Update(subject string, observedCategories []string) float64 {
	hit := 0.0
	for _, c := range observedCategories {
		if _, ok := t.categories[normaliseCategory(c)]; ok {
			hit = 1.0
			break
		}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[subject]; ok {
		e := el.Value.(*ewmaEntry)
		e.value = t.alpha*hit + (1-t.alpha)*e.value
		t.order.MoveToFront(el)
		return e.value
	}
	// New subject. First observation's EWMA = alpha * x_t. For a hit on the
	// first turn this yields exactly alpha; for a miss it yields 0.
	v := t.alpha * hit
	e := &ewmaEntry{subject: subject, value: v}
	el := t.order.PushFront(e)
	t.entries[subject] = el
	t.evictIfNeededLocked()
	return v
}

// Score returns the current EWMA for the subject; 0.0 if unknown.
// Does NOT decay-on-read — the tracker is event-driven. Operators that want
// "decay even when the agent is quiet" call Update(subject, nil) periodically.
func (t *Tracker) Score(subject string) float64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if el, ok := t.entries[subject]; ok {
		return el.Value.(*ewmaEntry).value
	}
	return 0.0
}

// Reset wipes all subject state.
func (t *Tracker) Reset() {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.entries = map[string]*list.Element{}
	t.order = list.New()
}

// Size returns the number of tracked subjects.
func (t *Tracker) Size() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return len(t.entries)
}

// Alpha returns the configured alpha for diagnostics.
func (t *Tracker) Alpha() float64 {
	return t.alpha
}

// Categories returns the configured category set (lowercased, comma-joined)
// for diagnostics.
func (t *Tracker) Categories() string {
	cats := make([]string, 0, len(t.categories))
	for c := range t.categories {
		cats = append(cats, c)
	}
	return strings.Join(cats, ",")
}

func (t *Tracker) evictIfNeededLocked() {
	for t.order.Len() > t.capacity {
		back := t.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*ewmaEntry)
		delete(t.entries, e.subject)
		t.order.Remove(back)
	}
}

func normaliseCategory(c string) string {
	return strings.ToUpper(strings.TrimSpace(c))
}
