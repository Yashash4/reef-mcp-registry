// Package ratelimit per-identity token bucket rate limiter keyed off SVID
// subject claims.
//
// Reef applies token-bucket rate limiting per `SVID.Subject` so a single
// agent identity that suddenly bursts (compromised key, runaway autonomous
// loop, DAST-A adversary) gets throttled without affecting other agents on
// the same fleet node.
//
// Implementation notes:
//   - Each subject gets its own *rate.Limiter from golang.org/x/time/rate.
//   - The limiter map is bounded by an LRU cap (default 10k entries) so a
//     malicious agent can't OOM us by rotating identities.
//   - On every Allow call we touch the entry's lastSeen timestamp; eviction
//     fires when the map exceeds Capacity by evicting the least-recently-used
//     entries until size is back to Capacity.
//   - Concurrent access is safe: we hold a sync.Mutex during map mutation;
//     the actual limiter.Allow call is lock-free (rate.Limiter is already
//     goroutine-safe).
package ratelimit

import (
	"container/list"
	"errors"
	"sync"
	"time"

	"golang.org/x/time/rate"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/defaults"
)

// DefaultCapacity is the LRU bound when no Capacity is supplied.
// Re-exported from internal/defaults so external callers continue to see
// the same value without importing the internal package directly.
const DefaultCapacity = defaults.LRURateLimitCapacity

// Errors returned by NewLimiter.
var (
	ErrInvalidRate  = errors.New("ratelimit: Rate must be > 0")
	ErrInvalidBurst = errors.New("ratelimit: Burst must be > 0")
)

// Limiter is the contract callers use. Allow returns true when the request
// fits inside the per-subject token bucket.
type Limiter interface {
	Allow(subject string) bool
	// Reset clears all per-subject state (used in tests and on policy reload).
	Reset()
	// Size returns the current number of tracked subjects.
	Size() int
}

// Config wires the dependencies a Limiter needs.
type Config struct {
	// Rate is the steady-state requests per second a single subject may
	// consume. Must be > 0.
	Rate float64
	// Burst is the bucket depth — how many requests a subject may stack up
	// before throttling kicks in. Must be > 0.
	Burst int
	// Capacity is the LRU bound on tracked subjects. Zero falls back to
	// DefaultCapacity (10000).
	Capacity int
	// Clock allows tests to inject a frozen clock. Nil falls back to time.Now.
	// The underlying x/time/rate limiter has its own clock semantics; this is
	// used only for the LRU lastSeen ordering.
	Clock func() time.Time
}

// New builds a Limiter from the config. Returns an error if Rate or Burst
// is non-positive — silently substituting "sensible defaults" is dishonest
// when the operator's policy literally said "Rate=0".
func New(cfg Config) (Limiter, error) {
	if cfg.Rate <= 0 {
		return nil, ErrInvalidRate
	}
	if cfg.Burst <= 0 {
		return nil, ErrInvalidBurst
	}
	cap := cfg.Capacity
	if cap <= 0 {
		cap = DefaultCapacity
	}
	clock := cfg.Clock
	if clock == nil {
		clock = time.Now
	}
	return &lruLimiter{
		rps:      cfg.Rate,
		burst:    cfg.Burst,
		capacity: cap,
		clock:    clock,
		entries:  map[string]*list.Element{},
		order:    list.New(),
	}, nil
}

// entry is the LRU node stored in the doubly-linked list.
type entry struct {
	subject  string
	limiter  *rate.Limiter
	lastSeen time.Time
}

type lruLimiter struct {
	rps      float64
	burst    int
	capacity int
	clock    func() time.Time

	mu      sync.Mutex
	entries map[string]*list.Element
	order   *list.List // front = most recent, back = least recent
}

// Allow returns true if subject's bucket has at least one token available.
// Empty subject is treated as a configured limiter slot too — operators who
// route unauthenticated traffic through the limiter still get a bucket so
// the load can't slip past unbounded.
func (l *lruLimiter) Allow(subject string) bool {
	l.mu.Lock()
	now := l.clock()
	if el, ok := l.entries[subject]; ok {
		e := el.Value.(*entry)
		e.lastSeen = now
		l.order.MoveToFront(el)
		limiter := e.limiter
		l.mu.Unlock()
		return limiter.Allow()
	}
	// New subject — create bucket, evict if over capacity.
	lim := rate.NewLimiter(rate.Limit(l.rps), l.burst)
	e := &entry{
		subject:  subject,
		limiter:  lim,
		lastSeen: now,
	}
	el := l.order.PushFront(e)
	l.entries[subject] = el
	l.evictIfNeededLocked()
	l.mu.Unlock()
	return lim.Allow()
}

// evictIfNeededLocked walks the LRU back-edge and drops entries until the
// map size <= capacity. MUST be called with l.mu held.
func (l *lruLimiter) evictIfNeededLocked() {
	for l.order.Len() > l.capacity {
		back := l.order.Back()
		if back == nil {
			return
		}
		e := back.Value.(*entry)
		delete(l.entries, e.subject)
		l.order.Remove(back)
	}
}

func (l *lruLimiter) Reset() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.entries = map[string]*list.Element{}
	l.order = list.New()
}

func (l *lruLimiter) Size() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.entries)
}
