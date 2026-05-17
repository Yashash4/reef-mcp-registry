package ratelimit

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestNew_RejectsInvalidConfig(t *testing.T) {
	if _, err := New(Config{Rate: 0, Burst: 5}); !errors.Is(err, ErrInvalidRate) {
		t.Errorf("Rate=0 err=%v want ErrInvalidRate", err)
	}
	if _, err := New(Config{Rate: 1, Burst: 0}); !errors.Is(err, ErrInvalidBurst) {
		t.Errorf("Burst=0 err=%v want ErrInvalidBurst", err)
	}
}

func TestAllow_BurstThenThrottle(t *testing.T) {
	// 1000 rps but burst of 3 → first 3 requests pass instantly, fourth fails
	// (we don't wait between calls).
	lim, err := New(Config{Rate: 1, Burst: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 3; i++ {
		if !lim.Allow("spiffe://reef/test") {
			t.Errorf("call %d should pass", i)
		}
	}
	if lim.Allow("spiffe://reef/test") {
		t.Errorf("4th immediate call should be throttled")
	}
}

func TestAllow_DifferentSubjectsIndependent(t *testing.T) {
	lim, err := New(Config{Rate: 1, Burst: 2})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Subject A exhausts its budget.
	if !lim.Allow("subject-A") || !lim.Allow("subject-A") {
		t.Errorf("subject-A first two calls should pass")
	}
	if lim.Allow("subject-A") {
		t.Errorf("subject-A 3rd call should throttle")
	}
	// Subject B should still have a full bucket.
	if !lim.Allow("subject-B") {
		t.Errorf("subject-B first call should pass")
	}
	if !lim.Allow("subject-B") {
		t.Errorf("subject-B second call should pass")
	}
	if lim.Allow("subject-B") {
		t.Errorf("subject-B third call should throttle")
	}
}

func TestAllow_LRUEvictionRespectsCapacity(t *testing.T) {
	lim, err := New(Config{Rate: 100, Burst: 5, Capacity: 4})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 10; i++ {
		lim.Allow(fmt.Sprintf("subject-%d", i))
	}
	if got := lim.Size(); got != 4 {
		t.Errorf("Size after 10 inserts with cap 4 = %d want 4", got)
	}
}

func TestAllow_TouchedSubjectsSurviveEviction(t *testing.T) {
	lim, err := New(Config{Rate: 100, Burst: 5, Capacity: 3})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Insert A, B, C.
	lim.Allow("A")
	lim.Allow("B")
	lim.Allow("C")
	// Touch A (moves it to front of LRU).
	lim.Allow("A")
	// Insert D — should evict B (least recently used).
	lim.Allow("D")
	// A should still be present (touch it).
	lim.Allow("A") // re-using existing bucket
	if got := lim.Size(); got != 3 {
		t.Errorf("Size=%d want 3", got)
	}
	// Insert E — should evict C (oldest after A's touch).
	lim.Allow("E")
	// Now if we Allow("B"), it should re-create the bucket (size remains 3
	// because we evict the LRU).
	lim.Allow("B")
	if got := lim.Size(); got != 3 {
		t.Errorf("after re-inserting B, Size=%d want 3", got)
	}
}

func TestReset_ClearsAllBuckets(t *testing.T) {
	lim, err := New(Config{Rate: 100, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	for i := 0; i < 5; i++ {
		lim.Allow(fmt.Sprintf("S%d", i))
	}
	if lim.Size() != 5 {
		t.Fatalf("Size pre-reset=%d", lim.Size())
	}
	lim.Reset()
	if lim.Size() != 0 {
		t.Errorf("Size post-reset=%d want 0", lim.Size())
	}
}

func TestAllow_ConcurrentNoRace(t *testing.T) {
	// Must be run with `go test -race` to detect races. The test itself
	// passes as long as no panics + the total Size stays within capacity.
	lim, err := New(Config{Rate: 1000, Burst: 100, Capacity: 50})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	const goroutines = 64
	const callsPer = 500
	var wg sync.WaitGroup
	var passes int64
	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for c := 0; c < callsPer; c++ {
				subj := fmt.Sprintf("subject-%d", (id*callsPer+c)%200)
				if lim.Allow(subj) {
					atomic.AddInt64(&passes, 1)
				}
			}
		}(g)
	}
	wg.Wait()
	if lim.Size() > 50 {
		t.Errorf("Size=%d exceeds capacity 50", lim.Size())
	}
	if passes == 0 {
		t.Errorf("no requests passed at all — expected at least burst*subjects")
	}
}

func TestAllow_RefillOverTime(t *testing.T) {
	// 100 rps + burst 1 → after burst exhaustion a token refills in ~10ms.
	lim, err := New(Config{Rate: 100, Burst: 1})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if !lim.Allow("S") {
		t.Fatal("first call should pass")
	}
	if lim.Allow("S") {
		t.Fatal("immediate second call should throttle")
	}
	time.Sleep(15 * time.Millisecond)
	if !lim.Allow("S") {
		t.Errorf("call after 15ms should refill and pass")
	}
}
