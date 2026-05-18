package pipeline

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/audit"
	"github.com/Yashash4/reef-mcp-registry/lobstertrap-reef/internal/policy"
)

// POV-1 / Refinement R-B7: actively exercise the AddObserver-vs-notify race
// path so `go test -race` will catch a regression if a future change drops
// the copy() in notify.
//
// We spin up N goroutines firing ProcessIngressWithAuth concurrently with M
// goroutines calling AddObserver. With the per-call copy() under RLock,
// neither side touches a shared backing array unsafely. With the previous
// `observers := p.observers` aliasing read, this test crashed under -race.
func TestNotify_ObserverRegistrationDuringDispatch(t *testing.T) {
	src := `
version: "1.0"
policy_name: "notify-race"
default_action: ALLOW
ingress_rules:
  - name: dummy
    description: dummy
    priority: 1
    action: LOG
    conditions:
      - field: token_count
        match_type: threshold
        value: 0
`
	pol, perr := policy.Parse([]byte(src))
	if perr != nil {
		t.Fatalf("parse: %v", perr)
	}
	pipe := New(pol, audit.NopLogger())

	const writers = 4
	const adders = 4
	const iters = 50
	const adderIters = 50

	var wg sync.WaitGroup
	var observed atomic.Int64

	// Add initial observer.
	pipe.AddObserver(func(e PipelineEvent) {
		observed.Add(1)
	})

	wg.Add(adders)
	for i := 0; i < adders; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < adderIters; j++ {
				pipe.AddObserver(func(e PipelineEvent) {
					observed.Add(1)
				})
			}
		}()
	}

	wg.Add(writers)
	for i := 0; i < writers; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < iters; j++ {
				_ = pipe.ProcessIngressWithAuth(context.Background(), "hi", nil, "")
			}
		}()
	}

	wg.Wait()

	if observed.Load() == 0 {
		t.Error("expected at least one observer call during the race")
	}
}
