package session

import (
	"errors"
	"fmt"
	"math"
	"testing"
)

func almostEqual(a, b float64) bool {
	return math.Abs(a-b) < 1e-9
}

func TestNewTracker_RejectsInvalidConfig(t *testing.T) {
	if _, err := NewTracker(TrackerConfig{Alpha: 0, Categories: []string{"ASI01"}}); !errors.Is(err, ErrInvalidAlpha) {
		t.Errorf("alpha=0 err=%v want ErrInvalidAlpha", err)
	}
	if _, err := NewTracker(TrackerConfig{Alpha: 1.5, Categories: []string{"ASI01"}}); !errors.Is(err, ErrInvalidAlpha) {
		t.Errorf("alpha=1.5 err=%v want ErrInvalidAlpha", err)
	}
	if _, err := NewTracker(TrackerConfig{Alpha: 0.3, Categories: nil}); !errors.Is(err, ErrInvalidCategory) {
		t.Errorf("nil categories err=%v want ErrInvalidCategory", err)
	}
}

func TestUpdate_FirstHitRaisesScoreByAlpha(t *testing.T) {
	tr, err := NewTracker(TrackerConfig{Alpha: 0.3, Categories: []string{"ASI06"}})
	if err != nil {
		t.Fatalf("NewTracker: %v", err)
	}
	got := tr.Update("agent-1", []string{"ASI06"})
	if !almostEqual(got, 0.3) {
		t.Errorf("first hit ewma=%v want 0.3", got)
	}
}

func TestUpdate_RepeatedHitsAsymptoteTowardOne(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.3, Categories: []string{"ASI06"}})
	var last float64
	for i := 0; i < 50; i++ {
		last = tr.Update("agent-1", []string{"ASI06"})
	}
	if last < 0.99 {
		t.Errorf("after 50 hits ewma=%v want ~1.0", last)
	}
	if last > 1.0 {
		t.Errorf("ewma=%v exceeded 1.0 — invariant violation", last)
	}
}

func TestUpdate_NoHitsDecayTowardZero(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.3, Categories: []string{"ASI06"}})
	// Get to a high score first.
	for i := 0; i < 20; i++ {
		tr.Update("agent-1", []string{"ASI06"})
	}
	if tr.Score("agent-1") < 0.9 {
		t.Fatalf("priming failed score=%v", tr.Score("agent-1"))
	}
	var last float64
	for i := 0; i < 50; i++ {
		last = tr.Update("agent-1", []string{"ASI09"}) // non-tracked category
	}
	if last > 0.01 {
		t.Errorf("after 50 misses ewma=%v want ~0", last)
	}
	if last < 0 {
		t.Errorf("ewma=%v dropped below 0", last)
	}
}

func TestUpdate_AlphaOneIsFullReplacement(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 1.0, Categories: []string{"ASI06"}})
	tr.Update("agent-1", []string{"ASI06"})
	if got := tr.Score("agent-1"); !almostEqual(got, 1.0) {
		t.Errorf("alpha=1 hit=%v want 1.0", got)
	}
	tr.Update("agent-1", nil)
	if got := tr.Score("agent-1"); !almostEqual(got, 0.0) {
		t.Errorf("alpha=1 miss after hit=%v want 0.0 (full replacement)", got)
	}
}

func TestUpdate_DifferentSubjectsIndependent(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.5, Categories: []string{"ASI06"}})
	tr.Update("agent-A", []string{"ASI06"})
	tr.Update("agent-A", []string{"ASI06"})
	scoreA := tr.Score("agent-A")
	scoreB := tr.Score("agent-B")
	if !almostEqual(scoreB, 0.0) {
		t.Errorf("agent-B was not updated, score=%v want 0", scoreB)
	}
	if scoreA <= 0 {
		t.Errorf("agent-A score=%v want > 0", scoreA)
	}
}

func TestUpdate_CategoryNormalisation(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.5, Categories: []string{"asi06", "ASI01"}})
	got := tr.Update("agent-1", []string{" asi06 "})
	if got <= 0 {
		t.Errorf("case-insensitive hit=%v want > 0", got)
	}
}

func TestUpdate_CrossesThresholdOnMultiTurnHits(t *testing.T) {
	// Reproduces the integration scenario in the spec: 10-turn conversation
	// with ASI06 hits on turns 3, 5, 7 → EWMA crosses 0.4 by turn 7.
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.3, Categories: []string{"ASI06"}})
	subject := "spiffe://reef/dast-victim"
	scores := []float64{}
	for turn := 1; turn <= 10; turn++ {
		var cats []string
		if turn == 3 || turn == 5 || turn == 7 {
			cats = []string{"ASI06"}
		}
		scores = append(scores, tr.Update(subject, cats))
	}
	if scores[6] < 0.4 {
		t.Errorf("turn 7 ewma=%v want >= 0.4", scores[6])
	}
	for i, s := range scores {
		t.Logf("turn %d ewma=%.4f", i+1, s)
	}
}

func TestTracker_LRUEviction(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{
		Alpha:      0.3,
		Categories: []string{"ASI06"},
		Capacity:   5,
	})
	for i := 0; i < 20; i++ {
		tr.Update(fmt.Sprintf("agent-%d", i), []string{"ASI06"})
	}
	if got := tr.Size(); got != 5 {
		t.Errorf("Size=%d want 5", got)
	}
}

func TestTracker_ResetClearsState(t *testing.T) {
	tr, _ := NewTracker(TrackerConfig{Alpha: 0.5, Categories: []string{"ASI06"}})
	tr.Update("agent-1", []string{"ASI06"})
	tr.Update("agent-2", []string{"ASI06"})
	tr.Reset()
	if tr.Size() != 0 {
		t.Errorf("Size=%d want 0", tr.Size())
	}
	if got := tr.Score("agent-1"); got != 0 {
		t.Errorf("score after reset=%v", got)
	}
}
