package anomaly

import (
	"context"
	"sync"
	"testing"
	"time"
)

// raceDetector is a no-op detector — the race we exercise is Dispatch vs Close
// on the runner's queue, not detector behavior.
type raceDetector struct{}

func (raceDetector) Name() string { return "race" }
func (raceDetector) Inspect(context.Context, *LoginEvent) ([]Signal, error) {
	return nil, nil
}

// TestDispatchCloseRace exercises Dispatch racing Close. Before the fix,
// Dispatch checked a standalone atomic closed-flag and then sent on r.queue in
// a separate step — a TOCTOU window where Close could close(r.queue) between
// the check and the send, panicking on send-to-closed-channel. The fix couples
// the closed-check and the send under one RWMutex that Close's writer-lock
// excludes. Run with -race -count=10 to surface the window.
func TestDispatchCloseRace(t *testing.T) {
	t.Parallel()
	r := NewRunner([]Detector{raceDetector{}}, nil)
	r.Start()

	var wg sync.WaitGroup
	const dispatchers = 32
	for i := 0; i < dispatchers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 500; j++ {
				// Must never panic, even after Close — Dispatch is a no-op once
				// the runner is closed.
				r.Dispatch(context.Background(), &LoginEvent{SubjectID: "alice"})
			}
		}()
	}

	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = r.Close(ctx)
	}()

	wg.Wait()
}
