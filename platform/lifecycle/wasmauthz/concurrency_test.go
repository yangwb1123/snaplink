package wasmauthz_test

// Concurrency-safety proof for the "fresh instance per call" design (see
// ../doc.go's "Concurrency" section): many goroutines hammering ONE shared
// *Engine must never race or corrupt each other's Decision. Run with
// -race (see AGENTS.md's race-fix convention); a shared mutable-state bug
// here would show up as a data race or a goroutine reading another
// goroutine's Decision.

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"github.com/yangwb1123/snaplink/platform/lifecycle/wasmauthz"
)

func TestAuthorize_ConcurrentCalls(t *testing.T) {
	t.Parallel()
	eng := newTestEngine(t, "policy.wasm")

	const goroutines = 50
	const callsPerGoroutine = 20

	var wg sync.WaitGroup
	errCh := make(chan error, goroutines*callsPerGoroutine)
	for g := 0; g < goroutines; g++ {
		g := g
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < callsPerGoroutine; i++ {
				req := requestForGoroutine(g, i)
				dec, err := eng.Authorize(context.Background(), req)
				if err != nil {
					errCh <- fmt.Errorf("goroutine %d call %d: %w", g, i, err)
					continue
				}
				if err := assertExpectedDecision(req, dec); err != nil {
					errCh <- fmt.Errorf("goroutine %d call %d: %w", g, i, err)
				}
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}
}

// requestForGoroutine alternates between the two ALLOW rules and a DENY
// case so concurrent calls are exercising genuinely different guest-side
// branches, not all hitting one cached path.
func requestForGoroutine(g, i int) wasmauthz.Request {
	switch (g + i) % 3 {
	case 0:
		return wasmauthz.Request{Subject: "alice", Action: "read", Resource: "doc:1"}
	case 1:
		return wasmauthz.Request{Subject: "bob", Action: "delete", Context: map[string]string{"role": "admin"}}
	default:
		return wasmauthz.Request{Subject: "eve", Action: "delete"}
	}
}

func assertExpectedDecision(req wasmauthz.Request, dec wasmauthz.Decision) error {
	wantAllowed := (req.Subject == "alice" && req.Action == "read") || req.Context["role"] == "admin"
	if dec.Allowed != wantAllowed {
		return fmt.Errorf("request %+v decision %+v, want allowed=%v", req, dec, wantAllowed)
	}
	return nil
}
