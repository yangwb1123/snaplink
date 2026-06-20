package sso

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// A leader computation that blocks until released should absorb every
// follower that arrives while it is in flight: all share the one result
// and compute runs exactly once.
func TestJWKSSingleFlight_CollapsesConcurrent(t *testing.T) {
	var f jwksSingleFlight
	var computes int32
	release := make(chan struct{})
	started := make(chan struct{})

	const followers = 16
	results := make([][]byte, followers+1)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		body, err := f.Do(func() ([]byte, error) {
			atomic.AddInt32(&computes, 1)
			close(started) // leader is now in flight
			<-release      // hold the slot open for followers
			return []byte("jwks-body"), nil
		})
		if err != nil {
			t.Errorf("leader: %v", err)
		}
		results[0] = body
	}()

	<-started // guarantee followers arrive during the leader's compute
	entered := make(chan struct{}, followers)
	for i := 1; i <= followers; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			entered <- struct{}{}
			body, err := f.Do(func() ([]byte, error) {
				atomic.AddInt32(&computes, 1)
				return []byte("should-not-run"), nil
			})
			if err != nil {
				t.Errorf("follower %d: %v", idx, err)
			}
			results[idx] = body
		}(i)
	}

	// Wait for every follower goroutine to be scheduled, then yield long
	// enough for them all to park on the in-flight leader before we
	// release it. Without single-flight, each would run its own compute.
	for i := 0; i < followers; i++ {
		<-entered
	}
	time.Sleep(20 * time.Millisecond)
	close(release)
	wg.Wait()

	if got := atomic.LoadInt32(&computes); got != 1 {
		t.Fatalf("compute ran %d times, want 1 (followers must share the leader)", got)
	}
	for i, b := range results {
		if string(b) != "jwks-body" {
			t.Errorf("result[%d] = %q, want jwks-body", i, b)
		}
	}
}

// A call that arrives after the in-flight one finishes must recompute —
// no result caching, so a rotation shows up on the next poll.
func TestJWKSSingleFlight_RecomputesSequential(t *testing.T) {
	var f jwksSingleFlight
	var computes int32
	for i := 0; i < 3; i++ {
		if _, err := f.Do(func() ([]byte, error) {
			atomic.AddInt32(&computes, 1)
			return []byte("x"), nil
		}); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}
	if got := atomic.LoadInt32(&computes); got != 3 {
		t.Fatalf("compute ran %d times, want 3 (sequential calls must not cache)", got)
	}
}
