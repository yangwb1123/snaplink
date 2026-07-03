package rs

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
)

// TestDPoPReplayCache_ConcurrentMarkSeenExactlyOneWinnerPerJTI drives many
// goroutines racing to mark the SAME jti seen. The replay cache exists to
// make a proof usable exactly once; under concurrency exactly one caller may
// observe first-use for each jti, or the guarantee is worthless against a
// proof replayed in a tight race window (the realistic attack shape).
func TestDPoPReplayCache_ConcurrentMarkSeenExactlyOneWinnerPerJTI(t *testing.T) {
	t.Parallel()
	c := newDPoPReplayCache(4096)
	const contenders = 64
	var wins atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < contenders; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if c.markSeen("shared-jti", 1_000_000_000, 0) {
				wins.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := wins.Load(); got != 1 {
		t.Fatalf("winners = %d, want exactly 1", got)
	}
}

// TestDPoPReplayCache_ConcurrentDistinctJTIsAllRaceFree exercises the
// capacity-eviction path under concurrency (small capacity forces
// evictLocked on nearly every insert) so `go test -race` can catch any
// unsynchronized access to the seen map.
func TestDPoPReplayCache_ConcurrentDistinctJTIsAllRaceFree(t *testing.T) {
	t.Parallel()
	c := newDPoPReplayCache(16)
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				c.markSeen(fmt.Sprintf("jti-%d-%d", i, j), int64(j+1), 0)
			}
		}(i)
	}
	wg.Wait()
}
