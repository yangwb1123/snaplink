package memory_test

import (
	"context"
	"strconv"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/platform/netpolicy/memory"
)

// TestBroadcastWatchCancelRace exercises broadcast (driven by Apply/Delete)
// racing the per-watcher ctx-cancel close. Before the fix, broadcast
// snapshotted the watcher channels under watchersMu, released it, then did a
// non-blocking send while the watcher goroutine closed the same channel
// outside any shared lock — a send on a CLOSED channel panics regardless of
// the non-blocking select. Run with -race -count=10 to surface the window.
func TestBroadcastWatchCancelRace(t *testing.T) {
	s := memory.New()
	defer func() { _ = s.Close() }()

	var wg sync.WaitGroup
	const rounds = 64
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ch, err := s.Watch(ctx)
		if err != nil {
			cancel()
			t.Fatalf("watch: %v", err)
		}
		go func() {
			for range ch {
			}
		}()
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				_, _ = s.Apply(context.Background(), &netpolicy.Policy{
					Name:  "p-" + strconv.Itoa(j),
					CIDRs: []string{"10.0.0.0/8"},
				})
			}
		}()
		// Cancel mid-flight so the watcher goroutine closes ch while broadcast
		// is sending.
		cancel()
	}
	wg.Wait()
}

// TestBroadcastCloseRace exercises broadcast racing Store.Close, which signals
// every watcher goroutine to close its channel.
func TestBroadcastCloseRace(t *testing.T) {
	s := memory.New()

	const watchers = 8
	var drained sync.WaitGroup
	for i := 0; i < watchers; i++ {
		ch, err := s.Watch(context.Background())
		if err != nil {
			t.Fatalf("watch: %v", err)
		}
		drained.Add(1)
		go func() {
			defer drained.Done()
			for range ch {
			}
		}()
	}

	var wg sync.WaitGroup
	const writers = 16
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				_, _ = s.Apply(context.Background(), &netpolicy.Policy{
					Name:  "p-" + strconv.Itoa(j),
					CIDRs: []string{"192.168.0.0/16"},
				})
			}
		}()
	}

	go func() { _ = s.Close() }()

	wg.Wait()
	drained.Wait()
}
