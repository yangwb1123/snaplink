package memory_test

import (
	"context"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/registry"
	"github.com/snaplink/sso/platform/registry/memory"
)

// TestBroadcastCloseRace exercises broadcast (driven by Register/Deregister)
// racing Close. Before the fix, broadcast snapshotted the watcher channels
// under the read lock, released it, then did a non-blocking send — which
// panics if Close (or removeWatcher) has closed the channel in between (the
// default: only guards a FULL channel, never a CLOSED one). Run with -race
// -count=10 to surface the window.
func TestBroadcastCloseRace(t *testing.T) {
	t.Parallel()
	const serviceName = "svc"
	r := memory.New()

	ch, err := r.Watch(context.Background(), serviceName)
	if err != nil {
		t.Fatalf("watch: %v", err)
	}
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range ch {
		}
	}()

	var wg sync.WaitGroup
	const writers = 32
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				svc := &registry.Service{
					ID:   "id-" + strconv.Itoa(j),
					Name: serviceName,
					TTL:  time.Minute,
				}
				// Register then Deregister both broadcast on the watcher.
				_ = r.Register(context.Background(), svc)
				_ = r.Deregister(context.Background(), svc.ID)
			}
		}()
	}

	go func() { _ = r.Close() }()

	wg.Wait()
	<-drained
}

// TestWatchCancelBroadcastRace exercises broadcast racing the per-watcher
// ctx-cancel path (removeWatcher closes the channel). This is the second
// goroutine that closes a subscriber channel without Close being involved.
func TestWatchCancelBroadcastRace(t *testing.T) {
	t.Parallel()
	const serviceName = "svc"
	r := memory.New()
	defer func() { _ = r.Close() }()

	var wg sync.WaitGroup
	const rounds = 64
	for i := 0; i < rounds; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		ch, err := r.Watch(ctx, serviceName)
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
				svc := &registry.Service{ID: "id", Name: serviceName, TTL: time.Minute}
				_ = r.Register(context.Background(), svc)
				_ = r.Deregister(context.Background(), svc.ID)
			}
		}()
		// Cancel mid-flight so removeWatcher closes ch while broadcast runs.
		cancel()
	}
	wg.Wait()
}
