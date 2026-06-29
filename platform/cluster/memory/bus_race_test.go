package memory_test

import (
	"context"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/cluster/memory"
)

// TestPublishCloseRace exercises Publish racing Close. Before the fix, Publish
// snapshotted the subscriber channels under the read lock, released it, then
// did a non-blocking send — which panics if Close has closed the channel in
// the meantime (the default: only guards a FULL channel, never a CLOSED one).
// A drained subscriber maximises the chance the send is actually attempted at
// the instant Close runs. Run with -race -count=10 to surface the window.
func TestPublishCloseRace(t *testing.T) {
	t.Parallel()
	b := memory.New()

	ch, err := b.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	// Drain continuously so sends succeed (not just hit the default branch),
	// putting the send on the channel right when Close closes it.
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		for range ch {
		}
	}()

	var wg sync.WaitGroup
	const publishers = 32
	for i := 0; i < publishers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: "tenant-1"}
			for j := 0; j < 200; j++ {
				// Publish must never panic, even after Close; ErrClosed is fine.
				_ = b.Publish(context.Background(), evt)
			}
		}()
	}

	// Close concurrently with the in-flight Publishes.
	go func() { _ = b.Close() }()

	wg.Wait()
	<-drained
}
