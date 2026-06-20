package memory_test

import (
	"context"
	"sync"
	"testing"

	"github.com/snaplink/sso/platform/signingkeys"
	"github.com/snaplink/sso/platform/signingkeys/memory"
)

// TestPublishCloseRace exercises Publish racing Close. Before the fix, Publish
// snapshotted the subscriber channels under the lock, released it, then did a
// non-blocking send — which panics if Close has closed the channel in between
// (the default: only guards a FULL channel, never a CLOSED one). Run with
// -race -count=10 to surface the window.
func TestPublishCloseRace(t *testing.T) {
	r := memory.New()

	ch, err := r.Subscribe(context.Background())
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
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
			ann := signingkeys.Announcement{ReplicaID: "replica-1"}
			for j := 0; j < 200; j++ {
				_ = r.Publish(context.Background(), ann)
			}
		}()
	}

	go func() { _ = r.Close() }()

	wg.Wait()
	<-drained
}
