package configaudit_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/cluster/memory"
	"github.com/snaplink/sso/platform/configaudit"
)

// waitFor polls cond until it's true or the deadline elapses, failing the
// test on timeout. Avoids a flaky fixed sleep for the async detector loop.
func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition not met before deadline")
}

func TestDriftDetector_MismatchEmitsAuditEventAndCallsOnMismatch(t *testing.T) {
	bus := memory.New()
	defer bus.Close()

	sink := audit.NewMemorySink(16)
	rec := audit.New(sink)

	var mu sync.Mutex
	var mismatches []string
	onMismatch := func(peerID, peerDigest, localDigest string) {
		mu.Lock()
		defer mu.Unlock()
		mismatches = append(mismatches, peerID)
	}

	localDigest := "local-digest-value"
	dd := configaudit.NewDriftDetector(bus, "replica-a", 10*time.Millisecond,
		func(context.Context) (string, error) { return localDigest, nil },
		rec, nil, onMismatch)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done, err := dd.Run(ctx)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}

	// Simulate a peer replica publishing a DIFFERENT digest.
	if err := bus.Publish(ctx, cluster.Event{
		Kind:    cluster.KindConfigDigest,
		Key:     "replica-b",
		Payload: map[string]string{cluster.MetaConfigDigest: "peer-digest-value"},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}

	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(mismatches) > 0
	})
	mu.Lock()
	if mismatches[0] != "replica-b" {
		t.Errorf("expected mismatch attributed to replica-b, got %v", mismatches)
	}
	mu.Unlock()

	waitFor(t, func() bool { return sink.Len() > 0 })
	events, err := sink.Query(ctx, audit.Query{})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	found := false
	for _, e := range events {
		if e.Type == configaudit.EventConfigDriftDetected {
			found = true
		}
	}
	if !found {
		t.Errorf("expected a %q audit event, got %+v", configaudit.EventConfigDriftDetected, events)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not exit after ctx cancel")
	}
}

func TestDriftDetector_MatchingDigestNoMismatch(t *testing.T) {
	bus := memory.New()
	defer bus.Close()

	var onMismatchCalled bool
	dd := configaudit.NewDriftDetector(bus, "replica-a", 10*time.Millisecond,
		func(context.Context) (string, error) { return "same-digest", nil },
		nil, nil, func(string, string, string) { onMismatchCalled = true })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := dd.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}

	if err := bus.Publish(ctx, cluster.Event{
		Kind:    cluster.KindConfigDigest,
		Key:     "replica-b",
		Payload: map[string]string{cluster.MetaConfigDigest: "same-digest"},
	}); err != nil {
		t.Fatalf("Publish: %v", err)
	}
	// Give the loop a moment to process — there is nothing to WAIT for on
	// the "nothing happened" path, so a short bounded sleep is the correct
	// tool (not waitFor, which needs a true condition to poll for).
	time.Sleep(50 * time.Millisecond)
	if onMismatchCalled {
		t.Errorf("matching digests must not trigger onMismatch")
	}
}

func TestDriftDetector_IgnoresOwnEcho(t *testing.T) {
	bus := memory.New()
	defer bus.Close()

	var onMismatchCalled bool
	dd := configaudit.NewDriftDetector(bus, "replica-a", 5*time.Millisecond,
		func(context.Context) (string, error) { return "digest-a", nil },
		nil, nil, func(string, string, string) { onMismatchCalled = true })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if _, err := dd.Run(ctx); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Let a few publish ticks happen — the detector publishes under its OWN
	// replica-a key and also receives it back via its own subscription.
	time.Sleep(60 * time.Millisecond)
	if onMismatchCalled {
		t.Errorf("the detector must never compare its own echoed publish against itself")
	}
}

func TestDriftDetector_OffByDefault(t *testing.T) {
	bus := memory.New()
	defer bus.Close()
	dd := configaudit.NewDriftDetector(bus, "replica-a", 0, /* interval <= 0 */
		func(context.Context) (string, error) { return "x", nil }, nil, nil, nil)

	done, err := dd.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Run with interval<=0 must return an already-closed channel")
	}
}

func TestDriftDetector_NilBus(t *testing.T) {
	dd := configaudit.NewDriftDetector(nil, "replica-a", time.Second,
		func(context.Context) (string, error) { return "x", nil }, nil, nil, nil)
	done, err := dd.Run(context.Background())
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	select {
	case <-done:
	default:
		t.Fatal("Run with a nil bus must return an already-closed channel")
	}
}
