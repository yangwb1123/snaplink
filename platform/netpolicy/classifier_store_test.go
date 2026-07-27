package netpolicy_test

// Store-driven Classifier tests: Start/Reload happy + error paths and end-to-end
// Watch delivery through the real netpolicy/memory backend. External package
// (netpolicy_test) so the real memory Store can be imported without the cycle an
// in-package test would hit (netpolicy/memory imports netpolicy). The Reload/
// Start error paths use a thin error-injecting wrapper around the real Store —
// NOT a mock framework, just a seam to force a List/Watch failure, mirroring the
// flakyStore convention in classifier_selfheal_test.go.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/netpolicy"
	"github.com/yangwb1123/snaplink/platform/netpolicy/memory"
)

// errStore wraps the real memory Store and can be told to fail any individual
// operation, to exercise Reload/Start + handler error returns without a mock.
// Shared across classifier_store_test.go and handlers_test.go (same package).
type errStore struct {
	inner      *memory.Store
	failList   bool
	failWatch  bool
	failGet    bool
	failApply  bool
	failDelete bool
}

var errInjected = errors.New("injected store failure")

func (e *errStore) Get(ctx context.Context, name string) (*netpolicy.Policy, error) {
	if e.failGet {
		return nil, errInjected
	}
	return e.inner.Get(ctx, name)
}
func (e *errStore) List(ctx context.Context) ([]*netpolicy.Policy, error) {
	if e.failList {
		return nil, errInjected
	}
	return e.inner.List(ctx)
}
func (e *errStore) Apply(ctx context.Context, p *netpolicy.Policy) (*netpolicy.Policy, error) {
	if e.failApply {
		return nil, errInjected
	}
	return e.inner.Apply(ctx, p)
}
func (e *errStore) Delete(ctx context.Context, name string) error {
	if e.failDelete {
		return errInjected
	}
	return e.inner.Delete(ctx, name)
}
func (e *errStore) Watch(ctx context.Context) (<-chan netpolicy.Event, error) {
	if e.failWatch {
		return nil, errInjected
	}
	return e.inner.Watch(ctx)
}
func (e *errStore) Close() error { return e.inner.Close() }

var _ netpolicy.Store = (*errStore)(nil)

func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

func TestReloadSeedsSnapshot(t *testing.T) {
	t.Parallel()

	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx := context.Background()
	if _, err := store.Apply(ctx, &netpolicy.Policy{Name: "intranet", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seed apply: %v", err)
	}

	c := netpolicy.NewClassifier()
	if err := c.Reload(ctx, store); err != nil {
		t.Fatalf("Reload: %v", err)
	}
	if got := c.Classify("10.0.0.1", ""); got == nil || got.Name != "intranet" {
		t.Fatalf("Reload did not seed snapshot: %v", got)
	}
}

func TestReloadListError(t *testing.T) {
	t.Parallel()

	store := &errStore{inner: memory.New(), failList: true}
	defer func() { _ = store.Close() }()

	c := netpolicy.NewClassifier()
	if err := c.Reload(context.Background(), store); !errors.Is(err, errInjected) {
		t.Fatalf("Reload error = %v, want injected", err)
	}
	// On a failed List the snapshot stays empty (nothing classifies).
	if got := c.Classify("10.0.0.1", ""); got != nil {
		t.Fatalf("snapshot mutated despite List error: %v", got)
	}
}

func TestStartWatchError(t *testing.T) {
	t.Parallel()

	store := &errStore{inner: memory.New(), failWatch: true}
	defer func() { _ = store.Close() }()

	c := netpolicy.NewClassifier()
	if _, err := c.Start(context.Background(), store); !errors.Is(err, errInjected) {
		t.Fatalf("Start Watch error = %v, want injected", err)
	}
}

func TestStartReloadError(t *testing.T) {
	t.Parallel()

	// Watch succeeds but the seeding List fails — Start must surface the error
	// (and not leave a leaked goroutine; the subscription channel is abandoned).
	store := &errStore{inner: memory.New(), failList: true}
	defer func() { _ = store.Close() }()

	c := netpolicy.NewClassifier()
	if _, err := c.Start(context.Background(), store); !errors.Is(err, errInjected) {
		t.Fatalf("Start Reload error = %v, want injected", err)
	}
}

func TestStartSeedsThenStreams(t *testing.T) {
	t.Parallel()

	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Pre-seed a policy so Start's initial Reload picks it up.
	if _, err := store.Apply(ctx, &netpolicy.Policy{Name: "seeded", CIDRs: []string{"10.0.0.0/8"}}); err != nil {
		t.Fatalf("seed: %v", err)
	}

	c := netpolicy.NewClassifier()
	done, err := c.Start(ctx, store)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// The pre-seeded policy is visible immediately (initial Reload).
	if got := c.Classify("10.0.0.1", ""); got == nil || got.Name != "seeded" {
		t.Fatalf("seeded policy not in snapshot after Start: %v", got)
	}

	// A policy added AFTER Start flows through the Watch consumer.
	if _, err := store.Apply(ctx, &netpolicy.Policy{Name: "live", CIDRs: []string{"192.168.0.0/16"}}); err != nil {
		t.Fatalf("live apply: %v", err)
	}
	if !waitFor(2*time.Second, func() bool {
		p := c.Classify("192.168.0.1", "")
		return p != nil && p.Name == "live"
	}) {
		t.Fatal("post-Start Apply never reflected via Watch")
	}

	// A delete flows through too (EventRemoved).
	if err := store.Delete(ctx, "live"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !waitFor(2*time.Second, func() bool { return c.Classify("192.168.0.1", "") == nil }) {
		t.Fatal("delete never reflected via Watch")
	}

	// Clean shutdown closes done.
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("done not closed after ctx cancel")
	}
}

// TestSubscribeBeforeSeedOrdering locks the Start contract: Watch is subscribed
// synchronously BEFORE the seeding Reload, so an Apply racing in right around
// boot is never silently dropped — it is either already in the seed List or
// arrives on the (already-open) Watch channel and is applied. We exercise the
// ordering by Applying immediately after Start and asserting eventual visibility.
func TestSubscribeBeforeSeedOrdering(t *testing.T) {
	t.Parallel()

	store := memory.New()
	defer func() { _ = store.Close() }()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	c := netpolicy.NewClassifier()
	done, err := c.Start(ctx, store)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}

	// Fire several policies back-to-back right after Start; all must land via the
	// already-open subscription (subscribe-before-seed guarantees none is lost).
	for _, n := range []struct{ name, cidr, addr string }{
		{"a", "10.1.0.0/16", "10.1.0.1"},
		{"b", "10.2.0.0/16", "10.2.0.1"},
		{"c", "10.3.0.0/16", "10.3.0.1"},
	} {
		if _, err := store.Apply(ctx, &netpolicy.Policy{Name: n.name, CIDRs: []string{n.cidr}}); err != nil {
			t.Fatalf("apply %s: %v", n.name, err)
		}
	}
	if !waitFor(3*time.Second, func() bool {
		return len(c.Snapshot()) == 3
	}) {
		t.Fatalf("not all rapid post-Start applies landed: snapshot=%d", len(c.Snapshot()))
	}

	cancel()
	<-done
}
