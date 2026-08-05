package rotation

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// fakeClientStore is a minimal core.ClientStore for scanner tests.
type fakeClientStore struct {
	mu      sync.Mutex
	clients []*core.Client
	err     error
}

func (f *fakeClientStore) List(context.Context) ([]*core.Client, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.err != nil {
		return nil, f.err
	}
	return f.clients, nil
}

func (f *fakeClientStore) Get(context.Context, string) (*core.Client, error) {
	return nil, core.ErrNoSuchClient
}
func (f *fakeClientStore) ValidateSecret(context.Context, string, string) error {
	return errors.New("invalid")
}
func (f *fakeClientStore) Add(context.Context, *core.Client) error    { return nil }
func (f *fakeClientStore) Update(context.Context, *core.Client) error { return nil }
func (f *fakeClientStore) Delete(context.Context, string) error       { return nil }
func (f *fakeClientStore) RotateSecret(context.Context, string) (string, error) {
	return "", nil
}

func TestClientSecretScan_WarnsWithinWindows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{clients: []*core.Client{
		{ID: "c-10d", SecretExpiresAt: time.Now().Add(10 * 24 * time.Hour)}, // inside 30d + 14d
		{ID: "c-3d", SecretExpiresAt: time.Now().Add(3 * 24 * time.Hour)},   // inside all three
		{ID: "c-far", SecretExpiresAt: time.Now().Add(90 * 24 * time.Hour)}, // outside all
		{ID: "c-never"}, // no expiry pinned
		{ID: "c-public", TokenEndpointAuthMethod: "none", SecretExpiresAt: time.Now().Add(24 * time.Hour)},
		{ID: "c-expired", SecretExpiresAt: time.Now().Add(-time.Hour)},
	}}
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	sc := NewClientSecretExpiryScanner(store, rec, nil, spi.NopLogger{})

	sc.sweep(ctx)

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 5 {
		t.Fatalf("events = %d, want 5 (c-10d: 30d+14d, c-3d: 30d+14d+7d); got %+v",
			len(events), events)
	}
	windows := map[string]int{}
	for _, e := range events {
		windows[e.ClientID+"|"+e.Reason]++
	}
	if windows["c-10d|720h0m0s"] != 1 || windows["c-10d|336h0m0s"] != 1 {
		t.Errorf("c-10d window events = %v, want 30d + 14d exactly once each", windows)
	}
	if windows["c-3d|168h0m0s"] != 1 {
		t.Errorf("c-3d missing 7d window: %v", windows)
	}
	for _, id := range []string{"c-far", "c-never", "c-public", "c-expired"} {
		if _, ok := windows[id]; ok {
			t.Errorf("client %s emitted events: %v", id, windows)
		}
	}
}

func TestClientSecretScan_DedupsPerDayPerWindow(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{clients: []*core.Client{
		{ID: "c-1", SecretExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
	}}
	sink := audit.NewMemorySink(50)
	rec := audit.New(sink)
	sc := NewClientSecretExpiryScanner(store, rec, nil, spi.NopLogger{})

	sc.sweep(ctx)
	sc.sweep(ctx) // same day: dedup must suppress

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 3 {
		t.Fatalf("events after two sweeps = %d, want 3 (one per window, deduped)", len(events))
	}
}

func TestClientSecretScan_StoreOutageFailsOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{err: context.DeadlineExceeded}
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	sc := NewClientSecretExpiryScanner(store, rec, nil, spi.NopLogger{})

	sc.sweep(ctx) // must not panic, must not emit

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 0 {
		t.Fatalf("store outage emitted %d events, want 0", len(events))
	}
}

// TestStartClientSecretScan_StopsOnCancel proves the loop lifecycle: the
// done channel closes when ctx is cancelled.
func TestStartClientSecretScan_StopsOnCancel(t *testing.T) {
	t.Parallel()
	ctx, cancel := context.WithCancel(context.Background())
	store := &fakeClientStore{clients: []*core.Client{
		{ID: "c-1", SecretExpiresAt: time.Now().Add(5 * 24 * time.Hour)},
	}}
	done := StartClientSecretScan(ctx, store, nil, nil, spi.NopLogger{})
	time.Sleep(20 * time.Millisecond)
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scanner loop did not exit after cancel")
	}
}
