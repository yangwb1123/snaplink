package rotation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
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

// captureLogger records Error messages so fail-open tests can assert the
// sweep logged the outage instead of silently swallowing it.
type captureLogger struct {
	mu     sync.Mutex
	errors []string
}

func (c *captureLogger) Error(msg string, _ ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.errors = append(c.errors, msg)
}
func (c *captureLogger) Info(string, ...any)  {}
func (c *captureLogger) Debug(string, ...any) {}

type failingWarningClaimStore struct{}

func (failingWarningClaimStore) Claim(context.Context, ClientSecretWarningClaim) (bool, error) {
	return false, errors.New("claim unavailable")
}

func TestClientSecretScan_WarnsWithinWindows(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	const secret = "client-secret-not-in-audit"
	store := &fakeClientStore{clients: []*core.Client{
		{ID: "c-10d", Secret: secret, SecretExpiresAt: time.Now().Add(10 * 24 * time.Hour)}, // inside 30d + 14d
		{ID: "c-3d", SecretExpiresAt: time.Now().Add(3 * 24 * time.Hour)},                   // inside all three
		{ID: "c-far", SecretExpiresAt: time.Now().Add(90 * 24 * time.Hour)},                 // outside all
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
	encoded, err := json.Marshal(events)
	if err != nil {
		t.Fatalf("marshal warning events: %v", err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatalf("warning event payload contains client secret: %s", encoded)
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
	if sc.claimStore != nil {
		t.Fatal("default scanner unexpectedly has a shared claim store")
	}

	sc.sweep(ctx)
	sc.sweep(ctx) // same day: dedup must suppress

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 3 {
		t.Fatalf("events after two sweeps = %d, want 3 (one per window, deduped)", len(events))
	}
}

func TestClientSecretScan_ChangedExpiryGenerationWarnsAgain(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	expires := time.Now().UTC().Add(5 * 24 * time.Hour)
	store := &fakeClientStore{clients: []*core.Client{{ID: "c-1", SecretExpiresAt: expires}}}
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	sc := NewClientSecretExpiryScanner(store, rec, nil, nil)

	sc.sweep(ctx)
	store.mu.Lock()
	store.clients[0].SecretExpiresAt = expires.Add(time.Hour)
	store.mu.Unlock()
	sc.sweep(ctx)

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 6 {
		t.Fatalf("events after changed expiry generation = %d, want 6", len(events))
	}
}

func TestClientSecretScan_SharedClaimStoreDeduplicatesReplicas(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{clients: []*core.Client{{ID: "c-1", SecretExpiresAt: time.Now().Add(5 * 24 * time.Hour)}}}
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	claims := NewMemoryClientSecretWarningClaimStore()
	scanners := []*ClientSecretExpiryScanner{
		NewClientSecretExpiryScanner(store, rec, nil, nil, WithClientSecretWarningClaimStore(claims)),
		NewClientSecretExpiryScanner(store, rec, nil, nil, WithClientSecretWarningClaimStore(claims)),
	}
	var wg sync.WaitGroup
	wg.Add(len(scanners))
	for _, sc := range scanners {
		go func(sc *ClientSecretExpiryScanner) {
			defer wg.Done()
			sc.sweep(ctx)
		}(sc)
	}
	wg.Wait()

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 3 {
		t.Fatalf("shared claim events = %d, want 3", len(events))
	}
}

func TestClientSecretScan_ClaimStoreOutageFallsBackToLocalDedup(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{clients: []*core.Client{{ID: "c-1", SecretExpiresAt: time.Now().Add(5 * 24 * time.Hour)}}}
	sink := audit.NewMemorySink(20)
	rec := audit.New(sink)
	log := &captureLogger{}
	sc := NewClientSecretExpiryScanner(store, rec, nil, log,
		WithClientSecretWarningClaimStore(failingWarningClaimStore{}))

	sc.sweep(ctx)
	sc.sweep(ctx)

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 3 {
		t.Fatalf("claim outage events = %d, want 3", len(events))
	}
	claimFailures := 0
	for _, msg := range log.errors {
		if msg == "client secret expiry warning claim failed" {
			claimFailures++
		}
	}
	if claimFailures != 3 {
		t.Fatalf("claim failure logs = %d, want 3: %v", claimFailures, log.errors)
	}
}

func TestMemoryClientSecretWarningClaimStore_Concurrent(t *testing.T) {
	t.Parallel()
	store := NewMemoryClientSecretWarningClaimStore()
	claim := ClientSecretWarningClaim{
		ClientID: "c-1", Window: 7 * 24 * time.Hour,
		Day:             time.Date(2026, time.January, 2, 0, 0, 0, 0, time.UTC),
		SecretExpiresAt: time.Date(2026, time.January, 9, 0, 0, 0, 0, time.UTC),
	}
	const attempts = 64
	results := make(chan bool, attempts)
	var wg sync.WaitGroup
	wg.Add(attempts)
	for i := 0; i < attempts; i++ {
		go func() {
			defer wg.Done()
			won, err := store.Claim(context.Background(), claim)
			if err != nil {
				t.Errorf("claim: %v", err)
			}
			results <- won
		}()
	}
	wg.Wait()
	close(results)
	winners := 0
	for won := range results {
		if won {
			winners++
		}
	}
	if winners != 1 {
		t.Fatalf("concurrent winners = %d, want 1", winners)
	}
}

func TestClientSecretScan_StoreOutageFailsOpen(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	store := &fakeClientStore{err: context.DeadlineExceeded}
	sink := audit.NewMemorySink(10)
	rec := audit.New(sink)
	log := &captureLogger{}
	sc := NewClientSecretExpiryScanner(store, rec, nil, log)

	sc.sweep(ctx) // must not panic, must not emit

	events, _ := sink.Query(ctx, audit.Query{Type: audit.EventClientSecretExpiring})
	if len(events) != 0 {
		t.Fatalf("store outage emitted %d events, want 0", len(events))
	}
	if len(log.errors) != 1 || log.errors[0] != "client secret expiry scan failed" {
		t.Fatalf("fail-open log = %v, want [client secret expiry scan failed]", log.errors)
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
