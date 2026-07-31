package sso

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso/servercache"
	"github.com/yangwb1123/snaplink/platform/cluster"
	clustermem "github.com/yangwb1123/snaplink/platform/cluster/memory"
	"github.com/yangwb1123/snaplink/shared/core"
)

func TestClientStoreCache_ServerWiring(t *testing.T) {
	t.Parallel()
	inner := newCountingClientStore()

	// Unwired: the server's clientStore is the RAW store, no wrapper.
	plain := NewServer(WithClientStore(inner))
	if _, isCache := plain.clientStore.(*servercache.ClientStoreCache); isCache {
		t.Fatal("clientStore was wrapped WITHOUT WithClientStoreCache (not byte-identical off)")
	}
	if plain.clientStore != core.ClientStore(inner) {
		t.Fatal("unwired clientStore is not the exact raw store")
	}
	// InvalidateClientCache is a safe no-op when no cache is wired.
	plain.InvalidateClientCache("anything")

	// Wired: the store is wrapped.
	wired := NewServer(WithClientStore(inner), WithClientStoreCache(time.Minute))
	if _, isCache := wired.clientStore.(*servercache.ClientStoreCache); !isCache {
		t.Fatal("WithClientStoreCache did not wrap the store")
	}
	if wired.clientStoreCacheRef == nil {
		t.Fatal("clientStoreCacheRef not retained for InvalidateClientCache")
	}

	// ttl <= 0 also => no wrapper.
	zero := NewServer(WithClientStore(inner), WithClientStoreCache(0))
	if _, isCache := zero.clientStore.(*servercache.ClientStoreCache); isCache {
		t.Fatal("WithClientStoreCache(0) wrapped the store; ttl<=0 must be off")
	}
}

// InvalidateClientCache on a wired server evicts the local cache so the next
// Get re-reads (the end-to-end path admin/DCR mutations use).
func TestServer_InvalidateClientCacheEvicts(t *testing.T) {
	t.Parallel()
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "s", Active: true, Name: "v1"})
	srv := NewServer(WithClientStore(inner), WithClientStoreCache(time.Minute))
	ctx := context.Background()

	if _, err := srv.clientStore.Get(ctx, "c1"); err != nil {
		t.Fatalf("prime: %v", err)
	}
	if err := inner.Update(ctx, &core.Client{ID: "c1", Secret: "s", Active: true, Name: "v2"}); err != nil {
		t.Fatalf("inner update: %v", err)
	}
	// Without invalidation the cache would still serve v1.
	srv.InvalidateClientCache("c1")
	got, err := srv.clientStore.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get after invalidate: %v", err)
	}
	if got.Name != "v2" {
		t.Fatalf("name after InvalidateClientCache = %q, want v2", got.Name)
	}
}

func TestServer_InvalidateRestoredControlPlanePublishesFullFlush(t *testing.T) {
	t.Parallel()
	bus := clustermem.New()
	t.Cleanup(func() { _ = bus.Close() })
	events, err := bus.Subscribe(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	NewServer(WithInvalidationBus(bus)).InvalidateRestoredControlPlane()
	select {
	case event := <-events:
		if event.Kind != cluster.KindControlPlaneRestore {
			t.Fatalf("event kind = %q", event.Kind)
		}
	case <-time.After(time.Second):
		t.Fatal("restore invalidation was not published")
	}
}

type countingClientStore struct {
	mu            sync.Mutex
	clients       map[string]*core.Client
	getCalls      atomic.Int64
	validateCalls atomic.Int64
	updateCalls   atomic.Int64
	deleteCalls   atomic.Int64
	rotateCalls   atomic.Int64
}

func newCountingClientStore() *countingClientStore {
	return &countingClientStore{clients: make(map[string]*core.Client)}
}

func (s *countingClientStore) seed(c *core.Client) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clients[c.ID] = c
}

func (s *countingClientStore) Get(_ context.Context, id string) (*core.Client, error) {
	s.getCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return nil, core.ErrNoSuchClient
	}
	return c, nil
}

func (s *countingClientStore) ValidateSecret(_ context.Context, id, secret string) error {
	s.validateCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return core.ErrNoSuchClient
	}
	if c.Secret != secret {
		return errors.New("invalid client secret")
	}
	return nil
}

func (s *countingClientStore) List(_ context.Context) ([]*core.Client, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*core.Client, 0, len(s.clients))
	for _, c := range s.clients {
		out = append(out, c)
	}
	return out, nil
}

func (s *countingClientStore) Add(_ context.Context, c *core.Client) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; ok {
		return core.ErrClientExists
	}
	s.clients[c.ID] = c
	return nil
}

func (s *countingClientStore) Update(_ context.Context, c *core.Client) error {
	s.updateCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.clients[c.ID]; !ok {
		return core.ErrNoSuchClient
	}
	s.clients[c.ID] = c
	return nil
}

func (s *countingClientStore) Delete(_ context.Context, id string) error {
	s.deleteCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.clients, id)
	return nil
}

func (s *countingClientStore) RotateSecret(_ context.Context, id string) (string, error) {
	s.rotateCalls.Add(1)
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[id]
	if !ok {
		return "", core.ErrNoSuchClient
	}
	c.Secret = "rotated-" + c.Secret
	return c.Secret, nil
}

var _ core.ClientStore = (*countingClientStore)(nil)

// §2 GATE: ValidateSecret BYPASSES the cache. After a cached Get of a client,
// mutating the inner store's secret must be reflected by ValidateSecret on the
// VERY NEXT call — a stale cached credential check is forbidden.
