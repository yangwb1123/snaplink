package servercache

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// countingClientStore is a REAL in-memory core.ClientStore (no mock — it
// genuinely stores + serves clients) that counts inner Get / ValidateSecret
// calls so a test can prove the cache served (or bypassed) a read. It is the
// test analogue of defaultimpl.MemoryClientStore, re-implemented here because
// defaultimpl imports package sso (importing it back would be a cycle).
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
func TestClientStoreCache_ValidateSecretBypassesCache(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "old", Active: true})
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	// Prime the metadata cache with a Get.
	if _, err := cache.Get(ctx, "c1"); err != nil {
		t.Fatalf("get: %v", err)
	}
	// Old secret validates.
	if err := cache.ValidateSecret(ctx, "c1", "old"); err != nil {
		t.Fatalf("validate old: %v", err)
	}
	// Rotate the secret directly on the inner store (out of band).
	if err := inner.Update(ctx, &core.Client{ID: "c1", Secret: "new", Active: true}); err != nil {
		t.Fatalf("update: %v", err)
	}
	// The cache STILL serves the stale metadata Get (TTL not expired, not
	// evicted) — that's the accepted tradeoff and proves the cache is active.
	if _, err := cache.Get(ctx, "c1"); err != nil {
		t.Fatalf("get after update: %v", err)
	}
	// But ValidateSecret MUST see the new secret immediately (bypasses cache).
	if err := cache.ValidateSecret(ctx, "c1", "old"); err == nil {
		t.Fatal("ValidateSecret accepted the STALE secret — cache leaked into credential check")
	}
	if err := cache.ValidateSecret(ctx, "c1", "new"); err != nil {
		t.Fatalf("ValidateSecret rejected the live secret: %v", err)
	}
	// Every ValidateSecret reached the inner store.
	if got := inner.validateCalls.Load(); got != 3 {
		t.Fatalf("ValidateSecret inner calls = %d, want 3 (cache must never serve it)", got)
	}
}

// §2 GATE: a MISS is never served stale. An unknown Get hits the inner store
// every time; once the client is created in the inner store, the next Get sees
// it (NOT a cached negative entry).
func TestClientStoreCache_MissNeverCached(t *testing.T) {
	inner := newCountingClientStore()
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	// Three misses must each reach the inner store.
	for i := 0; i < 3; i++ {
		if _, err := cache.Get(ctx, "ghost"); !errors.Is(err, core.ErrNoSuchClient) {
			t.Fatalf("miss %d: err = %v, want ErrNoSuchClient", i, err)
		}
	}
	if got := inner.getCalls.Load(); got != 3 {
		t.Fatalf("inner Get calls = %d, want 3 (misses must NOT be cached)", got)
	}

	// Create the client in the inner store; the NEXT Get must see it, not a
	// cached miss.
	inner.seed(&core.Client{ID: "ghost", Secret: "s", Active: true})
	got, err := cache.Get(ctx, "ghost")
	if err != nil {
		t.Fatalf("get after create: %v", err)
	}
	if got == nil || got.ID != "ghost" {
		t.Fatalf("get after create returned %+v, want the freshly-created client", got)
	}
}

// A cache HIT is served WITHOUT touching the inner store within TTL, and the
// entry expires after TTL (the next Get re-reads).
func TestClientStoreCache_HitServedThenExpires(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "s", Active: true})
	cache := NewClientStoreCache(inner, 40*time.Millisecond, nil)
	ctx := context.Background()

	// First Get = miss -> inner read (1).
	if _, err := cache.Get(ctx, "c1"); err != nil {
		t.Fatalf("get1: %v", err)
	}
	// Several more Gets within TTL = hits, no inner read.
	for i := 0; i < 5; i++ {
		if _, err := cache.Get(ctx, "c1"); err != nil {
			t.Fatalf("hit get: %v", err)
		}
	}
	if got := inner.getCalls.Load(); got != 1 {
		t.Fatalf("inner Get calls within TTL = %d, want 1 (hits must skip the store)", got)
	}

	// After TTL the entry expires; the next Get re-reads the inner store.
	time.Sleep(60 * time.Millisecond)
	if _, err := cache.Get(ctx, "c1"); err != nil {
		t.Fatalf("get after TTL: %v", err)
	}
	if got := inner.getCalls.Load(); got != 2 {
		t.Fatalf("inner Get calls after TTL = %d, want 2 (expired entry must re-read)", got)
	}
}

// evict() (the primitive InvalidateClientCache calls) drops the entry so the
// next Get sees the inner store's new metadata immediately.
func TestClientStoreCache_EvictReReads(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "s", Active: true, RedirectURIs: []string{"https://a"}})
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	first, err := cache.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get1: %v", err)
	}
	if len(first.RedirectURIs) != 1 || first.RedirectURIs[0] != "https://a" {
		t.Fatalf("get1 redirect = %v", first.RedirectURIs)
	}

	// Mutate the inner store, then evict (what InvalidateClientCache does).
	if err := inner.Update(ctx, &core.Client{ID: "c1", Secret: "s", Active: true, RedirectURIs: []string{"https://b"}}); err != nil {
		t.Fatalf("update: %v", err)
	}
	cache.Evict("c1")

	got, err := cache.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get after evict: %v", err)
	}
	if len(got.RedirectURIs) != 1 || got.RedirectURIs[0] != "https://b" {
		t.Fatalf("get after evict redirect = %v, want [https://b]", got.RedirectURIs)
	}
}

// Update/Delete through the decorator evict the affected entry automatically
// (belt-and-suspenders alongside the InvalidateClientCache bus).
func TestClientStoreCache_MutationsEvict(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "s", Active: true, Name: "v1"})
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	if _, err := cache.Get(ctx, "c1"); err != nil { // prime
		t.Fatalf("prime: %v", err)
	}
	// Update via the decorator -> evicts.
	if err := cache.Update(ctx, &core.Client{ID: "c1", Secret: "s", Active: true, Name: "v2"}); err != nil {
		t.Fatalf("update: %v", err)
	}
	got, err := cache.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get after decorator update: %v", err)
	}
	if got.Name != "v2" {
		t.Fatalf("name after update = %q, want v2 (Update must evict)", got.Name)
	}

	// Delete via the decorator -> evicts -> not-found on next Get.
	if err := cache.Delete(ctx, "c1"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := cache.Get(ctx, "c1"); !errors.Is(err, core.ErrNoSuchClient) {
		t.Fatalf("get after delete = %v, want ErrNoSuchClient (Delete must evict)", err)
	}
}

// §2 GATE: clone-on-read. A caller mutating its returned *core.Client must NOT
// corrupt the cached snapshot another caller observes, and must not corrupt the
// inner store (whose MemoryClientStore analogue returns shared pointers).
func TestClientStoreCache_CloneOnReadIsolation(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{
		ID:            "c1",
		Secret:        "s",
		Active:        true,
		RedirectURIs:  []string{"https://a"},
		AllowedScopes: []string{"openid"},
		Attributes:    map[string]string{"k": "v"},
		JWKS:          []core.JWK{{Kty: "OKP", Crv: "Ed25519", X: "xxx"}},
	})
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	a, err := cache.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get a: %v", err)
	}
	// Mutate every reference-typed field on the returned client.
	a.RedirectURIs[0] = "https://evil"
	a.RedirectURIs = append(a.RedirectURIs, "https://evil2")
	a.AllowedScopes[0] = "admin"
	a.Attributes["k"] = "tampered"
	a.Attributes["injected"] = "yes"
	a.JWKS[0].X = "tampered"
	a.Active = false
	a.Secret = "leaked"

	// A second Get (cache HIT) must observe the PRISTINE snapshot.
	b, err := cache.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("get b: %v", err)
	}
	if b.RedirectURIs[0] != "https://a" || len(b.RedirectURIs) != 1 {
		t.Fatalf("cached RedirectURIs corrupted: %v", b.RedirectURIs)
	}
	if b.AllowedScopes[0] != "openid" {
		t.Fatalf("cached AllowedScopes corrupted: %v", b.AllowedScopes)
	}
	if b.Attributes["k"] != "v" || b.Attributes["injected"] != "" {
		t.Fatalf("cached Attributes corrupted: %v", b.Attributes)
	}
	if b.JWKS[0].X != "xxx" {
		t.Fatalf("cached JWKS corrupted: %v", b.JWKS[0])
	}
	if !b.Active {
		t.Fatal("cached Active corrupted")
	}

	// The inner store snapshot must also be pristine (clone-on-store).
	raw, err := inner.Get(ctx, "c1")
	if err != nil {
		t.Fatalf("inner get: %v", err)
	}
	if raw.RedirectURIs[0] != "https://a" || raw.AllowedScopes[0] != "openid" || raw.Attributes["k"] != "v" {
		t.Fatalf("INNER store corrupted by caller mutation: %+v", raw)
	}
}

// cloneClient preserves nil-vs-empty so a clone compares equal to the original
// across every reference field.
func TestCloneClient_NilAndEmptyPreserved(t *testing.T) {
	if got := cloneClient(nil); got != nil {
		t.Fatalf("cloneClient(nil) = %v, want nil", got)
	}
	in := &core.Client{ID: "c1"} // all slices/maps nil
	out := cloneClient(in)
	if out.RedirectURIs != nil || out.AllowedScopes != nil || out.Attributes != nil || out.JWKS != nil {
		t.Fatalf("nil fields became non-nil on clone: %+v", out)
	}
	in2 := &core.Client{ID: "c2", RedirectURIs: []string{}}
	out2 := cloneClient(in2)
	if out2.RedirectURIs == nil || len(out2.RedirectURIs) != 0 {
		t.Fatalf("empty slice not preserved: %v", out2.RedirectURIs)
	}
}

// The metric callback fires with bounded {hit,miss} outcomes only.
func TestClientStoreCache_OutcomeCallback(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{ID: "c1", Secret: "s", Active: true})
	var hits, misses atomic.Int64
	cache := NewClientStoreCache(inner, time.Minute, func(outcome string) {
		switch outcome {
		case "hit":
			hits.Add(1)
		case "miss":
			misses.Add(1)
		default:
			t.Errorf("unexpected outcome label %q (must be bounded hit/miss)", outcome)
		}
	})
	ctx := context.Background()
	_, _ = cache.Get(ctx, "c1") // miss
	_, _ = cache.Get(ctx, "c1") // hit
	_, _ = cache.Get(ctx, "c1") // hit
	if misses.Load() != 1 || hits.Load() != 2 {
		t.Fatalf("outcomes: hits=%d misses=%d, want hits=2 misses=1", hits.Load(), misses.Load())
	}
}

// -count=10 -race: concurrent Get during evict must not race or tear.
func TestClientStoreCache_ConcurrentGetDuringEvict(t *testing.T) {
	inner := newCountingClientStore()
	inner.seed(&core.Client{
		ID:           "c1",
		Secret:       "s",
		Active:       true,
		RedirectURIs: []string{"https://a"},
		Attributes:   map[string]string{"k": "v"},
	})
	cache := NewClientStoreCache(inner, time.Minute, nil)
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Readers.
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				c, err := cache.Get(ctx, "c1")
				if err != nil {
					continue // a concurrent evict + miss path is legal
				}
				// Read the cloned fields — must never be a torn/shared value.
				if c.ID != "c1" || (len(c.RedirectURIs) > 0 && c.RedirectURIs[0] != "https://a") {
					t.Errorf("torn read: %+v", c)
					return
				}
				if v, ok := c.Attributes["k"]; ok && v != "v" {
					t.Errorf("torn attributes: %v", c.Attributes)
					return
				}
			}
		}()
	}
	// Evictors.
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					cache.Evict("c1")
				}
			}
		}()
	}

	time.Sleep(50 * time.Millisecond)
	close(stop)
	wg.Wait()
}

// Wiring: WithClientStoreCache decorates the store; absent the option the store
// is the raw store (byte-identical off), and InvalidateClientCache is a no-op
// when unwired.
