package servercache

import (
	"context"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security/clientrotation"
)

// DefaultClientStoreCacheTTL bounds how long a successfully-read client
// entity may be cached between core.ClientStore.Get round-trips. Mirrors the
// suspension cache's 30s default: short enough that an active-flag /
// metadata edit propagates promptly across the fleet, long enough that
// the >1k-QPS interactive-login + /token + tenant-bound hot path skips
// the per-request store read. The accepted staleness window is the same
// tradeoff as tenant.suspension_check.cache_ttl — a client deactivated
// (or whose metadata changed) mid-window keeps being served the prior
// value for at most TTL, unless an explicit InvalidateClientCache
// (local admin/DCR mutation + cross-replica bus) evicts it sooner.
const DefaultClientStoreCacheTTL = 30 * time.Second

// clientCacheEntry pairs a cached client snapshot with its freshness
// deadline. The stored *core.Client is a deep CLONE of what the inner
// store returned (see cloneClient) so a cache hit can never hand two
// callers the same mutable pointer.
type clientCacheEntry struct {
	client    *core.Client
	expiresAt time.Time
}

// ClientStoreCache is an OPTIONAL, opt-in TTL decorator over a
// core.ClientStore (WithClientStoreCache). It caches ONLY the metadata
// Get of an EXISTING client; every other concern stays correct by
// construction:
//
//   - ValidateSecret BYPASSES the cache entirely and passes through to
//     the inner store on EVERY call. A stale cached secret check is
//     forbidden (§2 HTTP-Basic / oracle-leak): the credential decision
//     must always reflect the authoritative store, never a TTL'd copy.
//   - MISSES are NEVER cached. A Get that returns the inner store's
//     not-found error falls through to the inner store on every call —
//     so a just-created client is visible immediately and a deleted
//     client's "unknown -> invalid_client" behavior can't drift. Only
//     successful Gets of existing clients populate the cache.
//   - Every mutating + listing method (List/Add/Update/Delete/
//     RotateSecret) passes through UNCACHED, and Update/Delete/
//     RotateSecret EVICT the affected entry so the next Get re-reads
//     (in addition to the cross-replica InvalidateClientCache bus the
//     Server wires from the admin + DCR mutation paths).
//   - Cache reads + writes hand out CLONES (cloneClient), so a caller
//     that mutates its returned *core.Client can't corrupt the cached
//     snapshot a concurrent caller observes.
//
// Optional extension interfaces a backend MAY implement
// (TenantScopedClientStore / ClientStoreStats) are surfaced via the
// passthrough type assertions below, so wrapping a backend never strips
// those capabilities.
type ClientStoreCache struct {
	inner core.ClientStore
	ttl   time.Duration

	mu      sync.RWMutex
	entries map[string]clientCacheEntry

	// onOutcome, when non-nil, is invoked with "hit" or "miss" on every
	// Get so the Server can bump a bounded {outcome} counter. Kept as a
	// nil-safe callback (not a metrics dependency in this leaf type) to
	// keep the decorator dependency-free.
	onOutcome func(outcome string)
}

// NewClientStoreCache wraps inner with a TTL'd Get cache. ttl <= 0 falls
// back to DefaultClientStoreCacheTTL. The caller (NewServer) is
// responsible for NOT constructing this when caching is disabled — a nil
// inner yields a degenerate cache that always reports the wrapped store's
// nil-deref, which is a programming error, not a runtime path.
func NewClientStoreCache(inner core.ClientStore, ttl time.Duration, onOutcome func(outcome string)) *ClientStoreCache {
	if ttl <= 0 {
		ttl = DefaultClientStoreCacheTTL
	}
	return &ClientStoreCache{
		inner:     inner,
		ttl:       ttl,
		entries:   make(map[string]clientCacheEntry),
		onOutcome: onOutcome,
	}
}

// Interface guard: the decorator is a drop-in core.ClientStore.
var _ core.ClientStore = (*ClientStoreCache)(nil)

// Get returns the client for clientID, served from the TTL cache on a
// fresh HIT and otherwise from the inner store. A successful inner read
// populates the cache; an error (including not-found) is returned as-is
// and NEVER cached, so misses always re-hit the inner store. The
// returned pointer is always a clone — the caller owns it and may mutate
// it freely without affecting the cached snapshot.
func (c *ClientStoreCache) Get(ctx context.Context, clientID string) (*core.Client, error) {
	if cl, ok := c.getFresh(clientID); ok {
		c.report("hit")
		return cl, nil
	}
	c.report("miss")
	cl, err := c.inner.Get(ctx, clientID)
	if err != nil || cl == nil {
		// Do NOT cache misses (or a nil-without-error): the next Get must
		// re-read the inner store so a just-created client is visible
		// immediately and a deleted client's unknown-behavior can't drift.
		return cl, err
	}
	c.store(clientID, cl)
	// Hand the caller its OWN clone, distinct from the one we cached.
	return cloneClient(cl), nil
}

// ValidateSecret ALWAYS passes through to the inner store — the
// credential decision is never served from cache (§2). No cache read,
// no cache write.
func (c *ClientStoreCache) ValidateSecret(ctx context.Context, clientID, clientSecret string) error {
	return c.inner.ValidateSecret(ctx, clientID, clientSecret)
}

// List passes through uncached — the admin/boot listing path is not the
// per-request hot path the cache targets, and a stale List would mask
// new/removed clients.
func (c *ClientStoreCache) List(ctx context.Context) ([]*core.Client, error) {
	return c.inner.List(ctx)
}

// Add passes through. A successful Add of a previously-unknown ID needs
// no eviction (a miss was never cached); evicting defensively is cheap
// and guards the (illegal) re-add-after-delete-within-TTL edge.
func (c *ClientStoreCache) Add(ctx context.Context, cl *core.Client) error {
	if err := c.inner.Add(ctx, cl); err != nil {
		return err
	}
	if cl != nil {
		c.Evict(cl.ID)
	}
	return nil
}

// Update passes through, then EVICTS the affected entry so the next Get
// re-reads the new metadata immediately on THIS replica (peers converge
// via the Server's InvalidateClientCache bus or their own TTL).
func (c *ClientStoreCache) Update(ctx context.Context, cl *core.Client) error {
	if err := c.inner.Update(ctx, cl); err != nil {
		return err
	}
	if cl != nil {
		c.Evict(cl.ID)
	}
	return nil
}

// Delete passes through, then EVICTS the affected entry so a deleted
// client immediately reverts to the inner store's not-found behavior.
func (c *ClientStoreCache) Delete(ctx context.Context, clientID string) error {
	if err := c.inner.Delete(ctx, clientID); err != nil {
		return err
	}
	c.Evict(clientID)
	return nil
}

// RotateSecret passes through, then EVICTS the affected entry — the
// cached snapshot carries the now-stale Secret field, so drop it.
func (c *ClientStoreCache) RotateSecret(ctx context.Context, clientID string) (string, error) {
	secret, err := c.inner.RotateSecret(ctx, clientID)
	if err != nil {
		return secret, err
	}
	c.Evict(clientID)
	return secret, nil
}

func (c *ClientStoreCache) RotateSecretWithOverlap(ctx context.Context, clientID string, overlap time.Duration) (string, error) {
	store, ok := c.inner.(clientrotation.ClientSecretOverlapRotator)
	if !ok {
		return "", core.ErrUnsupportedOperation
	}
	secret, err := store.RotateSecretWithOverlap(ctx, clientID, overlap)
	if err == nil {
		c.Evict(clientID)
	}
	return secret, err
}

func (c *ClientStoreCache) RotateSecretWithLifecycle(ctx context.Context, clientID string, overlap, lifetime time.Duration) (string, error) {
	store, ok := c.inner.(clientrotation.ClientSecretLifecycleRotator)
	if !ok {
		return "", core.ErrUnsupportedOperation
	}
	secret, err := store.RotateSecretWithLifecycle(ctx, clientID, overlap, lifetime)
	if err == nil {
		c.Evict(clientID)
	}
	return secret, err
}

// ListByTenant forwards to the inner store's TenantScopedClientStore
// extension when present, preserving that optional capability through the
// decorator (uncached — admin listing, not the hot path).
func (c *ClientStoreCache) ListByTenant(ctx context.Context, tenantID string) ([]*core.Client, error) {
	if ts, ok := c.inner.(core.TenantScopedClientStore); ok {
		return ts.ListByTenant(ctx, tenantID)
	}
	return nil, core.ErrUnsupportedOperation
}

// Stats forwards to the inner store's ClientStoreStats extension when
// present (uncached — the discovery doc has its own TTL cache; this only
// preserves the capability through the decorator).
func (c *ClientStoreCache) Stats(ctx context.Context) (int, string, error) {
	if st, ok := c.inner.(core.ClientStoreStats); ok {
		return st.Stats(ctx)
	}
	return 0, "", core.ErrUnsupportedOperation
}

// ListDueForRotation forwards to the inner store's
// clientrotation.ClientRotationLister extension when present, preserving
// that optional capability through the decorator (uncached — a scheduled
// sweep, not the per-request hot path).
func (c *ClientStoreCache) ListDueForRotation(ctx context.Context, olderThan time.Time) ([]string, error) {
	if l, ok := c.inner.(clientrotation.ClientRotationLister); ok {
		return l.ListDueForRotation(ctx, olderThan)
	}
	return nil, core.ErrUnsupportedOperation
}

// getFresh returns a CLONE of the cached client when a non-expired entry
// exists. The clone means the caller can never mutate the cached snapshot.
func (c *ClientStoreCache) getFresh(clientID string) (*core.Client, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[clientID]
	if !ok {
		return nil, false
	}
	if time.Since(e.expiresAt) > 0 {
		return nil, false
	}
	return cloneClient(e.client), true
}

// store caches a CLONE of cl under clientID with a fresh TTL deadline.
// Cloning on store (in addition to on read) means a later mutation of the
// pointer the inner store returned can't retroactively change the cached
// snapshot.
func (c *ClientStoreCache) store(clientID string, cl *core.Client) {
	clone := cloneClient(cl)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[clientID] = clientCacheEntry{
		client:    clone,
		expiresAt: time.Now().Add(c.ttl),
	}
}

// Evict drops the cached entry for clientID. Idempotent.
func (c *ClientStoreCache) Evict(clientID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, clientID)
}

// EvictAll drops every cached entry so the next Get per client re-reads the
// authoritative store. Exists for the invalidation-bus recovery re-seed: a
// KindClientChange event lost during a bus outage names a client we can no
// longer identify, so the only safe convergence is to flush the whole cache.
func (c *ClientStoreCache) EvictAll() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]clientCacheEntry)
}

func (c *ClientStoreCache) report(outcome string) {
	if c.onOutcome != nil {
		c.onOutcome(outcome)
	}
}

// cloneClient deep-copies a *core.Client so the cache never shares a
// mutable pointer (or a mutable slice/map backing array) across callers
// or with the inner store. A shallow struct copy duplicates the scalar
// fields; every reference-typed field (slices, the JWKS slice, the
// Attributes map) is copied explicitly so a caller appending to (or
// editing) a returned slice/map can't corrupt the cached snapshot.
//
// Adding a new reference-typed field to core.Client REQUIRES extending
// this function; scalar additions are covered by the struct copy.
func cloneClient(in *core.Client) *core.Client {
	if in == nil {
		return nil
	}
	out := *in // copies every scalar field by value
	out.RedirectURIs = cloneStrings(in.RedirectURIs)
	out.AllowedScopes = cloneStrings(in.AllowedScopes)
	out.AllowedAuthenticators = cloneStrings(in.AllowedAuthenticators)
	out.AllowedResources = cloneStrings(in.AllowedResources)
	out.PostLogoutRedirectURIs = cloneStrings(in.PostLogoutRedirectURIs)
	out.AllowedAuthorizationDetailsTypes = cloneStrings(in.AllowedAuthorizationDetailsTypes)
	out.AllowedPKCEMethods = cloneStrings(in.AllowedPKCEMethods)
	out.AllowedRequestURIs = cloneStrings(in.AllowedRequestURIs)
	if in.JWKS != nil {
		out.JWKS = make([]core.JWK, len(in.JWKS))
		copy(out.JWKS, in.JWKS)
	}
	if in.Attributes != nil {
		attrs := make(map[string]string, len(in.Attributes))
		for k, v := range in.Attributes {
			attrs[k] = v
		}
		out.Attributes = attrs
	}
	return &out
}

// cloneStrings returns a copy of s, preserving nil vs empty-slice so a
// round-tripped client compares equal to the original (append on a nil
// destination with zero elements would collapse an empty slice to nil, so
// allocate explicitly).
func cloneStrings(s []string) []string {
	if s == nil {
		return nil
	}
	out := make([]string, len(s))
	copy(out, s)
	return out
}
