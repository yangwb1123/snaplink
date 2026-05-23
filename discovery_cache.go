package sso

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"sort"
	"strconv"
	"time"
)

// defaultDiscoveryCacheTTL is the freshness window for client-store-
// derived discovery fields. 5 seconds is short enough that DCR /
// admin client edits visibly propagate (humans typically wait > 5s
// before refreshing the discovery doc) and long enough that a busy
// RP polling /.well-known/openid-configuration N times per second
// doesn't pay 5× ClientStore.List per request. When 0, the cache is
// disabled entirely (legacy behavior).
const defaultDiscoveryCacheTTL = 5 * time.Second

// clientDiscoverySnapshot memoizes the discovery-doc fields that
// derive from iterating the entire client store. Computing them
// requires one ClientStore.List + a pass per derivation; without
// caching, every /.well-known/openid-configuration hit pays 5×
// List + 5× iteration. With caching, the cost amortizes across the
// TTL window.
//
// IMPORTANT: every field here MUST be safe to read concurrently
// after the snapshot is published via atomic.Pointer. We copy slices
// at compute-time so downstream readers can't mutate the snapshot
// in place.
type clientDiscoverySnapshot struct {
	requirePAR                 bool
	requireSignedRequestObject bool
	frontchannelLogout         bool
	scopes                     []string
	authorizationDetailTypes   []string
	expiresAt                  time.Time
}

// WithDiscoveryCacheTTL overrides the freshness window for the
// client-store-derived discovery fields. Pass 0 to disable the
// cache (every request re-iterates the client store — useful when
// running in a hot-reload dev loop where DCR edits must reflect
// instantly). Defaults to defaultDiscoveryCacheTTL.
func WithDiscoveryCacheTTL(d time.Duration) Option {
	return func(s *Server) { s.discoveryCacheTTL = d }
}

// discoverySnapshot returns the current client-store-derived snapshot,
// refreshing it via single-flight when stale or absent. Safe for
// concurrent use. When the client store is unavailable or returns
// an error, the snapshot has empty/false fields (the legacy
// "degraded discovery" behavior) — discovery MUST keep serving even
// when the store is sick.
func (s *Server) discoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	ttl := s.discoveryCacheTTL
	if ttl == 0 {
		// Caching disabled — compute every time. The single-flight
		// path is bypassed so dev-loop hot-reload sees DCR edits
		// instantly.
		return s.computeDiscoverySnapshot(ctx)
	}
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	s.discoveryCacheMu.Lock()
	defer s.discoveryCacheMu.Unlock()
	// Re-check after acquiring the lock — a peer may have refreshed
	// while we waited. Standard double-checked-locking pattern.
	if snap := s.discoveryCache.Load(); snap != nil && time.Now().Before(snap.expiresAt) {
		return snap
	}
	snap := s.computeDiscoverySnapshot(ctx)
	s.discoveryCache.Store(snap)
	return snap
}

// computeDiscoverySnapshot does the expensive client-store iteration
// once and projects all four derived fields. Splitting compute from
// the cache wrapper lets tests assert the projection directly
// without poking the cache.
func (s *Server) computeDiscoverySnapshot(ctx context.Context) *clientDiscoverySnapshot {
	snap := &clientDiscoverySnapshot{expiresAt: time.Now().Add(s.discoveryCacheTTL)}
	if s.idTokenIssuer != nil {
		snap.scopes = []string{ScopeOpenID}
	}
	if s.clientStore == nil {
		return snap
	}
	clients, err := s.clientStore.List(ctx)
	if err != nil {
		return snap
	}
	scopesSeen := map[string]struct{}{}
	if s.idTokenIssuer != nil {
		scopesSeen[ScopeOpenID] = struct{}{}
	}
	adTypesSeen := map[string]struct{}{}
	allRequireSignedRequestObject := len(clients) > 0
	for _, c := range clients {
		if c == nil {
			allRequireSignedRequestObject = false
			continue
		}
		if c.RequirePAR {
			snap.requirePAR = true
		}
		if !c.RequireSignedRequestObject {
			allRequireSignedRequestObject = false
		}
		if c.FrontchannelLogoutURI != "" {
			snap.frontchannelLogout = true
		}
		for _, sc := range c.AllowedScopes {
			if sc != "" {
				scopesSeen[sc] = struct{}{}
			}
		}
		for _, t := range c.AllowedAuthorizationDetailsTypes {
			if t != "" {
				adTypesSeen[t] = struct{}{}
			}
		}
	}
	snap.requireSignedRequestObject = allRequireSignedRequestObject
	snap.scopes = sortedKeys(scopesSeen)
	if len(adTypesSeen) > 0 {
		snap.authorizationDetailTypes = sortedKeys(adTypesSeen)
	}
	return snap
}

func sortedKeys(m map[string]struct{}) []string {
	if len(m) == 0 {
		return nil
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// DefaultDiscoveryDocCacheTTL bounds how long a rendered discovery
// document may serve from cache. Same scale as the snapshot cache
// (which feeds the dynamic fields below). Set <= 0 via
// [WithDiscoveryDocCacheTTL] to disable body caching while keeping
// snapshot caching in place — useful when an upstream CDN already
// caches and operators want every origin hit to be fresh.
const DefaultDiscoveryDocCacheTTL = 5 * time.Second

// discoveryDocEntry is the cached, pre-marshaled discovery document
// for a given base URL. body + etag are computed together so the
// HTTP layer just writes both.
type discoveryDocEntry struct {
	body      []byte
	etag      string
	expiresAt time.Time
}

func (e *discoveryDocEntry) fresh() bool {
	return e != nil && time.Now().Before(e.expiresAt)
}

// buildDiscoveryDocEntry computes the strong ETag (sha256 prefix) and
// the expiry. Pure function so it's safe to call without the cache
// lock held.
func buildDiscoveryDocEntry(body []byte, ttl time.Duration) *discoveryDocEntry {
	sum := sha256.Sum256(body)
	return &discoveryDocEntry{
		body:      body,
		etag:      `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`,
		expiresAt: time.Now().Add(ttl),
	}
}

// lookupDiscoveryDocCache returns a fresh cached entry for base, or
// nil to signal "render fresh". The sync.Map keeps reads lock-free
// in the hot path.
func (s *Server) lookupDiscoveryDocCache(base string) *discoveryDocEntry {
	v, ok := s.discoveryDocCache.Load(base)
	if !ok {
		return nil
	}
	entry, _ := v.(*discoveryDocEntry)
	if entry.fresh() {
		return entry
	}
	// Stale — drop so the next caller re-renders.
	s.discoveryDocCache.Delete(base)
	return nil
}

func (s *Server) storeDiscoveryDocCache(base string, entry *discoveryDocEntry) {
	s.discoveryDocCache.Store(base, entry)
}

// writeDiscoveryDoc emits the cached document with Cache-Control +
// ETag headers and honors If-None-Match → 304.
func (s *Server) writeDiscoveryDoc(ctx HandlerContext, entry *discoveryDocEntry) {
	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(HeaderContentType, ContentTypeJSON)
	maxAge := int(s.discoveryDocCacheTTL.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("ETag", entry.etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == entry.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.body)
}

// WithDiscoveryDocCacheTTL configures how long a rendered discovery
// document body may serve from cache. ttl <= 0 disables body caching
// (snapshot caching via [WithDiscoveryCacheTTL] continues independently).
// Default is [DefaultDiscoveryDocCacheTTL].
func WithDiscoveryDocCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.discoveryDocCacheTTL = ttl }
}
