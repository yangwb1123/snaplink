package sso

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"
)

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

