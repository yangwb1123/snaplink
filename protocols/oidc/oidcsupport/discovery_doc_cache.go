package oidcsupport

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// DefaultDocCacheTTL bounds how long a rendered discovery document
// may serve from cache. Same scale as the snapshot cache (which
// feeds the dynamic fields below). Set <= 0 via the SDK option to
// disable body caching while keeping snapshot caching in place —
// useful when an upstream CDN already caches and operators want
// every origin hit to be fresh.
const DefaultDocCacheTTL = 5 * time.Second

// DocEntry is the cached, pre-marshaled discovery document for a
// given base URL. Body + ETag are computed together so the HTTP
// layer just writes both. Fields are exported so the SSO package can
// build them via the BuildDocEntry constructor; callers MUST treat
// each entry as immutable after publication.
type DocEntry struct {
	Body      []byte
	ETag      string
	ExpiresAt time.Time
}

// Fresh reports whether the cached entry is still within its TTL.
// nil-safe (returns false).
func (e *DocEntry) Fresh() bool {
	return e != nil && time.Now().Before(e.ExpiresAt)
}

// BuildDocEntry computes the strong ETag (sha256 prefix) and the
// expiry. Pure function so it's safe to call without a cache lock
// held.
func BuildDocEntry(body []byte, ttl time.Duration) *DocEntry {
	sum := sha256.Sum256(body)
	return &DocEntry{
		Body:      body,
		ETag:      `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`,
		ExpiresAt: time.Now().Add(ttl),
	}
}

// WriteDoc emits the cached document with Cache-Control + ETag
// headers and honors If-None-Match → 304. cacheTTL controls the
// max-age advertised to downstream caches; a value < 1s is clamped
// to 1s so the Cache-Control header always carries a positive ceiling.
func WriteDoc(ctx core.HandlerContext, entry *DocEntry, cacheTTL time.Duration) {
	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
	maxAge := int(cacheTTL.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("ETag", entry.ETag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == entry.ETag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(entry.Body)
}
