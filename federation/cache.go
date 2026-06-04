package federation

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/snaplink/sso/core"
)

// buildETag computes the strong ETag for a signed Entity Configuration:
// the quoted base64url of the first 8 bytes of sha256(compact). Identical
// scheme to the discovery doc + JWKS ETags so a federation consumer's
// If-None-Match handling is uniform across the server's cached endpoints.
func buildETag(compact []byte) string {
	sum := sha256.Sum256(compact)
	return `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`
}

// WriteEntityStatement emits a signed Entity Configuration with the
// federation media type, Cache-Control + ETag headers, honoring
// If-None-Match → 304. It mirrors oidc.WriteDoc EXACTLY (same ETag scheme,
// same max-age clamp, same 304 logic) but serves the compact JWS as
// application/entity-statement+jwt instead of a JSON body.
//
// This is PUBLIC metadata (an entity's self-description), not a credential —
// so Cache-Control is `public, max-age=<ttl>` (NOT no-store). A federation
// consumer + intervening CDN may cache it; the short max-age bounds how
// long a key rotation / metadata change takes to propagate. cacheTTL < 1s
// is clamped to 1s so the header always carries a positive ceiling.
func WriteEntityStatement(w http.ResponseWriter, r *http.Request, compact []byte, etag string, cacheTTL time.Duration) {
	w.Header().Set(core.HeaderContentType, ContentTypeEntityStatement)
	maxAge := int(cacheTTL.Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(maxAge))
	w.Header().Set("ETag", etag)
	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(compact)
}
