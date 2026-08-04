package federation

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/shared/core"
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

// RoutesDeps is the union of the federation-surface handler deps plus the
// mount-wiring accessors: the entity handler (presence + sub-feature checks)
// and the B2B connection store (home-realm — kept by interfaces/sso beside
// its body-bearing handler). The peer-health admin route lives in the health
// subpackage (health imports federation, so reaching it from here would be an
// import cycle). *sso.Server satisfies it via accessors.
type RoutesDeps interface {
	Deps
	ResolveDeps
	ListDeps
	TrustMarkStatusDeps
	FetchDeps
	FederationEntity() *EntityHandler
	ConnectionStore() connections.Store
}

// MountRoutes registers the OpenID Federation 1.0 entity surface on r,
// wrapped in a core.GatedRouter so the routes hot-toggle with the federation
// feature gate exactly as they did when registered from interfaces/sso
// (mountFederationEndpoints). Home-realm discovery + protected-resource
// metadata + historical-keys routes stay
// registered by interfaces/sso beside their body-bearing handlers. gate must
// be non-nil — the Server's live federationGateOn method value; nil is a
// programmer error.
func MountRoutes(r core.Router, d RoutesDeps, gate func() bool) {
	if gate == nil {
		panic("federation: MountRoutes requires a non-nil gate")
	}
	gr := core.NewGatedRouter(r, gate)
	if d.FederationEntity() != nil {
		gr.GET(core.PathFederationEntityConfig, func(ctx core.HandlerContext) { HandleEntityConfiguration(d, ctx) })
		if d.FederationEntity().HasSubordinates() {
			gr.GET(core.PathFederationFetch, func(ctx core.HandlerContext) { HandleFederationFetch(d, ctx) })
			gr.GET(core.PathFederationList, func(ctx core.HandlerContext) { HandleFederationList(d, ctx) })
		}
		if d.FederationEntity().Resolver().Enabled() {
			gr.GET(core.PathFederationResolve, func(ctx core.HandlerContext) { HandleFederationResolve(d, ctx) })
		}
	}
	gr.GET(core.PathFederationTrustMarkStatus, func(ctx core.HandlerContext) { HandleTrustMarkStatus(d, ctx) })
}
