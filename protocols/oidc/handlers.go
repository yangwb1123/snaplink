package oidc

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// HandleCheckSessionIframe implements the OpenID Connect Session Management
// 1.0 §2 check_session_iframe endpoint. It takes no Deps: the page is
// static, and the login-state comparison happens entirely client-side (the
// postMessage protocol embedded in RenderCheckSessionIframe), keyed off the
// CheckSessionCookieName cookie stamped at /auth/login and cleared at
// /end_session.
func HandleCheckSessionIframe(ctx core.HandlerContext) {
	RenderCheckSessionIframe(ctx)
}

// JWKSDeps is what the /jwks.json handler needs. *sso.Server satisfies
// it via the accessor methods on sso.Server.
type JWKSDeps interface {
	TokenIssuers() map[string]core.TokenIssuer
	JARDecrypter() security.JWEDecrypter // returns the wired JWE decrypter (or nil)
	// IntrospectionSigningKeys returns the optional RFC 9701 dedicated
	// introspection signer's public key set (already tagged
	// "use": "introspection"), or nil when unset.
	IntrospectionSigningKeys() core.JWKSProvider
	SrvLogger() spi.Logger
	JWKSCacheMaxAge() time.Duration
	// ComputeJWKSDocument runs the marshaling closure behind a
	// single-flight so concurrent polls share one computation.
	ComputeJWKSDocument(compute func() ([]byte, error)) ([]byte, error)
	// CachedJWKSETag returns the cached JWKS document's ETag without
	// recomputing the body. Returns empty string when the cache is
	// empty or stale — caller falls back to sha256(body).
	CachedJWKSETag() string
}

// HandleJWKS implements GET /.well-known/jwks.json — aggregates JWKs
// from every registered TokenIssuer that satisfies core.JWKSProvider,
// plus the JWE decrypter when it also publishes its enc key. Stamps a
// strong ETag for poll efficiency.
func HandleJWKS(d JWKSDeps, ctx core.HandlerContext) {
	// Behind a single-flight: concurrent polls share one issuer-walk +
	// marshal. The closure derives the doc solely from the issuer key
	// set (identical for every caller), so collapsing is safe.
	body, err := d.ComputeJWKSDocument(func() ([]byte, error) {
		return marshalJWKSDocument(d, ctx)
	})
	if err != nil {
		d.SrvLogger().Error("jwks marshal failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}
	etagHint := d.CachedJWKSETag()
	writeJWKSResponse(d, ctx, body, etagHint)
}

// marshalJWKSDocument walks every registered issuer (and the JAR JWE
// decrypter) and marshals the aggregated key set. It runs inside the
// single-flight closure, so it MUST derive the doc solely from the issuer
// key set — identical for every caller — to keep collapsing safe. ctx is
// passed in (never captured) so the request-scoped context is current.
func marshalJWKSDocument(d JWKSDeps, ctx core.HandlerContext) ([]byte, error) {
	keys := make([]core.JWK, 0)
	for _, ti := range d.TokenIssuers() {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		ks, err := jp.JWKS(ctx.Request().Context())
		if err != nil {
			d.SrvLogger().Error("jwks provider failed", "error", err)
			continue
		}
		keys = append(keys, ks...)
	}
	// JAR JWE decrypter typically also implements JWKSProvider so its
	// public encryption key (use: "enc") publishes alongside the
	// issuer signing keys (use: "sig"). A single JWKS doc covers both
	// roles; RPs branch on `use` to know which key to encrypt to vs
	// verify with.
	if dec := d.JARDecrypter(); dec != nil {
		if jp, ok := dec.(core.JWKSProvider); ok {
			ks, err := jp.JWKS(ctx.Request().Context())
			if err != nil {
				d.SrvLogger().Error("jwks decrypter failed", "error", err)
			} else {
				keys = append(keys, ks...)
			}
		}
	}
	// RFC 9701 dedicated introspection signer, tagged "use": "introspection"
	// (IntrospectionSigningKeys already wraps it — see
	// oauth.IntrospectionKeySet) so a resource server can pick the right
	// key without an out-of-band channel. nil = feature unwired.
	if ik := d.IntrospectionSigningKeys(); ik != nil {
		ks, err := ik.JWKS(ctx.Request().Context())
		if err != nil {
			d.SrvLogger().Error("jwks introspection signer failed", "error", err)
		} else {
			keys = append(keys, ks...)
		}
	}
	return json.Marshal(map[string]any{"keys": keys})
}

// writeJWKSResponse stamps the strong ETag + cache headers and honors a
// matching If-None-Match with a 304 short-circuit.
//
// etagHint is the cached ETag from CachedJWKSETag. When non-empty it
// is used directly (skipping the SHA-256 computation); when empty the
// ETag is computed from body (backward compat).
func writeJWKSResponse(d JWKSDeps, ctx core.HandlerContext, body []byte, etagHint string) {
	// ETag = strong validator. RP libraries can send If-None-Match on
	// poll-style fetches to short-circuit when keys haven't rotated.
	var etag string
	if etagHint != "" {
		etag = etagHint
	} else {
		sum := sha256.Sum256(body)
		etag = `"` + base64.RawURLEncoding.EncodeToString(sum[:8]) + `"`
	}

	w := ctx.ResponseWriter()
	r := ctx.Request()
	w.Header().Set(core.HeaderContentType, core.ContentTypeJSON)
	maxAge := d.JWKSCacheMaxAge()
	if maxAge <= 0 {
		maxAge = core.DefaultJWKSCacheMaxAge
	}
	w.Header().Set("Cache-Control", "public, max-age="+strconv.Itoa(int(maxAge.Seconds())))
	w.Header().Set("ETag", etag)

	if match := r.Header.Get("If-None-Match"); match != "" && match == etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
