// Package rs is the resource-server (RS) side of the SSO SDK: everything a
// microservice consuming this server's access tokens needs to validate them
// and make authorization decisions, without re-implementing the security
// gates the authorization server already enforces.
//
// Two validation modes:
//
//   - Local (stateless): ValidateToken verifies the JWT signature against the
//     cached JWKS — the AS is NOT on the per-request path and may even be
//     offline.
//   - Remote (introspection): ValidateTokenWithIntrospect asks the AS's RFC
//     7662 endpoint, so revocation is visible immediately at the cost of a
//     round-trip per call.
//
// ValidateTokenWithDPoP adds the RFC 9449 §7.1 resource-server checks for
// sender-constrained (cnf.jkt-bound) tokens on top of either mode.
//
// Region governance: Config.AllowedServingRegions optionally constrains a
// deployment to tokens minted by specific serving regions — the AS's
// `serving_region` claim (a SnapLink extension), echoed by introspection.
// The gate is opt-in (empty config skips it entirely) and FAIL-CLOSED when
// configured: a token without the claim is rejected, because a
// region-pinned deployment cannot accept unverifiable mint provenance. It
// is a governance denial — mapped to 403 region_not_allowed without a
// bearer challenge by the middleware — not a token-validity failure. See
// the Config field doc for the load-bearing rollout order.
//
// The package deliberately depends only on net/http plus the repo's shared
// verification kernel — no gRPC, no metrics, no framework adapters — so
// pulling it into a consumer stays cheap.
package rs

import (
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ssoclient/remote"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

// Wire constants used by the RS-side validation surface.
const (
	// RFC 9068 §2.1 access-token JOSE typ values. Both the short and the
	// full media-type spelling are accepted (RFC 7515 §4.1.9 lets emitters
	// omit the "application/" prefix); everything else — id tokens (JWT),
	// logout tokens (logout+jwt), SETs (secevent+jwt) — is a misrouted
	// token and is rejected BEFORE any signature work.
	accessTokenTyp     = "at+jwt"
	accessTokenTypFull = "application/at+jwt"

	// RFC 9449 §4.1 DPoP proof JOSE typ.
	dpopProofTyp = "dpop+jwt"

	headerAuthorization   = "Authorization"
	headerDPoP            = "DPoP"
	headerWWWAuthenticate = "WWW-Authenticate"
	headerCacheControl    = "Cache-Control"
	headerPragma          = "Pragma"
	headerContentType     = "Content-Type"
	headerAccept          = "Accept"

	schemeBearer = "Bearer"
	schemeDPoP   = "DPoP"

	contentTypeForm = "application/x-www-form-urlencoded"
	contentTypeJSON = "application/json"
)

// DefaultMaxClockSkew tolerates the wall-clock drift ordinarily seen between
// independently NTP-synced hosts when comparing exp/nbf/iat.
const DefaultMaxClockSkew = 30 * time.Second

// ClientCreds are the RS's own client credentials for the introspection
// endpoint (RFC 7662 requires the caller to authenticate — an open
// introspection endpoint would be a token-validity oracle).
type ClientCreds struct {
	ID     string
	Secret string
}

// Config carries everything the validation functions need. The zero value of
// every optional field selects a safe default; only Issuer (and a key source:
// JWKSCache for local mode, IntrospectURL for remote mode) must be set.
type Config struct {
	// Issuer is REQUIRED: the expected `iss` claim, matched exactly.
	Issuer string

	// JWKSCache supplies verification keys for local validation. Callers own
	// its lifecycle (share one cache across all consumers of the same AS).
	JWKSCache *JWKSCache

	// AllowedAlgs is the JWS alg allowlist, checked BEFORE any signature
	// verification. Empty selects the shared asymmetric set
	// (security.AsymmetricJWSAlgs) — never `none`, never symmetric HS*.
	AllowedAlgs []string

	// ExpectedAud, when set, requires the token's `aud` to contain it.
	ExpectedAud string

	// AllowedServingRegions, when non-empty, requires the token's
	// `serving_region` claim to be present and in this set — a token
	// without the claim is REJECTED (fail-closed): an operator who
	// declares a region-constrained deployment cannot accept unverifiable
	// mint provenance. Enforced in BOTH validation modes (local JWT and
	// introspection) and mapped to 403 region_not_allowed by the
	// middleware. Empty (the default) skips the gate entirely —
	// byte-identical to pre-region builds. Rollout order is load-bearing:
	// enable this only AFTER the AS fleet mints/echoes the claim (an older
	// AS that omits it from introspection responses denies every token).
	// Expressed as "this deployment only serves tokens minted by these
	// regions" — complements, does not replace, the AS's own residency
	// gates (the RS cannot observe the caller's region, only the token's
	// provenance). Refresh rotation re-stamps the claim with the region
	// that SERVED the rotation (mint-time semantics) — a rotated token may
	// carry a new region.
	AllowedServingRegions []string

	// DPoPVerifier tunes RFC 9449 proof checking; nil uses a process-wide
	// default (one shared jti replay cache — see DPoPVerifier).
	DPoPVerifier *DPoPVerifier

	// TrustedProxies gates DPoP htu reconstruction on the direct peer and
	// canonicalizes X-Forwarded-* once. Build it with
	// middleware.NewTrustedProxies. Nil preserves legacy first-hop trust.
	TrustedProxies *middleware.TrustedProxies

	// MaxClockSkew bounds exp/nbf/iat comparison drift; <=0 selects
	// DefaultMaxClockSkew.
	MaxClockSkew time.Duration

	// IntrospectURL enables remote (RFC 7662) validation instead of local
	// signature verification.
	IntrospectURL string

	// IntrospectCreds authenticates the RS to the introspection endpoint via
	// HTTP Basic.
	IntrospectCreds *ClientCreds

	// HTTPClient overrides the transport used for introspection calls.
	HTTPClient *http.Client
}

// skew resolves the effective clock-skew tolerance.
func (c Config) skew() time.Duration {
	if c.MaxClockSkew > 0 {
		return c.MaxClockSkew
	}
	return DefaultMaxClockSkew
}

// allowedAlgSet shapes AllowedAlgs for security.VerifyCompactJWS, which
// independently refuses any symmetric or `none` entry — a misconfigured
// allowlist therefore fails closed rather than opening the
// public-key-as-HMAC confusion attack.
func (c Config) allowedAlgSet() map[string]struct{} {
	if len(c.AllowedAlgs) == 0 {
		return security.AsymmetricJWSAlgs()
	}
	set := make(map[string]struct{}, len(c.AllowedAlgs))
	for _, alg := range c.AllowedAlgs {
		set[alg] = struct{}{}
	}
	return set
}

// allowedAlgValues renders the effective allowlist for the RFC 9449 §7.1
// `algs` challenge parameter.
func (c Config) allowedAlgValues() []string {
	if len(c.AllowedAlgs) == 0 {
		return security.AsymmetricJWSAlgValues()
	}
	return c.AllowedAlgs
}

// JWKSCache is the client-side JWKS cache shared with the remote AuthClient —
// re-exported so RS consumers import only this package. It fetches with
// ETag/If-None-Match revalidation, refreshes in the background on a jittered
// interval, and collapses concurrent miss-triggered fetches via singleflight.
type JWKSCache = remote.JWKSCache

// JWKSOption configures NewJWKSCache (HTTP client, refresh interval, ...).
type JWKSOption = remote.JWKSOption

// NewJWKSCache constructs a JWKS cache for url and starts its background
// refresher; call Close (or StartRefresher with a cancelable context) to stop
// it.
func NewJWKSCache(url string, opts ...JWKSOption) *JWKSCache {
	return remote.NewJWKSCache(url, opts...)
}

// IssuerJWKSURL derives the server's conventional JWKS document URL from its
// issuer base URL.
func IssuerJWKSURL(issuer string) string {
	return strings.TrimRight(issuer, "/") + core.PathJWKS
}
