package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
)

// ClientAssertionTypeJWTBearer is the RFC 7521 §4.2 URN for
// JWT Bearer client assertions. Pulled local so handle_introspect /
// handle_par / handle_revoke can branch on it without importing
// back to root.
const ClientAssertionTypeJWTBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"

// IntrospectDeps is what HandleIntrospect needs. *sso.Server
// satisfies it via accessor methods.
type IntrospectDeps interface {
	ClientStoreAccessor() core.ClientStore
	JTIReplayStore() security.JTIReplayStore
	TokenIssuers() map[string]core.TokenIssuer
	RefreshTokenStore() RefreshTokenStore
	ResolveIssuer(ctx core.HandlerContext) string
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	// IntrospectionCache returns the optional token introspection cache.
	// Returns nil when caching is disabled — every introspection pays the
	// full JWT verification cost.
	IntrospectionCache() IntrospectionCache
	// IntrospectionCacheTTL returns the TTL for cached introspection
	// results. Only meaningful when IntrospectionCache() is non-nil.
	IntrospectionCacheTTL() time.Duration
	// IntrospectionSigner returns the optional RFC 9701 dedicated signer
	// for JWT-formatted introspection responses. nil (the default) means
	// the feature is off — every response is plain RFC 7662 JSON
	// regardless of what the caller's Accept header requests.
	IntrospectionSigner() IntrospectionSigner
}

// introspectRequest is the bound form/JSON body for /token/introspect.
type introspectRequest struct {
	Token               string `json:"token"`
	TokenTypeHint       string `json:"token_type_hint"` // "access_token" | "refresh_token"
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	ClientAssertion     string `json:"client_assertion"`      // RFC 7521 + 7523
	ClientAssertionType string `json:"client_assertion_type"` // RFC 7521 + 7523
}

// HandleIntrospect implements RFC 7662 OAuth 2.0 Token Introspection.
// Returns active state + standard metadata claims for a presented
// access or refresh token. Inactive tokens return {active: false}
// only, with no extra metadata — §2.2 mandates this to limit
// oracle leakage.
//
// When an IntrospectionCache is wired, the handler checks the cache
// (keyed by SHA-256(token)) BEFORE performing full JWT signature
// verification. On a hit the cached response is returned immediately.
// On a miss the normal verification runs and the result is stored for
// the configured TTL (default 60s). This trades immediate revocation
// propagation for dramatic CPU savings in high-traffic microservice
// meshes — see the security considerations on the option doc for the
// deliberate eventual-consistency window.
//
// Auth: the introspecting client authenticates with client_id +
// client_secret (Basic auth or form body). Per §2.1 any registered
// active client may introspect — production deployments that want
// stronger isolation should layer an authorization middleware that
// checks a custom "introspect" scope or role on the client.
func HandleIntrospect(d IntrospectDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	clientStore := d.ClientStoreAccessor()
	if clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req introspectRequest
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		// HTTP Basic auth takes precedence over body fields when
		// present — matches the RFC 6749 §2.3.1 recommendation.
		req.ClientID = id
		req.ClientSecret = secret
	}

	// Client auth: the assertion branch and the secret-creds branch both
	// write the identical 401 invalid_client on failure (oracle-leak
	// collapse). handled==true means a response was already written.
	if handled := authenticateIntrospectClient(d, clientStore, ctx, &req); handled {
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	serveIntrospectWithCache(d, ctx, req.Token, req.TokenTypeHint, req.ClientID)
}

// serveIntrospectWithCache performs the resolution + optional-cache step of
// HandleIntrospect. Cache is keyed by SHA-256(token) so raw tokens are never
// stored in plaintext; both active and inactive results are cached.
// clientID is the ALREADY-AUTHENTICATED introspecting client (RFC 9701 §5.1
// `aud` when the JWT response format is in play).
func serveIntrospectWithCache(d IntrospectDeps, ctx core.HandlerContext, token, hint, clientID string) {
	// OPTIONAL cache check: keyed by SHA-256(token) so the raw token
	// is never stored in plaintext. When the cache is unwired, both
	// d.IntrospectionCache() and the cache itself are nil — every
	// branch falls through to full verification.
	cache := d.IntrospectionCache()
	var cacheKey string
	if cache != nil {
		cacheKey = tokenHash(token)
		if cached, ok := cache.Get(cacheKey); ok {
			writeIntrospectionResponse(d, ctx, cached.Body, clientID)
			return
		}
	}

	if body, ok := resolveIntrospection(d, ctx, token, hint); ok {
		if cache != nil {
			cache.Set(cacheKey, &CachedResult{Body: body}, d.IntrospectionCacheTTL())
		}
		writeIntrospectionResponse(d, ctx, body, clientID)
		return
	}

	// Unknown / expired / revoked → §2.2 mandates {active: false} only.
	inactive := map[string]any{core.KeyActive: false}
	if cache != nil {
		cache.Set(cacheKey, &CachedResult{Body: inactive}, d.IntrospectionCacheTTL())
	}
	writeIntrospectionResponse(d, ctx, inactive, clientID)
}

// writeIntrospectionResponse serves body as plain RFC 7662 JSON, unless the
// introspecting client's Accept header requests the RFC 9701 §5 JWT format
// AND a dedicated IntrospectionSigner is wired — in which case it signs and
// serves application/token-introspection+jwt instead. A client that sends
// the Accept header against a server that hasn't enabled the feature
// silently gets the same plain JSON it always got: content negotiation
// degrades gracefully rather than erroring, so a speculative Accept header
// can never break an existing integration (default-off requirement).
//
// A wired signer that FAILS to sign responds 500 rather than silently
// downgrading to JSON — the caller explicitly asked for an authenticated
// response and a silent format downgrade would defeat that ask exactly
// when the server is unable to honor it.
func writeIntrospectionResponse(d IntrospectDeps, ctx core.HandlerContext, body map[string]any, clientID string) {
	signer := d.IntrospectionSigner()
	if signer == nil || !WantsIntrospectionJWT(ctx.Request().Header.Get("Accept")) {
		ctx.JSON(http.StatusOK, body)
		return
	}
	jwt, err := SignIntrospectionResponse(ctx.Request().Context(), signer, d.ResolveIssuer(ctx), clientID, body)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	w := ctx.ResponseWriter()
	w.Header().Set(core.HeaderContentType, core.ContentTypeTokenIntrospectionJWT)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(jwt))
}

// authenticateIntrospectClient runs the hint-independent client-auth gate
// for /token/introspect. The RFC 7521/7523 JWT-assertion branch and the
// secret-creds branch BOTH emit the identical 401 invalid_client on failure
// — the oracle-leak collapse stays byte-for-byte. A wrong
// client_assertion_type still yields 400 invalid_request. Returns
// handled=true when it has already written the response (caller must return
// immediately); false lets the caller proceed.
func authenticateIntrospectClient(d IntrospectDeps, clientStore core.ClientStore, ctx core.HandlerContext, req *introspectRequest) (handled bool) {
	// RFC 7521/7523 JWT bearer client auth on /token/introspect.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return true
		}
		assertedID, err := d.VerifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			d.ResolveIssuer(ctx),
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return true
		}
		req.ClientID = assertedID
		// Bypass the secret-based authenticate path entirely: JWT
		// assertion stands in for the secret per RFC 7521 §4.2.
		// Still validate the tenant + active gates below via a
		// minimal client lookup so a deactivated client can't
		// introspect.
		c, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil || c == nil || !c.Active || !tenant.ClientOK(ctx, c) {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return true
		}
		return false
	}
	if err := authenticateIntrospectionClient(clientStore, ctx, req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return true
	}
	return false
}

// resolveIntrospection applies the hint-driven try-order and returns the
// first populated body. Resolution order is hint-driven: when the hint is
// "refresh_token" try the refresh store first to avoid an unnecessary
// access-token signature check, but ALWAYS fall back to the other tier so a
// wrong hint doesn't mark a valid token inactive.
func resolveIntrospection(d IntrospectDeps, ctx core.HandlerContext, token, hint string) (map[string]any, bool) {
	if hint == "refresh_token" {
		if body, ok := introspectRefresh(d.RefreshTokenStore(), ctx, token); ok {
			return body, true
		}
		if body, ok := introspectAccess(d, ctx, token); ok {
			return body, true
		}
		return nil, false
	}
	if body, ok := introspectAccess(d, ctx, token); ok {
		return body, true
	}
	if body, ok := introspectRefresh(d.RefreshTokenStore(), ctx, token); ok {
		return body, true
	}
	return nil, false
}

// introspectAccess validates the token as an access token via every
// registered issuer. Returns a populated metadata body on success.
func introspectAccess(d IntrospectDeps, ctx core.HandlerContext, token string) (map[string]any, bool) {
	if len(d.TokenIssuers()) == 0 {
		return nil, false
	}
	claims, issuerName, err := d.ValidateAnyToken(ctx.Request().Context(), token)
	if err != nil || claims == nil {
		return nil, false
	}
	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: core.TokenTypeBearer,
		core.KeySub:       claims.Subject,
		core.KeyIss:       claims.Issuer,
		core.KeyTokenHint: "access_token",
		core.KeyStrategy:  issuerName,
	}
	populateAccessIntrospectionBody(body, claims)
	return body, true
}

// populateAccessIntrospectionBody copies the optional RFC 7662 / RFC 9068
// claims onto an already-active access-token body. Purely additive: it
// carries NO early-return / auth-gate semantics — the ValidateAnyToken auth
// gate stays in introspectAccess.
func populateAccessIntrospectionBody(body map[string]any, claims *core.TokenClaims) {
	if !claims.ExpiresAt.IsZero() {
		body[core.KeyExp] = claims.ExpiresAt.Unix()
	}
	if !claims.IssuedAt.IsZero() {
		body[core.KeyIat] = claims.IssuedAt.Unix()
	}
	if !claims.NotBefore.IsZero() {
		body[core.KeyNbf] = claims.NotBefore.Unix()
	}
	if len(claims.Audience) > 0 {
		body[core.KeyAud] = claims.Audience
	}
	// RFC 9068 §2.2 supplies a first-class `client_id` claim. Prefer
	// it; fall back to the first audience entry for older tokens or
	// non-RFC-9068 issuers (per RFC 7662 §2.2 the field is optional).
	switch {
	case claims.ClientID != "":
		body[core.KeyClientID] = claims.ClientID
	case len(claims.Audience) > 0:
		body[core.KeyClientID] = claims.Audience[0]
	}
	if len(claims.Scopes) > 0 {
		body[core.KeyScope] = strings.Join(claims.Scopes, " ")
	}
	// RFC 9068 §2.2 jti — useful for replay tracking on the
	// introspecting resource server. Same goes for auth_time / acr
	// / amr which let downstream policy reason about how the user
	// authenticated.
	if claims.JTI != "" {
		body[core.KeyJTI] = claims.JTI
	}
	if !claims.AuthTime.IsZero() {
		body[core.KeyAuthTime] = claims.AuthTime.Unix()
	}
	if claims.ACR != "" {
		body[core.KeyACR] = claims.ACR
	}
	if len(claims.AMR) > 0 {
		body[core.KeyAMR] = claims.AMR
	}
	// RFC 7662 §2.2: echo the sender-constraint confirmation so an
	// introspection-based resource server can enforce RFC 8705 §3.3 (mTLS) /
	// RFC 9449 §7 (DPoP) binding. A token carries at most one PoP mechanism.
	if claims.ConfirmationX5TS256 != "" {
		body[core.KeyCnf] = map[string]any{core.KeyCnfX5TS256: claims.ConfirmationX5TS256}
	} else if claims.ConfirmationJKT != "" {
		body[core.KeyCnf] = map[string]any{core.KeyCnfJKT: claims.ConfirmationJKT}
	}
}

// introspectRefresh queries the optional RefreshTokenInspector.
// Returns (nil, false) when the store doesn't implement the
// inspector extension OR the token is unknown / expired.
func introspectRefresh(store RefreshTokenStore, ctx core.HandlerContext, token string) (map[string]any, bool) {
	insp, ok := store.(RefreshTokenInspector)
	if !ok {
		return nil, false
	}
	info, err := insp.Inspect(ctx.Request().Context(), token)
	if err != nil || info == nil {
		return nil, false
	}
	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: core.TokenTypeBearer,
		core.KeySub:       info.UserID,
		core.KeyClientID:  info.ClientID,
		core.KeyTokenHint: "refresh_token",
	}
	if !info.ExpiresAt.IsZero() {
		body[core.KeyExp] = info.ExpiresAt.Unix()
	}
	if !info.IssuedAt.IsZero() {
		body[core.KeyIat] = info.IssuedAt.Unix()
	}
	if len(info.Scopes) > 0 {
		body[core.KeyScope] = strings.Join(info.Scopes, " ")
	}
	return body, true
}

// authenticateIntrospectionClient verifies the introspecting client's
// credentials via the existing client store. Returns nil on success.
func authenticateIntrospectionClient(clientStore core.ClientStore, ctx core.HandlerContext, id, secret string) error {
	if id == "" || secret == "" {
		return errors.New("missing client credentials")
	}
	client, err := clientStore.Get(ctx.Request().Context(), id)
	if err != nil {
		return err
	}
	if !client.Active {
		return errors.New("inactive client")
	}
	if !tenant.ClientOK(ctx, client) {
		return errors.New("tenant mismatch")
	}
	return clientStore.ValidateSecret(ctx.Request().Context(), id, secret)
}

// tokenHash returns the hex-encoded SHA-256 digest of token. The hash
// (not the raw token) is the cache key so that plaintext tokens are
// never stored in the cache — an attacker who dumps the cache sees only
// opaque digests, not bearer credentials.
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

// --- RFC 9701 (JWT Response for OAuth Token Introspection) -----------------
//
// Kept in this file rather than a separate one: protocols/oauth is already
// at its frozen directory_fanout_test.go file-count ceiling (AGENTS.md
// §0.1 "Go files per dir ≤ 10" — this dir is a grandfathered exemption
// that may only shrink), so new introspection-only surface area is added
// here rather than growing the file count further.

// IntrospectionSigner is the seam RFC 9701 (JWT Response for OAuth Token
// Introspection) uses to sign the /token/introspect response. Structurally
// close to oidc.MetadataSigner/oidc.JARMSigner (SignMetadata), but kept as
// its OWN interface (own method name) so a general-purpose issuer type
// (Ed25519/ECDSA/RSA*JWTIssuer) can implement both roles as two distinct
// methods — the introspection method stamps the RFC 9701 §5.1 `typ`
// ("token-introspection+jwt") instead of the generic "JWT" typ JARM/
// metadata use, which is the RFC's defense against a resource server
// mistaking this response for a bearer access token.
//
// AGENTS.md requires this to be a DEDICATED key, never the issuer that
// mints access/ID tokens — wire a SEPARATE issuer instance via
// sso.WithIntrospectionSigning, mirroring the per-tenant-issuer pattern
// (WithTenantTokenIssuer) of an independently keyed + independently
// rotated named signer role rather than overloading the primary one.
type IntrospectionSigner interface {
	SignIntrospectionJWT(ctx context.Context, claims map[string]any) (string, error)
}

// JWKUseIntrospection is the "use" value stamped on the dedicated
// introspection signer's published JWK(s), distinguishing them in the
// aggregated /.well-known/jwks.json from the "sig" (access/ID token) and
// "enc" (JAR/response JWE) entries so a resource server can locate the
// right verification key without an out-of-band channel.
const JWKUseIntrospection = "introspection"

// IntrospectionKeySet decorates a core.JWKSProvider — typically the SAME
// dedicated issuer instance passed to sso.WithIntrospectionSigning — so
// its published JWKS entries carry "use": JWKUseIntrospection instead of
// the generic "sig" the general-purpose issuer types normally stamp. This
// keeps Ed25519/ECDSA/RSA*JWTIssuer free of a narrow, single-feature "use"
// value while still publishing the dedicated key through the existing
// JWKS aggregation path (see oidc.JWKSDeps.IntrospectionSigningKeys).
type IntrospectionKeySet struct {
	core.JWKSProvider
}

// NewIntrospectionKeySet wraps p. Returns nil when p is nil so callers can
// chain a possibly-absent signer's type assertion straight through without
// a separate nil check (a nil *IntrospectionKeySet stored in a non-nil
// interface would otherwise be a classic Go footgun).
func NewIntrospectionKeySet(p core.JWKSProvider) *IntrospectionKeySet {
	if p == nil {
		return nil
	}
	return &IntrospectionKeySet{JWKSProvider: p}
}

// JWKS re-publishes the wrapped provider's keys with Use overridden to
// JWKUseIntrospection. Every other field (kty/kid/alg/x/y/n/e) is passed
// through unchanged — only the usage tag differs.
func (k *IntrospectionKeySet) JWKS(ctx context.Context) ([]core.JWK, error) {
	keys, err := k.JWKSProvider.JWKS(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]core.JWK, len(keys))
	for i, jwk := range keys {
		jwk.Use = JWKUseIntrospection
		out[i] = jwk
	}
	return out, nil
}

// WantsIntrospectionJWT reports whether the request's Accept header asks
// for the RFC 9701 §5 JWT-formatted introspection response
// (core.ContentTypeTokenIntrospectionJWT). Matches like the existing
// acceptsHTML/acceptsJSON content-negotiation helpers elsewhere in this
// codebase — a raw substring check rather than full RFC 9110 media-range
// parsing (q-values, wildcards), which is more precision than a single
// exact media type warrants.
func WantsIntrospectionJWT(accept string) bool {
	return strings.Contains(accept, core.ContentTypeTokenIntrospectionJWT)
}

// SignIntrospectionResponse signs body (the already-computed RFC 7662
// introspection map — active:false or the populated active:true shape)
// into the RFC 9701 JWT wrapper. Per §5.1: iss identifies this AS, aud
// identifies the introspecting client (the resource server that will
// consume the response), iat is the signing moment. sub/exp are
// deliberately NEVER set at the top level (§8 substitution-attack
// defense) — the entire introspection payload, including any exp/sub it
// carries, lives ONLY inside the nested core.KeyTokenIntrospection claim.
func SignIntrospectionResponse(ctx context.Context, signer IntrospectionSigner, issuer, clientID string, body map[string]any) (string, error) {
	claims := map[string]any{
		core.KeyIss:                issuer,
		core.KeyAud:                clientID,
		core.KeyIat:                time.Now().Unix(),
		core.KeyTokenIntrospection: body,
	}
	return signer.SignIntrospectionJWT(ctx, claims)
}
