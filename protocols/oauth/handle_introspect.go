package oauth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/metering"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/domains/userlifecycle"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/platform/geo"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
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
	// TokenUsageRecorder returns the optional token-usage telemetry
	// recorder. A nil recorder (telemetry disabled) makes every Offer a
	// no-op — introspection behavior is unaffected either way.
	TokenUsageRecorder() *metering.Recorder
	// SessionManager returns the optional session manager for session-aware
	// introspection. When nil, the introspection layer cannot verify session
	// liveness and returns only token-level information (existing behavior).
	SessionManager() core.SessionManager

	// IntrospectionRenewExceeded reports whether the wired token-policy engine's
	// require_renew dimension marks this access token as needing refresh (used
	// past its require_renew fraction of TTL). When true the handler reports the
	// token INACTIVE (governance force-refresh, not a deny). renewAt is the
	// absolute early-warning time (zero when not applicable); surfaced on the
	// still-active response as core.KeyRenewAfter. Default-OFF: a nil
	// token-policy store returns (false, zero), so introspection is byte-
	// identical without a wired policy.
	IntrospectionRenewExceeded(ctx context.Context, clientID string, scopes []string, issuedAt, expiresAt time.Time) (exceeded bool, renewAt time.Time)
	// IntrospectionSigner returns the optional RFC 9701 dedicated signer
	// for JWT-formatted introspection responses (WithIntrospectionSigner /
	// WithIntrospectionSigning). Nil (the default) means every response
	// stays plain JSON regardless of the client's Accept header.
	IntrospectionSigner() IntrospectionSigner
	// IntrospectionBatchMaxSize returns the configured cap on how many
	// tokens one batch /token/introspect request may include, or 0 when the
	// batch capability is disabled (the default) — an inbound `tokens`
	// field is then ignored entirely and single-token behavior is unchanged.
	IntrospectionBatchMaxSize() int
}

// introspectRequest is the bound form/JSON body for /token/introspect.
type introspectRequest struct {
	Token               string `json:"token"`
	TokenTypeHint       string `json:"token_type_hint"` // "access_token" | "refresh_token"
	ClientID            string `json:"client_id"`
	ClientSecret        string `json:"client_secret"`
	ClientAssertion     string `json:"client_assertion"`      // RFC 7521 + 7523
	ClientAssertionType string `json:"client_assertion_type"` // RFC 7521 + 7523
	// Tokens opts into a batch request: introspect every listed token in one
	// call. Honored ONLY when the operator enabled the capability
	// (IntrospectionBatchMaxSize > 0); otherwise ignored entirely, so an
	// unconfigured server's behavior is byte-identical even if a caller
	// happens to send this field.
	Tokens []string `json:"tokens,omitempty"`
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

	// Batch mode (opt-in): an inbound `tokens` array is honored ONLY when
	// the operator enabled the capability; otherwise it's silently ignored
	// and a `token`-less request falls through to the single-token
	// invalid_request below, exactly as it always has.
	if maxBatch := d.IntrospectionBatchMaxSize(); maxBatch > 0 && len(req.Tokens) > 0 {
		serveIntrospectBatch(d, ctx, req.Tokens, req.TokenTypeHint, maxBatch)
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	serveIntrospectWithCache(d, ctx, req.Token, req.TokenTypeHint, req.ClientID)
}

// HandleIntrospect, then the optional RFC 9701 signed-response step. Cache
// is keyed by SHA-256(token) so raw tokens are never stored in plaintext;
// both active and inactive results are cached (see introspectOne). clientID
// is the ALREADY-AUTHENTICATED introspecting client (RFC 9701 §5.1 `aud`
// when the JWT response format is in play).
func serveIntrospectWithCache(d IntrospectDeps, ctx core.HandlerContext, token, hint, clientID string) {
	body := introspectOne(d, ctx, token, hint)
	writeIntrospectionResponse(d, ctx, body, clientID)
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
		if body, ok := introspectRefresh(d, ctx, token); ok {
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
	if body, ok := introspectRefresh(d, ctx, token); ok {
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
	if err != nil || !core.IsAccessTokenClaims(claims) {
		return nil, false
	}
	// Token-policy require_renew (opt-in, default-off): a token used past its
	// require_renew fraction of TTL is reported INACTIVE so the resource server
	// forces a refresh. This is a GOVERNANCE property, not a deny — {active:false}
	// is the oracle-safe RFC 7662 §2.2 signal. Falls through to the inactive
	// response (resolveIntrospection). No-op (never fires) when no policy store
	// is wired, so introspection stays byte-identical. renewAt (when non-zero)
	// is an early warning surfaced below on the still-active response, ahead of
	// this same threshold eventually flipping the token inactive.
	renewExceeded, renewAt := d.IntrospectionRenewExceeded(ctx.Request().Context(), introspectClientID(claims),
		claims.Scopes, claims.IssuedAt, claims.ExpiresAt)
	if renewExceeded {
		return nil, false
	}

	// Session-aware introspection (opt-in): when the token carries an sid claim
	// AND a SessionManager is wired, verify the session is still active. A nil
	// SessionManager skips the check. Oracle-safe: all failures collapse to
	// {active:false}. Fail-open on store errors (logged, treated as active).
	if claims.SID != "" && d.SessionManager() != nil {
		if !introspectSessionActive(d, ctx, claims) {
			return nil, false
		}
	}

	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: dpopTokenTypeOr(core.TokenTypeBearer, claims.ConfirmationJKT),
		core.KeySub:       claims.Subject,
		core.KeyIss:       claims.Issuer,
		core.KeyTokenHint: "access_token",
		core.KeyStrategy:  issuerName,
	}
	if !renewAt.IsZero() {
		body[core.KeyRenewAfter] = renewAt.Unix()
	}
	populateAccessIntrospectionBody(body, claims)
	recordIntrospectionUsage(d, ctx, claims)
	return body, true
}

// introspectClientID resolves the client that "owns" the token for token-policy
// selection: the RFC 9068 client_id claim, falling back to the first audience
// entry (older tokens / non-9068 issuers). Mirrors recordIntrospectionUsage's
// fallback so the renew check and the usage bucket agree on the owning client.
func introspectClientID(claims *core.TokenClaims) string {
	if claims.ClientID != "" {
		return claims.ClientID
	}
	if len(claims.Audience) > 0 {
		return claims.Audience[0]
	}
	return ""
}

// recordIntrospectionUsage, populateIntrospectionSID,
// populateIntrospectionConfirmation, populateAccessIntrospectionBody, and
// introspectSessionActive live in introspect_body.go (this file sits at
// the per-file line budget).

// introspectRefresh queries the optional RefreshTokenInspector.
// Returns (nil, false) when the store doesn't implement the
// inspector extension OR the token is unknown / expired.
func introspectRefresh(d IntrospectDeps, ctx core.HandlerContext, token string) (map[string]any, bool) {
	insp, ok := d.RefreshTokenStore().(RefreshTokenInspector)
	if !ok {
		return nil, false
	}
	info, err := insp.Inspect(ctx.Request().Context(), token)
	if err != nil || info == nil {
		return nil, false
	}
	if !introspectionLifecycleActive(d, ctx.Request().Context(), info.UserID) {
		return nil, false
	}
	body := map[string]any{
		core.KeyActive:    true,
		core.KeyTokenType: dpopTokenTypeOr(core.TokenTypeBearer, info.ConfirmationJKT),
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
	d.TokenUsageRecorder().Offer(metering.Event{
		Kind:       metering.KindRefresh,
		Endpoint:   metering.EndpointIntrospect,
		ClientID:   info.ClientID,
		SubjectID:  info.UserID,
		Thumbprint: metering.Thumbprint(info.JTI),
		GeoCountry: geo.CountryCodeFromContext(ctx),
	})
	return body, true
}

func introspectionLifecycleActive(deps any, ctx context.Context, subject string) bool {
	reader, ok := deps.(interface {
		LifecycleState(context.Context, string) (userlifecycle.State, error)
	})
	if !ok {
		return true
	}
	state, err := reader.LifecycleState(ctx, subject)
	return err == nil && userlifecycle.AllowsAuthentication(state)
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

// dpopTokenTypeOr returns core.TokenTypeNameDPoP when jkt is non-empty
// (the token carries an RFC 9449 §4 DPoP key-binding confirmation),
// else defaultType. Mirrors interfaces/sso's dpopTokenTypeOr used when
// tokens are ISSUED at /token; that copy can't be imported here
// (protocols/oauth sits below interfaces/sso — AGENTS.md §0.2 import
// direction), so introspection — which reports on already-issued
// tokens — keeps its own equivalent. RFC 7662 §2.2 callers (resource
// servers) rely on token_type to decide whether a DPoP proof is
// mandatory on every subsequent request; reporting "Bearer" for a
// sender-constrained token would let them skip that check entirely.
func dpopTokenTypeOr(defaultType, jkt string) string {
	if jkt != "" {
		return core.TokenTypeNameDPoP
	}
	return defaultType
}

// The RFC 9701 (JWT Response for OAuth Token Introspection) machinery
// (IntrospectionSigner, JWKUseIntrospection, IntrospectionKeySet,
// WantsIntrospectionJWT, SignIntrospectionResponse) lives in
// introspect_cache.go (which had room) to keep this file within the
// per-file line budget.
