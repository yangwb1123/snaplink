package oauth

import (
	"context"
	"errors"
	"net/http"

	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// RevokeDeps is what HandleRevoke + HandleRevokeAll need. *sso.Server
// satisfies it via accessor methods.
type RevokeDeps interface {
	ClientStoreAccessor() core.ClientStore
	JTIReplayStore() security.JTIReplayStore
	TokenIssuers() map[string]core.TokenIssuer
	RefreshTokenStore() RefreshTokenStore
	ResolveIssuer(ctx core.HandlerContext) string
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	ValidateAnyTokenForRevocation(ctx context.Context, token string) (*core.TokenClaims, string, error)
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	AuthenticateClientCreds(ctx core.HandlerContext, id, secret string) error
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	RevokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string)
	AuditPartialRevokeFailure(ctx core.HandlerContext, revoked, failed []string)
	SetBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDesc string)
	SrvLogger() spi.Logger

	// TrustedDeviceStore returns the "remember this device" MFA-skip store
	// (nil when unwired). HandleRevokeAll uses it to cascade "logout
	// everywhere" into every standing trusted-device grant for the caller —
	// see revokeTrustedDevicesOnRevokeAll.
	TrustedDeviceStore() core.TrustedDeviceStore

	// IntrospectionCache returns the optional token introspection cache so
	// HandleRevoke can evict the just-revoked token's cached result
	// immediately (best-effort — see InvalidateIntrospectionCache). Nil
	// disables both the cache and this eviction, byte-identical to a build
	// without caching.
	IntrospectionCache() IntrospectionCache
	// RequireFormContentType reports whether the strict credential wire is
	// enabled (B4-4, server.require_form_content_type): /token/revoke then
	// accepts ONLY application/x-www-form-urlencoded and answers 415 for a
	// JSON body, a missing Content-Type, or any other media type, before
	// the body is read. False (the default) keeps the dual-mode binder
	// byte-identical to a build without the feature.
	RequireFormContentType() bool
}

// revokeRequest is the parsed body/form for HandleRevoke (RFC 7009),
// including the RFC 7521/7523 JWT client-assertion fields.
type revokeRequest struct {
	Token                string `json:"token"`
	TokenTypeHint        string `json:"token_type_hint"`
	ClientID             string `json:"client_id"`
	ClientSecret         string `json:"client_secret"`
	ClientAssertion      string `json:"client_assertion"`      // RFC 7521 + 7523
	ClientAssertionType  string `json:"client_assertion_type"` // RFC 7521 + 7523
	authorizationPresent bool
	basicAuthUsed        bool
	bodySecretPresent    bool
}

func (r *revokeRequest) UnmarshalJSON(data []byte) error {
	type plain revokeRequest
	var decoded plain
	secretPresent, err := unmarshalCredentialJSON(data, &decoded)
	if err != nil {
		return err
	}
	*r = revokeRequest(decoded)
	r.bodySecretPresent = secretPresent
	return nil
}

// HandleRevoke implements RFC 7009 OAuth 2.0 Token Revocation.
//
// A client may revoke only tokens issued to its own client_id. Unknown
// and other-client tokens share the RFC 7009 success response. A public
// client using auth method "none" can authenticate with client_id alone.
//
// token_type_hint is honored as an optimization (try the named tier
// first) but the server still attempts the other tier on miss, so a
// wrong hint doesn't leave the token alive.
func HandleRevoke(d RevokeDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	clientStore := d.ClientStoreAccessor()
	if clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}
	var req revokeRequest
	if !parseRevokeRequest(d, ctx, &req) {
		return
	}
	if !authenticateRevokeClient(d, clientStore, ctx, &req) {
		return
	}
	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	binding, owned, err := inspectRevokeTokenBinding(d, ctx, req.Token, req.ClientID)
	if err != nil {
		writeRevokeUnavailable(ctx)
		return
	}
	if !owned {
		ctx.JSON(http.StatusOK, map[string]any{})
		return
	}
	if !revokeBoundToken(d, ctx, req, binding) {
		writeRevokeUnavailable(ctx)
		return
	}
	ctx.JSON(http.StatusOK, map[string]any{})
}

func parseRevokeRequest(d RevokeDeps, ctx core.HandlerContext, req *revokeRequest) bool {
	if bindCredentialRequest(d, ctx, req) {
		return false
	}
	req.bodySecretPresent = req.bodySecretPresent || ctx.Request().PostForm.Has("client_secret")
	req.authorizationPresent = len(ctx.Request().Header.Values("Authorization")) > 0
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		req.ClientID, req.ClientSecret = id, secret
		req.basicAuthUsed = true
	}
	return true
}

// revokeBoundToken revokes recognized tiers for the authenticated client.
// The hint only chooses order; cache eviction runs after each accepted token.
func revokeBoundToken(d RevokeDeps, ctx core.HandlerContext, req revokeRequest, binding revokeTokenBinding) bool {
	accessOK, refreshOK := true, true
	if req.TokenTypeHint == "refresh_token" {
		if binding.refresh != nil {
			refreshOK = revokeRefresh(d, ctx, req.Token, binding.refresh)
		}
		if binding.access {
			accessOK = revokeAccess(d, ctx, req.Token)
		}
	} else {
		if binding.access {
			accessOK = revokeAccess(d, ctx, req.Token)
		}
		if binding.refresh != nil {
			refreshOK = revokeRefresh(d, ctx, req.Token, binding.refresh)
		}
	}
	InvalidateIntrospectionCache(d.IntrospectionCache(), req.Token)
	return accessOK && refreshOK
}

func writeRevokeUnavailable(ctx core.HandlerContext) {
	ctx.ResponseWriter().Header().Set(core.HeaderRetryAfter, "1")
	ctx.JSON(http.StatusServiceUnavailable, core.ErrorBody(core.ErrServiceDegraded))
}

// authenticateRevokeClient performs RFC 7009 client authentication for
// /token/revoke: either RFC 7521/7523 JWT bearer assertion or
// id+secret creds. On failure it writes the response and returns false;
// EVERY auth failure collapses to an identical 401 invalid_client so a
// caller can't probe client existence (a wrong-type assertion is the
// only malformed-input case, surfaced as 400 invalid_request before any
// lookup). On success req.ClientID is the authenticated client id.
func authenticateRevokeClient(d RevokeDeps, clientStore core.ClientStore, ctx core.HandlerContext, req *revokeRequest) bool {
	// RFC 7521/7523 JWT bearer client auth on /token/revoke.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientSecret != "" || req.authorizationPresent || req.bodySecretPresent {
			return rejectRevokeClient(ctx)
		}
		return authenticateRevokeAssertion(d, clientStore, ctx, req)
	}
	client, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil || client == nil || !client.Active || !tenant.ClientOK(ctx, client) {
		return rejectRevokeClient(ctx)
	}
	if !revokeAuthMethodMatches(req, client.TokenEndpointAuthMethod) {
		return rejectRevokeClient(ctx)
	}
	if client.TokenEndpointAuthMethod == "none" {
		return true
	}
	if err := d.AuthenticateClientCreds(ctx, req.ClientID, req.ClientSecret); err != nil {
		return rejectRevokeClient(ctx)
	}
	return true
}

func revokeAuthMethodMatches(req *revokeRequest, method string) bool {
	if req.basicAuthUsed && req.bodySecretPresent {
		return false
	}
	switch method {
	case "none":
		return !req.basicAuthUsed && !req.authorizationPresent && !req.bodySecretPresent
	case "", "client_secret_basic":
		return req.basicAuthUsed && !req.bodySecretPresent
	case "client_secret_post":
		return !req.basicAuthUsed && !req.authorizationPresent && req.ClientSecret != ""
	default:
		// Certificate and other methods have no verifier on this handler.
		return false
	}
}

func rejectRevokeClient(ctx core.HandlerContext) bool {
	ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
	return false
}

func authenticateRevokeAssertion(d RevokeDeps, clientStore core.ClientStore, ctx core.HandlerContext, req *revokeRequest) bool {
	if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return false
	}
	assertedID, err := d.VerifyJWTClientAssertion(ctx.Request().Context(), req.ClientAssertion, req.ClientID, d.ResolveIssuer(ctx))
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return false
	}
	req.ClientID = assertedID
	c, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil || c == nil || !c.Active || c.TokenEndpointAuthMethod == "none" || !tenant.ClientOK(ctx, c) {
		return rejectRevokeClient(ctx)
	}
	if c.TokenEndpointAuthMethod != "private_key_jwt" {
		return rejectRevokeClient(ctx)
	}
	return true
}

type revokeTokenBinding struct {
	access  bool
	refresh *RefreshToken
}

func inspectRevokeTokenBinding(d RevokeDeps, ctx core.HandlerContext, token, clientID string) (revokeTokenBinding, bool, error) {
	var binding revokeTokenBinding
	claims, _, err := d.ValidateAnyTokenForRevocation(ctx.Request().Context(), token)
	if err != nil && !errors.Is(err, core.ErrTokenValidationRejected) {
		return revokeTokenBinding{}, false, err
	}
	if err == nil && core.IsAccessTokenClaims(claims) {
		if claims.ClientID != clientID {
			return revokeTokenBinding{}, false, nil
		}
		binding.access = true
	}
	if inspector, ok := d.RefreshTokenStore().(RefreshTokenInspector); ok {
		refresh, err := inspector.Inspect(ctx.Request().Context(), token)
		if err != nil && !errors.Is(err, ErrRefreshTokenNotFound) {
			return revokeTokenBinding{}, false, err
		}
		if err == nil && refresh != nil {
			if refresh.ClientID != clientID {
				return revokeTokenBinding{}, false, nil
			}
			binding.refresh = refresh
		}
	}
	return binding, binding.access || binding.refresh != nil, nil
}

// revokeAccess delegates to the existing per-issuer revocation chain.
func revokeAccess(d RevokeDeps, ctx core.HandlerContext, token string) bool {
	if len(d.TokenIssuers()) == 0 {
		return false
	}
	revoked, failed := d.RevokeAcrossIssuers(ctx.Request().Context(), token)
	d.AuditPartialRevokeFailure(ctx, revoked, failed)
	return len(failed) == 0
}

// revokeRefresh prefers family deletion so rotated descendants cannot survive.
func revokeRefresh(d RevokeDeps, ctx core.HandlerContext, token string, info *RefreshToken) bool {
	insp, ok := d.RefreshTokenStore().(RefreshTokenInspector)
	if !ok {
		return false
	}
	if info.FamilyID != "" {
		if tracker, ok := d.RefreshTokenStore().(RefreshTokenFamilyTracker); ok {
			_, err := tracker.DeleteFamily(ctx.Request().Context(), info.FamilyID)
			return err == nil
		}
	}
	return insp.Delete(ctx.Request().Context(), token) == nil
}

// HandleRevokeAll implements the "logout everywhere" endpoint. The
// user presents a bearer token; the server reads sub + aud from its
// claims, then kills every refresh token bound to that
// (subject, client) pair via the optional RefreshTokenSubjectIndex
// extension. The presented access token is also revoked via the
// normal per-issuer path so it stops working immediately.
//
// Authentication: bearer token only (not client credentials). The
// user is the actor — they're authorizing the revocation of their
// own tokens.
func HandleRevokeAll(d RevokeDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if len(d.TokenIssuers()) == 0 {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}
	idx, ok := d.RefreshTokenStore().(RefreshTokenSubjectIndex)
	if !ok {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrRefreshTokenNotConfigured))
		return
	}

	lookupSub, clientID, ok := authenticateRevokeAllBearer(d, ctx)
	if !ok {
		return
	}
	deleted, err := idx.DeleteAllForSubject(ctx.Request().Context(), lookupSub, clientID)
	if err != nil {
		d.SrvLogger().Error("revoke-all failed", "error", err, "subject", lookupSub)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}

	// Also revoke the presented access token across all issuers so it
	// stops working immediately — without this, the bearer the caller
	// just used would keep working until expiry, which is surprising
	// for a "logout everywhere" semantic.
	revoked, failed := d.RevokeAcrossIssuers(ctx.Request().Context(), BearerToken(ctx.Request()))
	d.AuditPartialRevokeFailure(ctx, revoked, failed)

	// "Logout everywhere" is exactly the account-compromise-adjacent signal
	// that must also kill any standing trusted-device MFA-skip grant: an
	// attacker who minted a grant off a transiently-stolen already-MFA'd
	// bearer token must not keep a standing MFA-skip after the legitimate
	// user revokes all their tokens. Every client, not just clientID — a
	// full logout-everywhere from ANY client is a strong enough signal to
	// distrust every device across every app the user holds a grant for
	// (mirrors the password-change and sign-out-everywhere hooks).
	devicesRevoked := revokeTrustedDevicesOnRevokeAll(d, ctx, lookupSub)

	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus:            core.StatusOK,
		"refresh_tokens_revoked":  deleted,
		"trusted_devices_revoked": devicesRevoked,
	})
}

// revokeTrustedDevicesOnRevokeAll invalidates every trusted-device MFA-skip
// grant for lookupSub. Best-effort / fail-open: a store error is logged, not
// surfaced, because the refresh-token + access-token revocation this handler
// exists for has already succeeded — a cleanup-step failure must not turn
// into a 500 for a "logout everywhere" call that otherwise worked. No-op
// (returns 0) when no store is wired, matching every other TrustedDeviceStore
// consumer's nil-store contract.
func revokeTrustedDevicesOnRevokeAll(d RevokeDeps, ctx core.HandlerContext, lookupSub string) int {
	store := d.TrustedDeviceStore()
	if store == nil {
		return 0
	}
	n, err := store.RevokeAll(ctx.Request().Context(), lookupSub)
	if err != nil {
		d.SrvLogger().Error("revoke trusted devices failed", "subject", lookupSub, "error", err)
		return 0
	}
	return n
}

// authenticateRevokeAllBearer authenticates the bearer presented to the
// "logout everywhere" endpoint and resolves the (local subject, client)
// pair used for the bulk delete. On failure it writes the response and
// returns ok=false, emitting the THREE distinct WWW-Authenticate
// challenges verbatim: empty (missing token) -> invalid_token "The access
// token is invalid or expired" -> invalid_token "Subject mapping
// unavailable". clientID is derived from the first audience entry.
func authenticateRevokeAllBearer(d RevokeDeps, ctx core.HandlerContext) (lookupSub, clientID string, ok bool) {
	bearer := BearerToken(ctx.Request())
	if bearer == "" {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingToken))
		return "", "", false
	}
	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || !core.IsAccessTokenClaims(claims) || claims.Subject == "" {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return "", "", false
	}

	// Scope the bulk revoke to the bearer's CLIENT via the RFC 9068 client_id
	// claim, NOT aud[0]: this server's access tokens put RFC 8707 resource
	// indicators in aud while the client lives in client_id, so keying on aud[0]
	// would scope the delete to a resource URI that matches NO stored refresh
	// token — a silent "logout everywhere" failure (200 + 0 revoked) on any
	// resource-indicator deployment. An empty client_id leaves clientID="" = the
	// documented kill-every-client path. Mirrors populateAccessIntrospectionBody.
	clientID = claims.ClientID

	// OIDC §8 pairwise: refresh tokens are stored by local sub.
	// Translate pairwise -> local before the bulk delete so the
	// caller's revoke-all actually finds anything.
	lookupSub, perr := d.ResolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		d.SrvLogger().Error("pairwise resolve failed at revoke-all", "error", perr, "subject", claims.Subject)
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return "", "", false
	}
	return lookupSub, clientID, true
}
