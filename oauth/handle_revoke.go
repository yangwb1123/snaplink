package oauth

import (
	"context"
	"net/http"

	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/tenant"
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
	VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error)
	AuthenticateClientCreds(ctx core.HandlerContext, id, secret string) error
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	RevokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string)
	AuditPartialRevokeFailure(ctx core.HandlerContext, revoked, failed []string)
	SetBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDesc string)
	SrvLogger() spi.Logger
}

// HandleRevoke implements RFC 7009 OAuth 2.0 Token Revocation.
//
// Any registered active client may revoke — but the server MUST NOT
// distinguish revocation of an unknown token from a successful
// revocation (§2.2), so the wire response is always 200 OK with an
// empty body when the credentials are valid, regardless of whether
// the token existed.
//
// token_type_hint is honored as an optimization (try the named tier
// first) but the server still attempts the other tier on miss, so a
// wrong hint doesn't leave the token alive.
func HandleRevoke(d RevokeDeps, ctx core.HandlerContext) {
	middleware.TokenNoStoreHeaders(ctx)
	if d.ClientStoreAccessor() == nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	var req struct {
		Token               string `json:"token"`
		TokenTypeHint       string `json:"token_type_hint"`
		ClientID            string `json:"client_id"`
		ClientSecret        string `json:"client_secret"`
		ClientAssertion     string `json:"client_assertion"`      // RFC 7521 + 7523
		ClientAssertionType string `json:"client_assertion_type"` // RFC 7521 + 7523
	}
	if err := BindParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if id, secret, ok := BasicClientCreds(ctx.Request()); ok {
		req.ClientID = id
		req.ClientSecret = secret
	}

	clientStore := d.ClientStoreAccessor()

	// RFC 7521/7523 JWT bearer client auth on /token/revoke.
	if req.ClientAssertion != "" || req.ClientAssertionType != "" {
		if req.ClientAssertionType != ClientAssertionTypeJWTBearer {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
			return
		}
		assertedID, err := d.VerifyJWTClientAssertion(
			ctx.Request().Context(),
			req.ClientAssertion,
			req.ClientID,
			d.ResolveIssuer(ctx),
		)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return
		}
		req.ClientID = assertedID
		c, err := clientStore.Get(ctx.Request().Context(), req.ClientID)
		if err != nil || c == nil || !c.Active || !tenant.ClientOK(ctx, c) {
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
			return
		}
	} else if err := d.AuthenticateClientCreds(ctx, req.ClientID, req.ClientSecret); err != nil {
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidClient))
		return
	}

	if req.Token == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}

	// Best-effort across both tiers. Errors are intentionally ignored
	// per §2.2 — the response is always 200 OK on valid credentials.
	if req.TokenTypeHint == "refresh_token" {
		revokeRefresh(d, ctx, req.Token)
		revokeAccess(d, ctx, req.Token)
	} else {
		revokeAccess(d, ctx, req.Token)
		revokeRefresh(d, ctx, req.Token)
	}

	ctx.JSON(http.StatusOK, map[string]any{})
}

// revokeAccess delegates to the existing per-issuer revocation chain.
func revokeAccess(d RevokeDeps, ctx core.HandlerContext, token string) {
	if len(d.TokenIssuers()) == 0 {
		return
	}
	revoked, failed := d.RevokeAcrossIssuers(ctx.Request().Context(), token)
	d.AuditPartialRevokeFailure(ctx, revoked, failed)
}

// revokeRefresh deletes via the optional RefreshTokenInspector.Delete
// extension. No-op when the store doesn't implement the extension —
// callers in that situation must rely on TTL expiry.
func revokeRefresh(d RevokeDeps, ctx core.HandlerContext, token string) {
	insp, ok := d.RefreshTokenStore().(RefreshTokenInspector)
	if !ok {
		return
	}
	_ = insp.Delete(ctx.Request().Context(), token)
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

	bearer := BearerToken(ctx.Request())
	if bearer == "" {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingToken))
		return
	}
	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil || claims.Subject == "" {
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return
	}

	clientID := ""
	if len(claims.Audience) > 0 {
		clientID = claims.Audience[0]
	}

	// OIDC §8 pairwise: refresh tokens are stored by local sub.
	// Translate pairwise → local before the bulk delete so the
	// caller's revoke-all actually finds anything.
	lookupSub, perr := d.ResolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		d.SrvLogger().Error("pairwise resolve failed at revoke-all", "error", perr, "subject", claims.Subject)
		d.SetBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
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
	revoked, failed := d.RevokeAcrossIssuers(ctx.Request().Context(), bearer)
	d.AuditPartialRevokeFailure(ctx, revoked, failed)

	ctx.JSON(http.StatusOK, map[string]any{
		core.KeyStatus:           core.StatusOK,
		"refresh_tokens_revoked": deleted,
	})
}
