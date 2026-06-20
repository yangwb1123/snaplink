package oidc

import (
	"context"
	"net/http"
	"slices"

	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// UserInfoDeps is what HandleUserInfo needs. *sso.Server satisfies it via
// accessor methods (accessors_userinfo.go), with a compile-time guard there.
// The security IMPLEMENTATIONS (DPoP/mTLS/residency/token validation) live in
// the root package; this interface surfaces them so the OIDC /userinfo endpoint
// orchestration can live in the oidc package without importing oauth.
type UserInfoDeps interface {
	RequireUserInfoDeps() error
	TokenNoStoreHeaders(ctx core.HandlerContext)
	BearerToken(r *http.Request) string
	SetResourceBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDescription string)
	ResolveIssuer(ctx core.HandlerContext) string
	ValidateAnyToken(ctx context.Context, token string) (*core.TokenClaims, string, error)
	VerifyDPoPBearer(ctx core.HandlerContext, claims *core.TokenClaims) error
	IsDPoPNonceRequired(err error) bool
	StampDPoPNonce(ctx core.HandlerContext)
	VerifyMTLSBearer(ctx core.HandlerContext, claims *core.TokenClaims) error
	ResidencyDeniedForAccess(ctx core.HandlerContext, claims *core.TokenClaims) (code string, denied bool)
	ResolveLocalSubject(ctx context.Context, sub string) (string, error)
	UserProvider() core.UserProvider
	MaybeSignUserInfo(ctx core.HandlerContext, clientID string, body map[string]any) bool
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	SrvLogger() spi.Logger
}

// HandleUserInfo implements the OIDC Core §5.3 UserInfo endpoint. Behavior is
// byte-identical to the prior root handler; the security primitives it calls
// (token validation, DPoP/mTLS sender-constraint, residency read-gate) are
// supplied via UserInfoDeps and implemented in the root package.
func HandleUserInfo(d UserInfoDeps, ctx core.HandlerContext) {
	// /userinfo carries the subject's profile (sub, name, email, custom claims).
	// Per RFC 6749 §5.1 the response must never be retained by intermediaries —
	// a stale cached body would leak across users if served from a different bearer.
	d.TokenNoStoreHeaders(ctx)
	if err := d.RequireUserInfoDeps(); err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrServerMisconfigured))
		return
	}

	tokenString := d.BearerToken(ctx.Request())
	if tokenString == "" {
		// RFC 6750 §3.1: the "no credentials" case omits error parameters.
		d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), "", "")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrMissingToken))
		return
	}

	claims, _, err := d.ValidateAnyToken(ctx.Request().Context(), tokenString)
	if err != nil {
		// RFC 6750 §3.1: validation failures carry error="invalid_token".
		d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "The access token is invalid or expired")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return
	}

	// RFC 9449 §7 — a cnf.jkt-bound token requires a matching DPoP proof. A
	// failure is indistinguishable from "invalid bearer" on the wire (single
	// error code) so attackers can't probe DPoP-bound vs unbound tokens.
	if err := d.VerifyDPoPBearer(ctx, claims); err != nil {
		// RFC 9449 §8 — RS-side nonce challenge: 401 + DPoP-Nonce header.
		if d.IsDPoPNonceRequired(err) {
			d.StampDPoPNonce(ctx)
			d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrUseDPoPNonce, "Fresh DPoP nonce required")
			ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrUseDPoPNonce))
			return
		}
		d.LogErrorCtx(ctx, "dpop bearer verification failed", "error", err, "subject", claims.Subject)
		d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "DPoP proof missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return
	}
	// RFC 8705 §3 — symmetric mTLS resource verification. Same wire-shape
	// collapse to invalid_token.
	if err := d.VerifyMTLSBearer(ctx, claims); err != nil {
		d.LogErrorCtx(ctx, "mtls bearer verification failed", "error", err, "subject", claims.Subject)
		d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Client certificate missing or thumbprint mismatch")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return
	}

	// Data-residency READ-gate: runs only for a holder of a fully-validated
	// token. A policy denial is a 403 with the residency wire code — NOT a 401
	// invalid_token (the token IS valid). Zero-cost when residency is disabled.
	if code, denied := d.ResidencyDeniedForAccess(ctx, claims); denied {
		ctx.JSON(http.StatusForbidden, core.ErrorBody(code))
		return
	}

	// OIDC §8 pairwise: resolve the per-sector sub to the local UserProvider key
	// for the lookup, but keep claims.Subject untouched for the response.
	lookupSub, perr := d.ResolveLocalSubject(ctx.Request().Context(), claims.Subject)
	if perr != nil {
		d.SrvLogger().Error("pairwise resolve failed at /userinfo", "error", perr, "subject", claims.Subject)
		d.SetResourceBearerChallenge(ctx, d.ResolveIssuer(ctx), core.ErrInvalidToken, "Subject mapping unavailable")
		ctx.JSON(http.StatusUnauthorized, core.ErrorBody(core.ErrInvalidToken))
		return
	}
	user, err := d.UserProvider().GetByID(ctx.Request().Context(), lookupSub)
	if err != nil {
		ctx.JSON(http.StatusNotFound, core.ErrorBody(core.ErrUserNotFound))
		return
	}

	// OIDC profile: when the token carries "openid", project the OIDC-standard
	// claim shape (§5.4). The full User struct is returned only for non-OIDC
	// tokens so pre-OIDC integrations keep working unchanged.
	if slices.Contains(claims.Scopes, core.ScopeOpenID) {
		body := ProjectUserInfoForOIDC(user, claims.Scopes, claims.RequestedClaims)
		// OIDC §8 pairwise: restore the inbound sub so the response matches the
		// RP's view (RPs verify userinfo.sub == id_token.sub per §5.3.2).
		if claims.Subject != "" && claims.Subject != user.ID {
			body["sub"] = claims.Subject
		}
		// RFC 9068 §2.2 claims passthrough: expose auth_time/acr/amr when the
		// token carries them (minted via /auth/login). Empty values omitted.
		if !claims.AuthTime.IsZero() {
			body["auth_time"] = claims.AuthTime.Unix()
		}
		if claims.ACR != "" {
			body["acr"] = claims.ACR
		}
		if len(claims.AMR) > 0 {
			body["amr"] = claims.AMR
		}
		// OIDC Core §5.3.2 — signed JWT response when the client opted in.
		if d.MaybeSignUserInfo(ctx, claims.ClientID, body) {
			return
		}
		ctx.JSON(http.StatusOK, body)
		return
	}

	ctx.JSON(http.StatusOK, user)
}
