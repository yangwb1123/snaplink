package tokengrant

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// AuthCodeGrantDeps is what HandleAuthCodeGrant needs. *sso.Server satisfies it
// via accessor methods (accessors_token_grant.go) with a compile-time guard
// there. The issuance/refresh-family IMPLEMENTATIONS live in the root package;
// this interface surfaces them so the authorization_code token exchange can
// live in internal/handler — the only tier that may import BOTH oauth (code
// store, refresh issuance) AND oidc (id_token issuance), which the grant needs
// and which neither oauth nor oidc may import from the other.
type AuthCodeGrantDeps interface {
	AuthCodeStore() oauth.AuthCodeStore
	RefreshTokenStore() oauth.RefreshTokenStore
	DeviceSecretStore() core.DeviceSecretStore
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	IDTokenIssuerForClient(c *core.Client) (oidc.IDTokenIssuer, bool, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error)
	IssueDeviceSecret(ctx context.Context, subject, sid, clientID string) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
	DPoPTokenTypeOr(defaultType, jkt string) string
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordIDTokenIssued(ctx core.HandlerContext, clientID, subjectID string)
	LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any)
	SrvLogger() spi.Logger
}

// HandleAuthCodeGrant processes the RFC 6749 §4.1.3 authorization_code token
// exchange. Behavior is byte-identical to the prior root handler.
//
// Oracle-leak collapse (AGENTS.md §3): unknown / expired / consumed code,
// client mismatch, redirect_uri mismatch, PKCE failure, and RFC 9449 §10
// DPoP jkt mismatch ALL return 400 invalid_grant so an attacker cannot
// distinguish which check failed (RFC 6749 §5.2 defines no
// invalid_redirect_uri for the token endpoint). The code is single-use —
// AuthCodeStore.Consume deletes it atomically.
//
// RFC 9068 §2.2: auth_time is stamped from AuthCode.AuthTime (the real
// /auth/login moment), NOT the exchange time, and the AMR/ACR are propagated
// from the original authentication event.
func HandleAuthCodeGrant(d AuthCodeGrantDeps, ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, scopes []string, dpopJKT, mtlsX5T string) {
	if d.AuthCodeStore() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrAuthCodeNotConfigured))
		return
	}
	if req.Code == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	info, ok := authCodeValidate(d, ctx, client, req, dpopJKT)
	if !ok {
		return
	}
	resp, token, issuedSub, authTime, scopes, ok := authCodeIssueAccessToken(d, ctx, client, req, info, scopes, dpopJKT, mtlsX5T)
	if !ok {
		return
	}
	authCodeIssueRefresh(d, ctx, client, info, scopes, dpopJKT, resp)
	var deviceSecretValue string
	if slices.Contains(info.Scopes, core.ScopeDeviceSSO) && d.DeviceSecretStore() != nil {
		if ds, dsErr := d.IssueDeviceSecret(ctx.Request().Context(), info.UserID, info.SID, client.ID); dsErr != nil {
			d.SrvLogger().Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", info.UserID)
		} else {
			deviceSecretValue = ds
		}
	}
	authCodeIssueIDToken(d, ctx, client, info, issuedSub, authTime, token.AccessToken, deviceSecretValue, resp)
	if deviceSecretValue != "" {
		resp[core.KeyDeviceSecret] = deviceSecretValue
	}
	ctx.JSON(http.StatusOK, resp)
}

// authCodeIssueAccessToken resolves the issuer, applies the scope/resource
// fallbacks and the pairwise subject, stamps auth_time from AuthCode.AuthTime
// (the real /auth/login moment, falling back to now only when zero), issues the
// access token (fail-CLOSED: a strategy or Issue error aborts the grant), and
// seeds the response map. ok=false means a wire error was already written.
func authCodeIssueAccessToken(d AuthCodeGrantDeps, ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, info *oauth.AuthCode, scopes []string, dpopJKT, mtlsX5T string) (map[string]any, *core.Token, string, time.Time, []string, bool) { //nolint:staticcheck // SA4009: auth-code grant intentionally uses the code-bound info.Scopes, not the request-scopes param
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return nil, nil, "", time.Time{}, nil, false
	}
	scopes = info.Scopes //nolint:staticcheck // SA4009: see func comment — code-bound scopes are authoritative
	if len(scopes) == 0 {
		scopes = strings.Split(req.Scope, " ")
	}
	resources := info.Resources
	if len(resources) == 0 {
		resources = req.Resource
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, info.UserID)
	authTime := info.AuthTime
	if authTime.IsZero() {
		authTime = time.Now()
	}
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID: issuedSub, Provider: info.Provider, Claims: info.Attributes,
		Resources:            resources,
		ClientID:             client.ID,
		AuthTime:             authTime,
		AMR:                  handler.AmrOrProvider(info.AuthMethods, info.Provider),
		ACR:                  info.ACR,
		AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
		SID:                  info.SID,
		TTL:                  client.AccessTokenTTL,
		ConfirmationJKT:      dpopJKT,
		ConfirmationX5TS256:  mtlsX5T,
		// OIDC §5.5: login-time claims param rides the token for /userinfo.
		RequestedClaims: oauth.CloneRawJSON(info.RequestedClaims),
	}, scopes)
	if err != nil {
		d.LogErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return nil, nil, "", time.Time{}, nil, false
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, info.UserID)
	d.RecordSubjectClientAccess(ctx.Request().Context(), info.UserID, client.ID)
	resp := map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     d.DPoPTokenTypeOr(token.TokenType, dpopJKT),
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
	}
	return resp, token, issuedSub, authTime, scopes, true
}

// authCodeValidate runs the oracle-collapse gauntlet: single-use Consume,
// client-binding check, redirect_uri match, and PKCE. Returns ok=false (after
// writing the wire response) when any check fails so the caller can return.
//
// Oracle-leak collapse: unknown/expired/consumed code, client mismatch,
// redirect_uri mismatch, PKCE failure, and DPoP jkt mismatch ALL return 400
// invalid_grant. redirect_uri mismatch collapses here too — RFC 6749 §5.2
// does NOT define invalid_redirect_uri for the token endpoint (it is an
// authorization-endpoint code); a §4.1.3 redirect_uri mismatch invalidates
// the grant, so the failure is indistinguishable from a code/client/PKCE/
// DPoP problem. PKCE is enforced ONLY when info.CodeChallenge != ""; both
// the length-bounds violation and a VerifyPKCE failure collapse to
// invalid_grant. RFC 9449 §10 DPoP code-binding is enforced ONLY when
// info.ConfirmationJKT != "" (the client presented a DPoP proof at
// /auth/login) — an exchange presenting no proof, or a proof under a
// different key, collapses to the same invalid_grant.
func authCodeValidate(d AuthCodeGrantDeps, ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT string) (*oauth.AuthCode, bool) {
	info, err := d.AuthCodeStore().Consume(ctx.Request().Context(), req.Code)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}
	if info.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}
	if info.RedirectURI != "" && req.RedirectURI != info.RedirectURI {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}
	if info.CodeChallenge != "" {
		if l := len(req.CodeVerifier); l < core.PKCEVerifierMinLen || l > core.PKCEVerifierMaxLen {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return nil, false
		}
		if !oauth.VerifyPKCE(info.CodeChallengeMethod, info.CodeChallenge, req.CodeVerifier) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return nil, false
		}
	}
	if info.ConfirmationJKT != "" && info.ConfirmationJKT != dpopJKT {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}
	return info, true
}

// authCodeIssueRefresh fail-OPENs (log + continue): a refresh issuance error
// never aborts the access-token response. Family seed "" starts a new family.
func authCodeIssueRefresh(d AuthCodeGrantDeps, ctx core.HandlerContext, client *core.Client, info *oauth.AuthCode, scopes []string, dpopJKT string, resp map[string]any) {
	if d.RefreshTokenStore() == nil {
		return
	}
	rt, err := d.IssueRefreshToken(ctx.Request().Context(),
		info.UserID, client.ID, info.Provider, scopes, info.Attributes, "", info.Resources,
		info.AuthorizationDetails, info.SID,
		// RFC 9068 §2.2: persist the original /auth/login amr/acr/auth_time
		// (raw AuthMethods so rotation re-resolves via AmrOrProvider exactly
		// like the access token above) so a refresh chain keeps the MFA context.
		oauth.RefreshAuthContext{AMR: info.AuthMethods, ACR: info.ACR, AuthTime: info.AuthTime},
		client.RefreshTokenTTL, dpopJKT)
	if err != nil {
		d.SrvLogger().Error("refresh token issue failed", "error", err, "client", client.ID, "user", info.UserID)
		return
	}
	resp[core.KeyRefreshToken] = rt
	d.RecordRefreshTokenIssued(ctx, client.ID, info.UserID, false)
}

// authCodeIssueIDToken fail-OPENs (log + omit): issuer-resolution, issuance, or
// encryption failure omits id_token rather than failing the grant. auth_time is
// the caller-supplied AuthCode.AuthTime (the real /auth/login moment).
func authCodeIssueIDToken(d AuthCodeGrantDeps, ctx core.HandlerContext, client *core.Client, info *oauth.AuthCode, issuedSub string, authTime time.Time, accessToken, deviceSecretValue string, resp map[string]any) {
	if !slices.Contains(info.Scopes, core.ScopeOpenID) {
		return
	}
	idIssuer, emit, idErr := d.IDTokenIssuerForClient(client)
	if idErr != nil {
		d.SrvLogger().Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", info.UserID)
		return
	}
	if !emit {
		return
	}
	// OIDC Core §5.5: project the RP-requested claims captured at /auth/login
	// so the exchange-minted id_token matches the direct-mint flow
	// (emitLoginIDToken) — no claims parameter means all attributes pass
	// through unchanged (backward compatible).
	claims := info.Attributes
	if len(info.RequestedClaims) > 0 {
		claims = oidc.ProjectIDTokenClaims(claims, info.RequestedClaims)
	}
	idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
		Subject:         issuedSub,
		Audience:        client.ID,
		Nonce:           info.Nonce,
		AuthTime:        authTime,
		AMR:             handler.AmrOrProvider(info.AuthMethods, info.Provider),
		ACR:             info.ACR,
		Claims:          claims,
		AccessToken:     accessToken,
		DeviceSecret:    deviceSecretValue,
		RequestedClaims: info.RequestedClaims,
	})
	if err != nil {
		d.SrvLogger().Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
		return
	}
	if enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
		resp[core.KeyIDToken] = enc
		d.RecordIDTokenIssued(ctx, client.ID, info.UserID)
	}
}
