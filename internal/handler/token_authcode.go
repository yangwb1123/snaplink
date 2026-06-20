package handler

import (
	"context"
	"net/http"
	"slices"
	"strings"
	"time"

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
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, clientTTLOverride time.Duration) (string, error)
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
// client mismatch, and PKCE failure ALL return 400 invalid_grant so an attacker
// cannot distinguish which check failed; only a redirect_uri mismatch returns
// the distinct invalid_redirect_uri (it is not a credential oracle). The code is
// single-use — AuthCodeStore.Consume deletes it atomically.
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
	info, err := d.AuthCodeStore().Consume(ctx.Request().Context(), req.Code)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	if info.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	if info.RedirectURI != "" && req.RedirectURI != info.RedirectURI {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRedirectURI))
		return
	}
	if info.CodeChallenge != "" {
		if l := len(req.CodeVerifier); l < core.PKCEVerifierMinLen || l > core.PKCEVerifierMaxLen {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return
		}
		if !oauth.VerifyPKCE(info.CodeChallengeMethod, info.CodeChallenge, req.CodeVerifier) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
			return
		}
	}
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	scopes = info.Scopes
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
		AMR:                  AmrOrProvider(info.AuthMethods, info.Provider),
		ACR:                  info.ACR,
		AuthorizationDetails: oauth.CloneRawJSON(info.AuthorizationDetails),
		SID:                  info.SID,
		TTL:                  client.AccessTokenTTL,
		ConfirmationJKT:      dpopJKT,
		ConfirmationX5TS256:  mtlsX5T,
	}, scopes)
	if err != nil {
		d.LogErrorCtx(ctx, "token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
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
	if d.RefreshTokenStore() != nil {
		rt, err := d.IssueRefreshToken(ctx.Request().Context(),
			info.UserID, client.ID, info.Provider, scopes, info.Attributes, "", info.Resources,
			info.AuthorizationDetails, info.SID, client.RefreshTokenTTL)
		if err != nil {
			d.SrvLogger().Error("refresh token issue failed", "error", err, "client", client.ID, "user", info.UserID)
		} else {
			resp[core.KeyRefreshToken] = rt
			d.RecordRefreshTokenIssued(ctx, client.ID, info.UserID, false)
		}
	}
	var deviceSecretValue string
	if slices.Contains(info.Scopes, core.ScopeDeviceSSO) && d.DeviceSecretStore() != nil {
		if ds, dsErr := d.IssueDeviceSecret(ctx.Request().Context(), info.UserID, info.SID, client.ID); dsErr != nil {
			d.SrvLogger().Error("device secret issue failed", "error", dsErr, "client", client.ID, "user", info.UserID)
		} else {
			deviceSecretValue = ds
		}
	}
	if slices.Contains(info.Scopes, core.ScopeOpenID) {
		idIssuer, emit, idErr := d.IDTokenIssuerForClient(client)
		if idErr != nil {
			d.SrvLogger().Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID, "user", info.UserID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:      issuedSub,
				Audience:     client.ID,
				Nonce:        info.Nonce,
				AuthTime:     authTime,
				AMR:          AmrOrProvider(info.AuthMethods, info.Provider),
				ACR:          info.ACR,
				Claims:       info.Attributes,
				AccessToken:  token.AccessToken,
				DeviceSecret: deviceSecretValue,
			})
			if err != nil {
				d.SrvLogger().Error("id token issue failed", "error", err, "client", client.ID, "user", info.UserID)
			} else if enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[core.KeyIDToken] = enc
				d.RecordIDTokenIssued(ctx, client.ID, info.UserID)
			}
		}
	}
	if deviceSecretValue != "" {
		resp[core.KeyDeviceSecret] = deviceSecretValue
	}
	ctx.JSON(http.StatusOK, resp)
}
