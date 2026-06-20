package handler

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// DeviceGrantDeps is what HandleDeviceGrant needs. *sso.Server satisfies it via
// accessors_token_grant.go with a compile-time guard there. The grant lives in
// internal/handler because it mints an id_token (oidc) alongside the access /
// refresh tokens (oauth).
type DeviceGrantDeps interface {
	DeviceCodeStore() oauth.DeviceCodeStore
	RefreshTokenStore() oauth.RefreshTokenStore
	IssuerForClient(c *core.Client) (string, core.TokenIssuer, error)
	IDTokenIssuerForClient(c *core.Client) (oidc.IDTokenIssuer, bool, error)
	ApplyPairwiseSubject(ctx context.Context, client *core.Client, localSub string) string
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, clientTTLOverride time.Duration) (string, error)
	MaybeEncryptIDToken(ctx context.Context, client *core.Client, signed string) (string, bool)
	RecordTokenIssued(ctx core.HandlerContext, clientID, strategy, subjectID string)
	RecordRefreshTokenIssued(ctx core.HandlerContext, clientID, subjectID string, rotation bool)
	RecordIDTokenIssued(ctx core.HandlerContext, clientID, subjectID string)
	RecordSubjectClientAccess(ctx context.Context, subject, clientID string)
	SrvLogger() spi.Logger
}

// HandleDeviceGrant is the device's poll path on /token (RFC 8628 §3.4-3.5).
// Behavior is byte-identical to the prior root handler.
//
// Returns one of the RFC 8628 §3.5 sentinels: authorization_pending (user hasn't
// acted), slow_down (polled faster than Interval), access_denied (user denied),
// expired_token (TTL elapsed / unknown code), invalid_grant (wrong client), or a
// standard token response on success. The device_code is single-use — deleted on
// success and on denial.
func HandleDeviceGrant(d DeviceGrantDeps, ctx core.HandlerContext, client *core.Client, deviceCode string) {
	store := d.DeviceCodeStore()
	if store == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrDeviceCodeNotConfigured))
		return
	}
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	dc, err := store.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrExpiredToken))
			return
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}
	// Bind: a device_code issued for client A can't be polled by client B.
	if dc.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within Interval of the previous poll.
	now := time.Now()
	if !dc.LastPoll.IsZero() && now.Sub(dc.LastPoll) < dc.Interval {
		_ = store.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSlowDown))
		return
	}
	_ = store.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)

	if dc.Denied {
		_ = store.Delete(ctx.Request().Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAccessDenied))
		return
	}
	if !dc.Approved {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAuthorizationPending))
		return
	}

	// Approved → mint tokens, then delete the device code (single-use).
	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, dc.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID: issuedSub, Provider: dc.Provider, Claims: dc.Attributes,
		Resources: dc.Resources,
		ClientID:  client.ID,
		AuthTime:  time.Now(),
		AMR:       []string{dc.Provider},
		TTL:       client.AccessTokenTTL,
	}, dc.Scopes)
	if err != nil {
		d.SrvLogger().Error("device token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	resp := map[string]any{
		core.KeyAccessToken:   token.AccessToken,
		core.KeyTokenType:     token.TokenType,
		core.KeyExpiresIn:     token.ExpiresIn,
		core.KeyScope:         token.Scope,
		core.KeyTokenStrategy: strategy,
	}
	if d.RefreshTokenStore() != nil {
		// Device grant doesn't accept authorization_details today; pass nil so
		// refresh rotations don't fabricate a binding the user never consented to.
		rt, err := d.IssueRefreshToken(ctx.Request().Context(),
			dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes, "", dc.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			d.SrvLogger().Error("refresh token issue failed", "error", err)
		} else {
			resp[core.KeyRefreshToken] = rt
			d.RecordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
		}
	}
	if slices.Contains(dc.Scopes, core.ScopeOpenID) {
		idIssuer, emit, idErr := d.IDTokenIssuerForClient(client)
		if idErr != nil {
			d.SrvLogger().Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:     issuedSub,
				Audience:    client.ID,
				Nonce:       dc.Nonce,
				AuthTime:    time.Now(),
				AMR:         []string{dc.Provider},
				Claims:      dc.Attributes,
				AccessToken: token.AccessToken,
			})
			if err != nil {
				d.SrvLogger().Error("id token issue failed", "error", err)
			} else if enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[core.KeyIDToken] = enc
				d.RecordIDTokenIssued(ctx, client.ID, dc.UserID)
			}
		}
	}
	d.RecordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	d.RecordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	_ = store.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}
