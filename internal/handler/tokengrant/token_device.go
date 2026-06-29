package tokengrant

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
	IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error)
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
	dc, ok := devicePollGate(d, ctx, store, client, deviceCode)
	if !ok {
		return
	}

	// Atomically CLAIM the approved code BEFORE minting: of N concurrent polls
	// exactly one wins the delete-and-return; the losers (and an already-consumed
	// or expired code) get ErrDeviceCodeNotFound -> expired_token. This is what
	// makes the device_code single-use under concurrency — the prior
	// mint-then-Delete let two simultaneous polls each mint a full token set.
	dc, err := store.ConsumeIfApproved(ctx.Request().Context(), deviceCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrExpiredToken))
		return
	}

	// Won the claim (already consumed atomically above) → mint + respond.
	deviceMintAndRespond(d, ctx, client, dc)
}

// deviceMintAndRespond issues the access/refresh/id tokens for an
// already-claimed (atomically consumed) approved device code and writes the 200.
func deviceMintAndRespond(d DeviceGrantDeps, ctx core.HandlerContext, client *core.Client, dc *oauth.DeviceCode) {
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
	deviceIssueRefresh(d, ctx, client, dc, resp)
	deviceIssueIDToken(d, ctx, client, dc, issuedSub, token.AccessToken, resp)
	d.RecordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	d.RecordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	ctx.JSON(http.StatusOK, resp)
}

// devicePollGate runs the RFC 8628 §3.5 poll-state checks (lookup, client bind,
// slow_down, denial, pending) and returns the device code only when it is
// approved and ready to mint. Each non-success branch writes its own DISTINCT
// wire response here, so behavior is byte-identical to the inline form.
func devicePollGate(d DeviceGrantDeps, ctx core.HandlerContext, store oauth.DeviceCodeStore, client *core.Client, deviceCode string) (*oauth.DeviceCode, bool) {
	dc, err := store.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		// CRITICAL: unknown/expired device_code stays expired_token, NOT invalid_grant.
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrExpiredToken))
			return nil, false
		}
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}
	// Bind: a device_code issued for client A can't be polled by client B.
	if dc.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, false
	}

	// slow_down: poll arrived within Interval of the previous poll.
	now := time.Now()
	if !dc.LastPoll.IsZero() && now.Sub(dc.LastPoll) < dc.Interval {
		_ = store.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSlowDown))
		return nil, false
	}
	_ = store.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)

	if dc.Denied {
		_ = store.Delete(ctx.Request().Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAccessDenied))
		return nil, false
	}
	if !dc.Approved {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAuthorizationPending))
		return nil, false
	}
	return dc, true
}

// deviceIssueRefresh mints a refresh token (fail-open: a failure is logged and
// the access token is still returned). Adds the token + records issuance on resp.
func deviceIssueRefresh(d DeviceGrantDeps, ctx core.HandlerContext, client *core.Client, dc *oauth.DeviceCode, resp map[string]any) {
	if d.RefreshTokenStore() == nil {
		return
	}
	// Device grant doesn't accept authorization_details today; pass nil so
	// refresh rotations don't fabricate a binding the user never consented to.
	rt, err := d.IssueRefreshToken(ctx.Request().Context(),
		dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes, "", dc.Resources, nil, "",
		// RFC 9068 §2.2: preserve auth_time across rotation. AMR is left empty so
		// rotation falls back to Provider (dc.Provider) — matching the access
		// token's AMR=[dc.Provider]; the device flow carries no acr.
		oauth.RefreshAuthContext{AuthTime: time.Now()},
		client.RefreshTokenTTL, "") // device flow: dpopJKT not threaded to this handler; unbound
	if err != nil {
		d.SrvLogger().Error("refresh token issue failed", "error", err)
		return
	}
	resp[core.KeyRefreshToken] = rt
	d.RecordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
}

// deviceIssueIDToken mints an id_token when openid was granted (fail-open:
// resolution/issue failures are logged and the id_token is simply omitted).
func deviceIssueIDToken(d DeviceGrantDeps, ctx core.HandlerContext, client *core.Client, dc *oauth.DeviceCode, issuedSub, accessToken string, resp map[string]any) {
	if !slices.Contains(dc.Scopes, core.ScopeOpenID) {
		return
	}
	idIssuer, emit, idErr := d.IDTokenIssuerForClient(client)
	if idErr != nil {
		d.SrvLogger().Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
		return
	}
	if !emit {
		return
	}
	idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
		Subject:     issuedSub,
		Audience:    client.ID,
		Nonce:       dc.Nonce,
		AuthTime:    time.Now(),
		AMR:         []string{dc.Provider},
		Claims:      dc.Attributes,
		AccessToken: accessToken,
	})
	if err != nil {
		d.SrvLogger().Error("id token issue failed", "error", err)
		return
	}
	if enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
		resp[core.KeyIDToken] = enc
		d.RecordIDTokenIssued(ctx, client.ID, dc.UserID)
	}
}
