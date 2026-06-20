package tokengrant

import (
	"context"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/spi"
)

// CIBAGrantDeps is what HandleCIBAGrant needs. *sso.Server satisfies it via
// accessors_token_grant.go with a compile-time guard there. The grant lives in
// internal/handler because it mints an id_token (oidc) alongside the access /
// refresh tokens (oauth).
type CIBAGrantDeps interface {
	CIBAStore() oauth.CIBAStore
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
	RecordCIBADecision(ctx core.HandlerContext, clientID, subjectID string, approved bool)
	SrvLogger() spi.Logger
}

// HandleCIBAGrant processes the OIDC CIBA poll/ping token grant (grant_type
// urn:openid:params:grant-type:ciba with an auth_req_id). Behavior is
// byte-identical to the prior root handler.
//
// Responses follow RFC 8628 device-flow semantics: authorization_pending (user
// hasn't decided), slow_down (poll-interval violation), expired_token (unknown /
// expired / consumed auth_req_id), access_denied (user denied), invalid_grant
// (auth_req_id issued for a different client), or a standard token response on
// success. AMR/AuthTime are set from the approval event per RFC 9068.
func HandleCIBAGrant(d CIBAGrantDeps, ctx core.HandlerContext, client *core.Client, authReqID, dpopJKT, mtlsX5T string) {
	r, now, ok := cibaPollGate(d, ctx, client, authReqID)
	if !ok {
		return
	}

	strategy, ti, err := d.IssuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
		return
	}
	provider := r.Provider
	if provider == "" {
		provider = core.CIBAAMR
	}
	issuedSub := d.ApplyPairwiseSubject(ctx.Request().Context(), client, r.SubjectID)
	token, err := ti.Issue(ctx.Request().Context(), &core.Subject{
		ID:                  issuedSub,
		Provider:            provider,
		Resources:           r.Resources,
		ClientID:            client.ID,
		AuthTime:            now,
		AMR:                 []string{provider},
		ACR:                 r.ACRValues,
		TTL:                 client.AccessTokenTTL,
		ConfirmationJKT:     dpopJKT,
		ConfirmationX5TS256: mtlsX5T,
	}, r.Scopes)
	if err != nil {
		d.SrvLogger().Error("ciba token issuance failed", "strategy", strategy, "error", err)
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
	cibaIssueRefresh(d, ctx, client, r, provider, resp)
	cibaIssueIDToken(d, ctx, client, r, provider, issuedSub, now, token.AccessToken, resp)
	d.RecordTokenIssued(ctx, client.ID, strategy, r.SubjectID)
	d.RecordSubjectClientAccess(ctx.Request().Context(), r.SubjectID, client.ID)
	d.RecordCIBADecision(ctx, client.ID, r.SubjectID, true)
	_ = d.CIBAStore().Delete(ctx.Request().Context(), authReqID)
	ctx.JSON(http.StatusOK, resp)
}

// cibaPollGate runs the pre-issuance gauntlet: store configured, auth_req_id
// present, lookup (expired_token on miss), client-binding (invalid_grant on
// mismatch), poll-interval (slow_down), and the status switch. It preserves the
// slow_down UpdateLastPoll side-effect ordering and the CIBADenied ->
// Delete + RecordCIBADecision(false) + access_denied path. Returns ok=false
// (response already written) unless the request is approved and ready to issue.
func cibaPollGate(d CIBAGrantDeps, ctx core.HandlerContext, client *core.Client, authReqID string) (*oauth.CIBARequest, time.Time, bool) {
	var zero time.Time
	if d.CIBAStore() == nil {
		ctx.JSON(http.StatusNotImplemented, core.ErrorBody(core.ErrCIBANotConfigured))
		return nil, zero, false
	}
	if authReqID == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return nil, zero, false
	}
	r, err := d.CIBAStore().Get(ctx.Request().Context(), authReqID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrExpiredToken))
		return nil, zero, false
	}
	if r.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
		return nil, zero, false
	}

	now := time.Now()
	if !r.LastPoll.IsZero() && r.Interval > 0 && now.Sub(r.LastPoll) < r.Interval {
		_ = d.CIBAStore().UpdateLastPoll(ctx.Request().Context(), authReqID, now)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrSlowDown))
		return nil, zero, false
	}
	_ = d.CIBAStore().UpdateLastPoll(ctx.Request().Context(), authReqID, now)

	switch r.Status {
	case oauth.CIBADenied:
		_ = d.CIBAStore().Delete(ctx.Request().Context(), authReqID)
		d.RecordCIBADecision(ctx, client.ID, r.SubjectID, false)
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAccessDenied))
		return nil, zero, false
	case oauth.CIBAApproved:
		// fall through to issuance below
	default:
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrAuthorizationPending))
		return nil, zero, false
	}
	return r, now, true
}

// cibaIssueRefresh mints and records the refresh token when a refresh store is
// configured, mutating resp. Refresh issuance is fail-open: an error is logged
// and the token simply omitted.
func cibaIssueRefresh(d CIBAGrantDeps, ctx core.HandlerContext, client *core.Client, r *oauth.CIBARequest, provider string, resp map[string]any) {
	if d.RefreshTokenStore() == nil {
		return
	}
	rt, err := d.IssueRefreshToken(ctx.Request().Context(),
		r.SubjectID, client.ID, provider, r.Scopes, nil, "", r.Resources, nil, "", client.RefreshTokenTTL)
	if err != nil {
		d.SrvLogger().Error("refresh token issue failed", "error", err)
		return
	}
	resp[core.KeyRefreshToken] = rt
	d.RecordRefreshTokenIssued(ctx, client.ID, r.SubjectID, false)
}

// cibaIssueIDToken mints, optionally encrypts, and records the id_token when the
// openid scope was granted, mutating resp. ID Token issuance is fail-open per
// RFC 9068: resolution/issue errors are logged and the id_token omitted.
func cibaIssueIDToken(d CIBAGrantDeps, ctx core.HandlerContext, client *core.Client, r *oauth.CIBARequest, provider, issuedSub string, now time.Time, accessToken string, resp map[string]any) {
	if !slices.Contains(r.Scopes, core.ScopeOpenID) {
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
		Nonce:       r.Nonce,
		AuthTime:    now,
		AMR:         []string{provider},
		AccessToken: accessToken,
	})
	if err != nil {
		d.SrvLogger().Error("id token issue failed", "error", err)
		return
	}
	if enc, ok := d.MaybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
		resp[core.KeyIDToken] = enc
		d.RecordIDTokenIssued(ctx, client.ID, r.SubjectID)
	}
}
