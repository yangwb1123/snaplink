package sso

import (
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
)

// handleCIBATokenGrant processes the CIBA poll/ping token grant.
// The client polls with grant_type=urn:openid:params:grant-type:ciba
// and an auth_req_id. Responses follow RFC 8628 device-flow semantics:
//   - authorization_pending: user hasn't decided yet
//   - slow_down: poll interval violation
//   - expired_token: auth_req_id unknown / expired / consumed
//   - access_denied: user explicitly denied
//   - invalid_grant: auth_req_id issued for a different client
//
// or a standard token response on success. AMR/AuthTime are set from
// the approval event per the RFC 9068 access-token claim rules.
func (s *Server) handleCIBATokenGrant(ctx HandlerContext, client *Client, authReqID, dpopJKT, mtlsX5T string) {
	if s.cibaStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrCIBANotConfigured))
		return
	}
	if authReqID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	r, err := s.cibaStore.Get(ctx.Request().Context(), authReqID)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
		return
	}
	if r.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	now := time.Now()
	if !r.LastPoll.IsZero() && r.Interval > 0 && now.Sub(r.LastPoll) < r.Interval {
		_ = s.cibaStore.UpdateLastPoll(ctx.Request().Context(), authReqID, now)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSlowDown))
		return
	}
	_ = s.cibaStore.UpdateLastPoll(ctx.Request().Context(), authReqID, now)

	switch r.Status {
	case oauth.CIBADenied:
		_ = s.cibaStore.Delete(ctx.Request().Context(), authReqID)
		s.recordCIBADecision(ctx, client.ID, r.SubjectID, false)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAccessDenied))
		return
	case oauth.CIBAApproved:
		// fall through to issuance below
	default:
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAuthorizationPending))
		return
	}

	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	provider := r.Provider
	if provider == "" {
		provider = CIBAAMR
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, r.SubjectID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
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
		s.logger.Error("ciba token issuance failed", "strategy", strategy, "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	resp := map[string]any{
		KeyAccessToken:   token.AccessToken,
		KeyTokenType:     token.TokenType,
		KeyExpiresIn:     token.ExpiresIn,
		KeyScope:         token.Scope,
		KeyTokenStrategy: strategy,
	}
	if s.refreshTokenStore != nil {
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			r.SubjectID, client.ID, provider, r.Scopes, nil, "", r.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, r.SubjectID, false)
		}
	}
	if slices.Contains(r.Scopes, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
		} else if emit {
			idToken, err := idIssuer.IssueIDToken(ctx.Request().Context(), &oidc.IDTokenRequest{
				Subject:     issuedSub,
				Audience:    client.ID,
				Nonce:       r.Nonce,
				AuthTime:    now,
				AMR:         []string{provider},
				AccessToken: token.AccessToken,
			})
			if err != nil {
				s.logger.Error("id token issue failed", "error", err)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, r.SubjectID)
			}
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, r.SubjectID)
	s.recordSubjectClientAccess(ctx.Request().Context(), r.SubjectID, client.ID)
	s.recordCIBADecision(ctx, client.ID, r.SubjectID, true)
	_ = s.cibaStore.Delete(ctx.Request().Context(), authReqID)
	ctx.JSON(http.StatusOK, resp)
}
