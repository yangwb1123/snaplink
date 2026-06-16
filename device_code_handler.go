package sso

import (
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
)

func generateDeviceCodeBytes() (string, error) { return oauth.GenerateDeviceCode() }

// generateUserCodeBytes delegates to oauth.GenerateUserCode.
func generateUserCodeBytes() (string, error) { return oauth.GenerateUserCode() }

// handleDeviceCode is the device-initiated endpoint of RFC 8628.
// The device POSTs its client_id (+ optional scope), the server
// returns device_code + user_code + verification_uri + interval +
// expires_in. The device then displays user_code + verification_uri
// to the user and starts polling /token.
func (s *Server) handleDeviceCode(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID string   `json:"client_id"`
		Scope    string   `json:"scope"`
		Nonce    string   `json:"nonce"`
		Resource []string `json:"resource"` // RFC 8707 resource indicators
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), req.ClientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidClient))
		return
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, errorBody(ErrInactiveClient))
		return
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ErrTenantMismatch))
		return
	}
	if !client.AreResourcesAllowed(req.Resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidTarget))
		return
	}

	deviceCode, err := generateDeviceCodeBytes()
	if err != nil {
		s.logger.Error("device code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	userCode, err := generateUserCodeBytes()
	if err != nil {
		s.logger.Error("user code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}

	// TTL resolution precedence: per-client > server-wide > default.
	// Same shape as Client.RefreshTokenTTL / Client.AccessTokenTTL.
	ttl := client.DeviceCodeTTL
	if ttl <= 0 {
		ttl = s.deviceCodeTTL
	}
	if ttl <= 0 {
		ttl = DefaultDeviceCodeTTL
	}
	interval := client.DeviceCodePollInterval
	if interval <= 0 {
		interval = s.deviceCodeInterval
	}
	if interval <= 0 {
		interval = DefaultDevicePollMin
	}
	// Scope authorization at device-authorization REQUEST time (not at
	// redemption): the client is fully authenticated here and
	// AllowedScopes is in scope, so an unapproved-scope device request is
	// rejected up front in the device flow's own shape — no double-check
	// at /token. The captured DeviceCode.Scopes is the GRANTED set
	// (validated, or defaulted to the client's allowlist when empty), so
	// the eventual token carries its entitled scope.
	scopes, err := oauth.GrantedScopes(splitScope(req.Scope), client)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidScope))
		return
	}

	// Store the normalized (dashless, uppercase) form as the lookup
	// key so /device/verify accepts the user_code with OR without the
	// cosmetic dash. The dashed form goes back to the device for
	// display only.
	dc := &oauth.DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   normalizeUserCode(userCode),
		ClientID:   client.ID,
		Scopes:     scopes,
		Nonce:      req.Nonce,
		Interval:   interval,
		Resources:  append([]string(nil), req.Resource...),
		ExpiresAt:  time.Now().Add(ttl),
	}
	if err := s.deviceCodeStore.Issue(ctx.Request().Context(), dc); err != nil {
		s.logger.Error("device code issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	s.recordDeviceCodeIssued(ctx, client.ID)

	base := s.deviceVerifyBaseURL
	if base == "" {
		base = requestBaseURL(ctx.Request()) + PathDeviceVerify
	}
	complete := base
	if strings.Contains(complete, "?") {
		complete += "&user_code=" + userCode
	} else {
		complete += "?user_code=" + userCode
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base,
		"verification_uri_complete": complete,
		"expires_in":                int(ttl.Seconds()),
		"interval":                  int(interval.Seconds()),
	})
}

// handleDeviceVerify is the user-facing approval endpoint. The user
// has already authenticated separately (via /auth/login → bearer
// token, or any other path); they present the bearer here along
// with the user_code they read from the device + an approve/deny
// flag. The server validates both and updates the device code's
// state so the next device poll succeeds (or returns access_denied).
func (s *Server) handleDeviceVerify(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrMissingToken))
		return
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ErrInvalidToken))
		return
	}

	var req struct {
		UserCode string `json:"user_code"`
		Approve  bool   `json:"approve"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	userCode := normalizeUserCode(req.UserCode)
	if userCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	// All user_code lookups go through the normalized form so
	// dashed / dashless / mixed-case inputs all resolve to the same
	// entry (typo tolerance on a code the user typed by hand).
	dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), userCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	provider := ""
	if attrProvider, ok := claims.Extra["provider"]; ok {
		provider = attrProvider
	}

	// dc.UserCode is already the normalized form (we store dashless);
	// approval/denial routes back through the same key.
	if req.Approve {
		if err := s.deviceCodeStore.Approve(ctx.Request().Context(),
			dc.UserCode, claims.Subject, provider, claims.Extra); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	} else {
		if err := s.deviceCodeStore.Deny(ctx.Request().Context(), dc.UserCode); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
			return
		}
	}
	s.recordDeviceCodeDecision(ctx, claims.Subject, dc.ClientID, req.Approve)

	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK})
}

// handleDeviceTokenGrant is the device's poll path on /token. Called
// from the GrantDeviceCode case in handleToken; pulled out so the
// switch stays readable.
//
// Returns one of the RFC 8628 §3.5 sentinels:
//   - authorization_pending: user hasn't acted yet
//   - slow_down: device polled faster than Interval (RFC says +5s)
//   - access_denied: user explicitly denied
//   - expired_token: TTL elapsed
//   - invalid_grant: unknown code / wrong client
//
// or a standard token response on success.
func (s *Server) handleDeviceTokenGrant(ctx HandlerContext, client *Client, deviceCode string) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ErrDeviceCodeNotConfigured))
		return
	}
	if deviceCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidRequest))
		return
	}
	dc, err := s.deviceCodeStore.GetByDeviceCode(ctx.Request().Context(), deviceCode)
	if err != nil {
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
			return
		}
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}
	// Bind: a device_code issued for client A can't be polled by client B.
	if dc.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within Interval of the previous poll.
	now := time.Now()
	if !dc.LastPoll.IsZero() && now.Sub(dc.LastPoll) < dc.Interval {
		_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSlowDown))
		return
	}
	_ = s.deviceCodeStore.UpdateLastPoll(ctx.Request().Context(), deviceCode, now)

	if dc.Denied {
		_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAccessDenied))
		return
	}
	if !dc.Approved {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrAuthorizationPending))
		return
	}

	// Approved → mint tokens, then delete the device code (single-use).
	strategy, ti, err := s.issuerForClient(client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrNoTokenStrategy))
		return
	}
	issuedSub := s.applyPairwiseSubject(ctx.Request().Context(), client, dc.UserID)
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID: issuedSub, Provider: dc.Provider, Claims: dc.Attributes,
		Resources: dc.Resources,
		ClientID:  client.ID,
		AuthTime:  time.Now(),
		AMR:       []string{dc.Provider},
		TTL:       client.AccessTokenTTL,
	}, dc.Scopes)
	if err != nil {
		s.logger.Error("device token issuance failed", "strategy", strategy, "error", err)
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
		// Device grant doesn't accept authorization_details today; pass
		// nil so refresh rotations don't fabricate a binding the user
		// never consented to.
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes, "", dc.Resources, nil, "", client.RefreshTokenTTL)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
		}
	}
	if slices.Contains(dc.Scopes, ScopeOpenID) {
		idIssuer, emit, idErr := s.idTokenIssuerForClient(client)
		if idErr != nil {
			s.logger.Error("id token issuer resolution failed; omitting id_token", "error", idErr, "client", client.ID)
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
				s.logger.Error("id token issue failed", "error", err)
			} else if enc, ok := s.maybeEncryptIDToken(ctx.Request().Context(), client, idToken); ok {
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, dc.UserID)
			}
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	s.recordSubjectClientAccess(ctx.Request().Context(), dc.UserID, client.ID)
	_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}

// handleCIBATokenGrant is the client's poll path on /token for
// grant_type=urn:openid:params:grant-type:ciba. Called from the
// GrantCIBA case in handleToken. Mirrors handleDeviceTokenGrant:
//
//   - authorization_pending: user hasn't confirmed out of band yet
//   - slow_down: client polled faster than the issued interval
//   - access_denied: user explicitly denied
//   - expired_token: unknown / expired auth_req_id (oracle-leak
//     collapse — RFC parity with the device flow)
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
		// Unknown / expired / consumed all collapse to expired_token
		// (anti-enumeration — mirrors the device flow's ErrExpiredToken).
		ctx.JSON(http.StatusBadRequest, errorBody(ErrExpiredToken))
		return
	}
	// Bind: an auth_req_id issued for client A can't be polled by client B.
	if r.ClientID != client.ID {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrInvalidGrant))
		return
	}

	// slow_down: poll arrived within the issued interval of the previous
	// poll. Reuses the device-flow anti-thrash logic.
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
		// First-issue: pass "" so a fresh 256-bit family id is minted. The
		// OIDC nonce belongs to the id_token only — reusing it as the family
		// id would make the family key low-entropy/guessable and let an RP
		// trigger a cross-flow DeleteFamily DoS by replaying a known nonce.
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
				// Route through the JWE encrypter so a client with
				// IDTokenEncryptedResponseAlg gets a JWE, matching every
				// other id_token grant (login/device/auth_code/exchange).
				resp[KeyIDToken] = enc
				s.recordIDTokenIssued(ctx, client.ID, r.SubjectID)
			}
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, r.SubjectID)
	s.recordSubjectClientAccess(ctx.Request().Context(), r.SubjectID, client.ID)
	s.recordCIBADecision(ctx, client.ID, r.SubjectID, true)
	// Single-use: delete after minting so a replay hits expired_token.
	_ = s.cibaStore.Delete(ctx.Request().Context(), authReqID)
	ctx.JSON(http.StatusOK, resp)
}

// normalizeUserCode delegates to oauth.NormalizeUserCode.
