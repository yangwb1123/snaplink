package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// userCodeAlphabet matches defaultimpl's — base32 minus easily-confused
// glyphs. Duplicated here so handle_device.go doesn't import defaultimpl
// (which would create an import cycle).
const handlerUserCodeAlphabet = "BCDFGHJKMNPQRSTVWXYZ23456789"

// generateDeviceCodeBytes mints a 32-byte base64url device_code.
func generateDeviceCodeBytes() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// generateUserCodeBytes mints an 8-char dashed user_code (XXXX-XXXX)
// from the ambiguous-glyph-free alphabet.
func generateUserCodeBytes() (string, error) {
	const length = 8
	out := make([]byte, length)
	for i := range length {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(handlerUserCodeAlphabet))))
		if err != nil {
			return "", err
		}
		out[i] = handlerUserCodeAlphabet[n.Int64()]
	}
	return string(out[:4]) + "-" + string(out[4:]), nil
}

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
	if err := s.requireDeps(depClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	var req struct {
		ClientID string `json:"client_id"`
		Scope    string `json:"scope"`
		Nonce    string `json:"nonce"`
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

	ttl := s.deviceCodeTTL
	if ttl <= 0 {
		ttl = DefaultDeviceCodeTTL
	}
	interval := s.deviceCodeInterval
	if interval <= 0 {
		interval = DefaultDevicePollMin
	}
	scopes := splitScope(req.Scope)

	// Store the normalized (dashless, uppercase) form as the lookup
	// key so /device/verify accepts the user_code with OR without the
	// cosmetic dash. The dashed form goes back to the device for
	// display only.
	dc := &DeviceCode{
		DeviceCode: deviceCode,
		UserCode:   normalizeUserCode(userCode),
		ClientID:   client.ID,
		Scopes:     scopes,
		Nonce:      req.Nonce,
		Interval:   interval,
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
	if err := s.requireDeps(depTokenIssuer); err != nil {
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
		if errors.Is(err, ErrDeviceCodeNotFound) {
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
	token, err := ti.Issue(ctx.Request().Context(), &Subject{
		ID: dc.UserID, Provider: dc.Provider, Claims: dc.Attributes,
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
		rt, err := s.issueRefreshToken(ctx.Request().Context(),
			dc.UserID, client.ID, dc.Provider, dc.Scopes, dc.Attributes)
		if err != nil {
			s.logger.Error("refresh token issue failed", "error", err)
		} else {
			resp[KeyRefreshToken] = rt
			s.recordRefreshTokenIssued(ctx, client.ID, dc.UserID, false)
		}
	}
	if hasOpenIDScope(dc.Scopes) && s.idTokenIssuer != nil {
		idToken, err := s.idTokenIssuer.IssueIDToken(ctx.Request().Context(), &IDTokenRequest{
			Subject:  dc.UserID,
			Audience: client.ID,
			Nonce:    dc.Nonce,
			AuthTime: time.Now(),
			AMR:      []string{dc.Provider},
			Claims:   dc.Attributes,
		})
		if err != nil {
			s.logger.Error("id token issue failed", "error", err)
		} else {
			resp[KeyIDToken] = idToken
			s.recordIDTokenIssued(ctx, client.ID, dc.UserID)
		}
	}
	s.recordTokenIssued(ctx, client.ID, strategy, dc.UserID)
	_ = s.deviceCodeStore.Delete(ctx.Request().Context(), deviceCode)
	ctx.JSON(http.StatusOK, resp)
}

// normalizeUserCode strips dashes + uppercases for lookup tolerance.
func normalizeUserCode(s string) string {
	return strings.ToUpper(strings.ReplaceAll(s, "-", ""))
}

// splitScope parses a space-delimited scope string into a slice,
// returning nil for empty input so the AuthCode / DeviceCode entry's
// Scopes field stays nil-not-empty.
func splitScope(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, " ")
}
