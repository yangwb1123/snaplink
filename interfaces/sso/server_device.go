package sso

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/internal/handler/tokengrant"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
)

func generateDeviceCodeBytes() (string, error) { return oauth.GenerateDeviceCode() }

// generateUserCodeBytes delegates to oauth.GenerateUserCode.
func generateUserCodeBytes() (string, error) { return oauth.GenerateUserCode() }

// deviceCodePrereqs verifies the device-code subsystem is wired (a device-code
// store + the client store). Returns false after writing the wire error when
// either is missing.
func (s *Server) deviceCodePrereqs(ctx HandlerContext) bool {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ctx, ErrDeviceCodeNotConfigured))
		return false
	}
	if err := s.requireDeps(DepClientStore); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrServerMisconfigured))
		return false
	}
	return true
}

// handleDeviceCode is the device-initiated endpoint of RFC 8628.
// The device POSTs its client_id (+ optional scope), the server
// returns device_code + user_code + verification_uri + interval +
// expires_in. The device then displays user_code + verification_uri
// to the user and starts polling /token.
func (s *Server) handleDeviceCode(ctx HandlerContext) {
	// RFC 8628 device_code/user_code credentials — non-cacheable on every path.
	tokenNoStoreHeaders(ctx)
	if !s.deviceCodePrereqs(ctx) {
		return
	}

	var req struct {
		ClientID string   `json:"client_id"`
		Scope    string   `json:"scope"`
		Nonce    string   `json:"nonce"`
		Resource []string `json:"resource"` // RFC 8707 resource indicators
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	if req.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrMissingClientID))
		return
	}
	client, ok := s.resolveDeviceCodeClient(ctx, req.ClientID, req.Resource)
	if !ok {
		return
	}

	deviceCode, userCode, scopes, ok := s.mintDeviceCodeArtifacts(ctx, client, req.Scope)
	if !ok {
		return
	}
	ttl, interval := s.resolveDeviceCodeTTL(client)

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
	if !s.issueDeviceCode(ctx, dc) {
		return
	}
	s.respondDeviceCode(ctx, deviceCode, userCode, ttl, interval)
}

// issueDeviceCode persists the assembled DeviceCode and records the issuance
// audit event. dc carries the normalized (dashless, uppercase) UserCode as its
// lookup key so /device/verify accepts the user_code with OR without the
// cosmetic dash; the dashed form goes back to the device for display only. A
// store failure maps to 500 internal_error (with the original log line) and
// returns false. The recordDeviceCodeIssued audit call stays immediately after
// a successful Issue — same order as before the extraction.
func (s *Server) issueDeviceCode(ctx HandlerContext, dc *oauth.DeviceCode) bool {
	if err := s.deviceCodeStore.Issue(ctx.Request().Context(), dc); err != nil {
		s.logger.Error("device code issue failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return false
	}
	s.recordDeviceCodeIssued(ctx, dc.ClientID)
	return true
}

// respondDeviceCode writes the RFC 8628 device-authorization success body
// (device_code + user_code + verification_uri[_complete] + expires_in +
// interval). The verification URIs derive from this request via
// buildDeviceVerificationURI; the body shape is unchanged.
func (s *Server) respondDeviceCode(ctx HandlerContext, deviceCode, userCode string, ttl, interval time.Duration) {
	base, complete := s.buildDeviceVerificationURI(ctx.Request(), userCode)

	ctx.JSON(http.StatusOK, map[string]any{
		"device_code":               deviceCode,
		"user_code":                 userCode,
		"verification_uri":          base,
		"verification_uri_complete": complete,
		KeyExpiresIn:                int(ttl.Seconds()),
		"interval":                  int(interval.Seconds()),
	})
}

// resolveDeviceCodeClient looks up the device-flow client and applies the
// authentication / authorization guards in their original order: unknown
// client (401 invalid_client), inactive client (403 inactive_client), tenant
// mismatch (403 tenant_mismatch), disallowed resource (400 invalid_target). On
// any rejection it writes the response and returns ok=false.
func (s *Server) resolveDeviceCodeClient(ctx HandlerContext, clientID string, resource []string) (*Client, bool) {
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidClient))
		return nil, false
	}
	if !client.Active {
		ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrInactiveClient))
		return nil, false
	}
	if !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrTenantMismatch))
		return nil, false
	}
	if !client.AreResourcesAllowed(resource) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidTarget))
		return nil, false
	}
	return client, true
}

// mintDeviceCodeArtifacts generates the device_code + user_code bytes and
// resolves the granted scope set. Generation failures map to 500
// (internal_error); scope rejection maps to 400 invalid_scope. On any failure
// it writes the response and returns ok=false.
//
// Scope authorization happens at device-authorization REQUEST time (not at
// redemption): the client is fully authenticated here and AllowedScopes is in
// scope, so an unapproved-scope device request is rejected up front in the
// device flow's own shape — no double-check at /token. The captured
// DeviceCode.Scopes is the GRANTED set (validated, or defaulted to the client's
// allowlist when empty), so the eventual token carries its entitled scope.
func (s *Server) mintDeviceCodeArtifacts(ctx HandlerContext, client *Client, scope string) (string, string, []string, bool) {
	deviceCode, err := generateDeviceCodeBytes()
	if err != nil {
		s.logger.Error("device code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return "", "", nil, false
	}
	userCode, err := generateUserCodeBytes()
	if err != nil {
		s.logger.Error("user code generation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return "", "", nil, false
	}
	scopes, err := oauth.GrantedScopes(splitScope(scope), client)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidScope))
		return "", "", nil, false
	}
	return deviceCode, userCode, scopes, true
}

// resolveDeviceCodeTTL resolves the device-code TTL and poll interval with
// precedence per-client > server-wide > default (same shape as the token TTLs).
func (s *Server) resolveDeviceCodeTTL(client *Client) (time.Duration, time.Duration) {
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
	return ttl, interval
}

// buildDeviceVerificationURI returns the RFC 8628 verification_uri and
// verification_uri_complete (the latter carries user_code as a query param). The
// base is the configured override or, falling back, this request's base URL.
func (s *Server) buildDeviceVerificationURI(r *http.Request, userCode string) (string, string) {
	base := s.deviceVerifyBaseURL
	if base == "" {
		base = requestBaseURL(r) + PathDeviceVerify
	}
	complete := base
	if strings.Contains(complete, "?") {
		complete += "&user_code=" + userCode
	} else {
		complete += "?user_code=" + userCode
	}
	return base, complete
}

// handleDeviceVerify is the user-facing approval endpoint. The user
// has already authenticated separately (via /auth/login → bearer
// token, or any other path); they present the bearer here along
// with the user_code they read from the device + an approve/deny
// flag. The server validates both and updates the device code's
// state so the next device poll succeeds (or returns access_denied).
func (s *Server) handleDeviceVerify(ctx HandlerContext) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ctx, ErrDeviceCodeNotConfigured))
		return
	}
	if err := s.requireDeps(DepTokenIssuer); err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrServerMisconfigured))
		return
	}

	claims, ok := s.authenticateDeviceVerifyBearer(ctx)
	if !ok {
		return
	}

	var req struct {
		UserCode string `json:"user_code"`
		Approve  bool   `json:"approve"`
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	userCode := normalizeUserCode(req.UserCode)
	if userCode == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidRequest))
		return
	}
	// All user_code lookups go through the normalized form so
	// dashed / dashless / mixed-case inputs all resolve to the same
	// entry (typo tolerance on a code the user typed by hand).
	dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), userCode)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidGrant))
		return
	}

	if !s.applyDeviceDecision(ctx, dc, claims, req.Approve) {
		return
	}
	s.recordDeviceCodeDecision(ctx, claims.Subject, dc.ClientID, req.Approve)

	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK})
}

// authenticateDeviceVerifyBearer extracts and validates the caller's bearer for
// the device-verify endpoint. A missing bearer yields 401 missing_token; a
// validation failure (or nil claims) yields 401 invalid_token — the two paths
// stay distinct. On any failure it writes the response and returns ok=false.
func (s *Server) authenticateDeviceVerifyBearer(ctx HandlerContext) (*TokenClaims, bool) {
	bearer := bearerToken(ctx.Request())
	if bearer == "" {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrMissingToken))
		return nil, false
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil {
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrInvalidToken))
		return nil, false
	}
	return claims, true
}

// applyDeviceDecision routes the user's approve/deny decision back through the
// normalized user_code key. dc.UserCode is already the normalized form (we store
// dashless). Both Approve and Deny failures collapse to an identical 400
// invalid_grant. On failure it writes the response and returns false.
func (s *Server) applyDeviceDecision(ctx HandlerContext, dc *oauth.DeviceCode, claims *TokenClaims, approve bool) bool {
	provider := ""
	if attrProvider, ok := claims.Extra["provider"]; ok {
		provider = attrProvider
	}
	if approve {
		if err := s.deviceCodeStore.Approve(ctx.Request().Context(),
			dc.UserCode, claims.Subject, provider, claims.Extra); err != nil {
			ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidGrant))
			return false
		}
		return true
	}
	if err := s.deviceCodeStore.Deny(ctx.Request().Context(), dc.UserCode); err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidGrant))
		return false
	}
	return true
}

// handleDeviceTokenGrant is the device's poll path on /token. dpopJKT and
// mtlsX5T carry the sender-constraints extracted by the caller.
//
// Returns one of the RFC 8628 §3.5 sentinels:
//   - authorization_pending: user hasn't acted yet
//   - slow_down: device polled faster than Interval (RFC says +5s)
//   - access_denied: user explicitly denied
//   - expired_token: TTL elapsed
//   - invalid_grant: unknown code / wrong client
//
// or a standard token response on success.
func (s *Server) handleDeviceTokenGrant(ctx HandlerContext, client *Client, deviceCode, dpopJKT, mtlsX5T string) {
	tokengrant.HandleDeviceGrant(s, ctx, client, deviceCode, dpopJKT, mtlsX5T)
}

// normalizeUserCode delegates to oauth.NormalizeUserCode.

// handleDeviceVerifyPage serves the RFC 8628 device verification page at
// GET /device/verify. No authentication is required — the page is a public
// form where users enter the user_code displayed on their device.
//
// Mode dispatch (query-param driven):
//   ?check=USERCODE  — JSON status (for the page's JS polling). Unauthenticated;
//                      only reveals states the device already learns via /token.
//   (no check)       — HTML verification page with content negotiation:
//                      Accept: text/html → HTML page; otherwise → 406.
//
// The HTML page includes code entry, inline authentication, and approval flow.
func (s *Server) handleDeviceVerifyPage(ctx HandlerContext) {
	if userCode := ctx.Query("check"); userCode != "" {
		s.handleDeviceVerifyCheck(ctx, userCode)
		return
	}
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, errorBody(ctx, ErrDeviceCodeNotConfigured))
		return
	}
	// Look up user_code from query BEFORE content negotiation
	// so JSON and HTML paths both have access to it.
	uc := normalizeUserCode(ctx.Query("user_code"))
	// Content negotiation: serve HTML when the client accepts text/html,
	// serve JSON when the client accepts application/json (for CLI tools
	// and automation), otherwise return JSON as the default.
	accept := ctx.Request().Header.Get("Accept")
	if acceptsJSON(accept) || !acceptsHTML(accept) {
		// JSON response for non-browser clients (CLI, curl, automation).
		s.handleDeviceVerifyJSON(ctx, uc)
		return
	}
	// Look up device code info to pass to the template when user_code is in query.
	data := oidc.DeviceVerifyData{
		UserCode: ctx.Query("user_code"),
	}
	if uc != "" {
		if dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), uc); err == nil && dc != nil {
			data.ClientID = dc.ClientID
			data.Scopes = dc.Scopes
			if s.clientStore != nil {
				if client, err := s.clientStore.Get(ctx.Request().Context(), dc.ClientID); err == nil && client != nil {
					data.ClientName = client.Name
				}
			}
		}
	}
	oidc.RenderDeviceVerifyPage(ctx.ResponseWriter(), data)
}

// acceptsHTML reports whether the Accept header indicates the client prefers
// text/html over application/json.
func acceptsHTML(accept string) bool {
	// text/html explicitly listed, or no preference that excludes it.
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}

// acceptsJSON reports whether the Accept header explicitly requests
// application/json over text/html.
func acceptsJSON(accept string) bool {
	return strings.Contains(accept, "application/json")
}

// handleDeviceVerifyJSON returns the device verification state as JSON
// for non-browser clients (CLI, curl, automation). uc is the normalized
// user_code from the query parameter.
func (s *Server) handleDeviceVerifyJSON(ctx HandlerContext, uc string) {
	if uc == "" {
		ctx.JSON(http.StatusOK, map[string]string{"status": "pending"})
		return
	}
	s.handleDeviceVerifyCheck(ctx, uc)
}

// handleDeviceVerifyCheck returns the current state of a user_code as JSON for
// the device verification page's polling loop. It is unauthenticated and only
// reveals information the device already has via /token polling.
func (s *Server) handleDeviceVerifyCheck(ctx HandlerContext, userCode string) {
	if s.deviceCodeStore == nil {
		ctx.JSON(http.StatusNotImplemented, map[string]string{"status": "error"})
		return
	}
	uc := normalizeUserCode(userCode)
	if uc == "" {
		ctx.JSON(http.StatusOK, map[string]string{"status": "invalid"})
		return
	}
	dc, err := s.deviceCodeStore.GetByUserCode(ctx.Request().Context(), uc)
	if err != nil {
		if errors.Is(err, oauth.ErrDeviceCodeNotFound) {
			ctx.JSON(http.StatusOK, map[string]string{"status": "not_found"})
		} else {
			s.logger.Error("device verify check lookup failed", "error", err)
			ctx.JSON(http.StatusInternalServerError, map[string]string{"status": "error"})
		}
		return
	}
	if dc.IsExpired() {
		ctx.JSON(http.StatusOK, map[string]string{"status": "expired"})
		return
	}
	if dc.Approved {
		ctx.JSON(http.StatusOK, map[string]string{"status": "approved"})
		return
	}
	if dc.Denied {
		ctx.JSON(http.StatusOK, map[string]string{"status": "denied"})
		return
	}
	ctx.JSON(http.StatusOK, map[string]string{"status": "pending"})
}
