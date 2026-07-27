package sso

import (
	"context"
	"errors"
	"fmt"
	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/domains/tokenpolicy"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"net/http"
	"time"
)

func (s *Server) captureAuthCodeDPoPBinding(ctx HandlerContext, state string) (dpopJKT string, handled bool) {
	proof := ctx.Request().Header.Get(HeaderDPoP)
	if proof == "" {
		return "", false
	}
	binding, err := verifyDPoPProof(
		ctx.Request().Context(),
		proof,
		ctx.Request().Method,
		requestURLForDPoP(ctx.Request()),
		s.jtiReplayStore,
		s.jtiReplayFailClosed,
		s.dpopNonceProvider,
		s.resolvedDPoPProofMaxAge(),
		s.resolvedDPoPProofClockSkew(), "", // issuance: no access token yet, no ath
	)
	if err != nil {
		if errors.Is(err, ErrDPoPNonceRequired) {
			s.stampDPoPNonce(ctx)
			ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrUseDPoPNonce, state))
			return "", true
		}
		s.logger.Error("dpop proof failed at authorization endpoint", "error", err)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidDPoPProof, state))
		return "", true
	}
	return binding.JKT, false
}
func isSecureRedirectURI(uri string) bool {
	return oauth.IsSecureRedirectURI(uri)
}
func isValidPKCEMethod(method string) bool {
	return oauth.IsValidPKCEMethod(method)
}

// isPKCEMethodAllowedForClient delegates to oauth.IsPKCEMethodAllowedForClient.
func isPKCEMethodAllowedForClient(method string, allowed []string) bool {
	return oauth.IsPKCEMethodAllowedForClient(method, allowed)
}
func generateAuthCodeBytes() (string, error) {
	return oauth.GenerateAuthCodeBytes()
}
func (s *Server) issueRefreshToken(
	ctx context.Context,
	userID, clientID, provider string,
	scopes []string,
	attributes map[string]string,
	familyID string,
	resources []string,
	authDetails []byte,
	sid string,
	authCtx oauth.RefreshAuthContext,
	clientTTLOverride time.Duration,
	confirmationJKT string,
) (string, error) {
	return oauth.IssueRefreshToken(ctx, oauth.IssueRefreshTokenParams{
		RefreshTokenTTL:      s.refreshTokenTTL,
		RefreshTokenStore:    s.refreshTokenStore,
		UserID:               userID,
		ClientID:             clientID,
		Provider:             provider,
		Scopes:               scopes,
		Attributes:           attributes,
		FamilyID:             familyID,
		Resources:            resources,
		AuthorizationDetails: authDetails,
		SID:                  sid,
		AMR:                  authCtx.AMR,
		ACR:                  authCtx.ACR,
		AuthTime:             authCtx.AuthTime,
		ClientTTLOverride:    clientTTLOverride,
		ConfirmationJKT:      confirmationJKT,
		Generation:           authCtx.Generation,
		FamilyCreatedAt:      authCtx.FamilyCreatedAt,
	})
}
func isScopeSubset(want, have []string) bool {
	return oauth.IsScopeSubset(want, have)
}

// handleCallback handles the OAuth callback. This remains in root as it's a Server HTTP handler.
func (s *Server) handleCallback(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	code := ctx.Query("code")
	state := ctx.Query("state")
	provider := ctx.Query("provider")
	if code == "" || state == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return
	}
	auth, ok := s.resolveCallbackAuthenticator(ctx, provider, code, state)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrUnknownProvider))
		return
	}
	result, err := auth.Callback(context.Background(), &CallbackState{Code: code, State: state})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrCallbackFailed))
		return
	}
	s.finalizeCallbackSession(ctx, result)
}

// resolveCallbackAuthenticator picks the authenticator that owns this callback.
func (s *Server) resolveCallbackAuthenticator(ctx HandlerContext, provider, code, state string) (Authenticator, bool) {
	if provider != "" {
		auth, _ := s.getAuthenticator(provider)
		if auth == nil {
			// collapses to the identical unknown_provider response — no 400-vs-401
			// or outbound-fetch timing oracle over cross-tenant connection ids.
			auth, _ = s.connectionLoginAuthenticator(ctx, provider)
		}
		return auth, auth != nil
	}
	for _, a := range s.authenticators {
		if _, err := a.Callback(context.Background(), &CallbackState{Code: code, State: state}); err == nil {
			return a, true
		}
	}
	return nil, false
}

// errMaxActiveSessions is the sentinel createSession returns when a wired
// token-policy max_active_sessions cap would be exceeded by minting another
// session for this (user, client). Unlike the tenant-quota path, createSession
// writes NO response for it — the login caller maps it to a clean access_denied
// and owns the single wire write, so there is no double WriteHeader.
var errMaxActiveSessions = errors.New("sso: max active sessions reached")

// sessionPolicyCapExceeded reports whether minting another session for (userID,
// clientID) would breach the wired token-policy max_active_sessions dimension.
// Default-OFF: a nil token-policy store returns false immediately, so a login
// with no policy wired is byte-identical to before the feature. This is a
// GOVERNANCE property, not a credential check — every uncertainty FAILS OPEN
// (returns false, allow the session): a policy-store load error or a ListByUser
// count error must never block a legitimate login (same stance as
// tenant-suspension / risk-scorer, AGENTS.md §3 Fail Modes). It reuses
// ListByUser — the same enumerator the WithMaxSessionsPerUser eviction cap uses
// — to count the subject's live sessions, and enforces the cap BEFORE the mint
// so an over-cap login is refused rather than evicting a peer session.
func (s *Server) sessionPolicyCapExceeded(ctx HandlerContext, userID, clientID string) bool {
	if s.tokenPolicyStore == nil || s.sessionMgr == nil {
		return false
	}
	policies, err := s.tokenPolicyStore.Policies(ctx.Request().Context())
	if err != nil {
		s.logger.Error("token policy load failed — allowing session (fail-open)", "error", err)
		return false
	}
	sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), userID)
	if err != nil {
		s.logger.Error("session cap: list by user failed — allowing session (fail-open)",
			"error", err, "user", userID)
		return false
	}
	dec := tokenpolicy.Evaluate(tokenpolicy.PolicyInput{
		ClientID:       clientID,
		Subject:        userID,
		ActiveSessions: len(sessions),
	}, policies)
	// Only the active-sessions dimension can fire on this seam (no scopes / no
	// refresh depth supplied); guard on the reason so an unrelated deny can never
	if !dec.Deny || dec.Reason != tokenpolicy.DenyActiveSessions {
		return false
	}
	s.metrics.ObserveTokenPolicyEvaluation(metrics.PolicyDecisionDeny)
	s.metrics.ObserveTokenPolicyDenial(string(dec.Reason))
	s.logger.Info("token policy denied session creation",
		"client", clientID, "user", userID, "active", len(sessions))
	return true
}

// IntrospectionRenewExceeded moved to sso_protocol.go (which had room) to
// keep this file within the per-file line budget.
// finalizeCallbackSession upserts the user (when a UserProvider is configured)
// and creates a session, writing the success or 500 error response.
func (s *Server) finalizeCallbackSession(ctx HandlerContext, result *AuthResult) {
	user := &User{
		ID:         result.UserID,
		ExternalID: result.ExternalID,
		Provider:   result.Provider,
		Attributes: result.Attributes,
	}
	if s.userProvider != nil {
		// Gate: reject deprovisioned users (SCIM active=false) before creating a
		// session — mirrors rejectDeactivatedUser on the password/LDAP path. A
		// not-found user (first federated login) is treated active (no SCIM state).
		if u, err := s.userProvider.GetByID(ctx.Request().Context(), result.UserID); err == nil && u != nil && !u.IsActive() {
			s.logger.Info("federated callback blocked: account deprovisioned", "user_id", result.UserID, "provider", result.Provider)
			ctx.JSON(http.StatusUnauthorized, errorBody(ctx, ErrCallbackFailed))
			return
		}
		if err := s.userProvider.CreateOrUpdate(ctx.Request().Context(), user); err != nil {
			s.logger.Error("failed to upsert user", "error", err)
			ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
			return
		}
	}
	// Federated callback has no OAuth client in play — pass an empty clientID
	// (and tenant), so only a fleet-wide (empty-selector) max_active_sessions
	// policy applies to this login.
	session, err := s.createSession(ctx, result.UserID, "", "")
	if err != nil {
		if errors.Is(err, errMaxActiveSessions) {
			ctx.JSON(http.StatusForbidden, errorBody(ctx, ErrAccessDenied))
			return
		}
		s.logger.Error("failed to create session", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	s.linkGlobalSession(ctx.Request().Context(), session, result.UserID)
	ctx.JSON(http.StatusOK, map[string]string{
		KeySessionID: session.ID,
		KeyStatus:    StatusAuthenticated,
	})
}
func (s *Server) requireDeps(deps ...string) error {
	for _, d := range deps {
		switch d {
		case DepTokenIssuer:
			if len(s.tokenIssuers) == 0 {
				return fmt.Errorf("at least one TokenIssuer is required")
			}
		case DepUserProvider:
			if s.userProvider == nil {
				return fmt.Errorf("UserProvider is required")
			}
		case DepClientStore:
			if s.clientStore == nil {
				return fmt.Errorf("ClientStore is required")
			}
		case DepSessionMgr:
			if s.sessionMgr == nil {
				return fmt.Errorf("SessionManager is required")
			}
		}
	}
	return nil
}

type deviceContext struct {
	ID          string                       `json:"id,omitempty"`
	Type        string                       `json:"type,omitempty"`
	Platform    string                       `json:"platform,omitempty"`
	OSVersion   string                       `json:"os_version,omitempty"`
	BrowserName string                       `json:"browser_name,omitempty"`
	DeviceName  string                       `json:"device_name,omitempty"`
	IsNew       bool                         `json:"is_new,omitempty"`
	Fingerprint string                       `json:"fingerprint,omitempty"`
	SecurityCtx *device.LoginSecurityContext `json:"security,omitempty"`
	TrustScore  float64                      `json:"trust_score,omitempty"`
}
type clientContext struct {
	IP     string         `json:"ip"`
	Geo    *core.GeoInfo  `json:"geo,omitempty"`
	Device *deviceContext `json:"device,omitempty"`
}
type providerInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	ButtonLabel string `json:"button_label,omitempty"`
	ButtonColor string `json:"button_color,omitempty"`
	Builtin     bool   `json:"builtin"`
}

func buildClientContext(ctx HandlerContext) clientContext {
	return clientContext{IP: audit.ClientIP(ctx.Request()), Geo: geoFromContext(ctx)}
}
func geoFromContext(ctx HandlerContext) *core.GeoInfo {
	if g, ok := GeoFromHandlerContext(ctx); ok && g != nil {
		return g
	}
	return nil
}
func uaSummary(ua string) string {
	if ua == "" {
		return ""
	}
	dp := device.ParseUserAgent(ua)
	if n := dp.DeviceName; n != "" {
		if p := dp.Platform; p != "" {
			return p + " · " + n
		}
		return n
	}
	if b := dp.BrowserName; b != "" {
		if p := dp.Platform; p != "" {
			return p + " · " + b
		}
		return b
	}
	if p := dp.Platform; p != "" {
		return p
	}
	return string(dp.Type)
}
func locationSummary(ctx HandlerContext) string {
	g := geoFromContext(ctx)
	if g == nil {
		return ""
	}
	if g.City != "" && g.Region != "" {
		return g.City + ", " + g.Region
	}
	if g.City != "" {
		return g.City
	}
	if g.CountryCode != "" {
		return g.CountryCode
	}
	return ""
}
func deviceCtxFrom(ctx HandlerContext) *deviceContext {
	v := ctx.Get("device_ctx")
	dc, _ := v.(*deviceContext)
	return dc
}
func deviceTypeFromCtx(ctx HandlerContext) string {
	dc := deviceCtxFrom(ctx)
	if dc == nil {
		return ""
	}
	return dc.Type
}
func computeDeviceTrustScore(secCtx *device.LoginSecurityContext, loginCount int, existing *device.Device) float64 {
	var score float64
	switch {
	case secCtx != nil && secCtx.DeviceIsNew:
		score = 0.3
	case secCtx != nil && secCtx.LocationIsNew:
		score = 0.4
	case existing != nil:
		score = existing.TrustScore
	default:
		score = 0.5
	}
	if loginCount > 1 {
		score += float64(loginCount-1) * 0.02
	}
	if existing != nil && loginCount >= 10 {
		score = 0.85
	}
	if score > 0.95 {
		score = 0.95
	}
	if score < 0.1 {
		score = 0.1
	}
	return score
}
func deviceAwareTTL(clientTTL time.Duration, dc *deviceContext, minTTL time.Duration) time.Duration {
	if dc == nil || dc.SecurityCtx == nil || clientTTL <= 0 {
		return clientTTL
	}
	if !dc.SecurityCtx.DeviceIsNew && !dc.SecurityCtx.LocationIsNew {
		return clientTTL
	}
	r := time.Hour
	if minTTL > 0 && r < minTTL {
		r = minTTL
	}
	if r < clientTTL {
		return r
	}
	return clientTTL
}
func appendTrustHistory(existing *device.Device, e device.TrustHistoryEntry) []device.TrustHistoryEntry {
	if existing == nil || len(existing.TrustHistory) == 0 {
		return []device.TrustHistoryEntry{e}
	}
	h := append(existing.TrustHistory, e)
	if len(h) > 20 {
		h = h[len(h)-20:]
	}
	return h
}
func (s *Server) registerLoginDevice(ctx HandlerContext, userID string) *deviceContext {
	if s.deviceStore == nil {
		return nil
	}
	ua := ctx.Request().UserAgent()
	dp := device.ParseUserAgent(ua)
	fp := device.NewFingerprint(ctx.Request().Header.Get(core.HeaderDeviceID), ua)
	if fp == "" {
		return nil
	}
	if dec := device.EvaluatePolicy(s.devicePolicy, s.deviceStore, userID, fp); !dec.Allowed {
		s.logger.Info("device policy rejected login", "user", userID, "reason", dec.Reason)
		return nil
	}
	ip := audit.ClientIP(ctx.Request())
	secCtx := device.BuildSecurityContext(s.deviceStore, func(uid string) (int, error) {
		if s.sessionMgr == nil {
			return 0, nil
		}
		sessions, err := s.sessionMgr.ListByUser(ctx.Request().Context(), uid)
		if err != nil {
			return 0, err
		}
		return len(sessions), nil
	}, userID, fp, ip)
	if secCtx != nil && secCtx.PreviousLogin != nil {
		secCtx.PreviousLogin.Location = locationSummary(ctx)
	}
	isNew := secCtx != nil && secCtx.DeviceIsNew
	var existingDevice *device.Device
	if existing, err := s.deviceStore.GetByFingerprint(ctx.Request().Context(), userID, fp); err == nil && existing != nil {
		existingDevice = existing
		if d := int(time.Since(existing.LastSeenAt).Hours() / 24); d > 0 {
			existingDevice.TrustScore = device.DecayTrustScore(existing.TrustScore, d)
		}
	}
	estimatedCount := 1
	if existingDevice != nil {
		estimatedCount = existingDevice.LoginCount + 1
	}
	trustScore := computeDeviceTrustScore(secCtx, estimatedCount, existingDevice)
	d := &device.Device{
		UserID: userID, Fingerprint: fp, Type: dp.Type, Platform: dp.Platform, OSVersion: dp.OSVersion,
		BrowserName: dp.BrowserName, BrowserVersion: dp.BrowserVersion, DeviceName: dp.DeviceName,
		RawUserAgent: ua, LastIP: ip, LastLocation: locationSummary(ctx),
		LoginCount: 1, TrustScore: trustScore, TrustLabel: device.TrustLabelForScore(trustScore),
		TrustHistory: appendTrustHistory(existingDevice, device.TrustHistoryEntry{Time: time.Now(), Score: trustScore, Label: device.TrustLabelForScore(trustScore), Reason: "login"}),
	}
	if err := s.deviceStore.Upsert(ctx.Request().Context(), d); err != nil {
		s.logger.Error("device: failed to register", "user", userID, "error", err)
		return nil
	}
	return &deviceContext{ID: d.ID, Type: string(dp.Type), Platform: dp.Platform, OSVersion: dp.OSVersion,
		BrowserName: dp.BrowserName, DeviceName: dp.DeviceName, IsNew: isNew, Fingerprint: fp,
		SecurityCtx: secCtx, TrustScore: trustScore}
}
func (s *Server) recordLoginHistory(ctx HandlerContext, result *AuthResult, devID string, dc *deviceContext) {
	if s.loginHistory == nil {
		return
	}
	deviceIsNew := dc != nil && dc.SecurityCtx != nil && dc.SecurityCtx.DeviceIsNew
	locIsNew := dc != nil && dc.SecurityCtx != nil && dc.SecurityCtx.LocationIsNew
	ts := float64(0)
	if dc != nil {
		ts = dc.TrustScore
	}
	rec := &device.LoginRecord{UserID: result.UserID, Time: time.Now(), IP: audit.ClientIP(ctx.Request()), TrustScore: ts,
		DeviceID: devID, Device: uaSummary(ctx.Request().UserAgent()), Location: locationSummary(ctx),
		Provider: result.Provider, Success: true, DeviceIsNew: deviceIsNew, LocationIsNew: locIsNew}
	if err := s.loginHistory.Record(rec); err != nil {
		s.logger.Error("login history: failed to record", "user", result.UserID, "error", err)
	}
}
func (s *Server) recordLoginSecurityEvents(ctx HandlerContext, result *AuthResult, clientID string, dc *deviceContext) {
	if s.auditor == nil || dc == nil || dc.SecurityCtx == nil {
		return
	}
	sec := dc.SecurityCtx
	if sec.DeviceIsNew {
		e := audit.EventFromRequest(ctx)
		e.Type = audit.EventNewDeviceLogin
		e.Outcome = audit.OutcomeSuccess
		e.ActorID = result.UserID
		e.ClientID = clientID
		s.auditor.Record(ctx.Request().Context(), e)
	}
	if sec.LocationIsNew && sec.PreviousLogin != nil && sec.PreviousLogin.IP != "" {
		e := audit.EventFromRequest(ctx)
		e.Type = audit.EventNewLocation
		e.Outcome = audit.OutcomeSuccess
		e.ActorID = result.UserID
		e.ClientID = clientID
		s.auditor.Record(ctx.Request().Context(), e)
	}
}
func (s *Server) applyDeviceTrustDecay(ctx HandlerContext, existing, existingDevice *device.Device, userID string, days int) {
	oldScore := existing.TrustScore
	existingDevice.TrustScore = device.DecayTrustScore(oldScore, days)
	if oldScore-existingDevice.TrustScore > 0.2 && s.auditor != nil {
		e := audit.EventFromRequest(ctx)
		e.Type = audit.EventTrustDecay
		e.Outcome = audit.OutcomeSuccess
		e.ActorID = userID
		s.auditor.Record(ctx.Request().Context(), e)
	}
}
func (s *Server) loginPageURIForClient(ctx HandlerContext, clientID string) string {
	if clientID == "" || s.clientStore == nil {
		return ""
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || c == nil {
		return ""
	}
	return c.LoginPageURI
}
func (s *Server) brandingForClient(ctx HandlerContext, clientID string) map[string]string {
	if clientID == "" || s.clientStore == nil || s.tenantStore == nil {
		return nil
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || c == nil || c.TenantID == "" {
		return nil
	}
	t, err := s.tenantStore.GetTenant(ctx.Request().Context(), c.TenantID)
	if err != nil || t == nil {
		return nil
	}
	return t.Settings
}
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []providerInfo {
	var builtins []string
	for name := range s.authenticators {
		builtins = append(builtins, name)
	}
	var tenantID string
	if clientID != "" && s.clientStore != nil {
		if c, err := s.clientStore.Get(ctx.Request().Context(), clientID); err == nil {
			tenantID = c.TenantID
			if len(c.AllowedAuthenticators) > 0 {
				var f []string
				for _, n := range builtins {
					if c.IsAuthenticatorAllowed(n) {
						f = append(f, n)
					}
				}
				builtins = f
			}
			if len(c.AllowedProviderIDs) > 0 {
				return s.filteredProviders(ctx, builtins, c.AllowedProviderIDs, tenantID)
			}
		}
	}
	out := make([]providerInfo, 0, len(builtins)+4)
	for _, n := range builtins {
		out = append(out, providerInfo{ID: n, Type: string(provider.TypeBuiltin), DisplayName: displayNameForBuiltin(n), Builtin: true})
	}
	return append(out, s.providerStoreProviders(ctx, tenantID)...)
}
func (s *Server) filteredProviders(ctx HandlerContext, builtins []string, allowIDs []string, tnID string) []providerInfo {
	allowSet := make(map[string]bool, len(allowIDs))
	for _, id := range allowIDs {
		allowSet[id] = true
	}
	out := make([]providerInfo, 0, len(allowIDs))
	for _, n := range builtins {
		if allowSet[n] {
			out = append(out, providerInfo{ID: n, Type: string(provider.TypeBuiltin), DisplayName: displayNameForBuiltin(n), Builtin: true})
		}
	}
	for _, p := range s.providerStoreProviders(ctx, tnID) {
		if allowSet[p.ID] {
			out = append(out, p)
		}
	}
	return out
}
func (s *Server) providerStoreProviders(ctx HandlerContext, tnID string) []providerInfo {
	if s.providerStore == nil {
		return nil
	}
	list, err := s.providerStore.ListByTenant(ctx.Request().Context(), tnID)
	if err != nil || len(list) == 0 {
		return nil
	}
	out := make([]providerInfo, 0, len(list))
	for _, p := range list {
		if !p.Enabled {
			continue
		}
		out = append(out, providerInfo{ID: p.ID, Type: string(p.Type), DisplayName: p.DisplayName, IconURL: p.IconURL, ButtonLabel: p.ButtonLabel, ButtonColor: p.ButtonColor})
	}
	return out
}
func displayNameForBuiltin(name string) string {
	switch name {
	case "password":
		return "Password"
	case "webauthn":
		return "Passkey"
	case "totp":
		return "Authenticator App"
	default:
		return name
	}
}
func (s *Server) respondLoginProviders(ctx HandlerContext, req *login.Request) bool {
	if req.Provider != "" {
		return false
	}
	if conn, ok := s.resolveHomeRealm(ctx, req.LoginHint); ok {
		ctx.JSON(http.StatusOK, map[string]any{keyHRConnectionRequired: true, keyHRConnectionID: conn.ID, keyHRType: string(conn.Type), keyHRTenantID: conn.TenantID, keyHRDisplayName: conn.DisplayName, KeyIss: s.resolveIssuer(ctx)})
		return true
	}
	resp := map[string]any{KeyProviders: s.providersForClient(ctx, req.ClientID), KeyClientContext: buildClientContext(ctx), KeyIss: s.resolveIssuer(ctx)}
	if lp := s.loginPageURIForClient(ctx, req.ClientID); lp != "" {
		resp[KeyLoginPageURI] = lp
	}
	if b := s.brandingForClient(ctx, req.ClientID); b != nil {
		resp[KeyBranding] = b
	}
	ctx.JSON(http.StatusOK, resp)
	return true
}
func trackSessionActivity(ctx context.Context, mgr core.SessionManager, sid string) {
	if mgr == nil || sid == "" {
		return
	}
	tracker, ok := mgr.(core.SessionActivityTracker)
	if !ok {
		return
	}
	tracker.TrackActivity(ctx, sid)
}
