package sso

import (
	"context"
	"errors"
	"fmt"
	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/connections"
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
		JTI:                  authCtx.JTI,
		Resources:            resources,
		AuthorizationDetails: authDetails,
		SID:                  sid,
		AMR:                  authCtx.AMR,
		ACR:                  authCtx.ACR,
		AuthTime:             authCtx.AuthTime,
		Roles:                authCtx.Roles,
		ClientTTLOverride:    clientTTLOverride,
		ConfirmationJKT:      confirmationJKT,
		Generation:           authCtx.Generation,
		FamilyCreatedAt:      authCtx.FamilyCreatedAt,
	})
}
func isScopeSubset(want, have []string) bool {
	return oauth.IsScopeSubset(want, have)
}

// handleCallback handles the OAuth callback (a Server HTTP handler).
func (s *Server) handleCallback(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	state := ctx.Query("state")
	if _, ok := federatedProviderFromState(state); !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidCallback))
		return
	}
	s.handleFederatedOAuthCallback(ctx, state)
}

func (s *Server) handleFederatedOAuthCallback(ctx HandlerContext, state string) {
	resume, client, ok := s.consumeFederatedAuthorization(ctx, state)
	if !ok {
		return
	}
	provider := ctx.Query("provider")
	if provider != "" && provider != resume.Provider {
		s.queueFederatedContinuation(ctx, resume, client, nil, ErrCallbackFailed)
		return
	}
	if upstreamError := ctx.Query("error"); upstreamError != "" {
		code := ErrCallbackFailed
		if upstreamError == ErrAccessDenied {
			code = ErrAccessDenied
		}
		s.queueFederatedContinuation(ctx, resume, client, nil, code)
		return
	}
	code := ctx.Query("code")
	auth, ok := s.resolveCallbackAuthenticator(ctx, resume.Provider)
	if !ok {
		s.queueFederatedContinuation(ctx, resume, client, nil, ErrCallbackFailed)
		return
	}
	result, err := auth.Callback(ctx.Request().Context(), &CallbackState{
		Code: code, State: state, ClientID: client.ID, Scope: resume.Request.Scope,
	})
	if err != nil {
		s.logger.Error("callback failed", "provider", auth.Name(), "error", err)
		s.recordCallbackFailure(ctx, auth.Name(), ErrCallbackFailed)
		s.queueFederatedContinuation(ctx, resume, client, nil, ErrCallbackFailed)
		return
	}
	s.queueFederatedContinuation(ctx, resume, client, result, "")
}

func (s *Server) resolveCallbackAuthenticator(ctx HandlerContext, provider string) (Authenticator, bool) {
	auth, _ := s.getAuthenticator(provider)
	if auth == nil {
		auth, _ = s.connectionLoginAuthenticator(ctx, provider)
	}
	return auth, auth != nil
}

func validFederatedResume(resume *federatedAuthorizationState, provider, subject, clientID string) bool {
	return resume != nil && resume.Provider == provider && resume.Request.Provider == provider &&
		resume.Request.ClientID == clientID && subject == provider
}

func validFederatedCallbackClient(
	ctx HandlerContext, client *Client, resume *federatedAuthorizationState, provider string,
) bool {
	return client != nil && client.Active && clientTenantOK(ctx, client) &&
		client.IsAuthenticatorAllowed(provider) &&
		client.IsRedirectURIValid(resume.Request.RedirectURI) &&
		validFederatedLoginPage(client.LoginPageURI)
}

// errMaxActiveSessions is the sentinel createSession returns when a wired
// token-policy max_active_sessions cap would be exceeded. Unlike the
// tenant-quota path, createSession writes NO response for it — the login
// caller maps it to access_denied and owns the single wire write.
var errMaxActiveSessions = errors.New("sso: max active sessions reached")

// sessionPolicyCapExceeded reports whether minting another session for (userID,
// clientID) breaches the wired token-policy max_active_sessions dimension.
// Default-OFF (nil policy store = false); every uncertainty FAILS OPEN; the
// count reuses ListByUser and the cap is enforced BEFORE the mint.
func (s *Server) sessionPolicyCapExceeded(ctx HandlerContext, userID, clientID, tenantID string) bool {
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
	in := tokenpolicy.PolicyInput{
		ClientID:       clientID,
		Subject:        userID,
		TenantID:       tenantID,
		ActiveSessions: len(sessions),
	}
	// Role resolution (fail-open): only when the seam has a tenant AND the
	// roster store is wired. An error is logged + counted, roles stay empty,
	// and role selectors simply don't match — a roster outage must never
	// block login. ensureJITMembership runs before createSession, so a
	// JIT-provisioned role is visible on the first login.
	in.SubjectRoles, _ = s.subjectRoles(ctx.Request().Context(),
		"token policy: role resolution failed — role selectors inert (fail-open)",
		tenantID, userID)
	dec := tokenpolicy.Evaluate(in, policies)
	if !dec.Deny || dec.Reason != tokenpolicy.DenyActiveSessions {
		return false
	}
	s.metrics.ObserveTokenPolicyEvaluation(metrics.PolicyDecisionDeny)
	s.metrics.ObserveTokenPolicyDenial(string(dec.Reason))
	s.logger.Info("token policy denied session creation",
		"client", clientID, "user", userID, "active", len(sessions))
	return true
}

// subjectRoles resolves the user's tenant-membership role codes from the
// TenantUserStore roster for tenantID, keyed on the LOCAL subject (never a
// pairwise pseudonym — the store is keyed (TenantID, UserID)). FAIL-OPEN
// with logging + metric: an outage returns nil roles (the caller omits the
// claim / role selectors stop matching) instead of blocking issuance.
// ErrNoMembership is NOT an error (absent membership stays silent). failMsg
// is the caller's log string — the policy seam keeps its wording, the mint path uses its own.
func (s *Server) subjectRoles(ctx context.Context, failMsg, tenantID, userID string) ([]string, error) {
	if tenantID == "" || s.tenantUserStore == nil {
		return nil, nil
	}
	m, err := s.tenantUserStore.Get(ctx, tenantID, userID)
	if err != nil {
		if errors.Is(err, core.ErrNoMembership) {
			return nil, nil
		}
		s.logger.Error(failMsg, "tenant", tenantID, "user", userID, "error", err)
		s.metrics.ObserveTokenPolicyRoleResolutionError()
		return nil, err
	}
	if m == nil {
		return nil, nil
	}
	return []string{string(m.Role)}, nil
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
	builtins := s.builtinProviderNames()
	client := s.providerClient(ctx, clientID)
	if client == nil {
		return s.allProviders(ctx, builtins, "")
	}
	builtins = filterBuiltinProviders(builtins, client)
	if len(client.AllowedProviderIDs) > 0 {
		return s.filteredProviders(ctx, builtins, client.AllowedProviderIDs, client.TenantID)
	}
	return s.allProviders(ctx, builtins, client.TenantID)
}

func (s *Server) builtinProviderNames() []string {
	names := make([]string, 0, len(s.authenticators))
	for name := range s.authenticators {
		names = append(names, name)
	}
	return names
}

func (s *Server) providerClient(ctx HandlerContext, clientID string) *core.Client {
	if clientID == "" || s.clientStore == nil {
		return nil
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		return nil
	}
	return client
}

func filterBuiltinProviders(builtins []string, client *core.Client) []string {
	if len(client.AllowedAuthenticators) == 0 {
		return builtins
	}
	filtered := make([]string, 0, len(builtins))
	for _, name := range builtins {
		if client.IsAuthenticatorAllowed(name) {
			filtered = append(filtered, name)
		}
	}
	return filtered
}

func (s *Server) allProviders(ctx HandlerContext, builtins []string, tenantID string) []providerInfo {
	out := make([]providerInfo, 0, len(builtins)+4)
	for _, name := range builtins {
		out = append(out, providerInfo{ID: name, Type: string(provider.TypeBuiltin), DisplayName: displayNameForBuiltin(name), Builtin: true})
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
		resp := map[string]any{keyHRConnectionRequired: true, keyHRConnectionID: conn.ID, keyHRType: string(conn.Type), keyHRTenantID: conn.TenantID, keyHRDisplayName: conn.DisplayName, keyAuthzRequestPassthrough: s.federatedContinuationSupported(ctx, req.ClientID), KeyIss: s.resolveIssuer(ctx)}
		// Login-path consumption of the admin-probe health: a degraded or unreachable
		// IdP is flagged so the UI can grey it out before the user clicks
		// into a timeout. Fail-open: a health read error leaves the flag
		// unset and the attempt still collapses to the standard error.
		if s.connectionStore != nil {
			if h, herr := s.connectionStore.Health(ctx.Request().Context(), conn.ID); herr == nil && h != nil && (h.Status == connections.HealthUnreachable || h.Status == connections.HealthDegraded) {
				resp[keyHRUnavailable] = true
			}
		}
		ctx.JSON(http.StatusOK, resp)
		return true
	}
	resp := map[string]any{KeyProviders: s.providersForClient(ctx, req.ClientID), KeyClientContext: buildClientContext(ctx), keyAuthzRequestPassthrough: s.federatedContinuationSupported(ctx, req.ClientID), KeyIss: s.resolveIssuer(ctx)}
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
	_ = tracker.TrackActivity(ctx, sid)
}
