package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
)

func (s *Server) issueAuthCode(
	ctx context.Context,
	result *AuthResult,
	req *login.Request,
	client *Client,
	confirmationJKT string,
	sessionID string,
) (string, error) {
	return oauth.IssueAuthCode(ctx, oauth.IssueAuthCodeParams{
		AuthCodeTTL:          s.authCodeTTL,
		AuthCodeStore:        s.authCodeStore,
		UserID:               result.UserID,
		ClientID:             client.ID,
		RedirectURI:          req.RedirectURI,
		Scopes:               req.Scope,
		Nonce:                req.Nonce,
		Provider:             result.Provider,
		AuthMethods:          result.AuthMethods,
		ACR:                  result.AchievedACR,
		AuthTime:             result.AuthTime,
		Attributes:           result.Attributes,
		CodeChallenge:        req.CodeChallenge,
		CodeChallengeMethod:  req.CodeChallengeMethod,
		Resources:            req.Resource,
		AuthorizationDetails: req.AuthorizationDetails,
		ConfirmationJKT:      confirmationJKT,
		RequestedClaims:      req.Claims,
		SID:                  sessionID,
	})
}

// authenticateUser resolves the authenticator and validates credentials: a
// federated authenticator with a LoginURL redirects (handled=true); otherwise
// the per-account lockout gate runs BEFORE the verifier (so a locked account
// can't drain the constant-time hash budget), the credential is verified, and
// lockout state is updated (a failure may lock; a success clears the counter
// before any risk decision). Returns (result, handled) — handled=true means a
// response was written (redirect or rejection). Ordering is unchanged from the
// inline form.
func (s *Server) authenticateUser(ctx HandlerContext, req *login.Request, client *Client) (*AuthResult, bool) {
	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		// Enterprise-connection dispatch: an HRD connection_required directive
		// makes the UI re-post with provider=<connection id>; a statically-
		// registered name always WINS (checked first). Any connection
		// miss/failure falls through to the SAME unsupported_provider response
		// as an unknown provider (anti-enumeration).
		auth, err = s.connectionLoginAuthenticator(ctx, req.Provider)
	}
	if err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrUnsupportedProvider, req.State))
		return nil, true
	}
	if s.beginFederatedLogin(ctx, req, client, auth) {
		return nil, true
	}
	lockKey := s.lockoutKey(auth, req.ClientID, req.Credential)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.IsLocked(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
			return nil, true
		}
	}
	result, err := auth.Authenticate(ctx.Request().Context(), &AuthRequest{
		Provider:        req.Provider,
		Credential:      req.Credential,
		ClientID:        req.ClientID,
		Scope:           req.Scope,
		State:           req.State,
		LoginHint:       req.LoginHint,
		ACRValues:       splitScope(req.ACRValues),
		UILocales:       splitScope(req.UILocales),
		RequestedClaims: oauth.CloneRawJSON(req.Claims),
	})
	if err != nil {
		s.handleAuthFailure(ctx, req, lockKey, err)
		return nil, true
	}
	if s.rejectDeactivatedUser(ctx, req, result.UserID) {
		return nil, true
	}
	// A single legit login resets the brute-force budget (before risk evaluation).
	if s.accountLockout != nil && lockKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), lockKey)
	}
	return result, false
}

// handleAuthFailure writes the authentication-failure response: it attributes the
// failure to per-account lockout (and emits account_locked when that trips)
// BEFORE the generic login_failure audit, then collapses to invalid_credentials
// — UNLESS the authenticator flagged the failure as a stateful ceremony problem
// (core.ErrCeremonySessionInvalid), in which case it renders the SAME
// oracle-safe 404 session_invalid a ceremony's own dedicated endpoint would
// (e.g. WebAuthn's /webauthn/login/*): a client must not be able to tell
// "unknown session" from "unknown user" by response shape, nor tell it
// reached that state via /auth/login vs. the ceremony's own endpoint.
func (s *Server) handleAuthFailure(ctx HandlerContext, req *login.Request, lockKey string, err error) {
	defer s.notifyLoginFailedHook(ctx, req, core.ErrInvalidCredentials)
	s.logErrorCtx(ctx, "authentication failed", "provider", req.Provider, "error", err)
	if s.accountLockout != nil && lockKey != "" {
		if locked, until, _ := s.accountLockout.RegisterFailure(ctx.Request().Context(), lockKey); locked {
			s.recordAccountLocked(ctx, req.ClientID, req.Provider, lockKey, until)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
			return
		}
	}
	if errors.Is(err, core.ErrCeremonySessionInvalid) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrSessionInvalid)
		ctx.JSON(http.StatusNotFound, s.authzErrorBodyWithState(ctx, core.ErrSessionInvalid, req.State))
		return
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrInvalidCredentials)
	ctx.JSON(http.StatusUnauthorized, s.authzErrorBodyWithState(ctx, core.ErrInvalidCredentials, req.State))
}

// rejectDeactivatedUser enforces SCIM deprovisioning (RFC 7643 active=false)
// and the optional user-lifecycle authentication gate: even with a correct
// credential, an unavailable account MUST NOT obtain tokens.
// Called AFTER credential verification, BEFORE any token/session side effect, so
// an IdP connector that PATCHed active=false actually revokes access. Collapses
// to account_locked (an unavailable account, not a credential oracle: the
// credential already verified). No UserProvider skips only the SCIM leg; no
// lifecycle store skips only the lifecycle leg. Returns true (with a response
// written) when the login must be rejected.
func (s *Server) rejectDeactivatedUser(ctx HandlerContext, req *login.Request, userID string) bool {
	if s.userProvider != nil {
		u, uerr := s.userProvider.GetByID(ctx.Request().Context(), userID)
		if uerr == nil && u != nil && !u.IsActive() {
			s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrAccountLocked)
			ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrAccountLocked, req.State))
			return true
		}
	}
	return s.rejectLifecycleBlockedUser(ctx, req, userID)
}

// lockoutKey derives the per-account brute-force lockout key. An authenticator
// that implements LockoutKeyer reports its OWN canonical, normalized identity
// field — authoritative: a credential it declares unkeyable ("") skips the gate
// rather than falling back to the spoofable field precedence (which an attacker
// could defeat by injecting a higher-precedence field the authenticator ignores,
// or by varying case/whitespace). Authenticators without it use the generic
// security.LockoutKey precedence (correct when their identity field is the first
// present, e.g. password's username).
func (s *Server) lockoutKey(auth Authenticator, clientID string, cred map[string]string) string {
	if lk, ok := auth.(LockoutKeyer); ok {
		id := lk.LockoutIdentity(cred)
		if id == "" {
			return ""
		}
		return clientID + ":" + id
	}
	return security.LockoutKey(clientID, cred)
}

// enforceLoginACR applies OIDC §3.1.2.6 / §5.5.1.1 ACR enforcement: the RP may
// demand ACR values via acr_values OR the claims parameter's id_token.acr entry,
// honored with identical strictness. Empty union = no constraint; a present list
// with no matching AchievedACR fails with the spec error (oracle-safe — the
// achieved ACR is never revealed). Returns true when it wrote an error response.
func (s *Server) enforceLoginACR(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	acrList := splitScope(req.ACRValues)
	if len(req.Claims) > 0 {
		acrList = append(acrList, oauth.RequestedACRFromClaims(req.Claims)...)
	}
	if len(acrList) > 0 && !slices.Contains(acrList, result.AchievedACR) {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrUnmetAuthReqs)
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, core.ErrUnmetAuthReqs, req.State))
		return true
	}
	return false
}

// enforceLoginMaxAge enforces OIDC Core §3.1.2.6 max_age. Fresh
// credentials always satisfy any max_age window (AuthTime=now).
func (s *Server) enforceLoginMaxAge(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if req.MaxAge == nil {
		return false
	}
	// max_age=0 → require fresh auth (user provided credentials ✓).
	// max_age=N → auth must be within N seconds (AuthTime=now ✓).
	// Issuance path sets AuthTime = time.Now() in tokens.
	return false
}

// rejectUnverifiedEmail returns true when mandatory email verification is
// enabled AND the authenticated user's email is not yet verified. The check
// occurs AFTER credential verification (oracle-safe: an attacker who knows
// the password cannot distinguish "user doesn't exist" from "unverified").
func (s *Server) rejectUnverifiedEmail(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	if !s.signupRequireVerification {
		return false
	}
	if s.userProvider == nil {
		return false
	}
	u, uerr := s.userProvider.GetByID(ctx.Request().Context(), result.UserID)
	// Fail closed: a store error or missing record cannot confirm verified status.
	if uerr != nil || u == nil || u.Attributes["email_verified"] != "true" {
		s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrEmailNotVerified)
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrEmailNotVerified, req.State))
		return true
	}
	return false
}

// rejectExpiredPassword returns true when the operator has configured
// PasswordPolicyConfig.MaxAgeDays > 0 (via WithPasswordPolicy) AND this login
// used the password factor AND the credential has aged past that window.
// Runs AFTER credential verification, alongside rejectUnverifiedEmail (same
// call site, same shape): the user has ALREADY proved they hold the CURRENT
// password, so "expired" here is a POLICY-STATE signal the client must react
// to (route the user through a forced change-password flow before retrying),
// NOT a credential-validity oracle — an attacker without the correct password
// never reaches this check, so a distinct code leaks nothing about whether a
// guessed password was ever valid (AGENTS.md §3 Anti-Enumeration).
//
// Fails OPEN (returns false = proceed) at every point the signal is
// unavailable: no policy wired, MaxAgeDays<=0, this login didn't use the
// password factor (result.AuthMethods lacks core.AMRPassword — e.g. WebAuthn/
// federated logins are unaffected), no PasswordCredentialStore wired, the
// wired store doesn't implement core.PasswordAgeReader, or the age lookup
// errors. A deployment that hasn't opted in (or hits any of those gaps) is
// byte-identical to before this feature.
func (s *Server) rejectExpiredPassword(ctx HandlerContext, req *login.Request, result *AuthResult) bool {
	maxAgeDays := s.passwordMaxAgeDays()
	if maxAgeDays <= 0 || !slices.Contains(result.AuthMethods, core.AMRPassword) {
		return false
	}
	reader, ok := s.passwordCredentialStore.(core.PasswordAgeReader)
	if !ok {
		return false
	}
	changedAt, err := reader.PasswordChangedAt(ctx.Request().Context(), result.UserID)
	if err != nil {
		return false
	}
	age, maxAge := time.Since(changedAt), time.Duration(maxAgeDays)*24*time.Hour
	if age < maxAge {
		s.recordPasswordExpiring(ctx, req, result, maxAge-age)
		return false
	}
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, core.ErrPasswordExpired)
	ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, core.ErrPasswordExpired, req.State))
	return true
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

func (s *Server) countLoginSessions(ctx context.Context, userID string) (int, error) {
	if s.sessionMgr == nil {
		return 0, nil
	}
	sessions, err := s.sessionMgr.ListByUser(ctx, userID)
	if err != nil {
		return 0, err
	}
	return len(sessions), nil
}

func (s *Server) existingLoginDevice(ctx context.Context, userID, fingerprint string) *device.Device {
	existing, err := s.deviceStore.GetByFingerprint(ctx, userID, fingerprint)
	if err != nil || existing == nil {
		return nil
	}
	if days := int(time.Since(existing.LastSeenAt).Hours() / 24); days > 0 {
		existing.TrustScore = device.DecayTrustScore(existing.TrustScore, days)
	}
	return existing
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
	requestCtx := ctx.Request().Context()
	ip := audit.ClientIP(ctx.Request())
	secCtx := device.BuildSecurityContext(s.deviceStore, func(uid string) (int, error) {
		return s.countLoginSessions(requestCtx, uid)
	}, userID, fp, ip)
	if secCtx != nil && secCtx.PreviousLogin != nil {
		secCtx.PreviousLogin.Location = locationSummary(ctx)
	}
	existingDevice := s.existingLoginDevice(requestCtx, userID, fp)
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
	if err := s.deviceStore.Upsert(requestCtx, d); err != nil {
		s.logger.Error("device: failed to register", "user", userID, "error", err)
		return nil
	}
	return &deviceContext{ID: d.ID, Type: string(dp.Type), Platform: dp.Platform, OSVersion: dp.OSVersion,
		BrowserName: dp.BrowserName, DeviceName: dp.DeviceName,
		IsNew: secCtx != nil && secCtx.DeviceIsNew, Fingerprint: fp,
		SecurityCtx: secCtx, TrustScore: trustScore}
}

// codeFlowSession resolves the canonical OP session for an authorization-code
// login. Precedence: an authenticator-resumed session (AuthResult.SessionID)
// is validated against the live session store; a fresh login that asked for
// one (AuthResult.CreateSession) mints it through the same createSession path
// the direct-mint branch uses (quotas, per-device caps, trust meta). Returns
// "" when no session manager is wired, the login carried no session semantics,
// or the session could not be created/validated (fail-open with an audit/log
// trail — the login itself never fails on a session-layer outage).
func (s *Server) codeFlowSession(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) string {
	if s.sessionMgr == nil {
		return ""
	}
	if result.SessionID != "" {
		sess, err := s.sessionMgr.Get(ctx.Request().Context(), result.SessionID)
		if err == nil && sess != nil && !sess.Revoked && !sess.IsExpired() && sess.UserID == result.UserID {
			return sess.ID
		}
		s.logger.Error("code flow: resumed session invalid, dropping sid", "session", result.SessionID, "error", err)
		return ""
	}
	if !result.CreateSession {
		return ""
	}
	sess, err := s.createSession(ctx, result.UserID, client.ID, client.TenantID, req.Scope, result.AuthTime)
	if err != nil {
		s.logger.Error("code flow: session creation failed, login continues without sid", "error", err, "user", result.UserID)
		return ""
	}
	return sess.ID
}
