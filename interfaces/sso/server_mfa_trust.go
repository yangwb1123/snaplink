package sso

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/domains/conditionalaccess"
	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// respFieldDeviceToken is the /auth/mfa success-response field carrying a
// freshly minted "remember this device" grant. Matches the field name
// POST /me/trusted-devices/trust already returns (protocols/selfservice/
// selfserviceaccount/trusted_devices.go's response map) so client code has
// ONE field name to look for across both endpoints.
const respFieldDeviceToken = "device_token"

// finishLoginWithDeviceTrust wraps finishLogin for the MFA-resume path only:
// when the caller asked to remember this device (trust_device=true) and a
// TrustedDeviceStore is wired, it arranges for a trust grant to be minted
// LAZILY — only if finishLogin's shared response pipeline actually reaches
// its terminal 2xx write (see mfaTrustDeviceCtx below). That means a device
// is trusted only when the login succeeds end-to-end (tokens minted), never
// on a downstream failure inside finishLogin (session-store outage,
// max-active-sessions, …) even though the MFA factor itself already
// verified. trustDevice=false or no store wired is a byte-identical no-op:
// finishLogin runs exactly as it did before this feature existed, and the
// non-MFA /auth/login path (which never calls this wrapper) is untouched.
func (s *Server) finishLoginWithDeviceTrust(ctx HandlerContext, result *AuthResult, req login.Request, client *Client, subjectID string, trustDevice bool) {
	if !trustDevice || s.trustedDeviceStore == nil {
		s.finishLogin(ctx, result, req, client)
		return
	}
	s.finishLogin(s.wrapForDeviceTrust(ctx, subjectID, client.ID), result, req, client)
}

// wrapForDeviceTrust returns a HandlerContext that mints a trusted-device
// grant for (subjectID, clientID) — the SAME core.TrustedDeviceStore.Trust
// call HandleTrustMyDevice makes (protocols/selfservice/selfserviceaccount/
// trusted_devices.go) — lazily and at most once, only if finishLogin goes on
// to write a genuine 2xx success body. A Trust error is logged and otherwise
// swallowed: the user already proved their MFA factor, so failing to
// remember the device degrades UX only, never the login itself (fail-open
// on a best-effort side effect, same philosophy as AGENTS.md's Fail Modes
// table even though TrustedDeviceStore isn't literally listed there).
func (s *Server) wrapForDeviceTrust(ctx HandlerContext, subjectID, clientID string) HandlerContext {
	return &mfaTrustDeviceCtx{
		HandlerContext: ctx,
		mint: func() (string, bool) {
			token, device, err := s.trustedDeviceStore.Trust(ctx.Request().Context(), subjectID, clientID, "", s.TrustedDeviceTTL())
			if err != nil {
				s.logger.Error("mfa: trust device failed", "error", err, "user", subjectID, "client", clientID)
				return "", false
			}
			s.recordMFADeviceTrusted(ctx, subjectID, clientID, device.ID)
			return token, true
		},
	}
}

// mfaTrustDeviceCtx overrides HandlerContext.JSON to inject the minted
// device_token into finishLogin's terminal response body, without changing
// finishLogin's signature or touching any file outside this one — it only
// shadows JSON for the ONE call finishLogin makes while handling this
// request. mint runs at most once (sync.Once): only a 2xx map[string]any
// body triggers it, so every error path (any non-2xx status, or a body that
// isn't a map — e.g. the form_post / JARM authorization_code render modes,
// which never call ctx.JSON at all) passes through byte-identical to the
// unwrapped ctx, and no orphan grant is ever minted without also being
// returned to the caller in that same response.
type mfaTrustDeviceCtx struct {
	HandlerContext
	once  sync.Once
	token string
	ok    bool
	mint  func() (string, bool)
}

func (c *mfaTrustDeviceCtx) JSON(code int, v any) {
	if code >= 200 && code < 300 {
		if body, isMap := v.(map[string]any); isMap {
			if body[KeyError] == nil {
				c.once.Do(func() { c.token, c.ok = c.mint() })
				if c.ok {
					body[respFieldDeviceToken] = c.token
				}
			}
		}
	}
	c.HandlerContext.JSON(code, v)
}

type loginContinuationCtx struct {
	HandlerContext
	server *Server
	state  mfaResumeState
	client *Client
}

func (s *Server) wrapForLoginContinuation(ctx HandlerContext, result *AuthResult, req login.Request, client *Client, trustDevice bool) HandlerContext {
	if s.consentStore == nil || s.loginTransactionStore == nil {
		return ctx
	}
	req.Credential = nil
	req.DeviceToken = ""
	req.LoginTransactionID = ""
	state := mfaResumeState{
		Result: result, Request: req, CredentialHealth: result.CredentialHealth,
		PolicyScopeRestriction: req.PolicyScopeRestriction,
		AuthenticationComplete: true, TrustDevice: trustDevice,
	}
	return &loginContinuationCtx{HandlerContext: ctx, server: s, state: state, client: client}
}

func (c *loginContinuationCtx) JSON(code int, value any) {
	errorCode, _, ok := authorizationErrorFields(value)
	if !ok || errorCode != ErrConsentRequired {
		c.HandlerContext.JSON(code, value)
		return
	}
	id, err := c.server.issueLoginTransaction(c, &c.state, c.client)
	if err != nil {
		c.HandlerContext.JSON(http.StatusInternalServerError, c.server.authzErrorBody(c, ErrInternal))
		return
	}
	body := authorizationResponseMap(value)
	body[login.KeyLoginTransactionID] = id
	c.HandlerContext.JSON(code, body)
}

func (s *Server) issueLoginTransaction(ctx HandlerContext, state *mfaResumeState, client *Client) (string, error) {
	blob, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	id, err := newMFAChallengeID()
	if err != nil {
		return "", err
	}
	ttl := s.loginTransactionTTL
	if ttl <= 0 {
		ttl = spi.DefaultMFAChallengeTTL
	}
	now := time.Now()
	subjectID := ""
	if state.Result != nil {
		subjectID = state.Result.UserID
	}
	err = s.loginTransactionStore.Put(ctx.Request().Context(), &spi.MFAChallenge{
		ID: id, SubjectID: subjectID, ClientID: client.ID,
		CreatedAt: now, ExpiresAt: now.Add(ttl), RequestState: blob,
	})
	return id, err
}

func (s *Server) resumeLoginTransaction(ctx HandlerContext, submitted login.Request) {
	challenge, state, ok := s.consumeLoginTransaction(ctx, submitted)
	if !ok {
		return
	}
	client, ok := s.loginTransactionClient(ctx, challenge, state)
	if !ok {
		return
	}
	if state.FederatedReturn {
		s.resumeFederatedLoginTransaction(ctx, state, client)
		return
	}
	state.Request.ConsentChallengeID = submitted.ConsentChallengeID
	state.Request.ConsentDecision = submitted.ConsentDecision
	authzCtx := s.wrapAuthorizationResponse(ctx, &state.Request, client)
	if s.rejectDeactivatedUser(authzCtx, &state.Request, state.Result.UserID) ||
		s.resumeLoginResidualGates(authzCtx, state, client) {
		return
	}
	if s.denyLoginConsent(authzCtx, state, client) {
		return
	}
	nextCtx := s.wrapForLoginContinuation(authzCtx, state.Result, state.Request, client, state.TrustDevice)
	s.finishLoginWithDeviceTrust(
		nextCtx, state.Result, state.Request, client, challenge.SubjectID, state.TrustDevice,
	)
}

func (s *Server) handleLoginContinuationOrPromptNone(ctx HandlerContext, req login.Request) bool {
	if req.LoginTransactionID != "" {
		s.resumeLoginTransaction(ctx, req)
		return true
	}
	prompts := oidc.ParsePromptValues(req.Prompt)
	if !oidc.PromptHasNone(prompts) {
		return false
	}
	s.handlePromptNone(ctx, prompts, &req)
	return true
}

func (s *Server) consumeLoginTransaction(ctx HandlerContext, submitted login.Request) (*spi.MFAChallenge, *mfaResumeState, bool) {
	if s.loginTransactionStore == nil || submitted.LoginTransactionID == "" ||
		submitted.ClientID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	challenge, err := s.loginTransactionStore.Consume(ctx.Request().Context(), submitted.LoginTransactionID)
	if err != nil || challenge == nil || challenge.ClientID != submitted.ClientID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	state := &mfaResumeState{}
	if json.Unmarshal(challenge.RequestState, state) != nil ||
		!validLoginTransactionState(challenge, state, submitted) {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	state.Request.PolicyScopeRestriction = cloneOptionalScopes(state.PolicyScopeRestriction)
	return challenge, state, true
}

func (s *Server) resumeFederatedLoginTransaction(ctx HandlerContext, state *mfaResumeState, client *Client) {
	authzCtx := s.wrapAuthorizationResponse(ctx, &state.Request, client)
	if state.FederatedError != "" {
		status := http.StatusUnauthorized
		if state.FederatedError == ErrAccessDenied {
			status = http.StatusForbidden
		}
		authzCtx.JSON(status, s.authzErrorBodyWithState(authzCtx, state.FederatedError, state.Request.State))
		return
	}
	if state.Result == nil || s.rejectDeactivatedUser(authzCtx, &state.Request, state.Result.UserID) {
		return
	}
	state.Result.CredentialHealth = state.CredentialHealth
	if s.runPostAuthenticateHook(authzCtx, &state.Request, client, state.Result) ||
		s.runPostCredentialGates(authzCtx, &state.Request, state.Result, client) {
		return
	}
	nextCtx := s.wrapForLoginContinuation(authzCtx, state.Result, state.Request, client, false)
	s.finishLogin(nextCtx, state.Result, state.Request, client)
}

func (s *Server) queueFederatedContinuation(
	ctx HandlerContext, resume *federatedAuthorizationState, client *Client,
	result *AuthResult, errorCode string,
) {
	if errorCode != "" {
		result = nil
		if errorCode != ErrAccessDenied {
			errorCode = ErrCallbackFailed
		}
	} else if result == nil || result.UserID == "" {
		result, errorCode = nil, ErrCallbackFailed
	} else if result.Provider == "" {
		result.Provider = resume.Provider
	} else if result.Provider != resume.Provider {
		result, errorCode = nil, ErrCallbackFailed
	}
	state := &mfaResumeState{
		Result: result, Request: resume.Request, AuthenticationComplete: true,
		FederatedReturn: true, FederatedError: errorCode,
	}
	id, err := s.issueLoginTransaction(ctx, state, client)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	target, err := federatedContinuationURI(client, resume.Request, id)
	if err != nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	ctx.Redirect(http.StatusFound, target)
}

// ResumeFederatedLogin lets a dedicated protocol callback (notably SAML ACS)
// hand a validated identity back to the same one-time OAuth login pipeline.
func (s *Server) ResumeFederatedLogin(
	w http.ResponseWriter, r *http.Request, state string, result *AuthResult,
) bool {
	if _, marked := federatedProviderFromState(state); !marked {
		return false
	}
	ctx := handlerContextForRequest(w, r)
	resume, client, ok := s.consumeFederatedAuthorization(ctx, state)
	if ok {
		s.queueFederatedContinuation(ctx, resume, client, result, "")
	}
	return true
}

func authenticationHasMFA(result *AuthResult) bool {
	return result != nil && slices.Contains(result.AuthMethods, "mfa")
}

func cloneOptionalScopes(scopes []string) []string {
	if scopes == nil {
		return nil
	}
	return append([]string{}, scopes...)
}

func mergeScopeRestrictions(current, next []string) []string {
	if current == nil {
		return cloneOptionalScopes(next)
	}
	return restrictGrantedScopes(current, next)
}

func policyScopeRemovedAll(granted, restricted, policy []string) bool {
	return policy != nil && len(granted) > 0 && len(restricted) == 0
}

func (s *Server) rejectPolicyScopeGrant(ctx HandlerContext, req *login.Request) bool {
	s.recordLoginFailure(ctx, req.ClientID, req.Provider, ErrInvalidScope)
	ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidScope, req.State))
	return true
}

func (s *Server) loginTransactionClient(ctx HandlerContext, challenge *spi.MFAChallenge, state *mfaResumeState) (*Client, bool) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return nil, false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || client == nil || !client.Active || !clientTenantOK(ctx, client) {
		ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrInactiveClient, state.Request.State))
		return nil, false
	}
	provider := state.Request.Provider
	if state.Result != nil && state.Result.Provider != "" {
		provider = state.Result.Provider
	}
	if s.residencyGateLogin(ctx, client.ID, provider, client.TenantID) {
		return nil, false
	}
	return client, true
}

func (s *Server) denyLoginConsent(ctx HandlerContext, state *mfaResumeState, client *Client) bool {
	decision := state.Request.ConsentDecision
	if decision == "" || decision == "allow" {
		return false
	}
	if decision != "deny" || s.consentStore == nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, state.Request.State))
		return true
	}
	granted, halted := s.validateAndAuthorizeScope(ctx, &state.Request, client)
	if halted {
		return true
	}
	state.Request.Scope = granted
	valid := s.consentChallenges.Consume(
		state.Request.ConsentChallengeID, state.Result.UserID, client.ID,
		granted, state.Request.AuthorizationDetails,
	)
	if !valid {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, state.Request.State))
		return true
	}
	s.recordConsentEvent(ctx, audit.EventConsentDenied, audit.OutcomeSuccess, state.Result.UserID, client.ID, granted)
	ctx.JSON(http.StatusForbidden, s.authzErrorBodyWithState(ctx, ErrAccessDenied, state.Request.State))
	return true
}

// recordMFADeviceTrusted mirrors selfserviceaccount.recordDeviceTrusted's
// audit shape (same event type, outcome, and device_id meta key) so a SIEM
// query for EventDeviceTrusted sees one consistent event regardless of which
// of the two entry points — POST /me/trusted-devices/trust, or this
// MFA-step checkbox — minted the grant. Never records the token or its
// hash, matching the self-service handler's same invariant.
func (s *Server) recordMFADeviceTrusted(ctx HandlerContext, userID, clientID, deviceID string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventDeviceTrusted,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  userID,
		ClientID: clientID,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, "device_id", deviceID)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// EnforceRefreshConditionalAccess is the refresh-token Policy Enforcement
// Point. It reuses the login signal builder so policy changes, live device/geo
// posture, group membership, and scope restrictions take effect on the next
// rotation instead of waiting for the original session to expire.
func (s *Server) EnforceRefreshConditionalAccess(ctx core.HandlerContext, client *core.Client, info *oauth.RefreshToken, scopes []string) ([]string, bool) {
	scopes, halted := s.applySessionScopeCeiling(ctx, info.SID, client.ID, scopes)
	if halted {
		return nil, true
	}
	if s.capEngine == nil || !s.capEngine.Config().Enforce {
		return scopes, false
	}
	result := &AuthResult{UserID: info.UserID, AuthMethods: info.Amr, AchievedACR: info.Acr, AuthTime: info.AuthTime, SessionID: info.SID}
	req := &login.Request{ClientID: client.ID, Scope: scopes}
	dec, err := s.capEngine.Evaluate(ctx.Request().Context(), s.buildAccessContext(ctx, result, req, client))
	if err != nil {
		s.logger.Error("refresh conditional access unavailable; failing open", "error", err,
			"user", info.UserID, "client", client.ID)
		return scopes, false
	}
	if s.metrics != nil {
		s.metrics.ObserveConditionalAccessDecision(string(dec.Verdict))
	}
	if dec.Log {
		s.logger.Info("refresh conditional access policy matched", "policy", dec.MatchedPolicy,
			"verdict", dec.Verdict, "user", info.UserID, "client", client.ID)
	}
	if dec.Verdict == conditionalaccess.VerdictDeny {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidGrant))
		return nil, true
	}
	if dec.Verdict == conditionalaccess.VerdictRequireStepUp && !authenticationHasMFA(result) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, security.ErrInsufficientUserAuthentication))
		return nil, true
	}
	if len(dec.RestrictScopes) > 0 {
		restricted := restrictGrantedScopes(scopes, dec.RestrictScopes)
		if policyScopeRemovedAll(scopes, restricted, dec.RestrictScopes) {
			ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidScope))
			return nil, true
		}
		scopes = restricted
	}
	return scopes, false
}

func (s *Server) applySessionScopeCeiling(ctx core.HandlerContext, sessionID, clientID string, scopes []string) ([]string, bool) {
	if sessionID == "" || s.sessionMgr == nil {
		return scopes, false
	}
	session, err := s.sessionMgr.Get(ctx.Request().Context(), sessionID)
	if err != nil || session == nil || session.ClientID != clientID || len(session.AuthorizedScopes) == 0 {
		return scopes, false
	}
	restricted := restrictGrantedScopes(scopes, session.AuthorizedScopes)
	if policyScopeRemovedAll(scopes, restricted, session.AuthorizedScopes) {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrInvalidScope))
		return nil, true
	}
	return restricted, false
}

func (s *Server) buildLoginAccessContext(ctx HandlerContext, result *AuthResult, req *login.Request, client *Client) conditionalaccess.AccessContext {
	ac := s.buildAccessContext(ctx, result, req, client)
	if ac.ConcurrentSessionsKnown {
		ac.ConcurrentSessions++
	}
	return ac
}

func (s *Server) withConcurrentSessions(ctx context.Context, ac conditionalaccess.AccessContext) conditionalaccess.AccessContext {
	if s.sessionMgr == nil || ac.Subject == "" {
		return ac
	}
	sessions, err := s.sessionMgr.ListByUser(ctx, ac.Subject)
	if err != nil {
		return ac
	}
	for _, session := range sessions {
		if session != nil && !session.Revoked && !session.IsExpired() && session.ClientID == ac.ClientID {
			ac.ConcurrentSessions++
		}
	}
	ac.ConcurrentSessionsKnown = true
	return ac
}

func (s *Server) conditionalAccessSessionCreatedAt(ctx core.HandlerContext, sessionID string) time.Time {
	if sessionID == "" || s.sessionMgr == nil {
		return time.Time{}
	}
	session, err := s.sessionMgr.Get(ctx.Request().Context(), sessionID)
	if err != nil || session == nil {
		return time.Time{}
	}
	return session.CreatedAt
}
