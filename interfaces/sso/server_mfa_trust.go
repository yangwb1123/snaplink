package sso

import (
	"encoding/json"
	"net/http"
	"sync"
	"time"

	"github.com/yangwb1123/snaplink/internal/auth/login"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oidc"
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

type authorizationResponseCtx struct {
	HandlerContext
	server *Server
	req    login.Request
	client *Client
}

func (s *Server) wrapAuthorizationResponse(ctx HandlerContext, req *login.Request, client *Client) HandlerContext {
	if req.RedirectURI == "" || !client.IsRedirectURIValid(req.RedirectURI) {
		return ctx
	}
	if s.oauth21Strict && !isSecureRedirectURI(req.RedirectURI) {
		return ctx
	}
	return &authorizationResponseCtx{HandlerContext: ctx, server: s, req: *req, client: client}
}

func (c *authorizationResponseCtx) JSON(code int, value any) {
	errorCode, description, ok := authorizationErrorFields(value)
	if !ok || errorCode == ErrMFARequired || errorCode == ErrConsentRequired {
		c.HandlerContext.JSON(code, value)
		return
	}
	if oidc.IsJARMResponseMode(c.req.ResponseMode) && c.writeJARMError(errorCode, description) {
		return
	}
	body := authorizationResponseMap(value)
	body["redirect_uri_validated"] = true
	c.HandlerContext.JSON(code, body)
}

func (c *authorizationResponseCtx) writeJARMError(code, description string) bool {
	signer, ok := c.server.jarmSignerForClient(c.client)
	if !ok {
		return false
	}
	if c.req.ResponseMode != oidc.ResponseModeFormPostJWT && c.Request().Method != http.MethodGet {
		response, err := oidc.SignJARMErrorResponse(
			c.Request().Context(), signer, c.server.resolveIssuer(c), c.client.ID,
			code, description, c.req.State,
		)
		if err != nil {
			return false
		}
		c.HandlerContext.JSON(http.StatusOK, map[string]any{oidc.KeyResponse: response})
		return true
	}
	return oidc.RenderJARMErrorResponse(
		c.HandlerContext, signer, c.req.ResponseMode, c.req.RedirectURI,
		c.server.resolveIssuer(c), c.client.ID, code, description, c.req.State,
	)
}

func authorizationErrorFields(value any) (string, string, bool) {
	switch body := value.(type) {
	case map[string]string:
		code := body[KeyError]
		return code, body[KeyErrorDescription], code != ""
	case map[string]any:
		code, _ := body[KeyError].(string)
		description, _ := body[KeyErrorDescription].(string)
		return code, description, code != ""
	default:
		return "", "", false
	}
}

func authorizationResponseMap(value any) map[string]any {
	result := map[string]any{}
	switch body := value.(type) {
	case map[string]string:
		for key, item := range body {
			result[key] = item
		}
	case map[string]any:
		for key, item := range body {
			result[key] = item
		}
	}
	return result
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
	err = s.loginTransactionStore.Put(ctx.Request().Context(), &spi.MFAChallenge{
		ID: id, SubjectID: state.Result.UserID, ClientID: client.ID,
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
		submitted.ClientID == "" || submitted.ConsentChallengeID == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	challenge, err := s.loginTransactionStore.Consume(ctx.Request().Context(), submitted.LoginTransactionID)
	if err != nil || challenge == nil || challenge.ClientID != submitted.ClientID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	state := &mfaResumeState{}
	if json.Unmarshal(challenge.RequestState, state) != nil || !state.AuthenticationComplete ||
		state.Result == nil || state.Result.UserID != challenge.SubjectID {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBodyWithState(ctx, ErrInvalidRequest, submitted.State))
		return nil, nil, false
	}
	return challenge, state, true
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
	if s.residencyGateLogin(ctx, client.ID, state.Result.Provider, client.TenantID) {
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
