package sso

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/internal/handler"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/spi"
)

type mfaResumeState struct {
	Result           *AuthResult       `json:"result"`
	Request          login.Request     `json:"request"`
	CredentialHealth *CredentialHealth `json:"credential_health,omitempty"`
}

// issueMFAChallenge mints a single-use challenge ID + persists the
// frozen login state for resumption. Writes the mfa_required response.
// Audit: emits mfa_required (success outcome — primary credential was
// fine, the user just hasn't completed step-up yet).
func (s *Server) issueMFAChallenge(ctx HandlerContext, result *AuthResult, req login.Request, client *Client) {
	id, ok := s.persistMFAChallenge(ctx, result, req, client)
	if !ok {
		return
	}

	s.recordMFARequiredAudit(ctx, result, client, id)

	methods := s.mfaProvider.SupportedMethods()
	// Metric: count one challenge per issuance, labeled by the FIRST
	// supported method (the user picks among them downstream). Zero
	// traffic when metrics aren't wired.
	if s.metrics != nil && len(methods) > 0 {
		s.metrics.MFAChallengesTotal.WithLabelValues(methods[0]).Inc()
	}

	resp := s.buildMFAChallengeResponse(ctx, result, req, id, methods)
	// HTTP 200 (not 400) — the primary credential was accepted; the
	// pending state is a normal step in the flow, not an error.
	ctx.JSON(http.StatusOK, resp)
}

// persistMFAChallenge marshals the frozen login state, mints a single-use
// challenge ID, and stores it. Returns the ID and ok=true on success; on
// any of the three failures (marshal, mint, store) it writes the verbatim
// 500 ErrInternal response and returns ok=false.
func (s *Server) persistMFAChallenge(ctx HandlerContext, result *AuthResult, req login.Request, client *Client) (string, bool) {
	// Set CredentialHealth explicitly: AuthResult.CredentialHealth is
	// json:"-", so the embedded Result drops it; this side channel
	// preserves it for the post-step-up audit in finishLogin.
	stateBlob, err := json.Marshal(&mfaResumeState{Result: result, Request: req, CredentialHealth: result.CredentialHealth})
	if err != nil {
		s.logger.Error("mfa: failed to marshal resume state", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return "", false
	}
	id, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("mfa: failed to mint challenge id", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return "", false
	}
	ttl := s.mfaChallengeTTL
	if ttl <= 0 {
		ttl = spi.DefaultMFAChallengeTTL
	}
	now := time.Now()
	challenge := &spi.MFAChallenge{
		ID:           id,
		SubjectID:    result.UserID,
		ClientID:     client.ID,
		CreatedAt:    now,
		ExpiresAt:    now.Add(ttl),
		RequestState: stateBlob,
	}
	if err := s.mfaChallengeStore.Put(ctx.Request().Context(), challenge); err != nil {
		s.logger.Error("mfa: failed to persist challenge", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return "", false
	}
	return id, true
}

// recordMFARequiredAudit emits the mfa_required audit event (no-op without
// auditor). Outcome is success — the primary credential was fine, the user
// just hasn't completed step-up yet.
func (s *Server) recordMFARequiredAudit(ctx HandlerContext, result *AuthResult, client *Client, id string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventMFARequired,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  result.UserID,
		ClientID: client.ID,
		Provider: result.Provider,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, KeyMFAChallengeID, id)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// buildMFAChallengeResponse assembles the mfa_required response body, running
// the per-method spi.MFABeginner dispatch.
func (s *Server) buildMFAChallengeResponse(ctx HandlerContext, result *AuthResult, req login.Request, id string, methods []string) map[string]any {
	resp := map[string]any{
		KeyError:          ErrMFARequired, // top-level error field so SPAs treating non-2xx-but-pending uniformly still surface it
		KeyMFAChallengeID: id,
		KeyMFAMethods:     methods,
		KeyIss:            s.resolveIssuer(ctx),
	}

	// spi.MFABeginner dispatch: providers needing server-side state
	// (WebAuthn challenge issuance, push notification fan-out, …)
	// get one Begin call per supported method. Results are bucketed
	// per method so clients picking method X read only their slice.
	// Per-method failure is non-fatal — the method stays in
	// mfa_methods but without an attached method_data entry; the
	// client can retry out-of-band or pick a different factor.
	if beginner, ok := s.mfaProvider.(spi.MFABeginner); ok && len(methods) > 0 {
		methodData := make(map[string]map[string]string, len(methods))
		for _, method := range methods {
			data, berr := beginner.Begin(ctx.Request().Context(), result.UserID, method)
			if berr != nil {
				s.logger.Error("mfa: begin failed", "method", method, "user", result.UserID, "error", berr)
				continue
			}
			if len(data) > 0 {
				methodData[method] = data
			}
		}
		if len(methodData) > 0 {
			resp[KeyMFAMethodData] = methodData
		}
	}

	if req.State != "" {
		resp[KeyState] = req.State
	}
	return resp
}

// handleMFAComplete is the POST /auth/mfa endpoint. The client presents
// the challenge ID + factor name + method-specific params; on success
// the server replays finishLogin against the frozen state so the
// response shape matches what the no-MFA path would have returned.
//
// Oracle-leak hardening: every failure path (missing challenge,
// expired, wrong method, wrong factor) collapses to the same
// HTTP 400 + error=mfa_invalid response so probes can't distinguish
// the cases.
func (s *Server) handleMFAComplete(ctx HandlerContext) {
	// Observe /auth/mfa duration with outcome label. defer + named
	// outcome lets every return path (auth-invalid, factor-failed,
	// success, transport-error) account uniformly. The Push factor's
	// long polling loop dominates this histogram — operators
	// alerting on push-flow stalls graph p95 here.
	start := time.Now()
	outcome := "failure"
	defer func() {
		if s.metrics != nil {
			s.metrics.MFACompletionDuration.WithLabelValues(outcome).Observe(time.Since(start).Seconds())
		}
	}()

	tokenNoStoreHeaders(ctx)
	if s.mfaProvider == nil || s.mfaChallengeStore == nil {
		// Endpoint is registered unconditionally so discovery doesn't
		// have to be re-derived per request, but without a wired
		// provider it can't do useful work. 404 (not 501) so a probe
		// can't fingerprint the deployment as MFA-capable-but-misconfigured.
		ctx.JSON(http.StatusNotFound, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	// Mark outcome on the one success path; left as "failure" for
	// every other return point.
	_ = outcome

	req, ok := s.parseMFACompleteRequest(ctx)
	if !ok {
		return
	}

	challenge, ok := s.verifyMFAFactor(ctx, req)
	if !ok {
		return
	}
	outcome = "success"

	// Factor verified — decode the frozen state, re-validate the client, and
	// resume the standard post-risk login flow.
	s.resumeLoginAfterMFA(ctx, challenge, req.Method, req.ChallengeID)
}

// mfaCompleteRequest is the POST /auth/mfa payload. Method + ChallengeID are
// mandatory; the flat Code/Assertion convenience fields are folded into Params
// downstream for the opaque spi.MFAProvider dispatch.
type mfaCompleteRequest struct {
	ChallengeID string            `json:"mfa_challenge_id"`
	Method      string            `json:"mfa_method"`
	Params      map[string]string `json:"params"`
	// Top-level convenience fields the flat-form callers prefer
	// (HTML forms, simple clients). When Params is empty we
	// collect the per-method known fields from these.
	Code      string `json:"code"`      // totp
	Assertion string `json:"assertion"` // webauthn
}

// parseMFACompleteRequest binds + validates the /auth/mfa payload. Any bind
// error or missing challenge/method collapses to the verbatim 400 mfa_invalid
// (no audit — these are pre-challenge-lookup malformed requests, not factor
// failures) and returns ok=false.
func (s *Server) parseMFACompleteRequest(ctx HandlerContext) (mfaCompleteRequest, bool) {
	var req mfaCompleteRequest
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return req, false
	}
	if req.ChallengeID == "" || req.Method == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return req, false
	}
	return req, true
}

// verifyMFAFactor consumes the single-use challenge and verifies the presented
// factor. Both the challenge-lookup miss and the factor-verify failure collapse
// to the verbatim 400 mfa_invalid (detail ONLY in the mfa_failure audit) and
// return ok=false. On success it returns the consumed challenge.
func (s *Server) verifyMFAFactor(ctx HandlerContext, req mfaCompleteRequest) (*spi.MFAChallenge, bool) {
	challenge, err := s.mfaChallengeStore.Consume(ctx.Request().Context(), req.ChallengeID)
	if err != nil || challenge == nil {
		s.recordMFAFailure(ctx, "", req.ChallengeID, req.Method, "challenge_invalid")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return nil, false
	}

	// Per-subject MFA brute-force lockout. The first leg (password) already
	// verified, so without throttling the SECOND factor an attacker who knows the
	// password could brute-force a 6-digit OTP unthrottled by minting a fresh
	// single-use challenge per guess. Keyed in a namespace DISTINCT from the
	// password lockout so the two don't cross-trip. A locked subject collapses to
	// the SAME mfa_invalid (no lockout oracle; detail only in the audit).
	mfaKey := mfaLockoutKey(challenge.SubjectID)
	if s.accountLockout != nil && mfaKey != "" {
		if locked, _, _ := s.accountLockout.IsLocked(ctx.Request().Context(), mfaKey); locked {
			s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, "mfa_locked")
			ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
			return nil, false
		}
	}

	// Flat -> Params normalization. The dispatch into spi.MFAProvider is opaque —
	// only the "totp" / "webauthn" contract is known here; richer providers get
	// whatever Params the caller supplies plus the flat code/assertion convenience.
	params := collectMFAParams(req.Params, req.Code, req.Assertion)

	if err := s.mfaProvider.Verify(ctx.Request().Context(), challenge.SubjectID, req.Method, params); err != nil {
		if s.accountLockout != nil && mfaKey != "" {
			_, _, _ = s.accountLockout.RegisterFailure(ctx.Request().Context(), mfaKey)
		}
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, err.Error())
		s.recordMFACompletion(req.Method, "failure")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return nil, false
	}
	if s.accountLockout != nil && mfaKey != "" {
		_ = s.accountLockout.RegisterSuccess(ctx.Request().Context(), mfaKey)
	}
	s.recordMFACompletion(req.Method, "success")
	return challenge, true
}

// mfaLockoutKey namespaces the per-subject MFA brute-force counter so it never
// collides with the password-leg lockout. Empty subject -> unkeyable (skip).
func mfaLockoutKey(subjectID string) string {
	if subjectID == "" {
		return ""
	}
	return "mfa:" + subjectID
}

// resumeLoginAfterMFA decodes the frozen pre-step-up state, folds the verified
// second factor into the AMR (RFC 8176), re-looks-up the client (it may have been
// deactivated / tenant-suspended in the verify window), re-applies the residency
// write-gate from THIS request's serving region, and resumes finishLogin (which
// writes the response — indistinguishable from a non-gated login bar the round
// trip). CredentialHealth is re-attached out-of-band because it is json:"-" and
// doesn't survive the embedded Result round trip.
func (s *Server) resumeLoginAfterMFA(ctx HandlerContext, challenge *spi.MFAChallenge, method, challengeID string) {
	state := &mfaResumeState{}
	if err := json.Unmarshal(challenge.RequestState, state); err != nil {
		s.logger.Error("mfa: failed to decode resume state", "error", err, "challenge", challengeID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	if state.Result == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	state.Result.CredentialHealth = state.CredentialHealth
	state.Result.AuthMethods = handler.WithMFAMethod(state.Result.AuthMethods, method)

	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || client == nil || !client.Active || !clientTenantOK(ctx, client) {
		// Client deactivated/deleted/tenant-suspended between issue and completion:
		// surface inactive_client (not mfa_invalid) so the audit shows it wasn't
		// the factor that failed.
		s.recordMFAFailure(ctx, challenge.SubjectID, challengeID, method, "client_unavailable")
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}
	s.recordMFASuccessEvent(ctx, challenge.SubjectID, client.ID, state.Result.Provider, method, challengeID)
	// Data-residency write-gate on the SECOND leg: the token is minted NOW from
	// THIS request's serving region (same middleware as /auth/login). No resolver
	// wired -> never fires (byte-identical).
	if s.residencyGateLogin(ctx, client.ID, state.Result.Provider, client.TenantID) {
		return
	}
	s.finishLogin(ctx, state.Result, state.Request, client)
}

// recordMFASuccessEvent emits the mfa_success audit event (no-op without auditor).
func (s *Server) recordMFASuccessEvent(ctx HandlerContext, subjectID, clientID, provider, method, challengeID string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:     audit.EventMFASuccess,
		Outcome:  audit.OutcomeSuccess,
		ActorID:  subjectID,
		ClientID: clientID,
		Provider: provider,
		ActorIP:  audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, KeyMFAMethod, method)
	audit.SetMeta(evt, KeyMFAChallengeID, challengeID)
	s.auditor.Record(ctx.Request().Context(), evt)
}

// collectMFAParams normalizes the MFA verification params: explicit Params win,
// with the flat code/assertion convenience fields folded in when absent.
func collectMFAParams(params map[string]string, code, assertion string) map[string]string {
	if params == nil {
		params = make(map[string]string, 2)
	}
	if _, ok := params["code"]; !ok && code != "" {
		params["code"] = code
	}
	if _, ok := params["assertion"]; !ok && assertion != "" {
		params["assertion"] = assertion
	}
	return params
}

// recordMFACompletion increments the MFA completion metric for the
// (method, outcome) pair, but only when the metric is wired AND the
// method appears in the configured provider's SupportedMethods set.
// Restricting to known methods bounds metric cardinality — a
// user-controlled method field would otherwise let attackers spray
// arbitrary labels into Prometheus storage.
func (s *Server) recordMFACompletion(method, outcome string) {
	if s.metrics == nil || s.mfaProvider == nil {
		return
	}
	if slices.Contains(s.mfaProvider.SupportedMethods(), method) {
		s.metrics.MFACompletionsTotal.WithLabelValues(method, outcome).Inc()
	}
}

// recordMFAFailure emits the mfa_failure audit event with the
// operator-visible reason. The wire response is always mfa_invalid;
// reason here is for SIEM investigation, never returned to the client.
func (s *Server) recordMFAFailure(ctx HandlerContext, subjectID, challengeID, method, reason string) {
	audit.RecordMFAFailure(s.auditor, ctx, subjectID, challengeID, method, reason)
}

// newMFAChallengeID mints a 32-byte crypto/rand identifier encoded as
// URL-safe base64 without padding (so it survives query params /
// path segments / form bodies unchanged). 256 bits of entropy — same
// strength as oauth.AuthCodeStore / oauth.DeviceCodeStore identifiers.
func newMFAChallengeID() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("mfa: rand.Read: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
