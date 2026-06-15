package sso

import (
	"github.com/snaplink/sso/internal/handler"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/spi"
)
type mfaResumeState struct {
	Result           *AuthResult       `json:"result"`
	Request          loginRequest      `json:"request"`
	CredentialHealth *CredentialHealth `json:"credential_health,omitempty"`
}

// issueMFAChallenge mints a single-use challenge ID + persists the
// frozen login state for resumption. Writes the mfa_required response.
// Audit: emits mfa_required (success outcome — primary credential was
// fine, the user just hasn't completed step-up yet).
func (s *Server) issueMFAChallenge(ctx HandlerContext, result *AuthResult, req loginRequest, client *Client) {
	// Set CredentialHealth explicitly: AuthResult.CredentialHealth is
	// json:"-", so the embedded Result drops it; this side channel
	// preserves it for the post-step-up audit in finishLogin.
	stateBlob, err := json.Marshal(&mfaResumeState{Result: result, Request: req, CredentialHealth: result.CredentialHealth})
	if err != nil {
		s.logger.Error("mfa: failed to marshal resume state", "error", err, "client", client.ID, "user", result.UserID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	id, err := newMFAChallengeID()
	if err != nil {
		s.logger.Error("mfa: failed to mint challenge id", "error", err)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
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
		return
	}

	if s.auditor != nil {
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

	methods := s.mfaProvider.SupportedMethods()
	// Metric: count one challenge per issuance, labeled by the FIRST
	// supported method (the user picks among them downstream). Zero
	// traffic when metrics aren't wired.
	if s.metrics != nil && len(methods) > 0 {
		s.metrics.MFAChallengesTotal.WithLabelValues(methods[0]).Inc()
	}
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
	// HTTP 200 (not 400) — the primary credential was accepted; the
	// pending state is a normal step in the flow, not an error.
	ctx.JSON(http.StatusOK, resp)
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

	var req struct {
		ChallengeID string            `json:"mfa_challenge_id"`
		Method      string            `json:"mfa_method"`
		Params      map[string]string `json:"params"`
		// Top-level convenience fields the flat-form callers prefer
		// (HTML forms, simple clients). When Params is empty we
		// collect the per-method known fields from these.
		Code      string `json:"code"`      // totp
		Assertion string `json:"assertion"` // webauthn
	}
	if err := bindOAuthParams(ctx, &req); err != nil {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	if req.ChallengeID == "" || req.Method == "" {
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	challenge, err := s.mfaChallengeStore.Consume(ctx.Request().Context(), req.ChallengeID)
	if err != nil || challenge == nil {
		s.recordMFAFailure(ctx, "", req.ChallengeID, req.Method, "challenge_invalid")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}

	// Flat → Params normalization. Params wins when both set so explicit
	// callers stay in control. The dispatch into spi.MFAProvider is opaque
	// — only the contract for "totp" / "webauthn" is known here; richer
	// providers (push notification, hardware key) get whatever Params
	// the caller supplies plus the flat code/assertion convenience.
	params := req.Params
	if params == nil {
		params = make(map[string]string, 2)
	}
	if _, ok := params["code"]; !ok && req.Code != "" {
		params["code"] = req.Code
	}
	if _, ok := params["assertion"]; !ok && req.Assertion != "" {
		params["assertion"] = req.Assertion
	}

	if err := s.mfaProvider.Verify(ctx.Request().Context(), challenge.SubjectID, req.Method, params); err != nil {
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, err.Error())
		s.recordMFACompletion(req.Method, "failure")
		ctx.JSON(http.StatusBadRequest, s.authzErrorBody(ctx, ErrMFAInvalid))
		return
	}
	s.recordMFACompletion(req.Method, "success")
	outcome = "success"

	// Factor verified. Decode the frozen state, re-look-up the client
	// (could have been deactivated / tenant-suspended in the window
	// between challenge issue and verify), and resume finishLogin.
	state := &mfaResumeState{}
	if err := json.Unmarshal(challenge.RequestState, state); err != nil {
		s.logger.Error("mfa: failed to decode resume state", "error", err, "challenge", req.ChallengeID)
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	if state.Result == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrInternal))
		return
	}
	// Re-attach the advisory carried out-of-band (AuthResult.CredentialHealth
	// is json:"-", so it never survives the embedded Result round trip) so
	// finishLogin emits the credential-health audit on the MFA-resumed path
	// exactly as it does on the direct path.
	state.Result.CredentialHealth = state.CredentialHealth

	// The second factor verified: fold it into the result's amr so the
	// resumed mint carries the real multi-factor signal (RFC 8176, e.g.
	// ["pwd","otp","mfa"]) rather than only the first-factor method
	// captured before the step-up.
	state.Result.AuthMethods = handler.WithMFAMethod(state.Result.AuthMethods, req.Method)

	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, s.authzErrorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), challenge.ClientID)
	if err != nil || client == nil || !client.Active || !clientTenantOK(ctx, client) {
		// Client was deactivated, deleted, or tenant-suspended between
		// challenge issue and completion. Surface as inactive_client
		// rather than mfa_invalid — operators investigating the audit
		// trail need to know it wasn't the factor that failed.
		s.recordMFAFailure(ctx, challenge.SubjectID, req.ChallengeID, req.Method, "client_unavailable")
		ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, ErrInactiveClient))
		return
	}

	if s.auditor != nil {
		evt := &audit.Event{
			Type:     audit.EventMFASuccess,
			Outcome:  audit.OutcomeSuccess,
			ActorID:  challenge.SubjectID,
			ClientID: client.ID,
			Provider: state.Result.Provider,
			ActorIP:  audit.ClientIP(ctx.Request()),
		}
		audit.SetMeta(evt, KeyMFAMethod, req.Method)
		audit.SetMeta(evt, KeyMFAChallengeID, req.ChallengeID)
		s.auditor.Record(ctx.Request().Context(), evt)
	}

	// Data-residency write-gate on the SECOND leg. The token is minted NOW, in
	// finishLogin, from the serving region of THIS /auth/mfa request — which
	// went through the same region middleware as /auth/login — so the gate reads
	// the live region here, not the (possibly different) region of the first
	// leg that issued the challenge. Mirrors the credential-path gate exactly
	// (isWrite=true, distinct governance codes, RFC 9207 iss via authzErrorBody,
	// one recordLoginFailure). Without a wired region resolver / residency check
	// the gate never fires (byte-identical). Provider is attributed to the
	// original credential provider, matching the mfa_success audit above.
	if s.residencyGateLogin(ctx, client.ID, state.Result.Provider, client.TenantID) {
		return
	}

	// Resume the standard post-risk login flow. finishLogin writes
	// the response, which can be the normal token/code/form-post
	// payload — caller can't tell the difference between an MFA-gated
	// login and a non-gated one (other than the extra round trip).
	s.finishLogin(ctx, state.Result, state.Request, client)
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
