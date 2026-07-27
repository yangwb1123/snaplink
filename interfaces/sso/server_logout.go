package sso

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/yangwb1123/snaplink/internal/auth/consent"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
	"net/http"
	"strings"
	"time"
)

func (s *Server) handleLogout(ctx HandlerContext) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	// Body is optional — bearer-only logouts are allowed.
	_ = ctx.Bind(&req)
	bearer := bearerToken(ctx.Request())
	if req.SessionID == "" && bearer == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrSessionIDOrBearerRequired))
		return
	}
	bcSubject, bcClientID, bcSID := s.captureBackchannelTarget(ctx, bearer)
	revoked := s.revokeLogoutCredentials(ctx, req.SessionID, bearer)
	s.maybeFanOutBackchannel(ctx, bcSubject, bcClientID, bcSID)
	s.TriggerSessionHubLogout(ctx.Request().Context(), bcSubject, bcSID)
	s.recordLogout(ctx, req.SessionID, revoked)
	// POST /logout is a definitive end to this session on this origin —
	// distinct from a per-token revoke, which may leave other sessions/tabs
	// alive. No-op unless security headers are enabled.
	s.ClearSiteData(ctx)
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusLoggedOut,
		KeyRevoked: revoked,
	})
}

// captureBackchannelTarget resolves the (subject, client, sid) for back-channel
// logout from the bearer BEFORE it is revoked — the post-revoke Validate call
// would fail. Best-effort: a malformed or already-expired bearer just yields no
// back-channel notification, never an error. ClientID is preferred, falling back
// to the first Audience entry.
func (s *Server) captureBackchannelTarget(ctx HandlerContext, bearer string) (bcSubject, bcClientID, bcSID string) {
	if bearer == "" {
		return "", "", ""
	}
	claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer)
	if err != nil || claims == nil {
		return "", "", ""
	}
	bcSubject = claims.Subject
	// OIDC §8 pairwise: the bearer's sub is the per-sector pseudonym. Resolve it
	// to the local id (mirrors handle_end_session) so the LOCAL-keyed
	// subject_client_index fan-out hits AND sendBackchannelLogout can re-derive
	// each target client's own pairwise sub. No-op for non-pairwise / already
	// local subs.
	if local, lerr := s.resolveLocalSubject(ctx.Request().Context(), bcSubject); lerr == nil && local != "" {
		bcSubject = local
	}
	bcSID = claims.SID
	if claims.ClientID != "" {
		bcClientID = claims.ClientID
	} else if len(claims.Audience) > 0 {
		bcClientID = claims.Audience[0]
	}
	return bcSubject, bcClientID, bcSID
}

// revokeLogoutCredentials destroys the session (when present) and revokes the
// bearer across every registered issuer, returning the list of revoked-credential
// markers in append order: RevokedSession first, then one RevokedToken per issuer
// that held the token.
//
// Uses the EXPORTED s.RevokeAcrossIssuers so the revocation is published on the
// cluster Bus (KindTokenRevoked), matching /token/revoke and /end_session. The
// unexported method is local-deny-set only; calling it here let a logged-out
// stateless access token keep validating on peer replicas until its natural exp.
func (s *Server) revokeLogoutCredentials(ctx HandlerContext, sessionID, bearer string) []string {
	revoked := []string{}
	if sessionID != "" && s.sessionMgr != nil {
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), sessionID); err != nil {
			s.logger.Error("logout: destroy session failed", "error", err)
		} else {
			revoked = append(revoked, RevokedSession)
		}
	}
	if bearer != "" && len(s.tokenIssuers) > 0 {
		issuersHit, failedIssuers := s.RevokeAcrossIssuers(ctx.Request().Context(), bearer)
		for range issuersHit {
			revoked = append(revoked, RevokedToken)
		}
		s.auditPartialRevokeFailure(ctx, issuersHit, failedIssuers)
	}
	return revoked
}

// maybeFanOutBackchannel notifies the client in the bearer's aud / client_id
// that this user just logged out so the RP can tear down its local session
// (OIDC Back-Channel Logout 1.0). No-op when the subsystem isn't wired or the
// client has no backchannel_logout_uri declared.
func (s *Server) maybeFanOutBackchannel(ctx HandlerContext, bcSubject, bcClientID, bcSID string) {
	if bcSubject == "" || bcClientID == "" || s.clientStore == nil {
		return
	}
	if c, err := s.clientStore.Get(ctx.Request().Context(), bcClientID); err == nil && c != nil {
		// Multi-RP fan-out when the security.SubjectClientIndex is wired;
		// degrades to single-RP notification of the bearer's
		// client when it isn't.
		s.fanOutBackchannelLogout(ctx, c, bcSubject, bcSID)
	}
}
func (s *Server) handleSendCode(ctx HandlerContext) {
	var req struct {
		Provider string `json:"provider"`
		Target   string `json:"target"`
	}
	if err := ctx.Bind(&req); err != nil || req.Provider == "" || req.Target == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrProviderAndTargetRequired))
		return
	}
	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrUnsupportedProvider))
		return
	}
	sender, ok := auth.(spi.CodeSender)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrProviderDoesNotSendCodes))
		return
	}
	if err := sender.SendCode(ctx.Request().Context(), req.Target); err != nil {
		s.logger.Error("send code failed", "provider", req.Provider, "error", err)
		s.recordCodeSent(ctx, req.Provider, req.Target, false)
		if errors.Is(err, spi.ErrCodeCooldownActive) {
			ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ErrResendTooSoon))
			return
		}
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrSendFailed))
		return
	}
	s.recordCodeSent(ctx, req.Provider, req.Target, true)
	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
}
func (s *Server) handleGetClient(ctx HandlerContext) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrClientStoreNotConfigured))
		return
	}
	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ctx, ErrMissingClientID))
		return
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ctx, ErrClientNotFound))
		return
	}
	ctx.JSON(http.StatusOK, client)
}

// handleConsentGate checks whether the user has consented to the requested
// scopes for the given client. Returns true when the gate fired (caller
// MUST return immediately) or false when the request may proceed.
//
// Gate logic:
//  1. prompt=consent forces re-prompt even when a valid grant exists.
//  2. No existing grant -> consent_required (first-time flow).
//  3. Existing grant that doesn't cover all requested scopes -> consent_required.
//  4. Otherwise -> record/refresh the grant (updates granted_at) and continue.
//
// When consent_required is returned, a server-issued consentChallengeID is
// included. The SPA must present this ID back in the next /auth/login call
// (consent_challenge_id field). The gate validates and atomically consumes the
// challenge — the challenge is bound to (userID, clientID, exact scopes) and
// expires after consent.ChallengeTTL, so a client cannot fabricate an approval
// or reuse a challenge for a different scope set.
func (s *Server) handleConsentGate(ctx HandlerContext, userID string, client *Client, scopes []string, prompt string, consentChallengeID string, authorizationDetails json.RawMessage) (halted bool) {
	requestCtx := ctx.Request().Context()
	clientID := client.ID
	// Per-client trust escape hatch: an operator-marked first-party client
	// bypasses the consent flow entirely (no prompt, no grant recorded). This
	// is operator policy, never DCR-settable — see Client.SkipConsent.
	if client.SkipConsent {
		return false
	}
	grant, err := s.consentStore.GetConsent(requestCtx, userID, clientID)
	if !s.evaluateConsentNeed(userID, client, scopes, prompt, grant, err) {
		// Grant exists and is sufficient. Refresh the record using the stored
		// grant's scope set (not the current request's narrower scopes) so that
		// previously-approved scopes are never silently erased. On store outage
		// (err != nil) grant is a zero value; skip the write and rely on the
		// fail-open path that already passed the gate.
		if err == nil {
			s.recordConsentGrant(requestCtx, userID, clientID, grant.Scopes)
		}
		return false
	}
	// Require a server-issued challenge that was previously returned in a
	// consent_required response. A bare boolean would let any caller bypass
	// the consent screen by fabricating the approval signal.
	if consentChallengeID == "" || !s.consentChallenges.Consume(consentChallengeID, userID, clientID, scopes, authorizationDetails) {
		s.issueConsentChallengeResponse(ctx, userID, client, scopes, consentChallengeID, authorizationDetails)
		return true
	}
	// Challenge validated and consumed: record the grant and continue.
	s.recordConsentGrant(requestCtx, userID, clientID, scopes)
	s.recordConsentEvent(ctx, audit.EventConsentGranted, audit.OutcomeSuccess, userID, clientID, scopes)
	return false
}

// evaluateConsentNeed is the pure consent-gate predicate: it returns whether the
// request must prompt for consent given the existing grant lookup result. On a
// store outage (err != nil that is not ErrNoConsentGrant) it fails open — logs
// and returns false — matching the audit / risk-scorer / geo fail-open contract.
func (s *Server) evaluateConsentNeed(userID string, client *Client, scopes []string, prompt string, grant ConsentGrant, err error) bool {
	promptConsent := consent.HasPromptValue(prompt, PromptConsent)
	switch {
	case errors.Is(err, ErrNoConsentGrant):
		// First-time authorization — user has never granted for this client.
		return true
	case err != nil:
		// Store outage: fail-open to preserve availability. Log and continue.
		s.logger.Error("consent store get failed; skipping gate", "user", userID, "client", client.ID, "error", err)
		return false
	case promptConsent:
		// RP requested explicit re-consent (e.g. for UI branding or re-auth).
		return true
	case !consent.ScopesSubsumed(grant.Scopes, scopes):
		// Existing grant does not cover all the requested scopes — new scopes
		// were added to the authorization request since the user last consented.
		return true
	case grant.IsExpired():
		// Server-level consent TTL expired — the grant is stale even though
		// the scopes still match. The user must re-authorize.
		return true
	case client.ConsentRefreshInterval > 0 && time.Since(grant.GrantedAt) > client.ConsentRefreshInterval:
		// Periodic re-consent: the grant still covers the scopes but is older
		// than this client's refresh cadence (high-risk clients re-confirm
		// authorization on a schedule). GrantedAt is refreshed on every
		// approval, so the clock restarts each time the user re-consents.
		return true
	}
	return false
}

// issueConsentChallengeResponse records a denial when a challenge was presented
// but failed (expired / fabricated / replayed / wrong scopes — a first-time
// prompt with an empty challenge is not a denial), then issues a fresh challenge
// and writes the consent_required response.
func (s *Server) issueConsentChallengeResponse(ctx HandlerContext, userID string, client *Client, scopes []string, consentChallengeID string, authorizationDetails json.RawMessage) {
	clientID := client.ID
	if consentChallengeID != "" {
		s.recordConsentEvent(ctx, audit.EventConsentDenied, audit.OutcomeFailure, userID, clientID, scopes)
	}
	challengeID := s.consentChallenges.Issue(userID, clientID, scopes, authorizationDetails)
	resp := map[string]any{
		KeyError:              ErrConsentRequired,
		KeyConsentChallengeID: challengeID,
		KeyIss:                s.resolveIssuer(ctx),
	}
	// Presentational enrichment so the consent UI can render a meaningful
	// screen (the app's display name + per-scope descriptions) instead of
	// raw IDs. Additive — older clients ignore the extra fields.
	if client.Name != "" {
		resp[KeyClientName] = client.Name
	}
	resp[KeyScopes] = s.describeScopes(scopes)
	// RFC 9396 §7: expose the authorization_details so the consent UI can
	// show the user exactly what they are being asked to authorize. Without
	// this the UI can only display scopes, not the fine-grained RAR payload.
	if len(authorizationDetails) > 0 {
		resp[oauth.KeyAuthorizationDetails] = authorizationDetails
	}
	ctx.JSON(http.StatusOK, resp)
}

// recordConsentGrant persists an up-to-date consent grant (refreshing GrantedAt).
// Fail-open on write errors.
func (s *Server) recordConsentGrant(requestCtx context.Context, userID, clientID string, scopes []string) {
	grant := ConsentGrant{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: time.Now(),
	}
	if s.consentMaxTTL > 0 {
		grant.ExpiresAt = grant.GrantedAt.Add(s.consentMaxTTL)
	}
	_ = s.consentStore.RecordConsent(requestCtx, grant)
}

// recordConsentEvent emits a user-initiated consent-lifecycle audit event
// (granted / revoked / denied). No-op when no auditor is wired. The acting
// subject is the resource owner (userID) — distinct from the admin-plane
// EventAdminConsentRevoked which is keyed on the operator. Scopes are joined
// into a single bounded metadata value (audit metadata is unbounded by design;
// only metrics labels carry the cardinality constraint).
func (s *Server) recordConsentEvent(ctx HandlerContext, evtType audit.EventType, outcome audit.Outcome, userID, clientID string, scopes []string) {
	if s.auditor == nil {
		return
	}
	evt := &audit.Event{
		Type:    evtType,
		Outcome: outcome,
		ActorID: userID,
		ActorIP: audit.ClientIP(ctx.Request()),
	}
	audit.SetMeta(evt, KeyClientID, clientID)
	if len(scopes) > 0 {
		audit.SetMeta(evt, "scopes", strings.Join(scopes, " "))
	}
	s.auditor.Record(ctx.Request().Context(), evt)
}

// ensureJITMembership auto-provisions org membership on login when enabled: a
// user authenticating through a tenant-bound client who has no membership in
// that tenant is added as a member, so federated users appear in their org
// roster without a manual invite. Opt-in (WithJITMembership), best-effort
// (errors logged, never block login), only fires for clients with a TenantID,
// and idempotent — an existing member keeps their current role untouched.
func (s *Server) ensureJITMembership(ctx HandlerContext, client *Client, userID string) {
	if !s.jitMembership || s.tenantUserStore == nil || client == nil || client.TenantID == "" {
		return
	}
	rctx := ctx.Request().Context()
	if _, err := s.tenantUserStore.Get(rctx, client.TenantID, userID); err == nil {
		return // already a member — preserve their role
	}
	if err := s.tenantUserStore.Add(rctx, &TenantMembership{
		TenantID: client.TenantID, UserID: userID, Role: TenantRoleMember, CreatedAt: time.Now(),
	}); err != nil {
		s.logger.Error("jit membership provisioning failed", "tenant", client.TenantID, "user", userID, "error", err)
		return
	}
	if s.auditor != nil {
		evt := &audit.Event{Type: audit.EventOrgMemberAutoProvisioned, Outcome: audit.OutcomeSuccess, ActorID: userID, ActorIP: audit.ClientIP(ctx.Request())}
		audit.SetMeta(evt, KeyTenantID, client.TenantID)
		s.auditor.Record(rctx, evt)
	}
}

// createSession mints a session capturing device context (IP/UA) and enforcing
// session caps (max_active_sessions, per-user, tenant quota). Eviction is
// scoped to tenantID; listing/eviction errors fail-open (logged, not blocking).
func (s *Server) createSession(ctx HandlerContext, userID, clientID, tenantID string, deviceID ...string) (*Session, error) {
	rctx := ctx.Request().Context()
	var devID string
	if len(deviceID) > 0 {
		devID = deviceID[0]
	}
	// Token-policy max_active_sessions (opt-in, default-off): reject a new
	// session once the subject is at/over the wired per-(user[,client]) cap.
	// Enforced BEFORE any mutation (tenant-quota increment, Create) so a
	// rejected login leaves no orphaned session or quota drift. Returns a
	// sentinel WITHOUT writing a response — the login caller owns the single
	// wire write (a clean access_denied), avoiding a double WriteHeader.
	if s.sessionPolicyCapExceeded(ctx, userID, clientID) {
		return nil, errMaxActiveSessions
	}
	// Tenant-level session quota check (quota.go's chargeSessionQuota). When
	// the tenant has reached its session limit, the creation is blocked with
	// a 403. A charge here is compensated below if creation fails afterward.
	charged, denied := s.chargeSessionQuota(ctx, tenantID, userID)
	if denied {
		return nil, core.ErrQuotaExceeded
	}
	if s.maxSessionsPerUser > 0 {
		s.evictOldestSession(rctx, userID, tenantID, s.maxSessionsPerUser)
	}
	// Enforce per-device session cap.
	if s.devicePolicy.MaxSessionsPerDevice > 0 && devID != "" {
		if s.deviceCapExceededForDevice(rctx, userID, devID) {
			return nil, errMaxActiveSessions
		}
	}
	sess, err := s.createSessionRecord(ctx, rctx, userID, tenantID, devID)
	if err != nil && charged {
		s.releaseSessionQuota(rctx, tenantID)
	}
	return sess, err
}

// createSessionRecord writes the session (CreateWithMeta or plain Create).
func (s *Server) createSessionRecord(ctx HandlerContext, rctx context.Context, userID, tenantID string, deviceID ...string) (*Session, error) {
	mc, ok := s.sessionMgr.(SessionMetaCreator)
	if !ok {
		return s.sessionMgr.Create(rctx, userID)
	}
	var devID string
	if len(deviceID) > 0 {
		devID = deviceID[0]
	}
	meta := SessionMeta{
		IP:        audit.ClientIP(ctx.Request()),
		UserAgent: ctx.Request().UserAgent(),
		TenantID:  tenantID,
		DeviceID:  devID,
	}
	// Zero-trust: bind the initial trust score + decay baseline at login when
	// WithSessionTrustDecay is wired. Uses device trust score when available
	// (higher for established devices). Off by default ⇒ zero values.
	if s.sessionTrust.enabled() {
		meta.TrustScore = s.sessionTrust.initialScore
		// Override with device trust score when available.
		if dc := deviceCtxFrom(ctx); dc != nil && dc.TrustScore > 0 {
			meta.TrustScore = dc.TrustScore
		}
		meta.TrustSetAt = time.Now()
	}
	return mc.CreateWithMeta(rctx, userID, meta)
}

// evictOldestSession lists the user's sessions for the given tenant and, when
// the count is at or above limit, destroys the session with the earliest
// CreatedAt. Scoped to tenantID: each tenant's quota is independent.
// Fail-open: any listing or eviction error is logged but does not block login.
func (s *Server) evictOldestSession(rctx context.Context, userID, tenantID string, limit int) {
	sessions, err := s.sessionMgr.ListByUser(rctx, userID)
	if err != nil {
		if s.logger != nil {
			s.logger.Error("session limit: list by user failed", "error", err, "user", userID)
		}
		return
	}
	var scoped []*Session
	for _, sess := range sessions {
		if sess != nil && sess.TenantID == tenantID {
			scoped = append(scoped, sess)
		}
	}
	if len(scoped) < limit {
		return
	}
	oldest := oldestSession(scoped)
	if oldest == nil || oldest.ID == "" {
		return
	}
	if err := s.sessionMgr.Destroy(rctx, oldest.ID); err != nil && s.logger != nil {
		s.logger.Error("session limit: evict oldest failed",
			"error", err, "user", userID, "session", oldest.ID)
	}
}

// deviceCapExceededForDevice checks if the device already has the max allowed
// sessions. Returns true when the cap would be exceeded (caller should refuse).
func (s *Server) deviceCapExceededForDevice(rctx context.Context, userID, devID string) bool {
	sessions, err := s.sessionMgr.ListByUser(rctx, userID)
	if err != nil {
		s.logger.Error("device session cap: list failed", "error", err)
		return false // fail-open
	}
	count := 0
	for _, sess := range sessions {
		if sess.DeviceID == devID {
			count++
		}
	}
	return count >= s.devicePolicy.MaxSessionsPerDevice
}

// oldestSession returns the session with the earliest CreatedAt from a slice.
func oldestSession(sessions []*Session) *Session {
	var oldest *Session
	for _, sess := range sessions {
		if oldest == nil || sess.CreatedAt.Before(oldest.CreatedAt) {
			oldest = sess
		}
	}
	return oldest
}

// describeScopes pairs each requested scope with its operator-defined human
// description (WithScopeDescriptions) for the consent_required response. A scope
// with no registered description carries an empty one — the consent UI falls
// back to the scope name (or its own built-in label).
func (s *Server) describeScopes(scopes []string) []map[string]string {
	out := make([]map[string]string, 0, len(scopes))
	for _, sc := range scopes {
		out = append(out, map[string]string{"scope": sc, "description": s.scopeDescriptions[sc]})
	}
	return out
}
