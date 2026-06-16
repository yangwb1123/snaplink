package sso

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/spi"
)

func (s *Server) handleLogout(ctx HandlerContext) {
	var req struct {
		SessionID string `json:"session_id"`
	}
	// Body is optional — bearer-only logouts are allowed.
	_ = ctx.Bind(&req)

	bearer := bearerToken(ctx.Request())

	if req.SessionID == "" && bearer == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrSessionIDOrBearerRequired))
		return
	}

	// Capture (subject, client) for back-channel logout BEFORE
	// revoking the bearer — the post-revoke Validate call would
	// fail. We do this in a best-effort way: a malformed or
	// already-expired bearer just yields no back-channel
	// notification, never an error.
	var bcSubject, bcClientID, bcSID string
	if bearer != "" {
		if claims, _, err := s.validateAnyToken(ctx.Request().Context(), bearer); err == nil && claims != nil {
			bcSubject = claims.Subject
			bcSID = claims.SID
			if claims.ClientID != "" {
				bcClientID = claims.ClientID
			} else if len(claims.Audience) > 0 {
				bcClientID = claims.Audience[0]
			}
		}
	}

	revoked := []string{}
	if req.SessionID != "" && s.sessionMgr != nil {
		if err := s.sessionMgr.Destroy(ctx.Request().Context(), req.SessionID); err != nil {
			s.logger.Error("logout: destroy session failed", "error", err)
		} else {
			revoked = append(revoked, RevokedSession)
		}
	}
	if bearer != "" && len(s.tokenIssuers) > 0 {
		issuersHit, failedIssuers := s.revokeAcrossIssuers(ctx.Request().Context(), bearer)
		for range issuersHit {
			revoked = append(revoked, RevokedToken)
		}
		s.auditPartialRevokeFailure(ctx, issuersHit, failedIssuers)
	}

	// OIDC Back-Channel Logout 1.0: notify the client in the
	// bearer's aud / client_id that this user just logged out so
	// the RP can tear down its local session. No-op when the
	// subsystem isn't wired or the client has no
	// backchannel_logout_uri declared.
	if bcSubject != "" && bcClientID != "" && s.clientStore != nil {
		if c, err := s.clientStore.Get(ctx.Request().Context(), bcClientID); err == nil && c != nil {
			// Multi-RP fan-out when the security.SubjectClientIndex is wired;
			// degrades to single-RP notification of the bearer's
			// client when it isn't.
			s.fanOutBackchannelLogout(ctx, c, bcSubject, bcSID)
		}
	}

	s.recordLogout(ctx, req.SessionID, revoked)

	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus:  StatusLoggedOut,
		KeyRevoked: revoked,
	})
}

func (s *Server) handleSendCode(ctx HandlerContext) {
	var req struct {
		Provider string `json:"provider"`
		Target   string `json:"target"`
	}
	if err := ctx.Bind(&req); err != nil || req.Provider == "" || req.Target == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderAndTargetRequired))
		return
	}

	auth, err := s.getAuthenticator(req.Provider)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrUnsupportedProvider))
		return
	}

	sender, ok := auth.(spi.CodeSender)
	if !ok {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrProviderDoesNotSendCodes))
		return
	}

	if err := sender.SendCode(ctx.Request().Context(), req.Target); err != nil {
		s.logger.Error("send code failed", "provider", req.Provider, "error", err)
		s.recordCodeSent(ctx, req.Provider, req.Target, false)
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrSendFailed))
		return
	}

	s.recordCodeSent(ctx, req.Provider, req.Target, true)

	ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
}

func (s *Server) handleGetClient(ctx HandlerContext) {
	if s.clientStore == nil {
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrClientStoreNotConfigured))
		return
	}

	clientID := ctx.Param("id")
	if clientID == "" {
		ctx.JSON(http.StatusBadRequest, errorBody(ErrMissingClientID))
		return
	}

	client, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil {
		ctx.JSON(http.StatusNotFound, errorBody(ErrClientNotFound))
		return
	}

	ctx.JSON(http.StatusOK, client)
}

// consentChallengeTTL is the lifetime of a server-issued consent challenge.
// The SPA must present the challenge ID within this window.
const consentChallengeTTL = 5 * time.Minute

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
// expires after consentChallengeTTL, so a client cannot fabricate an approval
// or reuse a challenge for a different scope set.
func (s *Server) handleConsentGate(ctx HandlerContext, userID string, client *Client, scopes []string, prompt string, consentChallengeID string) (halted bool) {
	requestCtx := ctx.Request().Context()
	clientID := client.ID

	// Per-client trust escape hatch: an operator-marked first-party client
	// bypasses the consent flow entirely (no prompt, no grant recorded). This
	// is operator policy, never DCR-settable — see Client.SkipConsent.
	if client.SkipConsent {
		return false
	}

	grant, err := s.consentStore.GetConsent(requestCtx, userID, clientID)

	promptConsent := hasPromptValue(prompt, PromptConsent)
	needsConsent := false

	switch {
	case errors.Is(err, ErrNoConsentGrant):
		// First-time authorization — user has never granted for this client.
		needsConsent = true
	case err != nil:
		// Store outage: fail-open to preserve availability (matches the
		// audit / risk-scorer / geo fail-open contract). Log and continue.
		s.logger.Error("consent store get failed; skipping gate", "user", userID, "client", clientID, "error", err)
	case promptConsent:
		// RP requested explicit re-consent (e.g. for UI branding or re-auth).
		needsConsent = true
	case !scopesSubsumed(grant.Scopes, scopes):
		// Existing grant does not cover all the requested scopes — new scopes
		// were added to the authorization request since the user last consented.
		needsConsent = true
	case client.ConsentRefreshInterval > 0 && time.Since(grant.GrantedAt) > client.ConsentRefreshInterval:
		// Periodic re-consent: the grant still covers the scopes but is older
		// than this client's refresh cadence (high-risk clients re-confirm
		// authorization on a schedule). GrantedAt is refreshed on every
		// approval, so the clock restarts each time the user re-consents.
		needsConsent = true
	}

	if needsConsent {
		// Require a server-issued challenge that was previously returned in a
		// consent_required response. A bare boolean would let any caller bypass
		// the consent screen by fabricating the approval signal.
		if consentChallengeID == "" || !s.consumeConsentChallenge(consentChallengeID, userID, clientID, scopes) {
			// A presented-but-invalid challenge is a failed approval attempt
			// (expired / fabricated / replayed / wrong scopes) — record it for
			// forensics. A first-time prompt (empty challenge) is not a denial.
			if consentChallengeID != "" {
				s.recordConsentEvent(ctx, audit.EventConsentDenied, audit.OutcomeFailure, userID, clientID, scopes)
			}
			challengeID := s.issueConsentChallenge(userID, clientID, scopes)
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
			ctx.JSON(http.StatusOK, resp)
			return true
		}
		// Challenge validated and consumed: record the grant and continue.
		_ = s.consentStore.RecordConsent(requestCtx, ConsentGrant{
			UserID:    userID,
			ClientID:  clientID,
			Scopes:    scopes,
			GrantedAt: time.Now(),
		})
		s.recordConsentEvent(ctx, audit.EventConsentGranted, audit.OutcomeSuccess, userID, clientID, scopes)
		return false
	}

	// Grant exists and is sufficient (or store outage fell through): persist
	// an up-to-date record so the granted_at timestamp stays fresh and any
	// newly-in-scope scopes are saved. Fail-open on write errors — the
	// absence of a stored grant is not a correctness issue here since we
	// already confirmed the existing grant is sufficient.
	_ = s.consentStore.RecordConsent(requestCtx, ConsentGrant{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    scopes,
		GrantedAt: time.Now(),
	})
	return false
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

// createSession mints a session for the authenticated user, capturing the
// request's device/location context (IP + user-agent) when the wired
// SessionManager implements SessionMetaCreator (memory + sqlite do). The IP
// honors the same first-hop X-Forwarded-For trust model as the rest of the
// server. A manager without the extension falls back to the plain Create.
// tenantID stamps Session.TenantID so SessionTenantIndex.DeleteByTenant can
// actively revoke this session when its tenant is suspended/deleted — pass the
// authenticating client's TenantID (empty for non-tenant clients, which leaves
// the session tenant-unbound and relies on the membership-roster revoke path).
func (s *Server) createSession(ctx HandlerContext, userID, tenantID string) (*Session, error) {
	if mc, ok := s.sessionMgr.(SessionMetaCreator); ok {
		return mc.CreateWithMeta(ctx.Request().Context(), userID, SessionMeta{
			IP:        audit.ClientIP(ctx.Request()),
			UserAgent: ctx.Request().UserAgent(),
			TenantID:  tenantID,
		})
	}
	return s.sessionMgr.Create(ctx.Request().Context(), userID)
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

// issueConsentChallenge generates and stores a single-use consent challenge
// bound to (userID, clientID, scopes). Returns the opaque challenge ID to
// include in the consent_required response.
func (s *Server) issueConsentChallenge(userID, clientID string, scopes []string) string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	id := base64.RawURLEncoding.EncodeToString(b)

	s.consentChallengeMu.Lock()
	defer s.consentChallengeMu.Unlock()
	if s.consentChallenges == nil {
		s.consentChallenges = make(map[string]*pendingConsentChallenge)
	}
	s.consentChallenges[id] = &pendingConsentChallenge{
		UserID:    userID,
		ClientID:  clientID,
		Scopes:    slices.Clone(scopes),
		ExpiresAt: time.Now().Add(consentChallengeTTL),
	}
	return id
}

// consumeConsentChallenge validates and atomically removes the challenge with
// the given ID. Returns true only if the challenge exists, matches
// (userID, clientID, exact scopes), and has not expired.
func (s *Server) consumeConsentChallenge(id, userID, clientID string, scopes []string) bool {
	s.consentChallengeMu.Lock()
	defer s.consentChallengeMu.Unlock()
	if s.consentChallenges == nil {
		return false
	}

	// Prune expired entries on every lookup to bound memory growth.
	now := time.Now()
	for k, v := range s.consentChallenges {
		if now.After(v.ExpiresAt) {
			delete(s.consentChallenges, k)
		}
	}

	ch, ok := s.consentChallenges[id]
	if !ok || now.After(ch.ExpiresAt) {
		return false
	}
	if ch.UserID != userID || ch.ClientID != clientID || !consentScopesMatch(ch.Scopes, scopes) {
		return false
	}
	// Single-use: consume immediately.
	delete(s.consentChallenges, id)
	return true
}

// consentScopesMatch reports whether a and b contain exactly the same scopes
// regardless of order. Used to bind challenge validation to the exact scope set
// the challenge was issued for.
func consentScopesMatch(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	as := slices.Clone(a)
	bs := slices.Clone(b)
	slices.Sort(as)
	slices.Sort(bs)
	return slices.Equal(as, bs)
}

// hasPromptValue reports whether the space-separated OIDC prompt parameter
// contains the named value (e.g. "consent"). Case-sensitive per spec.
func hasPromptValue(prompt, val string) bool {
	for _, p := range strings.Fields(prompt) {
		if p == val {
			return true
		}
	}
	return false
}

// scopesSubsumed reports whether every scope in requested is present in
// granted. An empty requested set is trivially subsumed (nothing to check).
func scopesSubsumed(granted, requested []string) bool {
	if len(requested) == 0 {
		return true
	}
	set := make(map[string]struct{}, len(granted))
	for _, s := range granted {
		set[s] = struct{}{}
	}
	for _, r := range requested {
		if _, ok := set[r]; !ok {
			return false
		}
	}
	return true
}
