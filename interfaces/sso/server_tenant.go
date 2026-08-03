package sso

import (
	"context"
	"errors"
	"fmt"
	"github.com/yangwb1123/snaplink/domains/region"
	"github.com/yangwb1123/snaplink/domains/tenant"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"net/http"
	"strconv"
	"time"

	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// ExternalUserStore returns the wired cross-tenant guest-record store
// (WithExternalUserStore), or nil when unwired. Relocated from accessors.go
// to keep that file within the per-file line budget; belongs beside the
// other tenant-scoped accessors here.
func (s *Server) ExternalUserStore() tenant.ExternalUserStore { return s.externalUserStore }

func (s *Server) codeSendContext(ctx HandlerContext) context.Context {
	tenantID := ""
	if resolved, ok := tenant.FromHandlerContext(ctx); ok && resolved.Tenant != nil {
		tenantID = resolved.Tenant.ID
	}
	return spi.WithCodeSendTenant(ctx.Request().Context(), tenantID)
}

func (s *Server) handleCodeSendFailure(ctx HandlerContext, provider, target string, err error) bool {
	if err == nil {
		return false
	}
	s.logger.Error("send code failed", "provider", provider, "error", err)
	s.recordCodeSent(ctx, provider, target, false)
	if errors.Is(err, spi.ErrCodeSendQuotaExceeded) {
		ctx.JSON(http.StatusOK, map[string]string{KeyStatus: StatusSent})
	} else if errors.Is(err, spi.ErrCodeCooldownActive) {
		ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ErrResendTooSoon))
	} else {
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrSendFailed))
	}
	return true
}

// TenantCollaborationStore returns the wired cross-tenant trust allow-list
// (WithTenantCollaborationStore), or nil when unwired.
func (s *Server) TenantCollaborationStore() tenant.CollaborationStore {
	return s.tenantCollaborationStore
}

// HomeTenantForClient resolves the TenantID of the client identified by
// clientID, or "" when the client is unknown, untenanted, or no ClientStore
// is wired. Used exclusively by the token-exchange cross-tenant B2B
// collaboration gate to discover a subject_token's home tenant (the tenant
// owning the client it was ORIGINALLY issued to) — mirrors the same
// s.clientStore.Get(ctx, claims.ClientID) lookup checkTenantNotSuspended
// already performs for the tenant-suspension gate.
func (s *Server) HomeTenantForClient(ctx context.Context, clientID string) string {
	if s.clientStore == nil || clientID == "" {
		return ""
	}
	c, err := s.clientStore.Get(ctx, clientID)
	if err != nil || c == nil {
		return ""
	}
	return c.TenantID
}

// Active credential revocation on tenant suspension/deletion.
//
// WithTenantSuspensionCheck is a *lazy* gate: it only rejects a tenant-bound
// access token on its next validate, and never touches refresh tokens or
// sessions. On its own that leaves a privilege-escape window — credentials
// minted while the tenant was Active keep working until natural expiry. The
// admin SetTenantStatus(Suspended) / DeleteTenant hooks call into here to close
// that window proactively: every refresh token of the tenant's clients AND
// every active session of the tenant's members is destroyed.

// RevokeTenantRefreshTokens is the active-revocation companion to tenant
// suspension/deletion. It proactively destroys both:
//
//   - every refresh token issued to any client belonging to the tenant, and
//   - every active session of the tenant's members,
//
// so a suspended tenant's access can't be resumed from a still-valid refresh
// token or session, and the credentials stay gone even after a later
// reactivation.
//
// Opt-in + best-effort throughout: each leg degrades to a no-op when the
// required capability isn't wired, and a single failure is logged + collected
// but never aborts the rest (one bad client/user can't strand the others). The
// returned count is the refresh tokens deleted (kept for the historical
// signature the admin hook ignores); session revocation is independent and
// audited separately. Both legs run regardless of whether the other is wired —
// a deployment with sessions but no client-scoped refresh store still gets its
// sessions revoked.
func (s *Server) RevokeTenantRefreshTokens(ctx context.Context, tenantID string) (int, error) {
	report := s.RevokeTenantCredentials(ctx, tenantID)
	var errs []error
	for _, result := range report.Results {
		if result.Status == "failed" {
			errs = append(errs, errors.New(result.Error))
		}
	}
	return report.RefreshTokensRevoked, errors.Join(errs...)
}

// RevokeTenantCredentials returns the exact, independently retryable outcome
// of every refresh-token and session purge leg.
func (s *Server) RevokeTenantCredentials(
	ctx context.Context, tenantID string,
) core.TenantCredentialRevocationReport {
	report := core.TenantCredentialRevocationReport{TenantID: tenantID, Results: []core.CredentialRevocationResult{}}
	if tenantID == "" {
		return report
	}
	report.RefreshTokensRevoked, report.Results = s.revokeTenantRefreshTokens(ctx, tenantID)
	var sessionResults []core.CredentialRevocationResult
	report.SessionsRevoked, sessionResults = s.revokeTenantSessions(ctx, tenantID)
	report.Results = append(report.Results, sessionResults...)
	return report
}

// TenantSuspended reports whether tenantID is currently suspended. It reuses the
// exact cache + FAIL-OPEN doctrine of the token-validation gate
// (checkTenantNotSuspended): when suspension is not wired, no tenant store is
// present, or the store read fails / the tenant is not found, it reports false
// (fail-open — an availability blip must NOT freeze the world). A fresh live read
// is cached when a suspension cache is wired.
//
// It is the tenantID-keyed seam the delegated org-admin surface uses to refuse
// MUTATIONS on a suspended org: the token gate keys off the token's client
// tenant, whereas this keys off an explicit tenant ID from the request path.
func (s *Server) TenantSuspended(ctx context.Context, tenantID string) bool {
	if !s.tenantSuspensionEnabled || s.tenantStore == nil || tenantID == "" {
		return false
	}
	if suspended, decided := s.checkSuspensionCache(tenantID); decided {
		return suspended
	}
	t, err := s.tenantStore.GetTenant(ctx, tenantID)
	if err != nil || t == nil {
		return false // fail-open on store outage / not-found
	}
	suspended := t.Status == tenant.StatusSuspended
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.put(tenantID, suspended)
	}
	return suspended
}

// revokeTenantRefreshTokens purges every refresh token issued to any client
// belonging to tenantID. Returns (0, nil) when the client store can't
// enumerate by tenant (no TenantScopedClientStore) or the refresh store can't
// purge by client (no oauth.RefreshTokenClientPurger). A per-client purge
// failure is logged + collected but never aborts the remaining clients.
func (s *Server) revokeTenantRefreshTokens(
	ctx context.Context, tenantID string,
) (int, []core.CredentialRevocationResult) {
	scoped, ok := s.clientStore.(TenantScopedClientStore)
	if !ok {
		return 0, nil
	}
	purger, ok := s.refreshTokenStore.(oauth.RefreshTokenClientPurger)
	if !ok {
		return 0, nil
	}
	clients, err := scoped.ListByTenant(ctx, tenantID)
	if err != nil {
		return 0, []core.CredentialRevocationResult{tenantRevocationFailure(
			tenantID, "refresh_tokens", tenantID, fmt.Errorf("list tenant clients: %w", err))}
	}
	var total int
	results := make([]core.CredentialRevocationResult, 0, len(clients))
	for _, c := range clients {
		n, derr := purger.DeleteAllForClient(ctx, c.ID)
		if derr != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant refresh tokens: client purge failed",
					"error", derr, "tenant", tenantID, "client", c.ID)
			}
			results = append(results, tenantRevocationFailure(tenantID, "refresh_tokens", c.ID, derr))
			continue
		}
		total += n
		results = append(results, tenantRevocationSuccess(tenantID, "refresh_tokens", c.ID, n))
	}
	s.auditTenantTokensRevoked(ctx, tenantID, total)
	return total, results
}

// revokeTenantSessions destroys every active session belonging to tenantID.
//
// Two complementary, fail-open paths run when wired:
//
//  1. Direct index — when the SessionManager implements SessionTenantIndex,
//     DeleteByTenant kills every session whose TenantID was stamped at login
//     in one query. This is the efficient path for backends that persist the
//     binding.
//  2. Membership roster — additionally walks the tenant's members via the
//     TenantUserStore and destroys each member's sessions (ListByUser →
//     Destroy). This catches sessions that predate the tenant binding (or
//     were minted by a SessionManager that doesn't persist TenantID) so
//     suspension is enforced even without the direct index — it's the floor
//     the security guarantee rests on.
//
// Best-effort + fail-open: a missing SessionManager, a store outage, or a
// per-user destroy failure is logged and skipped, never propagated — a tenant
// store partition must not block the status change (matching the suspension
// check's fail-open design). The total destroyed is audited (zero included).
func (s *Server) revokeTenantSessions(
	ctx context.Context, tenantID string,
) (int, []core.CredentialRevocationResult) {
	if s.sessionMgr == nil {
		return 0, nil
	}
	var total int
	var results []core.CredentialRevocationResult
	if idx, ok := s.sessionMgr.(SessionTenantIndex); ok {
		n, err := idx.DeleteByTenant(ctx, tenantID)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant sessions: index delete failed",
					"error", err, "tenant", tenantID)
			}
			results = append(results, tenantRevocationFailure(tenantID, "sessions", tenantID, err))
		} else {
			total += n
			results = append(results, tenantRevocationSuccess(tenantID, "sessions", tenantID, n))
		}
	}
	// Roster path: enumerate members and destroy their sessions individually.
	// Skipped when no membership store is wired (single-tenant deployments
	// rely on the direct index or have no per-tenant roster to walk).
	if s.tenantUserStore != nil {
		members, err := s.tenantUserStore.ListByTenant(ctx, tenantID)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant sessions: list members failed",
					"error", err, "tenant", tenantID)
			}
			results = append(results, tenantRevocationFailure(tenantID, "session_roster", tenantID, err))
		} else {
			var memberResults []core.CredentialRevocationResult
			var destroyed int
			destroyed, memberResults = s.destroyMemberSessions(ctx, tenantID, members)
			total += destroyed
			results = append(results, memberResults...)
		}
	}
	s.auditTenantSessionsRevoked(ctx, tenantID, total)
	return total, results
}

// destroyMemberSessions destroys every active session of the supplied members,
// returning the count destroyed. A per-user enumerate/destroy failure is
// logged and skipped so one bad member can't strand the rest.
func (s *Server) destroyMemberSessions(
	ctx context.Context, tenantID string, members []*TenantMembership,
) (int, []core.CredentialRevocationResult) {
	var total int
	var results []core.CredentialRevocationResult
	for _, member := range members {
		if member == nil {
			continue
		}
		n, userResults := s.destroyUserSessions(ctx, tenantID, member.UserID)
		total += n
		results = append(results, userResults...)
	}
	return total, results
}

func (s *Server) destroyUserSessions(
	ctx context.Context, tenantID, userID string,
) (int, []core.CredentialRevocationResult) {
	if userID == "" {
		return 0, nil
	}
	sessions, err := s.sessionMgr.ListByUser(ctx, userID)
	if err != nil {
		s.logTenantSessionRevocationError(
			"revoke tenant sessions: list by user failed", err, tenantID, userID,
		)
		return 0, []core.CredentialRevocationResult{
			tenantRevocationFailure(tenantID, "session_user", userID, err),
		}
	}
	var destroyed int
	results := make([]core.CredentialRevocationResult, 0, len(sessions))
	for _, session := range sessions {
		if session == nil {
			continue
		}
		if err := s.sessionMgr.Destroy(ctx, session.ID); err != nil {
			s.logTenantSessionRevocationError(
				"revoke tenant sessions: destroy failed", err, tenantID, userID,
			)
			results = append(results, tenantRevocationFailure(tenantID, "session", session.ID, err))
			continue
		}
		destroyed++
		results = append(results, tenantRevocationSuccess(tenantID, "session", session.ID, 1))
	}
	return destroyed, results
}

func tenantRevocationSuccess(tenantID, kind, id string, count int) core.CredentialRevocationResult {
	return core.CredentialRevocationResult{
		IdempotencyKey: "tenant:" + tenantID + ":" + kind + ":" + id,
		Kind:           kind, ResourceID: id, Status: "revoked", RevokedCount: count,
	}
}

func tenantRevocationFailure(tenantID, kind, id string, err error) core.CredentialRevocationResult {
	result := tenantRevocationSuccess(tenantID, kind, id, 0)
	result.Status = "failed"
	result.Error = err.Error()
	return result
}

func (s *Server) logTenantSessionRevocationError(message string, err error, tenantID, userID string) {
	if s.logger == nil {
		return
	}
	s.logger.Error(message, "error", err, "tenant", tenantID, "user", userID)
}

// auditTenantTokensRevoked records the active revocation a tenant suspension
// triggered. Count is informational; a zero count still records so a SIEM
// sees the suspension was enforced even when the tenant held no live tokens.
// Safe with a nil Recorder; uses audit.SetMeta so geo + tenant enrichment
// isn't clobbered. Takes a plain context (not HandlerContext) — this is an
// SDK-level operation, not necessarily tied to an inbound HTTP request.
func (s *Server) auditTenantTokensRevoked(ctx context.Context, tenantID string, count int) {
	if s.auditor == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventTenantTokensRevoked,
		Outcome:   audit.OutcomeSuccess,
		ActorID:   tenantID,
		Timestamp: time.Now(),
	}
	audit.SetMeta(e, "refresh_tokens_revoked", strconv.Itoa(count))
	s.auditor.Record(ctx, e)
}

// auditTenantSessionsRevoked records the active session revocation a tenant
// suspension/deletion triggered. Count is informational; a zero count still
// records so a SIEM sees the suspension was enforced even when the tenant held
// no live sessions. Safe with a nil Recorder; uses audit.SetMeta so geo +
// tenant enrichment isn't clobbered. Takes a plain context (not
// HandlerContext) — this is an SDK-level operation, not necessarily tied to an
// inbound HTTP request.
func (s *Server) auditTenantSessionsRevoked(ctx context.Context, tenantID string, count int) {
	if s.auditor == nil {
		return
	}
	e := &audit.Event{
		Type:      audit.EventTenantSessionsRevoked,
		Outcome:   audit.OutcomeSuccess,
		ActorID:   tenantID,
		Timestamp: time.Now(),
	}
	audit.SetMeta(e, "sessions_revoked", strconv.Itoa(count))
	s.auditor.Record(ctx, e)
}

// residencyGateTokenGrant is the data-residency write-gate for the /token grant
// endpoint. Token issuance is the WRITE side of residency, but previously only
// the interactive-login mint (residencyGateLogin) and the resource read
// (residencyDeniedForAccess) were gated — so a refresh rotation, token-exchange,
// CIBA, device, or authorization_code mint executed from a disallowed serving
// region slipped through, minting fresh credentials for a region-constrained
// tenant outside its residency boundary. The login write-gate is the primary
// control, but a refresh/exchange that rotates a previously-issued grant never
// re-traversed it; this closes that grant-side hole.
//
// The /token handler authenticates the client up-front and runs inside the
// HandlerContext pipeline, so the live serving region the region middleware
// stashed is in scope here — no plumbing through the bare-context issuance
// helpers is needed (the choke point has everything). Gate on the client's
// tenant: a grant carries no tenant of its own, and client.TenantID is the same
// binding the read-gate resolves. isWrite=true so EnforceWrites applies (a mint
// in a non-home region for a write-enforced tenant is blocked, matching login).
//
// Oracle-safe: runs ONLY after the client is authenticated (HTTP Basic / body
// secret / private_key_jwt all verified above), so it can't probe residency
// without valid client credentials. region_not_allowed / residency_violation
// are governance codes — exactly like the tenant_mismatch 403 already on this
// endpoint — not credential oracles, so they keep their distinct wire codes.
// The /token error shape (errorBody, no RFC 9207 iss) mirrors that sibling
// tenant_mismatch denial rather than the authorization-response authzErrorBody.
//
// Returns true when it WROTE the 403 and the caller MUST return without minting;
// false when the mint may proceed. Byte-identical when residency is unwired or
// no serving region is resolved: the first guard returns false before any work.
func (s *Server) residencyGateTokenGrant(ctx HandlerContext, client *Client) (handled bool) {
	if !s.tenantResidencyEnabled || client == nil || client.TenantID == "" {
		return false
	}
	servingRegion, ok := region.FromHandlerContext(ctx)
	if !ok || servingRegion == "" {
		return false
	}
	if err := s.checkTenantResidency(ctx.Request().Context(), client.TenantID, servingRegion, true); err != nil {
		ctx.JSON(http.StatusForbidden, errorBody(ctx, s.mapResidencyError(err)))
		return true
	}
	return false
}

// tenantMetricsEnabled reports whether the opt-in per-tenant metrics are
// armed: an operator-supplied allowlist AND a metrics registry with the
// vectors registered. When false every tenant-metric call below is a no-op
// (byte-identical off, §5).
func (s *Server) tenantMetricsEnabled() bool {
	return len(s.tenantMetricsAllowlist) > 0 &&
		s.metrics != nil && s.metrics.LoginAttemptsByTenantTotal != nil
}

// tenantLabel resolves clientID to a BOUNDED tenant label value. It looks up
// the client's TenantID and returns it ONLY when it is on the operator
// allowlist; every other tenant — and every untenanted / unknown client —
// folds into the single metrics.TenantLabelOther bucket. This caps the
// tenant label cardinality at len(allowlist)+1, the same discipline the MFA
// metric uses by restricting its label to SupportedMethods() (§5).
//
// Called ONLY when tenantMetricsEnabled() (the opt-in path), so the
// ClientStore.Get it issues never runs on a default build.
func (s *Server) tenantLabel(ctx HandlerContext, clientID string) string {
	if clientID == "" {
		return metrics.TenantLabelOther
	}
	c, err := s.clientStore.Get(ctx.Request().Context(), clientID)
	if err != nil || c == nil || c.TenantID == "" {
		return metrics.TenantLabelOther
	}
	if _, ok := s.tenantMetricsAllowlist[c.TenantID]; ok {
		return c.TenantID
	}
	return metrics.TenantLabelOther
}

// recordTenantLoginAttempt bumps the per-tenant login counter (outcome ∈
// {success, failure}) when the opt-in metrics are armed; otherwise no-op.
func (s *Server) recordTenantLoginAttempt(ctx HandlerContext, clientID, outcome string) {
	if !s.tenantMetricsEnabled() {
		return
	}
	s.metrics.LoginAttemptsByTenantTotal.WithLabelValues(s.tenantLabel(ctx, clientID), outcome).Inc()
}

// recordTenantTokenIssued bumps the per-tenant token-issue counter
// (by strategy) when the opt-in metrics are armed; otherwise no-op.
func (s *Server) recordTenantTokenIssued(ctx HandlerContext, clientID, strategy string) {
	if !s.tenantMetricsEnabled() {
		return
	}
	s.metrics.TokensIssuedByTenantTotal.WithLabelValues(s.tenantLabel(ctx, clientID), strategy).Inc()
}

// checkQuotaBeforeCreate / CheckClientCreateQuota live in quota.go, alongside
// the compensating-release (charged/denied) variants and the DCR rate-limit
// guard — kept together since they're all DCR-adjacent throttling concerns.
