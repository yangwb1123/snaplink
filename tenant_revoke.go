package sso

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/oauth"
)

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
	if tenantID == "" {
		return 0, nil
	}
	total, err := s.revokeTenantRefreshTokens(ctx, tenantID)
	// Session revocation is independent of the refresh-token leg's outcome:
	// a refresh-store error must not strand still-valid sessions.
	s.revokeTenantSessions(ctx, tenantID)
	return total, err
}

// revokeTenantRefreshTokens purges every refresh token issued to any client
// belonging to tenantID. Returns (0, nil) when the client store can't
// enumerate by tenant (no TenantScopedClientStore) or the refresh store can't
// purge by client (no oauth.RefreshTokenClientPurger). A per-client purge
// failure is logged + collected but never aborts the remaining clients.
func (s *Server) revokeTenantRefreshTokens(ctx context.Context, tenantID string) (int, error) {
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
		return 0, fmt.Errorf("sso: list tenant clients: %w", err)
	}
	var (
		total int
		errs  []error
	)
	for _, c := range clients {
		n, derr := purger.DeleteAllForClient(ctx, c.ID)
		if derr != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant refresh tokens: client purge failed",
					"error", derr, "tenant", tenantID, "client", c.ID)
			}
			errs = append(errs, derr)
			continue
		}
		total += n
	}
	s.auditTenantTokensRevoked(ctx, tenantID, total)
	return total, errors.Join(errs...)
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
func (s *Server) revokeTenantSessions(ctx context.Context, tenantID string) {
	if s.sessionMgr == nil {
		return
	}
	var total int
	if idx, ok := s.sessionMgr.(SessionTenantIndex); ok {
		n, err := idx.DeleteByTenant(ctx, tenantID)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant sessions: index delete failed",
					"error", err, "tenant", tenantID)
			}
		} else {
			total += n
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
		} else {
			total += s.destroyMemberSessions(ctx, tenantID, members)
		}
	}
	s.auditTenantSessionsRevoked(ctx, tenantID, total)
}

// destroyMemberSessions destroys every active session of the supplied members,
// returning the count destroyed. A per-user enumerate/destroy failure is
// logged and skipped so one bad member can't strand the rest.
func (s *Server) destroyMemberSessions(ctx context.Context, tenantID string, members []*TenantMembership) int {
	var n int
	for _, m := range members {
		if m == nil || m.UserID == "" {
			continue
		}
		sessions, err := s.sessionMgr.ListByUser(ctx, m.UserID)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("revoke tenant sessions: list by user failed",
					"error", err, "tenant", tenantID, "user", m.UserID)
			}
			continue
		}
		for _, sess := range sessions {
			if sess == nil {
				continue
			}
			if err := s.sessionMgr.Destroy(ctx, sess.ID); err != nil {
				if s.logger != nil {
					s.logger.Error("revoke tenant sessions: destroy failed",
						"error", err, "tenant", tenantID, "user", m.UserID)
				}
				continue
			}
			n++
		}
	}
	return n
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
