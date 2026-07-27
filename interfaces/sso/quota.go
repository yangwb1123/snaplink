package sso

import (
	"context"
	"math"
	"net/http"
	"strconv"

	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// checkQuotaBeforeCreate checks if the tenant has capacity to create a
// resource. denied=true means a 403 was already written and the caller must
// stop; charged=true means the caller MUST compensate with
// releaseResourceQuota if the resource creation subsequently fails, so a
// transient store error never permanently over-counts usage.
func (s *Server) checkQuotaBeforeCreate(ctx HandlerContext, tenantID string, resource core.ResourceType) (charged, denied bool) {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false, false
	}
	err := s.tenantQuotaStore.IncrementUsage(ctx.Request().Context(), tenantID, resource, 1)
	switch {
	case err == nil:
		return true, false
	case err == core.ErrQuotaExceeded:
		s.logger.Error("tenant quota exceeded", "tenant_id", tenantID, "resource", resource)
		ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrQuotaExceededCode))
		return false, true
	default:
		s.logger.Error("quota check failed", "tenant_id", tenantID, "resource", resource, "error", err)
		// Fail-open on store errors — don't block resource creation.
		return false, false
	}
}

// releaseResourceQuota compensates a checkQuotaBeforeCreate charge when the
// resource creation it guarded fails afterward. Fail-open: a decrement error
// is logged, never surfacing over the original creation error.
func (s *Server) releaseResourceQuota(ctx context.Context, tenantID string, resource core.ResourceType) {
	if err := s.tenantQuotaStore.DecrementUsage(ctx, tenantID, resource, 1); err != nil {
		s.logger.Error("tenant quota release failed", "tenant_id", tenantID, "resource", resource, "error", err)
	}
}

// chargeSessionQuota increments the tenant's session-quota counter before a
// new session is created (createSession, server_logout.go). denied=true
// means a 403 quota_exceeded was already written and the caller must stop
// without creating anything; charged=true means the caller MUST compensate
// with releaseSessionQuota if session creation subsequently fails, so a
// transient session-store error never permanently over-counts usage.
// Fail-open on a non-quota store error (charged=false, denied=false): a
// store outage must not block login.
func (s *Server) chargeSessionQuota(ctx HandlerContext, tenantID, userID string) (charged, denied bool) {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false, false
	}
	rctx := ctx.Request().Context()
	err := s.tenantQuotaStore.IncrementUsage(rctx, tenantID, core.ResourceSessions, 1)
	switch {
	case err == nil:
		return true, false
	case err == core.ErrQuotaExceeded:
		s.logger.Error("tenant session quota exceeded", "tenant_id", tenantID, "user", userID)
		ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrQuotaExceededCode))
		return false, true
	default:
		s.logger.Error("tenant quota check failed", "tenant_id", tenantID, "error", err)
		return false, false
	}
}

// releaseSessionQuota compensates a chargeSessionQuota charge when the
// session creation it guarded fails afterward. Fail-open: a decrement error
// is logged, never surfacing over the original session-creation error.
func (s *Server) releaseSessionQuota(rctx context.Context, tenantID string) {
	if err := s.tenantQuotaStore.DecrementUsage(rctx, tenantID, core.ResourceSessions, 1); err != nil {
		s.logger.Error("tenant session quota release failed", "tenant_id", tenantID, "error", err)
	}
}

// CheckClientCreateQuota is the oauth.RegisterDeps seam that makes the tenant
// client-create quota LIVE on the DCR /register path. It charges one unit of
// core.ResourceClients against the tenant; denied=true means a 403
// quota_exceeded was already written (the caller must stop). charged=true
// means the caller MUST call ReleaseClientCreateQuota if the client-store
// write subsequently fails. Skips (false, false) when no quota store is
// wired or the client is tenant-less, and fails OPEN on a non-quota store
// error — matching the createSession session-quota precedent.
func (s *Server) CheckClientCreateQuota(ctx HandlerContext, tenantID string) (charged, denied bool) {
	return s.checkQuotaBeforeCreate(ctx, tenantID, core.ResourceClients)
}

// ReleaseClientCreateQuota compensates a CheckClientCreateQuota charge when
// the DCR client-store write fails afterward — without it, a transient
// store error permanently over-counts the tenant's client usage.
func (s *Server) ReleaseClientCreateQuota(ctx context.Context, tenantID string) {
	s.releaseResourceQuota(ctx, tenantID, core.ResourceClients)
}

// defaultClientRegistrationRatePerSec / defaultClientRegistrationRateBurst
// give POST /register (RFC 7591 DCR) a built-in, conservative per-IP rate
// limit that every server gets for free — NewServer seeds it (sso.go); see
// checkClientRegistrationRateLimit's doc below for why an unauthenticated
// (or IAT-shared, effectively public) registration endpoint needs one by
// default rather than requiring every operator to remember to opt in.
// 5/min/IP (burst 5) is generous enough for normal client-provisioning
// bursts (a CI pipeline or onboarding script registering a handful of
// clients back to back) while bounding the worst case to 300/hour/IP —
// several orders of magnitude below what unlimited spam could do to
// client storage.
const (
	defaultClientRegistrationRatePerSec = 5.0 / 60
	defaultClientRegistrationRateBurst  = 5
)

// handleRegister enforces the DCR-specific rate limit, then delegates to
// oauth.HandleRegister (RFC 7591 DCR). Lives here (not handlers.go, where
// every other handleX wrapper is a one-liner) because handlers.go is at its
// 500-line budget ceiling; quota.go groups the DCR-adjacent throttling
// concerns (this + CheckClientCreateQuota above) and has ample headroom.
func (s *Server) handleRegister(ctx HandlerContext) {
	if s.checkClientRegistrationRateLimit(ctx) {
		return
	}
	oauth.HandleRegister(s, ctx)
}

// checkClientRegistrationRateLimit enforces the IP-scoped rate limit on POST
// /register (RFC 7591 DCR). This is DELIBERATELY separate from the global
// security.rate_limit.* policy (rateLimitPolicy / interfaces/ratelimit.Policy
// — opt-in, off by default, and only ever protects this endpoint if an
// operator remembers to add a "/register" prefix rule to it): an
// unauthenticated client-registration endpoint left completely unthrottled is
// a storage-exhaustion / enumeration vector regardless of whether the global
// limiter is wired, so this guard is seeded with a conservative default at
// construction time (see defaultClientRegistrationRatePerSec above) and stays
// on unless an operator explicitly disables it via
// WithClientRegistrationRateLimit(nil).
//
// Keyed by ratelimit.KeyByClientIP — the same trusted-proxies-aware
// IP-extraction the global rate limiter and geo enrichment use, so a
// deployment that already wired WithTrustedProxies gets the validated real
// client IP here too, with no extra configuration.
//
// Returns true (a 429 response already written) when the limit was exceeded.
func (s *Server) checkClientRegistrationRateLimit(ctx HandlerContext) bool {
	lim := s.clientRegistrationRateLimiter
	if lim == nil {
		return false
	}
	ok, retryAfter := lim.Allow(ratelimit.KeyByClientIP(ctx.Request()))
	if ok {
		return false
	}
	// Credential-shaped endpoint (mints a client_secret + registration_access_token
	// on success) — no-store applies to the rejection too, same as every other
	// /register* response (AGENTS.md "Credential Endpoints").
	middleware.TokenNoStoreHeaders(ctx)
	if retryAfter > 0 {
		// Ceiling division: RFC 7231 interprets Retry-After: 0 as "retry
		// immediately", so sub-second durations round up to 1.
		seconds := int(math.Ceil(retryAfter.Seconds()))
		if seconds < 1 {
			seconds = 1
		}
		ctx.ResponseWriter().Header().Set(ratelimit.HeaderRetryAfter, strconv.Itoa(seconds))
	}
	// Reuses the SAME stable "rate_limited" code the global limiter emits
	// (interfaces/ratelimit.ErrRateLimited) rather than inventing a new one —
	// callers that already branch on it for the global limiter get identical
	// behavior here.
	ctx.JSON(http.StatusTooManyRequests, errorBody(ctx, ratelimit.ErrRateLimited))
	return true
}
