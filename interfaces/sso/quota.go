package sso

import (
	"math"
	"net/http"
	"strconv"

	"golang.org/x/time/rate"

	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/shared/core"
)

// checkQuotaBeforeCreate checks if the tenant has capacity to create a
// resource. Returns handled=true when the response is already written
// (quota exceeded or store error).
func (s *Server) checkQuotaBeforeCreate(ctx HandlerContext, tenantID string, resource core.ResourceType) bool {
	if s.tenantQuotaStore == nil || tenantID == "" {
		return false
	}
	if err := s.tenantQuotaStore.IncrementUsage(ctx.Request().Context(), tenantID, resource, 1); err != nil {
		if err == core.ErrQuotaExceeded {
			s.logger.Error("tenant quota exceeded", "tenant_id", tenantID, "resource", resource)
			ctx.JSON(http.StatusForbidden, errorBody(ctx, core.ErrQuotaExceededCode))
			return true
		}
		s.logger.Error("quota check failed", "tenant_id", tenantID, "resource", resource, "error", err)
		// Fail-open on store errors — don't block resource creation.
		return false
	}
	return false
}

// CheckClientCreateQuota is the oauth.RegisterDeps seam that makes the tenant
// client-create quota LIVE on the DCR /register path. It charges one unit of
// core.ResourceClients against the tenant; returns true when a 403
// quota_exceeded was already written (the caller must stop). Skips (false) when
// no quota store is wired or the client is tenant-less, and fails OPEN on a
// non-quota store error — matching the createSession session-quota precedent.
func (s *Server) CheckClientCreateQuota(ctx HandlerContext, tenantID string) bool {
	return s.checkQuotaBeforeCreate(ctx, tenantID, core.ResourceClients)
}

// rateLimiterEntry pairs a token bucket limiter with the grant type it
// gates. Stored in grantRateLimiters by grant type URN.
type rateLimiterEntry struct {
	limiter *rate.Limiter
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
