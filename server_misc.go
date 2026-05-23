package sso

import (
	"context"
	"errors"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/tenant"
)

// Small Server-coupled response helpers grouped here for navigability.
// Formerly lived in standalone files (token_no_store.go, bearer_challenge.go,
// audit_partial_revoke.go); merged because the concern is one: shape an
// HTTP response with security / audit headers or events.

// tokenNoStoreHeaders stamps RFC 6749 §5.1 cache-prevention headers
// on credential-bearing responses. /token, /token/introspect,
// /token/revoke and /par all return data that intermediaries MUST
// NOT retain — leaked tokens replayed off a cache would defeat
// the rotation + revocation invariants the rest of the server
// enforces. Pragma: no-cache is the HTTP/1.0 companion the RFC
// requires alongside Cache-Control; both go on every response
// regardless of status so error bodies (which include error_code
// shapes a snooping cache could fingerprint) get the same
// treatment as success.
func tokenNoStoreHeaders(ctx HandlerContext) {
	h := ctx.ResponseWriter().Header()
	h.Set("Cache-Control", "no-store")
	h.Set("Pragma", "no-cache")
}

// setBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header
// on a 401 response. Protected resources that accept Bearer tokens
// MUST include this challenge so RPs know which scheme to use and
// can branch on `error=invalid_token` to trigger a refresh vs.
// `error=insufficient_scope` (reserved for /userinfo scope gates
// added later).
//
// realm: the protection space — defaulted to "sso" when the
// issuer can't be resolved. errorCode / errorDescription: omitted
// for the "no credentials presented" case (RFC §3.1: error
// parameters are only included when the request had a token that
// failed validation). Description values are quoted-string escaped
// per RFC 7235 §2.2 so untrusted upstream values can't break out
// and inject additional auth-params.
func setBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	if realm == "" {
		realm = "sso"
	}
	parts := []string{`Bearer realm=` + security.QuoteAuthParam(realm)}
	if errorCode != "" {
		parts = append(parts, `error=`+security.QuoteAuthParam(errorCode))
	}
	if errorDescription != "" {
		parts = append(parts, `error_description=`+security.QuoteAuthParam(errorDescription))
	}
	ctx.ResponseWriter().Header().Set("WWW-Authenticate", strings.Join(parts, ", "))
}

// auditPartialRevokeFailure emits an `EventPartialRevokeFailure` event
// when at least one TokenIssuer failed to revoke a token while at
// least one succeeded — the "logout everywhere" promise has been
// partially violated and operators MUST follow up manually before the
// failed-issuer's tokens reach natural expiry.
//
// Both lists are recorded so SIEM filters can compute the success
// ratio over time and alert when failed/(revoked+failed) crosses a
// threshold. When failed is empty (full success or "no issuer owned
// this token"), this is a no-op — emitting an event in those cases
// would be noise. Safe to call with a nil Recorder; uses setMeta so
// geo + tenant middleware enrichment isn't clobbered.
func (s *Server) auditPartialRevokeFailure(ctx HandlerContext, revoked, failed []string) {
	if s.auditor == nil || len(failed) == 0 {
		return
	}
	e := &audit.Event{
		Type:      audit.EventPartialRevokeFailure,
		Outcome:   audit.OutcomeFailure,
		Timestamp: time.Now(),
	}
	setMeta(e, "revoked", strings.Join(revoked, ","))
	setMeta(e, "failed", strings.Join(failed, ","))
	s.auditor.Record(ctx.Request().Context(), e)
}

// BuildInfo captures the deployment's version + VCS identity.
// Reads runtime/debug.ReadBuildInfo at first call; cached so
// /health is cheap. Operators investigating which commit a
// production replica is running read this from the unauthenticated
// health endpoint — saves a shell into the container.
//
// Fields are best-effort: when the binary wasn't built with
// `-buildvcs=true` (default for `go build`) or via `go install`
// from a non-VCS path, VCSRevision + VCSTime will be empty. Version
// defaults to "(devel)" when not built from a tagged module —
// matches the runtime/debug behavior so operators see something
// rather than an empty field.
type BuildInfo struct {
	Version     string `json:"version"`
	VCSRevision string `json:"vcs_revision,omitempty"`
	VCSTime     string `json:"vcs_time,omitempty"`
}

var (
	buildInfoOnce sync.Once
	buildInfoVal  BuildInfo
)

// ReadBuildInfo returns the cached BuildInfo, populating from
// runtime/debug.ReadBuildInfo on first call. Safe for concurrent
// use. Returns the zero value when the binary lacks build info
// (e.g. `go run` without -trimpath) — the health endpoint then
// surfaces Version="(devel)" without VCS fields, which operators
// can still read as a meaningful "this is a dev build" signal.
func ReadBuildInfo() BuildInfo {
	buildInfoOnce.Do(func() {
		info, ok := debug.ReadBuildInfo()
		if !ok {
			buildInfoVal = BuildInfo{Version: "(unknown)"}
			return
		}
		buildInfoVal.Version = info.Main.Version
		if buildInfoVal.Version == "" {
			buildInfoVal.Version = "(devel)"
		}
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				buildInfoVal.VCSRevision = s.Value
			case "vcs.time":
				buildInfoVal.VCSTime = s.Value
			}
		}
	})
	return buildInfoVal
}

// DefaultTenantSuspensionCacheTTL bounds how long a tenant's
// suspension state may be cached between lookups. Short enough that
// a Suspended → Active or Active → Suspended flip propagates
// promptly across the fleet; long enough that hot-path token
// validation doesn't hammer the tenant store on every request.
const DefaultTenantSuspensionCacheTTL = 30 * time.Second

// ErrTenantSuspended is returned by Validate when the token's
// owning client belongs to a tenant whose Status is Suspended.
// Resource paths map this to invalid_token; introspect maps it to
// inactive — same shape every other validation failure produces, so
// an attacker can't probe "is this tenant suspended?" by inspecting
// the error.
var ErrTenantSuspended = errors.New("sso: tenant suspended")

// suspensionCacheEntry pairs a tenant's suspended state with its
// freshness deadline. Caching the boolean lets the hot path skip the
// tenant.Store round-trip on every token validation.
type suspensionCacheEntry struct {
	suspended bool
	expiresAt time.Time
}

// suspensionCache is a tiny TTL map indexed by tenant ID. Sized for
// the typical tens-to-low-thousands of tenants; if you need more,
// swap to an LRU. Reads take RLock so they don't contend on the hot
// validate path.
type suspensionCache struct {
	mu      sync.RWMutex
	entries map[string]suspensionCacheEntry
	ttl     time.Duration
}

func newSuspensionCache(ttl time.Duration) *suspensionCache {
	return &suspensionCache{
		entries: make(map[string]suspensionCacheEntry),
		ttl:     ttl,
	}
}

func (c *suspensionCache) get(tenantID string) (suspended bool, fresh bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return false, false
	}
	if time.Now().After(e.expiresAt) {
		return false, false
	}
	return e.suspended, true
}

func (c *suspensionCache) put(tenantID string, suspended bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = suspensionCacheEntry{
		suspended: suspended,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *suspensionCache) invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// WithTenantSuspensionCheck enables a post-validation gate: every
// token whose owning client is bound to a tenant
// (Client.TenantID != "") has the tenant's Status looked up; tokens
// whose tenant is Suspended fail validation. Combined with the
// existing tenant_mismatch gate at issuance, this closes the gap
// where a token issued while the tenant was Active continues to
// work after suspension.
//
// Lookups are cached per tenant ID for ttl (default
// DefaultTenantSuspensionCacheTTL when ttl <= 0). A tenant store
// outage is treated as fail-open — the request proceeds with the
// cached value (or no check, if the cache hasn't seen this tenant
// yet) — because we'd rather serve stale-Active than 401 every
// request during a tenant store partition.
//
// No-op when no tenant store has been wired via [WithTenantStore].
func WithTenantSuspensionCheck(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultTenantSuspensionCacheTTL
		}
		s.tenantSuspensionEnabled = true
		s.tenantSuspensionCache = newSuspensionCache(ttl)
	}
}

// InvalidateTenantSuspensionCache clears the cached suspension state
// for tenantID. Wire this into admin SetStatus handlers so that an
// operator flipping Suspended → Active or Active → Suspended takes
// effect on the next validate, not after the TTL expires.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantSuspensionCache(tenantID string) {
	if s.tenantSuspensionCache == nil {
		return
	}
	s.tenantSuspensionCache.invalidate(tenantID)
}

// checkTenantNotSuspended is the post-validation gate. Returns nil
// when the token is allowed to proceed (no tenant binding, no store,
// store unreachable, or tenant active) and ErrTenantSuspended when
// the token's tenant has been suspended.
func (s *Server) checkTenantNotSuspended(ctx context.Context, claims *TokenClaims) error {
	if !s.tenantSuspensionEnabled {
		return nil
	}
	if s.tenantStore == nil || s.clientStore == nil {
		return nil
	}
	if claims == nil || claims.ClientID == "" {
		return nil
	}
	client, err := s.clientStore.Get(ctx, claims.ClientID)
	if err != nil || client == nil || client.TenantID == "" {
		// Unknown client or unbound client — nothing to gate on.
		return nil
	}
	if s.tenantSuspensionCache != nil {
		if suspended, fresh := s.tenantSuspensionCache.get(client.TenantID); fresh {
			if suspended {
				return ErrTenantSuspended
			}
			return nil
		}
	}
	t, err := s.tenantStore.GetTenant(ctx, client.TenantID)
	if err != nil || t == nil {
		// Fail open on store outage; don't 401 the world.
		return nil
	}
	suspended := t.Status == tenant.StatusSuspended
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.put(client.TenantID, suspended)
	}
	if suspended {
		return ErrTenantSuspended
	}
	return nil
}
