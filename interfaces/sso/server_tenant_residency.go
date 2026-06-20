package sso

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/domains/tenant"
	"github.com/snaplink/sso/platform/cluster"
)

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

// DefaultTenantResidencyCacheTTL bounds how long a tenant's resolved
// ResidencyPolicy may be cached between lookups. Mirrors the
// suspension-cache TTL rationale: short enough that a policy edit
// (HomeRegion / AllowedRegions / EnforceWrites) propagates promptly across
// the fleet, long enough that hot-path enforcement doesn't hammer the
// tenant store on every request.
const DefaultTenantResidencyCacheTTL = 60 * time.Second

// residencyCacheEntry pairs a tenant's resolved residency policy with its
// freshness deadline. Caching the value-typed policy lets the enforcement
// path skip the tenant.Store round-trip on every check.
type residencyCacheEntry struct {
	policy    region.ResidencyPolicy
	expiresAt time.Time
}

// residencyCache is a tiny TTL map indexed by tenant ID, sized for the
// typical tens-to-low-thousands of tenants (swap to an LRU if you need
// more). Reads take RLock so they don't contend on the enforcement path.
// Mirrors suspensionCache exactly, caching a ResidencyPolicy instead of a
// suspended bool.
type residencyCache struct {
	mu      sync.RWMutex
	entries map[string]*residencyCacheEntry
	ttl     time.Duration
}

func (c *residencyCache) get(tenantID string) (region.ResidencyPolicy, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	e, ok := c.entries[tenantID]
	if !ok {
		return region.ResidencyPolicy{}, false
	}
	if time.Now().After(e.expiresAt) {
		return region.ResidencyPolicy{}, false
	}
	return e.policy, true
}

func (c *residencyCache) put(tenantID string, policy region.ResidencyPolicy) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries[tenantID] = &residencyCacheEntry{
		policy:    policy,
		expiresAt: time.Now().Add(c.ttl),
	}
}

func (c *residencyCache) invalidate(tenantID string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.entries, tenantID)
}

// WithTenantResidencyCheck enables the data-residency enforcement engine:
// a tenant's ResidencyPolicy (derived from its HomeRegion / AllowedRegions
// / EnforceWrites fields) is consulted via [Server.checkTenantResidency] to
// decide whether the serving region may handle a given tenant-bound
// request. A serving region outside the tenant's AllowedRegions yields
// region.ErrRegionNotAllowed; a write that would land outside HomeRegion
// under EnforceWrites yields region.ErrResidencyViolation.
//
// Lookups are cached per tenant ID for ttl (default
// DefaultTenantResidencyCacheTTL when ttl <= 0). Like the suspension
// check, a tenant store outage is treated as FAIL-OPEN — residency is an
// AP/governance control, not a security CP invariant, so a store partition
// must not block the world.
//
// The cache is allocated ONLY here, so a server that never calls this
// option keeps tenantResidencyCache nil and behaves byte-identically to a
// pre-residency build.
//
// Coverage: checkTenantResidency backs BOTH a WRITE-side and a READ-side gate.
//
//   - WRITE side: every token-MINTING path. residencyGateLogin gates the
//     interactive-login mints — the credential path's /auth/login direct/code
//     mint, the prompt=none silent-renewal branch, and the /auth/mfa second
//     leg (handleLogin + handleMFAComplete). residencyGateTokenGrant gates the
//     /token grant endpoint (authorization_code exchange, refresh rotation,
//     token-exchange, CIBA, device, client_credentials) at the post-client-auth
//     choke point — that handler runs in the HandlerContext pipeline, so the
//     live serving region is in scope without threading it through the
//     bare-context issuance helpers. Both use isWrite=true.
//   - READ side (residencyDeniedForAccess): the resource-ACCESS bearer
//     endpoints that serve tenant data — /userinfo (403 region_not_allowed)
//     and the mesh ext_authz endpoint (oracle-safe DENY) — so a still-valid
//     token for a region-constrained tenant cannot be USED from a disallowed
//     serving region. isWrite=false, so only the AllowedRegions check fires.
//     These HTTP handlers have the HandlerContext (hence the serving region)
//     in scope.
//
// Deliberately NOT gated: /token/introspect returns a token-status answer to an
// authenticated RS client, not the data subject's tenant data, and the calling
// RS's region is not the data-serving region — its own {"active":false}
// anti-enumeration contract also makes a residency overlay a poor fit. The
// interactive-login write-gate remains the primary control.
func WithTenantResidencyCheck(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl <= 0 {
			ttl = DefaultTenantResidencyCacheTTL
		}
		s.tenantResidencyEnabled = true
		s.tenantResidencyCache = &residencyCache{
			entries: make(map[string]*residencyCacheEntry),
			ttl:     ttl,
		}
	}
}

// checkTenantResidency is the data-residency enforcement gate. It decides
// whether servingRegion may handle a request for tenantID (a write when
// isWrite). Returns nil when the request is allowed, region.ErrRegionNotAllowed
// when the serving region is outside the tenant's AllowedRegions, or
// region.ErrResidencyViolation when a write would leave the home region
// under EnforceWrites.
//
// Decision order (each early-return is its own "unconstrained" gate):
//
//  1. not enabled / no serving region / no tenant → nil (byte-identical,
//     unconstrained — region is a routing signal, absence means anywhere).
//  2. tenant store outage → nil (FAIL-OPEN — see below).
//  3. empty HomeRegion → nil (tenant set no residency anchor).
//  4. servingRegion == HomeRegion → nil (home is always allowed).
//  5. AllowedRegions non-empty AND servingRegion not in it →
//     ErrRegionNotAllowed.
//  6. isWrite AND EnforceWrites AND servingRegion != HomeRegion →
//     ErrResidencyViolation.
//  7. else → nil.
//
// FAIL-OPEN rationale: residency is an AP/governance control, NOT a
// security CP invariant. A tenant-store partition must not 4xx every
// tenant-bound request across the fleet — we'd rather serve a request in a
// possibly-non-home region for the brief outage window than take the
// service down. This mirrors checkTenantNotSuspended's fail-open exactly
// (an unreachable tenant store, or a not-found tenant, allows the request).
func (s *Server) checkTenantResidency(ctx context.Context, tenantID string, servingRegion region.ID, isWrite bool) error {
	if !s.tenantResidencyEnabled || servingRegion == "" || tenantID == "" {
		return nil
	}

	policy, ok := region.ResidencyPolicy{}, false
	if s.tenantResidencyCache != nil {
		policy, ok = s.tenantResidencyCache.get(tenantID)
	}
	if !ok {
		if s.tenantStore == nil {
			return nil
		}
		t, err := s.tenantStore.GetTenant(ctx, tenantID)
		if err != nil || t == nil {
			// Fail open on store outage (or not-found tenant) — don't 4xx the
			// world during a tenant store partition. Matches
			// checkTenantNotSuspended.
			if err != nil && s.logger != nil {
				s.logger.Error("tenant residency check: tenant store lookup failed; failing open",
					"error", err, "tenant", tenantID)
			}
			return nil
		}
		policy = residencyPolicyFromTenant(t)
		if s.tenantResidencyCache != nil {
			s.tenantResidencyCache.put(tenantID, policy)
		}
	}

	if policy.HomeRegion == "" {
		return nil
	}
	if servingRegion == policy.HomeRegion {
		return nil
	}
	if len(policy.AllowedRegions) > 0 && !slices.Contains(policy.AllowedRegions, servingRegion) {
		return region.ErrRegionNotAllowed
	}
	if isWrite && policy.EnforceWrites && servingRegion != policy.HomeRegion {
		return region.ErrResidencyViolation
	}
	return nil
}

// mapResidencyError maps a checkTenantResidency sentinel onto its public
// wire error code for the authorization-response body. The two residency
// sentinels stay DISTINCT governance codes — region_not_allowed and
// residency_violation reveal a tenant's data-residency binding exactly the
// way tenant_mismatch reveals tenant binding, so collapsing them to a generic
// access_denied would only blur an operator-facing governance signal, NOT
// close any credential-oracle (these carry no anti-enumeration concern, §2).
// An unexpected error falls back to access_denied (safe generic) rather than
// leaking an unmapped internal string.
func (s *Server) mapResidencyError(err error) string {
	switch {
	case errors.Is(err, region.ErrRegionNotAllowed):
		return ErrRegionNotAllowed
	case errors.Is(err, region.ErrResidencyViolation):
		return ErrResidencyViolation
	default:
		return ErrAccessDenied
	}
}

// residencyGateLogin is the data-residency write-gate shared by every
// token-MINTING exit of the interactive-login flow (the credential path's
// /auth/login direct/code mint, the prompt=none silent-renewal branch, and
// the /auth/mfa second leg). It reads the LIVE serving region the region
// middleware stashed on THIS request — so each minting branch is gated by the
// region that will actually mint, not by an earlier leg — and, when the engine
// is wired, rejects a mint that violates the tenant's ResidencyPolicy. Mint is
// the write side, so isWrite=true.
//
// Centralizing the check guarantees every minting path enforces residency
// IDENTICALLY (no copy-paste drift): same authzErrorBody shape (so the RFC
// 9207 iss rides the 403, §2), same distinct governance wire codes from
// mapResidencyError (region_not_allowed / residency_violation, NOT collapsed
// to access_denied — they reveal a tenant's residency binding like
// tenant_mismatch reveals tenant binding, no credential oracle), and exactly
// ONE recordLoginFailure per blocked mint (no double-record, §2).
//
// Returns true when it WROTE the 403 and the caller MUST return without
// minting; false when the mint may proceed. Nil-default byte-identical: no
// region resolver wired → FromHandlerContext reports no region (or empty) →
// the gate never fires; engine not wired → checkTenantResidency returns nil.
func (s *Server) residencyGateLogin(ctx HandlerContext, clientID, provider, tenantID string) (handled bool) {
	servingRegion, ok := region.FromHandlerContext(ctx)
	if !ok || servingRegion == "" {
		return false
	}
	err := s.checkTenantResidency(ctx.Request().Context(), tenantID, servingRegion, true)
	if err == nil {
		return false
	}
	code := s.mapResidencyError(err)
	s.recordLoginFailure(ctx, clientID, provider, code)
	ctx.JSON(http.StatusForbidden, s.authzErrorBody(ctx, code))
	return true
}

// ResidencyDecision is the HandlerContext-FREE residency-decision seam: it
// renders the same write/read residency verdict as the in-pipeline gates
// (residencyGateLogin / residencyDeniedForAccess) but takes a bare
// context.Context + an already-resolved serving region and returns the verdict
// instead of writing an HTTP response.
//
// WHY this exists: some token-MINTING surfaces are mounted by cmd as RAW
// http.HandlerFunc (e.g. the WebAuthn login ceremony in
// cmd/sso-server/webauthn.go), OUTSIDE the HandlerContext pipeline that the
// region middleware uses to stash the serving region — so they can't call the
// unexported checkTenantResidency, and FromHandlerContext has nothing to read.
// This exported seam lets such a handler resolve the serving region itself
// (via a region.Resolver over the raw *http.Request) and reuse the exact same
// policy engine + wire-code mapping, so residency enforcement stays IDENTICAL
// across the in-pipeline and raw-handler mint paths (no policy drift).
//
// Returns ("", false) when the mint/access may proceed — INCLUDING every
// fail-open / unconstrained case checkTenantResidency collapses to nil
// (engine not wired, empty serving region, tenant unconstrained, tenant-store
// outage). Returns (wireCode, true) — region_not_allowed / residency_violation
// from mapResidencyError — when it must be DENIED. isWrite mirrors the calling
// surface (true for a mint, like residencyGateLogin). Nil-safe / byte-identical
// when residency isn't wired: tenantResidencyEnabled is false ⇒ ("", false).
func (s *Server) ResidencyDecision(ctx context.Context, tenantID string, servingRegion region.ID, isWrite bool) (wireCode string, denied bool) {
	err := s.checkTenantResidency(ctx, tenantID, servingRegion, isWrite)
	if err == nil {
		return "", false
	}
	return s.mapResidencyError(err), true
}

// residencyDeniedForAccess is the data-residency READ-gate shared by the
// resource-ACCESS bearer endpoints that serve tenant data (/userinfo + the
// mesh ext_authz endpoint). It completes the read-side of data residency:
// the login write-gate (residencyGateLogin) already blocks ISSUANCE in a
// disallowed region; this rejects a still-valid token when it is USED from a
// serving region the token's tenant doesn't allow.
//
// It returns the public wire code (region_not_allowed) when access must be
// DENIED, or ("", false) when access may proceed. The caller — NOT this
// helper — writes the denial, because the two endpoints have DIFFERENT
// denial shapes: /userinfo answers a 403 JSON body carrying the code (the
// token is valid, so NOT a 401 invalid_token bearer challenge — a policy
// denial is a distinct condition), while mesh ext_authz answers a body-less
// 401 DENY (the mesh contract is binary ALLOW/DENY; a residency-denied
// request is just another DENY, kept indistinguishable from an invalid-token
// DENY so no detail leaks). Centralizing the DECISION keeps both endpoints
// enforcing residency identically while each owns its wire shape.
//
// ZERO-COST WHEN DISABLED: the tenantResidencyEnabled check is FIRST, so a
// non-residency deployment returns before touching the HandlerContext, the
// serving region, or — crucially — the ClientStore. The client/tenant lookup
// (claims.ClientID -> Client.TenantID, the only path to the tenant since
// TokenClaims carries no tenant) is reached ONLY when residency is enabled
// AND the region middleware stashed a non-empty serving region. That keeps
// the hot bearer path byte-identical for the overwhelmingly common
// non-residency case (no extra store round-trip, no allocation).
//
// ORACLE-SAFE: this runs ONLY after the bearer is fully validated (token
// valid + DPoP/mTLS sender-constraint already enforced by the caller), so an
// unauthenticated caller can never reach it — it cannot be used to enumerate
// tenants or probe residency bindings without a valid token. region_not_allowed
// is a governance signal (like tenant_mismatch / tenant suspension), not a
// credential oracle. isWrite=false, so only the AllowedRegions check can fire
// here (ErrResidencyViolation is write-only); a read in a non-home but
// allowed region is permitted.
//
// FAIL-OPEN: checkTenantResidency returns nil on a tenant-store outage, so an
// availability blip never 4xx's tenant-bound reads.
func (s *Server) residencyDeniedForAccess(hctx HandlerContext, claims *TokenClaims) (code string, denied bool) {
	// Gate the whole block — including the ClientStore lookup — on the
	// engine being wired, so a non-residency deployment pays nothing.
	if !s.tenantResidencyEnabled {
		return "", false
	}
	servingRegion, ok := region.FromHandlerContext(hctx)
	if !ok || servingRegion == "" {
		return "", false
	}
	if s.clientStore == nil || claims == nil || claims.ClientID == "" {
		return "", false
	}
	// Resolve the token's tenant. TokenClaims carries no tenant, so the
	// only binding is claims.ClientID -> Client.TenantID. An unknown or
	// tenant-unbound client has nothing to gate on (unconstrained).
	client, err := s.clientStore.Get(hctx.Request().Context(), claims.ClientID)
	if err != nil || client == nil || client.TenantID == "" {
		return "", false
	}
	if rerr := s.checkTenantResidency(hctx.Request().Context(), client.TenantID, servingRegion, false); rerr != nil {
		return s.mapResidencyError(rerr), true
	}
	return "", false
}

// residencyPolicyFromTenant maps a tenant's plain-string residency fields
// into the region.ResidencyPolicy value the enforcement gate operates on.
// tenant/ stays a lower-level package (plain strings); region/ owns the
// typed mapping. Kept separate so it's unit-testable and the cached value
// is the already-typed policy.
func residencyPolicyFromTenant(t *tenant.Tenant) region.ResidencyPolicy {
	var allowed []region.ID
	if len(t.AllowedRegions) > 0 {
		allowed = make([]region.ID, len(t.AllowedRegions))
		for i, r := range t.AllowedRegions {
			allowed[i] = region.ID(r)
		}
	}
	return region.ResidencyPolicy{
		HomeRegion:     region.ID(t.HomeRegion),
		AllowedRegions: allowed,
		EnforceWrites:  t.EnforceWrites,
	}
}

// InvalidateTenantResidencyCache clears the cached residency policy for
// tenantID. Wire this into admin handlers that mutate a tenant's
// HomeRegion / AllowedRegions / EnforceWrites so the change takes effect on
// the next enforcement check, not after the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica clears its local cache too —
// closing the cross-replica window where a stale residency policy is still
// honored elsewhere until that node's TTL elapses. Publish failures are
// logged, not propagated: the local invalidation already succeeded and
// peers fall back to their TTL, matching the residency check's fail-open
// design. Mirrors InvalidateTenantSuspensionCache exactly.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantResidencyCache(tenantID string) {
	if s.tenantResidencyCache != nil {
		s.tenantResidencyCache.invalidate(tenantID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindTenantResidency, Key: tenantID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", tenantID, "error", err)
		}
	}
}

// maybeEncryptIDToken applies OIDC ID Token encryption when the client
// registered an id_token_encrypted_response_alg. It returns the value
// to place in the response and whether emission is safe.
//
//   - Client opted out (empty alg): returns (signed, true) — the plain
//     signed JWS is emitted unchanged.
//   - Client opted in AND encryption succeeds: returns (jwe, true) —
//     the nested JWE(JWS(...)) is emitted.
//   - Client opted in but no encrypter is wired OR encryption fails
//     (missing/unusable RP enc key, crypto failure): returns ("",
//     false) — FAIL CLOSED. The caller MUST omit id_token rather than
//     leak a cleartext token a client explicitly asked to have
//     encrypted. The missing-key vs crypto-failure distinction never
//     reaches the wire (a single omission).
func (s *Server) maybeEncryptIDToken(ctx context.Context, client *Client, signed string) (string, bool) {
	if client == nil || client.IDTokenEncryptedResponseAlg == "" {
		return signed, true
	}
	if s.jweResponseEncrypter == nil {
		s.logger.Error("id_token encryption requested but no JWEResponseEncrypter wired; omitting id_token", "client", client.ID)
		return "", false
	}
	enc := client.IDTokenEncryptedResponseEnc
	if enc == "" {
		enc = "A256GCM"
	}
	jwe, err := s.jweResponseEncrypter.Encrypt(ctx, []byte(signed), client.JWKS, client.IDTokenEncryptedResponseAlg, enc)
	if err != nil {
		// Undifferentiated: missing key and crypto failure both land
		// here and both omit the token (no oracle).
		s.logger.Error("id_token encryption failed; omitting id_token", "error", err, "client", client.ID)
		return "", false
	}
	return jwe, true
}
