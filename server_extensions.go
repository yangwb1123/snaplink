package sso

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/caep"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/middleware"
	"github.com/snaplink/sso/security"
)

// temporarily fails.
// matching the JWT issuers' already-configurable skew.

// OIDC Back-Channel Logout 1.0.
//
// When a user logs out of the SSO server (via POST /logout or
// GET /end_session), every relying party that the user has an
// active session with should also tear down its local session
// — otherwise the user is "logged out of one app, still logged
// into N others". OIDC BCL closes that gap by having the AS
// POST a signed logout_token to each RP's registered
// `backchannel_logout_uri`. The RP verifies the token (it's a
// JWT signed by the same key serving the JWKS endpoint) and
// invalidates its session.
//
// Scope of THIS implementation:
//   - Single-RP notification is the default; multi-RP fan-out
//     (notify every RP the user is signed into) engages when
//     [WithSubjectClientIndex] is wired — fanOutBackchannelLogout
//     walks the index for the subject and posts a logout_token to
//     every BCL-capable client.
//   - sid claim is included on the logout_token when the issuer
//     has a session id for the subject (Server-side SessionManager
//     populates one; the access-token issuer stamps it via the
//     RFC 9068 `sid` claim). Fan-out targets keep their original
//     sid when one is recorded; missing-sid targets omit the
//     claim per OIDC BCL §2.4.

// LogoutTokenIssuer mints OIDC Back-Channel Logout 1.0 §2.4
// logout tokens. Same signing key as the access-token issuer is
// the conventional and recommended setup so RPs verify with one
// JWKS entry.
type LogoutTokenIssuer interface {
	IssueLogoutToken(ctx context.Context, req *LogoutTokenRequest) (string, error)
}

// LogoutTokenRequest carries the issuance inputs. TTL falls
// back to a short default when zero — logout tokens are
// single-use and short-lived by nature (the RP processes one
// immediately on receipt).
type LogoutTokenRequest struct {
	Subject  string
	Audience string
	TTL      time.Duration

	// SID is the OIDC Back-Channel Logout 1.0 §2.4 session
	// identifier. When set, the issued logout_token carries a
	// `sid` claim — the RP uses it to invalidate the specific
	// session it received the matching id_token for, rather
	// than wiping every session for the subject. Empty omits
	// the claim (legacy/coarse behavior).
	SID string
}

// LogoutNotifier delivers a signed logout_token to the RP's
// backchannel_logout_uri per OIDC BCL §2.5. Implementations MUST
// respect the supplied context's deadline so the AS isn't
// blocked when an RP is slow or unreachable.
type LogoutNotifier interface {
	Notify(ctx context.Context, uri string, logoutToken string) error
}

// DefaultBackchannelLogoutTimeout caps an individual RP
// notification. Short on purpose — the user is waiting on the
// /logout response while this round-trips, and a slow RP must
// not delay the rest of the logout pipeline. A failure here is
// logged + audited but not fatal.
const DefaultBackchannelLogoutTimeout = 5 * time.Second

// DefaultBackchannelLogoutMaxConcurrent caps the multi-RP fan-out
// parallelism so a user with 50+ active RPs doesn't have /end_session
// open 50 simultaneous outbound HTTP connections (which can starve
// the connection pool + exhaust ephemeral ports under burst). 8 is
// a conservative default that keeps p99 logout latency bounded at
// roughly `timeout × ceil(N / max)` instead of `timeout × N` in the
// serial path. Override with WithBackchannelLogoutMaxConcurrent.
const DefaultBackchannelLogoutMaxConcurrent = 8

// HTTPLogoutNotifier is the production LogoutNotifier. POSTs
// `logout_token=<jwt>` as
// application/x-www-form-urlencoded per OIDC BCL §2.5.
type HTTPLogoutNotifier struct {
	Client *http.Client
}

// NewHTTPLogoutNotifier returns an HTTP notifier with a default
// 5s timeout. Callers may swap in a custom *http.Client to wire
// proxies, custom TLS roots, or tracing instrumentation.
func tokenNoStoreHeaders(ctx HandlerContext) { middleware.TokenNoStoreHeaders(ctx) }

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
// setResourceBearerChallenge stamps the RFC 6750 challenge and, when RFC 9728
// Protected Resource Metadata is enabled, appends the §5.1 resource_metadata
// parameter pointing at the PRM document — so a client (e.g. an MCP / AI-agent
// client) hitting a 401 on a protected resource can discover this resource's
// authorization server. Used ONLY on protected-RESOURCE endpoints (/userinfo,
// /me*), not the AS credential endpoints (those use invalid_client, not a
// bearer-resource challenge).
func (s *Server) setResourceBearerChallenge(ctx HandlerContext, realm, errorCode, errorDescription string) {
	setBearerChallenge(ctx, realm, errorCode, errorDescription)
	if s.protectedResourceMetadata == nil {
		return
	}
	h := ctx.ResponseWriter().Header()
	existing := h.Get("WWW-Authenticate")
	url := requestBaseURL(ctx.Request()) + PathProtectedResourceMetadata
	h.Set("WWW-Authenticate", existing+", resource_metadata="+security.QuoteAuthParam(url))
}

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
// would be noise. Safe to call with a nil Recorder; uses audit.SetMeta so
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
	audit.SetMeta(e, "revoked", strings.Join(revoked, ","))
	audit.SetMeta(e, "failed", strings.Join(failed, ","))
	s.auditor.Record(ctx.Request().Context(), e)
}

// maxSETBodyBytes bounds how much of an inbound SET body the receiver
// reads. A compact-JWS SET is small (header + a few claims + signature);
// 64 KiB is generous for an RSA-4096 signature + a richer subject id yet
// caps a hostile/oversized body before it allocates. The body limit
// middleware (when wired) also caps it; this is a defensive inner bound for
// the byte-stream read regardless of middleware.
const maxSETBodyBytes = 64 << 10

// handleSSFReceive is the opt-in OpenID Shared Signals (CAEP/SSF) push
// delivery RECEIVER endpoint (RFC 8935) — the inbound half of Shared
// Signals, the inverse of the CAEP transmitter. A CONFIGURED trusted
// upstream transmitter POSTs a signed Security Event Token (a compact JWS,
// Content-Type application/secevent+jwt) in the body; the receiver
// validates it FAIL-CLOSED (trusted-iss allowlist + signature against that
// transmitter's JWKS via the alg-confusion-safe security.VerifyCompactJWS +
// aud-binding + exp/iat + jti-replay) and, for a PRECISELY-mapped local
// subject on a revocation event, revokes that subject's local access.
//
// Response contract (RFC 8935):
//   - 202 Accepted on a VALID SET — including a valid SET that maps to no
//     local subject or carries only unknown events (the transmitter did its
//     job; the receiver simply had nothing to do). No body.
//   - 400 with an oracle-safe SSF error body ({err, description}) on a
//     MALFORMED / UNSIGNED / UNTRUSTED-iss / WRONG-aud / EXPIRED / REPLAYED
//     SET. The `err` is a COARSE SSF-standard code (invalid_request /
//     invalid_key); it does NOT reveal which precise gate failed.
//   - 500 only on a transient internal failure AFTER full validation (a
//     resolver/revoke-store outage) — the validated revocation intent is
//     real, so the transmitter should retry rather than the receiver
//     silently dropping it.
//
// This is a credential-bearing endpoint (the SET is a signed bearer
// artefact), so tokenNoStoreHeaders stamps no-store on every response.
func (s *Server) handleSSFReceive(ctx HandlerContext) {
	tokenNoStoreHeaders(ctx)
	if s.caepReceiver == nil {
		// Defensive: the route is only mounted when the receiver is wired,
		// but guard so a future refactor can't reach a nil receiver.
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrServerMisconfigured))
		return
	}

	// Read the compact-JWS SET from the body (bounded). The SET is the body
	// per the SSF push-delivery profile; we don't require an exact
	// Content-Type match (transmitters vary), but cap the size.
	body, err := io.ReadAll(io.LimitReader(ctx.Request().Body, maxSETBodyBytes+1))
	if err != nil || len(body) == 0 || len(body) > maxSETBodyBytes {
		writeSSFError(ctx, caep.ErrReceiverInvalidRequest)
		return
	}

	res, rerr := s.caepReceiver.Receive(ctx.Request().Context(), strings.TrimSpace(string(body)))
	if rerr != nil {
		// A transient internal failure AFTER full validation (the SET was
		// authentic + addressed here, but the revoke/resolve store faltered).
		// 500 so the transmitter retries — we must not ack a revocation we
		// didn't perform. No oracle: the body is a generic internal error.
		ctx.JSON(http.StatusInternalServerError, errorBody(ErrInternal))
		return
	}
	if !res.Acked {
		writeSSFError(ctx, res.RejectCode)
		return
	}
	// Valid + acked (acted or no-op). RFC 8935: 202 with no body.
	ctx.JSON(http.StatusAccepted, struct{}{})
}

// writeSSFError renders an RFC 8935 §2.4 SSF error response: a 400 with a
// minimal {err, description} body. The `err` is the COARSE SSF-standard
// code from the receiver (invalid_request | invalid_key) — it never leaks
// which precise validation gate failed (signature vs aud vs replay vs
// expiry all collapse to invalid_key), so a probing transmitter learns
// only the standard category. The description is a fixed, non-revealing
// string (no per-failure detail).
func writeSSFError(ctx HandlerContext, code string) {
	if code == "" {
		code = caep.ErrReceiverInvalidKey
	}
	desc := "the security event token could not be authenticated"
	if code == caep.ErrReceiverInvalidRequest {
		desc = "the request body is not a valid security event token"
	}
	ctx.JSON(http.StatusBadRequest, map[string]string{
		"err":         code,
		"description": desc,
	})
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
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica clears its local cache
// too — closing the cross-replica window where a just-suspended tenant
// is still honored elsewhere until that node's TTL elapses. Publish
// failures are logged, not propagated: the local invalidation already
// succeeded and peers fall back to their TTL, matching the suspension
// check's fail-open design.
//
// Safe to call when no cache is configured (no-op).
func (s *Server) InvalidateTenantSuspensionCache(tenantID string) {
	if s.tenantSuspensionCache != nil {
		s.tenantSuspensionCache.invalidate(tenantID)
	}
	if s.invalidationBus != nil {
		evt := cluster.Event{Kind: cluster.KindTenantSuspension, Key: tenantID}
		if err := s.invalidationBus.Publish(context.Background(), evt); err != nil {
			s.logger.Error("invalidation bus publish failed", "kind", string(evt.Kind), "key", tenantID, "error", err)
		}
	}
}

// InvalidateClientCache evicts the cached client entity for clientID from
// the opt-in per-login ClientStore cache (WithClientStoreCache). Wire this
// into every client-mutation path — admin ClientAdminService
// Create/Update/Delete/RotateSecret and the RFC 7591/7592 DCR
// register/update/delete handlers — so a metadata edit (redirect_uri /
// scopes / active flag / secret) takes effect on the next Get, not after
// the TTL expires.
//
// When an invalidation bus is wired ([WithInvalidationBus]), this also
// publishes the change so every other replica evicts its local cache too —
// closing the cross-replica window where a just-edited client is still
// served stale elsewhere until that node's TTL elapses. Publish failures
// are logged, not propagated: the local eviction already succeeded and
// peers fall back to their TTL, matching the suspension cache's fail-open
// design.
//
// Safe to call when no cache is configured (no-op). Note this affects only
// the METADATA cache — ValidateSecret bypasses the cache entirely (§2), so
// a credential decision is never stale to begin with.
