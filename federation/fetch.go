package federation

import (
	"net/http"
	"sync"
	"time"

	"github.com/snaplink/sso/core"
)

// OpenID Federation 1.0 §8 — the Federation Fetch endpoint, the SUPERIOR /
// INTERMEDIATE side of federation. Slices 1-4 made THIS server a federation
// LEAF + a trust-chain RESOLVER (the consuming side). This file makes it a
// SUPERIOR: it issues SIGNED Subordinate Statements about the entities the
// operator configured as its subordinates, so a subordinate can list this
// server in its authority_hints and a resolver can climb THROUGH this server
// up to a higher anchor.
//
// # What a Subordinate Statement is (vs the self-signed Entity Configuration)
//
// A Subordinate Statement is the SAME EntityStatementClaims structure as the
// Entity Configuration, but it is NOT self-signed: iss == THIS server (the
// issuing superior), sub == the subordinate, and jwks == the SUBORDINATE's
// keys that THIS server vouches for. The superior MAY additionally impose a
// §10 metadata_policy and §6.2 constraints on the subtree below it — those go
// INTO the Subordinate Statement here (the OP-side AUTHORING of exactly what
// metadata_policy.go / constraints.go ENFORCE on the consuming side). It is
// signed with THIS server's own key (the same key in its JWKS), so a resolver
// that already validated this server's Entity Configuration validates the
// Subordinate Statement with no new trust — chained trust.
//
// # The security crux — vouch only for operator-configured keys
//
// The request supplies ONLY `sub`, which is LOOKED UP in the operator-
// configured subordinates. The vouched jwks + any metadata_policy/constraints
// come from OPERATOR CONFIG (this server vouches for exactly what the operator
// configured), NEVER from request input. An unknown/unregistered sub → 404
// not_found (this server NEVER issues a statement about an entity it was not
// configured to vouch for — that would be vouching for an unvetted entity).
// iss is always == this server (a superior issues only its OWN statements);
// sub is always the looked-up subordinate.
//
// # Opt-in / default-off (byte-identical)
//
// With no subordinates configured, the endpoint is NOT mounted AND this
// server's Entity Configuration advertises NO federation_fetch_endpoint — so a
// default-off build is byte-identical to the slice-1 leaf-OP behavior.

// §8 Federation Fetch request parameter names (OpenID Federation 1.0 §8.1).
// Kept as federation-package consts (alongside EntityStatementTyp /
// ContentTypeEntityStatement) so the §8 wire literals stay centralized
// (AGENTS.md §8). They coincide with the JWT claim names sub/iss but are the
// QUERY-PARAMETER names of the Fetch request.
const (
	// ParamSub is the REQUIRED `sub` query parameter: the Entity Identifier of
	// the subordinate the caller wants a Subordinate Statement about.
	ParamSub = "sub"
	// ParamIss is the OPTIONAL `iss` query parameter: the expected issuer (this
	// server's entity id). When present it MUST equal this server's id.
	ParamIss = "iss"
)

// FederationError codes (OpenID Federation 1.0 §8). The Federation Fetch
// endpoint's error body is the §8 federation error response — a JSON object
// with members `error` + (optional) `error_description`. The JSON MEMBER names
// match the OAuth error shape, but the CODE catalog is the federation one:
//
//   - invalid_request — a required request parameter is missing (no `sub`, or
//     an `iss` that does not equal this server's entity id) → HTTP 400.
//   - not_found — the requested `sub` is not a configured subordinate of this
//     entity → HTTP 404. Federation membership is PUBLIC (a resolver discovers
//     it by walking authority_hints), so a 404 for a non-subordinate is not a
//     credential oracle — it is the spec-mandated answer.
const (
	// ErrFederationInvalidRequest is the §8 invalid_request error (HTTP 400):
	// the Fetch request is missing the required `sub`, or carries an `iss` that
	// is not this server's entity id. Same string value as the OAuth
	// invalid_request, but emitted in the federation error JSON shape.
	ErrFederationInvalidRequest = "invalid_request"
	// ErrFederationNotFound is the §8 not_found error (HTTP 404): the requested
	// `sub` is not a configured subordinate of this entity. NO statement is
	// issued (this server vouches only for operator-configured subordinates).
	ErrFederationNotFound = "not_found"
)

// SubordinateEntity is one operator-configured subordinate this server vouches
// for as a federation SUPERIOR. The Subordinate Statement this server issues
// about it carries iss == this server, sub == EntityID, jwks == Keys (the keys
// this server vouches FOR the subordinate), and optionally the MetadataPolicy /
// Constraints this superior imposes on it. EVERYTHING here is OPERATOR CONFIG —
// the §8 request supplies only `sub` (looked up against EntityID); this server
// NEVER vouches for keys/policy a request supplies.
type SubordinateEntity struct {
	// EntityID is the subordinate's Entity Identifier (an HTTPS URL) — the value
	// a §8 Fetch request's `sub` MUST equal to receive a statement. The issued
	// statement's `sub` is this exact id.
	EntityID string
	// JWKSFile is the local path the subordinate's JWKS was loaded from.
	// Retained for provenance/diagnostics; the live vouched keys are in Keys.
	JWKSFile string
	// Keys is the subordinate's published JWKS as REGISTERED WITH THIS SUPERIOR
	// — the keys this server vouches for in the Subordinate Statement's `jwks`.
	// A resolver climbing through this server verifies the subordinate's own
	// Entity Configuration against THESE keys (the keys the superior published
	// for it), NOT the subordinate's self-asserted keys. cmd loads JWKSFile into
	// Keys at boot so a configured-but-unloadable subordinate is a boot error (a
	// statement vouching for an empty key set would be useless and would fail
	// every downstream chain validation, surfacing as a mysterious resolution
	// failure rather than a named misconfig).
	Keys []core.JWK
	// MetadataPolicy is the OPTIONAL §10 metadata_policy this superior imposes
	// on the subordinate's subtree (the OP-side authoring of what
	// metadata_policy.go enforces). Same raw nested shape as
	// EntityStatementClaims.MetadataPolicy (keyed by metadata type → parameter →
	// operator object). nil ⇒ the statement carries no metadata_policy.
	MetadataPolicy map[string]map[string]map[string]any
	// Constraints is the OPTIONAL §6.2 constraints (max_path_length /
	// naming_constraints / allowed_entity_types) this superior imposes on the
	// subtree below the subordinate (the OP-side authoring of what
	// constraints.go enforces). nil ⇒ the statement carries no constraints.
	Constraints *EntityConstraints
}

// lookupSubordinate returns the configured SubordinateEntity whose EntityID
// equals entityID, or nil on miss. This is the ONLY way the §8 endpoint
// produces a statement: a `sub` that is NOT a configured subordinate never
// matches (→ 404 not_found), so this server never vouches for an unconfigured
// entity. Linear scan over the (small, operator-sized) subordinate list.
func (c *Config) lookupSubordinate(entityID string) *SubordinateEntity {
	if c == nil {
		return nil
	}
	for i := range c.Subordinates {
		if c.Subordinates[i].EntityID == entityID {
			return &c.Subordinates[i]
		}
	}
	return nil
}

// hasSubordinates reports whether the operator configured this server as a
// federation SUPERIOR (≥1 subordinate). Gates BOTH the §8 route mount AND the
// federation_fetch_endpoint advertisement in the Entity Configuration, so a
// no-subordinate config is byte-identical to the slice-1 leaf OP.
func (c *Config) hasSubordinates() bool {
	return c != nil && len(c.Subordinates) > 0
}

// subordinateStatementEntry is one cached, signed Subordinate Statement for a
// given (issuer, subordinate) pair. Mirrors entityConfigEntry exactly: compact
// is the full signed JWS; etag/expiresAt drive the HTTP ETag + freshness.
type subordinateStatementEntry struct {
	compact   []byte
	etag      string
	expiresAt time.Time
}

// fresh reports whether the cached entry is still within its TTL. nil-safe.
func (e *subordinateStatementEntry) fresh(now time.Time) bool {
	return e != nil && now.Before(e.expiresAt)
}

// SubordinateStatementCache caches signed Subordinate Statements keyed by
// (issuer, subordinate). Keyed by BOTH because the statement's iss is the
// resolved issuer (a multi-host server can resolve different issuers, each
// signing its own bytes) and sub is the requested subordinate — so distinct
// subordinates (and distinct issuers) each get their own cached signature,
// bounded by the statement TTL. Reads are sync.Map-served lock-free, mirroring
// EntityConfigCache.
type SubordinateStatementCache struct {
	m sync.Map // "issuer\x00sub" -> *subordinateStatementEntry
}

// NewSubordinateStatementCache returns an empty cache.
func NewSubordinateStatementCache() *SubordinateStatementCache {
	return &SubordinateStatementCache{}
}

// subStmtCacheKey composes the per-(issuer, subordinate) cache key. The NUL
// separator cannot appear in an entity-id URL, so distinct (iss, sub) pairs
// can never collide.
func subStmtCacheKey(issuer, sub string) string { return issuer + "\x00" + sub }

// lookup returns a fresh cached entry for (issuer, sub), or nil on miss/stale.
func (c *SubordinateStatementCache) lookup(issuer, sub string, now time.Time) *subordinateStatementEntry {
	v, ok := c.m.Load(subStmtCacheKey(issuer, sub))
	if !ok {
		return nil
	}
	e, _ := v.(*subordinateStatementEntry)
	if !e.fresh(now) {
		return nil
	}
	return e
}

// store publishes an entry for (issuer, sub).
func (c *SubordinateStatementCache) store(issuer, sub string, e *subordinateStatementEntry) {
	c.m.Store(subStmtCacheKey(issuer, sub), e)
}

// FetchDeps is what HandleFederationFetch needs from the host server.
// *sso.Server satisfies it via accessor methods (accessors.go) — the same
// hexagonal seam HandleEntityConfiguration uses, so the handler body lives in
// this package (which never imports root sso) while the root delegates a
// one-liner. It REUSES the entity-config Deps fields (ResolveIssuer for iss,
// FederationSigner for the SignJWT seam, FederationConfig for the subordinate
// lookup + TTLs, FederationNow for the clock, LogError) and adds only the
// per-statement cache.
type FetchDeps interface {
	// ResolveIssuer returns THIS server's entity identifier for the request
	// (the issuing superior's id — the statement's iss). Same derivation the
	// Entity Configuration uses for its self-signed iss/sub.
	ResolveIssuer(ctx core.HandlerContext) string
	// FederationSigner is the OP signing issuer reused via its SignJWT seam
	// (typ entity-statement+jwt). The statement's kid is one of THIS server's
	// JWKS keys, so a resolver validates it against this server's already-
	// trusted entity-config jwks (chained trust).
	FederationSigner() JWTSigner
	// FederationConfig carries the configured Subordinates (the lookup source)
	// + the statement/cache TTLs. nil ⇒ no federation surface.
	FederationConfig() *Config
	// FederationFetchCache is the per-(issuer, subordinate) signed-statement
	// cache. nil disables caching (the statement is signed every request).
	FederationFetchCache() *SubordinateStatementCache
	// FederationNow is the clock the handler stamps iat/exp from. Injected (not
	// a direct time.Now) so a test drives a fixed time through BOTH the handler
	// and its assertions, keeping exp deterministic.
	FederationNow() time.Time
	// LogError logs a non-fatal error (signing failure). Mirrors the entity-
	// config path.
	LogError(msg string, args ...any)
}

// HandleFederationFetch serves GET /fetch — the OpenID Federation 1.0 §8
// Federation Fetch endpoint, issuing a SIGNED Subordinate Statement about a
// requested subordinate. It:
//
//  1. parses the required `sub` (missing → 400 invalid_request) and the
//     OPTIONAL `iss` (if present, MUST equal this server's entity id, else 400
//     invalid_request — a superior issues only its OWN statements);
//  2. looks `sub` up in the operator-configured Subordinates — UNKNOWN → 404
//     not_found (NO statement; this server vouches only for what it was
//     configured to vouch for);
//  3. builds the Subordinate Statement claims { iss = this server, sub = the
//     subordinate, iat = now, exp = now+TTL, jwks = the subordinate's
//     OPERATOR-CONFIGURED keys, + the OPTIONAL metadata_policy / constraints
//     this superior imposes } and signs via the OP's SignJWT seam (typ
//     entity-statement+jwt);
//  4. ETag + Cache-Control (public, max-age — PUBLIC metadata, NOT no-store)
//     caches per (issuer, sub) and writes the signed JWS, honoring
//     If-None-Match → 304.
//
// A signing failure logs + returns 500 internal_error (mirroring the entity-
// config 500 path). The endpoint is mounted ONLY when subordinates are
// configured, so an unwired build never reaches here (route 404).
func HandleFederationFetch(deps FetchDeps, ctx core.HandlerContext) {
	cfg := deps.FederationConfig()
	now := deps.FederationNow()
	issuer := deps.ResolveIssuer(ctx)

	// §8 request parsing + the operator-config lookup (the trust gate). A bad
	// request or an unknown subordinate has already written the §8 error here.
	sub, subordinate, ok := parseFetchRequest(cfg, ctx, issuer)
	if !ok {
		return
	}

	// Per-(issuer, sub) body cache: skip the SIGN when a recent rendering is
	// fresh (signing can be a KMS round-trip under resolver polling). Honors
	// If-None-Match → 304 via WriteEntityStatement.
	cache := deps.FederationFetchCache()
	if cache != nil {
		if entry := cache.lookup(issuer, sub, now); entry != nil {
			WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), entry.compact, entry.etag, cfg.cacheTTL())
			return
		}
	}

	claims := subordinateStatementClaims(issuer, subordinate, now, cfg.entityStatementTTL())

	compact, err := deps.FederationSigner().SignJWT(ctx.Request().Context(), EntityStatementTyp, claims)
	if err != nil {
		// Mirror the entity-config signing-failure path: log + 500. The signed
		// Subordinate Statement is the whole response, so there is nothing to
		// fall back to.
		deps.LogError("federation: subordinate statement signing failed", "error", err, "sub", sub)
		ctx.JSON(http.StatusInternalServerError, map[string]string{core.KeyError: core.ErrInternal})
		return
	}

	body := []byte(compact)
	etag := buildETag(body)
	if cache != nil {
		cache.store(issuer, sub, &subordinateStatementEntry{compact: body, etag: etag, expiresAt: now.Add(cfg.cacheTTL())})
	}
	WriteEntityStatement(ctx.ResponseWriter(), ctx.Request(), body, etag, cfg.cacheTTL())
}

// parseFetchRequest validates the §8 Fetch request and resolves the requested
// subordinate from operator config. On any failure it writes the §8 error
// response (400 invalid_request for a missing sub / mismatched iss, 404
// not_found for an unconfigured sub) and returns ok=false. On success it
// returns the requested sub + its configured SubordinateEntity.
func parseFetchRequest(cfg *Config, ctx core.HandlerContext, issuer string) (string, *SubordinateEntity, bool) {
	// §8: `sub` is REQUIRED. Missing → 400 invalid_request (the federation
	// error JSON). Fail-closed: no `sub`, no statement.
	sub := ctx.Query(ParamSub)
	if sub == "" {
		federationError(ctx, http.StatusBadRequest, ErrFederationInvalidRequest, "sub is required")
		return "", nil, false
	}
	// §8: `iss` is OPTIONAL but, when present, MUST identify THIS server (the
	// superior issues only its own statements). A mismatched iss → 400
	// invalid_request (not 404: the caller asked the wrong issuer, not for an
	// unknown subordinate).
	if reqIss := ctx.Query(ParamIss); reqIss != "" && reqIss != issuer {
		federationError(ctx, http.StatusBadRequest, ErrFederationInvalidRequest, "iss does not match this entity")
		return "", nil, false
	}

	// The lookup is the trust gate: ONLY a configured subordinate yields a
	// statement. An unknown/unregistered sub → 404 not_found — this server
	// NEVER issues a statement about an entity it was not configured to vouch
	// for (vouching for an unvetted entity would forge trust).
	subordinate := cfg.lookupSubordinate(sub)
	if subordinate == nil {
		federationError(ctx, http.StatusNotFound, ErrFederationNotFound, "not a subordinate of this entity")
		return "", nil, false
	}
	return sub, subordinate, true
}

// subordinateStatementClaims builds the §8 Subordinate Statement claims for a
// configured subordinate. NOT self-signed: iss == this server (the issuing
// superior), sub == the subordinate. The vouched keys + the imposed
// policy/constraints are OPERATOR CONFIG, never request input.
func subordinateStatementClaims(issuer string, subordinate *SubordinateEntity, now time.Time, ttl time.Duration) EntityStatementClaims {
	return EntityStatementClaims{
		Iss:            issuer,
		Sub:            subordinate.EntityID,
		Iat:            now.Unix(),
		Exp:            now.Add(ttl).Unix(),
		JWKS:           EntityJWKS{Keys: subordinate.Keys},
		MetadataPolicy: subordinate.MetadataPolicy,
		Constraints:    subordinate.Constraints,
	}
}

// federationError writes the OpenID Federation 1.0 §8 error response: a JSON
// object with `error` + (optional) `error_description`. The JSON member names
// coincide with the OAuth error shape, but this is the federation error
// CATALOG (not_found / invalid_request) — kept here (not via the OAuth
// errorBody) so the §8 endpoint's error shape is self-contained. Public
// metadata, so NO no-store header (the entity-config path is likewise public).
func federationError(ctx core.HandlerContext, status int, code, description string) {
	body := map[string]string{core.KeyError: code}
	if description != "" {
		body[core.KeyErrorDescription] = description
	}
	ctx.JSON(status, body)
}
