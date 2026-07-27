package federation

import (
	"time"

	"github.com/yangwb1123/snaplink/shared/core"
)

// TrustAnchor names one configured federation trust anchor: its Entity
// Identifier and its published JWKS (its trust-bundle keys). The keys are THE
// ROOT OF TRUST for chain validation — the resolver verifies the anchor's
// fetched Entity Configuration against THESE configured keys, NEVER the keys
// the fetched statement asserts about itself (a forged anchor config carries
// its own keys; trusting them would make the whole chain forgeable). cmd loads
// JWKSFile into Keys at construction so a configured-but-unloadable anchor is a
// boot error (the resolver never silently runs without its root keys).
type TrustAnchor struct {
	// EntityID is the trust anchor's Entity Identifier (an HTTPS URL). A chain
	// is trusted ONLY if it terminates at an entity whose identifier matches
	// one configured here.
	EntityID string
	// JWKSFile is the local path the anchor's JWKS was loaded from. Retained
	// for provenance/diagnostics; the live keys are in Keys.
	JWKSFile string
	// Keys is the anchor's published JWKS — the configured root-of-trust key
	// set the anchor's Entity Configuration is verified against. Populated by
	// cmd (from JWKSFile) or a test (directly). An anchor with no Keys cannot
	// root a chain (validation against an empty key set fails closed).
	Keys []core.JWK
}

// Config carries the operator's federation settings: the entity-PUBLISHING
// fields (consumed by the well-known handler) AND the trust-chain RESOLUTION
// fields (consumed by ResolveTrustChain). TrustAnchors, empty by default,
// gates the resolver: with none configured the resolver is INERT (no anchor =
// no trust to root in), so a default-off build is byte-identical to slice 1.
// A nil *Config means the whole federation surface is OFF.
type Config struct {
	// AuthorityHints are the immediate superiors (Entity Identifiers) whose
	// trust chains this OP participates in. Emitted verbatim in the Entity
	// Configuration's authority_hints; a resolver climbs them toward a trust
	// anchor. Empty = a trust-anchor-only / standalone entity.
	AuthorityHints []string
	// TrustAnchors is the configured set of federation trust anchors — the
	// roots of trust the resolver terminates a chain at and verifies the
	// anchor's Entity Configuration against (TrustAnchor.Keys). A chain that
	// does not reach one of these is REJECTED. Empty ⇒ the resolver is inert.
	TrustAnchors []TrustAnchor
	// OrganizationName + Contacts populate the federation_entity metadata
	// entry. Both optional.
	OrganizationName string
	Contacts         []string

	// Subordinates is the operator-configured set of subordinate entities this
	// server vouches for as a federation SUPERIOR / INTERMEDIATE (OpenID
	// Federation 1.0 §8). Each entry's keys (+ optional metadata_policy /
	// constraints) are AUTHORED into the SIGNED Subordinate Statement the §8
	// Federation Fetch endpoint (PathFederationFetch) issues about it — iss ==
	// this server, sub == the subordinate. EVERYTHING here is OPERATOR CONFIG; a
	// §8 request supplies only `sub` (looked up against EntityID), never the
	// vouched keys. Empty (default) ⇒ this server is a LEAF only: the §8 route
	// is NOT mounted AND the Entity Configuration advertises NO
	// federation_fetch_endpoint — byte-identical to the slice-1 leaf OP. cmd
	// loads each subordinate's jwks_file into Keys at boot (unloadable ⇒ boot
	// error). See fetch.go.
	Subordinates []SubordinateEntity
	// EntityStatementTTL bounds the lifetime stamped into each Entity
	// Configuration (exp - iat). Federation consumers re-fetch after exp.
	// Defaults to DefaultEntityStatementTTL when zero/negative.
	EntityStatementTTL time.Duration
	// CacheTTL controls the in-process body cache + the Cache-Control
	// max-age advertised to downstream caches/CDNs. Defaults to
	// DefaultCacheTTL when zero/negative.
	CacheTTL time.Duration

	// MaxTrustChainDepth bounds how many superiors the resolver will climb
	// from the leaf before giving up (loop/DoS guard, alongside the visited-set
	// cycle detector). Counts authority-hint hops, NOT the leaf itself. 0 ⇒
	// DefaultMaxTrustChainDepth.
	MaxTrustChainDepth int
	// MaxClockSkew widens the exp/iat freshness check at EVERY hop (clock drift
	// between this resolver and each remote entity). Federation statements are
	// long-lived (hours/days), so the skew is a small allowance, never a way to
	// accept a meaningfully-expired statement. 0 ⇒ DefaultFederationClockSkew.
	MaxClockSkew time.Duration

	// ----- automatic-registration abuse resistance (slice 3) ---------------
	//
	// These bound the UNAUTHENTICATED resolution-on-authz surface: an
	// /auth/login with a fake-but-HTTPS client_id that misses the ClientStore
	// triggers a full ResolveTrustChain (up to ~MaxTrustChainDepth-fanout
	// outbound fetches). Without a failure cache + a concurrency bound, distinct
	// fake IDs amplify into an unbounded outbound-fetch DoS / SSRF confused-
	// deputy. They are defense-in-depth — NOT a complete SSRF wall (the operator
	// egress policy is, see doc.go); both apply ONLY when auto-registration is
	// wired and are oracle-safe (a blunted resolution returns the same
	// unknown-client error as any miss). Zero/negative ⇒ the SDK default.

	// ResolutionNegativeCacheTTL is how long a FAILED on-the-fly resolution is
	// remembered (keyed by entity ID) so a repeated fake-but-HTTPS client_id does
	// not re-trigger a fresh unbounded resolution. Kept SHORT on purpose: it only
	// DELAYS re-attempts, so a legit RP whose superior was transiently down
	// retries soon — it is never permanently pinned out. 0 ⇒
	// DefaultResolutionNegativeCacheTTL (30s).
	ResolutionNegativeCacheTTL time.Duration

	// MaxConcurrentResolutions bounds the number of CONCURRENT in-flight
	// trust-chain resolutions across ALL distinct entity IDs. The per-entity
	// coalescing lock already collapses a burst for ONE id; this caps DISTINCT-id
	// parallelism so a flood of fake ids cannot exhaust sockets/goroutines/
	// outbound-fetch budget. When saturated a resolution is NOT attempted and the
	// oracle-safe unknown-client error is returned (fail-closed); a legit RP
	// retries. 0 ⇒ DefaultMaxConcurrentResolutions (16).
	MaxConcurrentResolutions int

	// ResolutionNegativeCacheMaxSize caps the negative cache's entry count so the
	// cache itself cannot become an unbounded-memory DoS under an attacker
	// wielding millions of distinct fake ids. At the cap, expired entries are
	// swept and then the oldest entry is evicted to admit a new one. 0 ⇒
	// DefaultResolutionNegativeCacheMaxSize (1024).
	ResolutionNegativeCacheMaxSize int

	// ----- §7 trust-mark requirement (slice 4b) ----------------------------
	//
	// OpenID Federation 1.0 §7. An EXTRA admission requirement layered ON TOP of
	// the slice-3 auto-registration gate: an auto-registering RP MUST carry a
	// valid Trust Mark (a signed conformance assertion) of EACH required type,
	// else it is not admitted. Empty RequiredTrustMarkTypes ⇒ the gate is OFF
	// (the slice-3 path is byte-identical). Additive + fail-closed: it can only
	// make admission STRICTER, never weaken a slice-2/slice-3 check.

	// RequiredTrustMarkTypes are the Trust Mark Type URIs an auto-registering RP
	// MUST carry (one valid mark per type) to be admitted. Empty (default) ⇒ no
	// trust-mark requirement — slice-3 behavior unchanged. When non-empty, an RP
	// whose validated leaf lacks a valid mark for ANY of these types stays
	// UNKNOWN (oracle-safe, the slice-3 unknown-client path).
	RequiredTrustMarkTypes []string

	// TrustMarkIssuers is the set of AUTHORIZED Trust Mark Issuers — the
	// PRIMARY (operator-configured) source of issuers whose signed Trust Marks
	// can satisfy a RequiredTrustMarkTypes requirement. WHY operator-configured:
	// a Trust Mark is only as trustworthy as the issuer's keys, so the operator
	// pins both the issuer Entity ID AND its keys here. A mark whose iss is NOT
	// in this set, or whose iss IS here but is not authorized for the mark's
	// type (AllowedTypes), or whose signature fails against the issuer's keys →
	// does NOT satisfy via this path. This is the FIRST (and, by default, ONLY)
	// authorized-issuer path; the federation-resolved path below is opt-in and
	// only attempted as a FALLBACK when the configured path doesn't recognize
	// the iss. Only consulted when RequiredTrustMarkTypes is non-empty.
	TrustMarkIssuers []TrustMarkIssuer

	// AllowFederationResolvedTrustMarkIssuers opts into the DYNAMIC-FEDERATION
	// trust-mark issuer path (slice 4c, OpenID Federation 1.0 §3.1.2/§7): a
	// SECOND authorized-issuer source where a Trust Mark Issuer is itself a
	// federation entity, discovered + validated via its trust chain rather than
	// pre-configured. Default FALSE ⇒ ONLY the operator-configured
	// TrustMarkIssuers path runs (the slice-4b gate is byte-identical — zero
	// regression to the reviewed gate). When TRUE: for a required mark whose iss
	// is NOT in TrustMarkIssuers, the issuer is resolved as a federation entity
	// (ResolveTrustChain to a CONFIGURED trust anchor, slice 2, fail-closed) and
	// MUST be listed in that anchor's validated trust_mark_issuers for the
	// required type; only then do the issuer's CHAIN-VALIDATED keys verify the
	// mark (under the same slice-4b sub==RP / signed-type / typ / freshness
	// checks). The authorization ROOT is the configured anchor's
	// trust_mark_issuers — NOT the issuer's self-assertion, NOT the mark, NOT
	// request input. An issuer not chaining to a configured anchor, or not
	// listed for the type, is REJECTED (fail-closed, oracle-safe). The
	// configured path always takes PRECEDENCE (this is only tried on its miss).
	// Requires a resolver with configured trust anchors (otherwise inert). Only
	// consulted when RequiredTrustMarkTypes is non-empty.
	AllowFederationResolvedTrustMarkIssuers bool

	// ----- federation-resolved issuer DoS bounds (slice 4c hardening) ---------
	//
	// The federation-resolved issuer path is a NEW outbound trigger DEEPER than
	// the slice-3 surface: an already-chain-validated leaf can carry an arbitrary
	// `trust_marks` array (the 256KiB leaf cap allows ~1500 entries), and each
	// mark with a DISTINCT iss that is not operator-configured fires its OWN full
	// nested ResolveTrustChain(iss) (~a chain-depth-fanout of fetches, each with
	// its own timeout) BEFORE the mark's signature is even checked. Without a
	// bound, one already-trusted-but-malicious RP amplifies a single registration
	// into hundreds of uncached, concurrency-unbounded nested resolutions — a DoS
	// on the registration/login path. These three knobs bound the per-call
	// fan-out, the global concurrency, and re-resolution of dead issuers. They
	// are consulted ONLY on the federation-resolved path (the flag ON); with the
	// flag off they are never touched (byte-identical to slice 4b). All are
	// fail-CLOSED + oracle-safe: a budget-exceeded / semaphore-saturated /
	// negative-cached issuer simply does not satisfy the required type (the RP
	// stays unknown — the same path as any unsatisfied mark).

	// MaxResolvedIssuersPerRequest bounds the number of DISTINCT issuers a single
	// trust-mark validation (one RP registration) will federation-RESOLVE. The
	// candidate iss values are deduped, so N marks naming the SAME iss cost ONE
	// resolution; beyond the cap, further distinct-iss resolutions are NOT
	// attempted (the required types they would have satisfied go unsatisfied →
	// fail-closed). This caps the per-RP fan-out regardless of how many
	// distinct-iss marks the leaf carries. 0 ⇒ DefaultMaxResolvedIssuersPerRequest
	// (4). Only consulted on the federation-resolved path.
	MaxResolvedIssuersPerRequest int

	// MaxConcurrentIssuerResolutions bounds the GLOBAL number of CONCURRENT
	// nested issuer resolutions across ALL in-flight registrations (independent of
	// the slice-3 resolveSem, which governs the OUTER RP resolution — already
	// consumed by the time the trust-mark gate runs). A non-blocking acquire that
	// FAILS CLOSED when saturated (the resolution is shed, the mark not satisfied,
	// oracle-safe). 0 ⇒ DefaultMaxConcurrentIssuerResolutions (8). Only consulted
	// on the federation-resolved path.
	MaxConcurrentIssuerResolutions int

	// ResolvedIssuerNegativeCacheTTL is how long a FAILED/shed nested issuer
	// resolution is remembered (keyed by issuer Entity ID) so a repeated or
	// distinct-request dead/slow iss is not re-resolved every time. SHORT on
	// purpose (it only DELAYS re-attempts; a legit issuer whose superior was
	// transiently down re-attempts soon — never permanently pinned out). 0 ⇒
	// DefaultResolvedIssuerNegativeCacheTTL (30s). Only consulted on the
	// federation-resolved path.
	ResolvedIssuerNegativeCacheTTL time.Duration

	// ResolvedIssuerNegativeCacheMaxSize caps the resolved-issuer negative cache's
	// entry count so the cache itself cannot become an unbounded-memory DoS. At
	// the cap, expired entries are swept then the soonest-to-expire is evicted. 0
	// ⇒ DefaultResolvedIssuerNegativeCacheMaxSize (1024). Only consulted on the
	// federation-resolved path.
	ResolvedIssuerNegativeCacheMaxSize int

	// MaxLeafTrustMarks caps how many trust_marks entries a validated leaf may
	// carry before the trust-mark scan is bounded (defense-in-depth against an
	// absurd-cardinality leaf — the 256KiB cap permits ~1500 entries, far beyond
	// any legitimate RP). A leaf exceeding the cap fails the trust-mark gate
	// CLOSED (oracle-safe; the RP stays unknown) rather than scanning + resolving
	// thousands of marks. 0 ⇒ DefaultMaxLeafTrustMarks (64). Consulted on BOTH
	// paths (it is a cheap structural bound), but only ever exercised when the
	// trust-mark gate is live (RequiredTrustMarkTypes non-empty).
	MaxLeafTrustMarks int
}

// TrustMarkIssuer names one operator-AUTHORIZED Trust Mark Issuer: its Entity
// Identifier, its published keys (the root of trust for verifying the marks it
// signs), and the Trust Mark Types it is authorized to issue. ONLY a mark
// signed by a configured authorized issuer (iss matches + AllowedTypes permits
// the type + the signature verifies against Keys) can satisfy a required type —
// this is the federation-operator analogue of a trust anchor's
// trust_mark_issuers declaration. cmd loads JWKSFile into Keys at construction
// so a configured-but-unloadable issuer is a boot error (the gate never
// silently runs without an authorized issuer's keys, which would reject every
// otherwise-valid mark and surface as a mysterious admission failure).
type TrustMarkIssuer struct {
	// EntityID is the Trust Mark Issuer's Entity Identifier (the value a Trust
	// Mark's `iss` claim MUST equal to be attributed to this issuer).
	EntityID string
	// JWKSFile is the local path the issuer's JWKS was loaded from. Retained for
	// provenance/diagnostics; the live verification keys are in Keys.
	JWKSFile string
	// Keys is the issuer's published JWKS — the key set a Trust Mark signed by
	// this issuer is verified against (via security.VerifyCompactJWS). An issuer
	// with no Keys can satisfy nothing (verification against an empty set fails
	// closed).
	Keys []core.JWK
	// AllowedTypes restricts which Trust Mark Types this issuer may issue. A
	// non-empty list authorizes ONLY those types (a mark of any other type from
	// this issuer is rejected — an issuer authorized for type X cannot vouch for
	// type Y). EMPTY ⇒ this issuer is authorized for ANY required type (the
	// operator trusts it broadly). The check is on the SIGNED type, so a wrapper
	// cannot relabel a mark into a type its issuer is authorized for.
	AllowedTypes []string
}

// Default lifetimes mirror the discovery/JWKS scale: a long statement TTL
// (consumers re-fetch the configuration roughly daily) with a short body
// cache so a key rotation or metadata change propagates within minutes.
const (
	// DefaultEntityStatementTTL is the default exp - iat window stamped into
	// an Entity Configuration when Config.EntityStatementTTL is unset. 24h is
	// the conventional federation re-fetch cadence.
	DefaultEntityStatementTTL = 24 * time.Hour
	// DefaultCacheTTL is the default in-process body cache + Cache-Control
	// max-age when Config.CacheTTL is unset. Matches the discovery / JWKS
	// 5-minute public-metadata caching window.
	DefaultCacheTTL = 5 * time.Minute
	// DefaultMaxTrustChainDepth bounds the authority-hint climb when
	// Config.MaxTrustChainDepth is unset. 5 superiors is deep for a real
	// federation (leaf -> a couple of intermediates -> anchor); the bound is a
	// DoS/loop guard, not a topology limit operators are expected to tune.
	DefaultMaxTrustChainDepth = 5
	// DefaultFederationClockSkew is the default exp/iat skew allowance per hop
	// when Config.MaxClockSkew is unset. Mirrors the SPIFFE/DPoP 60s default —
	// enough to absorb ordinary clock drift, negligible against multi-hour
	// statement lifetimes.
	DefaultFederationClockSkew = 60 * time.Second

	// DefaultResolutionNegativeCacheTTL is the default lifetime of a cached
	// FAILED automatic-registration resolution when
	// Config.ResolutionNegativeCacheTTL is unset. SHORT (30s) so a repeated fake
	// id is blunted without pinning a legit RP out long (a transient superior
	// outage re-attempts within the window).
	DefaultResolutionNegativeCacheTTL = 30 * time.Second
	// DefaultMaxConcurrentResolutions bounds CONCURRENT distinct-id trust-chain
	// resolutions when Config.MaxConcurrentResolutions is unset. 16 is generous
	// for legitimate first-time-RP bursts while capping a fake-id flood's
	// outbound-fetch/socket fan-out.
	DefaultMaxConcurrentResolutions = 16
	// DefaultResolutionNegativeCacheMaxSize caps the negative cache's entries
	// when Config.ResolutionNegativeCacheMaxSize is unset, so the cache cannot
	// itself become an unbounded-memory DoS.
	DefaultResolutionNegativeCacheMaxSize = 1024

	// DefaultMaxResolvedIssuersPerRequest bounds DISTINCT federation-resolved
	// issuers per trust-mark validation when
	// Config.MaxResolvedIssuersPerRequest is unset. SMALL (4): a legitimate RP
	// carries marks from a handful of issuers at most, so 4 distinct nested
	// resolutions per registration is generous while capping a malicious leaf's
	// ~1500-distinct-iss fan-out.
	DefaultMaxResolvedIssuersPerRequest = 4
	// DefaultMaxConcurrentIssuerResolutions bounds GLOBAL concurrent nested issuer
	// resolutions when Config.MaxConcurrentIssuerResolutions is unset. 8 caps the
	// aggregate nested-resolution fan-out across all in-flight registrations
	// independent of the slice-3 outer-resolution semaphore.
	DefaultMaxConcurrentIssuerResolutions = 8
	// DefaultResolvedIssuerNegativeCacheTTL is the default lifetime of a cached
	// FAILED/shed nested issuer resolution when
	// Config.ResolvedIssuerNegativeCacheTTL is unset. SHORT (30s) so a dead/slow
	// iss is blunted without pinning a legit issuer out long (mirrors the slice-3
	// resolution negative-cache TTL).
	DefaultResolvedIssuerNegativeCacheTTL = 30 * time.Second
	// DefaultResolvedIssuerNegativeCacheMaxSize caps the resolved-issuer negative
	// cache's entries when Config.ResolvedIssuerNegativeCacheMaxSize is unset, so
	// the cache cannot itself become an unbounded-memory DoS.
	DefaultResolvedIssuerNegativeCacheMaxSize = 1024
	// DefaultMaxLeafTrustMarks caps a validated leaf's trust_marks entries when
	// Config.MaxLeafTrustMarks is unset. 64 is far beyond any legitimate RP
	// (which carries a handful of conformance marks) yet a hard ceiling against an
	// absurd-cardinality leaf (the 256KiB cap allows ~1500 entries).
	DefaultMaxLeafTrustMarks = 64
)

// entityStatementTTL returns the configured statement TTL or the default.
func (c *Config) entityStatementTTL() time.Duration {
	if c == nil || c.EntityStatementTTL <= 0 {
		return DefaultEntityStatementTTL
	}
	return c.EntityStatementTTL
}

// cacheTTL returns the configured cache TTL or the default.
func (c *Config) cacheTTL() time.Duration {
	if c == nil || c.CacheTTL <= 0 {
		return DefaultCacheTTL
	}
	return c.CacheTTL
}

// maxTrustChainDepth returns the configured authority-hint climb bound or the
// default.
func (c *Config) maxTrustChainDepth() int {
	if c == nil || c.MaxTrustChainDepth <= 0 {
		return DefaultMaxTrustChainDepth
	}
	return c.MaxTrustChainDepth
}

// maxClockSkew returns the configured per-hop exp/iat skew or the default.
func (c *Config) maxClockSkew() time.Duration {
	if c == nil || c.MaxClockSkew <= 0 {
		return DefaultFederationClockSkew
	}
	return c.MaxClockSkew
}

// maxResolvedIssuersPerRequest returns the configured per-call distinct-issuer
// resolution budget or the default.
func (c *Config) maxResolvedIssuersPerRequest() int {
	if c == nil || c.MaxResolvedIssuersPerRequest <= 0 {
		return DefaultMaxResolvedIssuersPerRequest
	}
	return c.MaxResolvedIssuersPerRequest
}

// maxConcurrentIssuerResolutions returns the configured global nested-resolution
// concurrency bound or the default.
func (c *Config) maxConcurrentIssuerResolutions() int {
	if c == nil || c.MaxConcurrentIssuerResolutions <= 0 {
		return DefaultMaxConcurrentIssuerResolutions
	}
	return c.MaxConcurrentIssuerResolutions
}

// resolvedIssuerNegativeCacheTTL returns the configured resolved-issuer negative
// cache TTL or the default.
func (c *Config) resolvedIssuerNegativeCacheTTL() time.Duration {
	if c == nil || c.ResolvedIssuerNegativeCacheTTL <= 0 {
		return DefaultResolvedIssuerNegativeCacheTTL
	}
	return c.ResolvedIssuerNegativeCacheTTL
}

// resolvedIssuerNegativeCacheMaxSize returns the configured resolved-issuer
// negative cache entry cap or the default.
func (c *Config) resolvedIssuerNegativeCacheMaxSize() int {
	if c == nil || c.ResolvedIssuerNegativeCacheMaxSize <= 0 {
		return DefaultResolvedIssuerNegativeCacheMaxSize
	}
	return c.ResolvedIssuerNegativeCacheMaxSize
}

// maxLeafTrustMarks returns the configured leaf trust_marks count cap or the
// default.
func (c *Config) maxLeafTrustMarks() int {
	if c == nil || c.MaxLeafTrustMarks <= 0 {
		return DefaultMaxLeafTrustMarks
	}
	return c.MaxLeafTrustMarks
}
