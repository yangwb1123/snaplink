package config

import "time"

type FederationConfig struct {
	Enabled bool `yaml:"enabled"`

	// AuthorityHints are the immediate superiors (Entity Identifiers, HTTPS
	// URLs) whose trust chains this OP participates in. Emitted verbatim in
	// the Entity Configuration's authority_hints so a federation resolver
	// knows where to climb toward a trust anchor. Empty = a standalone /
	// trust-anchor-only entity.
	AuthorityHints []string `yaml:"authority_hints"`

	// TrustAnchors is the configured set of federation trust anchors. LIVE:
	// each anchor's jwks_file is loaded at boot as the root-of-trust key set the
	// resolver validates a remote entity's chain against (a chain not reaching a
	// configured anchor is rejected). A configured-but-unloadable anchor is a
	// boot error. Empty ⇒ the resolver is inert (entity-publishing only).
	TrustAnchors []TrustAnchorConfig `yaml:"trust_anchors"`

	// Subordinates opts this server into the OpenID Federation 1.0 §8 role of a
	// federation SUPERIOR / INTERMEDIATE: it issues SIGNED Subordinate
	// Statements about these entities at the §8 Federation Fetch endpoint
	// (/fetch), so a subordinate can list this server in its authority_hints and
	// a resolver can climb THROUGH this server up to a higher anchor. Each
	// entry's jwks_file is loaded at boot as the subordinate's keys this server
	// VOUCHES FOR (a configured-but-unloadable subordinate is a boot error);
	// optional metadata_policy / constraints (this superior's imposed limits) are
	// authored into the statement. The §8 request supplies only `sub` (looked up
	// against entity_id), never the vouched keys. Empty (default) ⇒ this server
	// is a LEAF only: the §8 route is NOT mounted AND the Entity Configuration
	// advertises NO federation_fetch_endpoint — byte-identical to a build with no
	// subordinates.
	Subordinates []SubordinateConfig `yaml:"subordinates"`

	// OrganizationName + Contacts populate the federation_entity metadata
	// entry in the Entity Statement. Both optional (omitted when empty).
	OrganizationName string   `yaml:"organization_name"`
	Contacts         []string `yaml:"contacts"`

	// EntityStatementTTL bounds the lifetime (exp - iat) stamped into each
	// Entity Configuration; consumers re-fetch after exp. 0 ⇒ SDK default
	// (24h).
	EntityStatementTTL time.Duration `yaml:"entity_statement_ttl"`

	// CacheTTL controls the in-process body cache + the Cache-Control
	// max-age advertised to downstream caches. 0 ⇒ SDK default (5m).
	CacheTTL time.Duration `yaml:"cache_ttl"`

	// MaxTrustChainDepth bounds how many superiors the trust-chain resolver
	// climbs from a leaf before giving up (a DoS/loop guard alongside cycle
	// detection). 0 ⇒ SDK default (5).
	MaxTrustChainDepth int `yaml:"max_trust_chain_depth"`

	// MaxClockSkew widens the exp/iat freshness check at every hop of trust-
	// chain validation (clock drift between this resolver and remote entities).
	// 0 ⇒ SDK default (60s).
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`

	// AutoRegister opts into OpenID Federation 1.0 AUTOMATIC client
	// registration (slice 3): when true (and trust_anchors are configured), an
	// authorization-endpoint client-store MISS for a valid HTTPS federation
	// entity ID triggers an on-the-fly trust-chain resolution that DERIVES the
	// client from the POLICY-CONSTRAINED openid_relying_party metadata (chain-
	// vouched JWKS for private_key_jwt auth, NO shared secret). A validated
	// federation RP thus becomes a usable OAuth client with no manual
	// registration; an invalid/forged/unanchored chain leaves the client_id
	// unknown (oracle-safe). REQUIRES trust_anchors — enabling it without any
	// is a boot error (there is no root of trust to admit anyone). False ⇒ the
	// authz/token flow is byte-identical (no decoration). SECURITY-SENSITIVE: it
	// admits token-getting clients on the strength of the validated chain.
	//
	// SECURITY (abuse resistance): the resolution trigger is UNAUTHENTICATED —
	// a fake-but-HTTPS client_id that misses the store fires a full outbound
	// trust-chain resolution. Operators enabling this MUST front /auth/login
	// with the server rate limiter (rate_limit / WithRateLimit, keyed by client
	// IP) AND a deny-by-default egress policy (the SSRF containment). The knobs
	// below (negative cache + concurrency cap) are defense-in-depth, NOT a full
	// SSRF wall.
	AutoRegister bool `yaml:"auto_register"`

	// ResolutionNegativeCacheTTL is how long a FAILED on-the-fly resolution is
	// remembered (keyed by entity ID) so a repeated fake-but-HTTPS client_id
	// does not re-trigger a fresh resolution. SHORT on purpose (it only DELAYS
	// re-attempts, so a legit RP whose superior was transiently down retries
	// soon — never permanently pinned out). 0 ⇒ SDK default (30s). Only
	// relevant when auto_register is enabled.
	ResolutionNegativeCacheTTL time.Duration `yaml:"resolution_negative_cache_ttl"`

	// ResolutionMaxConcurrency bounds CONCURRENT in-flight trust-chain
	// resolutions across ALL distinct entity IDs, so a flood of distinct fake
	// IDs cannot exhaust the outbound-fetch / socket budget. Saturated ⇒ the
	// resolution is shed and the oracle-safe unknown-client error returned
	// (fail-closed; a legit RP retries). 0 ⇒ SDK default (16). Only relevant
	// when auto_register is enabled.
	ResolutionMaxConcurrency int `yaml:"resolution_max_concurrency"`

	// ResolutionNegativeCacheMaxSize caps the negative cache's entry count so it
	// cannot itself become an unbounded-memory DoS under an attacker wielding
	// millions of distinct fake IDs (at the cap, expired entries are swept then
	// the oldest is evicted). 0 ⇒ SDK default (1024). Only relevant when
	// auto_register is enabled.
	ResolutionNegativeCacheMaxSize int `yaml:"resolution_negative_cache_max_size"`

	// RequiredTrustMarkTypes opts into the OpenID Federation 1.0 §7 trust-mark
	// requirement (slice 4b): the Trust Mark Type URIs an auto-registering RP
	// MUST each carry a valid Trust Mark for (a signed conformance assertion
	// from a configured authorized Trust Mark Issuer) to be admitted. Layered ON
	// TOP of auto_register — an RP whose validated chain lacks a valid required
	// mark stays UNKNOWN (oracle-safe). Empty (default) ⇒ NO trust-mark
	// requirement; the auto_register path is byte-identical. SECURITY-SENSITIVE:
	// it is a stricter ADMISSION gate; a forged/unauthorized/expired/wrong-
	// subject mark must NOT admit the RP. Only relevant when auto_register is
	// enabled; non-empty REQUIRES at least one trust_mark_issuer (cmd fails
	// loud — a required type with no authorized issuer could never be satisfied,
	// locking out every RP).
	RequiredTrustMarkTypes []string `yaml:"required_trust_mark_types"`

	// TrustMarkIssuers is the set of operator-AUTHORIZED Trust Mark Issuers —
	// the PRIMARY (and, by default, only) issuers whose signed Trust Marks can
	// satisfy a required_trust_mark_types requirement. Each entry pins the issuer
	// Entity ID, its published keys (jwks_file → the root of trust for verifying
	// its marks), and (optionally) the types it may issue. A configured-but-
	// unloadable issuer is a boot error. The federation-resolved issuer path
	// (allow_federation_resolved_trust_mark_issuers, below) is an opt-in
	// FALLBACK; this remains the operator-pinned-keys path. Only relevant when
	// required_trust_mark_types is non-empty.
	TrustMarkIssuers []TrustMarkIssuerConfig `yaml:"trust_mark_issuers"`

	// AllowFederationResolvedTrustMarkIssuers opts into the DYNAMIC-FEDERATION
	// trust-mark issuer path (OpenID Federation 1.0 §3.1.2/§7): a SECOND
	// authorized-issuer source where a Trust Mark Issuer is itself a federation
	// entity, discovered + validated via its trust chain rather than pre-
	// configured in trust_mark_issuers. Default FALSE ⇒ ONLY the operator-
	// configured trust_mark_issuers path runs (byte-identical to the reviewed
	// gate). When TRUE: for a required mark whose iss is NOT in trust_mark_issuers,
	// the issuer is resolved as a federation entity (trust chain to a CONFIGURED
	// trust anchor, fail-closed) and MUST be listed in that anchor's validated
	// trust_mark_issuers for the required type; only then do the issuer's chain-
	// validated keys verify the mark (under the same sub==RP / signed-type /
	// freshness checks). The authorization ROOT is the configured anchor's
	// trust_mark_issuers — NOT the issuer's self-assertion, NOT the mark. An
	// issuer not chaining to a configured anchor, or not anchor-authorized for the
	// type, is rejected. Requires trust_anchors (the root of trust); the
	// configured path always takes precedence. SECURITY-SENSITIVE: it admits
	// marks from dynamically-discovered issuers; the anchor's trust_mark_issuers
	// is the gate. Only relevant when required_trust_mark_types is non-empty +
	// auto_register is enabled.
	AllowFederationResolvedTrustMarkIssuers bool `yaml:"allow_federation_resolved_trust_mark_issuers"`

	// ----- federation-resolved issuer DoS bounds (slice 4c hardening) ---------
	//
	// The federation-resolved issuer path fires a NESTED trust-chain resolution
	// for each distinct, non-configured mark iss BEFORE the mark signature check.
	// An already-chained but malicious RP can carry many distinct-iss marks (the
	// 256KiB leaf cap allows ~1500), amplifying one registration into hundreds of
	// uncached, concurrency-unbounded nested resolutions — a DoS on the
	// registration/login path. These bound the per-request fan-out, the global
	// concurrency, and re-resolution of dead issuers. All fail-closed +
	// oracle-safe; only consulted on the federation-resolved path (the flag ON).
	// Each 0 ⇒ the SDK default. Only relevant when
	// allow_federation_resolved_trust_mark_issuers is true.

	// ResolutionMaxResolvedIssuersPerRequest bounds DISTINCT issuers a single RP
	// registration will federation-RESOLVE (deduped); beyond it, further
	// distinct-iss resolutions are not attempted (the required types they would
	// satisfy go unsatisfied → fail-closed). 0 ⇒ SDK default (4).
	ResolutionMaxResolvedIssuersPerRequest int `yaml:"resolution_max_resolved_issuers_per_request"`

	// ResolutionMaxConcurrentIssuerResolutions bounds GLOBAL concurrent NESTED
	// issuer resolutions across all in-flight registrations (independent of
	// resolution_max_concurrency, which governs the OUTER RP resolution).
	// Saturated ⇒ the nested resolution is shed (fail-closed). 0 ⇒ SDK default (8).
	ResolutionMaxConcurrentIssuerResolutions int `yaml:"resolution_max_concurrent_issuer_resolutions"`

	// ResolvedIssuerNegativeCacheTTL is how long a FAILED/shed nested issuer
	// resolution is remembered (keyed by issuer Entity ID) so a dead/slow iss is
	// not re-resolved on every distinct request. SHORT on purpose. 0 ⇒ SDK
	// default (30s).
	ResolvedIssuerNegativeCacheTTL time.Duration `yaml:"resolved_issuer_negative_cache_ttl"`

	// ResolvedIssuerNegativeCacheMaxSize caps the resolved-issuer negative cache's
	// entries so it cannot itself become an unbounded-memory DoS. 0 ⇒ SDK default
	// (1024).
	ResolvedIssuerNegativeCacheMaxSize int `yaml:"resolved_issuer_negative_cache_max_size"`

	// MaxLeafTrustMarks caps how many trust_marks entries a validated leaf may
	// carry before the trust-mark scan is bounded (defense-in-depth against an
	// absurd-cardinality leaf). A leaf over the cap fails the gate closed. 0 ⇒ SDK
	// default (64). Relevant whenever required_trust_mark_types is non-empty.
	MaxLeafTrustMarks int `yaml:"max_leaf_trust_marks"`

	// ConnectionHealth opts into the federation metadata-health lifecycle:
	// per-peer fetch observability (last success/failure, consecutive
	// failures, last-observed TLS certificate expiry), surfaced read-only at
	// GET /api/v1/admin/federation/health. Default-off (zero value): no
	// wrapping, no store, no route — byte-identical to a build without it.
	ConnectionHealth FederationHealthConfig `yaml:"connection_health"`
}

// FederationHealthConfig opts into tracking each federation peer's
// fetch-path health. PURE OBSERVABILITY: it wraps the SAME hardened
// EntityStatementFetcher the trust-chain resolver already uses via a
// decorator that never alters a fetch's result — trust-chain validation and
// its fail-closed semantics are unaffected either way. This is a queryable
// list an operator polls (or scrapes into their own alerting), NOT a new
// outbound push/notification channel.
type FederationHealthConfig struct {
	// Enabled turns on peer health tracking + mounts the admin listing.
	// False (default) ⇒ byte-identical to a build without this package.
	Enabled bool `yaml:"enabled"`
	// CertExpiryWarning is the "expiring soon" threshold: a tracked peer
	// whose last-observed TLS leaf certificate expires within this window is
	// flagged cert_expiring in the admin listing. 0 ⇒ SDK default (30 days).
	// Only relevant when Enabled.
	CertExpiryWarning time.Duration `yaml:"cert_expiry_warning"`
}

// TrustMarkIssuerConfig names one operator-authorized Trust Mark Issuer for the
// §7 trust-mark requirement: its Entity Identifier, its published JWKS (the
// root of trust the marks it signs are verified against), and (optionally) the
// Trust Mark Types it is authorized to issue. EntityID + JWKSFile are REQUIRED
// when an issuer is listed (the resolver verifies a mark's signature against
// the loaded JWKS, so a missing/empty key set is a boot error, not a silent
// no-issuer). AllowedTypes empty ⇒ authorized for any required type; non-empty
// ⇒ only those types (an issuer authorized for type X cannot vouch for type Y).
type TrustMarkIssuerConfig struct {
	// EntityID is the Trust Mark Issuer's Entity Identifier — the value a Trust
	// Mark's `iss` claim MUST equal to be attributed to this authorized issuer.
	EntityID string `yaml:"entity_id"`
	// JWKSFile is the local path to the issuer's published JWKS document
	// (`{"keys":[...]}`) — the key set its signed Trust Marks are verified
	// against (the root of trust for this issuer).
	JWKSFile string `yaml:"jwks_file"`
	// AllowedTypes restricts which Trust Mark Types this issuer may issue. Empty
	// ⇒ any required type; non-empty ⇒ only the listed type URIs.
	AllowedTypes []string `yaml:"allowed_types"`
}

// TrustAnchorConfig names one configured federation trust anchor: its Entity
// Identifier + its published JWKS. Both are REQUIRED when an anchor is listed;
// the trust-chain resolver verifies the anchor's fetched Entity Configuration
// against the loaded JWKS (the root of trust), so a missing/empty key set is a
// boot error, not a silent no-anchor.
type TrustAnchorConfig struct {
	// EntityID is the trust anchor's Entity Identifier (an HTTPS URL). A chain
	// is trusted only if it terminates at an entity matching this id.
	EntityID string `yaml:"entity_id"`
	// JWKSFile is the local path to the anchor's published JWKS document
	// (`{"keys":[...]}`, its trust bundle) — the root-of-trust key set.
	JWKSFile string `yaml:"jwks_file"`
}

// SubordinateConfig names one entity this server vouches for as an OpenID
// Federation 1.0 §8 SUPERIOR: the entity it issues a SIGNED Subordinate
// Statement about at /fetch. EntityID + JWKSFile are REQUIRED (the statement's
// `jwks` is the loaded key set this server vouches FOR the subordinate, so a
// missing/empty set is a boot error, not a silent vouch-for-nothing). The
// optional MetadataPolicy + Constraints are this superior's imposed limits,
// authored INTO the statement (what metadata_policy.go / constraints.go enforce
// on the consuming side). The §8 request supplies only `sub` (looked up against
// EntityID), never these.
type SubordinateConfig struct {
	// EntityID is the subordinate's Entity Identifier (an HTTPS URL) — the value
	// a §8 Fetch request's `sub` MUST equal to receive a statement.
	EntityID string `yaml:"entity_id"`
	// JWKSFile is the local path to the subordinate's published JWKS document
	// (`{"keys":[...]}`) — the keys this server VOUCHES FOR in the Subordinate
	// Statement's `jwks` (a resolver climbing through this server verifies the
	// subordinate's own Entity Configuration against THESE keys, not its self-
	// asserted ones).
	JWKSFile string `yaml:"jwks_file"`
	// MetadataPolicy is the OPTIONAL §10 metadata_policy this superior imposes on
	// the subordinate's subtree, authored into the statement verbatim. Keyed by
	// metadata type → parameter name → operator object (value/add/default/
	// one_of/subset_of/superset_of/essential), the SAME nested shape the resolver
	// enforces. nil/omitted ⇒ the statement carries no metadata_policy.
	MetadataPolicy map[string]map[string]map[string]any `yaml:"metadata_policy"`
	// Constraints is the OPTIONAL §6.2 constraints this superior imposes on the
	// subtree below the subordinate, authored into the statement. nil/omitted ⇒
	// no constraints.
	Constraints *SubordinateConstraintsConfig `yaml:"constraints"`
}

// SubordinateConstraintsConfig is the YAML projection of the §6.2
// constraints a superior imposes on a subordinate's subtree (max_path_length /
// naming_constraints / allowed_entity_types). Pointer/omitempty fields preserve
// the "absent vs meaningful-zero" distinction the SDK's EntityConstraints
// relies on (e.g. max_path_length 0 = "no intermediates", an EMPTY
// allowed_entity_types = "only federation_entity"). cmd translates this onto
// federation.EntityConstraints.
type SubordinateConstraintsConfig struct {
	// MaxPathLength bounds the intermediates allowed below the subordinate. A
	// pointer because 0 is MEANINGFUL (no intermediates) vs absent (no limit).
	MaxPathLength *int `yaml:"max_path_length"`
	// NamingConstraintsPermitted / Excluded are the §6.2.2 permitted/excluded URI
	// name subtrees restricting subordinate Entity Identifiers (excluded beats
	// permitted). Either empty ⇒ that side is unconstrained; both empty ⇒ no
	// naming_constraints object is emitted.
	NamingConstraintsPermitted []string `yaml:"naming_constraints_permitted"`
	NamingConstraintsExcluded  []string `yaml:"naming_constraints_excluded"`
	// AllowedEntityTypes restricts the §6.2.3 Entity Types below the subordinate.
	// A pointer to a slice because the EMPTY array [] is MEANINGFUL (only
	// federation_entity) vs absent (any type). nil ⇒ absent; a non-nil pointer
	// (even to an empty slice) ⇒ the claim is emitted.
	AllowedEntityTypes *[]string `yaml:"allowed_entity_types"`
}

// DPoPConfig tunes the RFC 9449 DPoP proof iat-window validation. Both
// knobs default to 60s in the SDK (the conventional FAPI 2.0 / RFC 9449
// value); leaving them at 0 wires nothing, so behavior is byte-identical
// to the previous hardcoded 60s. They exist for the same reason the JWT
// issuers expose keys.signing.max_clock_skew: a fleet whose DPoP clients
// drift beyond 60s needs to loosen, and a strict deployment to tighten.
//
// ProofMaxAge bounds how stale a proof may be (iat in the PAST);
// MaxClockSkew bounds how far ahead a client's clock may run (iat in the
// FUTURE). This block governs proof iat only — the optional server-issued
// nonce (security.dpop_nonce) carries its own TTL.
