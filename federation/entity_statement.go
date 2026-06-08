package federation

import (
	"context"
	"sync"
	"time"

	"github.com/snaplink/sso/core"
)

// EntityStatementTyp is the REQUIRED JOSE `typ` header for an Entity
// Statement (OpenID Federation 1.0 §3.1). A verifier that fetched this
// document expecting an entity statement MUST reject any other typ, so a
// plain access/id token signed by the same OP key can never be mistaken for
// a federation statement (the inverse of the issuers' at+jwt typ gate).
const EntityStatementTyp = "entity-statement+jwt"

// ContentTypeEntityStatement is the media type the well-known endpoint
// serves the signed Entity Configuration as (OpenID Federation 1.0 §9). It
// is distinct from application/json so a federation consumer's content
// negotiation routes the JWS to its statement parser, not a JSON decoder.
const ContentTypeEntityStatement = "application/entity-statement+jwt"

// JWTSigner is the narrow generic-JWT signing seam this package consumes to
// sign the Entity Configuration. It is satisfied structurally by the
// Ed25519 / ECDSA / RSA issuers in defaultimpl (their SignJWT method) — the
// SAME signer that mints access + ID + logout tokens and whose public key
// is already published in JWKS. Reusing it means a federation consumer
// validates the Entity Statement with no new trust setup: the statement's
// kid resolves to a key already in the OP's JWKS.
//
// Defined here (not in root sso) so the federation package depends only on
// core + security, keeping the import graph acyclic (root sso imports
// federation for WithFederationEntity; federation must therefore not import
// root sso). The compile-time proof that the issuers satisfy it lives in
// federation/jwtsigner_guard_test.go, NOT in defaultimpl (that would be a
// backwards import edge).
type JWTSigner interface {
	// SignJWT signs claims as a compact JWS stamping `typ` in the header,
	// using the issuer's active signing key + kid. typ MUST be non-empty.
	SignJWT(ctx context.Context, typ string, claims any) (string, error)
}

// EntityStatementClaims is the payload of an Entity Statement (OpenID
// Federation 1.0 §3). For a self-signed Entity Configuration, Iss == Sub ==
// the entity identifier (the issuer URL). JWKS is the entity's OWN key set
// (the statement is signed by one of these keys). Metadata advertises the
// entity's protocol-specific metadata (here: openid_provider +
// federation_entity). AuthorityHints names the immediate superiors whose
// trust chains this entity participates in — a resolver climbs them to
// reach a trust anchor (NOT followed in this slice).
//
// MetadataPolicy is the §10 metadata policy carried on a SUBORDINATE
// Statement (a superior constraining its subordinates); it is absent from a
// self-signed Entity Configuration. It is held as a raw nested map so the
// resolver's policy engine (metadata_policy.go) interprets the operators
// without this model committing to a fixed metadata-field set. omitempty keeps
// the entity-PUBLISHING path (slice 1, which never sets it) byte-identical.
type EntityStatementClaims struct {
	Iss            string          `json:"iss"`
	Sub            string          `json:"sub"`
	Iat            int64           `json:"iat"`
	Exp            int64           `json:"exp"`
	JWKS           EntityJWKS      `json:"jwks"`
	Metadata       *EntityMetadata `json:"metadata,omitempty"`
	AuthorityHints []string        `json:"authority_hints,omitempty"`

	// MetadataPolicy is the §10 metadata_policy claim: per-metadata-type
	// objects of policy operators (value/add/default/one_of/subset_of/
	// superset_of/essential) a superior applies to its subordinates' metadata.
	// Keyed by metadata type (e.g. "openid_relying_party"); each value maps a
	// parameter name to its operator object. Raw nested map so the policy
	// engine owns interpretation. Set only on Subordinate Statements.
	MetadataPolicy map[string]map[string]map[string]any `json:"metadata_policy,omitempty"`

	// Constraints is the §6.2 (anchor chain_constraints) constraints claim: the
	// trust-chain delegation limits a superior (a trust anchor or intermediate)
	// imposes on the subtree of subordinates BELOW it — max_path_length,
	// naming_constraints, allowed_entity_types. Set ONLY on Subordinate
	// Statements (the entity-PUBLISHING path, slice 1, never sets it, so
	// omitempty keeps that path byte-identical). Enforced by constraints.go
	// AFTER the chain is signature-validated, so the limits come from TRUSTED
	// statements. Per §6.2 each statement's constraints are applied
	// INDEPENDENTLY; any failure invalidates the whole chain (fail-closed).
	Constraints *EntityConstraints `json:"constraints,omitempty"`

	// TrustMarks is the §7 trust_marks claim: the array of Trust Marks the
	// entity carries in its OWN Entity Configuration (a self-asserted WRAPPER
	// around each signed Trust Mark JWT). Each entry pairs the unsigned
	// trust_mark_type with the signed trust_mark JWS; the WRAPPER is untrusted
	// (the leaf asserts it about itself), so the SIGNED Trust Mark JWT inside is
	// what trust_marks.go cryptographically validates (issuer signature +
	// sub==leaf + signed-type + freshness). Set on a leaf Entity Configuration;
	// absent from Subordinate Statements. omitempty keeps the slice-1 entity-
	// publishing path (which never sets it) byte-identical.
	TrustMarks []TrustMarkEntry `json:"trust_marks,omitempty"`
}

// TrustMarkEntry is one element of the §7 trust_marks array carried in an
// Entity Configuration: the WRAPPER pairing a Trust Mark Type identifier with
// its signed Trust Mark. Member names follow OpenID Federation 1.0 final (§7):
// `trust_mark_type` (the Type URI) + `trust_mark` (the signed Trust Mark, a
// compact JWS). NOTE the WRAPPER's trust_mark_type is the entity's OWN
// (unsigned) assertion and is therefore NOT authoritative — the trust decision
// reads the trust_mark_type CLAIM inside the signature-validated Trust Mark
// JWT (trust_marks.go), so a wrapper that lies about its type cannot satisfy a
// requirement a different signed type belongs to.
type TrustMarkEntry struct {
	// TrustMarkType is the Trust Mark Type identifier (a URI) this entry claims
	// to carry. Unsigned wrapper metadata — used only to LOCATE a candidate
	// entry for a required type; the authoritative type is the signed claim.
	TrustMarkType string `json:"trust_mark_type"`
	// TrustMark is the signed Trust Mark itself: a compact JWS (typ
	// trust-mark+jwt) issued by a Trust Mark Issuer. This is what is verified.
	TrustMark string `json:"trust_mark"`
}

// EntityConstraints is the §6.2 constraints object carried on a Subordinate
// Statement. Every field is OPTIONAL/pointer so "absent" is distinguishable
// from a meaningful zero value:
//
//   - MaxPathLength is a *int because 0 is MEANINGFUL (no Intermediates may
//     appear between the constraining Entity and the Trust Chain subject —
//     the subject must be a leaf directly below this Entity) whereas absent
//     means "no path-length limit from this statement". A negative value is
//     malformed (§6.2.1 requires >= 0) → fail-closed reject.
//   - NamingConstraints is a *NamingConstraints (absent vs present-but-empty).
//   - AllowedEntityTypes is a *[]string because the EMPTY array [] is
//     MEANINGFUL (only federation_entity is allowed, §6.2.3) and must be
//     distinguished from an absent claim (any Entity Type allowed). A nil
//     pointer = absent; a non-nil pointer to an empty slice = "[]".
type EntityConstraints struct {
	MaxPathLength      *int               `json:"max_path_length,omitempty"`
	NamingConstraints  *NamingConstraints `json:"naming_constraints,omitempty"`
	AllowedEntityTypes *[]string          `json:"allowed_entity_types,omitempty"`
}

// NamingConstraints is the §6.2.2 naming_constraints object: permitted and/or
// excluded URI name subtrees restricting the Entity Identifiers of Subordinate
// Entities. Matching follows RFC 5280 §4.2.1.10 domain-name constraints
// applied to the HOST component of each Entity Identifier (an https URL);
// excluded beats permitted (a host matching ANY excluded entry is invalid
// regardless of the permitted list). See constraints.go for the matcher.
type NamingConstraints struct {
	Permitted []string `json:"permitted,omitempty"`
	Excluded  []string `json:"excluded,omitempty"`
}

// EntityJWKS is the inline JSON Web Key Set (RFC 7517) embedded in an
// Entity Statement's `jwks` claim. For a self-signed Entity Configuration
// it holds the entity's signing public keys — the same keys the OP
// publishes at its JWKS endpoint — so the statement is verifiable against a
// key the consumer already trusts.
type EntityJWKS struct {
	Keys []core.JWK `json:"keys"`
}

// EntityMetadata is the `metadata` claim (OpenID Federation 1.0 §5.1): a map
// keyed by metadata type. This OP advertises the openid_provider entry
// (the OIDC OP metadata, a superset of the discovery doc) and the
// federation_entity entry (federation-level contact/organization info).
// Both are omitempty so a future entity type that is purely a
// federation_entity (e.g. an intermediate authority) can omit the OP block.
type EntityMetadata struct {
	OP               *OPFederationMetadata `json:"openid_provider,omitempty"`
	FederationEntity *FederationEntityMeta `json:"federation_entity,omitempty"`

	// RP is the openid_relying_party metadata entry — the entry the trust-chain
	// RESOLVER reads off a leaf RP's Entity Configuration and that the merged
	// §10 metadata policy is applied to. Held as a raw map (not a typed RP
	// struct) so the policy engine can operate on arbitrary RP parameters and
	// the resolved metadata is returned as-is to the registration path (slice
	// 3). omitempty so this OP's own entity-publishing path (slice 1, which
	// only sets OP + FederationEntity) stays byte-identical.
	RP map[string]any `json:"openid_relying_party,omitempty"`
}

// OPFederationMetadata is the openid_provider metadata subset advertised in
// the Entity Statement (OpenID Federation 1.0 §4.5 — federation OP
// metadata is OIDC discovery metadata plus federation-specific fields). The
// fields here are DERIVED from the server's existing OpenID Connect
// Discovery document (see the OP's BuildOPMetadata projection) so the
// federation view can never drift from the discovery view; federation-only
// fields (client_registration_types_supported, etc.) belong to later
// slices. Required discovery fields (issuer, the endpoints, jwks_uri,
// response_types_supported, subject_types_supported) are always present;
// the rest are omitempty mirroring the discovery doc's own emission rules.
type OPFederationMetadata struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	UserinfoEndpoint                  string   `json:"userinfo_endpoint,omitempty"`
	JWKSURI                           string   `json:"jwks_uri"`
	RegistrationEndpoint              string   `json:"registration_endpoint,omitempty"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	SubjectTypesSupported             []string `json:"subject_types_supported"`
	IDTokenSigningAlgValuesSupported  []string `json:"id_token_signing_alg_values_supported,omitempty"`
	ScopesSupported                   []string `json:"scopes_supported,omitempty"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported,omitempty"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported,omitempty"`
}

// FederationEntityMeta is the federation_entity metadata entry (OpenID
// Federation 1.0 §5.2.1): federation-level descriptive metadata that is NOT
// protocol-specific. All fields are omitempty so the entry collapses to an
// empty object (or is omitted entirely by EntityMetadata's omitempty) when
// the operator configures none.
//
// FederationFetchEndpoint is the §8.1 endpoint a SUPERIOR (an intermediate or
// trust anchor) publishes so a resolver can fetch the Subordinate Statements
// it issues about its subordinates. This OP's own entity-publishing path
// (slice 1) leaves it empty (it is a leaf OP, not a superior); the resolver
// READS it off a superior's fetched Entity Configuration to know where to ask
// for the next link up the chain. omitempty keeps the slice-1 emission
// byte-identical.
type FederationEntityMeta struct {
	OrganizationName        string   `json:"organization_name,omitempty"`
	Contacts                []string `json:"contacts,omitempty"`
	FederationFetchEndpoint string   `json:"federation_fetch_endpoint,omitempty"`

	// TrustMarkIssuers is the §7 (federation_entity) trust_mark_issuers claim a
	// TRUST ANCHOR publishes to declare which issuer Entity IDs are authorized
	// to mint Trust Marks of each type (OpenID Federation 1.0 §3.1.2): a JSON
	// object mapping a trust_mark_type URI to the array of authorized issuer
	// Entity Identifiers. It is the AUTHORIZATION ROOT for the federation-
	// resolved trust-mark path (slice 4c): when a required mark's iss is not
	// operator-pre-configured, the issuer is resolved as a federation entity and
	// MUST be listed here (in the validated ANCHOR config — the root of trust)
	// for the required type. Per spec, an EMPTY array authorizes ANYONE for that
	// type ("anyone MAY issue"); the gate reads this off the CHAIN-VALIDATED
	// anchor config ONLY (the spec mandates it be IGNORED on any non-anchor
	// Entity Configuration, so a self-asserted value on the issuer or an
	// intermediate is never consulted). omitempty keeps the slice-1 entity-
	// publishing path (which never sets it — this OP is a leaf, not an anchor)
	// byte-identical.
	TrustMarkIssuers map[string][]string `json:"trust_mark_issuers,omitempty"`
}

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

// resolutionNegativeCacheTTL returns the configured failed-resolution cache TTL
// or the default.
func (c *Config) resolutionNegativeCacheTTL() time.Duration {
	if c == nil || c.ResolutionNegativeCacheTTL <= 0 {
		return DefaultResolutionNegativeCacheTTL
	}
	return c.ResolutionNegativeCacheTTL
}

// maxConcurrentResolutions returns the configured distinct-id concurrency bound
// or the default.
func (c *Config) maxConcurrentResolutions() int {
	if c == nil || c.MaxConcurrentResolutions <= 0 {
		return DefaultMaxConcurrentResolutions
	}
	return c.MaxConcurrentResolutions
}

// resolutionNegativeCacheMaxSize returns the configured negative-cache entry cap
// or the default.
func (c *Config) resolutionNegativeCacheMaxSize() int {
	if c == nil || c.ResolutionNegativeCacheMaxSize <= 0 {
		return DefaultResolutionNegativeCacheMaxSize
	}
	return c.ResolutionNegativeCacheMaxSize
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

// EntityHandler holds the immutable federation-entity wiring: the operator
// config, the signer (the OP's signing issuer reused via its SignJWT seam),
// the response cache, and the trust-chain resolver (slice 2). Constructed once
// at server build time and shared across requests (both the cache and the
// resolver are concurrency-safe). A nil *EntityHandler on the Server means the
// federation route is not mounted.
type EntityHandler struct {
	cfg        *Config
	signer     JWTSigner
	cache      *EntityConfigCache
	fetchCache *SubordinateStatementCache
	resolver   *TrustChainResolver
}

// NewEntityHandler builds an EntityHandler. Both cfg and signer MUST be
// non-nil for the handler to be usable; the SDK option guards that and
// leaves the Server's field nil (route unmounted) otherwise. The trust-chain
// resolver is built from the SAME config; it is inert (Resolver().Enabled() ==
// false) until the operator configures trust anchors, so a config with no
// anchors keeps slice-1 behavior (the resolver is never invoked) byte-
// identical.
func NewEntityHandler(cfg *Config, signer JWTSigner, resolverOpts ...TrustChainResolverOption) *EntityHandler {
	return &EntityHandler{
		cfg:        cfg,
		signer:     signer,
		cache:      NewEntityConfigCache(),
		fetchCache: NewSubordinateStatementCache(),
		resolver:   NewTrustChainResolver(cfg, resolverOpts...),
	}
}

// Config returns the wired federation config (used by the Deps accessor so
// the handler reads TTLs + authority_hints + federation_entity fields).
func (h *EntityHandler) Config() *Config { return h.cfg }

// Signer returns the wired federation JWT signer.
func (h *EntityHandler) Signer() JWTSigner { return h.signer }

// Cache returns the per-issuer Entity Configuration cache.
func (h *EntityHandler) Cache() *EntityConfigCache { return h.cache }

// FetchCache returns the per-(issuer, subordinate) Subordinate Statement cache
// the §8 Federation Fetch endpoint (fetch.go) uses. Never nil for a
// constructed handler.
func (h *EntityHandler) FetchCache() *SubordinateStatementCache { return h.fetchCache }

// HasSubordinates reports whether this server is configured as a federation
// SUPERIOR (≥1 subordinate). Gates the §8 route mount + the
// federation_fetch_endpoint advertisement (slice-1 byte-identical when false).
func (h *EntityHandler) HasSubordinates() bool { return h.cfg.hasSubordinates() }

// Resolver returns the trust-chain resolver (slice 2). Slice 3 (federation
// client registration) calls Resolver().ResolveTrustChain to validate a remote
// RP's chain up to a configured trust anchor before standing in for out-of-
// band registration. The resolver is inert (returns ErrFederationResolver
// Disabled) until trust anchors are configured. Never nil for a constructed
// handler.
func (h *EntityHandler) Resolver() *TrustChainResolver { return h.resolver }

// entityConfigEntry is one cached, signed Entity Configuration for a given
// issuer URL. compact is the full signed JWS; etag/expiresAt drive the
// HTTP-layer ETag + freshness, mirroring the discovery doc entry. Treated
// as immutable after publication.
type entityConfigEntry struct {
	compact   []byte
	etag      string
	expiresAt time.Time
}

// fresh reports whether the cached entry is still within its TTL. nil-safe.
func (e *entityConfigEntry) fresh(now time.Time) bool {
	return e != nil && now.Before(e.expiresAt)
}

// EntityConfigCache caches the signed Entity Configuration per issuer URL.
// Keyed by issuer (not request base URL) because the statement's iss/sub —
// and therefore the signed bytes — are determined by the resolved issuer;
// the same multi-host server can resolve different issuers, and each gets
// its own cached signature. Reads are sync.Map-served lock-free.
type EntityConfigCache struct {
	m sync.Map // issuer(string) -> *entityConfigEntry
}

// NewEntityConfigCache returns an empty cache.
func NewEntityConfigCache() *EntityConfigCache { return &EntityConfigCache{} }

// lookup returns a fresh cached entry for issuer, or nil on miss/stale.
func (c *EntityConfigCache) lookup(issuer string, now time.Time) *entityConfigEntry {
	v, ok := c.m.Load(issuer)
	if !ok {
		return nil
	}
	e, _ := v.(*entityConfigEntry)
	if !e.fresh(now) {
		return nil
	}
	return e
}

// store publishes an entry for issuer.
func (c *EntityConfigCache) store(issuer string, e *entityConfigEntry) {
	c.m.Store(issuer, e)
}
