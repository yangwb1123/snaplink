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

// EntityHandler holds the immutable federation-entity wiring: the operator
// config, the signer (the OP's signing issuer reused via its SignJWT seam),
// the response cache, and the trust-chain resolver (slice 2). Constructed once
// at server build time and shared across requests (both the cache and the
// resolver are concurrency-safe). A nil *EntityHandler on the Server means the
// federation route is not mounted.
type EntityHandler struct {
	cfg      *Config
	signer   JWTSigner
	cache    *EntityConfigCache
	resolver *TrustChainResolver
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
		cfg:      cfg,
		signer:   signer,
		cache:    NewEntityConfigCache(),
		resolver: NewTrustChainResolver(cfg, resolverOpts...),
	}
}

// Config returns the wired federation config (used by the Deps accessor so
// the handler reads TTLs + authority_hints + federation_entity fields).
func (h *EntityHandler) Config() *Config { return h.cfg }

// Signer returns the wired federation JWT signer.
func (h *EntityHandler) Signer() JWTSigner { return h.signer }

// Cache returns the per-issuer Entity Configuration cache.
func (h *EntityHandler) Cache() *EntityConfigCache { return h.cache }

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
