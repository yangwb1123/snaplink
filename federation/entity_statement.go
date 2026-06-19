package federation

import (
	"context"

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
