// Package federation implements a dependency-free OpenID Federation 1.0
// surface, starting with the OP as a federation ENTITY: it serves the
// server's self-signed Entity Configuration at the well-known endpoint.
//
// # What an Entity Configuration is (OpenID Federation 1.0 §3, §9)
//
// In a federation, every participant (an OP, an RP, an intermediate
// authority, a trust anchor) is an Entity identified by an Entity
// Identifier (an HTTPS URL). Each entity publishes, at
// "<entity-id>/.well-known/openid-federation", an Entity Statement ABOUT
// ITSELF — the Entity Configuration. It is a signed JWS whose payload is an
// Entity Statement with iss == sub == the entity identifier (self-signed,
// §3.1): the entity asserts its OWN keys + metadata. The signature is made
// with one of the keys in the statement's own jwks, so any party that
// already trusts that key (e.g. an RP that has cached this OP's JWKS)
// validates the configuration with NO extra trust setup.
//
// The crux of the spec — building a trust CHAIN from this entity up through
// its authority_hints to a configured trust anchor, and validating each
// link's signature + metadata policy — is the actual trust boundary and is
// a SEPARATE slice. This slice serves the leaf statement only; it performs
// NO chain resolution and grants NO trust. authority_hints are emitted (so
// a resolver knows where to climb) but not followed.
//
// # How it reuses existing machinery (zero new deps)
//
//   - The Entity Configuration is signed via the generic-JWT seam of the
//     SAME signing issuer that mints access + ID + logout tokens
//     (JWTSigner.SignJWT, typ "entity-statement+jwt"). The statement's jwks
//     is exactly the OP's published signing keys, so a verifier validates
//     the configuration against a key already in the OP's JWKS — the same
//     key-reuse rationale the CAEP SET transmitter relies on. It is NOT the
//     access-token Issue path (which stamps typ at+jwt).
//   - openid_provider metadata is DERIVED from the existing OpenID Connect
//     Discovery document (via the OP's BuildOPMetadata projection), not
//     hand-duplicated — so the federation view can never drift from the
//     discovery view.
//   - The response is ETag + Cache-Control cached exactly like the
//     discovery doc (it is public metadata, not a credential — so
//     Cache-Control public, max-age, NOT no-store).
//
// # Opt-in / default-off
//
// Wired via sso.WithFederationEntity; unwired ⇒ the route is NOT mounted and
// behavior is byte-identical to a build without it. The federation package
// imports only core + security and NEVER imports the root sso package (the
// root depends on federation for the option, so the edge must point one
// way) — mirroring the caep package's acyclic boundary.
//
// # Slices beyond this one
//
//   - Slice 2: trust-chain validation — fetch + verify the chain from this
//     entity's authority_hints up to a configured TrustAnchor, applying
//     metadata policy. THAT is the trust boundary. The Config already
//     carries TrustAnchors (present-but-inert here) so the operator config
//     format is forward-compatible.
//   - Slice 3: automatic/explicit client registration via the federation
//     trust chain (an RP's Entity Statement, validated to a trust anchor,
//     stands in for out-of-band client registration).
package federation
