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
// The crux of the spec — building a trust CHAIN from an entity up through its
// authority_hints to a configured trust anchor, and validating each link's
// signature + metadata policy — is the actual trust boundary. It is
// implemented by the TrustChainResolver (trust_chain.go + fetcher.go +
// metadata_policy.go): given a remote leaf Entity Identifier it fetches the
// leaf's Entity Configuration, walks authority_hints up to an operator-
// CONFIGURED trust anchor over SSRF-safe fetches, validates every hop's
// signature against the keys established higher in the chain (the anchor's
// config against the CONFIGURED anchor keys — the root of trust — NEVER the
// fetched keys), checks exp/iat + iss/sub + typ per hop, bounds path length +
// detects cycles, then applies the merged metadata_policy. The well-known
// handler in this file still serves only THIS server's leaf statement; it
// performs no chain resolution itself.
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
// # Slices
//
//   - Slice 1 (this file): entity PUBLISHING — serve the OP's self-signed
//     Entity Configuration at the well-known endpoint.
//   - Slice 2 (trust_chain.go, fetcher.go, metadata_policy.go): trust-chain
//     RESOLUTION + VALIDATION — the trust boundary. TrustAnchor is now LIVE
//     (its configured keys are the root of trust). Opt-in: with no trust
//     anchors configured the resolver is inert (slice-1 behavior byte-
//     identical). No resolver endpoint is mounted (it is a component).
//   - Slice 3 (registration.go): AUTOMATIC client registration via the
//     federation trust chain. RegistrationClientStore decorates the operator's
//     ClientStore; when the authorization endpoint misses a client_id that is a
//     valid HTTPS entity identifier (and federation is active), it resolves the
//     RP's trust chain (ResolveTrustChain) and DERIVES a usable core.Client from
//     the POLICY-CONSTRAINED openid_relying_party metadata — JWKS = the chain-
//     vouched entity keys (asymmetric private_key_jwt / JAR auth), NO shared
//     secret. An invalid/forged/unanchored/expired chain leaves the client_id
//     unknown (the byte-identical unknown-client error — oracle-safe). The
//     derived client runs the SAME authz validation as any client; the metadata
//     policy bounds it (a redirect_uri/response_type/scope the policy disallows
//     is simply absent). Cached per entity ID, bounded by the chain exp. Opt-in
//     via sso.WithFederationAutoRegistration (REQUIRES configured trust
//     anchors); default-off is byte-identical (the decorator is a transparent
//     pass-through when the resolver is inert). The automatic path adds NO new
//     endpoint — it is the existing /auth/login (and /token for client auth).
//
// # Slice 3 — abuse resistance for the on-the-fly resolution (SECURITY)
//
// The resolution TRIGGER is UNAUTHENTICATED: an /auth/login carrying
// client_id=<any HTTPS URL> that misses the ClientStore fires a full
// ResolveTrustChain — up to dozens of outbound HTTPS fetches, including
// authority_hints-derived URLs the leaf itself names. Two amplification
// primitives follow: (1) an attacker with many DISTINCT fake-but-HTTPS
// client_ids forces a fresh resolution each time (DoS); (2) the resolver fetches
// leaf-named authority_hints URLs DURING ASSEMBLY before any trust decision, so
// a hostile leaf can point them at arbitrary EXTERNAL victim URLs — the OP
// becomes an outbound-fetch confused-deputy (SSRF-amplification, https-gated but
// arbitrary external targets).
//
// The RegistrationClientStore decorator carries two in-code mitigations
// (constructed ONLY when auto-registration is wired, so a default-off build is
// unaffected), both oracle-safe — a blunted path returns the SAME unknown-client
// error as any miss, leaking no federation-internal signal:
//
//   - A short-TTL bounded-size NEGATIVE (failure) cache. A failed resolution is
//     remembered per entity ID for federation.ResolutionNegativeCacheTTL (30s
//     default) so a repeated fake id does NOT re-fetch. The TTL is SHORT on
//     purpose: the negative cache only DELAYS re-attempts, so a legit RP whose
//     superior was transiently down retries soon — it is never permanently
//     pinned out. Its entry count is capped
//     (federation.ResolutionNegativeCacheMaxSize, 1024 default; expired entries
//     swept, then oldest evicted) so the cache cannot itself become an
//     unbounded-memory DoS under millions of distinct fake ids.
//   - A global bounded-concurrency semaphore
//     (federation.MaxConcurrentResolutions, 16 default) caps the number of
//     CONCURRENT trust-chain resolutions across ALL distinct entity ids (the
//     per-entity coalescing lock only collapses a burst for ONE id). Saturated ⇒
//     the resolution is SHED and the oracle-safe unknown-client error returned
//     (fail-closed); a legit RP retries.
//
// These are DEFENSE-IN-DEPTH, NOT a complete SSRF wall. When auto-registration
// is enabled the operator MUST also:
//
//   - Front /auth/login with the server rate limiter (sso.WithRateLimit, keyed
//     by client IP — see config rate_limit) so the unauthenticated trigger is
//     per-source throttled.
//   - Run a deny-by-default EGRESS policy. The SSRF containment is the
//     operator's egress policy; the in-code https-only + internal-IP literal
//     gate (validateFederationURL) bounds obvious targets but does NOT stop
//     DNS-rebinding to internal IPs (a hostname that resolves to an internal
//     address still passes the literal-IP gate). The egress firewall is the wall.
//
// # Interop note — private_key_jwt is EdDSA-only (slice 3 caveat)
//
// A federation RP admitted here authenticates asymmetrically via
// private_key_jwt / signed request objects against its chain-vouched JWKS. The
// general client-assertion verifier currently accepts EdDSA only, so a
// federation RP whose chain-vouched keys are ES256/RS256/PS256 is ADMITTED but
// cannot authenticate at /token until it publishes an Ed25519 key. This is a
// broader client-assertion interop gap (not specific to federation) tracked
// separately; nothing here changes the assertion verifier.
package federation
