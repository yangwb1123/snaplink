package sso

import (
	"time"

	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/oidc"
)

// WithJWKSCacheTTL overrides the Cache-Control max-age advertised
// on /.well-known/jwks.json. Default is [DefaultJWKSCacheMaxAge]
// (5 minutes). Lower this when key rotation must propagate faster;
// raise it when RP traffic strains the JWKS endpoint.
//
// Note: many RP libraries cache the JWKS in-process past the
// max-age signal, so the practical lower bound depends on the RP
// fleet's behavior. Validating-side ETag + 304 keeps the round
// trips cheap, so an aggressive low value (30s-60s) is usually
// safe without flooding origins.
func WithJWKSCacheTTL(ttl time.Duration) Option {
	return func(s *Server) { s.jwksCacheTTL = ttl }
}

// WithMetadataSigner enables RFC 8414 §2.1 signed_metadata on the
// discovery document. When wired, every /.well-known/openid-configuration
// response carries a `signed_metadata` field whose value is a JWS over
// the same claims as the surrounding document; RPs verify the
// signature against JWKS before trusting any endpoint. Defends
// against a tampering proxy substituting endpoints — a security
// improvement that's a one-line opt-in.
//
// Both the default Ed25519JWTIssuer and oidc.IDTokenIssuer satisfy
// oidc.MetadataSigner — pass either, typically the same instance already
// wired as TokenIssuer / oidc.IDTokenIssuer so JWKS continues to cover
// metadata signing with one key.
func WithMetadataSigner(s oidc.MetadataSigner) Option {
	return func(srv *Server) { srv.metadataSigner = s }
}

// WithFederationEntity mounts the OpenID Federation 1.0 entity-configuration
// endpoint (PathFederationEntityConfig, "/.well-known/openid-federation"),
// serving this server's SELF-SIGNED Entity Statement so the OP participates
// in a multilateral federation as an ENTITY (eduGAIN / research / government
// trust frameworks). The statement carries iss == sub == issuer, the OP's
// published signing keys inline (jwks), openid_provider metadata DERIVED
// from the discovery doc, and the operator's authority_hints; it is signed
// via the issuer's generic SignJWT seam with typ "entity-statement+jwt" —
// the SAME key already in JWKS, so a federation consumer validates it with
// no new trust setup. ETag + Cache-Control (public, max-age) cached — it is
// public metadata, NOT a credential.
//
// signer is the OP signing issuer (typically the same instance wired as
// WithTokenIssuer / WithIDTokenIssuer, so one key covers tokens, id_tokens,
// SETs, and the entity statement). cfg carries authority_hints,
// organization/contacts, the TTLs, and (present-but-inert in this slice) the
// trust anchors.
//
// Opt-in / default-off: a nil cfg OR a nil signer leaves the Server's field
// nil — the route is NOT mounted and behavior is byte-identical to a build
// without it. This is the entity-PUBLISHING slice; trust-chain VALIDATION
// (resolving authority_hints up to a trust anchor — the actual trust
// boundary) and federation client registration are separate slices.
// resolverOpts are forwarded to the trust-chain resolver the handler builds
// (the test seam: WithTrustChainFetcher injects a fake federation,
// WithTrustChainClock a fixed instant; an operator may inject a proxy-aware
// fetcher). They configure ONLY the slice-2 resolver — when no trust anchors
// are configured the resolver is inert regardless, so passing options to a
// no-anchor config stays byte-identical to slice 1.
func WithFederationEntity(cfg *federation.Config, signer federation.JWTSigner, resolverOpts ...federation.TrustChainResolverOption) Option {
	return func(srv *Server) {
		if cfg == nil || signer == nil {
			return
		}
		srv.federationEntity = federation.NewEntityHandler(cfg, signer, resolverOpts...)
	}
}

// WithFederationAutoRegistration opts into OpenID Federation 1.0 automatic
// client registration (slice 3): when the authorization endpoint misses a
// client_id in the ClientStore AND federation is wired with configured trust
// anchors AND the client_id is a syntactically-valid HTTPS entity identifier,
// the OP resolves that RP's trust chain on-the-fly (slice 2, fail-closed,
// rooted in a configured anchor) and DERIVES a usable OAuth client from the
// POLICY-CONSTRAINED openid_relying_party metadata — no manual registration.
//
// The derived client carries JWKS = the chain-validated entity keys (for
// asymmetric private_key_jwt / signed-request-object auth) and NO secret; its
// redirect_uris / response_types / scope are bounded by the trust anchor's
// metadata_policy; it then runs the SAME /auth/login + /token validation as
// any client. An invalid / forged / unanchored / expired chain leaves the
// client_id UNKNOWN (the byte-identical unknown-client error — oracle-safe; no
// federation-internal detail on the wire). Derived clients are cached per
// entity ID, bounded by the chain's earliest exp, and re-resolved on expiry.
//
// Composition: it decorates whatever ClientStore is wired (WithClientStore)
// with federation.RegistrationClientStore, applied AFTER all options run so
// option order is irrelevant. A pre-registered client always wins (the wrapped
// store's hit short-circuits before any federation work). REQUIRES both
// WithClientStore and WithFederationEntity with configured trust anchors —
// absent either, the option is INERT and the build is byte-identical (no
// decoration, no resolution ever attempted). Default-off.
func WithFederationAutoRegistration() Option {
	return func(s *Server) { s.federationAutoRegister = true }
}

// FederationEntity returns the wired federation entity handler (nil when
// WithFederationEntity is not configured).
func (s *Server) FederationEntity() *federation.EntityHandler { return s.federationEntity }
