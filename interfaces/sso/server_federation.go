package sso

import (
	"net/http"
	"time"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/protocols/oidc"
)

func (s *Server) BuildOPMetadata(ctx HandlerContext, base string) federation.OPFederationMetadata {
	cfg := s.buildOIDCConfiguration(ctx, base)
	return federation.OPFederationMetadata{
		Issuer:                            cfg.Issuer,
		AuthorizationEndpoint:             cfg.AuthorizationEndpoint,
		TokenEndpoint:                     cfg.TokenEndpoint,
		UserinfoEndpoint:                  cfg.UserInfoEndpoint,
		JWKSURI:                           cfg.JWKSURI,
		RegistrationEndpoint:              cfg.RegistrationEndpoint,
		ResponseTypesSupported:            cfg.ResponseTypesSupported,
		SubjectTypesSupported:             cfg.SubjectTypesSupported,
		IDTokenSigningAlgValuesSupported:  cfg.IDTokenSigningAlgValuesSupported,
		ScopesSupported:                   cfg.ScopesSupported,
		TokenEndpointAuthMethodsSupported: cfg.TokenEndpointAuthMethodsSupported,
		CodeChallengeMethodsSupported:     cfg.CodeChallengeMethodsSupported,
	}
}

// handleFederationEntityConfig delegates to the hexagonal federation handler
// (*Server satisfies federation.Deps via accessors.go). Only mounted when
// WithFederationEntity is wired.
func (s *Server) handleFederationEntityConfig(ctx HandlerContext) {
	federation.HandleEntityConfiguration(s, ctx)
}

// handleFederationFetch delegates to the hexagonal OpenID Federation 1.0 §8
// Federation Fetch handler (*Server satisfies federation.FetchDeps via
// accessors.go). Only mounted when WithFederationEntity is wired AND
// subordinates are configured (this server acts as a federation SUPERIOR) —
// byte-identical off otherwise.
func (s *Server) handleFederationFetch(ctx HandlerContext) {
	federation.HandleFederationFetch(s, ctx)
}

// requestBaseURL delegates to middleware.BaseURL — see that function
// for the X-Forwarded-Proto / X-Forwarded-Host edge trust contract.
func requestBaseURL(r *http.Request) string { return middleware.BaseURL(r) }

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

// mountClusterEndpoints registers the full-path admin/cluster endpoints
// (authz policy bundle, storage health, mesh ext_authz, CAEP/SSF receiver),
// each opt-in and gated on its wiring. Moved from server_routes.go (which
// was at the line budget) — this file already holds the fields these routes
// gate on (federationMeshState).
func (s *Server) mountClusterEndpoints() {
	// Authorization policy bundle export (decentralized authz). Full
	// path (not group-relative) registered directly on the router; its
	// /api/v1/admin/ prefix means AdminMiddleware gates it as admin:read.
	// Only mounted when a permissions provider is wired — the bundle is
	// the role-DEFINITION half of that model. AdminAPI-gated like the rest
	// of the /api/v1/admin/ surface.
	if s.permissions != nil && s.adminAPIGateOn() {
		s.router.GET(PathAuthzPolicyBundle, s.handleAuthzPolicyBundle)
	}

	// Per-store storage-health report (opt-in WithStorageHealth). Full-path
	// admin endpoint gated by AdminMiddleware via the /api/v1/admin/ prefix.
	// Only mounted when at least one source is wired AND AdminAPI is on —
	// byte-identical to a build without it.
	if len(s.storageHealthSources) > 0 && s.adminAPIGateOn() {
		s.router.GET(PathStorageHealth, s.handleStorageHealth)
	}

	// Mesh ext_authz HTTP endpoint (opt-in, cluster C1). The sidecar may
	// call it with the original request method, so register both GET and
	// POST at the configured path. Not mounted unless WithMeshExtAuthz is
	// wired — byte-identical to a build without it.
	if s.meshExtAuthz {
		path := s.meshExtAuthzPath
		if path == "" {
			path = PathMeshExtAuthz
		}
		s.router.GET(path, s.handleMeshExtAuthz)
		s.router.POST(path, s.handleMeshExtAuthz)
	}

	// CAEP/SSF push-delivery RECEIVER (opt-in, the inbound half of OpenID
	// Shared Signals). A trusted upstream transmitter POSTs a signed SET
	// here; the receiver validates it fail-closed and revokes the mapped
	// subject's local access. Not mounted unless WithCAEPReceiver is wired
	// AND the CAEP gate is on — byte-identical to a build without it.
	if s.caepReceiver != nil && s.caepGateOn() {
		s.router.POST(PathSSFReceive, s.handleSSFReceive)
	}
}

// mountFederationEndpoints registers the RFC 9728 protected-resource metadata,
// the OpenID Federation 1.0 entity configuration (+ §8 fetch when this server
// is a superior), and the B2B home-realm discovery routes — each opt-in, and
// all behind the Federation feature gate.
func (s *Server) mountFederationEndpoints() {
	if !s.federationGateOn() {
		return
	}
	// OpenID Federation 1.0 entity configuration (opt-in). Serves the OP's
	// self-signed Entity Statement at the well-known endpoint so the OP is
	// discoverable as a federation ENTITY. Not mounted unless
	// RFC 9728 Protected Resource Metadata (opt-in). Public discovery doc;
	// unmounted when not wired (byte-identical).
	if s.protectedResourceMetadata != nil {
		s.router.GET(PathProtectedResourceMetadata, s.handleProtectedResourceMetadata)
	}
	// WithFederationEntity is wired — byte-identical to a build without it.
	if s.federationEntity != nil {
		s.router.GET(PathFederationEntityConfig, s.handleFederationEntityConfig)
		// OpenID Federation 1.0 §8 Federation Fetch endpoint — mounted ONLY when
		// this server is configured as a SUPERIOR (≥1 subordinate). It issues
		// SIGNED Subordinate Statements about configured subordinates so a
		// resolver can climb THROUGH this server. With no subordinates the route
		// is NOT mounted AND the entity config advertises no
		// federation_fetch_endpoint — byte-identical to the slice-1 leaf OP.
		if s.federationEntity.HasSubordinates() {
			s.router.GET(PathFederationFetch, s.handleFederationFetch)
		}
	}

	// Home-realm discovery (opt-in B2B). Given a login identifier (email) it
	// returns the enterprise connection serving that domain so the login UI
	// routes the user to the right upstream IdP. Not mounted unless
	// WithConnectionStore is wired — byte-identical to a build without it.
	if s.connectionStore != nil {
		s.router.GET(PathHomeRealm, s.handleHomeRealm)
		s.router.POST(PathHomeRealm, s.handleHomeRealm)
	}
}

// federationMeshState holds OpenID Federation, CAEP receiver, B2B connections, Envoy/Istio mesh ext_authz, and storage-health fields.
type federationMeshState struct {
	// CAEP/SSF RECEIVER (the inbound half of OpenID Shared Signals — the
	// inverse of caepTransmitter). When caepReceiver is wired
	// (WithCAEPReceiver), the server mounts a push-delivery endpoint
	// (PathSSFReceive) that consumes signed Security Event Tokens from
	// CONFIGURED trusted upstream transmitters and, on a fully-validated
	// session-revoked / account-disabled / token-claims-change event for a
	// PRECISELY-mapped local subject, revokes that subject's local access
	// (sessions + refresh tokens). Validation is fail-closed (iss-allowlist
	// + VerifyCompactJWS signature + aud-binding + exp + jti-replay, all
	// alg=none-safe); an unmapped subject is acked but NOT acted on (no
	// wrongful revocation). Nil ⇒ the route is NOT mounted — byte-identical
	// to a build without it.
	caepReceiver *caep.Receiver

	// connectionStore holds per-organization enterprise connections for B2B
	// home-realm discovery (connections.Store). Nil ⇒ the /auth/home-realm
	// route is NOT mounted — byte-identical to a build without it.
	connectionStore connections.Store

	// Opt-in Envoy/Istio ext_authz HTTP-mode authorization endpoint
	// (cluster C1 mesh data-plane, the HTTP variant — the gRPC variant
	// needs the go-control-plane proto dep and lives in a separate
	// operator module). When meshExtAuthz is true (WithMeshExtAuthz), the
	// server mounts a per-request authorization endpoint at
	// meshExtAuthzPath: a mesh sidecar calls it, a 200 = ALLOW with
	// derived X-Auth-* identity headers the sidecar injects upstream, any
	// other status = DENY. False ⇒ the route is NOT mounted — behavior is
	// byte-identical to a build without it. meshExtAuthzPath empty ⇒
	// PathMeshExtAuthz.
	meshExtAuthz     bool
	meshExtAuthzPath string

	// Opt-in OpenID Federation 1.0 entity configuration. When
	// federationEntity is wired (WithFederationEntity), the server mounts
	// PathFederationEntityConfig serving the OP's self-signed Entity
	// Statement (iss == sub == issuer, signed by the OP's own JWKS key, typ
	// entity-statement+jwt) so the OP participates in a multilateral
	// federation as an ENTITY. Nil ⇒ the route is NOT mounted — behavior is
	// byte-identical to a build without it. This is the entity-publishing
	// slice only; trust-chain VALIDATION (the trust boundary) is a separate
	// slice.
	federationEntity *federation.EntityHandler

	// federationAutoRegister opts into OpenID Federation 1.0 AUTOMATIC client
	// registration (WithFederationAutoRegistration, slice 3): when true AND a
	// ClientStore is wired AND federationEntity carries a resolver with
	// configured trust anchors, NewServer decorates s.clientStore with
	// federation.RegistrationClientStore so an authorization-endpoint
	// ClientStore MISS for a valid HTTPS federation entity ID triggers an
	// on-the-fly trust-chain resolution that DERIVES the client from the
	// policy-constrained RP metadata (chain-vouched JWKS, no secret). The
	// decoration happens post-options (so order is irrelevant) and is INERT —
	// byte-identical to off — without all three preconditions. False ⇒ no
	// decoration; the authz/token flow is unchanged.
	federationAutoRegister bool

	// Opt-in per-store storage-health admin report (WithStorageHealth).
	// Each source describes one wired store: a Name, a Ping for
	// reachability, and an optional schema-version getter (a cmd-supplied
	// closure over the store's *sql.DB driving migrate.Status). Empty ⇒ the
	// /api/v1/admin/storage-health route is NOT mounted (byte-identical to a
	// build without it). The SDK doesn't own the store handles or their
	// *sql.DB — cmd collects these at the same point it gathers Ping-capable
	// stores for /readyz.
	storageHealthSources []StorageHealthSource
}
