package sso

import (
	"github.com/yangwb1123/snaplink/domains/authenticators/device"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/connections/provider"
	"github.com/yangwb1123/snaplink/domains/federation"
	federationhealth "github.com/yangwb1123/snaplink/domains/federation/health"
	"github.com/yangwb1123/snaplink/interfaces/admin"
	"github.com/yangwb1123/snaplink/interfaces/middleware"
	"github.com/yangwb1123/snaplink/protocols/caep"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"net/http"
	"time"
)

// PathAdminFederationHealth re-export.
const PathAdminFederationHealth = core.PathAdminFederationHealth

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

// for the X-Forwarded-Proto / X-Forwarded-Host edge trust contract.
func requestBaseURL(r *http.Request) string { return middleware.BaseURL(r) }

// WithJWKSCacheTTL overrides the Cache-Control max-age advertised
// on /.well-known/jwks.json. Default is [DefaultJWKSCacheMaxAge]
// (5 minutes). Lower this when key rotation must propagate faster;
// raise it when RP traffic strains the JWKS endpoint.
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
// signer is the OP signing issuer (typically the same instance wired as
// WithTokenIssuer / WithIDTokenIssuer, so one key covers tokens, id_tokens,
// SETs, and the entity statement). cfg carries authority_hints,
// organization/contacts, the TTLs, and (present-but-inert in this slice) the
// trust anchors.
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

// WithFederationHistoricalKeyStore wires the historical signing key store
// for the OpenID Federation 1.0 8.5 historical_keys endpoint. When wired,
// the server mounts PathFederationHistoricalKeys returning a JWKS of all
// previously-published signing keys. Nil (default) => the route is NOT
// mounted -- byte-identical to a build without it.
func WithFederationHistoricalKeyStore(store federation.HistoricalKeyStore) Option {
	return func(srv *Server) { srv.federationHistoricalKeyStore = store }
}

// WithFederationAutoRegistration opts into OpenID Federation 1.0 automatic
// client registration (slice 3): when the authorization endpoint misses a
// client_id in the ClientStore AND federation is wired with configured trust
// anchors AND the client_id is a syntactically-valid HTTPS entity identifier,
// the OP resolves that RP's trust chain on-the-fly (slice 2, fail-closed,
// rooted in a configured anchor) and DERIVES a usable OAuth client from the
// POLICY-CONSTRAINED openid_relying_party metadata — no manual registration.
// The derived client carries JWKS = the chain-validated entity keys (for
// asymmetric private_key_jwt / signed-request-object auth) and NO secret; its
// redirect_uris / response_types / scope are bounded by the trust anchor's
// metadata_policy; it then runs the SAME /auth/login + /token validation as
// any client. An invalid / forged / unanchored / expired chain leaves the
// client_id UNKNOWN (the byte-identical unknown-client error — oracle-safe; no
// federation-internal detail on the wire). Derived clients are cached per
// entity ID, bounded by the chain's earliest exp, and re-resolved on expiry.
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

// WithFederationConnectionHealth wires an OPTIONAL observability store
// tracking each federation peer's fetch-path health (last success/failure,
// consecutive-failure count, last-observed TLS certificate expiry) and mounts
// the read-only GET PathAdminFederationHealth admin listing. PURE
// OBSERVABILITY: the store is populated by a decorator
// (federationhealth.NewObservingFetcher) wrapped around whatever
// EntityStatementFetcher the trust-chain resolver uses — pass the SAME
// wrapped fetcher to WithFederationEntity's resolverOpts
// (federation.WithTrustChainFetcher) so tracking and surfacing share one
// store. The decorator never alters a fetch's result, so trust-chain
// validation and its fail-closed semantics are completely unaffected (AGENTS.md:
// health tracking wraps the fetch path, it is never a new gate).
// certExpiryWarning is the config-gated "expiring soon" threshold a tracked
// peer's certificate must fall within to be flagged cert_expiring in the
// listing (a queryable list, NOT an active alert/notification channel).
// <= 0 ⇒ federationhealth.DefaultCertExpiryWarning (30 days).
// A nil store leaves the Server's field nil — the route is NOT mounted and
// behavior is byte-identical to a build without it (default-off).
func WithFederationConnectionHealth(store federationhealth.ConnectionHealth, certExpiryWarning time.Duration) Option {
	return func(s *Server) {
		if store == nil {
			return
		}
		s.federationHealth = store
		s.federationCertExpiryWarning = certExpiryWarning
	}
}

// FederationConnectionHealth returns the wired health store (nil when
// WithFederationConnectionHealth is not configured). Satisfies
// federationhealth.Deps for HandleListPeerHealth.
func (s *Server) FederationConnectionHealth() federationhealth.ConnectionHealth {
	return s.federationHealth
}

// FederationCertExpiryWarning returns the configured "expiring soon"
// threshold (<= 0 when unconfigured — HandleListPeerHealth applies its
// default). Satisfies federationhealth.Deps.
func (s *Server) FederationCertExpiryWarning() time.Duration { return s.federationCertExpiryWarning }

// FederationHealthNow is the clock federationhealth.HandleListPeerHealth
// computes the cert_expiring classification against. Satisfies
// federationhealth.Deps.
func (s *Server) FederationHealthNow() time.Time { return time.Now() }

// listing handler (*Server satisfies federationhealth.Deps via the accessors
// above). Only mounted when WithFederationConnectionHealth is wired.
func (s *Server) handleFederationHealth(ctx HandlerContext) {
	federationhealth.HandleListPeerHealth(s, ctx)
}

func (s *Server) mountFederationEndpoints() {
	gr := core.NewGatedRouter(s.router, s.federationGateOn)

	if s.protectedResourceMetadata != nil {
		gr.GET(PathProtectedResourceMetadata, s.handleProtectedResourceMetadata)
	}

	if s.federationEntity != nil {
		gr.GET(PathFederationEntityConfig, s.handleFederationEntityConfig)

		if s.federationEntity.HasSubordinates() {
			gr.GET(PathFederationFetch, s.handleFederationFetch)

			gr.GET(PathFederationList, s.handleFederationList)
		}

		if s.federationEntity.Resolver().Enabled() {
			gr.GET(PathFederationResolve, s.handleFederationResolve)
		}

	}

	if s.connectionStore != nil {
		gr.GET(PathHomeRealm, s.handleHomeRealm)
		gr.POST(PathHomeRealm, s.handleHomeRealm)
	}

	gr.GET(PathFederationTrustMarkStatus, s.handleFederationTrustMarkStatus)

	if s.federationHistoricalKeyStore != nil {
		gr.GET(PathFederationHistoricalKeys, s.handleFederationHistoricalKeys)
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
	// connectionStore for B2B HRD. Nil ⇒ unmounted.
	connectionStore connections.Store
	// providerStore for third-party login provider configs. Nil ⇒ unmounted.
	providerStore provider.Store
	// deviceStore for authenticated device tracking. Nil ⇒ no tracking.
	deviceStore device.Store
	// devicePolicy for device-related security rules.
	devicePolicy device.Policy
	// loginHistory records login events. Nil ⇒ no recording.
	loginHistory device.HistoryStore
	// domainVerificationResolver for admin domain-verify. Nil ⇒ stdlib-backed.
	domainVerificationResolver connections.DNSResolver
	// connectionProber for admin POST .../connections/:id/probe (WithConnectionProber).
	// Nil ⇒ stdlib-backed HTTP prober.
	connectionProber connections.Prober
	// connectionProbeTimeout bounds per-probe round-trip (WithConnectionProbeTimeout).
	// Zero ⇒ DefaultProbeTimeout. No effect when connectionProber is set.
	connectionProbeTimeout time.Duration
	// connectionAuthFactory builds the live upstream authenticator for a
	// resolved enterprise connection at /auth/login dispatch time
	// (WithConnectionAuthenticatorFactory) — the runtime half of B2B
	// connections; connectionStore is the routing half. Nil ⇒ a connection id
	// never resolves as a provider — byte-identical to the HRD-directive-only
	// build.
	connectionAuthFactory connections.AuthenticatorFactory
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
	// federationHistoricalKeyStore persists retired signing keys for the
	// 8.5 historical keys endpoint. Nil => the route is NOT mounted.
	federationHistoricalKeyStore federation.HistoricalKeyStore
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
	// Opt-in federation peer connection-health observability
	// (WithFederationConnectionHealth). Nil ⇒ the
	// PathAdminFederationHealth route is NOT mounted — byte-identical to a
	// build without it. PURE OBSERVABILITY: populated by a decorator wrapped
	// around the trust-chain resolver's EntityStatementFetcher; never
	// consulted by trust-chain validation itself.
	federationHealth federationhealth.ConnectionHealth
	// federationCertExpiryWarning is the config-gated "expiring soon"
	// threshold surfaced on GET .../federation/health. <= 0 ⇒
	// federationhealth.DefaultCertExpiryWarning.
	federationCertExpiryWarning time.Duration
}

// Enterprise connection email-domain verification (admin). Relocated from
// server_admin_handlers.go (which was at the line budget) to sit beside
// this file's other connectionStore-backed handlers.
func (s *Server) handleAdminListConnectionDomains(ctx HandlerContext) {
	admin.HandleAdminListConnectionDomains(s, ctx)
}
func (s *Server) handleAdminVerifyConnectionDomain(ctx HandlerContext) {
	admin.HandleAdminVerifyConnectionDomain(s, ctx)
}

// Zero-trust conditional-access (CAP) governance view (admin). Relocated
// from server_admin_handlers.go (which was at the line budget).
func (s *Server) handleAdminListAccessPolicies(ctx HandlerContext) {
	admin.HandleAdminListAccessPolicies(s, ctx)
}

func (s *Server) handleAdminConvergeAccessPolicies(ctx HandlerContext) {
	admin.HandleAdminConvergeAccessPolicies(s, ctx)
}

// ConnectionProber returns the wired reachability prober for the admin
// connection-test endpoint, defaulting to the stdlib-backed production HTTP
// prober (bounded by connectionProbeTimeout) when no custom one was injected.
// Relocated from accessors.go (which was at the line budget) — beside the
// connectionProber field it reads.
func (s *Server) ConnectionProber() connections.Prober {
	if s.connectionProber != nil {
		return s.connectionProber
	}
	return connections.NewHTTPProber(s.connectionProbeTimeout)
}

// WithConnectionProber injects the reachability check the admin
// POST /api/v1/admin/connections/:id/probe endpoint uses to test a
// connection's configured upstream (first-class DI so tests run
// network-free with a fake). Nil/unset uses the stdlib-backed production
// HTTP prober (OIDC discovery / SAML metadata fetch), bounded by
// WithConnectionProbeTimeout. Relocated from options_admin.go (which was
// at the line budget).
func WithConnectionProber(p connections.Prober) Option {
	return func(s *Server) {
		if p != nil {
			s.connectionProber = p
		}
	}
}

// WithConnectionProbeTimeout bounds the production HTTP prober's per-probe
// round-trip (connections.DefaultProbeTimeout, 10s, when unset). No effect
// when WithConnectionProber supplies a custom Prober.
func WithConnectionProbeTimeout(d time.Duration) Option {
	return func(s *Server) {
		if d > 0 {
			s.connectionProbeTimeout = d
		}
	}
}

func (s *Server) handleFederationEntityConfig(ctx HandlerContext) {
	federation.HandleEntityConfiguration(s, ctx)
}

func (s *Server) handleFederationFetch(ctx HandlerContext) {
	federation.HandleFederationFetch(s, ctx)
}

func (s *Server) handleFederationResolve(ctx HandlerContext) {
	federation.HandleFederationResolve(s, ctx)
}

func (s *Server) FederationFetcher() federation.EntityStatementFetcher { return nil }

func (s *Server) handleFederationTrustMarkStatus(ctx HandlerContext) {
	federation.HandleTrustMarkStatus(s, ctx)
}

func (s *Server) handleFederationList(ctx HandlerContext) {
	federation.HandleFederationList(s, ctx)
}

// (8.5). When a HistoricalKeyStore is wired, it returns a JSON JWKS
// containing all previously-published keys.
func (s *Server) handleFederationHistoricalKeys(ctx HandlerContext) {
	if s.federationHistoricalKeyStore == nil {
		tokenNoStoreHeaders(ctx)
		ctx.JSON(http.StatusOK, map[string]any{"keys": []any{}})
		return
	}
	keys, err := s.federationHistoricalKeyStore.HistoricalKeys(ctx.Request().Context())
	if err != nil {
		s.logger.Error("historical keys fetch failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(ctx, ErrInternal))
		return
	}
	jwkKeys := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		if k.JWK != nil {
			entry := make(map[string]any)
			for kk, vv := range k.JWK {
				entry[kk] = vv
			}
			if !k.ActiveUntil.IsZero() {
				entry["active_until"] = k.ActiveUntil.Unix()
			}
			if !k.RetiredAt.IsZero() {
				entry["retired_at"] = k.RetiredAt.Unix()
			}
			jwkKeys = append(jwkKeys, entry)
		}
	}
	tokenNoStoreHeaders(ctx)
	ctx.JSON(http.StatusOK, map[string]any{"keys": jwkKeys})
}
