package sso

import (
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/protocols/caep"
)

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
