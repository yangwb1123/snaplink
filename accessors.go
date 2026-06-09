// Code generated. Server field accessors for use by handlers/middleware
// subpackages that need read-only access to Server configuration.
// These exist because handlers/ + middleware/ live in separate packages
// from sso and cannot reach into unexported Server fields directly.

package sso

import (
	"context"
	"sort"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/federation"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
)

// AuthCodeStore returns the wired AuthCodeStore (nil when not configured).
func (s *Server) AuthCodeStore() oauth.AuthCodeStore { return s.authCodeStore }

// AuthCodeTTL returns the configured AuthCode TTL.
func (s *Server) AuthCodeTTL() time.Duration { return s.authCodeTTL }

// RefreshTokenStore returns the wired RefreshTokenStore (nil when not configured).
func (s *Server) RefreshTokenStore() oauth.RefreshTokenStore { return s.refreshTokenStore }

// RefreshTokenTTL returns the configured RefreshToken TTL.
func (s *Server) RefreshTokenTTL() time.Duration { return s.refreshTokenTTL }

// DeviceCodeStore returns the wired DeviceCodeStore (nil when not configured).
func (s *Server) DeviceCodeStore() oauth.DeviceCodeStore { return s.deviceCodeStore }

// DeviceCodeTTL returns the configured DeviceCode TTL.
func (s *Server) DeviceCodeTTL() time.Duration { return s.deviceCodeTTL }

// DeviceCodeInterval returns the device-flow poll interval.
func (s *Server) DeviceCodeInterval() time.Duration { return s.deviceCodeInterval }

// DeviceVerifyBaseURL returns the device verify base URL.
func (s *Server) DeviceVerifyBaseURL() string { return s.deviceVerifyBaseURL }

// PARStore returns the wired PARStore (nil when not configured).
func (s *Server) PARStore() oauth.PARStore { return s.parStore }

// PARTTL returns the configured PAR TTL.
func (s *Server) PARTTL() time.Duration { return s.parTTL }

// CIBAStore returns the wired CIBAStore (nil when not configured).
func (s *Server) CIBAStore() oauth.CIBAStore { return s.cibaStore }

// CIBARequestTTL returns the configured CIBA auth_req_id lifetime.
func (s *Server) CIBARequestTTL() time.Duration { return s.cibaRequestTTL }

// CIBAPollInterval returns the configured CIBA poll interval.
func (s *Server) CIBAPollInterval() time.Duration { return s.cibaPollInterval }

// DCRPolicy returns the configured DCR policy (nil when not configured).
func (s *Server) DCRPolicy() *oauth.DCRPolicy { return s.dcrPolicy }

// JTIReplayStore returns the wired JTIReplayStore (nil when not configured).
func (s *Server) JTIReplayStore() security.JTIReplayStore { return s.jtiReplayStore }

// SubjectClientIndex returns the wired SubjectClientIndex (nil when not configured).
func (s *Server) SubjectClientIndex() security.SubjectClientIndex { return s.subjectClientIndex }

// JARFetcher returns the wired JARFetcher (nil when not configured).
func (s *Server) JARFetcher() security.JARFetcher { return s.jarFetcher }

// JARDecrypter returns the wired JWE decrypter (nil when not configured).
func (s *Server) JARDecrypter() security.JWEDecrypter { return s.jarDecrypter }

// JWEResponseEncrypter returns the wired response-direction JWE
// encrypter (nil when not configured), backing the id_token + userinfo
// encryption paths.
func (s *Server) JWEResponseEncrypter() security.JWEEncrypter { return s.jweResponseEncrypter }

// EncryptIDTokenForClient backs oidc.SilentRenewalDeps — delegates to
// the shared maybeEncryptIDToken fail-closed wrapper.
func (s *Server) EncryptIDTokenForClient(ctx context.Context, client *Client, signed string) (string, bool) {
	return s.maybeEncryptIDToken(ctx, client, signed)
}

// AccountLockout returns the wired account lockout (nil when not configured).
func (s *Server) AccountLockout() security.AccountLockout { return s.accountLockout }

// PairwiseStore returns the wired pairwise subject store (nil when not configured).
func (s *Server) PairwiseStore() security.PairwiseSubjectStore { return s.pairwiseStore }

// ClientCertExtractor returns the wired ClientCertExtractor (nil when not configured).
func (s *Server) ClientCertExtractor() ClientCertExtractor { return s.clientCertExtractor }

// DPoPNonceProvider returns the wired DPoPNonceProvider (nil when not configured).
func (s *Server) DPoPNonceProvider() DPoPNonceProvider { return s.dpopNonceProvider }

// IDTokenIssuer returns the wired IDTokenIssuer (nil when not configured).
func (s *Server) IDTokenIssuer() oidc.IDTokenIssuer { return s.idTokenIssuer }

// MetadataSigner returns the wired MetadataSigner (nil when not configured).
func (s *Server) MetadataSigner() oidc.MetadataSigner { return s.metadataSigner }

// JARMSigner returns the wired JARM signer (nil when JARM is not configured).
func (s *Server) JARMSigner() oidc.JARMSigner { return s.jarmSigner }

// MFAProvider returns the wired MFAProvider (nil when not configured).
func (s *Server) MFAProvider() spi.MFAProvider { return s.mfaProvider }

// MFAChallengeStore returns the wired MFAChallengeStore (nil when not configured).
func (s *Server) MFAChallengeStore() spi.MFAChallengeStore { return s.mfaChallengeStore }

// MFAChallengeTTL returns the MFA challenge TTL.
func (s *Server) MFAChallengeTTL() time.Duration { return s.mfaChallengeTTL }

// AnomalyRunner returns the wired anomaly Runner (nil when not configured).
func (s *Server) AnomalyRunner() *anomaly.Runner { return s.anomalyRunner }

// Auditor returns the audit Recorder (nil when not configured).
func (s *Server) Auditor() *audit.Recorder { return s.auditor }

// Permissions returns the permissions Provider (nil when not configured).
func (s *Server) Permissions() permissions.Provider { return s.permissions }

// EmbedPermissions reports whether to embed permissions in login response.
func (s *Server) EmbedPermissions() bool { return s.embedPermissions }

// NetStore returns the wired netpolicy Store (nil when not configured).
func (s *Server) NetStore() netpolicy.Store { return s.netStore }

// NetClassifier returns the wired netpolicy Classifier (nil when not configured).
func (s *Server) NetClassifier() *netpolicy.Classifier { return s.netClassifier }

// Metrics returns the wired metrics (nil when not configured).
func (s *Server) Metrics() *metrics.Metrics { return s.metrics }

// SrvLogger returns the wired logger (never nil; defaults to spi.NopLogger).
// Named SrvLogger to avoid colliding with the `Logger` method consumers
// might expect to return spi.Logger differently.
func (s *Server) SrvLogger() spi.Logger { return s.logger }

// Issuer returns the configured issuer URL.
func (s *Server) Issuer() string { return s.issuer }

// SessionMgr returns the wired SessionManager (nil when not configured).
func (s *Server) SessionMgr() core.SessionManager { return s.sessionMgr }

// ClientStoreAccessor returns the wired ClientStore (nil when not configured).
// Named *Accessor to avoid colliding with the embedded `ClientStore` type.
func (s *Server) ClientStoreAccessor() core.ClientStore { return s.clientStore }

// TokenIssuers returns the map of strategy → TokenIssuer.
func (s *Server) TokenIssuers() map[string]core.TokenIssuer { return s.tokenIssuers }

// LogoutTokenIssuer returns the wired LogoutTokenIssuer (nil when not configured).
func (s *Server) LogoutTokenIssuer() LogoutTokenIssuer { return s.logoutTokenIssuer }

// SigningAlgValues returns the distinct JWS `alg` values the wired
// signers actually publish, for the discovery doc's *_signing_alg_
// values_supported lists. When WithSupportedSigningAlgs was set it wins
// (the operator's explicit allowlist is authoritative). Otherwise the
// set is derived from every registered JWKSProvider issuer's JWKS `alg`
// fields (so wiring an ECDSAJWTIssuer advertises ES256, an
// Ed25519JWTIssuer advertises EdDSA, and a mixed deployment advertises
// both). Falls back to ["EdDSA"] when nothing is derivable, preserving
// the historical default. Order is deterministic (sorted).
func (s *Server) SigningAlgValues(ctx context.Context) []string {
	if len(s.supportedSigningAlgs) > 0 {
		out := append([]string(nil), s.supportedSigningAlgs...)
		sort.Strings(out)
		return out
	}
	seen := map[string]struct{}{}
	for _, ti := range s.tokenIssuers {
		jp, ok := ti.(core.JWKSProvider)
		if !ok {
			continue
		}
		jwks, err := jp.JWKS(ctx)
		if err != nil {
			continue
		}
		for _, k := range jwks {
			if k.Alg != "" {
				seen[k.Alg] = struct{}{}
			}
		}
	}
	if len(seen) == 0 {
		return []string{"EdDSA"}
	}
	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// LogoutNotifier returns the wired LogoutNotifier (nil when not configured).
func (s *Server) LogoutNotifier() LogoutNotifier { return s.logoutNotifier }

// OpPolicyURI returns the operator policy URI for discovery.
func (s *Server) OpPolicyURI() string { return s.opPolicyURI }

// OpTosURI returns the operator ToS URI for discovery.
func (s *Server) OpTosURI() string { return s.opTosURI }

// ServiceDocumentation returns the service documentation URI.
func (s *Server) ServiceDocumentation() string { return s.serviceDocumentation }

// SupportedACRValues returns the operator-configured ACR values list.
func (s *Server) SupportedACRValues() []string { return s.supportedACRValues }

// JWKSCacheTTL returns the JWKS cache TTL.
func (s *Server) JWKSCacheTTL() time.Duration { return s.jwksCacheTTL }

// JWKSCacheMaxAge returns the JWKS cache max-age (alias for JWKSCacheTTL).
func (s *Server) JWKSCacheMaxAge() time.Duration { return s.jwksCacheTTL }

// ComputeJWKSDocument runs compute behind a process-local single-flight so
// a burst of concurrent /jwks.json polls (the unknown-kid stampede that
// follows a key rotation) collapses to one issuer-walk + marshal instead
// of one per request. No TTL: the first poll after the in-flight compute
// finishes recomputes, so a rotation shows up immediately.
func (s *Server) ComputeJWKSDocument(compute func() ([]byte, error)) ([]byte, error) {
	return s.jwksFlight.Do(compute)
}

// DiscoveryCacheTTL returns the discovery snapshot cache TTL.
func (s *Server) DiscoveryCacheTTL() time.Duration { return s.discoveryCacheTTL }

// DiscoveryDocCacheTTL returns the discovery body cache TTL.
func (s *Server) DiscoveryDocCacheTTL() time.Duration { return s.discoveryDocCacheTTL }

// ResolveIssuer returns the issuer URL to stamp on tokens + discovery
// responses for the current request. Honors WithTrustForwardedProto
// + X-Forwarded-Host edge-trust contract.
func (s *Server) ResolveIssuer(ctx core.HandlerContext) string { return s.resolveIssuer(ctx) }

// RequestBaseURL derives the absolute scheme://host base for the request,
// the SAME derivation the discovery doc uses. Backs federation.Deps so the
// federation package needn't reach into the middleware base-URL extractor.
func (s *Server) RequestBaseURL(ctx core.HandlerContext) string {
	return requestBaseURL(ctx.Request())
}

// FederationSigner returns the OpenID Federation entity-configuration signer
// (the OP signing issuer reused via SignJWT). nil when WithFederationEntity
// is not wired. Backs federation.Deps.
func (s *Server) FederationSigner() federation.JWTSigner {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Signer()
}

// FederationConfig returns the wired OpenID Federation config (nil when
// WithFederationEntity is not wired). Backs federation.Deps.
func (s *Server) FederationConfig() *federation.Config {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Config()
}

// FederationCache returns the per-issuer Entity Configuration cache (nil when
// WithFederationEntity is not wired). Backs federation.Deps.
func (s *Server) FederationCache() *federation.EntityConfigCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Cache()
}

// FederationFetchCache returns the per-(issuer, subordinate) Subordinate
// Statement cache the OpenID Federation 1.0 §8 Federation Fetch endpoint uses
// (nil when WithFederationEntity is not wired). Backs federation.FetchDeps.
func (s *Server) FederationFetchCache() *federation.SubordinateStatementCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.FetchCache()
}

// FederationNow is the clock the federation handler stamps the Entity
// Configuration's iat/exp from. Real wall clock in production; a test wiring
// its own federation.Deps injects a fixed time so exp stays deterministic.
// Backs federation.Deps.
func (s *Server) FederationNow() time.Time { return time.Now() }

// LogError logs a non-fatal error through the server logger. Backs
// federation.Deps (the signing/marshal failure path).
func (s *Server) LogError(msg string, args ...any) { s.logger.Error(msg, args...) }

// ValidateAnyToken iterates registered TokenIssuers until one accepts
// the bearer. Returns issuer name on success for revocation /audit
// correlation. Exposed for Hexagonal handler subpackages.
func (s *Server) ValidateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	return s.validateAnyToken(ctx, token)
}

// VerifyJWTClientAssertion validates an RFC 7521/7523 client
// assertion JWT presented at /token, /token/introspect,
// /token/revoke, or /par. Exposed so Hexagonal handler subpackages
// can authenticate clients without re-implementing the JWS parse +
// JWKS lookup + jti replay-store interaction.
func (s *Server) VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error) {
	return verifyJWTClientAssertion(ctx, assertion, formClientID, s.clientStore, asIssuer, s.jtiReplayStore, s.jtiReplayFailClosed)
}

// AuthenticateClientCreds verifies client_id + secret via the wired
// ClientStore + tenant gate. Returns nil on success.
func (s *Server) AuthenticateClientCreds(ctx core.HandlerContext, id, secret string) error {
	return s.authenticateClientCreds(ctx, id, secret)
}

// RequireClientStore reports whether a ClientStore is wired, returning
// a non-nil error when the dependency is missing. Exposes the internal
// requireDeps check to the oauth handler subpackage.
func (s *Server) RequireClientStore() error {
	return s.requireDeps(DepClientStore)
}

// ResolveLocalSubject translates a (possibly pairwise) subject back
// to the local user identifier. Required by /token/revoke-all so
// the bulk delete actually hits the row keyed on the local sub.
func (s *Server) ResolveLocalSubject(ctx context.Context, sub string) (string, error) {
	return s.resolveLocalSubject(ctx, sub)
}

// RevokeAcrossIssuers asks every registered TokenIssuer to revoke
// the supplied access token. Returns (revoked, failed) issuer-name
// lists so callers can emit partial-revoke audit on failure.
//
// This is the user-driven revocation seam (/token/revoke, /token/revoke-all,
// /end_session id_token_hint). When WithCrossReplicaRevocation is armed AND a
// local issuer actually revoked the token, it ALSO publishes a
// cluster.KindTokenRevoked Event so every armed replica adds the token to its
// own in-process deny-set (best-effort, fail-open). The publish lives HERE, not
// in the unexported revokeAcrossIssuers, so the bus subscriber's adopt path
// (applyTokenRevocation → s.revokeAcrossIssuers) NEVER re-publishes — no
// broadcast loop. No-op publish when unarmed or no bus is wired.
func (s *Server) RevokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string) {
	revoked, failed = s.revokeAcrossIssuers(ctx, token)
	// Only propagate a revocation a local issuer actually owned — broadcasting a
	// token no issuer here recognised would just churn peers for nothing.
	if len(revoked) > 0 {
		s.publishTokenRevocation(ctx, token, jwtExpUnsafe(token))
	}
	return revoked, failed
}

// AuditPartialRevokeFailure emits an audit event when some — but
// not all — issuers successfully revoked a token.
func (s *Server) AuditPartialRevokeFailure(ctx core.HandlerContext, revoked, failed []string) {
	s.auditPartialRevokeFailure(ctx, revoked, failed)
}

// SetBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header.
// realm defaults to "sso" when empty; errorCode/errorDesc omitted
// for the "no credentials presented" case.
func (s *Server) SetBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDesc string) {
	setBearerChallenge(ctx, realm, errorCode, errorDesc)
}

// FanOutBackchannelLogout dispatches OIDC BCL 1.0 logout_token POSTs
// to every RP the user is signed into for the originating client.
// No-op when BCL isn't wired or the client doesn't declare a
// backchannel_logout_uri.
func (s *Server) FanOutBackchannelLogout(ctx core.HandlerContext, originClient *Client, subject, sid string) {
	s.fanOutBackchannelLogout(ctx, originClient, subject, sid)
}

// GatherFrontchannelLogoutIframes returns the FCL 1.0 iframe target
// URIs for the subject + primary client. Empty when no client opted
// in via FrontchannelLogoutURI.
func (s *Server) GatherFrontchannelLogoutIframes(ctx core.HandlerContext, subject string, primary *Client, sid string) []string {
	return s.gatherFrontchannelLogoutIframes(ctx, subject, primary, sid)
}

// RenderFrontchannelLogout writes the OIDC FCL 1.0 HTML page with
// hidden iframes for each target URI, then a meta-refresh to the
// optional post-logout redirect.
func (s *Server) RenderFrontchannelLogout(ctx core.HandlerContext, iframeURIs []string, redirectURI string) {
	s.renderFrontchannelLogout(ctx, iframeURIs, redirectURI)
}

// RecordLogout emits a logout audit event with optional revoked
// hints. Used by /logout and /end_session.
func (s *Server) RecordLogout(ctx core.HandlerContext, sessionID string, revoked []string) {
	s.recordLogout(ctx, sessionID, revoked)
}

// AuthzErrorBody builds the authorization-flow error envelope
// (includes the RFC 9207 iss parameter). Used by any handler that
// surfaces an /auth/login-style error.
func (s *Server) AuthzErrorBody(ctx core.HandlerContext, code string) map[string]string {
	return s.authzErrorBody(ctx, code)
}

// AuthzErrorBodyDesc adds error_description to AuthzErrorBody.
func (s *Server) AuthzErrorBodyDesc(ctx core.HandlerContext, code, desc string) map[string]string {
	return s.authzErrorBodyDesc(ctx, code, desc)
}

// IssuerForClient resolves the per-client TokenIssuer strategy. Used
// by handlers that mint tokens outside the standard /token grant
// path (silent renewal, MFA resume, etc).
func (s *Server) IssuerForClient(c *Client) (string, TokenIssuer, error) {
	return s.issuerForClient(c)
}

// IDTokenIssuerForClient resolves the per-tenant id_token issuer.
// Backs oidc.SilentRenewalDeps so the prompt=none renewal path signs a
// tenant's id_token with the tenant's key (fail-closed on a
// misconfigured tenant issuer — see idTokenIssuerForClient).
func (s *Server) IDTokenIssuerForClient(c *Client) (oidc.IDTokenIssuer, bool, error) {
	return s.idTokenIssuerForClient(c)
}

// JARMSignerForClient resolves the per-tenant JARM signer (ok=false ⇒
// fail closed: no signer, omit). Exposed for tests/consumers asserting
// per-tenant JARM isolation — see jarmSignerForClient.
func (s *Server) JARMSignerForClient(c *Client) (oidc.JARMSigner, bool) {
	return s.jarmSignerForClient(c)
}

// RecordLoginSuccess emits a login audit event with the standard
// shape (provider, strategy, subject, sid).
func (s *Server) RecordLoginSuccess(ctx core.HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	s.recordLoginSuccess(ctx, clientID, provider, strategy, userID, sessionID)
}

// AddReadyCheck registers a named /readyz dependency AFTER construction —
// the post-Mount counterpart to WithReadyCheck (same merge-into-placeholder
// semantics, same nil/empty guards). It exists for subsystems mounted from
// cmd's buildHTTPHandler (e.g. an operator's SAML handler-set, whose
// readiness probe is only built once the server's stores are resolved), so
// their health surfaces on /readyz alongside the option-wired stores.
//
// MUST be called during startup wiring, BEFORE the server begins serving
// /readyz — readyChecks is read lock-free at probe time, so a concurrent
// append while serving would race. cmd's buildHTTPHandler runs inside
// buildApp, before the listener starts, satisfying this.
func (s *Server) AddReadyCheck(name string, check ReadyCheck) {
	if check == nil || name == "" {
		return
	}
	for i := range s.readyChecks {
		if s.readyChecks[i].Name == name && s.readyChecks[i].Check == nil {
			s.readyChecks[i].Check = check
			return
		}
	}
	s.readyChecks = append(s.readyChecks, namedReadyCheck{Name: name, Check: check})
}
