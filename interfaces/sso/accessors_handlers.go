// Code generated. Server handler methods exposed for subpackage delegation.
package sso

import (
	"context"
	"fmt"
	"time"

	"github.com/snaplink/sso/shared/security"

	"github.com/snaplink/sso/domains/federation"
	"github.com/snaplink/sso/internal/handler"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
)

// LogError logs a non-fatal error through the server logger.
func (s *Server) LogError(msg string, args ...any) { s.logger.Error(msg, args...) }

// ValidateAnyToken iterates registered TokenIssuers until one accepts the bearer.
func (s *Server) ValidateAnyToken(ctx context.Context, token string) (*TokenClaims, string, error) {
	return s.validateAnyToken(ctx, token)
}

// VerifyJWTClientAssertion validates an RFC 7521/7523 client assertion JWT.
func (s *Server) VerifyJWTClientAssertion(ctx context.Context, assertion, formClientID, asIssuer string) (string, error) {
	return verifyJWTClientAssertion(ctx, assertion, formClientID, s.clientStore, asIssuer, s.jtiReplayStore, s.jtiReplayFailClosed)
}

// AuthenticateClientCreds verifies client_id + secret via the wired ClientStore.
func (s *Server) AuthenticateClientCreds(ctx core.HandlerContext, id, secret string) error {
	return s.authenticateClientCreds(ctx, id, secret)
}

// RequireClientStore reports whether a ClientStore is wired.
func (s *Server) RequireClientStore() error {
	return s.requireDeps(DepClientStore)
}

// ResolveLocalSubject translates a (possibly pairwise) subject back to the local user id.
func (s *Server) ResolveLocalSubject(ctx context.Context, sub string) (string, error) {
	return s.resolveLocalSubject(ctx, sub)
}

// RevokeAcrossIssuers asks every registered TokenIssuer to revoke the supplied access token.
func (s *Server) RevokeAcrossIssuers(ctx context.Context, token string) (revoked, failed []string) {
	revoked, failed = s.revokeAcrossIssuers(ctx, token)
	if len(revoked) > 0 {
		s.publishTokenRevocation(ctx, token, jwtExpUnsafe(token))
	}
	return revoked, failed
}

// MintImpersonationToken implements admin.Deps: it mints the marked,
// TTL-bounded bearer a break-glass impersonate/escalate grant hands to the
// support admin. The token's sub is the TARGET user and it carries NO scope,
// so every downstream authorization check resolves the target's OWN boundary
// (NON-BYPASS) — never the admin's. The admin appears only in the RFC 8693
// `act` claim and break_glass_admin_session_id; amr=break_glass marks it so it
// can never read as the user authenticating themselves. It reuses the exact
// issuerForClient + TokenIssuer.Issue path a normal login uses (no fork) and
// clamps the lifetime to the grant window (a.ExpiresAt).
func (s *Server) MintImpersonationToken(ctx context.Context, a core.AdminSession) (core.ImpersonationCredential, error) {
	// Structural backstop: a readonly (or any non-impersonate/escalate) grant
	// can NEVER produce a bearer, independent of the handler's own scope gate.
	if a.Scope != core.AdminScopeImpersonate && a.Scope != core.AdminScopeEscalate {
		return core.ImpersonationCredential{}, fmt.Errorf("break-glass: scope %q may not impersonate", a.Scope)
	}
	ttl := time.Until(a.ExpiresAt)
	if ttl <= 0 {
		return core.ImpersonationCredential{}, fmt.Errorf("break-glass: grant window already closed")
	}
	_, ti, err := s.issuerForClient(nil)
	if err != nil {
		return core.ImpersonationCredential{}, fmt.Errorf("break-glass: no token issuer: %w", err)
	}
	sid := ""
	if len(a.SessionIDs) > 0 {
		sid = a.SessionIDs[0]
	}
	tok, err := ti.Issue(ctx, &Subject{
		ID:       a.TargetUserID,
		ClientID: core.BreakGlassImpersonationClientID,
		AuthTime: time.Now(),
		AMR:      []string{core.AMRBreakGlass},
		TTL:      ttl,
		SID:      sid,
		Actor:    &core.ActorClaim{Subject: a.AdminUserID},
		Claims: map[string]string{
			core.ClaimBreakGlassAdminSessionID: a.ID,
			core.ClaimBreakGlass:               "true",
		},
	}, nil)
	if err != nil {
		return core.ImpersonationCredential{}, fmt.Errorf("break-glass: issue impersonation token: %w", err)
	}
	return core.ImpersonationCredential{
		Token:     tok.AccessToken,
		TokenType: tok.TokenType,
		ExpiresIn: tok.ExpiresIn,
		ExpiresAt: time.Now().Add(ttl),
		SessionID: sid,
	}, nil
}

// RevokeToken implements admin.Deps: it denies a bearer across every registered
// issuer (publishing on the cluster bus so peer replicas honor it too). The
// break-glass cascade calls it to invalidate an impersonation credential the
// instant a grant is revoked/expired. Best-effort — a nil/absent issuer is a
// no-op, matching the logout revocation path.
func (s *Server) RevokeToken(ctx context.Context, token string) {
	if token == "" || len(s.tokenIssuers) == 0 {
		return
	}
	_, _ = s.RevokeAcrossIssuers(ctx, token)
}

// AuditPartialRevokeFailure emits an audit event when some issuers failed to revoke.
func (s *Server) AuditPartialRevokeFailure(ctx core.HandlerContext, revoked, failed []string) {
	s.auditPartialRevokeFailure(ctx, revoked, failed)
}

// SetBearerChallenge stamps an RFC 6750 §3 WWW-Authenticate header.
func (s *Server) SetBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDesc string) {
	setBearerChallenge(ctx, realm, errorCode, errorDesc)
}

// FanOutBackchannelLogout dispatches OIDC BCL 1.0 logout_token POSTs.
func (s *Server) FanOutBackchannelLogout(ctx core.HandlerContext, originClient *Client, subject, sid string) {
	s.fanOutBackchannelLogout(ctx, originClient, subject, sid)
}

// GatherFrontchannelLogoutIframes returns the FCL 1.0 iframe target URIs.
func (s *Server) GatherFrontchannelLogoutIframes(ctx core.HandlerContext, subject string, primary *Client, sid string) []string {
	return s.gatherFrontchannelLogoutIframes(ctx, subject, primary, sid)
}

// RenderFrontchannelLogout writes the OIDC FCL 1.0 HTML page.
func (s *Server) RenderFrontchannelLogout(ctx core.HandlerContext, iframeURIs []string, redirectURI string) {
	s.renderFrontchannelLogout(ctx, iframeURIs, redirectURI)
}

// RecordLogout emits a logout audit event.
func (s *Server) RecordLogout(ctx core.HandlerContext, sessionID string, revoked []string) {
	s.recordLogout(ctx, sessionID, revoked)
}

// AuthzErrorBody builds the authorization-flow error envelope.
func (s *Server) AuthzErrorBody(ctx core.HandlerContext, code string) map[string]string {
	return s.authzErrorBody(ctx, code)
}

// AuthzErrorBodyDesc adds error_description to AuthzErrorBody.
func (s *Server) AuthzErrorBodyDesc(ctx core.HandlerContext, code, desc string) map[string]string {
	return s.authzErrorBodyDesc(ctx, code, desc)
}

// IssuerForClient resolves the per-client TokenIssuer strategy.
func (s *Server) IssuerForClient(c *Client) (string, TokenIssuer, error) {
	return s.issuerForClient(c)
}

// IDTokenIssuerForClient resolves the per-tenant id_token issuer.
func (s *Server) IDTokenIssuerForClient(c *Client) (oidc.IDTokenIssuer, bool, error) {
	return s.idTokenIssuerForClient(c)
}

// JARMSignerForClient resolves the per-tenant JARM signer.
func (s *Server) JARMSignerForClient(c *Client) (oidc.JARMSigner, bool) {
	return s.jarmSignerForClient(c)
}

// RecordLoginSuccess emits a login audit event.
func (s *Server) RecordLoginSuccess(ctx core.HandlerContext, clientID, provider, strategy, userID, sessionID string) {
	s.recordLoginSuccess(ctx, clientID, provider, strategy, userID, sessionID)
}

// AddReadyCheck registers a named /readyz dependency AFTER construction.
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

// StorageHealthSources returns the wired storage health sources.
func (s *Server) StorageHealthSources() []StorageHealthSource {
	return s.storageHealthSources
}

// FederationEntityConfig returns the federation entity configuration.
func (s *Server) FederationEntityConfig() *federation.Config { return s.federationEntity.Config() }

// MeSubjectOrChallenge validates the bearer token and returns the authenticated user's subject.
func (s *Server) MeSubjectOrChallenge(ctx core.HandlerContext) (string, bool) {
	return s.meSubjectOrChallenge(ctx)
}

// MeClaimsOrChallenge validates the bearer token and returns the full claims.
func (s *Server) MeClaimsOrChallenge(ctx core.HandlerContext) (*core.TokenClaims, bool) {
	return s.meClaimsOrChallenge(ctx)
}

// SelfEditableAttrs returns the operator allowlist of self-editable profile attribute keys.
func (s *Server) SelfEditableAttrs() map[string]struct{} { return s.selfEditableAttrs }

// WebAuthnRegistrar returns the self-service passkey registrar (nil when unwired).
func (s *Server) WebAuthnRegistrar() core.WebAuthnRegistrar { return s.webauthnRegistrar }

// MFAEnrollmentStore returns the MFA enrollment store (nil when unwired).
func (s *Server) MFAEnrollmentStore() core.MFAEnrollmentStore { return s.mfaEnrollmentStore }

// TOTPEnroller returns the TOTP enroller (nil when unwired).
func (s *Server) TOTPEnroller() core.TOTPEnroller { return s.totpEnroller }

// NewMFAFactorID mints a random opaque factor id (same generator as login MFA challenges).
func (s *Server) NewMFAFactorID() (string, error) { return newMFAChallengeID() }

// BuildHandlerDeps populates handler.ServerDeps from Server fields. The 66
// fields are assigned across three focused populate helpers (stores ->
// subsystems -> server-method callbacks) purely to stay under the per-function
// budget; the resulting struct is byte-identical to the original composite
// literal (field assignment order is irrelevant — no field depends on another).
func (s *Server) BuildHandlerDeps() *handler.ServerDeps {
	d := &handler.ServerDeps{}
	s.populateHandlerDepsStores(d)
	s.populateHandlerDepsSubsystems(d)
	s.populateHandlerDepsCallbacks(d)
	return d
}

// populateHandlerDepsStores assigns the logging/audit/metrics handles, the
// credential/session stores, and their TTLs/intervals.
func (s *Server) populateHandlerDepsStores(d *handler.ServerDeps) {
	d.Logger = s.logger
	d.Auditor = s.auditor
	d.Metrics = s.metrics
	d.Permissions = s.permissions
	d.AnomalyRunner = s.anomalyRunner
	d.ClientStore = s.clientStore
	d.UserProvider = s.userProvider
	d.SessionMgr = s.sessionMgr
	d.ConsentStore = s.consentStore
	d.TenantUserStore = s.tenantUserStore
	d.DeviceSecretStore = s.deviceSecretStore
	d.AuthCodeStore = s.authCodeStore
	d.AuthCodeTTL = s.authCodeTTL
	d.RefreshTokenStore = s.refreshTokenStore
	d.RefreshTokenTTL = s.refreshTokenTTL
	d.DeviceCodeStore = s.deviceCodeStore
	d.DeviceCodeTTL = s.deviceCodeTTL
	d.DeviceCodeInterval = s.deviceCodeInterval
	d.DeviceVerifyBaseURL = s.deviceVerifyBaseURL
	d.PARStore = s.parStore
	d.PARTTL = s.parTTL
	d.CIBAStore = s.cibaStore
	d.CIBARequestTTL = s.cibaRequestTTL
	d.CIBAPollInterval = s.cibaPollInterval
	d.DCRPolicy = s.dcrPolicy
}

// populateHandlerDepsSubsystems assigns the issuers, lockout/replay/JAR/pairwise
// security primitives, MFA, FAPI, the feature flags, and cluster wiring.
func (s *Server) populateHandlerDepsSubsystems(d *handler.ServerDeps) {
	d.TokenIssuers = s.tokenIssuers
	d.IDTokenIssuer = s.idTokenIssuer
	d.JARMSigner = s.jarmSigner
	d.AccountLockout = s.accountLockout
	d.JTIReplayStore = s.jtiReplayStore
	d.JTIReplayFailClosed = s.jtiReplayFailClosed
	d.JARFetcher = s.jarFetcher
	d.JARDecrypter = s.jarDecrypter
	d.PairwiseStore = s.pairwiseStore
	d.SubjectClientIndex = s.subjectClientIndex
	d.MFAProvider = s.mfaProvider
	d.MFAChallengeStore = s.mfaChallengeStore
	d.MFAChallengeTTL = s.mfaChallengeTTL
	d.OAuth21Strict = s.oauth21Strict
	d.EmbedPermissions = s.embedPermissions
	d.FAPIValidator = s.fapiValidator
	d.ScopeDescriptions = s.scopeDescriptions
	d.ConnectionStore = s.connectionStore
	d.BackchannelLogoutMaxConcurrent = s.backchannelLogoutMaxConcurrent
	d.AllowDynamicClientRegistration = s.dcrPolicy != nil
	d.Issuer = s.issuer
	d.SupportedSigningAlgs = s.supportedSigningAlgs
	d.CrossReplicaRevocation = s.crossReplicaRevocation
	d.InvalidationBus = s.invalidationBus
}

// populateHandlerDepsCallbacks assigns the server-method closures the extracted
// handlers call back into (authz error bodies, issuer resolution, audit
// recorders, token validation, ready/storage-health probes).
func (s *Server) populateHandlerDepsCallbacks(d *handler.ServerDeps) {
	d.AuthzErrorBody = s.authzErrorBody
	d.AuthzErrorBodyDesc = s.authzErrorBodyDesc
	d.ResolveIssuer = s.resolveIssuer
	d.RecordLoginFailure = s.recordLoginFailure
	d.RecordLoginSuccess = s.recordLoginSuccess
	d.RecordTokenIssued = s.recordTokenIssued
	d.RecordLogout = s.recordLogout
	d.RecordIDTokenIssued = s.recordIDTokenIssued
	d.RecordRefreshTokenIssued = s.recordRefreshTokenIssued
	d.MeSubjectOrChallenge = s.meSubjectOrChallenge
	d.LogErrorCtx = s.logErrorCtx
	d.RevokeAcrossIssuers = s.revokeAcrossIssuers
	d.ValidateToken = s.ValidateToken
	d.RecordTenantLoginAttempt = s.recordTenantLoginAttempt
	d.RecordTenantTokenIssued = s.recordTenantTokenIssued
	d.ReadyChecks = func() map[string]func(ctx context.Context) error {
		m := make(map[string]func(ctx context.Context) error)
		for _, rc := range s.readyChecks {
			m[rc.Name] = rc.Check
		}
		return m
	}
	d.StorageHealthSources = func() []handler.StorageHealthSource {
		return s.storageHealthSources
	}
}

// Accessors exposing the issuance/refresh-family primitives to the extracted
// token-grant handlers in internal/handler (which *Server satisfies via the
// tokengrant.AuthCodeGrantDeps interface). These are thin wrappers over the
// existing root methods — the issuance IMPLEMENTATIONS stay in root; only the
// grant orchestration moved. The compile-time guard below proves *Server
// implements every method the interface needs (the interface pattern's safety
// vs. a nil-able Deps struct).
var _ tokengrant.AuthCodeGrantDeps = (*Server)(nil)
var _ tokengrant.RefreshGrantDeps = (*Server)(nil)
var _ tokengrant.DeviceGrantDeps = (*Server)(nil)
var _ tokengrant.CIBAGrantDeps = (*Server)(nil)
var _ tokengrant.TokenExchangeDeps = (*Server)(nil)
var _ tokengrant.ClientCredentialsDeps = (*Server)(nil)
var _ tokengrant.JWTBearerGrantDeps = (*Server)(nil)
var _ tokengrant.SAML2BearerGrantDeps = (*Server)(nil)

// SPIFFEValidator exposes the SPIFFE JWT-SVID validator (nil when WithSPIFFEJWTSVID
// is unwired — the SVID fallback is then skipped).
func (s *Server) SPIFFEValidator() *security.SPIFFEValidator { return s.spiffeValidator }

// SPIFFEAudience is this server's identifier that an inbound JWT-SVID must target.
func (s *Server) SPIFFEAudience() string { return s.spiffeAudience }

// IntrospectionCache returns the optional introspection result cache
// (WithIntrospectionCache). Nil means caching is disabled and every
// /token/introspect call pays full JWT verification.
func (s *Server) IntrospectionCache() oauth.IntrospectionCache { return s.introspectionCache }

// IntrospectionCacheTTL returns the configured TTL for cached introspection
// results. Only meaningful when IntrospectionCache() is non-nil.
func (s *Server) IntrospectionCacheTTL() time.Duration { return s.introspectionCacheTTL }

// HandleDeviceSecretExchange delegates the Native SSO device-secret actor branch
// of token-exchange to the root implementation (server_native_sso.go).
func (s *Server) HandleDeviceSecretExchange(ctx HandlerContext, idTokenClaims *TokenClaims, rawIDToken, deviceSecret string, client *Client, req tokengrant.TokenExchangeRequest) {
	s.handleDeviceSecretExchange(ctx, idTokenClaims, rawIDToken, deviceSecret, client, req)
}

// RecordCIBADecision emits the CIBA approve/deny audit event.
func (s *Server) RecordCIBADecision(ctx HandlerContext, clientID, subjectID string, approved bool) {
	s.recordCIBADecision(ctx, clientID, subjectID, approved)
}

// RefreshGrace exposes the refresh double-submit grace store (nil when unwired).
func (s *Server) RefreshGrace() tokengrant.RefreshGraceStore { return s.refreshGrace }

// RecordRefreshTokenReuse emits the family-reuse audit event (token replayed
// after rotation → family killed).
func (s *Server) RecordRefreshTokenReuse(ctx HandlerContext, clientID, familyID string, killed int) {
	s.recordRefreshTokenReuse(ctx, clientID, familyID, killed)
}

// RecordRefreshRotationVelocity emits the rotation-velocity-breach audit event.
func (s *Server) RecordRefreshRotationVelocity(ctx HandlerContext, clientID, familyID string, count, killed int) {
	s.recordRefreshRotationVelocity(ctx, clientID, familyID, count, killed)
}

// IncRefreshRotationVelocityExceeded bumps the velocity-breach metric (no-op
// when metrics are unwired).
func (s *Server) IncRefreshRotationVelocityExceeded() {
	if s.metrics != nil {
		s.metrics.RefreshRotationVelocityExceededTotal.Inc()
	}
}

// ApplyPairwiseSubject maps a local subject to its per-sector pairwise sub
// (OIDC §8) when the client opts in; passthrough otherwise.
func (s *Server) ApplyPairwiseSubject(ctx context.Context, client *Client, localSub string) string {
	return s.applyPairwiseSubject(ctx, client, localSub)
}

// IssueRefreshToken mints a refresh token, seeding a new rotation family.
func (s *Server) IssueRefreshToken(ctx context.Context, userID, clientID, provider string, scopes []string, attributes map[string]string, familyID string, resources []string, authDetails []byte, sid string, authCtx oauth.RefreshAuthContext, clientTTLOverride time.Duration, confirmationJKT string) (string, error) {
	return s.issueRefreshToken(ctx, userID, clientID, provider, scopes, attributes, familyID, resources, authDetails, sid, authCtx, clientTTLOverride, confirmationJKT)
}

// IssueDeviceSecret mints a Native SSO device secret (OIDC Native SSO §3.1).
func (s *Server) IssueDeviceSecret(ctx context.Context, subject, sid, clientID string) (string, error) {
	return s.issueDeviceSecret(ctx, subject, sid, clientID)
}

// MaybeEncryptIDToken applies JWE encryption to the signed id_token when the
// client registered encryption parameters; returns the signed token unchanged
// otherwise. The bool is false only on an encryption failure (id_token omitted).
func (s *Server) MaybeEncryptIDToken(ctx context.Context, client *Client, signed string) (string, bool) {
	return s.maybeEncryptIDToken(ctx, client, signed)
}

// DPoPTokenTypeOr returns "DPoP" when a JKT binding is present, else defaultType.
func (s *Server) DPoPTokenTypeOr(defaultType, jkt string) string {
	return dpopTokenTypeOr(defaultType, jkt)
}

// RecordTokenIssued emits the access-token-issued audit event + metric.
func (s *Server) RecordTokenIssued(ctx HandlerContext, clientID, strategy, subjectID string) {
	s.recordTokenIssued(ctx, clientID, strategy, subjectID)
}

// RecordSubjectClientAccess records the subject<->client access edge (used by
// back-channel logout to know which clients hold a session for the subject).
func (s *Server) RecordSubjectClientAccess(ctx context.Context, subject, clientID string) {
	s.recordSubjectClientAccess(ctx, subject, clientID)
}

// RecordRefreshTokenIssued emits the refresh-token-issued audit event + metric.
func (s *Server) RecordRefreshTokenIssued(ctx HandlerContext, clientID, subjectID string, rotation bool) {
	s.recordRefreshTokenIssued(ctx, clientID, subjectID, rotation)
}

// RecordIDTokenIssued emits the id-token-issued audit event + metric.
func (s *Server) RecordIDTokenIssued(ctx HandlerContext, clientID, subjectID string) {
	s.recordIDTokenIssued(ctx, clientID, subjectID)
}

// JWTBearerAssertionValidator returns the RFC 7523 JWT Bearer assertion
// validator, or nil when the grant is not enabled.
func (s *Server) JWTBearerAssertionValidator() tokengrant.JWTAssertionValidator {
	return s.jwtBearerValidator
}

// SAML2AssertionValidator returns the RFC 7522 SAML 2.0 Bearer assertion
// validator, or nil when the grant is not enabled.
func (s *Server) SAML2AssertionValidator() tokengrant.SAMLAssertionValidator {
	return s.saml2BearerValidator
}
