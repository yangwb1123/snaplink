package sso

import (
	"context"
	"errors"
	"github.com/snaplink/sso/domains/federation"
	"net/http"
	"sort"
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/platform/cluster"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/platform/netpolicy"
	"github.com/snaplink/sso/domains/region"
	"github.com/snaplink/sso/protocols/compliance"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/core"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// Server field accessors, consolidated. These expose Server internals to the
// hexagonally-extracted handlers in internal/, oauth/, oidc/, selfservice/, etc.
// (thin getters + a few thin record/encrypt wrappers). Grouped here to keep the
// root file count down; the per-concern compile-guards live alongside their
// interface consumers in accessors_handlers.go / accessors_discovery.go /
// accessors_userinfo.go / accessors_token_grant.go.

// Accessors for the B2B org handlers extracted to admin/ (tenant-member +
// invitation admin) and selfservice/ (the /me organization endpoints).
func (s *Server) InvitationStore() core.InvitationStore  { return s.invitationStore }
func (s *Server) InvitationSender() spi.InvitationSender { return s.invitationSender }

func (s *Server) AuthCodeStore() oauth.AuthCodeStore         { return s.authCodeStore }
func (s *Server) AuthCodeTTL() time.Duration                 { return s.authCodeTTL }
func (s *Server) RefreshTokenStore() oauth.RefreshTokenStore { return s.refreshTokenStore }
func (s *Server) RefreshTokenTTL() time.Duration             { return s.refreshTokenTTL }
func (s *Server) DeviceCodeStore() oauth.DeviceCodeStore     { return s.deviceCodeStore }
func (s *Server) DeviceCodeTTL() time.Duration               { return s.deviceCodeTTL }
func (s *Server) DeviceCodeInterval() time.Duration          { return s.deviceCodeInterval }
func (s *Server) DeviceVerifyBaseURL() string                { return s.deviceVerifyBaseURL }
func (s *Server) PARStore() oauth.PARStore                   { return s.parStore }
func (s *Server) PARTTL() time.Duration                      { return s.parTTL }
func (s *Server) CIBAStore() oauth.CIBAStore                 { return s.cibaStore }
func (s *Server) CIBARequestTTL() time.Duration              { return s.cibaRequestTTL }
func (s *Server) CIBAPollInterval() time.Duration            { return s.cibaPollInterval }
func (s *Server) DCRPolicy() *oauth.DCRPolicy                { return s.dcrPolicy }

func (s *Server) JTIReplayStore() security.JTIReplayStore         { return s.jtiReplayStore }
func (s *Server) SubjectClientIndex() security.SubjectClientIndex { return s.subjectClientIndex }
func (s *Server) JARFetcher() security.JARFetcher                 { return s.jarFetcher }
func (s *Server) JARDecrypter() security.JWEDecrypter             { return s.jarDecrypter }
func (s *Server) JWEResponseEncrypter() security.JWEEncrypter     { return s.jweResponseEncrypter }
func (s *Server) AccountLockout() security.AccountLockout         { return s.accountLockout }
func (s *Server) PairwiseStore() security.PairwiseSubjectStore    { return s.pairwiseStore }
func (s *Server) ClientCertExtractor() ClientCertExtractor        { return s.clientCertExtractor }
func (s *Server) DPoPNonceProvider() DPoPNonceProvider            { return s.dpopNonceProvider }

// EncryptIDTokenForClient encrypts an id_token for a specific client when
// the client has id_token_encrypted_response_alg configured.
func (s *Server) EncryptIDTokenForClient(ctx context.Context, client *Client, signed string) (string, bool) {
	return s.maybeEncryptIDToken(ctx, client, signed)
}

func (s *Server) Auditor() *audit.Recorder                  { return s.auditor }
func (s *Server) Permissions() permissions.Provider         { return s.permissions }
func (s *Server) EmbedPermissions() bool                    { return s.embedPermissions }
func (s *Server) NetStore() netpolicy.Store                 { return s.netStore }
func (s *Server) NetClassifier() *netpolicy.Classifier      { return s.netClassifier }
func (s *Server) Metrics() *metrics.Metrics                 { return s.metrics }
func (s *Server) SrvLogger() spi.Logger                     { return s.logger }
func (s *Server) Issuer() string                            { return s.issuer }
func (s *Server) SessionMgr() core.SessionManager           { return s.sessionMgr }
func (s *Server) ClientStoreAccessor() core.ClientStore     { return s.clientStore }
func (s *Server) TokenIssuers() map[string]core.TokenIssuer { return s.tokenIssuers }
func (s *Server) LogoutTokenIssuer() LogoutTokenIssuer      { return s.logoutTokenIssuer }
func (s *Server) LogoutNotifier() LogoutNotifier            { return s.logoutNotifier }

func (s *Server) IDTokenIssuer() oidc.IDTokenIssuer { return s.idTokenIssuer }

// SubjectRefreshRevoker exposes the refresh-token store's bulk subject-revocation
// capability as a narrow oidc-local interface, so oidc/end-session need not import
// oauth. Nil when the wired store lacks the subject index (feature off).
func (s *Server) SubjectRefreshRevoker() oidc.SubjectRefreshRevoker {
	if idx, ok := s.refreshTokenStore.(oauth.RefreshTokenSubjectIndex); ok {
		return idx
	}
	return nil
}

func (s *Server) MetadataSigner() oidc.MetadataSigner      { return s.metadataSigner }
func (s *Server) JARMSigner() oidc.JARMSigner              { return s.jarmSigner }
func (s *Server) MFAProvider() spi.MFAProvider             { return s.mfaProvider }
func (s *Server) MFAChallengeStore() spi.MFAChallengeStore { return s.mfaChallengeStore }
func (s *Server) MFAChallengeTTL() time.Duration           { return s.mfaChallengeTTL }
func (s *Server) AnomalyRunner() *anomaly.Runner           { return s.anomalyRunner }

func (s *Server) ConnectionStore() connections.Store        { return s.connectionStore }
func (s *Server) ConsentStore() core.ConsentStore           { return s.consentStore }
func (s *Server) TenantUserStore() core.TenantUserStore     { return s.tenantUserStore }
func (s *Server) UserProviderAccessor() core.UserProvider   { return s.userProvider }
func (s *Server) DeviceSecretStore() core.DeviceSecretStore { return s.deviceSecretStore }
func (s *Server) CrossReplicaRevocationEnabled() bool       { return s.crossReplicaRevocation }
func (s *Server) InvalidationBus() cluster.Bus              { return s.invalidationBus }
func (s *Server) DataExporter() *compliance.Exporter        { return s.dataExporter }
func (s *Server) AccountEraser() *compliance.Eraser         { return s.accountEraser }

// ResidencyGateAccess is the data-residency READ gate for the /me/* surface.
// It delegates to the same engine as /userinfo; returns (code, true) when the
// region denies access and the caller must write a 403.
func (s *Server) ResidencyGateAccess(ctx HandlerContext, claims *TokenClaims) (string, bool) {
	return s.residencyDeniedForAccess(ctx, claims)
}

// ResidencyGateWrite is the data-residency WRITE gate for the /me/* surface.
// It resolves clientID → tenant and delegates to ResidencyDecision. Returns
// (code, true) when the write must be denied; ("", false) when it may proceed.
func (s *Server) ResidencyGateWrite(ctx HandlerContext, claims *TokenClaims) (string, bool) {
	if !s.tenantResidencyEnabled || claims == nil || claims.ClientID == "" {
		return "", false
	}
	client, err := s.clientStore.Get(ctx.Request().Context(), claims.ClientID)
	if err != nil || client == nil || client.TenantID == "" {
		return "", false
	}
	servingRegion, ok := region.FromHandlerContext(ctx)
	if !ok || servingRegion == "" {
		return "", false
	}
	return s.ResidencyDecision(ctx.Request().Context(), client.TenantID, servingRegion, true)
}

// RecordConsentRevoked emits the consent-revoked audit event (selfservice seam).
func (s *Server) RecordConsentRevoked(ctx HandlerContext, userID, clientID string) {
	s.recordConsentEvent(ctx, audit.EventConsentRevoked, audit.OutcomeSuccess, userID, clientID, nil)
}

// Tenant metrics accessors.
func (s *Server) RecordTenantLoginAttempt(ctx HandlerContext, clientID, outcome string) {
	s.recordTenantLoginAttempt(ctx, clientID, outcome)
}
func (s *Server) RecordTenantTokenIssued(ctx HandlerContext, clientID, strategy string) {
	s.recordTenantTokenIssued(ctx, clientID, strategy)
}
func (s *Server) TenantMetricsEnabled() bool { return s.tenantMetricsEnabled() }
func (s *Server) TenantLabel(ctx HandlerContext, clientID string) string {
	return s.tenantLabel(ctx, clientID)
}
func (s *Server) TenantMetricsAllowlist() map[string]struct{} { return s.tenantMetricsAllowlist }

// Accessors exposing the /userinfo security-orchestration primitives to
// oidc.HandleUserInfo (which *Server satisfies via the oidc.UserInfoDeps
// interface). These are thin wrappers over the existing root methods — the
// security IMPLEMENTATIONS (DPoP/mTLS/residency/token validation) stay in root;
// only the OIDC endpoint orchestration moved to oidc. The compile-time guard
// below proves *Server implements every method the interface needs (so no
// accessor can be silently missing — the interface pattern's safety vs. a
// nil-able Deps struct).

// RequireUserInfoDeps reports a misconfiguration when the token issuer or user
// provider needed by /userinfo is unwired.
func (s *Server) RequireUserInfoDeps() error { return s.requireDeps(DepTokenIssuer, DepUserProvider) }

// BearerToken extracts the RFC 6750 bearer credential from the request.
func (s *Server) BearerToken(r *http.Request) string { return bearerToken(r) }

// IsDPoPNonceRequired reports whether err is the DPoP nonce-required sentinel.
func (s *Server) IsDPoPNonceRequired(err error) bool { return errors.Is(err, ErrDPoPNonceRequired) }

// SetResourceBearerChallenge stamps the RFC 6750 §3 resource-server challenge.
func (s *Server) SetResourceBearerChallenge(ctx core.HandlerContext, realm, errorCode, errorDescription string) {
	s.setResourceBearerChallenge(ctx, realm, errorCode, errorDescription)
}

// VerifyDPoPBearer enforces the RFC 9449 §7 DPoP sender-constraint on a bearer.
func (s *Server) VerifyDPoPBearer(ctx core.HandlerContext, claims *core.TokenClaims) error {
	return s.verifyDPoPBearer(ctx, claims)
}

// StampDPoPNonce sets the RFC 9449 §8 DPoP-Nonce response header.
func (s *Server) StampDPoPNonce(ctx core.HandlerContext) { s.stampDPoPNonce(ctx) }

// VerifyMTLSBearer enforces the RFC 8705 §3 mTLS sender-constraint on a bearer.
func (s *Server) VerifyMTLSBearer(ctx core.HandlerContext, claims *core.TokenClaims) error {
	return s.verifyMTLSBearer(ctx, claims)
}

// ResidencyDeniedForAccess applies the data-residency read-gate for a validated token.
func (s *Server) ResidencyDeniedForAccess(ctx core.HandlerContext, claims *core.TokenClaims) (string, bool) {
	return s.residencyDeniedForAccess(ctx, claims)
}

// MaybeSignUserInfo signs the userinfo response as a JWT when the client opted in.
func (s *Server) MaybeSignUserInfo(ctx core.HandlerContext, clientID string, body map[string]any) bool {
	return s.maybeSignUserInfo(ctx, clientID, body)
}

// LogErrorCtx logs a non-fatal error with request correlation.
func (s *Server) LogErrorCtx(ctx core.HandlerContext, msg string, kv ...any) {
	s.logErrorCtx(ctx, msg, kv...)
}

// Compile-time proof that *Server fully satisfies the userinfo handler's deps
// (so no accessor can be silently missing).
var _ oidc.UserInfoDeps = (*Server)(nil)

// Code generated. Server field accessors for discovery, config, and federation.

// Discovery and cache TTL accessors.
func (s *Server) JWKSCacheTTL() time.Duration          { return s.jwksCacheTTL }
func (s *Server) JWKSCacheMaxAge() time.Duration       { return s.jwksCacheTTL }
func (s *Server) DiscoveryCacheTTL() time.Duration     { return s.discoveryCacheTTL }
func (s *Server) DiscoveryDocCacheTTL() time.Duration  { return s.discoveryDocCacheTTL }
func (s *Server) OpPolicyURI() string                  { return s.opPolicyURI }
func (s *Server) OpTosURI() string                     { return s.opTosURI }
func (s *Server) ServiceDocumentation() string         { return s.serviceDocumentation }
func (s *Server) SupportedACRValues() []string         { return s.supportedACRValues }
func (s *Server) OAuth21Strict() bool                  { return s.oauth21Strict }
func (s *Server) ScopeDescriptions() map[string]string { return s.scopeDescriptions }
func (s *Server) JTIReplayFailClosed() bool            { return s.jtiReplayFailClosed }
func (s *Server) AllowDynamicClientRegistration() bool { return s.dcrPolicy != nil }

// ResolveIssuer returns the issuer URL for the current request.
func (s *Server) ResolveIssuer(ctx core.HandlerContext) string { return s.resolveIssuer(ctx) }

// RequestBaseURL derives the absolute scheme://host base for the request.
func (s *Server) RequestBaseURL(ctx core.HandlerContext) string {
	return requestBaseURL(ctx.Request())
}

// SigningAlgValues returns the distinct JWS `alg` values the wired
// signers actually publish, for the discovery doc's *_signing_alg_values_supported.
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

// Federation accessors.
func (s *Server) FederationSigner() federation.JWTSigner {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Signer()
}

func (s *Server) FederationConfig() *federation.Config {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Config()
}

func (s *Server) FederationCache() *federation.EntityConfigCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.Cache()
}

func (s *Server) FederationFetchCache() *federation.SubordinateStatementCache {
	if s.federationEntity == nil {
		return nil
	}
	return s.federationEntity.FetchCache()
}

func (s *Server) FederationNow() time.Time { return time.Now() }

// JWKS document cache methods.
func (s *Server) ComputeJWKSDocument(compute func() ([]byte, error)) ([]byte, error) {
	if s.jwksCacheTTL > 0 {
		s.jwksBodyMu.RLock()
		if time.Now().Before(s.jwksBodyExp) && len(s.jwksBodyCache) > 0 {
			body := s.jwksBodyCache
			s.jwksBodyMu.RUnlock()
			return body, nil
		}
		s.jwksBodyMu.RUnlock()
	}
	body, err := s.jwksFlight.Do(compute)
	if err != nil {
		return nil, err
	}
	if s.jwksCacheTTL > 0 {
		s.jwksBodyMu.Lock()
		s.jwksBodyCache = body
		s.jwksBodyExp = time.Now().Add(s.jwksCacheTTL)
		s.jwksBodyMu.Unlock()
	}
	return body, nil
}

func (s *Server) InvalidateJWKSBodyCache() {
	s.jwksBodyMu.Lock()
	s.jwksBodyExp = time.Time{}
	s.jwksBodyMu.Unlock()
}
