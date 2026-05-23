// Code generated. Server field accessors for use by handlers/middleware
// subpackages that need read-only access to Server configuration.
// These exist because handlers/ + middleware/ live in separate packages
// from sso and cannot reach into unexported Server fields directly.

package sso

import (
	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
	"time"
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

// DiscoveryCacheTTL returns the discovery snapshot cache TTL.
func (s *Server) DiscoveryCacheTTL() time.Duration { return s.discoveryCacheTTL }

// DiscoveryDocCacheTTL returns the discovery body cache TTL.
func (s *Server) DiscoveryDocCacheTTL() time.Duration { return s.discoveryDocCacheTTL }
