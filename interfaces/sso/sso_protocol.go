package sso

import (
	"time"

	"github.com/snaplink/sso/domains/anomaly"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/middleware"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/internal/handler/tokengrant"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/protocols/fapi"
	"github.com/snaplink/sso/protocols/oauth"
	"github.com/snaplink/sso/protocols/oidc"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
)

// protocolState holds risk/MFA/anomaly/metrics/transport wiring and the OAuth/OIDC grant + discovery static configuration fields.
type protocolState struct {
	riskScorer        spi.RiskScorer
	mfaProvider       spi.MFAProvider
	mfaChallengeStore spi.MFAChallengeStore
	mfaChallengeTTL   time.Duration
	anomalyRunner     *anomaly.Runner
	metrics           *metrics.Metrics
	// trustedProxies validates X-Forwarded-For chains when wired via
	// WithTrustedProxies. When non-nil its Middleware is inserted outermost
	// in Handler() (before rate limiting and every other middleware), so
	// downstream KeyByClientIP calls see the validated IP via RealClientIP
	// rather than the raw header. Nil = no XFF validation; every XFF
	// consumer trusts the raw header unconditionally — safe only behind an
	// edge that strips and re-adds XFF.
	trustedProxies                 *middleware.TrustedProxies
	tenantMetricsAllowlist         map[string]struct{} // nil/empty = per-tenant metrics off (§5)
	rateLimitPolicy                *ratelimit.Policy
	bodyLimit                      int64
	bodyLimitByPath                map[string]int64 // exact-prefix overrides; longest prefix wins
	readyChecks                    []namedReadyCheck
	tracingOperation               string
	corsPolicy                     *cors.Policy
	securityHeadersEnabled         bool
	issuer                         string
	authCodeStore                  oauth.AuthCodeStore
	authCodeTTL                    time.Duration
	refreshTokenStore              oauth.RefreshTokenStore
	refreshTokenTTL                time.Duration
	refreshGrace                   tokengrant.RefreshGraceStore
	idTokenIssuer                  oidc.IDTokenIssuer
	deviceCodeStore                oauth.DeviceCodeStore
	deviceCodeTTL                  time.Duration
	deviceCodeInterval             time.Duration
	deviceVerifyBaseURL            string
	parStore                       oauth.PARStore
	parTTL                         time.Duration
	deviceSecretStore              DeviceSecretStore
	deviceSecretTTL                time.Duration
	protectedResourceMetadata      *ProtectedResourceMetadata
	cibaStore                      oauth.CIBAStore
	cibaTransport                  oauth.CIBATransport
	cibaPingNotifier               oauth.CIBAPingNotifier
	cibaRequestTTL                 time.Duration
	cibaPollInterval               time.Duration
	dcrPolicy                      *oauth.DCRPolicy
	oauth21Strict                  bool
	fapiValidator                  *fapi.Validator
	logoutTokenIssuer              LogoutTokenIssuer
	logoutNotifier                 LogoutNotifier
	backchannelLogoutMaxConcurrent int
	accountLockout                 security.AccountLockout
	jtiReplayStore                 security.JTIReplayStore
	jtiReplayFailClosed            bool
	subjectClientIndex             security.SubjectClientIndex
	jarFetcher                     security.JARFetcher
	jarDecrypter                   security.JWEDecrypter
	jweResponseEncrypter           security.JWEEncrypter
	clientCertExtractor            ClientCertExtractor
	dpopNonceProvider              DPoPNonceProvider
	dpopProofMaxAge                time.Duration
	dpopProofClockSkew             time.Duration
	metadataSigner                 oidc.MetadataSigner
	jarmSigner                     oidc.JARMSigner
	jwksCacheTTL                   time.Duration
	supportedACRValues             []string
	opPolicyURI                    string
	opTosURI                       string
	serviceDocumentation           string
}
