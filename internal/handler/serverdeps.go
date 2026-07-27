package handler

import (
	"context"
	"time"

	"crypto/x509"
	"github.com/yangwb1123/snaplink/domains/anomaly"
	"github.com/yangwb1123/snaplink/domains/connections"
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/platform/audit"
	"github.com/yangwb1123/snaplink/platform/cluster"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/protocols/compliance"
	"github.com/yangwb1123/snaplink/protocols/fapi"
	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/protocols/oidc"
	"github.com/yangwb1123/snaplink/shared/core"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
	"net/http"
)

// ServerDeps holds all Server dependencies for handlers.
type ServerDeps struct {
	// Core services
	Logger        spi.Logger
	Auditor       *audit.Recorder
	Metrics       *metrics.Metrics
	Permissions   permissions.Provider
	AnomalyRunner *anomaly.Runner

	// Core stores
	ClientStore           core.ClientStore
	UserProvider          core.UserProvider
	SessionMgr            core.SessionManager
	ConsentStore          core.ConsentStore
	TenantUserStore       core.TenantUserStore
	DeviceSecretStore     core.DeviceSecretStore
	PasswordResetStore    core.PasswordResetStore
	PasswordResetTTL      time.Duration
	PasswordResetSender   func(ctx context.Context, email, token string) error
	PasswordResetResolver func(ctx context.Context, email string) (string, error)
	InvitationStore       core.InvitationStore
	InvitationSender      func(ctx context.Context, email, token, tenantID string) error

	// OAuth stores
	AuthCodeStore        oauth.AuthCodeStore
	AuthCodeTTL          time.Duration
	RefreshTokenStore    oauth.RefreshTokenStore
	RefreshTokenTTL      time.Duration
	DeviceCodeStore      oauth.DeviceCodeStore
	DeviceCodeTTL        time.Duration
	DeviceCodeInterval   time.Duration
	DeviceVerifyBaseURL  string
	PARStore             oauth.PARStore
	PARTTL               time.Duration
	CIBAStore            oauth.CIBAStore
	CIBARequestTTL       time.Duration
	CIBAPollInterval     time.Duration
	DCRPolicy            *oauth.DCRPolicy
	TokenIssuers         map[string]core.TokenIssuer
	DefaultTokenStrategy string

	// OIDC
	IDTokenIssuer  oidc.IDTokenIssuer
	JARMSigner     oidc.JARMSigner
	MetadataSigner oidc.MetadataSigner

	// Security
	AccountLockout      security.AccountLockout
	JTIReplayStore      security.JTIReplayStore
	JTIReplayFailClosed bool
	JARFetcher          security.JARFetcher
	JARDecrypter        security.JWEDecrypter
	PairwiseStore       security.PairwiseSubjectStore
	SubjectClientIndex  security.SubjectClientIndex
	ClientCertExtractor func(r *http.Request) (*x509.Certificate, bool)
	DPoPNonceProvider   func(ctx context.Context) (string, error)

	// MFA
	MFAProvider        spi.MFAProvider
	MFAChallengeStore  spi.MFAChallengeStore
	MFAChallengeTTL    time.Duration
	MFAEnrollmentStore core.MFAEnrollmentStore
	TOTPEnroller       interface {
		Enroll(ctx context.Context, userID string) (interface{}, error)
	}
	WebAuthnRegistrar interface {
		BeginRegistration(ctx context.Context, userID string) (interface{}, error)
	}

	// Feature flags
	OAuth21Strict    bool
	EmbedPermissions bool
	FAPIValidator    *fapi.Validator
	SignupEnabled    bool
	JITMembership    bool
	AuditAPI         bool

	// Config
	ScopeDescriptions              map[string]string
	ConnectionStore                connections.Store
	BackchannelLogoutMaxConcurrent int
	AllowDynamicClientRegistration bool
	Issuer                         string
	SupportedSigningAlgs           []string
	JWKSCacheTTL                   time.Duration
	DiscoveryDocCacheTTL           time.Duration
	BodyLimit                      int64
	BodyLimitByPath                map[string]int64
	SelfEditableAttrs              []string
	RateLimitPolicy                interface{}

	// Tenant
	TenantMetricsEnabled     bool
	RecordTenantLoginAttempt func(ctx HandlerContext, clientID, outcome string)
	RecordTenantTokenIssued  func(ctx HandlerContext, clientID, strategy string)
	TenantSuspensionCache    interface {
		Get(tenantID string) (suspended bool, fresh bool)
	}
	TenantResidencyCache interface {
		Get(tenantID string) (allowed bool, fresh bool)
	}

	// Ready / Storage health
	ReadyChecks          func() map[string]func(ctx context.Context) error
	StorageHealthSources func() []StorageHealthSource

	// Cross-replica
	CrossReplicaRevocation bool
	InvalidationBus        cluster.Bus

	// Extra stores for self-service
	EmailChangeSender       func(ctx context.Context, userID, newEmail, token string) error
	EmailChangeStore        core.EmailChangeStore
	EmailChangeTTL          time.Duration
	PasswordCredentialStore core.PasswordCredentialStore
	DataExporter            interface {
		Export(ctx context.Context, subject string) (*compliance.Report, error)
	}
	AccountEraser interface {
		Erase(ctx context.Context, subject string) (*compliance.Report, error)
	}
	ConsentChallenges    map[string]interface{}
	ConsentChallengeFunc func(ctx context.Context, challengeID string) (interface{}, bool)

	// Func wrappers for Server methods
	AuthzErrorBody           func(ctx HandlerContext, code string) map[string]string
	AuthzErrorBodyDesc       func(ctx HandlerContext, code, desc string) map[string]string
	ResolveIssuer            func(ctx HandlerContext) string
	RecordLoginFailure       func(ctx HandlerContext, clientID, provider, reason string)
	RecordLoginSuccess       func(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string)
	RecordTokenIssued        func(ctx HandlerContext, clientID, strategy, subjectID string)
	RecordLogout             func(ctx HandlerContext, sessionID string, revoked []string)
	RecordIDTokenIssued      func(ctx HandlerContext, clientID, subjectID string)
	RecordRefreshTokenIssued func(ctx HandlerContext, clientID, subjectID string, rotation bool)
	RecordCallbackFailure    func(ctx HandlerContext, provider, reason string)
	RecordAccountLocked      func(ctx HandlerContext, clientID, provider, lockKey string, until time.Time)
	RecordCodeSent           func(ctx HandlerContext, provider, target string, ok bool)
	RecordDeviceCodeIssued   func(ctx HandlerContext, clientID string)
	RecordSelfErase          func(ctx HandlerContext, userID string)
	RecordRefreshTokenReuse  func(ctx HandlerContext, clientID, familyID string, killed int)
	MeSubjectOrChallenge     func(ctx HandlerContext) (string, bool)
	LogErrorCtx              func(ctx HandlerContext, msg string, kv ...any)
	RevokeAcrossIssuers      func(ctx context.Context, token string) ([]string, []string)
	ValidateToken            func(ctx context.Context, token string) (*core.TokenClaims, error)
	ApplyPairwiseSubject     func(ctx context.Context, client *core.Client, user *core.User) string
	IssuerForClient          func(client *core.Client) (string, core.TokenIssuer, error)
	IDTokenIssuerForClient   func(client *core.Client) (oidc.IDTokenIssuer, bool, error)
	JARMSignerForClient      func(client *core.Client) (oidc.JARMSigner, bool)
	AuthenticateClientCreds  func(ctx HandlerContext, id, secret string) error
	AuthenticatedSubject     func(ctx HandlerContext) (userID, clientID string, ok bool)
	BuildOIDCConfiguration   func(ctx HandlerContext, base string) map[string]any
	ComputeDiscoverySnapshot func(ctx context.Context) any
}

type HandlerContext = core.HandlerContext

type StorageHealthSource struct {
	Name           string
	Ping           func(ctx context.Context) error
	SchemaVersions func(ctx context.Context) (map[string]int, error)
}
