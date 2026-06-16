package handler

import (
	"context"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/cluster"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/fapi"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
)

// ServerDeps holds all Server dependencies for handlers.
// Populated once by root package via Server.BuildHandlerDeps().
type ServerDeps struct {
	// Core services
	Logger        spi.Logger
	Auditor       *audit.Recorder
	Metrics       *metrics.Metrics
	Permissions   permissions.Provider
	AnomalyRunner *anomaly.Runner

	// Core stores
	ClientStore       core.ClientStore
	UserProvider      core.UserProvider
	SessionMgr        core.SessionManager
	ConsentStore      core.ConsentStore
	TenantUserStore   core.TenantUserStore
	DeviceSecretStore core.DeviceSecretStore

	// OAuth stores
	AuthCodeStore       oauth.AuthCodeStore
	AuthCodeTTL         time.Duration
	RefreshTokenStore   oauth.RefreshTokenStore
	RefreshTokenTTL     time.Duration
	DeviceCodeStore     oauth.DeviceCodeStore
	DeviceCodeTTL       time.Duration
	DeviceCodeInterval  time.Duration
	DeviceVerifyBaseURL string
	PARStore            oauth.PARStore
	PARTTL              time.Duration
	CIBAStore           oauth.CIBAStore
	CIBARequestTTL      time.Duration
	CIBAPollInterval    time.Duration
	DCRPolicy           *oauth.DCRPolicy
	TokenIssuers        map[string]core.TokenIssuer

	// OIDC
	IDTokenIssuer oidc.IDTokenIssuer
	JARMSigner    oidc.JARMSigner

	// Security
	AccountLockout       security.AccountLockout
	JTIReplayStore       security.JTIReplayStore
	JTIReplayFailClosed  bool
	JARFetcher           security.JARFetcher
	JARDecrypter         security.JWEDecrypter
	PairwiseStore        security.PairwiseSubjectStore
	SubjectClientIndex   security.SubjectClientIndex

	// MFA
	MFAProvider       spi.MFAProvider
	MFAChallengeStore spi.MFAChallengeStore
	MFAChallengeTTL   time.Duration

	// Feature flags
	OAuth21Strict      bool
	EmbedPermissions   bool
	FAPIValidator      *fapi.Validator

	// Misc
	ScopeDescriptions              map[string]string
	ConnectionStore                connections.Store
	BackchannelLogoutMaxConcurrent int
	AllowDynamicClientRegistration bool

	// Tenant metrics
	TenantMetricsEnabled    bool
	RecordTenantLoginAttempt func(ctx HandlerContext, clientID, outcome string)
	RecordTenantTokenIssued  func(ctx HandlerContext, clientID, strategy string)

	// Ready / Storage health
	ReadyChecks          func() map[string]func(ctx context.Context) error
	StorageHealthSources func() []StorageHealthSource

	// Cross-replica
	CrossReplicaRevocation bool
	InvalidationBus        cluster.Bus

	// Func wrappers for common Server methods
	AuthzErrorBody          func(ctx HandlerContext, code string) map[string]string
	AuthzErrorBodyDesc      func(ctx HandlerContext, code, desc string) map[string]string
	ResolveIssuer           func(ctx HandlerContext) string
	RecordLoginFailure      func(ctx HandlerContext, clientID, provider, reason string)
	RecordLoginSuccess      func(ctx HandlerContext, clientID, provider, strategy, userID, sessionID string)
	RecordTokenIssued       func(ctx HandlerContext, clientID, strategy, subjectID string)
	RecordLogout            func(ctx HandlerContext, sessionID string, revoked []string)
	RecordIDTokenIssued     func(ctx HandlerContext, clientID, subjectID string)
	RecordRefreshTokenIssued func(ctx HandlerContext, clientID, subjectID string, rotation bool)
	MeSubjectOrChallenge    func(ctx HandlerContext) (string, bool)
	LogErrorCtx             func(ctx HandlerContext, msg string, kv ...any)
	RevokeAcrossIssuers     func(ctx context.Context, token string) ([]string, []string)
}

// HandlerContext alias.
type HandlerContext = core.HandlerContext

// StorageHealthSource describes one wired store.
type StorageHealthSource struct {
	Name           string
	Ping           func(ctx context.Context) error
	SchemaVersions func(ctx context.Context) (map[string]int, error)
}
