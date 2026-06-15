package handler

import (
	"context"
	"time"

	"github.com/snaplink/sso/anomaly"
	"github.com/snaplink/sso/audit"
	"github.com/snaplink/sso/core"
	"github.com/snaplink/sso/metrics"
	"github.com/snaplink/sso/oauth"
	"github.com/snaplink/sso/oidc"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/security"
	"github.com/snaplink/sso/spi"
	"github.com/snaplink/sso/connections"
	"github.com/snaplink/sso/federation"
)

// ServerDeps is the interface handler functions use to access Server
// configuration and state. Grows incrementally as files are moved.
type ServerDeps interface {
	SrvLogger() spi.Logger
	Auditor() *audit.Recorder
	Metrics() *metrics.Metrics
	AnomalyRunner() *anomaly.Runner
	Permissions() permissions.Provider

	// Core stores
	ClientStoreAccessor() core.ClientStore
	UserProviderAccessor() core.UserProvider
	SessionMgr() core.SessionManager
	ConsentStore() core.ConsentStore
	TenantUserStore() core.TenantUserStore

	// OAuth stores
	AuthCodeStore() oauth.AuthCodeStore
	AuthCodeTTL() time.Duration
	RefreshTokenStore() oauth.RefreshTokenStore
	RefreshTokenTTL() time.Duration
	DeviceCodeStore() oauth.DeviceCodeStore
	PARStore() oauth.PARStore
	PARTTL() time.Duration
	CIBAStore() oauth.CIBAStore
	DCRPolicy() *oauth.DCRPolicy

	// OIDC
	IDTokenIssuer() oidc.IDTokenIssuer
	JARMSigner() oidc.JARMSigner

	// Security
	AccountLockout() security.AccountLockout
	JTIReplayStore() security.JTIReplayStore
	JTIReplayFailClosed() bool
	JARFetcher() security.JARFetcher
	JARDecrypter() security.JWEDecrypter
	PairwiseStore() security.PairwiseSubjectStore

	// MFA
	MFAProvider() spi.MFAProvider
	MFAChallengeStore() spi.MFAChallengeStore
	MFAChallengeTTL() time.Duration

	// Feature flags
	OAuth21Strict() bool
	EmbedPermissions() bool

	// Federation
	FederationEntityConfig() *federation.Config
	FederationSigner() federation.JWTSigner

	// Misc
	ScopeDescriptions() map[string]string
	AllowDynamicClientRegistration() bool
	ConnectionStore() connections.Store
}

// HandlerContext is an alias to keep handler signatures consistent.
type HandlerContext = core.HandlerContext

// StorageHealthSource describes one wired store for the storage-health report.
type StorageHealthSource struct {
	Name           string
	Ping           func(ctx context.Context) error
	SchemaVersions func(ctx context.Context) (map[string]int, error)
}

// StorageHealthDeps is the interface for storage health handlers.
type StorageHealthDeps interface {
	StorageHealthSources() []StorageHealthSource
}
