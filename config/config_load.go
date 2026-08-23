package config

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/interfaces/ratelimit"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/lifecycle/authpipeline"
)

// Load reads and parses a YAML config file, then applies defaults.
//
// Implemented as a thin wrapper over the layered Source/Loader chain
// — equivalent to LoadFromSources(NewFileSource(path)). Use
// LoadFromSources directly when you need ENV / flag / etcd overlays.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultFileName
	}
	return LoadFromSources(context.Background(), NewFileSource(path))
}

// LoadFromSources builds a Loader from the given priority chain
// (lowest → highest) and resolves it into a fully-defaulted +
// validated *Config. Returns the first source / parse / validation
// error encountered.
//
// Typical production wiring:
//
//	cfg, err := config.LoadFromSources(ctx,
//	    config.NewFileSource("/etc/sso/config.yaml"),
//	    &config.FileSource{Path: "/etc/sso/local.yaml", Optional: true},
//	    config.NewEnvSource(),
//	)
//
// CLI flags sit on top of this chain via a forthcoming FlagSource.
func LoadFromSources(ctx context.Context, sources ...Source) (*Config, error) {
	return NewLoader(sources...).Load(ctx)
}

// DefaultServerIssuer is the cmd-side default for server.issuer when
// operators omit it. Intentionally NOT [sso.DefaultIssuer]: the SDK's
// DefaultIssuer is a sentinel that resolveIssuer + the OIDC discovery
// renderer treat as "fall back to requestBaseURL", while the
// Ed25519JWTIssuer always stamps the literal value into the JWT iss
// claim. Setting the SDK sentinel as cmd's default would produce a
// discovery doc whose `issuer` field is the requestBaseURL (e.g.
// http://localhost:9090) but JWTs whose `iss` claim is "snaplink-sso"
// — a wire-contract divergence that breaks every RFC 9068 access
// token validator. Using a non-sentinel default ("sso-server") keeps
// every path agreeing on the same string. Operators should set a
// canonical URL via `server.issuer` for production deployments.
const DefaultServerIssuer = "sso-server"

// DefaultBodyLimitBytes is the conservative body-size cap applied when the
// operator omits security.body_limit entirely. 64 KiB is generous for any
// OAuth/OIDC flow (typical /token ≈ 1 KiB; a JAR with a large JWKS is the
// ceiling). Set security.body_limit.max_bytes = -1 to explicitly opt into
// unlimited.
const DefaultBodyLimitBytes int64 = 64 * 1024

func (c *Config) applyDefaults() {
	if c.Server.Issuer == "" {
		c.Server.Issuer = DefaultServerIssuer
	}
	// Body-limit default: absent (0) → secure default; negative → unlimited (0).
	if c.Security.BodyLimit.MaxBytes == 0 {
		c.Security.BodyLimit.MaxBytes = DefaultBodyLimitBytes
	} else if c.Security.BodyLimit.MaxBytes < 0 {
		c.Security.BodyLimit.MaxBytes = 0 // explicit unlimited escape hatch
	}
	if c.Server.SessionTTL == 0 {
		c.Server.SessionTTL = sso.DefaultSessionDuration
	}
	if c.Server.TokenTTL == 0 {
		c.Server.TokenTTL = sso.DefaultTokenTTL
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Authenticators.Phone != nil {
		applyCodeDefaults(&c.Authenticators.Phone.CodeAuthConfig, authenticators.DefaultPhoneCodeTTL)
	}
	if c.Authenticators.Email != nil {
		applyCodeDefaults(c.Authenticators.Email, authenticators.DefaultEmailCodeTTL)
	}
	applyMagicLinkDefaults(c.Authenticators.MagicLink)
	applyCodeSendQuotaDefaults(&c.Authenticators.CodeSendQuota)
	applyBCLFailureQueueDefaults(&c.BackchannelLogout.FailureQueue)
	c.applyNotificationDefaults()
	if c.Authenticators.TempToken != nil && c.Authenticators.TempToken.TTL == 0 {
		c.Authenticators.TempToken.TTL = authenticators.DefaultTempTokenTTL
	}
	if c.Authenticators.KeyPair != nil && c.Authenticators.KeyPair.MaxClockSkew == 0 {
		c.Authenticators.KeyPair.MaxClockSkew = authenticators.DefaultKeyPairClockSkew
	}
}

func applyCodeSendQuotaDefaults(quota *CodeSendQuotaConfig) {
	if quota.IdentityLimit == 0 {
		quota.IdentityLimit = authenticators.DefaultCodeIdentitySendLimit
	}
	if quota.TenantLimit == 0 {
		quota.TenantLimit = authenticators.DefaultCodeTenantSendLimit
	}
	if quota.Window == 0 {
		quota.Window = authenticators.DefaultCodeSendQuotaWindow
	}
}

// applyMagicLinkDefaults is its own function (rather than an inline nil-check
// block in applyDefaults, like TempToken/KeyPair's single-field checks) to
// keep applyDefaults under the cyclomatic-complexity budget — MagicLinkConfig
// has two independently-defaulted fields, the same reason applyCodeDefaults
// exists for Phone/Email. A nil ml is a no-op (disabled/omitted section).
func applyMagicLinkDefaults(ml *MagicLinkConfig) {
	if ml == nil {
		return
	}
	if ml.TokenLength == 0 {
		ml.TokenLength = authenticators.DefaultMagicLinkTokenBytes
	}
	if ml.TTL == 0 {
		ml.TTL = authenticators.DefaultMagicLinkTTL
	}
}

func applyCodeDefaults(c *CodeAuthConfig, ttl time.Duration) {
	if c.CodeLength == 0 {
		c.CodeLength = authenticators.DefaultCodeLength
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = ttl
	}
}

func (c *Config) validate() error {
	if err := ValidateVersion(c); err != nil {
		return err
	}
	if err := c.normalizeFeatureGates(); err != nil {
		return err
	}
	// hosted_login is a legacy no-op: sso-server mounts no frontend, so the
	// parsed block can never enable anything; deprecation is loud (removal
	// lands with the next schema-version bump).
	if c.HostedLogin.Enabled {
		slog.Warn("config: hosted_login is deprecated and has no effect — sso-server serves no " +
			"frontend; deploy the login UI as a separate project (see docs/frontend-contract.md)")
	}
	if err := c.validateTopology(); err != nil {
		return err
	}
	if err := c.validateTenantResourceQuota(); err != nil {
		return err
	}
	if err := c.validateRegionPolicyStore(); err != nil {
		return err
	}
	if err := c.validateFeatureConfig(); err != nil {
		return err
	}
	if err := c.validateLogging(); err != nil {
		return err
	}
	// Reject the SDK's internal sentinel. resolveIssuer + the OIDC
	// discovery renderer treat sso.DefaultIssuer as "fall back to
	// requestBaseURL", while Ed25519JWTIssuer stamps it literally
	// into the JWT iss claim — the resulting discovery doc and
	// access tokens then disagree on the issuer string, which
	// breaks every spec-compliant RFC 9068 validator. See
	// DefaultServerIssuer above.
	if c.Server.Issuer == sso.DefaultIssuer {
		return fmt.Errorf("config: server.issuer must not equal the SDK sentinel %q — set it to your canonical public URL (e.g. https://sso.example.com) or accept the cmd default %q", sso.DefaultIssuer, DefaultServerIssuer)
	}
	if err := validateConfiguredClients(c); err != nil {
		return err
	}
	if err := validateIDTokenAlgs(c); err != nil {
		return err
	}
	if c.Backup.Keep < 0 {
		return fmt.Errorf("config: backup.keep must be >= 0 (0 disables retention), got %d", c.Backup.Keep)
	}
	return nil
}

// validateLogging validates the logging block: the level switch and the
// always-on access-log posture (tri-state enabled flag + body policy).
func (c *Config) validateLogging() error {
	switch strings.ToLower(c.Logging.Level) {
	case "debug", "info", "error":
	default:
		return fmt.Errorf("config: invalid logging.level %q", c.Logging.Level)
	}
	if err := c.Logging.AccessLog.validate(); err != nil {
		return err
	}
	return nil
}

func (c *Config) validateFeatureConfig() error {
	if err := c.Security.CORS.validate(); err != nil {
		return err
	}
	if err := c.ReBAC.validate(); err != nil {
		return err
	}
	if c.Audit.ExternalWorker.Enabled && !c.Audit.Enabled {
		return errors.New("config: audit.external_worker.enabled requires audit.enabled")
	}
	if err := c.Audit.ExternalWorker.validate(); err != nil {
		return err
	}
	if err := c.validateAuthPipeline(); err != nil {
		return err
	}
	if err := c.validateCodeSendQuota(); err != nil {
		return err
	}
	if err := c.Authenticators.CodeDelivery.validate(); err != nil {
		return err
	}
	if err := c.Activation.validate(); err != nil {
		return err
	}
	if err := c.validateBCLFailureQueue(); err != nil {
		return err
	}
	if err := c.validateScopeRegistry(); err != nil {
		return err
	}
	return c.validateNotifications()
}

func (c *Config) validateCodeSendQuota() error {
	quota := c.Authenticators.CodeSendQuota
	if quota.IdentityLimit < -1 || quota.TenantLimit < -1 {
		return errors.New("config: authenticators.code_send_quota limits must be -1 or greater")
	}
	// Zero is the pre-defaulting value used by tests and programmatic callers;
	// applyDefaults turns it into the stock 24-hour window on the load path.
	if quota.Window < 0 {
		return errors.New("config: authenticators.code_send_quota.window must be positive")
	}
	return nil
}

func (c *Config) applyNotificationDefaults() {
	if !c.Notifications.Enabled {
		return
	}
	if strings.TrimSpace(c.Notifications.Backend) == "" {
		c.Notifications.Backend = "memory"
	}
	if c.Notifications.Cooldown == 0 {
		c.Notifications.Cooldown = 5 * time.Minute
	}
	if c.Notifications.QueueSize == 0 {
		c.Notifications.QueueSize = 256
	}
	if c.Notifications.Workers == 0 {
		c.Notifications.Workers = 2
	}
	if c.Notifications.SessionExpiryWarning == 0 {
		c.Notifications.SessionExpiryWarning = 30 * time.Minute
	}
	if c.Notifications.SessionScanInterval == 0 {
		c.Notifications.SessionScanInterval = time.Minute
	}
}

func (c *Config) validateNotifications() error {
	if !c.Notifications.Enabled {
		return nil
	}
	switch strings.ToLower(strings.TrimSpace(c.Notifications.Backend)) {
	case "memory":
	case "sqlite":
		if strings.TrimSpace(c.Notifications.SQLite.DSN) == "" {
			return errors.New("config: notifications.sqlite.dsn required for sqlite backend")
		}
	default:
		return fmt.Errorf("config: notifications.backend must be memory or sqlite, got %q", c.Notifications.Backend)
	}
	if c.Notifications.Cooldown < 0 || c.Notifications.QueueSize < 1 || c.Notifications.Workers < 1 ||
		c.Notifications.SessionExpiryWarning < 1 || c.Notifications.SessionScanInterval < 1 {
		return errors.New("config: notifications cooldown must be non-negative and queue_size/workers/session expiry durations must be positive")
	}
	return nil
}

func (c *Config) validateTopology() error {
	mode := strings.ToLower(strings.TrimSpace(c.Server.Topology.Mode))
	switch mode {
	case "", TopologyModeSingle, TopologyModeMulti:
		c.Server.Topology.Mode = mode
	default:
		return fmt.Errorf("config: server.topology.mode must be %q or %q, got %q",
			TopologyModeSingle, TopologyModeMulti, c.Server.Topology.Mode)
	}
	if c.Server.Topology.AllowPerPodState && mode != TopologyModeMulti {
		return errors.New("config: server.topology.allow_per_pod_state requires mode: multi")
	}
	if mode == TopologyModeMulti && !c.Server.Topology.AllowPerPodState && c.ReBAC.Enabled {
		backend := strings.ToLower(strings.TrimSpace(c.ReBAC.Backend))
		if backend == "" || backend == "memory" {
			return errors.New("config: rebac.backend=memory is unsafe with server.topology.mode=multi; use sqlite")
		}
	}
	if mode == TopologyModeMulti && !c.Server.Topology.AllowPerPodState &&
		strings.EqualFold(strings.TrimSpace(c.Activation.Backend), "memory") {
		return errors.New("config: activation.backend=memory is unsafe with server.topology.mode=multi; use a shared ActivationStore")
	}
	return nil
}

// ServerOptions returns the sso.Option values implied by the configuration.
// Wire dependency-injected providers (TokenIssuer, UserProvider, ...) and
// authenticators separately.
func (c *Config) ServerOptions() []sso.Option {
	// Server.{BaseURL,SessionTTL,TokenTTL} are NOT wired here — the
	// matching sso.WithX options are deprecated no-ops. The real
	// session / token lifetimes live on the SessionManager and
	// TokenIssuer constructors; cmd/sso-server reads SessionTTL +
	// TokenTTL directly to feed those constructors.
	opts := []sso.Option{
		sso.WithIssuer(c.Server.Issuer),
	}
	if c.Server.DefaultTokenStrategy != "" {
		opts = append(opts, sso.WithDefaultTokenStrategy(c.Server.DefaultTokenStrategy))
	}
	opts = append(opts, c.securityMiddlewareOptions()...)
	opts = append(opts, c.backupOptions()...)
	// Always-on access log: on by default unless explicitly disabled.
	opts = append(opts, c.accessLogOptions()...)
	// Only wired when the operator touched at least one feature_gates key —
	// an all-nil FeatureGatesConfig is functionally identical to omitting
	// the option (every gate already defaults to on), so skipping the call
	// keeps ServerOptions' output byte-identical to a pre-gate build.
	if c.FeatureGates.anySet() {
		opts = append(opts, sso.WithFeatureGates(c.FeatureGates.toSSOGates()))
	}
	opts = append(opts, c.authPipelineOptions()...)
	return append(opts, c.credentialFormOnlyOptions()...)
}

func (c *Config) validateAuthPipeline() error {
	if _, err := authpipeline.NewIPSkipMFAHook(c.AuthPipeline.IPSkipMFACIDRs); err != nil {
		return fmt.Errorf("config: auth_pipeline.ip_skip_mfa_cidrs: %w", err)
	}
	seen := make(map[string]struct{}, len(c.AuthPipeline.RequiredProfileAttributes))
	for index, raw := range c.AuthPipeline.RequiredProfileAttributes {
		field := strings.TrimSpace(raw)
		if field == "" {
			return fmt.Errorf("config: auth_pipeline.required_profile_attributes[%d] must not be empty", index)
		}
		if _, exists := seen[field]; exists {
			return fmt.Errorf("config: auth_pipeline.required_profile_attributes contains duplicate %q", field)
		}
		seen[field] = struct{}{}
		c.AuthPipeline.RequiredProfileAttributes[index] = field
	}
	return nil
}

func (c *Config) authPipelineOptions() []sso.Option {
	options := make([]sso.Option, 0, 2)
	if len(c.AuthPipeline.IPSkipMFACIDRs) != 0 {
		hook, err := authpipeline.NewIPSkipMFAHook(c.AuthPipeline.IPSkipMFACIDRs)
		if err != nil {
			slog.Error("config: invalid auth pipeline CIDR; hook omitted", "error", err)
		} else {
			options = append(options, sso.WithAuthHook(hook))
		}
	}
	if len(c.AuthPipeline.RequiredProfileAttributes) != 0 {
		options = append(options, sso.WithAuthHook(authpipeline.NewProfileCompletionHook(c.AuthPipeline.RequiredProfileAttributes)))
	}
	return options
}

// toPolicy builds the ratelimit.Policy implied by the YAML block.
// Default rate / burst applies to unmatched paths; Prefixes layer
// per-endpoint overrides.
//
// Backend selects the limiter implementation, mirroring
// cmd/sso-server/serverbuildplatform.BuildRateLimitPolicy's semantics (the
// wiring every full sso-server deployment actually uses): "" / "memory"
// (default) builds in-process MemoryLimiters; "sqlite" builds
// cluster-shared SQLiteLimiters against SQLite.DSN. A "redis" backend needs
// a live *redis.Client this package cannot construct (config stays free of
// the redis transitive dep, mirroring Config.BuildNetworkStore's etcd
// carve-out), and an unrecognized backend is an operator typo — both cases
// log an error and fall back to an in-process limiter rather than silently
// pretending the configured backend was honored: an embedder calling
// ServerOptions() directly (unlike cmd/sso-server, which layers its own
// backend-aware BuildRateLimitPolicy call on top and so never actually hit
// this gap in production) would otherwise get a per-replica-only limiter
// with ZERO indication that "sqlite"/"redis" cluster-shared enforcement
// was silently downgraded.
func (r *RateLimitConfig) toPolicy() ratelimit.Policy {
	backend := strings.ToLower(strings.TrimSpace(r.Backend))
	switch backend {
	case "", "memory":
		// fall through to the memory build below.
	case "sqlite":
		if policy, err := r.sqliteRateLimitPolicy(); err != nil {
			slog.Error("config: security.rate_limit.backend=sqlite misconfigured — falling back to an in-process limiter that is NOT cluster-shared", "error", err)
		} else {
			return policy
		}
	default:
		slog.Error("config: unsupported security.rate_limit.backend for config.ServerOptions — falling back to an in-process limiter that is NOT cluster-shared; wire this backend via cmd/sso-server or sso.WithRateLimit directly", "backend", r.Backend)
	}
	return r.memoryRateLimitPolicy()
}

// memoryRateLimitPolicy builds per-replica MemoryLimiters — the default,
// and the fallback used when a configured Backend can't be honored here.
func (r *RateLimitConfig) memoryRateLimitPolicy() ratelimit.Policy {
	policy := ratelimit.Policy{}
	if r.DefaultPerSec > 0 && r.DefaultBurst > 0 {
		policy.Default = ratelimit.NewMemoryLimiter(r.DefaultPerSec, r.DefaultBurst)
	}
	for _, p := range r.Prefixes {
		if p.Prefix == "" || p.PerSec <= 0 || p.Burst <= 0 {
			continue
		}
		policy.Prefixes = append(policy.Prefixes, ratelimit.PrefixRule{
			Prefix:  p.Prefix,
			Limiter: ratelimit.NewMemoryLimiter(p.PerSec, p.Burst),
		})
	}
	return policy
}

// serverOption returns the sso.Option implied by a
// security.client_registration_rate_limit block, and ok=false when the
// section carries no EXPLICIT override — leaving sso.NewServer's built-in
// default limiter in place untouched (see the type's doc for why the zero
// value here is not "disabled", unlike every other security.* block).
func (r *ClientRegistrationRateLimitConfig) serverOption() (opt sso.Option, ok bool) {
	if r.Disabled {
		return sso.WithClientRegistrationRateLimit(nil), true
	}
	if r.PerSec > 0 && r.Burst > 0 {
		return sso.WithClientRegistrationRateLimit(ratelimit.NewMemoryLimiter(r.PerSec, r.Burst)), true
	}
	return nil, false
}

// sqliteRateLimitPolicy builds cluster-shared SQLiteLimiters; each prefix
// gets a distinct bucket_name so multiple rules can share one DSN file
// without colliding — mirrors
// serverbuildplatform.sqliteRateLimitPolicy's shape exactly.
func (r *RateLimitConfig) sqliteRateLimitPolicy() (ratelimit.Policy, error) {
	if r.SQLite.DSN == "" {
		return ratelimit.Policy{}, errors.New("security.rate_limit.sqlite.dsn required when backend=sqlite")
	}
	policy := ratelimit.Policy{}
	if r.DefaultPerSec > 0 && r.DefaultBurst > 0 {
		lim, err := ratelimit.NewSQLiteLimiter(r.SQLite.DSN, r.DefaultPerSec, r.DefaultBurst, "default")
		if err != nil {
			return ratelimit.Policy{}, fmt.Errorf("rate_limit default sqlite: %w", err)
		}
		policy.Default = lim
	}
	for _, p := range r.Prefixes {
		if p.Prefix == "" || p.PerSec <= 0 || p.Burst <= 0 {
			continue
		}
		lim, err := ratelimit.NewSQLiteLimiter(r.SQLite.DSN, p.PerSec, p.Burst, p.Prefix)
		if err != nil {
			return ratelimit.Policy{}, fmt.Errorf("rate_limit prefix %q sqlite: %w", p.Prefix, err)
		}
		policy.Prefixes = append(policy.Prefixes, ratelimit.PrefixRule{Prefix: p.Prefix, Limiter: lim})
	}
	return policy, nil
}
