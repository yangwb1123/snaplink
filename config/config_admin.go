package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/cors"
	"github.com/yangwb1123/snaplink/shared/core"
)

type DPoPNonceConfig struct {
	Enabled bool          `yaml:"enabled"`
	KeyFile string        `yaml:"key_file"`
	TTL     time.Duration `yaml:"ttl"`
}

// BodyLimitConfig caps request body size. MaxBytes=0 disables the
// global limit (sso.WithBodyLimit is not wired). Typical production
// value: 1048576 (1 MiB) — generous for any auth-flow payload,
// blocks gigabyte-class DoS.
//
// Overrides applies a per-prefix override (longest-match wins). Use
// a value of 0 in an override to mean "unlimited for this prefix"
// — the escape hatch for endpoints that legitimately accept large
// bodies (PAR request objects, WebAuthn attestation blobs) while
// keeping a global cap on everything else.
type BodyLimitConfig struct {
	MaxBytes  int64                     `yaml:"max_bytes"`
	Overrides []BodyLimitOverrideConfig `yaml:"overrides"`
}

// BodyLimitOverrideConfig is one entry in BodyLimitConfig.Overrides.
// Prefix is matched against the request path; the longest matching
// prefix's MaxBytes wins. Zero means "unlimited for this prefix".
type BodyLimitOverrideConfig struct {
	Prefix   string `yaml:"prefix"`
	MaxBytes int64  `yaml:"max_bytes"`
}

// RateLimitConfig configures the token-bucket middleware. Default
// values apply to every path not matched by a Prefixes entry; per-
// prefix overrides tighten the bucket for hot endpoints like
// /auth/login.
//
// Backend choice:
//   - "" / "memory" (default) — single-replica only.
//   - "sqlite" — cluster-shared bucket state; a request that drained
//     the bucket on replica A is visible to replica B before B
//     grants the next request. SQLite handles low-thousands writes/sec
//     comfortably; Redis is the recommended next step for SaaS-scale
//     auth-heavy workloads.
type RateLimitConfig struct {
	Enabled       bool                    `yaml:"enabled"`
	Backend       string                  `yaml:"backend"`
	SQLite        RateLimitSQLiteConfig   `yaml:"sqlite"`
	DefaultPerSec float64                 `yaml:"default_per_sec"`
	DefaultBurst  int                     `yaml:"default_burst"`
	Prefixes      []RateLimitPrefixConfig `yaml:"prefixes"`

	// PruneInterval, when positive and backend is "" or "memory", starts a
	// background sweep (ratelimit.MemoryLimiter.StartPruner) on every
	// configured limiter instead of the default sampled inline prune. The
	// inline prune runs its O(N) shard scan WHILE holding that shard's
	// lock, so a high-cardinality attack repeatedly hashing to one shard
	// makes it increasingly expensive and blocks every other request
	// hashed there — the rate limiter amplifying, rather than absorbing,
	// the attack it exists to stop. 0 (the default) keeps the existing
	// sampled inline behavior, byte-identical to before this field existed.
	PruneInterval time.Duration `yaml:"prune_interval"`
}

type RateLimitSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// RateLimitPrefixConfig is one path-prefix rule inside RateLimitConfig.
// Order matters — first match wins, evaluated in declaration order.
type RateLimitPrefixConfig struct {
	Prefix string  `yaml:"prefix"`
	PerSec float64 `yaml:"per_sec"`
	Burst  int     `yaml:"burst"`
}

// ClientRegistrationRateLimitConfig configures the narrow, IP-keyed rate
// limit on POST /register (RFC 7591 Dynamic Client Registration). Every
// other security.* block in this file is opt-in / off-by-default for
// backward compat; this one is the deliberate exception — DCR is an
// unauthenticated (or IAT-shared, effectively-public) endpoint, so a zero
// value here does NOT mean "disabled" the way it does for RateLimitConfig
// above. sso.NewServer already seeds a conservative built-in MemoryLimiter
// (see checkClientRegistrationRateLimit's doc in interfaces/sso/quota.go)
// so registration spam is bounded even when an operator never touches this
// section. Set Disabled: true to turn it off (e.g. it's already throttled
// at an edge/WAF); set PerSec/Burst (both > 0) to override the built-in
// rate without disabling it. This is intentionally SEPARATE from
// RateLimitConfig.Prefixes above (which already supports a "/register"
// prefix rule) because that whole mechanism is opt-in via
// RateLimitConfig.Enabled — an operator would have to remember to turn on
// the GLOBAL limiter just to protect this one endpoint.
type ClientRegistrationRateLimitConfig struct {
	Disabled bool    `yaml:"disabled"`
	PerSec   float64 `yaml:"per_sec"`
	Burst    int     `yaml:"burst"`
}

// CORSConfig configures the CORS middleware. When Enabled is true, at least
// one of AllowedOrigins or PathOverrides must be populated to install CORS;
// an empty default origin list is valid when path-specific policies are used.
type CORSConfig struct {
	Enabled          bool          `yaml:"enabled"`
	AllowedOrigins   []string      `yaml:"allowed_origins"`
	AllowedMethods   []string      `yaml:"allowed_methods"`
	AllowedHeaders   []string      `yaml:"allowed_headers"`
	ExposedHeaders   []string      `yaml:"exposed_headers"`
	AllowCredentials bool          `yaml:"allow_credentials"`
	MaxAge           time.Duration `yaml:"max_age"`
	// PathOverrides applies a separate CORS policy to each URL path prefix.
	// The map key must start with /. Override Enabled fields are ignored;
	// presence of an entry activates it, while an empty AllowedOrigins list
	// deliberately emits no CORS headers for that prefix.
	PathOverrides map[string]CORSConfig `yaml:"path_overrides"`
}

// validate rejects path overrides that cannot be represented by the
// middleware. Nested overrides are rejected rather than silently discarded.
func (c CORSConfig) validate() error {
	for prefix, override := range c.PathOverrides {
		if !strings.HasPrefix(prefix, "/") {
			return fmt.Errorf("config: security.cors.path_overrides key %q must start with /", prefix)
		}
		if strings.HasPrefix(core.PathLogin, prefix) {
			return fmt.Errorf("config: security.cors.path_overrides key %q overlaps %s origin gate", prefix, core.PathLogin)
		}
		if len(override.PathOverrides) > 0 {
			return fmt.Errorf("config: security.cors.path_overrides[%q].path_overrides must not be nested", prefix)
		}
	}
	return nil
}

// policyWithoutOverrides maps one CORS policy's fields. Override entries use
// this helper so their own path_overrides map cannot be silently recursed.
func (c CORSConfig) policyWithoutOverrides() cors.Policy {
	return cors.Policy{
		AllowedOrigins:   c.AllowedOrigins,
		AllowedMethods:   c.AllowedMethods,
		AllowedHeaders:   c.AllowedHeaders,
		ExposedHeaders:   c.ExposedHeaders,
		AllowCredentials: c.AllowCredentials,
		MaxAge:           c.MaxAge,
	}
}

// ToPolicy builds the cors.Policy implied by the YAML block. Empty
// AllowedMethods / AllowedHeaders fall back to the cors package's defaults
// (GET/POST/PUT/DELETE/OPTIONS, Authorization/Content-Type). Path override
// entries are mapped one level deep using the same field semantics.
func (c CORSConfig) ToPolicy() cors.Policy {
	policy := c.policyWithoutOverrides()
	if len(c.PathOverrides) == 0 {
		return policy
	}
	policy.PathOverrides = make(map[string]cors.Policy, len(c.PathOverrides))
	for prefix, override := range c.PathOverrides {
		policy.PathOverrides[prefix] = override.policyWithoutOverrides()
	}
	return policy
}

// RARLimitsConfig bounds an RFC 9396 authorization_details payload's SHAPE
// before the server fully unmarshals it — an arbitrarily deep or huge JSON
// blob would otherwise cost unbounded CPU during parse, ahead of the
// existing client type-allowlist check (sso.ValidateAuthorizationDetails).
// Every field's zero value disables that specific check (unbounded) —
// byte-identical to a build without this section until an operator opts
// in. Composes with (does not replace) SecurityConfig.BodyLimit, which
// caps the WHOLE request body; this caps only the authorization_details
// value once it's been bound out of that body. Maps to
// sso.WithAuthorizationDetailsLimits.
//
// Lives here (not its own config_rar.go) because config/ is at its frozen
// per-directory file-count ceiling — see BreakGlassConfig's doc above.
type RARLimitsConfig struct {
	MaxBytes    int `yaml:"max_bytes"`
	MaxElements int `yaml:"max_elements"`
	MaxDepth    int `yaml:"max_depth"`
}

// RARCatalogCheckConfig enables PAR-time verification for first-party RFC
// 9396 resource types (http_api, grpc_api, graphql_api). When enabled, the
// server resolves those elements against a permission provider implementing
// permissions.ResourceProvider; a provider without that extension keeps the
// documented shape-only compatibility mode. Maps to sso.WithRARCatalogCheck.
type RARCatalogCheckConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ScopeLimitConfig caps the number of space-separated scopes accepted in a
// single request's `scope` parameter on /auth/login and /par. MaxCount <= 0
// (default) = unbounded — byte-identical to today. This is a token-COUNT
// cap, distinct from protocols/oauth's existing hardcoded MaxScopeLen BYTE
// cap. Maps to sso.WithMaxScopeCount.
type ScopeLimitConfig struct {
	MaxCount int `yaml:"max_count"`
}

// AdminConfig toggles the command admin control plane. When Enabled is true
// the sso-server mounts the admin gRPC services and AdminMiddleware. The
// command's generated gRPC-gateway REST proxy is mounted under
// /api/v1/admin/ only when APIRESTEnabled is true. Source-loaded configs
// default APIRESTEnabled to true when omitted; set it false to disable that
// generated gateway while retaining the separately wired SDK HTTP surfaces.
type AdminConfig struct {
	Enabled        bool `yaml:"enabled"`
	APIRESTEnabled bool `yaml:"api_rest_enabled"`
}

// AdminWriteQuotaConfig opts into a hard, fixed-window cap on the number of
// admin WRITE operations (POST/PUT/PATCH/DELETE under /api/v1/admin/) a
// given tenant or admin identity may perform per window — a QUOTA (a bounded
// budget that resets wholesale on a schedule), distinct from
// SecurityConfig.RateLimit's token-bucket rate. Wired via
// AdminMiddleware.SetWriteQuota (interfaces/admin), not an sso.Option — the
// admin middleware, like its existing SetRateLimit/SetAdminTokenStore
// knobs, is configured directly on the constructed *sso.AdminMiddleware.
// Disabled by default: Enabled=false leaves every request byte-identical to
// a build without this feature.
type AdminWriteQuotaConfig struct {
	Enabled bool          `yaml:"enabled"`
	Limit   int           `yaml:"limit"`
	Window  time.Duration `yaml:"window"`
	// KeyBy selects the quota dimension: "tenant" keys by the acting admin's
	// tenant (falling back to admin identity when the token carries none);
	// anything else (including the empty default) keys by admin identity.
	KeyBy string `yaml:"key_by"`
}

// AdminChangeApprovalConfig opts into the generic two-person change-approval
// workflow (platform/lifecycle/admingovernance): an admin PROPOSES an action_type +
// payload (POST /api/v1/admin/changes), a DIFFERENT admin APPROVES it
// (POST .../{id}/approve), and — when the deployment registered an Applier
// for that action_type — the approval immediately applies the change.
// Generalizes core.BreakGlassStore's propose/approve/self-approval-refusal
// shape beyond emergency-access grants. ActionTypes, when non-empty,
// restricts Propose to only the listed action_type values (empty = any
// action_type accepted). Disabled by default: no /api/v1/admin/changes
// routes are mounted.
type AdminChangeApprovalConfig struct {
	Enabled     bool     `yaml:"enabled"`
	ActionTypes []string `yaml:"action_types"`
}

// AdminDestructiveActionsConfig opts into a pre-check on admin mutations
// classified destructive (tenant deletion, client deletion, bulk token
// revocation, ...): the caller MUST send the X-Confirm: true header,
// mirroring the {confirm: true} convention the bulk-revoke-by-user and
// self-service account-erase endpoints already use, generalized to a
// transport-level header because this gate runs BEFORE any handler parses a
// body (and it must also cover the grpc-gateway-proxied admin services,
// which never see interfaces/admin's own JSON body binding). Rules is a
// configured (method, path-prefix) allow-list — see
// platform/lifecycle/admingovernance.DestructiveRule; Enabled=false (the default)
// leaves every mutation exactly as it behaves today. Wired via
// AdminMiddleware.SetDestructiveActions.
type AdminDestructiveActionsConfig struct {
	Enabled bool                         `yaml:"enabled"`
	Rules   []AdminDestructiveActionRule `yaml:"rules"`
}

// AdminDestructiveActionRule is one entry of AdminDestructiveActionsConfig.Rules.
type AdminDestructiveActionRule struct {
	Method     string `yaml:"method"`
	PathPrefix string `yaml:"path_prefix"`
	Action     string `yaml:"action"`
}

// AdminIPAllowlistConfig opts into restricting /api/v1/admin/* access to
// configured IP ranges and/or geographic regions. Composes with the
// EXISTING geo enrichment SPI (platform/geo.Provider) rather than
// reimplementing IP-to-geo resolution: CIDRs are checked directly against
// the request IP (via the SAME geo.DefaultIPExtractor the enrichment
// middleware uses); Countries are checked against whatever geo.Provider the
// deployment already wires. Both lists empty (the default) disables the
// check; when both are configured a request must satisfy BOTH dimensions
// (see platform/lifecycle/admingovernance.Allowed). Wired via
// AdminMiddleware.SetIPAllowlist.
type AdminIPAllowlistConfig struct {
	Enabled   bool     `yaml:"enabled"`
	CIDRs     []string `yaml:"cidrs"`
	Countries []string `yaml:"countries"`
}

// BreakGlassConfig opts into emergency ("break-glass") admin sessions
// (core.BreakGlassStore + the POST/GET/DELETE/approve /api/v1/admin/break-glass
// lifecycle endpoints, sso.WithBreakGlassStore). Disabled by default: without
// it no break-glass surface exists.
//
// SweeperInterval drives the ACTIVE expiry sweeper (Server.RunBreakGlassSweeper)
// — the loop that destroys a grant's derived impersonation sessions the moment
// it expires. <=0 defaults to 1m at wiring time. The grant TTL default + cap
// and the per-request require_approval flag are SDK-side (core.DefaultBreakGlassTTL
// / core.MaxBreakGlassTTL / the create-request body), not server config, so they
// are intentionally not knobs here.
//
// Lives beside AdminConfig because config/ is at its frozen per-directory
// file-count ceiling (directory_fanout_test.go) — new sections fold into a
// topically-related file rather than a new config_*.go.
type BreakGlassConfig struct {
	Enabled         bool          `yaml:"enabled"`
	SweeperInterval time.Duration `yaml:"sweeper_interval"`
}

// UserLifecycleConfig opts into the domains/userlifecycle admin
// state-machine surface (sso.WithUserLifecycle): mounts GET/POST
// /api/v1/admin/users/:id/lifecycle so operators can inspect and drive an
// account through INVITED -> ACTIVE -> {SUSPENDED, INACTIVE} -> ARCHIVED ->
// PURGED. When enabled it also gates end-user authentication and token use:
// only ACTIVE may proceed, while lifecycle read errors fail closed. Disabled
// by default: Enabled=false wires nothing — byte-identical to a build without
// the feature.
//
// AutoDeprovision is a SEPARATE, independently-gated opt-in (mirrors
// sso.WithUserAutoDeprovision itself requiring sso.WithUserLifecycle — the
// sweep persists through the SAME store): Enabled here alone only mounts
// the admin read/write surface; the background dormancy sweep additionally
// needs AutoDeprovision.Enabled (plus DormantAfter/SweepInterval > 0).
//
// Lives beside AdminConfig/BreakGlassConfig because config/ is at its
// frozen per-directory file-count ceiling (directory_fanout_test.go) — new
// sections fold into a topically-related file rather than a new
// config_*.go.
type UserLifecycleConfig struct {
	Enabled         bool                      `yaml:"enabled"`
	Backend         string                    `yaml:"backend"` // ""|memory|postgres
	AutoDeprovision UserAutoDeprovisionConfig `yaml:"auto_deprovision"`
}

// UserAutoDeprovisionConfig opts into the background dormancy sweep
// (userlifecycle.SweepOnce, driven by Server.RunUserAutoDeprovision) that
// advances a stale ACTIVE account to INACTIVE past DormantAfter, and — when
// ArchiveAfter > 0 — an INACTIVE account to ARCHIVED past
// DormantAfter+ArchiveAfter. Activity is derived from the wired
// core.SessionManager (userlifecycle.SessionLastActive — no other activity
// backend exists); a user with no live session reads as "unknown" and is
// never touched (the package's own fail-safe default).
//
// Requires UserLifecycleConfig.Enabled; DormantAfter and SweepInterval must
// both be > 0 or the sweep stays off — matching
// userlifecycle.DeprovisionConfig.Enabled()'s own zero-value-is-off
// contract. Enabled with UserLifecycleConfig.Enabled=false fails loud at
// boot rather than silently building a sweep with nowhere to persist its
// transitions.
type UserAutoDeprovisionConfig struct {
	Enabled bool `yaml:"enabled"`
	// DormantAfter is how long an ACTIVE account may be idle (no activity
	// per the LastActiveSource) before the sweep moves it to INACTIVE.
	// <=0 disables the sweep entirely.
	DormantAfter time.Duration `yaml:"dormant_after"`
	// ArchiveAfter is the ADDITIONAL idle time beyond DormantAfter before an
	// INACTIVE account is advanced to ARCHIVED (measured from last
	// activity). <=0 leaves INACTIVE accounts untouched indefinitely.
	ArchiveAfter time.Duration `yaml:"archive_after"`
	// MaxPerSweep caps the number of transitions a single sweep applies (a
	// deprovisioning-storm guard). 0 = unlimited.
	MaxPerSweep int `yaml:"max_per_sweep"`
	// SweepInterval is the Server.RunUserAutoDeprovision background-loop
	// cadence. <=0 disables the loop even when DormantAfter is set.
	SweepInterval time.Duration `yaml:"sweep_interval"`
}

// BootstrapConfig configures the first-run init Runner. StatePath is the
// JSON file the file-backed Tracker writes to (defaults to "bootstrap.json"
// when empty). Set Disabled=true to skip the runner entirely (useful in
// tests or when an external orchestrator owns init).
type BootstrapConfig struct {
	Disabled       bool   `yaml:"disabled"`
	StatePath      string `yaml:"state_path"`
	AdminUserID    string `yaml:"admin_user_id"`
	AdminClientID  string `yaml:"admin_client_id"`
	AdminRoleCode  string `yaml:"admin_role_code"`
	AdminClientApp string `yaml:"admin_client_app"`

	// AdminPasswordFile is an optional path where the generated
	// admin password is written (mode 0600) on first boot in
	// ADDITION to the stdout banner. Containerized deployments
	// where stdout is async-shipped to a log sink frequently lose
	// the boot banner; pointing at a tmpfs / secret-volume path
	// guarantees retrievability. The file is written once per
	// generation; if the bootstrap step doesn't re-run (already
	// at high-water), the file is NOT touched.
	AdminPasswordFile string              `yaml:"admin_password_file"`
	Lock              BootstrapLockConfig `yaml:"lock"`
}

// BootstrapLockConfig configures the distributed lock the Runner takes
// before applying steps. Backend selects which implementation:
//
//   - "" or "noop"  → no coordination (single-replica default)
//   - "file"        → flock(2) on Lock.File.Path; single-host multi-process
//   - "etcd"        → etcd lease + Txn; multi-replica HA
//
// Key namespaces the lock; defaults to "/sso/bootstrap/<namespace>".
