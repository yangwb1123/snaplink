package config

import "time"

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

// CORSConfig configures the CORS middleware. AllowedOrigins is the
// only required field; leaving it empty disables CORS even when
// Enabled=true (the middleware reduces to identity).
type CORSConfig struct {
	Enabled          bool          `yaml:"enabled"`
	AllowedOrigins   []string      `yaml:"allowed_origins"`
	AllowedMethods   []string      `yaml:"allowed_methods"`
	AllowedHeaders   []string      `yaml:"allowed_headers"`
	ExposedHeaders   []string      `yaml:"exposed_headers"`
	AllowCredentials bool          `yaml:"allow_credentials"`
	MaxAge           time.Duration `yaml:"max_age"`
}

// AdminConfig toggles the admin control plane. When Enabled is true the
// sso-server mounts the four admin gRPC services and the grpc-gateway
// REST proxy under /api/v1/admin/. APIRESTEnabled defaults to true when
// Enabled is true; set false to expose admin gRPC-only.
type AdminConfig struct {
	Enabled        bool `yaml:"enabled"`
	APIRESTEnabled bool `yaml:"api_rest_enabled"`
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
