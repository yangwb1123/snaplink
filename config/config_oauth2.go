package config

import "time"

type OAuthConfig struct {
	// Backend selects the storage substrate for auth_code,
	// refresh_token, and device_code. "memory" (default) is in-
	// process; "sqlite" persists across restarts and shares state
	// across processes that point at the same file. PAR remains
	// memory-only (no SQLite backend yet). Each individually-enabled
	// store inherits this choice unless the store's own Backend
	// override is set.
	Backend      string                  `yaml:"backend"`
	SQLite       OAuthSQLiteConfig       `yaml:"sqlite"`
	AuthCode     OAuthStoreConfig        `yaml:"auth_code"`
	RefreshToken OAuthRefreshTokenConfig `yaml:"refresh_token"`
	DeviceCode   OAuthDeviceCodeConfig   `yaml:"device_code"`
	PAR          OAuthStoreConfig        `yaml:"par"`
	JAR          OAuthJARConfig          `yaml:"jar"`
	JARM         OAuthJARMConfig         `yaml:"jarm"`
	Compliance   OAuthComplianceConfig   `yaml:"compliance"`
}

// OAuthJARMConfig opts into JARM (JWT Secured Authorization Response
// Mode). When enabled, clients may request response_mode=jwt (and the
// query.jwt / fragment.jwt / form_post.jwt variants) and the
// authorization response is returned as a signed JWT, signed with the
// server's existing signing key (no separate key needed).
type OAuthJARMConfig struct {
	Enabled bool `yaml:"enabled"`
}

// OAuthComplianceConfig opts into a named OAuth/OIDC security profile.
// Today only the FAPI 2.0 Security Profile is supported. The underlying
// capabilities (PAR / JAR / DPoP or mTLS) must be independently wired
// for clients to actually pass enforcement — the profile only checks.
type OAuthComplianceConfig struct {
	// Profile selects the compliance profile: "" (off) | "fapi_2".
	Profile string `yaml:"profile"`
	// InspectionOnly, when a profile is set, runs audit-only:
	// violations emit fapi_compliance_violation events (+ the
	// sso_fapi_violations_total metric) but requests proceed — the
	// ramp-up path to collect the per-RP compliance-gap list before
	// flipping to enforce. Default false = enforce (reject violations).
	InspectionOnly bool `yaml:"inspection_only"`
}

// OAuthSQLiteConfig groups the SQLite-only knobs. DSN follows
// modernc.org/sqlite syntax — typical production form:
// `file:/var/lib/sso/sso.db?_journal=WAL&_pragma=busy_timeout(5000)`.
// Each store opens its own *sql.DB pool against the same file;
// SQLite's OS-level file lock coordinates writes.
type OAuthSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// OAuthJARConfig opts into RFC 9101 §5.2.2 — request_uri URL fetching.
// Without Enabled, the AS still accepts the inline `request` parameter
// (which doesn't need a fetcher); a JAR `request_uri` value would
// be rejected with invalid_request_uri.
//
// HTTPS-only, redirects disabled (avoids 302-to-internal-IP SSRF),
// body capped at MaxBytes (default 16KB). Timeout caps the entire
// fetch — should stay well below the user's patience tolerance.
//
// Each client still needs AllowedRequestURIs set on its YAML entry —
// the fetcher only delivers bodies; the AS-side allowlist gate runs
// before the fetcher is even consulted.
type OAuthJARConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Timeout  time.Duration `yaml:"timeout"`
	MaxBytes int64         `yaml:"max_bytes"`
}

// OAuthRefreshTokenConfig extends OAuthStoreConfig with the optional
// per-family rotation velocity cap. All base fields are inherited via
// embedding so existing YAML configs (enabled/ttl) continue to work.
type OAuthRefreshTokenConfig struct {
	OAuthStoreConfig `yaml:",inline"`
}

// OAuthStoreConfig is the shared shape for the simple TTL-only stores.
type OAuthStoreConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
	// MaxRotationsPerWindow and RotationWindow wire the opt-in per-family
	// rotation velocity cap on the RefreshTokenStore (§2 oracle-safe).
	// Only meaningful for the refresh_token store; ignored by other stores.
	MaxRotationsPerWindow int           `yaml:"max_rotations_per_window"`
	RotationWindow        time.Duration `yaml:"rotation_window"`
	// RotationGraceWindow wires the opt-in refresh-rotation grace window
	// (sso.WithRefreshRotationGrace): within this window a concurrent
	// double-submit of the just-rotated refresh token is idempotent (returns
	// the same successor) instead of tripping family-reuse detection — for
	// multi-tab SPAs / mobile cold-start races. 0 = disabled (strict single-use).
	// Only meaningful for the refresh_token store.
	RotationGraceWindow time.Duration `yaml:"rotation_grace_window"`
}

// OAuthDeviceCodeConfig adds device-code-specific tunables on top of
// the shared TTL: poll_interval (minimum allowed poll cadence, slower
// devices get back slow_down) and verification_base_url (what the
// server tells devices to display; empty derives from the request).
type OAuthDeviceCodeConfig struct {
	Enabled             bool          `yaml:"enabled"`
	TTL                 time.Duration `yaml:"ttl"`
	PollInterval        time.Duration `yaml:"poll_interval"`
	VerificationBaseURL string        `yaml:"verification_base_url"`
}

// MetricsConfig toggles Prometheus instrumentation. When Enabled,
// cmd/sso-server constructs a metrics.Metrics with its own Registry,
// wires sso.WithMetrics so request count / latency / login / token /
// risk counters all fire, and exposes /metrics for scraping.
//
// When an audit AsyncSink is also wired (audit.async.enabled), the
// matching metrics.AsyncSinkCollector is registered automatically so
// drop counters and queue depth land on the same registry.
