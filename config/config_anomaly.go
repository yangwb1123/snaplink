package config

import "time"

type AnomalyConfig struct {
	Enabled bool `yaml:"enabled"`

	// IPSalt is hex-encoded bytes that salt the IP + UA hash
	// schemes. Deployment-stable; rotating breaks history
	// continuity. Recommended: 32 hex chars (16 random bytes).
	IPSalt string `yaml:"ip_salt"`

	// RecentLogin selects backend for the per-subject login
	// history store consumed by impossible_travel +
	// new_device + new_country detectors.
	RecentLogin AnomalyStoreConfig `yaml:"recent_login"`

	// IPFailure selects backend for the IP-keyed failure
	// counter consumed by brute_force_shadow.
	IPFailure AnomalyStoreConfig `yaml:"ip_failure"`

	// Detectors enables/configures each reference detector.
	Detectors AnomalyDetectorsConfig `yaml:"detectors"`

	// Runner tunes the AsyncAnomalyRunner worker pool.
	Runner AnomalyRunnerConfig `yaml:"runner"`

	// Retention wires the background prune loop against
	// RecentLogin + IPFailure stores. Mirrors the audit /
	// snapshot / push_approvals retention pattern.
	Retention AnomalyRetentionConfig `yaml:"retention"`
}

// AnomalyStoreConfig is the standard backend selector — memory
// for single-replica + tests, sqlite for cluster-shared state.
type AnomalyStoreConfig struct {
	Backend string                   `yaml:"backend"` // memory | sqlite
	SQLite  AnomalyStoreSQLiteConfig `yaml:"sqlite"`
}

type AnomalyStoreSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// AnomalyDetectorsConfig enables/tunes each reference detector.
// All disabled by default — operators opt in per-detector after
// reviewing the threshold trade-offs.
type AnomalyDetectorsConfig struct {
	ImpossibleTravel ImpossibleTravelDetectorConfig `yaml:"impossible_travel"`
	Velocity         VelocityDetectorConfig         `yaml:"velocity"`
	NewDevice        BaselineDetectorConfig         `yaml:"new_device"`
	NewCountry       BaselineDetectorConfig         `yaml:"new_country"`
	BruteForceShadow BruteForceShadowDetectorConfig `yaml:"brute_force_shadow"`
}

type ImpossibleTravelDetectorConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxSpeedKmh   float64       `yaml:"max_speed_kmh"`  // 0 → SDK default 800
	HistoryWindow time.Duration `yaml:"history_window"` // 0 → SDK default 24h
}

type VelocityDetectorConfig struct {
	Enabled     bool `yaml:"enabled"`
	HourlyLimit int  `yaml:"hourly_limit"` // 0 disables hourly check
	DailyLimit  int  `yaml:"daily_limit"`  // 0 disables daily check
}

type BaselineDetectorConfig struct {
	Enabled              bool          `yaml:"enabled"`
	BaselineWindow       time.Duration `yaml:"baseline_window"`        // 0 → SDK default
	BootstrapGracePeriod time.Duration `yaml:"bootstrap_grace_period"` // 0 → SDK default
}

type BruteForceShadowDetectorConfig struct {
	Enabled              bool          `yaml:"enabled"`
	Window               time.Duration `yaml:"window"`                 // 0 → SDK default 1h
	FailureLimit         int           `yaml:"failure_limit"`          // 0 disables
	DistinctSubjectLimit int           `yaml:"distinct_subject_limit"` // 0 disables
}

type AnomalyRunnerConfig struct {
	QueueSize      int           `yaml:"queue_size"`      // 0 → SDK default 1024
	Workers        int           `yaml:"workers"`         // 0 → SDK default 4
	DropPolicy     string        `yaml:"drop_policy"`     // drop_newest | block; default drop_newest
	InspectTimeout time.Duration `yaml:"inspect_timeout"` // 0 → SDK default 5s per detector
}

type AnomalyRetentionConfig struct {
	Enabled        bool          `yaml:"enabled"`
	RecentLoginAge time.Duration `yaml:"recent_login_age"` // 0 → 90d default; prune entries older than this
	IPFailureAge   time.Duration `yaml:"ip_failure_age"`   // 0 → 2h default; aggressive — counters are short-window
	Interval       time.Duration `yaml:"interval"`         // 0 → 1h default; loop cadence
}

// RiskConfig wires the reference rule-based [spi.RiskScorer] into
// cmd. Operators with non-trivial risk needs (impossible-travel,
// device fingerprint deltas, ML scoring) fork cmd and pass their
// own [spi.RiskScorer] via WithRiskScorer — this config covers the
// 80% case of declarative deny-by-IP / deny-by-country /
// allow-only-from-these.
//
// Evaluation is first-match-wins. The deny lists short-circuit
// before the allow lists, so a CIDR in both lists always denies.
// CountryAllowList rule fires only when geo enrichment populated
// req.Geo.CountryCode; DenyOnGeoMissing flips that to "no geo =
// deny" for deployments where geo is a hard requirement.
type RiskConfig struct {
	Enabled          bool     `yaml:"enabled"`
	IPDenyList       []string `yaml:"ip_deny_list"`
	IPAllowList      []string `yaml:"ip_allow_list"`
	CountryDenyList  []string `yaml:"country_deny_list"`
	CountryAllowList []string `yaml:"country_allow_list"`
	DenyOnGeoMissing bool     `yaml:"deny_on_geo_missing"`
}

// MFAConfig wires the step-up MFA orchestration that gates risk-
// flagged logins through a second factor. When [RiskConfig] (or any
// custom [spi.RiskScorer] supplied via the SDK) returns
// DecisionRequireMFA, /auth/login responds with mfa_required +
// challenge_id; the client posts the second factor to /auth/mfa
// and on success the server replays the standard token-mint response
// — the caller can't tell an MFA-gated login from a non-gated one.
//
// Without Provider + Challenge.Backend both wired, RequireMFA decays
// to Allow (back-compat: scorers may ship the decision ahead of the
// operator wiring the orchestration). Enabled=false short-circuits
// to the same fallthrough so flipping the flag is the only switch
// operators need to disable MFA cluster-wide.
//
// Provider.Kind selects the factor implementation. "totp" reuses
// the same TOTPAuthenticator + secret store the primary
// /auth/login?provider=totp flow uses — one enrollment, two roles
// (requires authenticators.totp.enabled). Custom factors (WebAuthn
// step-up, push notification, hardware FIDO2) implement
// [spi.MFAProvider] directly and bypass this YAML knob.
type MFAConfig struct {
	Enabled   bool               `yaml:"enabled"`
	Provider  MFAProviderConfig  `yaml:"provider"`
	Challenge MFAChallengeConfig `yaml:"challenge"`
}

// MFAProviderConfig selects the step-up factor implementation.
// "totp", "webauthn", and "push" ship as YAML-toggleable kinds;
// richer providers (IdP step-up, hardware OTP) ship in the SDK
// and embedders wire them via [sso.WithMFAProvider] directly.
//
// kind=multi composes several leaf kinds via the SDK's
// [defaultimpl.MultiMFAProvider] — operators wanting concurrent
// TOTP + WebAuthn factors set Kind="multi" + Kinds=[totp, webauthn]
// so users with a registered authenticator get the WebAuthn flow
// while users without one fall back to TOTP. Kinds dedup at
// construction; nested multi is rejected (no recursion).
//
// kind=push activates the reference [defaultimpl.PushMFAProvider]
// shipped with this binary — Begin records a PENDING approval and
// invokes the configured transport (today: log-only stub; operators
// fork cmd to drop in FCM/APNs/webhook). Verify polls the approval
// store until the user's device callback resolves the entry. See
// MFAPushConfig + cmd buildPushMFAProvider for the wiring.
type MFAProviderConfig struct {
	Kind  string        `yaml:"kind"`
	Kinds []string      `yaml:"kinds"` // used when Kind=multi
	Push  MFAPushConfig `yaml:"push"`  // used when Kind=push (or in Kinds)
}

// MFAPushConfig wires the push-notification MFA factor. Backend
// selects the PushApprovalStore implementation: memory for single-
// replica dev/demo; sqlite for cluster-shared state (Begin on
// replica A → callback on replica B → Verify on replica C all
// see the same approval row).
//
// Transport selects how the approval id reaches the user's device.
// "log" is the default reference transport — it writes the
// approval id + subject to the server's structured log, matching
// the SMS/email "stub" pattern. Production deployments fork cmd to
// drop in FCM/APNs/webhook; the SDK's PushTransport interface is
// stable.
//
// PollInterval and MaxWait tune the Verify polling cadence + the
// total wait the server holds /auth/mfa open. MaxWait MUST be <=
// the parent MFAChallengeTTL; otherwise the challenge expires
// mid-Verify and operators see ErrMFAChallengeNotFound instead of
// ErrPushApprovalTimeout. cmd validates this at boot.
//
// The user-device callback that resolves a PushApproval (PENDING
