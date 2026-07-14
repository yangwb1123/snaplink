package config

import (
	"time"

	"github.com/snaplink/sso/domains/conditionalaccess"
	"github.com/snaplink/sso/domains/threataction"
	"github.com/snaplink/sso/domains/tokenpolicy"
)

// TTL bounds how long the lease lives between heartbeats; the Runner
// renews on TTL/3. Blocking switches contention behavior between
// fail-fast (default) and retry-with-Backoff.
type BootstrapLockConfig struct {
	Backend  string         `yaml:"backend"`
	Key      string         `yaml:"key"`
	TTL      time.Duration  `yaml:"ttl"`
	Blocking bool           `yaml:"blocking"`
	Backoff  time.Duration  `yaml:"backoff"`
	File     LockFileConfig `yaml:"file"`
	Etcd     LockEtcdConfig `yaml:"etcd"`
}

// LockFileConfig configures the file (flock) lock backend.
type LockFileConfig struct {
	Dir string `yaml:"dir"` // directory the lock file lives in; "" = cwd
}

// LockEtcdConfig configures the etcd lock backend.
type LockEtcdConfig struct {
	Endpoints   []string      `yaml:"endpoints"`
	DialTimeout time.Duration `yaml:"dial_timeout"`
	Username    string        `yaml:"username"`
	Password    string        `yaml:"password"`
}

// SnapshotConfig configures the snapshot subsystem (Phase D-2). When
// Enabled is false the admin SnapshotService is not mounted and the
// bootstrap restore_from_snapshot step no-ops. Storage selects where
// envelopes live (file/inline); Encryption selects how they're sealed
// (none/passphrase). RestoreFrom is a snapshot URI consumed by the
// bootstrap step on first boot — overridden by --bootstrap-restore-from.
type SnapshotConfig struct {
	Enabled     bool                     `yaml:"enabled"`
	Storage     SnapshotStorageConfig    `yaml:"storage"`
	Encryption  SnapshotEncryptionConfig `yaml:"encryption"`
	RestoreFrom string                   `yaml:"restore_from"`
	Retention   SnapshotRetentionConfig  `yaml:"retention"`

	// RedactSecrets opts into stripping credential-bearing client
	// fields (Secret, RFC 7592 RegistrationAccessToken) from EVERY
	// export via snapshot.SnapshotRedactSecrets. Default false =
	// byte-identical export (backward-compatible). This is a
	// defense-in-depth knob for the SAFE-SHARING / inspection use case:
	// a redacted export can be forwarded for review without leaking live
	// client credentials. It is NOT a restore path — a redacted
	// snapshot's clients cannot authenticate after restore. Encryption
	// (snapshot.encryption.backend) remains the mitigation for
	// RESTORABLE backups; do not enable RedactSecrets for those.
	RedactSecrets bool `yaml:"redact_secrets"`
}

// SnapshotRetentionConfig opts into background pruning of old
// snapshot envelopes via [snapshot.PruneOldest]. Operators take
// snapshots on a schedule (admin SnapshotService or external
// cron); without retention the storage dir grows monotonically.
//
// Keep <= 0 with Enabled=true is rejected at boot (would wipe
// every snapshot at the first tick — operators wanting that
// disable retention and run a wipe manually).
//
// Interval defaults to 6h when unset/<=0. Operators taking
// hourly snapshots typically set Interval=1h so the prune runs
// shortly after each new snapshot lands.
type SnapshotRetentionConfig struct {
	Enabled  bool          `yaml:"enabled"`
	Keep     int           `yaml:"keep"`
	Interval time.Duration `yaml:"interval"`
}

// SnapshotStorageConfig picks where Pipeline persists envelopes. Backend
// is "file" (default) or "inline" (in-memory; useful for tests).
type SnapshotStorageConfig struct {
	Backend string             `yaml:"backend"`
	File    SnapshotFileConfig `yaml:"file"`
}

// SnapshotFileConfig configures the file-backed Storage. Dir defaults to
// "./snapshots" when empty.
type SnapshotFileConfig struct {
	Dir string `yaml:"dir"`
}

// SnapshotEncryptionConfig picks the Sealer.
//
// Backend choices:
//   - "none" (default) — envelopes are plaintext JSON.
//   - "passphrase" — argon2id + XChaCha20-Poly1305; supply
//     Passphrase (literal, fine for tests) or PassphraseFile.
//   - "aes-gcm" — direct 32-byte AES-256 key + AES-GCM AEAD;
//     supply Key (hex/base64; not recommended) or KeyFile (raw 32
//     bytes). Aimed at operators with a KMS that hands them DEKs
//     (skip the human-passphrase + argon2id derivation step).
type SnapshotEncryptionConfig struct {
	Backend        string `yaml:"backend"`
	Passphrase     string `yaml:"passphrase"`
	PassphraseFile string `yaml:"passphrase_file"`
	Key            string `yaml:"key"`      // hex- or base64-encoded 32 bytes
	KeyFile        string `yaml:"key_file"` // file containing raw 32-byte key OR base64/hex
}

// ReleasesConfig configures the admin app version pin / rollback
// subsystem (Phase D-3). When Enabled is false the admin
// ReleaseService is not mounted. Store selects the persistence
// backend; Pinner selects the deploy mechanism. Probe (optional)
// gates auto-rollback on Pin failure; SnapshotIntegration (boolean)
// turns on ConfigSnapshot-aware Rollback when the snapshot subsystem
// is also enabled.
type ReleasesConfig struct {
	Enabled             bool                `yaml:"enabled"`
	Store               ReleaseStoreConfig  `yaml:"store"`
	Pinner              ReleasePinnerConfig `yaml:"pinner"`
	Probe               ReleaseProbeConfig  `yaml:"probe"`
	SnapshotIntegration bool                `yaml:"snapshot_integration"`
}

// ReleaseStoreConfig picks where Releases are persisted. Backend is
// "file" (default; one <id>.json per release + a CURRENT marker) or
// "memory" (lost on restart; for tests/demos).
type ReleaseStoreConfig struct {
	Backend string                 `yaml:"backend"`
	File    ReleaseStoreFileConfig `yaml:"file"`
}

// ReleaseStoreFileConfig configures the file-backed Store. Dir
// defaults to "./releases" when empty.
type ReleaseStoreFileConfig struct {
	Dir string `yaml:"dir"`
}

// ReleasePinnerConfig picks the Pinner. Backend choices:
//   - "noop"   — records the call, no-op (default; tests / dry-runs)
//   - "static" — frontend bundle on-disk symlink swap
//   - "docker" — docker compose pull + up -d in BundleDir
type ReleasePinnerConfig struct {
	Backend string                    `yaml:"backend"`
	Static  ReleasePinnerStaticConfig `yaml:"static"`
	Docker  ReleasePinnerDockerConfig `yaml:"docker"`
}

// ReleasePinnerStaticConfig configures the static Pinner. BundleDir
// is the directory containing per-release subdirs + the "current"
// symlink the Pinner swaps.
type ReleasePinnerStaticConfig struct {
	BundleDir string `yaml:"bundle_dir"`
}

// ReleasePinnerDockerConfig configures the docker compose Pinner.
// BundleDir is the working directory containing the operator's
// compose file (the Pinner runs `docker compose pull && up -d` in
// it after rewriting a managed .env). Cmd lets operators swap to
// podman or a custom binary path; defaults to "docker".
type ReleasePinnerDockerConfig struct {
	BundleDir string `yaml:"bundle_dir"`
	Cmd       string `yaml:"cmd"`
}

// ReleaseProbeConfig configures the post-Pin health probe. When
// Backend is empty no probe runs and forward Pin always succeeds
// even if the new release is unhealthy. Backend "http" GETs URL
// and treats 2xx as healthy. Polls / Backoff control the retry loop
// (defaults: 6 attempts × 5s).
type ReleaseProbeConfig struct {
	Backend string                 `yaml:"backend"` // "" | "http"
	HTTP    ReleaseProbeHTTPConfig `yaml:"http"`
	Polls   int                    `yaml:"polls"`
	Backoff time.Duration          `yaml:"backoff"`
}

// BackupConfig configures the admin online-backup endpoint
// (POST /api/v1/admin/backup). Dir is where VACUUM INTO snapshots land
// (empty = OS temp dir); Keep retains only the newest N backup files per
// source after each run (0 = keep all).
type BackupConfig struct {
	Dir  string `yaml:"dir"`
	Keep int    `yaml:"keep"`
}

// DRConfig configures the disaster-recovery framework foundations
// (docs/dr-framework.md): a background loop that periodically exports the
// SAME sealed snapshot the manual/retention snapshot pipeline above
// produces and copies it to an off-node DR replica mount, plus the RPO/RTO
// targets DRReadiness measures the live replica against.
//
// Disabled by default (Enabled: false) — a zero-value DRConfig wires
// nothing, matching every other opt-in subsystem in this file. Requires
// snapshot.enabled=true: DR replicates the configured snapshot pipeline's
// export, it does not stand up a second one.
type DRConfig struct {
	Enabled bool `yaml:"enabled"`

	// TargetDir is the DR replica mount the replicator copies verified
	// snapshot envelopes into. Required when Enabled — an operator who
	// forgets it fails loud at boot rather than silently writing nowhere.
	TargetDir string `yaml:"target_dir"`

	// Interval between replication cycles. <=0 defaults to
	// dr.DefaultReplicationInterval (15m) at wiring time. The first cycle
	// always fires immediately regardless of Interval (see
	// SnapshotReplicator.Run), so a fresh boot isn't "not ready" for a
	// full interval with no operational reason.
	Interval time.Duration `yaml:"interval"`

	// Keep bounds the retained replica count in TargetDir; older replicas
	// are pruned after each successful cycle. <=0 defaults to
	// dr.DefaultReplicationKeep (7).
	Keep int `yaml:"keep"`

	// RPOTarget is the maximum acceptable staleness of the last verified
	// replica; DRReadiness compares the live replication lag against it.
	// <=0 disables the age comparison — Ready reports true as soon as any
	// replica exists (no RPO commitment configured to violate).
	RPOTarget time.Duration `yaml:"rpo_target"`

	// RTOTarget is the maximum acceptable measured recovery duration.
	// Surfaced alongside the RecoveryTimeTracker history on the admin
	// status endpoint for operator comparison; it does not gate anything
	// live (RTO is only known after a drill actually runs).
	RTOTarget time.Duration `yaml:"rto_target"`

	// RTOHistory bounds the retained measured-RTO record count kept for
	// the admin status endpoint. <=0 defaults to dr.DefaultRTOHistory (32).
	RTOHistory int `yaml:"rto_history"`

	// GateReadiness wires the DR readiness verdict into this replica's
	// /readyz probe. Default false: DR status stays report-only (admin
	// status endpoint + Prometheus gauges) and never affects the
	// platform's readiness signal on its own — a stale/missing DR replica
	// is an operator page, not a reason to pull auth traffic out of
	// rotation. Set true only when an operator has decided DR staleness
	// SHOULD take this replica out of the Kubernetes/LB pool.
	GateReadiness bool `yaml:"gate_readiness"`
}

// RotationConfig opts into the unified credential-rotation framework
// (platform/lifecycle/rotation): a background Scheduler rotates each registered
// credential class on Interval with an Overlap verify-window, and the read-only
// governance inventory is served at GET /api/v1/admin/credentials
// (sso.WithCredentialRotation — NEVER exposes secret material).
//
// The only CredentialRotator the SDK currently ships is the webhook-HMAC secret
// rotator (securityverify.WebhookSecretRotator); cmd seeds it from
// audit.webhook.signing_secret (empty ⇒ a fresh random secret). Disabled by
// default: a zero-value RotationConfig wires nothing, matching every other
// opt-in subsystem here.
//
// Lives beside the other lifecycle subsystems (snapshot/DR/releases) in this
// file because config/ is at its frozen per-directory file-count ceiling
// (directory_fanout_test.go) — new sections fold into a topically-related file.
type RotationConfig struct {
	Enabled bool `yaml:"enabled"`

	// Interval is the per-class rotation cadence. Required (> 0) when Enabled —
	// a rotator with no interval would never fire, so cmd fails loud at boot.
	Interval time.Duration `yaml:"interval"`

	// Overlap is the window a demoted secret stays verify-only after a rotation,
	// so in-flight deliveries signed pre-rotation still authenticate. <=0 drops
	// the previous secret immediately (no overlap).
	Overlap time.Duration `yaml:"overlap"`

	// Tick is the scheduler's due-check polling resolution (how late a due
	// rotation can fire), NOT the cadence. <=0 uses rotation.DefaultSchedulerTick.
	Tick time.Duration `yaml:"tick"`

	// RetryBase / RetryMax bound the failure-retry backoff (base doubled per
	// consecutive failure, capped at max) while the old credential keeps
	// serving. <=0 uses the rotation package defaults.
	RetryBase time.Duration `yaml:"retry_base"`
	RetryMax  time.Duration `yaml:"retry_max"`
}

// TokenPolicyConfig opts into the token-policy governance engine
// (domains/tokenpolicy, sso.WithTokenPolicy): rules clamp access-token TTLs
// downward (max_ttl) and deny dangerous scope combinations, and the read-only
// governance view is served at GET /api/v1/admin/token-policies (NEVER exposes
// secret material). Disabled by default: an absent section (no File, no inline
// Policies) wires nothing, byte-identical to a build without the feature. A
// store lookup error at request time FAILS OPEN (issue the token) per §3.
//
// Rules come from EITHER an external bundle (File — a standalone document whose
// top-level token_policies: list is parsed via tokenpolicy.ParseYAML) OR the
// inline Policies list; setting both is a config error (ambiguous source).
//
// Lives beside the other governance/lifecycle subsystems (snapshot/DR/rotation)
// in this file because config/ is at its frozen per-directory file-count ceiling
// (directory_fanout_test.go) — new sections fold into a topically-related file.
type TokenPolicyConfig struct {
	// File is an optional path to a standalone token-policy bundle (top-level
	// token_policies: list). Mutually exclusive with Policies.
	File string `yaml:"file"`
	// Policies inlines the rule list directly in the server config (same schema
	// as a bundle's token_policies: entries).
	Policies []tokenpolicy.Policy `yaml:"policies"`
}

// AccessPolicyConfig opts into the zero-trust conditional-access (CAP) engine
// (domains/conditionalaccess, sso.WithConditionalAccess) and mounts the
// read-only governance view GET /api/v1/admin/access-policies. The engine is
// ALWAYS evaluable via Server.EvaluateConditionalAccess; it additionally
// becomes a live /auth/login Policy Enforcement Point only when Enforce is
// true. Disabled by default: an absent section (no File, no inline Policies)
// wires nothing, byte-identical to a build without the feature — and even a
// wired-but-Enforce:false section changes no live auth decision.
//
// Policies come from EITHER an external bundle (File — parsed via the strict
// conditionalaccess YAML loader, unknown keys rejected) OR the inline Policies
// list; setting both is a config error. DegradedTrust / DefaultDeny tune the
// engine's fail modes (a missing signal substitutes DegradedTrust; DefaultDeny
// flips the no-policy-matched verdict from allow to deny). A policy-store
// outage at /auth/login always fails OPEN regardless of DefaultDeny (AGENTS.md
// "Fail Modes") — DefaultDeny only governs the no-match-with-live-data case.
type AccessPolicyConfig struct {
	// File is an optional path to a standalone CAP policy bundle. Mutually
	// exclusive with Policies.
	File string `yaml:"file"`
	// Policies inlines the CAP rule list directly in the server config.
	Policies []conditionalaccess.Policy `yaml:"policies"`
	// DegradedTrust is the conservative trust value substituted when a signal is
	// missing; <=0 or >1 normalizes to the engine default (0.3).
	DegradedTrust float64 `yaml:"degraded_trust"`
	// DefaultDeny flips the no-match verdict to deny (a zero-trust posture) and
	// governs the fallback when the policy store is unavailable.
	DefaultDeny bool `yaml:"default_deny"`
	// Enforce activates the live /auth/login PEP (sso.ConditionalAccessConfig.Enforce):
	// false (the default) keeps the engine advisory-only, matching every prior
	// release's behavior. Operators should stage policies with Enforce:false +
	// dry_run policy entries, confirm the admin governance view looks right,
	// THEN flip this on.
	Enforce bool `yaml:"enforce"`
}

// DegradationConfig opts into the disaster-recovery degraded-service control
// plane (platform/lifecycle/degradation, sso.WithDegradationManager): an
// atomically-swappable service Mode the enforcement gate consults to shed
// non-essential request classes, plus the admin GET/POST /api/v1/admin/dr/mode
// read+toggle. Disabled by default: an absent section installs no gate and
// mounts no route (byte-identical); the manager's normal mode is itself a
// pass-through, so even an enabled-but-normal build has no request-path effect
// beyond one atomic load per request.
type DegradationConfig struct {
	Enabled bool `yaml:"enabled"`

	// InitialMode is the posture the server boots into: normal (default) |
	// read_only | auth_only | local_only | maintenance. An empty value is
	// normal; an unrecognized value fails loud at boot rather than silently
	// falling back to a request-shedding posture.
	InitialMode string `yaml:"initial_mode"`

	// AutoReadOnlyOnStoreLoss is an operator INTENT flag: the server should drop
	// to read_only when a backing datastore's health signal is lost. cmd has no
	// continuous storage-health push loop today (health is pull-based via
	// /readyz + the storage-health admin report), so there is no clean seam to
	// drive this automatically — the manager is EXPOSED via /api/v1/admin/dr/mode
	// for an operator or an external health loop to call SetMode(read_only). The
	// flag is honored as a boot-time log acknowledgement until such a loop exists.
	AutoReadOnlyOnStoreLoss bool `yaml:"auto_read_only_on_store_loss"`
}

// SessionTrustDecayConfig opts into the zero-trust session-trust-decay feature
// (sso.WithSessionTrustDecay, Direction 3 Phase 3): a trust score bound to each
// session at login decays over time, a background ContinuousVerificationAgent
// marks below-floor sessions for step-up, and the min-trust gate
// (Server.RequireSessionTrust) challenges high-risk operations.
//
// Disabled by default: an absent section (or interval<=0 / factor outside (0,1))
// wires nothing — no decay stamped at login, no agent, and the gate fail-opens
// (byte-identical to a build without the feature).
type SessionTrustDecayConfig struct {
	// Interval + Factor define the exponential decay curve (score *= Factor once
	// per Interval). Both must be set for the feature to enable.
	Interval time.Duration `yaml:"interval"`
	Factor   float64       `yaml:"factor"`

	// Floor is the agent's step-up threshold; a live session whose decayed score
	// drops below Floor is marked for step-up.
	Floor float64 `yaml:"floor"`

	// MinScore is the asymptotic lower bound the decayed score never falls below.
	MinScore float64 `yaml:"min_score"`

	// SweepInterval is the agent's polling cadence (<=0 ⇒ the package default).
	SweepInterval time.Duration `yaml:"sweep_interval"`

	// StepUpACRValues / StepUpMaxAge shape the RFC 9470 step-up challenge the gate
	// returns; when both are empty the gate demands a fresh re-authentication.
	StepUpACRValues []string `yaml:"step_up_acr_values"`
	StepUpMaxAge    int      `yaml:"step_up_max_age"`

	// InitialScore is the trust bound to a session at login (0 < v <= 1); out of
	// range defaults to 1.0.
	InitialScore float64 `yaml:"initial_score"`
}

// TokenAnomalyConfig opts into the wave-4 token-behavior anomaly detector
// (sso.WithTokenAnomalyDetector, Phase 3 token governance): a
// tokenanomaly.Detector decorates the token-usage recorder's store, captures
// per-thumbprint geo/velocity observations off the request path, and a periodic
// Server.RunTokenAnomalyDetection sweep turns them (plus the per-client rate
// buckets) into governance findings surfaced on GET
// /api/v1/admin/tokens/suspicious. DETECTION / REPORTING ONLY — a finding NEVER
// feeds an auth decision (same contract as anomaly.Runner).
//
// Enabling this ALSO wires the wave-1 token-usage recorder
// (sso.WithTokenUsageRecorder) as the detector's telemetry substrate: the
// detector is a tokenusage.Store decorator, so it only observes events the
// recorder drains off the request path. That co-wiring also mounts the
// token-usage / portfolio admin read APIs — the recorder is not independently
// configurable this wave (it exists only to feed the detector).
//
// Disabled by default: an absent section (enabled=false) wires neither the
// recorder nor the detector and starts no sweep — byte-identical to a build
// without the feature.
type TokenAnomalyConfig struct {
	// Enabled turns the whole subsystem on. SweepInterval MUST be > 0 when set
	// (a sweep with no cadence would never emit a finding).
	Enabled bool `yaml:"enabled"`
	// SweepInterval is the Server.RunTokenAnomalyDetection cadence — how often
	// the off-path Analyze pass converts observations into findings.
	SweepInterval time.Duration `yaml:"sweep_interval"`

	// MaxFindings bounds the in-memory finding store the sweep upserts into
	// (<=0 ⇒ the package default; it is a rolling operational view, not an
	// archive).
	MaxFindings int `yaml:"max_findings"`
	// QueueSize bounds the recorder's drop-on-full ingest queue (<=0 ⇒ default).
	QueueSize int `yaml:"queue_size"`
	// MaxBuckets bounds the token-usage aggregation store the detector decorates
	// (<=0 ⇒ default).
	MaxBuckets int `yaml:"max_buckets"`

	// Detector tuning — all optional (a zero value keeps the adaptive package
	// default, so operators rarely touch these). MaxThumbprints caps the
	// per-thumbprint observation table; Window is the analysis look-back;
	// VelocityGap is the impossible-travel interval; SpikeFactor / SpikeMinCount
	// shape the per-client rate-spike signal.
	MaxThumbprints int           `yaml:"max_thumbprints"`
	Window         time.Duration `yaml:"window"`
	VelocityGap    time.Duration `yaml:"velocity_gap"`
	SpikeFactor    float64       `yaml:"spike_factor"`
	SpikeMinCount  int64         `yaml:"spike_min_count"`
}

// ThreatActionConfig opts into the Active ITDR threat-executor bridge
// (domains/threataction, sso.WithThreatExecutor + sso.WithThreatPolicyStore):
// translates domains/anomaly + domains/tokenanomaly detection signals into
// response actions (session suspension, refresh-token family revocation, MFA
// step-up, admin notification) off the request path — the "smoke alarm" the
// anomaly subsystems raise finally gets a "call the fire department" step.
//
// Disabled by default: an absent/false section wires neither the composite
// executor nor the policy store into anomaly.Runner / tokenanomaly.Detector /
// the Server — byte-identical to a build without the feature. Even enabled
// with an empty Policies list, every threat resolves to DefaultAction (or the
// package's Noop default) until policies are added here or via the admin CRUD
// API (GET/PUT/DELETE /api/v1/admin/threat-policies, mounted once enabled).
type ThreatActionConfig struct {
	Enabled bool `yaml:"enabled"`

	// DefaultAction applies when no policy matches a threat. Empty = "noop"
	// (audit-only, no live response) — the package default.
	DefaultAction string `yaml:"default_action"`

	// Policies seeds the in-memory ThreatPolicyStore at boot; further policies
	// can be added/edited at runtime via the admin CRUD API.
	Policies []threataction.ThreatPolicy `yaml:"policies"`
}
