package config

import "time"

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
