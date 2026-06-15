package config

import "time"

type MFAPushConfig struct {
	Backend       string                `yaml:"backend"`       // memory | sqlite
	Transport     string                `yaml:"transport"`     // log | webhook
	PollInterval  time.Duration         `yaml:"poll_interval"` // 0 → SDK default
	MaxWait       time.Duration         `yaml:"max_wait"`      // 0 → SDK default
	SQLite        MFAPushSQLiteConfig   `yaml:"sqlite"`
	PruneInterval time.Duration         `yaml:"prune_interval"` // background PruneExpired cadence (sqlite-only); 0 disables
	Webhook       MFAPushWebhookConfig  `yaml:"webhook"`        // used when transport=webhook
	Callback      MFAPushCallbackConfig `yaml:"callback"`
	// ChannelNotify opts into the built-in channel-based Verify wakeup
	// ([defaultimpl.WithPushChannelNotify]). When true and the
	// reference callback is mounted, an approve/deny callback wakes the
	// blocked /auth/mfa Verify in milliseconds instead of after a
	// poll_interval tick. Pure latency optimization — the approval
	// store stays authoritative, so correctness is unchanged if the
	// signal is missed. Single-process hint: a callback handled on a
	// different replica than the parked Verify still falls back to
	// polling.
	ChannelNotify bool `yaml:"channel_notify"`
}

// MFAPushWebhookConfig wires the HTTP webhook PushTransport. The
// SSO server POSTs JSON {approval_id, subject_id, metadata} to the
// configured URL; the operator's gateway translates to FCM/APNs/
// SMS-proxy/etc and later calls /push/approval/:id/:decision (or
// SetStatus directly) to resolve the approval.
//
// URL is required when transport=webhook. BearerToken sets
// Authorization: Bearer; Headers sets arbitrary additional headers;
// Timeout bounds the per-attempt HTTP call. RetryMaxAttempts /
// RetryInitialBackoff / RetryMaxBackoff tune exponential backoff
// (defaults: 3 / 250ms / 5s).
type MFAPushWebhookConfig struct {
	URL                 string            `yaml:"url"`
	BearerToken         string            `yaml:"bearer_token"`
	Headers             map[string]string `yaml:"headers"`
	Timeout             time.Duration     `yaml:"timeout"`
	RetryMaxAttempts    int               `yaml:"retry_max_attempts"`
	RetryInitialBackoff time.Duration     `yaml:"retry_initial_backoff"`
	RetryMaxBackoff     time.Duration     `yaml:"retry_max_backoff"`
}

type MFAPushSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// MFAPushCallbackConfig opts into the reference HTTP callback the
// SSO server mounts at POST /push/approval/{id}/{decision} where
// decision is approve|deny. Operators who already proxy through
// their own gateway can leave Enabled=false and call
// PushApprovalStore.SetStatus from their own handler.
//
// Authentication: BearerToken + AllowedCIDRs. Wire one or both —
// a token alone is fine for trusted internal networks; an IP
// allowlist alone for VPC-only deployments. Disabled (empty
// both) → handler accepts ALL requests; only safe behind an edge
// that enforces auth.
type MFAPushCallbackConfig struct {
	Enabled      bool     `yaml:"enabled"`
	BearerToken  string   `yaml:"bearer_token"`
	AllowedCIDRs []string `yaml:"allowed_cidrs"`
}

// MFAChallengeConfig selects the MFAChallengeStore backend + per-
// challenge TTL. memory keeps single-replica deploys simple; sqlite
// shares challenges across replicas so a challenge minted on replica
// A is consumable on replica B (which load balancers without session
// affinity always demand).
//
// TTL defaults to [spi.DefaultMFAChallengeTTL] (5 minutes) when
// unset / <= 0.
type MFAChallengeConfig struct {
	Backend string                   `yaml:"backend"`
	TTL     time.Duration            `yaml:"ttl"`
	SQLite  MFAChallengeSQLiteConfig `yaml:"sqlite"`
}

type MFAChallengeSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// RegistryConfig configures the service registry (etcd or in-process
// memory). cmd self-registers under name "sso" so peers + dashboards
// discovering the SSO cluster see every replica.
//
//   - Backend: "memory" (default, single-replica) or "etcd"
//     (cluster-shared via TTL lease).
//   - ServiceID: declarative override for the per-replica id; falls
//     back to "<issuer>-<short-hostname>" so multiple replicas on
//     the same etcd cluster don't collide on the same key.
//   - ServiceAddress / ServiceTags / ServiceTTL tune what every
//     replica advertises + how long its lease survives between
//     KeepAlives. The TTL only matters under etcd — memory ignores it
//     (process lifetime IS the registration lifetime).
//   - Etcd* settings mirror NetworkConfig + LockEtcdConfig.
