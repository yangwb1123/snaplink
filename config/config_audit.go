package config

import "time"

// AuditConfig configures security audit logging. When Enabled is false, no
// audit Recorder is wired and the API endpoints are not mounted.
//
// Backend selects the primary [audit.Sink] backend ("memory" or
// "sqlite"). MemorySink is a process-local ring buffer that drops
// events on restart; SQLite persists to a shared file so audit
// survives restarts and replicates across replicas pointed at the
// same DSN. Both still feed into the same MultiSink+Webhook
// composition when audit.webhook.enabled.
type AuditConfig struct {
	Enabled        bool                    `yaml:"enabled"`
	APIEnabled     bool                    `yaml:"api_enabled"`
	Backend        string                  `yaml:"backend"` // memory | sqlite
	Sqlite         AuditSqliteConfig       `yaml:"sqlite"`
	MemoryCapacity int                     `yaml:"memory_capacity"`
	Async          AuditAsyncConfig        `yaml:"async"`
	HashChain      bool                    `yaml:"hash_chain"`
	PIIRedaction   AuditPIIRedactionConfig `yaml:"pii_redaction"`
	Webhook        AuditWebhookConfig      `yaml:"webhook"`
	Retention      AuditRetentionConfig    `yaml:"retention"`
}

// AuditRetentionConfig opts into background pruning of old audit
// events via [audit/sqlite.Sink.Prune]. Active only when audit
// backend = sqlite — the in-memory ring buffer prunes itself by
// capacity. Disabled by default (retention policy is a regulated
// decision operators choose per compliance regime).
//
// When Enabled is true, cmd launches a goroutine that wakes every
// Interval and prunes events with ts < now - MaxAge. The first
// prune fires Interval after server start (not immediately) so
// short-lived deployments don't trigger expensive bulk deletes
// during boot.
//
// Hash-chain caveat (per audit/sqlite Prune doc): pruning leaves
// the first surviving event with a dangling PrevHash that
// VerifyChain reports as a break. Operators retaining N days
// accept the boundary discontinuity; operators wanting a clean
// post-prune chain must run their own re-chaining migration
// (out of scope for the scheduler).
type AuditRetentionConfig struct {
	Enabled  bool          `yaml:"enabled"`
	MaxAge   time.Duration `yaml:"max_age"`  // events older than (now - MaxAge) are eligible
	Interval time.Duration `yaml:"interval"` // how often to wake + prune (default 1h)
}

// AuditSqliteConfig is the SQLite backend's DSN. Production DSN
// shape: file:/var/lib/sso/audit.db?_journal=WAL&_pragma=busy_timeout(5000)
// (matches the other SQLite backends in the SDK).
type AuditSqliteConfig struct {
	DSN string `yaml:"dsn"`
}

// AuditWebhookConfig enables a [audit.WebhookSink] sibling to the
// MemorySink so every recorded event is POSTed as JSON to URL. Sits
// inside a RetryingSink so transient downstream failures don't drop
// events on the floor; AsyncSink (when audit.async.enabled) wraps the
// composite so the network roundtrip stays off the request hot path.
//
// Headers maps to a static Authorization / API-key header set the
// downstream collector requires. Timeout, Retry.* fall back to
// audit-package defaults when zero. Compose order matches AGENTS.md:
// AsyncSink(MultiSink(MemorySink, RetryingSink(WebhookSink))).
type AuditWebhookConfig struct {
	Enabled bool                    `yaml:"enabled"`
	URL     string                  `yaml:"url"`
	Timeout time.Duration           `yaml:"timeout"`
	Headers map[string]string       `yaml:"headers"`
	Retry   AuditWebhookRetryConfig `yaml:"retry"`
	// SigningSecret enables HMAC-SHA256 payload signing (X-Signature:
	// t=<unix>,v1=<hex>) on every delivery. Empty disables. Inject via
	// SSO_AUDIT__WEBHOOK__SIGNING_SECRET or a secret:// reference — never
	// commit the literal to YAML.
	SigningSecret string `yaml:"signing_secret"`
}

// AuditWebhookRetryConfig tunes the retry wrapper around the webhook
// sink. MaxAttempts is the total tries (initial + retries); zero =
// library default. Backoff doubles after each failure, capped at
// MaxBackoff. Total worst-case latency is bounded by MaxAttempts *
// MaxBackoff — set [AuditAsyncConfig.RecordTimeoutMs] tighter than
// that to give the AsyncSink worker a fallback cap when retry stalls.
type AuditWebhookRetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}

// AuditPIIRedactionConfig enables conservative PII redaction on every
// recorded event BEFORE the hash chain runs (so the chain validates
// over the redacted form, with no "what was the pre-redaction value"
// leak path). DefaultPIIRedactor hashes ActorID with Salt, truncates
// IP, strips User-Agent.
//
// Salt MUST be deployment-stable and secret — leaking it re-enables
// hash inversion attacks. Prefer SaltFile (loaded out-of-band) over
// embedding the salt in YAML.
type AuditPIIRedactionConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Salt     string `yaml:"salt"`
	SaltFile string `yaml:"salt_file"`
}

// AuditAsyncConfig wraps the configured audit sink with an
// audit.AsyncSink so Record calls return on a buffered hot path
// instead of waiting for the inner sink. Critical when the sink is
// network-bound (webhook); pointless overhead for MemorySink.
//
// BufferSize and Workers fall back to library defaults when <= 0.
// RecordTimeoutMs caps a single inner Record call so a hung
// downstream doesn't pin a worker indefinitely (0 = no timeout).
type AuditAsyncConfig struct {
	Enabled         bool `yaml:"enabled"`
	BufferSize      int  `yaml:"buffer_size"`
	Workers         int  `yaml:"workers"`
	RecordTimeoutMs int  `yaml:"record_timeout_ms"`
}
