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
	// CEF, OCSF, and Syslog are three INDEPENDENT SIEM export formatters —
	// any subset may be enabled simultaneously (e.g. CEF to one collector
	// AND OCSF to another), unlike Webhook's single-format assumption. Each
	// composes into the same sink stack as Webhook, after PII redaction
	// (see cmd/sso-server/serverbuildauthn.BuildAuditSIEMSinks). Formatters
	// only — no network transport; Output is stdout/stderr/a local file
	// path, never a network address. Network SIEM delivery over Kafka is
	// AuditKafkaConfig below, which reuses these exact byte-formatters.
	CEF    AuditCEFConfig    `yaml:"cef"`
	OCSF   AuditOCSFConfig   `yaml:"ocsf"`
	Syslog AuditSyslogConfig `yaml:"syslog"`
	// Kafka publishes every recorded event to a Kafka topic — the network
	// transport CEF/OCSF/Syslog's doc comments defer to. Requires the
	// operator's forked cmd binary to import infrastructure/kafka and
	// register its factory (see that module's package doc); enabling this
	// with no factory registered fails boot closed with a clear error.
	Kafka AuditKafkaConfig `yaml:"kafka"`
}

// AuditCEFConfig enables an ArcSight CEF (Common Event Format) sink.
// Vendor/Product/Version fill the CEF header's Device Vendor/Product/
// Version fields; empty falls back to "Snaplink"/"SSO"/the running binary's
// build version (see BuildAuditSIEMSinks) so a minimal `enabled: true,
// output: stdout` config still produces a spec-valid header.
type AuditCEFConfig struct {
	Enabled bool   `yaml:"enabled"`
	Output  string `yaml:"output"` // "stdout" | "stderr" | a file path (append, created 0600)
	Vendor  string `yaml:"vendor"`
	Product string `yaml:"product"`
	Version string `yaml:"version"`
}

// AuditOCSFConfig enables an OCSF (Open Cybersecurity Schema Framework)
// JSON-lines sink. No format-specific fields today — OCSF's product/vendor
// metadata is fixed ("Snaplink"/"SSO") rather than config-supplied, unlike
// CEF's header, since it is schema metadata rather than a wire-visible
// header operators commonly need to override.
type AuditOCSFConfig struct {
	Enabled bool   `yaml:"enabled"`
	Output  string `yaml:"output"` // "stdout" | "stderr" | a file path (append, created 0600)
}

// AuditSyslogConfig enables an RFC 5424 syslog sink (structured-data
// carries Event.Metadata; RFC 3164 legacy BSD framing is NOT supported).
// Facility follows RFC 5424 Table 1 (0-23); zero falls back to 10
// (authpriv) — facility 0 (kernel) is never a realistic operator choice for
// an application audit trail, so the zero-value-as-default convention used
// elsewhere in this config is safe here too. Hostname empty resolves
// os.Hostname() at wiring time; AppName empty defaults to "sso-server".
type AuditSyslogConfig struct {
	Enabled  bool   `yaml:"enabled"`
	Output   string `yaml:"output"` // "stdout" | "stderr" | a file path (append, created 0600)
	Facility int    `yaml:"facility"`
	Hostname string `yaml:"hostname"`
	AppName  string `yaml:"app_name"`
}

// AuditKafkaConfig enables publishing every recorded audit event to a Kafka
// topic — the network-transport counterpart to the CEF/OCSF/Syslog
// FILE/stdout formatters above, reusing those exact byte-formatters over
// this transport (see infrastructure/kafka's package doc).
//
// The github.com/segmentio/kafka-go dependency lives ONLY in the
// infrastructure/kafka nested module's own go.mod — this core module never
// imports it — so Enabled:true requires the operator's forked cmd binary to
// import that module and call serverbuildauthn.RegisterAuditKafkaSinkFactory
// once at init (mirrors keys.signing.external /
// serverbuildsign.RegisterExternalSigner for KMS/HSM signers). Enabled with
// no factory registered fails boot CLOSED with an error naming the missing
// registration call, not a silently-dropped audit stream.
type AuditKafkaConfig struct {
	Enabled bool `yaml:"enabled"`
	// Brokers lists the bootstrap broker addresses (host:port); required
	// when Enabled.
	Brokers []string `yaml:"brokers"`
	// Topic is the destination topic for every published event; required
	// when Enabled. No per-tenant/per-event-type topic routing in v1.
	Topic string `yaml:"topic"`
	// ClientID identifies this producer in Kafka broker-side logs/metrics.
	// Empty defaults to "sso-server".
	ClientID string `yaml:"client_id"`
	// RequiredAcks selects the durability/latency trade-off: "none" | "one"
	// | "all". Empty defaults to "all" (full ISR ack) — audit events are a
	// compliance record this sink does not want silently dropped on a
	// leader failover.
	RequiredAcks string `yaml:"required_acks"`
	// Format selects the wire encoding of each published message: "json"
	// (default; explicit schema_version field, see infrastructure/kafka's
	// FormatJSON) or one of the existing SIEM formatters "cef" | "ocsf" |
	// "syslog" — the SAME formatters audit.cef/audit.ocsf/audit.syslog use,
	// reused unchanged over this transport.
	Format string `yaml:"format"`
	// BatchTimeout bounds how long the producer buffers a partial batch
	// before flushing. Zero falls back to the underlying Kafka client's
	// library default (1s).
	BatchTimeout time.Duration `yaml:"batch_timeout"`
	// Async publishes fire-and-forget (the produce call returns without
	// waiting for the broker ack, and any resulting error is swallowed)
	// when true. Defaults to false — synchronous, so a publish failure
	// surfaces to the audit Recorder's fail-open policy / ErrorHandler
	// instead of being silently dropped. Pair false with audit.async
	// (AuditAsyncConfig) to move the wait off the request hot path instead
	// of setting this true.
	Async bool `yaml:"async"`
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
	// Subscriptions fans the audit stream out to multiple endpoints, each
	// with its own event-type filter. The legacy scalar URL above (when
	// set) is compiled as one additional, unfiltered subscription named
	// "default" — so a list entry may not reuse that name when a scalar URL
	// is also configured. Empty EventTypes on a subscription = firehose (all
	// events); non-empty restricts delivery to matching types. See
	// AuditWebhookSubscription for the matching semantics.
	Subscriptions []AuditWebhookSubscription `yaml:"subscriptions"`
}

// AuditWebhookSubscription is one filtered audit webhook endpoint. Name is
// REQUIRED and must be unique across the list (boot fails otherwise); it names
// the subscription in logs and reserves the identity for future
// per-subscription metrics.
//
// EventTypes selects which events reach this endpoint. Each entry is either an
// exact audit event type (e.g. "login") or a trailing-* prefix wildcard (e.g.
// "admin_*" — matches every admin_ event); no other globbing is supported.
// An EMPTY EventTypes list is a firehose (every event). Unknown type strings
// are accepted (custom event types are legal) with a boot-time log line.
//
// Timeout, Headers, SigningSecret, and Retry mirror the scalar webhook fields
// and fall back to library defaults when zero. SigningSecret is a credential:
// inject it via a secret:// reference, never a YAML literal.
type AuditWebhookSubscription struct {
	Name          string                  `yaml:"name"`
	URL           string                  `yaml:"url"`
	EventTypes    []string                `yaml:"event_types"`
	Timeout       time.Duration           `yaml:"timeout"`
	Headers       map[string]string       `yaml:"headers"`
	SigningSecret string                  `yaml:"signing_secret"`
	Retry         AuditWebhookRetryConfig `yaml:"retry"`
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

// EventsConfig opts into the realtime admin event stream — GET
// /api/v1/admin/events/stream (Server-Sent Events), consumed with the
// browser's EventSource API. Disabled by default: a deployment without it
// is byte-identical (no extra sink, no route, no goroutines). It only
// EMITS when audit.enabled is also true — the broker is wired as an
// additional audit Sink (the same AddSink/MultiSink fan-out audit.webhook
// uses), so it carries only whatever the audit Recorder already records,
// projected to a redacted summary (never secrets, raw tokens, or the
// free-form audit metadata blob — see sse.Summary).
//
// Lives beside AuditConfig (not its own config_events.go) because the config
// package directory is at its frozen non-test .go file ceiling (see
// directory_fanout_test.go dirFileCountExemptions) — the ceiling may only
// shrink, so new sections fold into an existing, topically-related file.
type EventsConfig struct {
	Enabled bool `yaml:"enabled"`

	// SubscriberBuffer bounds the per-connection channel: how many unread
	// events a single admin console tab may lag behind before it is evicted
	// as a slow consumer. <= 0 falls back to the SDK default
	// (sse.DefaultSubscriberBuffer) — the publisher NEVER blocks on a slow
	// reader regardless of this value.
	SubscriberBuffer int `yaml:"subscriber_buffer"`

	// ReplayBuffer bounds the ring of recently-published events kept for
	// Last-Event-ID reconnects. <= 0 falls back to the SDK default
	// (sse.DefaultReplayBuffer). A reconnect gap wider than this window is
	// silently skipped — delivery is at-least-once WITHIN the window.
	ReplayBuffer int `yaml:"replay_buffer"`

	// MaxSubscribers caps concurrently live streaming connections. A connect
	// attempt past the cap gets 503 event_stream_busy rather than growing
	// server memory unbounded. <= 0 falls back to the SDK default
	// (sse.DefaultMaxSubscribers).
	MaxSubscribers int `yaml:"max_subscribers"`

	// HeartbeatInterval spaces the SSE comment keep-alive frames that stop
	// intermediary proxies from idling out a quiet connection. <= 0 falls
	// back to the SDK default (sse.DefaultHeartbeat).
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
}

// ConfigAuditConfig configures runtime-configuration audit + drift
// detection (platform/configaudit) — a sibling of AuditConfig above (event
// audit), living in the same file rather than a new config_configaudit.go
// because config/ is already at its frozen per-directory file-count
// ceiling (directory_fanout_test.go). When Enabled is false, no config
// snapshot/history wiring happens and the GET /api/v1/admin/config/* API
// is not mounted — byte-identical to a build without the feature.
//
// Backend selects the [configaudit.Store] backend ("memory" or "sqlite"),
// mirroring AuditConfig.Backend's shape. Retention reuses the same
// interval/max-age shape as AuditRetentionConfig (AGENTS.md: "config_history
// reuses the existing audit.retention config").
type ConfigAuditConfig struct {
	Enabled   bool                       `yaml:"enabled"`
	Backend   string                     `yaml:"backend"` // memory | sqlite
	Sqlite    ConfigAuditSqliteConfig    `yaml:"sqlite"`
	Retention ConfigAuditRetentionConfig `yaml:"retention"`
	Drift     ConfigAuditDriftConfig     `yaml:"drift"`
}

// ConfigAuditSqliteConfig is the SQLite backend's DSN, matching
// AuditSqliteConfig's shape.
type ConfigAuditSqliteConfig struct {
	DSN string `yaml:"dsn"`
}

// ConfigAuditRetentionConfig bounds config_history growth. Mirrors
// AuditRetentionConfig; unlike audit events (potentially very high
// volume), config-history entries are one per admin mutation, so most
// deployments can leave this disabled and rely on the MemoryStore/SQLite
// row count instead.
type ConfigAuditRetentionConfig struct {
	Enabled  bool          `yaml:"enabled"`
	MaxAge   time.Duration `yaml:"max_age"`
	Interval time.Duration `yaml:"interval"`
}

// ConfigAuditDriftConfig opts into the cross-replica config-digest
// broadcast loop (platform/configaudit.DriftDetector). Interval <= 0
// (the default) disables it entirely — a report-only observability
// feature that never runs unless an operator explicitly asks for it.
type ConfigAuditDriftConfig struct {
	Interval time.Duration `yaml:"interval"`
}

// WebhooksConfig opts into the generic event/webhook egress engine
// (platform/lifecycle/webhook, sso.WithWebhookEngine): a MultiSink sibling to the
// primary audit sink (and to audit.webhook above) that fans matching
// events out to whichever EventSubscriptions are registered at runtime via
// the admin API (POST /api/v1/admin/webhooks/subscriptions) — the
// subscriptions themselves are dynamic and intentionally NOT expressible in
// YAML (same story as EventsConfig's SSE broker), so this section carries
// only the engine-wide enablement + delivery tuning.
//
// Lives beside AuditConfig (not its own config_webhooks.go) because config/
// is at its frozen per-directory file-count ceiling
// (directory_fanout_test.go) — the ceiling may only shrink, so a new
// section folds into an existing, topically-related file.
type WebhooksConfig struct {
	Enabled bool `yaml:"enabled"`
	// DeliveryTimeout bounds a single webhook POST. 0 = SDK default (10s).
	DeliveryTimeout time.Duration `yaml:"delivery_timeout"`
	// DeadLetterCapacity bounds the in-memory dead-letter ring
	// (GET /api/v1/admin/webhooks/deadletters). 0 = SDK default (1000).
	DeadLetterCapacity int                 `yaml:"dead_letter_capacity"`
	Retry              WebhooksRetryConfig `yaml:"retry"`
}

// WebhooksRetryConfig tunes the per-delivery retry wrapper, mirroring
// AuditWebhookRetryConfig's shape.
type WebhooksRetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}
