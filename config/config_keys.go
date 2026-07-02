package config

import "time"

type KeysConfig struct {
	Signing              SigningConfig              `yaml:"signing"`
	Rotation             KeyRotationConfig          `yaml:"rotation"`
	SigningKeyRegistry   SigningKeyRegistryConfig   `yaml:"signing_key_registry"`
	IntrospectionSigning IntrospectionSigningConfig `yaml:"introspection_signing"`
}

// IntrospectionSigningConfig opts into RFC 9701 JWT-formatted
// /token/introspect responses (docs/config-reference.md "Signing Keys").
// Enabled=false (default) is byte-identical to a build without this
// feature — every introspection response stays plain RFC 7662 JSON no
// matter what the caller's Accept header requests.
//
// The embedded SigningConfig is REUSED so this role gets the exact same
// alg / external-KMS / revocation-backend machinery as the primary
// signing key (BuildSigningIssuer) — but constructs a SEPARATE issuer
// instance with its own key, because the whole point of AGENTS.md's
// "dedicated key" requirement is that compromising one signer can't be
// used to forge the other's output. This key's rotation is therefore
// already independent of keys.rotation (which only ever targets the
// primary issuer): call RotateKey/RotateNow directly on the constructed
// issuer, or extend KeyAdminService to a named-role RPC as a follow-on —
// out of scope here (mirrors the deferred multi-key scope noted on the
// on-demand KeyAdminService rotation feature).
type IntrospectionSigningConfig struct {
	Enabled       bool `yaml:"enabled"`
	SigningConfig `yaml:",inline"`
}

// SigningKeyRegistryConfig opts into leaderless multi-replica signing-key
// aggregation. In a leaderless deployment each replica holds its own
// in-process signing key with a distinct kid; without aggregation a token
// minted by one replica fails verification on a peer (or on an RP that
// fetched JWKS from a peer). With this enabled each replica PUBLISHES its
// signing PUBLIC keys to a shared registry and ADOPTS its peers' public keys
// VERIFY-ONLY, so JWKS + Validate serve the union while each replica still
// signs only with its own key. No shared private key, no leader election.
//
// Backend: "" (disabled, default) | "memory" (single-process / test) |
// "etcd" (cross-process: each replica announces its public keys under a lease
// and peers Watch + adopt). The etcd_* fields mirror ClusterBusConfig for
// operator familiarity and are only consulted when backend=etcd.
type SigningKeyRegistryConfig struct {
	Backend   string        `yaml:"backend"`
	ReplicaID string        `yaml:"replica_id"`
	LeaseTTL  time.Duration `yaml:"lease_ttl"`

	EtcdEndpoints   []string      `yaml:"etcd_endpoints"`
	EtcdPrefix      string        `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration `yaml:"etcd_dial_timeout"`
	EtcdUsername    string        `yaml:"etcd_username"`
	EtcdPassword    string        `yaml:"etcd_password"`
}

// SigningConfig selects the JWT signing algorithm for the server's own
// tokens (access / id_token / userinfo / logout / signed metadata).
type SigningConfig struct {
	// Alg: "" | "eddsa" (Ed25519, default) | "es256" (ECDSA P-256).
	// es256 is the common FAPI choice. Scheduled key rotation
	// (keys.rotation) is currently only available for eddsa; with
	// es256 + rotation enabled, cmd logs a warning and skips the
	// scheduled loop (manual RotateKey/RetireKey still work).
	Alg string `yaml:"alg"`

	// External names a KMS/HSM signer factory registered via the cmd
	// RegisterExternalSigner hook (in an operator's forked binary).
	// When set, the signing key lives outside this process — the
	// factory's crypto.Signer is bridged into the issuer's signing seam
	// (see defaultimpl/cryptosigner) and the factory's kid names it in
	// JWKS. Empty (default) = an in-process generated/loaded key. Must
	// match Alg's algorithm family. Scheduled key rotation is disabled
	// with an external signer (the key's lifecycle is managed in the
	// KMS/HSM, not by this process).
	External string `yaml:"external"`

	// RevocationBackend selects the durable RevocationStore backend for
	// access-token revocations that survive a process restart.
	// "" (default) = in-process only; "memory" = durable MemoryRevocationStore
	// (for testing / single-replica); "sqlite" = durable SQLite store (requires
	// RevocationDSN). When set, the store is seeded at boot so a pre-restart
	// revocation is honored again. Orthogonal to the live cross-replica bus
	// (WithCrossReplicaRevocation). cmd knob: keys.signing.revocation_backend.
	RevocationBackend string `yaml:"revocation_backend"`
	// RevocationDSN is the SQLite DSN for the durable revocation store.
	// Required when RevocationBackend = "sqlite"; ignored otherwise.
	RevocationDSN string `yaml:"revocation_dsn"`
}

// KeyRotationConfig drives the automatic signing-key rotation loop.
// GracePeriod MUST be >= the maximum access-token TTL so tokens minted
// just before a rotation stay verifiable until they expire. Single-
// issuer semantics: in a multi-replica cluster, enable this on a single
// leader (or back the issuer with a shared KMS signer), otherwise
// replicas advertise divergent kids.
type KeyRotationConfig struct {
	Enabled     bool          `yaml:"enabled"`
	Interval    time.Duration `yaml:"interval"`     // e.g. 2160h (90d)
	GracePeriod time.Duration `yaml:"grace_period"` // e.g. 168h (7d)
	// CoordinatedCutover arms WithCoordinatedKeyRotation so every replica
	// retires the old signing kid at the same instant (broadcast via
	// cluster.Bus KindSigningKeyRotation). Requires cluster.bus. Nil bus
	// = log error + INERT (§2 fail-safe — always widens, never narrows
	// the verify window). cmd knob: keys.rotation.coordinated_cutover.
	CoordinatedCutover bool `yaml:"coordinated_cutover"`
}

// ClusterConfig wires cross-replica coordination via cluster.Bus. The
// bus propagates cache invalidations (today: tenant suspension) so an
// admin action on one replica takes effect on every replica immediately
// instead of after each node's cache TTL elapses. The memory backend is
// per-process (effectively a no-op for multi-replica — single-node
// already invalidates locally); etcd is cluster-shared. The bus is
// fail-open by design, so it is deliberately NOT a readiness dependency.
type ClusterConfig struct {
	Bus ClusterBusConfig `yaml:"bus"`
	// CrossReplicaRevocation enables propagation of access-token revocations
	// to peer replicas via cluster.Bus KindTokenRevoked. Requires cluster.bus.
	// Nil bus = log error + INERT. cmd knob: cluster.cross_replica_revocation.
	CrossReplicaRevocation bool `yaml:"cross_replica_revocation"`
}

// ClusterBusConfig selects and configures the invalidation bus backend.
// The etcd_* fields mirror RegistryConfig for operator familiarity.
type ClusterBusConfig struct {
	Backend string `yaml:"backend"` // "" | "memory" | "etcd"

	EtcdEndpoints   []string      `yaml:"etcd_endpoints"`
	EtcdPrefix      string        `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration `yaml:"etcd_dial_timeout"`
	EtcdEventTTL    time.Duration `yaml:"etcd_event_ttl"`
	EtcdUsername    string        `yaml:"etcd_username"`
	EtcdPassword    string        `yaml:"etcd_password"`
}

// RedisConfig is the single shared Redis connection used by every store whose
// backend is set to "redis". One client is built from this block and fanned
// out to all redis-backed stores (auth_code, refresh, session, par,
// device_code, ciba, jti_replay, mfa challenge, ratelimit, ...), so HA tuning
// lives in one place. cmd maps this onto the redis module's Options (the module
// owns the go-redis dependency); this struct stays free of any external-SDK
// import so the core config package does too.
//
// Mode selects the topology: "single" (default), "sentinel", or "cluster".
// Cluster mode requires db=0 and at least one seed addr; sentinel requires
// master_name. Secrets (password) are typically injected via the env override
// SSO_REDIS__PASSWORD rather than committed to the file.
type RedisConfig struct {
	// Mode is "" (infer: master_name -> sentinel, >1 addr -> cluster, else
	// single) | "single" | "sentinel" | "cluster".
	Mode  string   `yaml:"mode"`
	Addrs []string `yaml:"addrs"`

	Username     string `yaml:"username"`
	Password     string `yaml:"password"`
	PasswordFile string `yaml:"password_file"`
	DB           int    `yaml:"db"`          // single/sentinel only; cluster requires 0
	MasterName   string `yaml:"master_name"` // required for sentinel

	PoolSize        int           `yaml:"pool_size"`
	MinIdleConns    int           `yaml:"min_idle_conns"`
	MaxRetries      int           `yaml:"max_retries"`
	DialTimeout     time.Duration `yaml:"dial_timeout"`
	ReadTimeout     time.Duration `yaml:"read_timeout"`
	WriteTimeout    time.Duration `yaml:"write_timeout"`
	PoolTimeout     time.Duration `yaml:"pool_timeout"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`

	// RouteByLatency / RouteRandomly / ReadOnly spread reads across cluster
	// replicas. Keep them OFF (default) for correctness: the single-use and
	// replay stores must read from the master, or replica lag could let a
	// replay momentarily evade detection. Enable only for read-mostly stores
	// in a deployment that pins those hot stores to the master separately.
	RouteByLatency bool `yaml:"route_by_latency"`
	RouteRandomly  bool `yaml:"route_randomly"`
	ReadOnly       bool `yaml:"read_only"`

	TLS RedisTLSConfig `yaml:"tls"`
}

// RedisTLSConfig configures an optional TLS transport to Redis. Enabled=false
// (the zero value) is a plaintext connection.
type RedisTLSConfig struct {
	Enabled            bool   `yaml:"enabled"`
	CAFile             string `yaml:"ca_file"`
	CertFile           string `yaml:"cert_file"`
	KeyFile            string `yaml:"key_file"`
	ServerName         string `yaml:"server_name"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

// Configured reports whether a Redis connection is declared (at least one
// addr). The store dispatchers use this to fail loudly when a backend is set
// to "redis" but no redis block was provided.
func (c RedisConfig) Configured() bool { return len(c.Addrs) > 0 }

// PostgresConfig is the single shared Postgres-wire connection used by every
// DURABLE store whose backend is set to "postgres" (clients, users, consent,
// …). One *sql.DB pool is built from this block and fanned out to all
// postgres-backed stores, so HA pool tuning lives in one place. cmd maps this
// onto the postgres module's Config (the module owns the pgx dependency); this
// struct stays free of any external-SDK import so the core config package does
// too. dialect selects the small set of behaviors that differ between plain
// PostgreSQL and CockroachDB (advisory locks vs serialization-retry). DSN is
// typically injected via env (SSO_POSTGRES__DSN); behind a tx-mode pooler
// (pgbouncer) add default_query_exec_mode=simple_protocol to the DSN and keep
// max_open_conns small (N replicas x max_open must stay under DB max_connections).
type PostgresConfig struct {
	DSN     string `yaml:"dsn"`
	Dialect string `yaml:"dialect"` // "" | postgres | cockroach

	MaxOpenConns    int           `yaml:"max_open_conns"`
	MaxIdleConns    int           `yaml:"max_idle_conns"`
	ConnMaxLifetime time.Duration `yaml:"conn_max_lifetime"`
	ConnMaxIdleTime time.Duration `yaml:"conn_max_idle_time"`
}

// Configured reports whether a Postgres connection is declared. The store
// dispatchers use this to fail loudly when a backend is set to "postgres" but
// no postgres block was provided.
func (c PostgresConfig) Configured() bool { return c.DSN != "" }

// AnomalyConfig wires the async behavioral anomaly detection
// subsystem (impossible_travel / velocity / new_device /
// new_country / brute_force_shadow). Decoupled from RiskConfig
// because anomaly detectors run OFF the request path on every
// login event (success + failure) and surface anomalies via
// audit + metrics — they NEVER block login by design.
//
// When Enabled=false the entire subsystem short-circuits: no
// runner spawned, no store connections opened, zero overhead.
// When Enabled=true, at least one detector must be enabled or
// cmd boots with a warning (the runner is a no-op without
// detectors registered).
//
// IPSalt is the deployment-stable hash salt used by
// defaultimpl.HashLoginEntry — required for non-test deploys
// (PII privacy depends on it). Empty IPSalt + Enabled=true →
// boot warning. Operator MAY accept this for memory-only
// single-replica deploys but MUST set IPSalt before persisting
// to SQLite.
