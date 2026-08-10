package config

import (
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/scopecontract"
	"github.com/yangwb1123/snaplink/protocols/oauth/scoperegistry"
)

// validateScopeRegistry validates the scope_registry block ALWAYS — even
// when enabled is false — so a malformed snapshot fails boot loudly instead
// of silently diverging when the fleet flip later turns the block on
// (fail-closed, never runtime fail-open). Steps run in deterministic order
// so error precedence is testable:
//
//  1. matrix row grammar (always) — the registry's own pattern grammar
//     (exact or "domain:*" only);
//  2. exact-string matrix duplicates (always) — NewMemory silently dedupes
//     (set semantics), so the duplicate check must be explicit here: the
//     semantic check the reflection schema cannot express;
//  3. extra_scopes grammar (always) — mirrors step 1;
//  4. client.allowed_scopes membership (ONLY when enabled: true) — every
//     entry must be Registered by the exact registry the server would build
//     (MatrixOrDefault + extra_scopes), so the config gate can never
//     disagree with /token. When disabled, no membership check runs: the
//     runtime 400 this gate prevents pre-deploy only exists under an
//     enabled registry, and an unconditional check would break every
//     existing deploy config (byte-compat pin).
func (c *Config) validateScopeRegistry() error {
	regCfg := &c.OAuth.ScopeRegistry
	for _, s := range regCfg.Matrix {
		if err := scoperegistry.ValidatePattern(s); err != nil {
			return fmt.Errorf("config: oauth.scope_registry.matrix %q invalid: %w", s, err)
		}
	}
	seen := make(map[string]struct{}, len(regCfg.Matrix))
	for _, s := range regCfg.Matrix {
		if _, dup := seen[s]; dup {
			return fmt.Errorf("config: oauth.scope_registry.matrix lists duplicate scope %q", s)
		}
		seen[s] = struct{}{}
	}
	for _, s := range regCfg.ExtraScopes {
		if err := scoperegistry.ValidatePattern(s); err != nil {
			return fmt.Errorf("config: oauth.scope_registry.extra_scopes %q invalid: %w", s, err)
		}
	}
	if !regCfg.Enabled {
		return nil
	}
	reg, err := scoperegistry.NewMemory(regCfg.MatrixOrDefault(), regCfg.ExtraScopes)
	if err != nil {
		// Unreachable after the grammar steps above; defense in depth —
		// never run a gate that could disagree with the runtime registry.
		return fmt.Errorf("config: oauth.scope_registry: %w", err)
	}
	for _, client := range c.Clients {
		for _, s := range client.AllowedScopes {
			if !reg.Registered(s) {
				return fmt.Errorf("config: client %q allowed_scopes %q is not registered by oauth.scope_registry (matrix + protocol scopes + extra_scopes)", client.ID, s)
			}
		}
	}
	return nil
}

type OAuthConfig struct {
	// Backend selects the storage substrate for auth_code,
	// refresh_token, device_code, and PAR. "memory" (default) is in-
	// process; "sqlite" persists across restarts and shares state
	// across processes that point at the same file; "postgres" shares
	// the cluster-wide state across replicas via the postgres: block
	// (no separate DSN — the shared pool is reused, mirroring
	// identity.session_backend=postgres). Each individually-enabled
	// store inherits this choice unless the store's own Backend
	// override is set.
	Backend       string                   `yaml:"backend"`
	SQLite        OAuthSQLiteConfig        `yaml:"sqlite"`
	Redis         OAuthRedisConfig         `yaml:"redis"`
	Postgres      OAuthPostgresConfig      `yaml:"postgres"`
	AuthCode      OAuthAuthCodeConfig      `yaml:"auth_code"`
	RefreshToken  OAuthRefreshTokenConfig  `yaml:"refresh_token"`
	DeviceCode    OAuthDeviceCodeConfig    `yaml:"device_code"`
	PAR           OAuthPARConfig           `yaml:"par"`
	JAR           OAuthJARConfig           `yaml:"jar"`
	JARM          OAuthJARMConfig          `yaml:"jarm"`
	Compliance    OAuthComplianceConfig    `yaml:"compliance"`
	Introspection OAuthIntrospectionConfig `yaml:"introspection"`
	TokenExchange OAuthTokenExchangeConfig `yaml:"token_exchange"`
	ScopeRegistry ScopeRegistryConfig      `yaml:"scope_registry"`
}

// ScopeRegistryConfig opts into the global scope registry (scope-matrix-v2,
// campaign B4-2): when Enabled, /token grants may only mint registered
// scopes — the nine-scope matrix (interfaces/scopecontract) plus the OIDC
// protocol set (pre-seeded by construction) plus ExtraScopes — and an
// unregistered scope is rejected with the standard 400 invalid_scope.
//
// Default-off: with no block (or enabled: false) the server is byte-identical
// to a build without the feature. The flip is a deployment-wide config
// change, never a per-replica toggle: two replicas built from the same
// snapshot answer identically, and rollback is flipping enabled back to
// false (no data migration, no token invalidation).
//
// ExtraScopes feeds the registry ONLY — it is never merged into discovery's
// scopes_supported and never expands any grant. It is restricted to tenant
// RESOURCE scopes: the seven protocol scopes (openid, device_sso, profile,
// email, address, phone, offline_access) are pre-registered and listing them
// here is a harmless no-op. There is no hot-reload of this block — boot-time
// only (the registry is build-once).
//
// Matrix provisions the scope-matrix-v2 table from config. Absent or empty:
// the built-in nine-scope table (interfaces/scopecontract) is used —
// byte-identical to a config without the key. Present: the provisioned table
// REPLACES the built-in at the registry construction site, so provisioning is
// explicit and complete-table CI-verifiable. Rows follow the registry's own
// pattern grammar (exact scope or "domain:*" only); row grammar and
// exact-string duplicates are validated ALWAYS (fail-closed, mirroring
// extra_scopes). A row equal to a pre-seeded protocol scope (e.g. openid) is
// an idempotent no-op, not an error; cross-list duplication with extra_scopes
// is likewise idempotent (registry set semantics).
type ScopeRegistryConfig struct {
	Enabled bool `yaml:"enabled"`
	// ExtraScopes registers additional tenant resource scopes; a bare "*" or
	// any non-"domain:*" wildcard is rejected at boot even when Enabled is
	// false (fail-closed, so a stale/malformed snapshot fails loudly at the
	// next restart instead of silently diverging).
	ExtraScopes []string `yaml:"extra_scopes"`
	Matrix      []string `yaml:"matrix"`
}

// MatrixOrDefault returns the provisioned matrix when non-empty, else the
// built-in nine-scope table (interfaces/scopecontract.Matrix). The registry
// construction site (cmd/sso-server) and the config gate both consult this,
// so the validator can never disagree with the runtime registry. Callers
// must not mutate the returned slice.
func (c ScopeRegistryConfig) MatrixOrDefault() []string {
	if len(c.Matrix) > 0 {
		return c.Matrix
	}
	return scopecontract.Matrix()
}

// OAuthTokenExchangeConfig groups RFC 8693 token-exchange governance knobs.
// The hop-authorization Policy SPI itself (domains/tokenexchange.Policy) is
// deliberately NOT YAML-driven — like spi.RiskScorer / spi.MFAProvider, it
// encodes operator-specific business rules an inline config schema can't
// generically express; wire a custom implementation (or the reference
// domains/tokenexchange/memory.Store) via sso.WithTokenExchangePolicy.
type OAuthTokenExchangeConfig struct {
	// MaxChainLifetime caps an RFC 8693 delegation chain's total age —
	// measured from the subject_token's AuthTime (the original end-user
	// login or SPIFFE SVID presentation, propagated UNCHANGED across every
	// exchange hop), independent of any single hop's access-token TTL. 0
	// (default) disables the cap — byte-identical to pre-feature behavior.
	MaxChainLifetime time.Duration `yaml:"max_chain_lifetime"`
}

// OAuthIntrospectionConfig groups /token/introspect tuning: response caching,
// signed (JWT) responses, and batch requests. All fields default off/zero —
// byte-identical to today's plain-JSON, uncached, single-token behavior.
type OAuthIntrospectionConfig struct {
	// CacheTTL enables the optional short-lived cache (protocols/oauth.
	// IntrospectionCache) for /token/introspect responses keyed by
	// SHA-256(token), so a burst of introspection calls for the same token
	// doesn't all pay full JWT verification. 0 (default) = disabled. Backed
	// by an in-process handler.MemoryIntrospectionCache; a multi-replica
	// deployment wanting a SHARED cache should wire a custom
	// oauth.IntrospectionCache via sso.WithIntrospectionCache instead.
	CacheTTL time.Duration `yaml:"cache_ttl"`
	// SignedResponseEnabled opts into RFC 9701-style JWT-signed introspection
	// responses, reusing the server's existing token-signing key (no
	// separate key is minted) — the introspection-side analogue of JARM. A
	// wired signer only takes effect when the introspecting client ALSO
	// opts in per-request via `Accept: application/token-introspection+jwt`;
	// a request without that header always gets plain JSON.
	SignedResponseEnabled bool `yaml:"signed_response_enabled"`
	// BatchEnabled opts into accepting a `tokens` array in the
	// /token/introspect request body (JSON `{"tokens":[...]}"` or repeated
	// form field `tokens`) and returning an array of RFC 7662 result bodies
	// in one round trip. Default false: an inbound `tokens` field is
	// ignored and the single-`token` behavior is unchanged.
	BatchEnabled bool `yaml:"batch_enabled"`
	// MaxBatchSize caps how many tokens one batch request may include.
	// <= 0 falls back to oauth.DefaultMaxIntrospectBatchSize.
	MaxBatchSize int `yaml:"max_batch_size"`
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
	DSN                       string `yaml:"dsn"`
	LookupHMACKeyFile         string `yaml:"lookup_hmac_key_file"`
	LookupHMACPreviousKeyFile string `yaml:"lookup_hmac_previous_key_file"`
}

// OAuthPostgresConfig protects opaque OAuth artifacts in Postgres columns
// with the same domain-separated HMAC lookup keys the sqlite/redis peers
// use. The previous key permits rolling rotation without invalidating
// in-flight grants; legacy plaintext reads support safe first rollout.
// The postgres: block remains the single DSN source — this section carries
// lookup keys only. Unset keys fall back to raw plaintext storage, exactly
// like the peers (set them in production).
type OAuthPostgresConfig struct {
	LookupHMACKeyFile         string `yaml:"lookup_hmac_key_file"`
	LookupHMACPreviousKeyFile string `yaml:"lookup_hmac_previous_key_file"`
}

// OAuthRedisConfig protects opaque OAuth artifacts in Redis key names and
// values. The previous key permits rolling rotation without invalidating
// in-flight grants; legacy plaintext reads support safe first rollout.
type OAuthRedisConfig struct {
	LookupHMACKeyFile         string `yaml:"lookup_hmac_key_file"`
	LookupHMACPreviousKeyFile string `yaml:"lookup_hmac_previous_key_file"`
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

	// AbsoluteMaxLifetime caps a refresh-token FAMILY's total age since
	// original issuance (FamilyCreatedAt), enforced at rotation time
	// independent of the per-token TTL/idle-expiry (TTL above) and the
	// rotation-velocity cap (MaxRotationsPerWindow/RotationWindow) — a family
	// that keeps rotating on schedule never re-triggers either of those. 0
	// (the default) disables the cap: a family may rotate forever, exactly
	// as before this field existed.
	AbsoluteMaxLifetime time.Duration `yaml:"absolute_max_lifetime"`

	// MaxEntries caps the in-process memory backend's live token count
	// (0 = unbounded, the default); ignored by sqlite/redis backends,
	// which bound growth via their own storage. ReapInterval, when
	// positive, starts a background sweep removing expired tokens that
	// no Consume/Inspect call ever revisits again. MaxEntries applies only
	// to memory; ReapInterval applies to memory and SQLite (Redis uses native
	// key TTL). See memorystoreoauth.MemoryRefreshTokenStore.
	MaxEntries   int           `yaml:"max_entries"`
	ReapInterval time.Duration `yaml:"reap_interval"`
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
	// RotationGraceBackend selects where the grace successor is remembered:
	// "" | "memory" (in-process, single-replica ONLY) | "redis" (cluster-shared,
	// requires a redis block) | "postgres" (cluster-shared, requires a
	// postgres block). On a multi-replica deployment with a no-affinity
	// load balancer, "memory" causes a false family-reuse kill (logout storm)
	// when a double-submit lands on a different replica than the rotation — use
	// "redis"/"postgres" so the grace decision is shared. Ignored when
	// grace_window = 0.
	RotationGraceBackend string `yaml:"rotation_grace_backend"`
}

// OAuthAuthCodeConfig extends OAuthStoreConfig with bounded-memory and
// memory/SQLite expiry-sweep knobs. It remains a distinct type because the
// sibling configs embed OAuthStoreConfig and redeclare the same fields.
type OAuthAuthCodeConfig struct {
	OAuthStoreConfig `yaml:",inline"`

	MaxEntries   int           `yaml:"max_entries"`
	ReapInterval time.Duration `yaml:"reap_interval"`
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

	// MaxEntries applies to memory. ReapInterval applies to memory and SQLite;
	// Redis expires each code natively. Both default to 0.
	MaxEntries   int           `yaml:"max_entries"`
	ReapInterval time.Duration `yaml:"reap_interval"`
}

// OAuthPARConfig extends OAuthStoreConfig with the same bounded-memory and
// memory/SQLite expiry-sweep knobs as the other opaque OAuth stores.
type OAuthPARConfig struct {
	OAuthStoreConfig `yaml:",inline"`

	MaxEntries   int           `yaml:"max_entries"`
	ReapInterval time.Duration `yaml:"reap_interval"`
}

// MetricsConfig toggles Prometheus instrumentation. When Enabled,
// cmd/sso-server constructs a metrics.Metrics with its own Registry,
// wires sso.WithMetrics so request count / latency / login / token /
// risk counters all fire, and exposes /metrics for scraping.
//
// When an audit AsyncSink is also wired (audit.async.enabled), the
// matching metrics.AsyncSinkCollector is registered automatically so
// drop counters and queue depth land on the same registry.
