package config

import "time"

type IdentityConfig struct {
	Backend     string               `yaml:"backend"` // memory | sqlite
	SQLite      IdentitySQLiteConfig `yaml:"sqlite"`
	ClientCache ClientCacheConfig    `yaml:"client_cache"`
}

// ClientCacheConfig opts into the per-login ClientStore metadata cache
// (WithClientStoreCache). When Enabled, each ClientStore.Get on the
// hot login path is cached for TTL and evicted on admin/DCR mutations
// via the cluster.Bus KindClientChange event. ValidateSecret always
// bypasses the cache (never caches credentials). TTL 0 = SDK default
// (30s). cmd knob: identity.client_cache.{enabled,ttl}.
type ClientCacheConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"` // 0 → 30s SDK default
}

type IdentitySQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// ClientRegistrationConfig opts into RFC 7591 Dynamic Client Registration
// (POST /register) and the matching RFC 7592 management endpoints
// (GET/PUT/DELETE /register/:client_id). Without Enabled, /register
// returns 501 and every RP must be operator-registered up front.
//
// Security: leave InitialAccessToken set in production. Operators
// who set AllowOpenRegistration=true without an initial access token
// open the endpoint to the world — every public DCR endpoint in the
// wild eventually gets used for resource exhaustion / spam client
// creation.
type ClientRegistrationConfig struct {
	Enabled               bool     `yaml:"enabled"`
	InitialAccessToken    string   `yaml:"initial_access_token"`
	AllowOpenRegistration bool     `yaml:"allow_open_registration"`
	DefaultActive         bool     `yaml:"default_active"`
	DefaultTokenStrategy  string   `yaml:"default_token_strategy"`
	AllowedAuthenticators []string `yaml:"allowed_authenticators"`
	// RotateAccessToken mints a fresh registration_access_token on every
	// PUT /register/:id (RFC 7592 §3.2), limiting a leaked token's lifetime.
	// Default false keeps the token stable across updates (byte-identical);
	// enabling it requires managing clients to capture the new token per PUT.
	RotateAccessToken bool `yaml:"rotate_access_token"`
}

// BackchannelLogoutConfig opts into OIDC Back-Channel Logout 1.0.
// When Enabled, /logout + /end_session POST a signed logout_token to
// each affected RP's backchannel_logout_uri so they can drop the
// matching session. SessionManager is required for session-scoped
// (`sid` claim) emission — cmd wires the memory SessionManager by
// default, so this flag is sufficient.
//
// Backed by:
//   - Ed25519JWTIssuer (reused from access tokens) as LogoutTokenIssuer
//   - HTTPLogoutNotifier with the SDK default 5s timeout
//   - SubjectClientIndex per Index.Backend — memory by default
//     (single-replica) or sqlite (cluster-shared)
//
// MaxConcurrent caps the fan-out parallelism per logout (default 8).
type BackchannelLogoutConfig struct {
	Enabled       bool           `yaml:"enabled"`
	MaxConcurrent int            `yaml:"max_concurrent"`
	Index         BCLIndexConfig `yaml:"index"`
}

// BCLIndexConfig configures the SubjectClientIndex backend that
// drives multi-RP fan-out. memory keeps the simple-bootstrap story;
// sqlite shares the index across replicas so a logout routed to a
// replica that never issued tokens for a sibling RP still fans out
// correctly.
type BCLIndexConfig struct {
	Backend string               `yaml:"backend"`
	SQLite  BCLIndexSQLiteConfig `yaml:"sqlite"`
}

type BCLIndexSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// OAuthConfig opts into the OAuth/OIDC grant stores that cmd's binary
// wires. Each sub-block independently enables one grant:
//
//   - oauth.AuthCode  → grant_type=authorization_code (RFC 6749 §4.1)
//   - Refresh   → grant_type=refresh_token (RFC 6749 §6 — single-use rotation)
//   - Device    → grant_type=urn:ietf:params:oauth:grant-type:device_code (RFC 8628)
//   - PAR       → /par + request_uri (RFC 9126)
//
// Without these flags the corresponding endpoints return 501. Memory
// backends are wired today; SQLite / Redis can be plugged in by
// embedding apps.
//
// Each block's TTL is optional; <=0 falls back to the SDK default
// constants (DefaultAuthCodeTTL, DefaultRefreshTokenTTL, DefaultDeviceCodeTTL,
// oauth.DefaultPARTTL).
