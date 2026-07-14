package config

import "time"

type DPoPConfig struct {
	ProofMaxAge  time.Duration `yaml:"proof_max_age"`
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`
}

// SCIMConfig opts into the SCIM 2.0 /Groups resource (RFC 7643 §4.2).
// SCIM Users are always mounted when admin auth + a UserProvider are
// present; Groups additionally require a permissions.Provider, because a
// SCIM group is mapped onto a permissions.Role (its members become role
// assignments). GroupClientID names the app whose roles an IdP group push
// drives — "" is the valid demo/default bucket. Leave Groups.Enabled
// false to mount Users only.
type SCIMConfig struct {
	Groups SCIMGroupsConfig `yaml:"groups"`
	// Push opts into OUTBOUND SCIM 2.0 provisioning
	// (protocols/scimprovision, sso.WithSCIMProvisioner): the reverse
	// direction of this section's inbound Users/Groups receiver. Disabled
	// by default — zero outbound traffic, byte-identical to a build
	// without the feature.
	Push SCIMPushConfig `yaml:"push"`
}

// SCIMGroupsConfig configures the SCIM /Groups <-> permissions.Role
// mapping.
type SCIMGroupsConfig struct {
	Enabled       bool   `yaml:"enabled"`
	GroupClientID string `yaml:"group_client_id"`
}

// SCIMPushConfig configures the OUTBOUND SCIM provisioner: a Sink sibling
// to the primary audit sink (like AuditWebhookConfig below, NOT the
// dynamic multi-target platform/lifecycle/webhook.Engine) that pushes
// user create/update/delete and group-membership changes to ONE downstream
// SCIM 2.0 application. A single, statically-configured target mirrors
// AuditWebhookConfig's shape because a provisioning target is normally one
// fixed downstream app an operator wires at deploy time, not something end
// users register at runtime.
type SCIMPushConfig struct {
	Enabled bool `yaml:"enabled"`
	// BaseURL is the downstream SCIM 2.0 service root (e.g.
	// "https://app.example.com/scim/v2"); /Users and /Groups are resolved
	// relative to it. Required when Enabled.
	BaseURL string `yaml:"base_url"`
	// BearerToken authenticates every outbound request
	// (Authorization: Bearer <token>) — SCIM's common auth model (RFC 7644
	// §2). Inject via SSO_SCIM__PUSH__BEARER_TOKEN or a secret:// reference
	// — never commit the literal to YAML (mirrors
	// AuditWebhookConfig.SigningSecret's convention).
	BearerToken string `yaml:"bearer_token"`
	// Timeout bounds a single outbound HTTP call. 0 = SDK default (10s).
	Timeout time.Duration `yaml:"timeout"`
	// GroupClientID scopes which permissions.Role changes are pushed as
	// SCIM Groups. 0-value "" falls back to Groups.GroupClientID so a
	// deployment that already configured inbound Groups doesn't repeat
	// itself; set explicitly to push a DIFFERENT client's roles than the
	// receiver accepts.
	GroupClientID string              `yaml:"group_client_id"`
	Retry         SCIMPushRetryConfig `yaml:"retry"`
}

// SCIMPushRetryConfig tunes the per-delivery retry wrapper, mirroring
// AuditWebhookRetryConfig's shape.
type SCIMPushRetryConfig struct {
	MaxAttempts    int           `yaml:"max_attempts"`
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
}

// CIBAConfig opts into OIDC CIBA (Client-Initiated Backchannel
// Authentication) poll mode. The out-of-band challenge is delivered
// via the same transport primitives as push MFA (log | webhook):
// server issues an auth_req_id, a device confirms out-of-band, the
// client polls /token with grant_type=urn:openid:params:grant-type:ciba.
type CIBAConfig struct {
	Enabled       bool                 `yaml:"enabled"`
	Backend       string               `yaml:"backend"`        // memory | sqlite
	SQLiteDSN     string               `yaml:"sqlite_dsn"`     // required when backend=sqlite
	RequestTTL    time.Duration        `yaml:"request_ttl"`    // 0 → SDK default
	Interval      time.Duration        `yaml:"interval"`       // poll interval advertised to clients; 0 → SDK default
	Transport     string               `yaml:"transport"`      // log | webhook
	Webhook       MFAPushWebhookConfig `yaml:"webhook"`        // used when transport=webhook
	PruneInterval time.Duration        `yaml:"prune_interval"` // background PruneExpired cadence (sqlite-only); 0 disables
	Ping          CIBAPingConfig       `yaml:"ping"`           // ping delivery mode (poll stays available)
	Push          CIBAPushConfig       `yaml:"push"`           // push delivery mode (CIBA Core §10.3; poll/ping stay available)
}

// CIBAPingConfig opts into CIBA ping delivery (CIBA Core §10.2). When
// enabled, discovery advertises "ping" and the server POSTs to a client's
// notification endpoint when its backchannel request resolves. Endpoints
// maps client_id → notification URL; a client absent from the map (or an
// empty URL) silently degrades to poll. The endpoint lives in cmd config
// rather than the SDK Client model to keep core.Client minimal.
type CIBAPingConfig struct {
	Enabled   bool              `yaml:"enabled"`
	Endpoints map[string]string `yaml:"endpoints"` // client_id → notification endpoint URL
	Timeout   time.Duration     `yaml:"timeout"`   // per-ping HTTP timeout; 0 → default
}

// CIBAPushConfig opts into CIBA push delivery (CIBA Core §10.3). When
// enabled, discovery advertises "push" and — the moment an approved
// backchannel request resolves — the server mints the token set itself
// and POSTs it directly to the client's registered delivery endpoint, so
// a push-registered client never needs to poll /token at all (poll stays
// available as a live fallback). Endpoints maps client_id ->
// backchannel_token_delivery_uri (https only, enforced by the notifier); a
// client absent from the map (or an empty URL) silently degrades to
// poll/ping. The endpoint lives in cmd config rather than the SDK Client
// model, mirroring CIBAPingConfig, to keep core.Client minimal.
//
// Deliveries that still fail after Timeout + retries are captured by a
// dead-letter store for operator replay rather than silently dropped; that
// store reuses this CIBAConfig's Backend/SQLiteDSN (memory when unset) — a
// push failure is a sub-concern of the same CIBA storage backend, not a
// separate knob.
type CIBAPushConfig struct {
	Enabled    bool              `yaml:"enabled"`
	Endpoints  map[string]string `yaml:"endpoints"`   // client_id -> backchannel_token_delivery_uri
	Timeout    time.Duration     `yaml:"timeout"`     // per-push HTTP timeout; 0 → SDK default (5s)
	MaxRetries int               `yaml:"max_retries"` // delivery retries before dead-letter; 0 → SDK default (3)
}

// OIDCConfig holds OIDC-specific server toggles that don't belong to
// the OAuth store layer.
type OIDCConfig struct {
	// ResponseEncryption opts into JWE-encrypting id_token and
	// /userinfo responses for clients that register
	// id_token_encrypted_response_alg / userinfo_encrypted_response_alg.
	// The encrypter is stateless and reads each recipient's public
	// key from the client's registered JWKS (use:"enc"); no server-
	// side key material is required.
	ResponseEncryption ResponseEncryptionConfig `yaml:"response_encryption"`
	// SessionManagement opts into OpenID Connect Session Management 1.0 —
	// see SessionManagementConfig.
	SessionManagement SessionManagementConfig `yaml:"session_management"`
}

// SessionManagementConfig opts into OpenID Connect Session Management 1.0:
// `session_state` on /auth/login responses (openid scope only) + the
// GET /check_session_iframe OP iframe + its discovery advertisement.
// Default-off — byte-identical discovery/login-response shape otherwise.
type SessionManagementConfig struct {
	Enabled bool `yaml:"enabled"`
}

// ResponseEncryptionConfig selects the JWE response-encryption backend.
type ResponseEncryptionConfig struct {
	Enabled bool `yaml:"enabled"`
	// Backend: "" | "rsa" (RSA-OAEP-256) | "ecdh" (ECDH-ES[+A256KW]) |
	// "multi" (both, routed per-client by registered key type). All use
	// A256GCM content encryption.
	Backend string `yaml:"backend"`
}

// KeysConfig governs signing-key lifecycle.
