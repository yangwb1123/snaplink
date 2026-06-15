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
}

// SCIMGroupsConfig configures the SCIM /Groups <-> permissions.Role
// mapping.
type SCIMGroupsConfig struct {
	Enabled       bool   `yaml:"enabled"`
	GroupClientID string `yaml:"group_client_id"`
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
