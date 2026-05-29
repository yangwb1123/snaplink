// Package config loads SSO server configuration from a YAML file and exposes
// helpers that translate it into sso.Option values and per-authenticator
// settings. Code-only inputs (password verifier, SMS sender, CA pool, ...)
// are still wired in Go because they're not safely expressible in YAML.
package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso"
	"github.com/snaplink/sso/authenticators"
	"github.com/snaplink/sso/cors"
	"github.com/snaplink/sso/netpolicy"
	"github.com/snaplink/sso/netpolicy/memory"
	"github.com/snaplink/sso/permissions"
	"github.com/snaplink/sso/ratelimit"
)

// Default config file name searched if no path is given.
const DefaultFileName = "config.yaml"

// Config is the root configuration document.
type Config struct {
	Server             ServerConfig             `yaml:"server"`
	Authenticators     AuthenticatorsConfig     `yaml:"authenticators"`
	Logging            LoggingConfig            `yaml:"logging"`
	Audit              AuditConfig              `yaml:"audit"`
	Permissions        PermissionsConfig        `yaml:"permissions"`
	Network            NetworkConfig            `yaml:"network"`
	Clients            []ClientConfig           `yaml:"clients"`
	Admin              AdminConfig              `yaml:"admin"`
	Bootstrap          BootstrapConfig          `yaml:"bootstrap"`
	Snapshot           SnapshotConfig           `yaml:"snapshot"`
	Releases           ReleasesConfig           `yaml:"releases"`
	Geo                GeoConfig                `yaml:"geo"`
	Tenant             TenantConfig             `yaml:"tenant"`
	Security           SecurityConfig           `yaml:"security"`
	Metrics            MetricsConfig            `yaml:"metrics"`
	OAuth              OAuthConfig              `yaml:"oauth"`
	BackchannelLogout  BackchannelLogoutConfig  `yaml:"backchannel_logout"`
	ClientRegistration ClientRegistrationConfig `yaml:"client_registration"`
	Identity           IdentityConfig           `yaml:"identity"`
	WebAuthn           WebAuthnConfig           `yaml:"webauthn"`
	Registry           RegistryConfig           `yaml:"registry"`
	Risk               RiskConfig               `yaml:"risk"`
	MFA                MFAConfig                `yaml:"mfa"`
	Anomaly            AnomalyConfig            `yaml:"anomaly"`
	Cluster            ClusterConfig            `yaml:"cluster"`
	Keys               KeysConfig               `yaml:"keys"`
	CIBA               CIBAConfig               `yaml:"ciba"`
	OIDC               OIDCConfig               `yaml:"oidc"`
	SCIM               SCIMConfig               `yaml:"scim"`
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
type KeysConfig struct {
	Signing  SigningConfig     `yaml:"signing"`
	Rotation KeyRotationConfig `yaml:"rotation"`
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
type AnomalyConfig struct {
	Enabled bool `yaml:"enabled"`

	// IPSalt is hex-encoded bytes that salt the IP + UA hash
	// schemes. Deployment-stable; rotating breaks history
	// continuity. Recommended: 32 hex chars (16 random bytes).
	IPSalt string `yaml:"ip_salt"`

	// RecentLogin selects backend for the per-subject login
	// history store consumed by impossible_travel +
	// new_device + new_country detectors.
	RecentLogin AnomalyStoreConfig `yaml:"recent_login"`

	// IPFailure selects backend for the IP-keyed failure
	// counter consumed by brute_force_shadow.
	IPFailure AnomalyStoreConfig `yaml:"ip_failure"`

	// Detectors enables/configures each reference detector.
	Detectors AnomalyDetectorsConfig `yaml:"detectors"`

	// Runner tunes the AsyncAnomalyRunner worker pool.
	Runner AnomalyRunnerConfig `yaml:"runner"`

	// Retention wires the background prune loop against
	// RecentLogin + IPFailure stores. Mirrors the audit /
	// snapshot / push_approvals retention pattern.
	Retention AnomalyRetentionConfig `yaml:"retention"`
}

// AnomalyStoreConfig is the standard backend selector — memory
// for single-replica + tests, sqlite for cluster-shared state.
type AnomalyStoreConfig struct {
	Backend string                   `yaml:"backend"` // memory | sqlite
	SQLite  AnomalyStoreSQLiteConfig `yaml:"sqlite"`
}

type AnomalyStoreSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// AnomalyDetectorsConfig enables/tunes each reference detector.
// All disabled by default — operators opt in per-detector after
// reviewing the threshold trade-offs.
type AnomalyDetectorsConfig struct {
	ImpossibleTravel ImpossibleTravelDetectorConfig `yaml:"impossible_travel"`
	Velocity         VelocityDetectorConfig         `yaml:"velocity"`
	NewDevice        BaselineDetectorConfig         `yaml:"new_device"`
	NewCountry       BaselineDetectorConfig         `yaml:"new_country"`
	BruteForceShadow BruteForceShadowDetectorConfig `yaml:"brute_force_shadow"`
}

type ImpossibleTravelDetectorConfig struct {
	Enabled       bool          `yaml:"enabled"`
	MaxSpeedKmh   float64       `yaml:"max_speed_kmh"`  // 0 → SDK default 800
	HistoryWindow time.Duration `yaml:"history_window"` // 0 → SDK default 24h
}

type VelocityDetectorConfig struct {
	Enabled     bool `yaml:"enabled"`
	HourlyLimit int  `yaml:"hourly_limit"` // 0 disables hourly check
	DailyLimit  int  `yaml:"daily_limit"`  // 0 disables daily check
}

type BaselineDetectorConfig struct {
	Enabled              bool          `yaml:"enabled"`
	BaselineWindow       time.Duration `yaml:"baseline_window"`        // 0 → SDK default
	BootstrapGracePeriod time.Duration `yaml:"bootstrap_grace_period"` // 0 → SDK default
}

type BruteForceShadowDetectorConfig struct {
	Enabled              bool          `yaml:"enabled"`
	Window               time.Duration `yaml:"window"`                 // 0 → SDK default 1h
	FailureLimit         int           `yaml:"failure_limit"`          // 0 disables
	DistinctSubjectLimit int           `yaml:"distinct_subject_limit"` // 0 disables
}

type AnomalyRunnerConfig struct {
	QueueSize  int    `yaml:"queue_size"`  // 0 → SDK default 1024
	Workers    int    `yaml:"workers"`     // 0 → SDK default 4
	DropPolicy string `yaml:"drop_policy"` // drop_newest | block; default drop_newest
}

type AnomalyRetentionConfig struct {
	Enabled        bool          `yaml:"enabled"`
	RecentLoginAge time.Duration `yaml:"recent_login_age"` // 0 → 90d default; prune entries older than this
	IPFailureAge   time.Duration `yaml:"ip_failure_age"`   // 0 → 2h default; aggressive — counters are short-window
	Interval       time.Duration `yaml:"interval"`         // 0 → 1h default; loop cadence
}

// RiskConfig wires the reference rule-based [spi.RiskScorer] into
// cmd. Operators with non-trivial risk needs (impossible-travel,
// device fingerprint deltas, ML scoring) fork cmd and pass their
// own [spi.RiskScorer] via WithRiskScorer — this config covers the
// 80% case of declarative deny-by-IP / deny-by-country /
// allow-only-from-these.
//
// Evaluation is first-match-wins. The deny lists short-circuit
// before the allow lists, so a CIDR in both lists always denies.
// CountryAllowList rule fires only when geo enrichment populated
// req.Geo.CountryCode; DenyOnGeoMissing flips that to "no geo =
// deny" for deployments where geo is a hard requirement.
type RiskConfig struct {
	Enabled          bool     `yaml:"enabled"`
	IPDenyList       []string `yaml:"ip_deny_list"`
	IPAllowList      []string `yaml:"ip_allow_list"`
	CountryDenyList  []string `yaml:"country_deny_list"`
	CountryAllowList []string `yaml:"country_allow_list"`
	DenyOnGeoMissing bool     `yaml:"deny_on_geo_missing"`
}

// MFAConfig wires the step-up MFA orchestration that gates risk-
// flagged logins through a second factor. When [RiskConfig] (or any
// custom [spi.RiskScorer] supplied via the SDK) returns
// DecisionRequireMFA, /auth/login responds with mfa_required +
// challenge_id; the client posts the second factor to /auth/mfa
// and on success the server replays the standard token-mint response
// — the caller can't tell an MFA-gated login from a non-gated one.
//
// Without Provider + Challenge.Backend both wired, RequireMFA decays
// to Allow (back-compat: scorers may ship the decision ahead of the
// operator wiring the orchestration). Enabled=false short-circuits
// to the same fallthrough so flipping the flag is the only switch
// operators need to disable MFA cluster-wide.
//
// Provider.Kind selects the factor implementation. "totp" reuses
// the same TOTPAuthenticator + secret store the primary
// /auth/login?provider=totp flow uses — one enrollment, two roles
// (requires authenticators.totp.enabled). Custom factors (WebAuthn
// step-up, push notification, hardware FIDO2) implement
// [spi.MFAProvider] directly and bypass this YAML knob.
type MFAConfig struct {
	Enabled   bool               `yaml:"enabled"`
	Provider  MFAProviderConfig  `yaml:"provider"`
	Challenge MFAChallengeConfig `yaml:"challenge"`
}

// MFAProviderConfig selects the step-up factor implementation.
// "totp", "webauthn", and "push" ship as YAML-toggleable kinds;
// richer providers (IdP step-up, hardware OTP) ship in the SDK
// and embedders wire them via [sso.WithMFAProvider] directly.
//
// kind=multi composes several leaf kinds via the SDK's
// [defaultimpl.MultiMFAProvider] — operators wanting concurrent
// TOTP + WebAuthn factors set Kind="multi" + Kinds=[totp, webauthn]
// so users with a registered authenticator get the WebAuthn flow
// while users without one fall back to TOTP. Kinds dedup at
// construction; nested multi is rejected (no recursion).
//
// kind=push activates the reference [defaultimpl.PushMFAProvider]
// shipped with this binary — Begin records a PENDING approval and
// invokes the configured transport (today: log-only stub; operators
// fork cmd to drop in FCM/APNs/webhook). Verify polls the approval
// store until the user's device callback resolves the entry. See
// MFAPushConfig + cmd buildPushMFAProvider for the wiring.
type MFAProviderConfig struct {
	Kind  string        `yaml:"kind"`
	Kinds []string      `yaml:"kinds"` // used when Kind=multi
	Push  MFAPushConfig `yaml:"push"`  // used when Kind=push (or in Kinds)
}

// MFAPushConfig wires the push-notification MFA factor. Backend
// selects the PushApprovalStore implementation: memory for single-
// replica dev/demo; sqlite for cluster-shared state (Begin on
// replica A → callback on replica B → Verify on replica C all
// see the same approval row).
//
// Transport selects how the approval id reaches the user's device.
// "log" is the default reference transport — it writes the
// approval id + subject to the server's structured log, matching
// the SMS/email "stub" pattern. Production deployments fork cmd to
// drop in FCM/APNs/webhook; the SDK's PushTransport interface is
// stable.
//
// PollInterval and MaxWait tune the Verify polling cadence + the
// total wait the server holds /auth/mfa open. MaxWait MUST be <=
// the parent MFAChallengeTTL; otherwise the challenge expires
// mid-Verify and operators see ErrMFAChallengeNotFound instead of
// ErrPushApprovalTimeout. cmd validates this at boot.
//
// The user-device callback that resolves a PushApproval (PENDING
// → APPROVED/DENIED) is intentionally NOT shipped from cmd —
// authentication, transport-specific deep-link handling, and the
// callback URL itself are operator-decisions. Operators build the
// handler against the SDK's [defaultimpl.PushApprovalStore]
// SetStatus method and route it through their own gateway.
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
type RegistryConfig struct {
	Backend        string        `yaml:"backend"` // "memory" | "etcd"
	ServiceID      string        `yaml:"service_id"`
	ServiceAddress string        `yaml:"service_address"`
	ServiceTags    []string      `yaml:"service_tags"`
	ServiceTTL     time.Duration `yaml:"service_ttl"`

	EtcdEndpoints   []string      `yaml:"etcd_endpoints"`
	EtcdPrefix      string        `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration `yaml:"etcd_dial_timeout"`
	EtcdUsername    string        `yaml:"etcd_username"`
	EtcdPassword    string        `yaml:"etcd_password"`
}

// WebAuthnConfig opts into CTAP/FIDO2 ceremony endpoints
// (/webauthn/{registration,login}/{begin,finish}). Without Enabled
// the routes aren't mounted and the subsystem is dark — no goroutines,
// no DB, no transitive go-webauthn dependency at runtime.
//
// RPID must be the registrable domain suffix of the origin the user
// agent will report (e.g. "example.com" for an SSO server at
// sso.example.com). RPOrigins MUST be fully qualified including the
// scheme. Misconfiguring either breaks attestation verification at
// finish time.
//
// Storage chooses where credentials + ceremony sessions live. memory
// is single-replica only; sqlite shares both across the cluster.
// Sessions and credentials use independent DSNs so operators can
// retain a short-lived in-memory session store while still persisting
// credentials.
type WebAuthnConfig struct {
	Enabled       bool                  `yaml:"enabled"`
	RPID          string                `yaml:"rp_id"`
	RPDisplayName string                `yaml:"rp_display_name"`
	RPOrigins     []string              `yaml:"rp_origins"`
	SessionTTL    time.Duration         `yaml:"session_ttl"`
	Storage       WebAuthnStorageConfig `yaml:"storage"`
}

// WebAuthnStorageConfig selects the substrate for the WebAuthn
// UserStore + SessionStore. Both default to memory; operators
// running multi-replica turn on sqlite for each (independent DSNs
// so a fast-disk credential store can coexist with an in-memory
// session store on the same host).
type WebAuthnStorageConfig struct {
	Users    WebAuthnBackendConfig `yaml:"users"`
	Sessions WebAuthnBackendConfig `yaml:"sessions"`
}

// WebAuthnBackendConfig is the memory|sqlite selector + DSN for a
// single WebAuthn store.
type WebAuthnBackendConfig struct {
	Backend string                      `yaml:"backend"` // memory | sqlite
	SQLite  WebAuthnBackendSQLiteConfig `yaml:"sqlite"`
}

type WebAuthnBackendSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// IdentityConfig selects the substrate for User + Client persistence
// (the two long-lived identity-domain stores). Default memory keeps
// the simple-bootstrap story but loses every DCR-registered client
// and every password-authenticator user on restart. SQLite persists
// across restarts and (with shared DSN) across replicas via OS file
// locking.
//
// Independent of [OAuthConfig.Backend] — the two domains can be
// mixed (e.g. SQLite identity + memory OAuth state for low-traffic
// CLI deployments) by setting backends separately.
type IdentityConfig struct {
	Backend string               `yaml:"backend"` // memory | sqlite
	SQLite  IdentitySQLiteConfig `yaml:"sqlite"`
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
type OAuthConfig struct {
	// Backend selects the storage substrate for auth_code,
	// refresh_token, and device_code. "memory" (default) is in-
	// process; "sqlite" persists across restarts and shares state
	// across processes that point at the same file. PAR remains
	// memory-only (no SQLite backend yet). Each individually-enabled
	// store inherits this choice unless the store's own Backend
	// override is set.
	Backend      string                `yaml:"backend"`
	SQLite       OAuthSQLiteConfig     `yaml:"sqlite"`
	AuthCode     OAuthStoreConfig      `yaml:"auth_code"`
	RefreshToken OAuthStoreConfig      `yaml:"refresh_token"`
	DeviceCode   OAuthDeviceCodeConfig `yaml:"device_code"`
	PAR          OAuthStoreConfig      `yaml:"par"`
	JAR          OAuthJARConfig        `yaml:"jar"`
	JARM         OAuthJARMConfig       `yaml:"jarm"`
	Compliance   OAuthComplianceConfig `yaml:"compliance"`
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
// `file:/var/lib/sso/sso.db?_journal=WAL&_busy_timeout=5000`.
// Each store opens its own *sql.DB pool against the same file;
// SQLite's OS-level file lock coordinates writes.
type OAuthSQLiteConfig struct {
	DSN string `yaml:"dsn"`
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

// OAuthStoreConfig is the shared shape for the simple TTL-only stores.
type OAuthStoreConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
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
}

// MetricsConfig toggles Prometheus instrumentation. When Enabled,
// cmd/sso-server constructs a metrics.Metrics with its own Registry,
// wires sso.WithMetrics so request count / latency / login / token /
// risk counters all fire, and exposes /metrics for scraping.
//
// When an audit AsyncSink is also wired (audit.async.enabled), the
// matching metrics.AsyncSinkCollector is registered automatically so
// drop counters and queue depth land on the same registry.
type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

// SecurityConfig groups operator-facing security tunables that hook
// into the Server's middleware stack (body limit + rate limit + CORS).
// Each sub-block is opt-in — leaving the block out (or setting
// Enabled=false) skips the corresponding middleware with zero
// overhead. See AGENTS.md §8d / §8f / §8g for the runtime behavior
// of each.
type SecurityConfig struct {
	BodyLimit      BodyLimitConfig      `yaml:"body_limit"`
	RateLimit      RateLimitConfig      `yaml:"rate_limit"`
	CORS           CORSConfig           `yaml:"cors"`
	DPoPNonce      DPoPNonceConfig      `yaml:"dpop_nonce"`
	JTIReplay      JTIReplayConfig      `yaml:"jti_replay"`
	AccountLockout AccountLockoutConfig `yaml:"account_lockout"`
	MTLS           MTLSConfig           `yaml:"mtls"`
}

// MTLSConfig opts into RFC 8705 mTLS-bound access tokens.
//
// Backend choice:
//   - "" / "tls" (default) — DefaultTLSPeerCertExtractor; reads
//     r.TLS.PeerCertificates[0]. Works only when the binary
//     terminates TLS itself (--tls-cert/--tls-key).
//   - "header" — HeaderClientCertExtractor; parses the forwarded
//     client cert out of an HTTP header set by a TLS-terminating
//     reverse proxy. Pair with Header.Name + Header.Encoding.
//     SECURITY: the header MUST be stripped from public traffic at
//     the edge; otherwise an attacker can mint mTLS-bound tokens
//     for any cert without holding the matching key. Treat the
//     header like X-Forwarded-For — trusted-edge only.
//
// With the extractor wired, /token binds cnf.x5t#S256 onto issued
// tokens when the request presents a client cert, and resource
// endpoints (/userinfo) enforce the binding. Discovery doc flips
// mtls_endpoint_aliases on automatically.
type MTLSConfig struct {
	Enabled bool             `yaml:"enabled"`
	Backend string           `yaml:"backend"`
	Header  MTLSHeaderConfig `yaml:"header"`
}

// MTLSHeaderConfig configures the header-backend extractor. Common
// edges:
//   - nginx ($ssl_client_escaped_cert):  X-SSL-Client-Cert / url-pem
//   - AWS ALB mTLS:                      X-Amzn-Mtls-Clientcert / url-pem
//   - Apache mod_ssl (SSL_CLIENT_CERT):  Ssl-Client-Cert / pem
//   - custom base64-DER edge:                            / base64-der
//
// Encoding values: "url-pem" (default), "pem", "base64-der". Empty
// string is treated as "url-pem".
type MTLSHeaderConfig struct {
	Name     string `yaml:"name"`
	Encoding string `yaml:"encoding"`
}

// AccountLockoutConfig opts into per-account lockout on /auth/login.
// After MaxFailures bad attempts within FailureWindow, the account is
// locked for LockoutDuration — subsequent logins return immediately
// without consulting authenticators (mitigates credential stuffing
// and bcrypt-CPU starvation attacks).
//
// All three numeric fields fall back to SDK defaults (5 failures,
// 15min lockout, 1h sliding window) when <= 0.
//
// Backend choice:
//   - "" / "memory" (default) — single-replica; an attacker rotating
//     targets across replicas evades each replica's local threshold.
//   - "sqlite" — cluster-shared file; the counter sums failures
//     across every replica so the threshold is global.
//
// Redis / Memcached backends still need to be wired via the SDK
// directly for high-write workloads where SQLite's lock contention
// would dominate /auth/login latency.
type AccountLockoutConfig struct {
	Enabled         bool                       `yaml:"enabled"`
	Backend         string                     `yaml:"backend"`
	SQLite          AccountLockoutSQLiteConfig `yaml:"sqlite"`
	MaxFailures     int                        `yaml:"max_failures"`
	LockoutDuration time.Duration              `yaml:"lockout_duration"`
	FailureWindow   time.Duration              `yaml:"failure_window"`
}

type AccountLockoutSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// JTIReplayConfig opts into RFC 9101 §10.8 + RFC 9449 §11.1 jti-based
// replay protection on JWTs the server consumes (JAR request objects;
// DPoP proofs and JWT bearer client assertions follow the same store).
// Without it, signature-valid JWTs are accepted once per validation —
// the spec-permitted but weaker fallback.
//
// Backend choice:
//   - "" / "memory" (default) — single-replica only; a jti seen on
//     replica A is unknown to replica B and the defense forks.
//   - "sqlite" — shared file; multi-replica safe. Requires SQLite.DSN.
//
// For Redis or other shared backends, operators wire their own
// implementation via sso.WithJTIReplayStore directly.
type JTIReplayConfig struct {
	Enabled bool               `yaml:"enabled"`
	Backend string             `yaml:"backend"`
	SQLite  JTIReplaySQLiteCfg `yaml:"sqlite"`
}

// JTIReplaySQLiteCfg configures the SQLite-backed jti replay store.
type JTIReplaySQLiteCfg struct {
	DSN string `yaml:"dsn"`
}

// DPoPNonceConfig opts into RFC 9449 §8 server-issued nonces. When
// Enabled, every DPoP-bearing request must echo a fresh nonce in
// the proof JWT — the AS/RS challenges with `use_dpop_nonce` and
// delivers a nonce via the `DPoP-Nonce` response header on each
// rejection.
//
// KeyFile points at a file containing the HMAC signing key. Required
// in multi-replica deployments so nonces issued by one replica
// verify on every other; single-replica setups may leave it empty
// to auto-generate a 32-byte process-local secret on boot. The
// file's first 64 hex chars (or first 32 raw bytes) seed the key;
// anything beyond that is ignored.
//
// TTL bounds nonce freshness; <= 0 falls back to the SDK default
// (5 minutes).
type DPoPNonceConfig struct {
	Enabled bool          `yaml:"enabled"`
	KeyFile string        `yaml:"key_file"`
	TTL     time.Duration `yaml:"ttl"`
}

// BodyLimitConfig caps request body size. MaxBytes=0 disables the
// global limit (sso.WithBodyLimit is not wired). Typical production
// value: 1048576 (1 MiB) — generous for any auth-flow payload,
// blocks gigabyte-class DoS.
//
// Overrides applies a per-prefix override (longest-match wins). Use
// a value of 0 in an override to mean "unlimited for this prefix"
// — the escape hatch for endpoints that legitimately accept large
// bodies (PAR request objects, WebAuthn attestation blobs) while
// keeping a global cap on everything else.
type BodyLimitConfig struct {
	MaxBytes  int64                     `yaml:"max_bytes"`
	Overrides []BodyLimitOverrideConfig `yaml:"overrides"`
}

// BodyLimitOverrideConfig is one entry in BodyLimitConfig.Overrides.
// Prefix is matched against the request path; the longest matching
// prefix's MaxBytes wins. Zero means "unlimited for this prefix".
type BodyLimitOverrideConfig struct {
	Prefix   string `yaml:"prefix"`
	MaxBytes int64  `yaml:"max_bytes"`
}

// RateLimitConfig configures the token-bucket middleware. Default
// values apply to every path not matched by a Prefixes entry; per-
// prefix overrides tighten the bucket for hot endpoints like
// /auth/login.
//
// Backend choice:
//   - "" / "memory" (default) — single-replica only.
//   - "sqlite" — cluster-shared bucket state; a request that drained
//     the bucket on replica A is visible to replica B before B
//     grants the next request. SQLite handles low-thousands writes/sec
//     comfortably; Redis is the recommended next step for SaaS-scale
//     auth-heavy workloads.
type RateLimitConfig struct {
	Enabled       bool                    `yaml:"enabled"`
	Backend       string                  `yaml:"backend"`
	SQLite        RateLimitSQLiteConfig   `yaml:"sqlite"`
	DefaultPerSec float64                 `yaml:"default_per_sec"`
	DefaultBurst  int                     `yaml:"default_burst"`
	Prefixes      []RateLimitPrefixConfig `yaml:"prefixes"`
}

type RateLimitSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// RateLimitPrefixConfig is one path-prefix rule inside RateLimitConfig.
// Order matters — first match wins, evaluated in declaration order.
type RateLimitPrefixConfig struct {
	Prefix string  `yaml:"prefix"`
	PerSec float64 `yaml:"per_sec"`
	Burst  int     `yaml:"burst"`
}

// CORSConfig configures the CORS middleware. AllowedOrigins is the
// only required field; leaving it empty disables CORS even when
// Enabled=true (the middleware reduces to identity).
type CORSConfig struct {
	Enabled          bool          `yaml:"enabled"`
	AllowedOrigins   []string      `yaml:"allowed_origins"`
	AllowedMethods   []string      `yaml:"allowed_methods"`
	AllowedHeaders   []string      `yaml:"allowed_headers"`
	ExposedHeaders   []string      `yaml:"exposed_headers"`
	AllowCredentials bool          `yaml:"allow_credentials"`
	MaxAge           time.Duration `yaml:"max_age"`
}

// AdminConfig toggles the admin control plane. When Enabled is true the
// sso-server mounts the four admin gRPC services and the grpc-gateway
// REST proxy under /api/v1/admin/. APIRESTEnabled defaults to true when
// Enabled is true; set false to expose admin gRPC-only.
type AdminConfig struct {
	Enabled        bool `yaml:"enabled"`
	APIRESTEnabled bool `yaml:"api_rest_enabled"`
}

// BootstrapConfig configures the first-run init Runner. StatePath is the
// JSON file the file-backed Tracker writes to (defaults to "bootstrap.json"
// when empty). Set Disabled=true to skip the runner entirely (useful in
// tests or when an external orchestrator owns init).
type BootstrapConfig struct {
	Disabled       bool   `yaml:"disabled"`
	StatePath      string `yaml:"state_path"`
	AdminUserID    string `yaml:"admin_user_id"`
	AdminClientID  string `yaml:"admin_client_id"`
	AdminRoleCode  string `yaml:"admin_role_code"`
	AdminClientApp string `yaml:"admin_client_app"`

	// AdminPasswordFile is an optional path where the generated
	// admin password is written (mode 0600) on first boot in
	// ADDITION to the stdout banner. Containerized deployments
	// where stdout is async-shipped to a log sink frequently lose
	// the boot banner; pointing at a tmpfs / secret-volume path
	// guarantees retrievability. The file is written once per
	// generation; if the bootstrap step doesn't re-run (already
	// at high-water), the file is NOT touched.
	AdminPasswordFile string              `yaml:"admin_password_file"`
	Lock              BootstrapLockConfig `yaml:"lock"`
}

// BootstrapLockConfig configures the distributed lock the Runner takes
// before applying steps. Backend selects which implementation:
//
//   - "" or "noop"  → no coordination (single-replica default)
//   - "file"        → flock(2) on Lock.File.Path; single-host multi-process
//   - "etcd"        → etcd lease + Txn; multi-replica HA
//
// Key namespaces the lock; defaults to "/sso/bootstrap/<namespace>".
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

// ReleaseProbeHTTPConfig configures the http probe.
type ReleaseProbeHTTPConfig struct {
	URL string `yaml:"url"`
}

// GeoConfig configures the IP → geo enrichment middleware. When
// Enabled is false the SSO server skips installing the middleware
// entirely. Backend selects which geo.Provider implementation
// supplies the lookups.
//
// The static backend is in-process and useful for small operator
// curated tables (private RFC1918 ranges, regional office
// blocks). Real geo coverage typically wants a future maxmind
// backend stacked behind static — see geo/ docs.
type GeoConfig struct {
	Enabled bool            `yaml:"enabled"`
	Backend string          `yaml:"backend"` // "static" (default)
	Static  GeoStaticConfig `yaml:"static"`
	// LookupTimeout caps a single Lookup in the request hot path.
	// Defaults to sso.DefaultGeoLookupTimeout (200ms) when zero.
	LookupTimeout time.Duration `yaml:"lookup_timeout"`
}

// GeoStaticConfig configures the in-process CIDR → GeoInfo table.
// Entries are added in declaration order; longest-prefix match
// wins regardless.
type GeoStaticConfig struct {
	Entries []GeoStaticEntry `yaml:"entries"`
}

// GeoStaticEntry is one CIDR → GeoInfo mapping.
type GeoStaticEntry struct {
	CIDR                string `yaml:"cidr"`
	CountryCode         string `yaml:"country_code"`
	Region              string `yaml:"region"`
	City                string `yaml:"city"`
	TimeZone            string `yaml:"time_zone"`
	RecommendedLanguage string `yaml:"recommended_language"` // BCP-47
}

// TenantConfig configures the multi-tenant + multi-domain
// routing layer. When Enabled is false the SSO server skips
// installing the tenant middleware entirely. Backend selects
// which tenant.Store implementation to use — "memory" for
// single-replica dev / tests, "sqlite" for cluster-shared state
// (admin SetTenantStatus on replica A surfaces on every replica
// after the suspension-check cache TTL elapses).
//
// Tenants + Domains can be seeded via TenantConfig.Tenants and
// TenantConfig.Domains for embedded deployments. Operators
// running an admin-managed setup can leave both empty and
// populate via the admin TenantService RPCs.
type TenantConfig struct {
	Enabled          bool                        `yaml:"enabled"`
	Backend          string                      `yaml:"backend"` // memory | sqlite
	SQLite           TenantSQLiteConfig          `yaml:"sqlite"`
	LookupTimeout    time.Duration               `yaml:"lookup_timeout"`
	IncludeSuspended bool                        `yaml:"include_suspended"`
	Tenants          []TenantSeedConfig          `yaml:"tenants"`
	Domains          []TenantDomainConfig        `yaml:"domains"`
	SuspensionCheck  TenantSuspensionCheckConfig `yaml:"suspension_check"`
}

// TenantSQLiteConfig is the SQLite backend's DSN.
type TenantSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// TenantSuspensionCheckConfig opts the server into the active
// post-validation gate: tokens whose owning client.TenantID maps to
// a now-Suspended tenant fail validation. Without this, a
// suspension only blocks NEW issuance — bearers minted before the
// flip keep working until natural expiry.
//
// CacheTTL bounds how long a tenant's status may be cached between
// lookups; <= 0 falls back to the SDK default (30s).
type TenantSuspensionCheckConfig struct {
	Enabled  bool          `yaml:"enabled"`
	CacheTTL time.Duration `yaml:"cache_ttl"`
}

// TenantSeedConfig declares a tenant to PutTenant on boot.
type TenantSeedConfig struct {
	ID       string            `yaml:"id"`
	Slug     string            `yaml:"slug"`
	Name     string            `yaml:"name"`
	Status   string            `yaml:"status"` // "active" (default) | "suspended"
	Settings map[string]string `yaml:"settings"`
}

// TenantDomainConfig declares a hostname → tenant mapping.
type TenantDomainConfig struct {
	Hostname        string            `yaml:"hostname"`
	TenantID        string            `yaml:"tenant_id"`
	DefaultClientID string            `yaml:"default_client_id"`
	IsApex          bool              `yaml:"is_apex"`
	Branding        map[string]string `yaml:"branding"`
}

// PermissionsConfig configures role/menu authorization. When disabled,
// the /permissions/me, /menus/me, /roles/me endpoints reply 501.
//
// Backend selects which permissions.Provider implementation is wired:
// memory keeps the process-local map (single-replica only); sqlite
// shares roles + assignments + menus across the cluster (admin
// AddRole / AssignRoles / SetMenus on one replica surface on every
// replica's next lookup). Apps + UserRoles seeds run against the
// chosen backend at boot — duplicate seeds across replicas pointed
// at the same SQLite DSN deduplicate via the ON CONFLICT UPSERT
// the backend uses.
type PermissionsConfig struct {
	Enabled      bool                    `yaml:"enabled"`
	Backend      string                  `yaml:"backend"` // memory | sqlite
	SQLite       PermissionsSQLiteConfig `yaml:"sqlite"`
	EmbedInLogin bool                    `yaml:"embed_in_login"`
	Apps         []AppPermissionsConfig  `yaml:"apps"`
	UserRoles    []UserRoleAssignment    `yaml:"user_roles"`
}

// PermissionsSQLiteConfig is the SQLite backend's DSN.
type PermissionsSQLiteConfig struct {
	DSN string `yaml:"dsn"`
}

// AppPermissionsConfig declares the roles and menu tree for one APP. Roles
// listed here are referenced by UserRoleAssignment.Roles for assignment.
type AppPermissionsConfig struct {
	ClientID string               `yaml:"client_id"`
	Roles    []permissions.Role   `yaml:"roles"`
	Menus    permissions.MenuTree `yaml:"menus"`
}

// UserRoleAssignment binds a user to a set of role codes within a given APP.
type UserRoleAssignment struct {
	UserID   string   `yaml:"user_id"`
	ClientID string   `yaml:"client_id"`
	Roles    []string `yaml:"roles"`
}

// BuildPermissionProvider materializes a permissions.MemoryProvider from the
// static config. Returns nil when permissions are disabled.
func (c *Config) BuildPermissionProvider() *permissions.MemoryProvider {
	if !c.Permissions.Enabled {
		return nil
	}
	ctx := context.Background()
	p := permissions.NewMemoryProvider()
	for _, app := range c.Permissions.Apps {
		for _, role := range app.Roles {
			_ = p.AddRole(ctx, app.ClientID, role)
		}
		if app.Menus != nil {
			_ = p.SetMenus(ctx, app.ClientID, app.Menus)
		}
	}
	for _, a := range c.Permissions.UserRoles {
		_ = p.AssignRoles(ctx, a.UserID, a.ClientID, a.Roles)
	}
	return p
}

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
// shape: file:/var/lib/sso/audit.db?_journal=WAL&_busy_timeout=5000
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

// NetworkConfig configures the network-classification control plane.
//
//   - Enabled=true wires a Store and Classifier into the Server.
//   - APIEnabled=true additionally mounts the REST endpoints
//     (/api/v1/netpolicy/...).
//   - Store selects the backend; "memory" (default) is in-process, "etcd"
//     reads from an etcd cluster (see EtcdEndpoints below). The etcd
//     backend is materialized by cmd/sso-server, NOT by [Config.BuildNetworkStore]
//     — the config package keeps the etcd transitive dep out of the SPI.
//   - Policies is the seed list applied at startup. Operators can also add /
//     update / delete policies live via the API.
type NetworkConfig struct {
	Enabled         bool                `yaml:"enabled"`
	APIEnabled      bool                `yaml:"api_enabled"`
	Store           string              `yaml:"store"` // "memory" | "etcd"
	EtcdEndpoints   []string            `yaml:"etcd_endpoints"`
	EtcdPrefix      string              `yaml:"etcd_prefix"`
	EtcdDialTimeout time.Duration       `yaml:"etcd_dial_timeout"`
	EtcdUsername    string              `yaml:"etcd_username"`
	EtcdPassword    string              `yaml:"etcd_password"`
	Policies        []NetworkPolicySeed `yaml:"policies"`
}

// NetworkPolicySeed is the YAML projection of netpolicy.Policy with only the
// fields operators are allowed to set declaratively.
type NetworkPolicySeed struct {
	Name                string            `yaml:"name"`
	CIDRs               []string          `yaml:"cidrs"`
	Hostnames           []string          `yaml:"hostnames"`
	Priority            int32             `yaml:"priority"`
	AdvertisedBaseURL   string            `yaml:"advertised_base_url"`
	AdvertisedJWKSURL   string            `yaml:"advertised_jwks_url"`
	AdvertisedLogoutURL string            `yaml:"advertised_logout_url"`
	Metadata            map[string]string `yaml:"metadata"`
}

// BuildNetworkStore returns a netpolicy.Store configured per NetworkConfig
// and seeds it with the declared policies. Returns nil when network is
// disabled. Callers own the returned store's lifetime — Close it at
// shutdown.
//
// The etcd backend intentionally errors here so the config package stays
// free of the etcd transitive dep. Operators wiring network.store=etcd
// MUST construct the [netpolicy/etcd.Store] inside cmd/sso-server (or
// any embedder) and feed seeds through [ApplyNetworkPolicySeeds].
func (c *Config) BuildNetworkStore() (netpolicy.Store, error) {
	if !c.Network.Enabled {
		return nil, nil
	}
	var store netpolicy.Store
	switch strings.ToLower(c.Network.Store) {
	case "", "memory":
		store = memory.New()
	case "etcd":
		return nil, errors.New("config: network.store=etcd: construct via cmd/sso-server directly (needs endpoints + dial timeout)")
	default:
		return nil, fmt.Errorf("config: unknown network.store %q", c.Network.Store)
	}
	if err := ApplyNetworkPolicySeeds(context.Background(), store, c.Network.Policies); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

// ApplyNetworkPolicySeeds applies declarative NetworkPolicySeed entries
// to any netpolicy.Store via its [netpolicy.Store.Apply] method. Used
// by [Config.BuildNetworkStore] for the memory path and by cmd
// directly for the etcd path so both stay in lockstep on seed
// semantics + error wrapping.
//
// Returns a wrapped error identifying the offending policy on the
// first failure; the caller is responsible for closing the partially
// populated store.
func ApplyNetworkPolicySeeds(ctx context.Context, store netpolicy.Store, seeds []NetworkPolicySeed) error {
	for _, seed := range seeds {
		if _, err := store.Apply(ctx, &netpolicy.Policy{
			Name:                seed.Name,
			CIDRs:               seed.CIDRs,
			Hostnames:           seed.Hostnames,
			Priority:            seed.Priority,
			AdvertisedBaseURL:   seed.AdvertisedBaseURL,
			AdvertisedJWKSURL:   seed.AdvertisedJWKSURL,
			AdvertisedLogoutURL: seed.AdvertisedLogoutURL,
			Metadata:            seed.Metadata,
		}); err != nil {
			return fmt.Errorf("config: seed policy %q: %w", seed.Name, err)
		}
	}
	return nil
}

// ServerConfig holds top-level Server tunables.
type ServerConfig struct {
	Issuer               string        `yaml:"issuer"`
	BaseURL              string        `yaml:"base_url"`
	Listen               string        `yaml:"listen"`
	SessionTTL           time.Duration `yaml:"session_ttl"`
	TokenTTL             time.Duration `yaml:"token_ttl"`
	DefaultTokenStrategy string        `yaml:"default_token_strategy"`
	// DiscoveryDocCacheTTL caches the marshaled discovery document
	// + its ETag for this long, keyed by base URL. Set to 0 to
	// disable both the cache and the response Cache-Control / ETag
	// headers (useful when an upstream CDN owns caching). Defaults
	// to the SDK constant when unset (5s).
	DiscoveryDocCacheTTL time.Duration `yaml:"discovery_doc_cache_ttl"`

	// DiscoveryCacheTTL caches the in-process clientDiscoverySnapshot
	// (the projection of opt-in features + client store union) for
	// this long. Separate from the marshaled-body cache above —
	// reuses the snapshot across multiple base-URL renders. Defaults
	// to the SDK constant when unset (5s).
	DiscoveryCacheTTL time.Duration `yaml:"discovery_cache_ttl"`

	// JWKSCacheTTL caches the JWKS response body + its ETag for
	// this long. RPs and downstream resource servers honor the
	// Cache-Control: max-age header so this controls how aggressively
	// they refresh the signing-key set. Lower during planned key
	// rotation, higher otherwise. Defaults to the SDK constant
	// when unset (5 minutes).
	JWKSCacheTTL time.Duration `yaml:"jwks_cache_ttl"`

	// SignedMetadata adds an RFC 8414 §2.1 signed_metadata field
	// to /.well-known/openid-configuration. The configured default
	// TokenIssuer must satisfy the oidc.MetadataSigner interface (the
	// built-in Ed25519JWTIssuer does); otherwise this flag is a
	// no-op and an info log is emitted at startup.
	SignedMetadata bool `yaml:"signed_metadata"`

	// OAuth21StrictMode flips the AS into draft-OAuth-2.1 strict
	// posture: rejects response_type=token (implicit), drops `plain`
	// from code_challenge_methods_supported (S256-only), and gates
	// every /auth/login on PKCE regardless of per-client opt-out.
	// Discovery doc adjusts accordingly so RPs see the actual
	// posture and don't request features they'd fail.
	OAuth21StrictMode bool `yaml:"oauth_21_strict_mode"`

	// PairwiseSubjects opts into OIDC Core §8 pairwise subject
	// identifiers. Per-client subject_type metadata gates use:
	// SubjectType="pairwise" on a Client makes the AS mint an opaque
	// per-sector sub instead of the local one. Memory backend only;
	// multi-replica deployments need a shared backend.
	PairwiseSubjects PairwiseSubjectsConfig `yaml:"pairwise_subjects"`

	// MaxClockSkew widens the exp/nbf validation window the wired
	// Ed25519JWTIssuer accepts on inbound JWTs (RFC 7519 §4.1.4-5
	// leeway). Useful when AS and resource server clocks drift.
	// 0 = exact comparison (no leeway). Recommended production
	// value: 30s-2min.
	MaxClockSkew time.Duration `yaml:"max_clock_skew"`

	// SupportedACRValues advertises the OIDC `acr_values_supported`
	// claim on the discovery doc. RPs use it to know which Authentication
	// Context Class References they can demand via `acr_values` /
	// `claims.id_token.acr`. Empty list omits the claim entirely.
	SupportedACRValues []string `yaml:"supported_acr_values"`

	// OperatorMetadata surfaces the OIDC Discovery §3 op_policy_uri,
	// op_tos_uri, and service_documentation fields. RPs link them
	// from consent screens / integrator docs. Each field is
	// independently optional — empty values are omitted.
	OperatorMetadata OperatorMetadataConfig `yaml:"operator_metadata"`
}

// PairwiseSubjectsConfig wires WithPairwiseSubjectStore +
// WithPairwiseSalt. Salt MUST be deployment-stable; prefer SaltFile
// so it doesn't end up in YAML/git. Empty salt at enable time falls
// back to security.DefaultPairwiseSalt (publicly known — fine for tests
// only).
//
// Backend choice:
//   - "" / "memory" (default) — single-replica only; a pairwise sub
//     minted on replica A is unknown to replica B at /userinfo time.
//   - "sqlite" — cluster-shared file; reverse lookup works on every
//     replica.
type PairwiseSubjectsConfig struct {
	Enabled  bool                      `yaml:"enabled"`
	Salt     string                    `yaml:"salt"`
	SaltFile string                    `yaml:"salt_file"`
	Backend  string                    `yaml:"backend"`
	SQLite   PairwiseSubjectsSQLiteCfg `yaml:"sqlite"`
}

type PairwiseSubjectsSQLiteCfg struct {
	DSN string `yaml:"dsn"`
}

// OperatorMetadataConfig groups the three Discovery §3 informational
// URIs. All three fields are independently optional; the SDK omits
// each one whose value is empty.
type OperatorMetadataConfig struct {
	PolicyURI            string `yaml:"policy_uri"`
	TosURI               string `yaml:"tos_uri"`
	ServiceDocumentation string `yaml:"service_documentation"`
}

// LoggingConfig controls the embedded logger.
type LoggingConfig struct {
	Level string `yaml:"level"` // debug | info | error
}

// ClientConfig is a registered relying-party application.
//
// AllowedAuthenticators (whitelist of provider names) and TokenStrategy (which
// registered TokenIssuer to use) drive the per-app dynamic policy: same SDK,
// different login flows + different token formats per APP.
type ClientConfig struct {
	ID                    string   `yaml:"id"`
	Secret                string   `yaml:"secret"`
	Name                  string   `yaml:"name"`
	RedirectURIs          []string `yaml:"redirect_uris"`
	AllowedScopes         []string `yaml:"allowed_scopes"`
	AllowedAuthenticators []string `yaml:"allowed_authenticators"`
	TokenStrategy         string   `yaml:"token_strategy"`
	Active                bool     `yaml:"active"`
	// TenantID binds this client to one tenant; empty = no tenant
	// affinity (single-tenant deployments + the platform-admin
	// client). When set, login + token endpoints reject requests
	// whose resolved tenant doesn't match this id.
	TenantID string `yaml:"tenant_id"`

	// Below fields mirror the SDK Client struct exactly — the cmd's
	// YAML→Client seeding used to drop them silently, leaving SDK
	// features (RFC 8707 resource allowlist, RFC 9101 JAR client
	// JWKS, OIDC pairwise sub, FAPI 2.0 require-JAR/PAR, OIDC FCL +
	// BCL, per-client TTLs) unreachable via YAML. Every field is
	// optional; omit to use server-wide defaults.
	RequirePKCE                      bool          `yaml:"require_pkce,omitempty"`
	AllowedResources                 []string      `yaml:"allowed_resources,omitempty"`
	PostLogoutRedirectURIs           []string      `yaml:"post_logout_redirect_uris,omitempty"`
	AllowedAuthorizationDetailsTypes []string      `yaml:"allowed_authorization_details_types,omitempty"`
	RefreshTokenTTL                  time.Duration `yaml:"refresh_token_ttl,omitempty"`
	AccessTokenTTL                   time.Duration `yaml:"access_token_ttl,omitempty"`
	AllowedPKCEMethods               []string      `yaml:"allowed_pkce_methods,omitempty"`
	RequireSignedRequestObject       bool          `yaml:"require_signed_request_object,omitempty"`
	RequirePAR                       bool          `yaml:"require_par,omitempty"`
	AllowedRequestURIs               []string      `yaml:"allowed_request_uris,omitempty"`
	DeviceCodeTTL                    time.Duration `yaml:"device_code_ttl,omitempty"`
	DeviceCodePollInterval           time.Duration `yaml:"device_code_poll_interval,omitempty"`
	UserinfoSignedResponseAlg        string        `yaml:"userinfo_signed_response_alg,omitempty"`
	BackchannelLogoutURI             string        `yaml:"backchannel_logout_uri,omitempty"`
	SubjectType                      string        `yaml:"subject_type,omitempty"`
	SectorIdentifierURI              string        `yaml:"sector_identifier_uri,omitempty"`
	FrontchannelLogoutURI            string        `yaml:"frontchannel_logout_uri,omitempty"`
	JWKS                             []ClientJWK   `yaml:"jwks,omitempty"`
}

// ClientJWK mirrors sso.JWK in YAML-friendly form. Used to register
// the client's verification keys for RFC 9101 JAR / RFC 7521+7523
// private_key_jwt. The set of supported parameters matches sso.JWK
// (Ed25519 via OKP+Crv+X, RSA via N+E).
type ClientJWK struct {
	Kty string `yaml:"kty"` // "RSA" | "EC" | "OKP"
	Kid string `yaml:"kid"`
	Use string `yaml:"use,omitempty"` // "sig" | "enc"
	Alg string `yaml:"alg,omitempty"` // e.g. "RS256", "EdDSA"

	// RSA
	N string `yaml:"n,omitempty"` // base64url big-endian modulus
	E string `yaml:"e,omitempty"` // base64url big-endian exponent

	// OKP (Ed25519)
	Crv string `yaml:"crv,omitempty"` // "Ed25519"
	X   string `yaml:"x,omitempty"`
}

// AuthenticatorsConfig toggles and tunes each available authenticator.
// All sub-sections are nullable — omit a section to disable that method.
type AuthenticatorsConfig struct {
	Password       *PasswordConfig             `yaml:"password,omitempty"`
	Phone          *CodeAuthConfig             `yaml:"phone,omitempty"`
	Email          *CodeAuthConfig             `yaml:"email,omitempty"`
	TempToken      *TempTokenConfig            `yaml:"temp_token,omitempty"`
	KeyPair        *KeyPairConfig              `yaml:"keypair,omitempty"`
	APIKey         *APIKeyConfig               `yaml:"apikey,omitempty"`
	Certificate    *CertificateConfig          `yaml:"certificate,omitempty"`
	TOTP           *TOTPConfig                 `yaml:"totp,omitempty"`
	OIDCFederation []*OIDCFederationAuthConfig `yaml:"oidc_federation,omitempty"`
}

// OIDCFederationAuthConfig describes one upstream OAuth 2.0 / OIDC
// IdP the AS delegates authentication to. Multiple entries supported
// — each yields a separate authenticator name accessible via
// /auth/login?provider=<name>. Bootstrap from a provider's OIDC
// Discovery 1.0 metadata at .well-known/openid-configuration to fill
// the endpoint fields.
type OIDCFederationAuthConfig struct {
	Name                  string        `yaml:"name"`
	AuthorizationEndpoint string        `yaml:"authorization_endpoint"`
	TokenEndpoint         string        `yaml:"token_endpoint"`
	UserinfoEndpoint      string        `yaml:"userinfo_endpoint"`
	ClientID              string        `yaml:"client_id"`
	ClientSecret          string        `yaml:"client_secret"`
	RedirectURI           string        `yaml:"redirect_uri"`
	Scopes                []string      `yaml:"scopes"`
	SubjectFieldOverride  string        `yaml:"subject_field"`
	Timeout               time.Duration `yaml:"timeout"`
}

// PasswordConfig configures the password authenticator + the seed
// list of known (username -> bcrypt hash file -> subject_id) tuples
// the reference cmd verifier uses. Production installs typically
// fork cmd to plug in a custom PasswordVerifier that talks to their
// own user store; the file-seeded reference path lets a small
// deployment work out of the box without holding plaintext secrets
// in YAML.
type PasswordConfig struct {
	Enabled bool                 `yaml:"enabled"`
	Users   []PasswordUserConfig `yaml:"users,omitempty"`
}

// PasswordUserConfig seeds one known user into cmd's bcrypt
// verifier. BcryptHashFile is a path to a file whose first line is
// the bcrypt hash (matches the output of
// `htpasswd -bnBC 12 "" pw | tr -d ':\n'` or
// `python -c 'import bcrypt; print(bcrypt.hashpw(b"pw",
// bcrypt.gensalt()).decode())'`). The file pattern keeps hashes
// out of YAML — even though bcrypt hashes are not directly
// reversible, leaking them gives an attacker an offline cracking
// target. SubjectID is the sso.Subject.ID returned on a successful
// match; the username is also surfaced as ExternalID.
type PasswordUserConfig struct {
	Username       string `yaml:"username"`
	BcryptHashFile string `yaml:"bcrypt_hash_file"`
	SubjectID      string `yaml:"subject_id"`
}

// CodeAuthConfig configures phone (SMS) and email OTP flows.
type CodeAuthConfig struct {
	Enabled    bool          `yaml:"enabled"`
	CodeLength int           `yaml:"code_length"`
	CodeTTL    time.Duration `yaml:"code_ttl"`
}

// TempTokenConfig configures the temporary-token authenticator.
type TempTokenConfig struct {
	Enabled bool          `yaml:"enabled"`
	TTL     time.Duration `yaml:"ttl"`
}

// KeyPairConfig configures Ed25519 signature verification.
//
// PublicKeys seeds the in-process MemoryPublicKeyStore at boot so
// known service identities can authenticate immediately without an
// admin RPC. Each entry maps a key_id (the credential the client
// posts) to a PEM-encoded Ed25519 public key on disk and the
// sso.Subject the authenticator returns on success. Production
// installations rotate by re-emitting YAML + reloading; runtime
// rotation needs an admin RPC the SDK doesn't ship today.
type KeyPairConfig struct {
	Enabled      bool                     `yaml:"enabled"`
	MaxClockSkew time.Duration            `yaml:"max_clock_skew"`
	PublicKeys   []KeyPairPublicKeyConfig `yaml:"public_keys,omitempty"`
}

// KeyPairPublicKeyConfig seeds a single Ed25519 verifier into the
// MemoryPublicKeyStore. PublicKeyFile MUST be a PEM-encoded
// "PUBLIC KEY" block (the output of `openssl pkey -pubout`); the
// raw 32-byte form is intentionally not accepted to keep operators
// from accidentally swapping public/private material at the YAML
// layer.
type KeyPairPublicKeyConfig struct {
	KeyID         string `yaml:"key_id"`
	PublicKeyFile string `yaml:"public_key_file"`
	SubjectID     string `yaml:"subject_id"`
}

// APIKeyConfig configures the API-key authenticator + optional seed
// entries that pre-populate the in-process MemoryAPIKeyStore at
// boot. Production rotation needs an admin RPC the SDK doesn't ship
// today — operators rotate by re-emitting YAML + reloading.
type APIKeyConfig struct {
	Enabled bool                `yaml:"enabled"`
	Keys    []APIKeyConfigEntry `yaml:"keys,omitempty"`
}

// APIKeyConfigEntry seeds a single key into the MemoryAPIKeyStore.
// SecretFile is a path to a file whose contents (one line, trailing
// newline tolerated) form the shared secret — keeping secrets out of
// YAML is the same pattern bootstrap.admin_password_file uses.
type APIKeyConfigEntry struct {
	KeyID      string `yaml:"key_id"`
	SecretFile string `yaml:"secret_file"`
	SubjectID  string `yaml:"subject_id"`
}

// CertificateConfig configures X.509 certificate authentication.
type CertificateConfig struct {
	Enabled           bool     `yaml:"enabled"`
	TrustedCAFiles    []string `yaml:"trusted_ca_files"`
	IntermediateFiles []string `yaml:"intermediate_files"`
}

// TOTPConfig wires the RFC 6238 TOTP authenticator. Enabled=true
// constructs an in-process MemoryTOTPStore (operators wanting
// durable secret storage should fork cmd and supply their own
// TOTPStore — the secrets are MUST-encrypt material and the
// in-memory store is a demo / dev tier). SkewSteps tolerates ±N
// 30-second step windows of clock drift between caller and server;
// defaults to 1 (≈±30s) when zero.
type TOTPConfig struct {
	Enabled   bool `yaml:"enabled"`
	SkewSteps int  `yaml:"skew_steps"`
}

// Load reads and parses a YAML config file, then applies defaults.
//
// Implemented as a thin wrapper over the layered Source/Loader chain
// — equivalent to LoadFromSources(NewFileSource(path)). Use
// LoadFromSources directly when you need ENV / flag / etcd overlays.
func Load(path string) (*Config, error) {
	if path == "" {
		path = DefaultFileName
	}
	return LoadFromSources(context.Background(), NewFileSource(path))
}

// LoadFromSources builds a Loader from the given priority chain
// (lowest → highest) and resolves it into a fully-defaulted +
// validated *Config. Returns the first source / parse / validation
// error encountered.
//
// Typical production wiring:
//
//	cfg, err := config.LoadFromSources(ctx,
//	    config.NewFileSource("/etc/sso/config.yaml"),
//	    &config.FileSource{Path: "/etc/sso/local.yaml", Optional: true},
//	    config.NewEnvSource(),
//	)
//
// CLI flags sit on top of this chain via a forthcoming FlagSource.
func LoadFromSources(ctx context.Context, sources ...Source) (*Config, error) {
	return NewLoader(sources...).Load(ctx)
}

// DefaultServerIssuer is the cmd-side default for server.issuer when
// operators omit it. Intentionally NOT [sso.DefaultIssuer]: the SDK's
// DefaultIssuer is a sentinel that resolveIssuer + the OIDC discovery
// renderer treat as "fall back to requestBaseURL", while the
// Ed25519JWTIssuer always stamps the literal value into the JWT iss
// claim. Setting the SDK sentinel as cmd's default would produce a
// discovery doc whose `issuer` field is the requestBaseURL (e.g.
// http://localhost:9090) but JWTs whose `iss` claim is "snaplink-sso"
// — a wire-contract divergence that breaks every RFC 9068 access
// token validator. Using a non-sentinel default ("sso-server") keeps
// every path agreeing on the same string. Operators should set a
// canonical URL via `server.issuer` for production deployments.
const DefaultServerIssuer = "sso-server"

func (c *Config) applyDefaults() {
	if c.Server.Issuer == "" {
		c.Server.Issuer = DefaultServerIssuer
	}
	if c.Server.SessionTTL == 0 {
		c.Server.SessionTTL = sso.DefaultSessionDuration
	}
	if c.Server.TokenTTL == 0 {
		c.Server.TokenTTL = sso.DefaultTokenTTL
	}
	if c.Logging.Level == "" {
		c.Logging.Level = "info"
	}
	if c.Authenticators.Phone != nil {
		applyCodeDefaults(c.Authenticators.Phone, authenticators.DefaultPhoneCodeTTL)
	}
	if c.Authenticators.Email != nil {
		applyCodeDefaults(c.Authenticators.Email, authenticators.DefaultEmailCodeTTL)
	}
	if c.Authenticators.TempToken != nil && c.Authenticators.TempToken.TTL == 0 {
		c.Authenticators.TempToken.TTL = authenticators.DefaultTempTokenTTL
	}
	if c.Authenticators.KeyPair != nil && c.Authenticators.KeyPair.MaxClockSkew == 0 {
		c.Authenticators.KeyPair.MaxClockSkew = authenticators.DefaultKeyPairClockSkew
	}
}

func applyCodeDefaults(c *CodeAuthConfig, ttl time.Duration) {
	if c.CodeLength == 0 {
		c.CodeLength = authenticators.DefaultCodeLength
	}
	if c.CodeTTL == 0 {
		c.CodeTTL = ttl
	}
}

func (c *Config) validate() error {
	level := strings.ToLower(c.Logging.Level)
	switch level {
	case "debug", "info", "error":
	default:
		return fmt.Errorf("config: invalid logging.level %q", c.Logging.Level)
	}
	// Reject the SDK's internal sentinel. resolveIssuer + the OIDC
	// discovery renderer treat sso.DefaultIssuer as "fall back to
	// requestBaseURL", while Ed25519JWTIssuer stamps it literally
	// into the JWT iss claim — the resulting discovery doc and
	// access tokens then disagree on the issuer string, which
	// breaks every spec-compliant RFC 9068 validator. See
	// DefaultServerIssuer above.
	if c.Server.Issuer == sso.DefaultIssuer {
		return fmt.Errorf("config: server.issuer must not equal the SDK sentinel %q — set it to your canonical public URL (e.g. https://sso.example.com) or accept the cmd default %q", sso.DefaultIssuer, DefaultServerIssuer)
	}
	for _, cl := range c.Clients {
		if cl.ID == "" {
			return errors.New("config: client.id required")
		}
	}
	return nil
}

// ServerOptions returns the sso.Option values implied by the configuration.
// Wire dependency-injected providers (TokenIssuer, UserProvider, ...) and
// authenticators separately.
func (c *Config) ServerOptions() []sso.Option {
	// Server.{BaseURL,SessionTTL,TokenTTL} are NOT wired here — the
	// matching sso.WithX options are deprecated no-ops. The real
	// session / token lifetimes live on the SessionManager and
	// TokenIssuer constructors; cmd/sso-server reads SessionTTL +
	// TokenTTL directly to feed those constructors.
	opts := []sso.Option{
		sso.WithIssuer(c.Server.Issuer),
	}
	if c.Server.DefaultTokenStrategy != "" {
		opts = append(opts, sso.WithDefaultTokenStrategy(c.Server.DefaultTokenStrategy))
	}

	// Security middleware — body limit + rate limit + CORS. Each
	// opt-in via its own block; absent / disabled blocks omit the
	// corresponding sso.WithX call so the middleware is not wired.
	if c.Security.BodyLimit.MaxBytes > 0 {
		opts = append(opts, sso.WithBodyLimit(c.Security.BodyLimit.MaxBytes))
	}
	if c.Security.RateLimit.Enabled {
		opts = append(opts, sso.WithRateLimit(c.Security.RateLimit.toPolicy()))
	}
	if c.Security.CORS.Enabled && len(c.Security.CORS.AllowedOrigins) > 0 {
		opts = append(opts, sso.WithCORS(c.Security.CORS.toPolicy()))
	}
	return opts
}

// toPolicy builds the ratelimit.Policy implied by the YAML block.
// Default rate / burst applies to unmatched paths; Prefixes layer
// per-endpoint overrides.
func (r *RateLimitConfig) toPolicy() ratelimit.Policy {
	policy := ratelimit.Policy{}
	if r.DefaultPerSec > 0 && r.DefaultBurst > 0 {
		policy.Default = ratelimit.NewMemoryLimiter(r.DefaultPerSec, r.DefaultBurst)
	}
	for _, p := range r.Prefixes {
		if p.Prefix == "" || p.PerSec <= 0 || p.Burst <= 0 {
			continue
		}
		policy.Prefixes = append(policy.Prefixes, ratelimit.PrefixRule{
			Prefix:  p.Prefix,
			Limiter: ratelimit.NewMemoryLimiter(p.PerSec, p.Burst),
		})
	}
	return policy
}

// toPolicy builds the cors.Policy implied by the YAML block. Empty
// AllowedMethods / AllowedHeaders fall back to the cors package's
// defaults (GET/POST/PUT/DELETE/OPTIONS, Authorization/Content-Type).
func (c *CORSConfig) toPolicy() cors.Policy {
	return cors.Policy{
		AllowedOrigins:   c.AllowedOrigins,
		AllowedMethods:   c.AllowedMethods,
		AllowedHeaders:   c.AllowedHeaders,
		ExposedHeaders:   c.ExposedHeaders,
		AllowCredentials: c.AllowCredentials,
		MaxAge:           c.MaxAge,
	}
}
