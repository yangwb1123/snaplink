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
	Server             ServerConfig                    `yaml:"server"`
	Authenticators     AuthenticatorsConfig            `yaml:"authenticators"`
	Logging            LoggingConfig                   `yaml:"logging"`
	Audit              AuditConfig                     `yaml:"audit"`
	Permissions        PermissionsConfig               `yaml:"permissions"`
	Network            NetworkConfig                   `yaml:"network"`
	Clients            []ClientConfig                  `yaml:"clients"`
	Admin              AdminConfig                     `yaml:"admin"`
	Bootstrap          BootstrapConfig                 `yaml:"bootstrap"`
	Snapshot           SnapshotConfig                  `yaml:"snapshot"`
	Releases           ReleasesConfig                  `yaml:"releases"`
	Geo                GeoConfig                       `yaml:"geo"`
	Region             RegionConfig                    `yaml:"region"`
	Tenant             TenantConfig                    `yaml:"tenant"`
	Connections        ConnectionsConfig               `yaml:"connections"`
	Security           SecurityConfig                  `yaml:"security"`
	Metrics            MetricsConfig                   `yaml:"metrics"`
	OAuth              OAuthConfig                     `yaml:"oauth"`
	BackchannelLogout  BackchannelLogoutConfig         `yaml:"backchannel_logout"`
	ClientRegistration ClientRegistrationConfig        `yaml:"client_registration"`
	Identity           IdentityConfig                  `yaml:"identity"`
	WebAuthn           WebAuthnConfig                  `yaml:"webauthn"`
	Registry           RegistryConfig                  `yaml:"registry"`
	Risk               RiskConfig                      `yaml:"risk"`
	MFA                MFAConfig                       `yaml:"mfa"`
	Anomaly            AnomalyConfig                   `yaml:"anomaly"`
	Cluster            ClusterConfig                   `yaml:"cluster"`
	Keys               KeysConfig                      `yaml:"keys"`
	CIBA               CIBAConfig                      `yaml:"ciba"`
	OIDC               OIDCConfig                      `yaml:"oidc"`
	SCIM               SCIMConfig                      `yaml:"scim"`
	DPoP               DPoPConfig                      `yaml:"dpop"`
	CAEP               CAEPConfig                      `yaml:"caep"`
	SPIFFE             SPIFFEConfig                    `yaml:"spiffe"`
	Mesh               MeshConfig                      `yaml:"mesh"`
	Federation         FederationConfig                `yaml:"federation"`
	SAML               SAMLConfig                      `yaml:"saml"`
	HostedLogin        HostedLoginConfig               `yaml:"hosted_login"`
	SelfService        SelfServiceConfig               `yaml:"self_service"`
	NativeSSO          NativeSSOConfig                 `yaml:"native_sso"`
	ProtectedResource  ProtectedResourceMetadataConfig `yaml:"protected_resource_metadata"`
}

// ProtectedResourceMetadataConfig opts into the RFC 9728 OAuth 2.0 Protected
// Resource Metadata endpoint (/.well-known/oauth-protected-resource). Enabling
// it lets MCP / AI-agent clients discover this server's authorization metadata.
// All fields beyond Enabled are optional overrides — defaults derive from
// server state (resource = base URL, authorization_servers = [issuer]).

// → APPROVED/DENIED) is intentionally NOT shipped from cmd —
// authentication, transport-specific deep-link handling, and the
// callback URL itself are operator-decisions. Operators build the
// handler against the SDK's [defaultimpl.PushApprovalStore]
// SetStatus method and route it through their own gateway.

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
// PprofConfig controls the optional Go runtime profiling endpoints. Disabled
// by default: pprof exposes heap/goroutine/CPU profiles (a memory-content
// leak + a CPU-profile DoS vector), so it MUST run on its own listener bound
// to a trusted interface — never the public router. Listen defaults to
// 127.0.0.1:6060 (localhost only); operators reach it via an SSH/port-forward.
type PprofConfig struct {
	Enabled bool   `yaml:"enabled"`
	Listen  string `yaml:"listen"`
}

type ServerConfig struct {
	Issuer               string        `yaml:"issuer"`
	BaseURL              string        `yaml:"base_url"`
	Listen               string        `yaml:"listen"`
	Pprof                PprofConfig   `yaml:"pprof"`
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

	// Per-client consent policy (operator-provisioned; never DCR-settable).
	// SkipConsent bypasses the consent gate for trusted first-party clients;
	// ConsentRefreshInterval (>0) forces periodic re-consent even when scopes
	// still match. Both default off (byte-identical to prior behavior).
	SkipConsent            bool          `yaml:"skip_consent,omitempty"`
	ConsentRefreshInterval time.Duration `yaml:"consent_refresh_interval,omitempty"`

	// Attributes is the open per-client extension bag (mirrors
	// sso.Client.Attributes). Carries server-side registered capabilities
	// such as the OpenID Shared Signals / CAEP receiver:
	//   attributes:
	//     caep_receiver_endpoint: https://rp.example.com/ssf/receive
	//     caep_receiver_auth: "Bearer <token>"
	// caep_receiver_endpoint is validated https at boot.
	Attributes map[string]string `yaml:"attributes,omitempty"`
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
	Enabled bool                  `yaml:"enabled"`
	Users   []PasswordUserConfig  `yaml:"users,omitempty"`
	Health  *PasswordHealthConfig `yaml:"health,omitempty"`

	// ImportedHashLogin enables login for users migrated via cmd/sso-import,
	// whose credential hash (any of bcrypt / argon2id / PBKDF2) lives on the
	// User record's Attributes. When true and a UserProvider is wired, an
	// attribute-backed multi-format verifier is chained after the primary
	// (YAML / store) verifier, wrapped in lazy bcrypt re-hashing so a migrated
	// user is upgraded to bcrypt on first login. Default false — byte-identical
	// (the import tool's output is otherwise inert: nothing reads those hashes).
	ImportedHashLogin bool `yaml:"imported_hash_login,omitempty"`
}

// PasswordHealthConfig wires the optional login-time credential-health
// signal. When Enabled, cmd attaches a PasswordHealthChecker to the
// password authenticator. The check runs only AFTER a password verifies,
// NEVER blocks login, and surfaces purely as a
// password_weak / password_compromised audit event (plus the
// sso_credential_health_signals_total metric). This server has no
// register / change-password endpoint, so login is the only moment it
// sees plaintext — this is the only place such a signal can be derived.
//
// Kind selects the checker: "dictionary" (default, fully offline,
// DictionaryPasswordHealthChecker) or "hibp" (online Have I Been Pwned
// k-anonymity breach lookup — only a 5-char SHA-1 prefix ever leaves the
// process; fail-open so an HIBP outage never blocks login).
type PasswordHealthConfig struct {
	Enabled bool `yaml:"enabled"`
	// Kind selects the checker implementation: "" / "dictionary" (offline,
	// the default) or "hibp" (online breach lookup). An unknown value fails
	// the boot loudly.
	Kind string `yaml:"kind,omitempty"`
	// WeakPasswordFile optionally extends the built-in weak-password set
	// with a newline-delimited file (blank lines + '#' comments skipped).
	// A read error fails the boot loudly rather than silently shrinking
	// coverage. Only consulted for the dictionary checker.
	WeakPasswordFile string `yaml:"weak_password_file"`
	// HIBP holds the Have I Been Pwned checker tunables; only consulted
	// when Kind is "hibp".
	HIBP *HIBPHealthConfig `yaml:"hibp,omitempty"`
}

// HIBPHealthConfig tunes the "hibp" credential-health checker. All fields
// are optional — zero values fall back to the SDK defaults (the public
// HIBP range API, a 5s timeout, MinCount 1).
type HIBPHealthConfig struct {
	// BaseURL overrides the range-API base (default
	// https://api.pwnedpasswords.com/range/, trailing slash required).
	// Point at a self-hosted mirror to keep prefixes inside your network.
	BaseURL string `yaml:"base_url,omitempty"`
	// Timeout caps a single range request (default 5s). The lookup is on
	// the synchronous login path, so this bounds how long a slow HIBP
	// endpoint can delay a login before the fail-open path engages.
	Timeout time.Duration `yaml:"timeout,omitempty"`
	// MinCount only flags a password whose breach count is >= MinCount
	// (default 1 = flag any appearance).
	MinCount int `yaml:"min_count,omitempty"`
	// UserAgent overrides the request User-Agent (default a descriptive
	// snaplink UA). Some mirrors require a non-empty UA.
	UserAgent string `yaml:"user_agent,omitempty"`
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
// constructs an in-process store (the secrets are MUST-encrypt material
// and the in-memory store is a demo / dev tier — set SQLiteDSN for
// durable, multi-replica storage). SkewSteps tolerates ±N 30-second step
// windows of clock drift between caller and server; defaults to 1 (≈±30s)
// when zero.
type TOTPConfig struct {
	Enabled   bool `yaml:"enabled"`
	SkewSteps int  `yaml:"skew_steps"`
	// SQLiteDSN enables durable TOTP secret + factor storage backing both
	// login verification and self-service enrollment (/me/mfa/totp). When set,
	// the unified SQLite store is used instead of the in-memory store —
	// required for secrets to survive restarts and for multi-replica
	// deployments. The secret is MUST-encrypt material: use an encrypted DSN
	// or full-disk encryption.
	SQLiteDSN string `yaml:"sqlite_dsn,omitempty"`
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

// DefaultBodyLimitBytes is the conservative body-size cap applied when the
// operator omits security.body_limit entirely. 64 KiB is generous for any
// OAuth/OIDC flow (typical /token ≈ 1 KiB; a JAR with a large JWKS is the
// ceiling). Set security.body_limit.max_bytes = -1 to explicitly opt into
// unlimited.
const DefaultBodyLimitBytes int64 = 64 * 1024

func (c *Config) applyDefaults() {
	if c.Server.Issuer == "" {
		c.Server.Issuer = DefaultServerIssuer
	}
	// Body-limit default: absent (0) → secure default; negative → unlimited (0).
	if c.Security.BodyLimit.MaxBytes == 0 {
		c.Security.BodyLimit.MaxBytes = DefaultBodyLimitBytes
	} else if c.Security.BodyLimit.MaxBytes < 0 {
		c.Security.BodyLimit.MaxBytes = 0 // explicit unlimited escape hatch
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
