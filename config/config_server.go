package config

import (
	"fmt"
	"time"

	"github.com/yangwb1123/snaplink/interfaces/sso"
)

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
	Issuer   string         `yaml:"issuer"`
	BaseURL  string         `yaml:"base_url"`
	Listen   string         `yaml:"listen"`
	Pprof    PprofConfig    `yaml:"pprof"`
	Topology TopologyConfig `yaml:"topology"`
	// RequiredCapabilities is a deployment contract checked against the
	// immutable capability inventory embedded by the module builder.
	RequiredCapabilities []string      `yaml:"required_capabilities"`
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

	// RequireFormContentType opts the server into the strict credential
	// wire (B4-4): when true, the four credential endpoints (/token,
	// /token/introspect, /token/revoke, /par) accept ONLY
	// application/x-www-form-urlencoded (RFC 6749 §3.2 / 7662 §2.1 /
	// 7009 §2.1 / 9126 §4.1) and answer 415 Unsupported Media Type with
	// the plain {"error":"invalid_request"} envelope for a JSON body, a
	// missing Content-Type, or any other media type — before the body is
	// read; nothing is minted, revoked, introspected, or stored. Unset
	// (nil) or false = legacy JSON acceptance, byte-identical to a build
	// without the key. Boot-time only; no hot-reload; rollback = drop the
	// key or set false.
	RequireFormContentType *bool `yaml:"require_form_content_type"`

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

	// APIVersioning wires the opt-in Accept-Version negotiation +
	// Sunset/Deprecation response headers + the v2alpha proof-of-mechanism
	// route (ADR-0008). Every sub-field's zero value disables its own
	// mechanism — a deployment that never sets api_versioning: behaves
	// byte-identically to today for every route.
	APIVersioning APIVersioningConfig `yaml:"api_versioning"`

	// HTTP2 controls HTTP/2 server-side support.
	// nil = disabled (current default behavior via GODEBUG=http2server=0).
	// When set to &HTTP2Config{Enabled: true}, HTTP/2 is enabled.
	// Note: if the GODEBUG env var is already set explicitly, this field
	// does not override it (explicit env var takes precedence).
	HTTP2 *HTTP2Config `yaml:"http2,omitempty"`
}

const (
	TopologyModeSingle = "single"
	TopologyModeMulti  = "multi"
)

// TopologyConfig declares whether requests can land on more than one server
// process. Multi-replica mode turns per-process security state into a boot
// error; AllowPerPodState is an explicit development-only escape hatch.
type TopologyConfig struct {
	Mode             string `yaml:"mode"`
	AllowPerPodState bool   `yaml:"allow_per_pod_state"`
}

// APIVersioningConfig is the YAML shape of ADR-0008's API versioning
// mechanism: Accept-Version request-header negotiation, Sunset/Deprecation
// response headers (whole-API or per-route), and the v2alpha example route.
type APIVersioningConfig struct {
	// SupportedVersions lists the Accept-Version tokens this deployment
	// accepts (e.g. ["v1", "v2alpha"]). Empty (the default) disables
	// negotiation — every request, with or without the header, is
	// unaffected.
	SupportedVersions []string `yaml:"supported_versions"`
	// Deprecation marks the WHOLE API deprecated (Sunset + Deprecation
	// response headers on every response). The zero value (Since, Sunset,
	// and Link all unset) adds no headers.
	Deprecation DeprecationConfig `yaml:"deprecation"`
	// RouteDeprecations marks specific endpoints or path-prefix groups
	// deprecated, keyed by exact path or a "/"-suffixed prefix. Empty (the
	// default) adds no per-route headers.
	RouteDeprecations map[string]DeprecationConfig `yaml:"route_deprecations"`
	// V2AlphaPreview mounts GET /api/v2alpha/version, the one example route
	// proving the v2alpha path-prefix mechanism ADR-0008 documents. False
	// (the default) ⇒ the route is not mounted.
	V2AlphaPreview bool `yaml:"v2alpha_preview"`
}

// DeprecationConfig is the YAML shape of a middleware.DeprecationPolicy
// (interfaces/sso can't be imported from config — see AGENTS.md §0.2 layer
// direction — so this is a plain-data mirror the cmd layer translates).
type DeprecationConfig struct {
	Since  time.Time `yaml:"since"`
	Sunset time.Time `yaml:"sunset"`
	Link   string    `yaml:"link"`
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

// HTTP2Config controls HTTP/2 server-side support.
// The zero value (Enabled=false) disables HTTP/2, matching the
// current default behavior (GODEBUG=http2server=0). When Enabled
// is true, HTTP/2 is active unless the GODEBUG env var is already
// explicitly set (explicit env override takes precedence).
type HTTP2Config struct {
	Enabled bool `yaml:"enabled"`
}

// LoggingConfig controls the embedded logger and the always-on access log.
type LoggingConfig struct {
	Level     string          `yaml:"level"` // debug | info | error
	AccessLog AccessLogConfig `yaml:"access_log"`
}

// AccessLogConfig controls the always-on INFO access log
// (interfaces/middleware.AccessLogger). Enabled is tri-state: nil (absent)
// means ON — the sso-server default, so "default config produces access
// logs" without changing SDK assembly semantics; false explicitly removes
// the middleware from the chain (zero added overhead). Body capture is a
// separate, deliberate per-deployment posture: zero values never capture
// bodies.
type AccessLogConfig struct {
	Enabled *bool               `yaml:"enabled"`
	Body    AccessLogBodyConfig `yaml:"body"`
}

// AccessLogBodyConfig maps 1:1 onto middleware.BodyLogPolicy; zero values
// keep the no-bodies posture.
type AccessLogBodyConfig struct {
	Paths         []string `yaml:"paths"`           // exact-path allowlist; empty = no path eligible
	AllowAllPaths bool     `yaml:"allow_all_paths"` // deprecated escape hatch (old logBodies=true)
	SampleRate    float64  `yaml:"sample_rate"`     // 0 = body capture never happens
	MaxBodyBytes  int64    `yaml:"max_body_bytes"`  // 0 = default 4096
}

// validate rejects a misconfigured access-log block loudly at boot. An
// allowlist combined with the AllowAllPaths escape hatch is ambiguous
// (the operator asked for both bounded and unbounded capture); sample_rate
// outside [0,1] and a negative byte cap are arithmetic errors.
func (c AccessLogConfig) validate() error {
	if len(c.Body.Paths) > 0 && c.Body.AllowAllPaths {
		return fmt.Errorf("config: logging.access_log.body: allow_all_paths cannot be combined with a populated paths allowlist")
	}
	if c.Body.SampleRate < 0 || c.Body.SampleRate > 1 {
		return fmt.Errorf("config: logging.access_log.body.sample_rate must be within [0,1], got %v", c.Body.SampleRate)
	}
	if c.Body.MaxBodyBytes < 0 {
		return fmt.Errorf("config: logging.access_log.body.max_body_bytes must be >= 0, got %d", c.Body.MaxBodyBytes)
	}
	return nil
}

// enabled reports the tri-state access-log switch: nil (absent) means ON —
// the sso-server default; only an explicit false removes the middleware.
func (c AccessLogConfig) enabled() bool {
	return c.Enabled == nil || *c.Enabled
}

// bodyPolicy maps the config block onto the SDK body-capture policy.
func (c AccessLogConfig) bodyPolicy() sso.BodyLogPolicy {
	return sso.BodyLogPolicy{
		Paths:         c.Body.Paths,
		AllowAllPaths: c.Body.AllowAllPaths,
		SampleRate:    c.Body.SampleRate,
		MaxBodyBytes:  c.Body.MaxBodyBytes,
	}
}

// accessLogOptions returns the always-on access-log option when enabled.
// Absent (nil) or explicit true enables it — the sso-server default; only
// logging.access_log.enabled: false removes the middleware entirely (the
// tri-state keeps "absent" distinguishable from "explicitly off").
func (c *Config) accessLogOptions() []sso.Option {
	if !c.Logging.AccessLog.enabled() {
		return nil
	}
	return []sso.Option{sso.WithAccessLogging(c.Logging.AccessLog.bodyPolicy())}
}

// securityMiddlewareOptions maps the security.* blocks onto their sso.WithX
// options. Each block is opt-in via its own section; absent / disabled blocks
// omit the corresponding sso.WithX call so the middleware is not wired.
func (c *Config) securityMiddlewareOptions() []sso.Option {
	var opts []sso.Option
	if c.Security.BodyLimit.MaxBytes > 0 {
		opts = append(opts, sso.WithBodyLimit(c.Security.BodyLimit.MaxBytes))
	}
	if c.Security.RateLimit.Enabled {
		opts = append(opts, sso.WithRateLimit(c.Security.RateLimit.toPolicy()))
	}
	// Unlike the block above, ClientRegistrationRateLimit has NO "enabled"
	// gate: omitting the section (or leaving PerSec/Burst at 0) is not
	// "disabled" — sso.NewServer already seeds a conservative built-in
	// limiter, so there is nothing to wire here in that case. Only an
	// EXPLICIT override (Disabled, or a custom PerSec+Burst) needs an
	// Option call.
	if opt, ok := c.Security.ClientRegistrationRateLimit.serverOption(); ok {
		opts = append(opts, opt)
	}
	if c.Security.CORS.Enabled && len(c.Security.CORS.AllowedOrigins) > 0 {
		opts = append(opts, sso.WithCORS(c.Security.CORS.toPolicy()))
	}
	return opts
}

// backupOptions maps the backup.* blocks onto their sso.WithX options; only
// a populated section wires an Option call.
func (c *Config) backupOptions() []sso.Option {
	var opts []sso.Option
	if c.Backup.Dir != "" {
		opts = append(opts, sso.WithBackupDir(c.Backup.Dir))
	}
	if c.Backup.Keep > 0 {
		opts = append(opts, sso.WithBackupRetention(c.Backup.Keep))
	}
	return opts
}

// credentialFormOnlyOptions returns the opt-in strict credential wire
// option (B4-4, server.require_form_content_type). Unset (nil) appends
// nothing so ServerOptions stays byte-identical to a pre-B4-4 build;
// false is the explicit-legacy spelling of the same default. Only true
// changes the four credential endpoints' wire behavior (415 for
// JSON/missing/unexpected Content-Type).
func (c *Config) credentialFormOnlyOptions() []sso.Option {
	if c.Server.RequireFormContentType == nil {
		return nil
	}
	return []sso.Option{sso.WithCredentialFormOnly(*c.Server.RequireFormContentType)}
}
