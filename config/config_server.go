package config

import "time"

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
