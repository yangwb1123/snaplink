package config

import "time"

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
	// TenantLabelAllowlist enables per-tenant login/token metrics for the
	// listed tenant IDs. Tenants not in the list land in an "other" bucket.
	// Empty (default) = per-tenant breakdown disabled. Keep this list
	// small — cardinality grows with the slice length. cmd knob:
	// metrics.tenant_label_allowlist. Requires WithTenantMetricsAllowlist.
	TenantLabelAllowlist []string `yaml:"tenant_label_allowlist"`
}

// SecurityConfig groups operator-facing security tunables that hook
// into the Server's middleware stack (body limit + rate limit + CORS).
// Each sub-block is opt-in — leaving the block out (or setting
// Enabled=false) skips the corresponding middleware with zero
// overhead. See AGENTS.md §8d / §8f / §8g for the runtime behavior
// of each.
type SecurityConfig struct {
	BodyLimit       BodyLimitConfig       `yaml:"body_limit"`
	RateLimit       RateLimitConfig       `yaml:"rate_limit"`
	CORS            CORSConfig            `yaml:"cors"`
	DPoPNonce       DPoPNonceConfig       `yaml:"dpop_nonce"`
	JTIReplay       JTIReplayConfig       `yaml:"jti_replay"`
	AccountLockout  AccountLockoutConfig  `yaml:"account_lockout"`
	MTLS            MTLSConfig            `yaml:"mtls"`
	TrustedProxies  TrustedProxiesConfig  `yaml:"trusted_proxies"`
	SecurityHeaders SecurityHeadersConfig `yaml:"security_headers"`
}

// SecurityHeadersConfig opts into the security-headers framework: CSP (with a
// per-request script-src nonce), Permissions-Policy, X-Content-Type-Options,
// Referrer-Policy, and (TLS-only) HSTS on every HTML-serving response —
// including the opt-in admin console / hosted login / self-service portal SPA
// bundles, which are served outside the SSO router's own middleware chain and
// so need the same wrap applied explicitly (see sso.WithSecurityHeaders's
// doc). Also adds Clear-Site-Data on POST /logout and POST /me/account/erase,
// instructing the browser to purge this origin's cache/cookies/storage on a
// definitive session end.
//
// Off by default — byte-identical to a build without this feature; this
// touches response headers on EVERY existing endpoint, so it must never
// activate unless explicitly enabled. CSPDirectives / PermissionsPolicy let
// an operator override the SDK's conservative default (see
// handler.DefaultSecurityHeadersPolicy); leave both empty/unset to use it.
type SecurityHeadersConfig struct {
	Enabled bool `yaml:"enabled"`
	// CSPDirectives overrides the Content-Security-Policy directive list
	// (e.g. ["default-src 'self'", "object-src 'none'"]). Empty ⇒ the SDK
	// default. A per-request nonce is appended to script-src automatically —
	// do not include one here.
	CSPDirectives []string `yaml:"csp_directives"`
	// PermissionsPolicy overrides the raw Permissions-Policy header value.
	// Empty ⇒ the SDK default (camera/microphone/geolocation/payment/usb
	// denied).
	PermissionsPolicy string `yaml:"permissions_policy"`
}

// TrustedProxiesConfig opts into XFF-aware real-IP extraction.
// When CIDRs is non-empty, the middleware.TrustedProxies middleware is
// installed: XFF is walked right-to-left, CIDRs up to Hops trusted
// hops are skipped, and the first non-trusted address is the real client
// IP used for rate-limiting and geo enrichment.
// Hops 0 = walk the full XFF chain until a non-trusted address.
// SECURITY: list ONLY the CIDRs of your actual load balancers / CDN
// egress IPs; a spoofed X-Forwarded-For header injected BEFORE the
// trusted proxy will be accepted as the real client IP if you over-trust.
type TrustedProxiesConfig struct {
	CIDRs []string `yaml:"cidrs"`
	Hops  int      `yaml:"hops"` // 0 = unlimited
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
	// FailClosed rejects a request when the store can't confirm a jti
	// is unseen (transport error) instead of falling through (default
	// fail-open). Opt in for replay-sensitive multi-replica
	// deployments — it trades availability during a store outage for a
	// closed replay window. Maps to sso.WithJTIReplayFailClosed.
	FailClosed bool `yaml:"fail_closed"`
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
