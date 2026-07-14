package config

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/interfaces/cors"
	"github.com/snaplink/sso/interfaces/ratelimit"
	"github.com/snaplink/sso/interfaces/sso"
)

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
		applyCodeDefaults(&c.Authenticators.Phone.CodeAuthConfig, authenticators.DefaultPhoneCodeTTL)
	}
	if c.Authenticators.Email != nil {
		applyCodeDefaults(c.Authenticators.Email, authenticators.DefaultEmailCodeTTL)
	}
	applyMagicLinkDefaults(c.Authenticators.MagicLink)
	if c.Authenticators.TempToken != nil && c.Authenticators.TempToken.TTL == 0 {
		c.Authenticators.TempToken.TTL = authenticators.DefaultTempTokenTTL
	}
	if c.Authenticators.KeyPair != nil && c.Authenticators.KeyPair.MaxClockSkew == 0 {
		c.Authenticators.KeyPair.MaxClockSkew = authenticators.DefaultKeyPairClockSkew
	}
}

// applyMagicLinkDefaults is its own function (rather than an inline nil-check
// block in applyDefaults, like TempToken/KeyPair's single-field checks) to
// keep applyDefaults under the cyclomatic-complexity budget — MagicLinkConfig
// has two independently-defaulted fields, the same reason applyCodeDefaults
// exists for Phone/Email. A nil ml is a no-op (disabled/omitted section).
func applyMagicLinkDefaults(ml *MagicLinkConfig) {
	if ml == nil {
		return
	}
	if ml.TokenLength == 0 {
		ml.TokenLength = authenticators.DefaultMagicLinkTokenBytes
	}
	if ml.TTL == 0 {
		ml.TTL = authenticators.DefaultMagicLinkTTL
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
	if err := ValidateVersion(c); err != nil {
		return err
	}
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
	if c.Backup.Keep < 0 {
		return fmt.Errorf("config: backup.keep must be >= 0 (0 disables retention), got %d", c.Backup.Keep)
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
	if c.Backup.Dir != "" {
		opts = append(opts, sso.WithBackupDir(c.Backup.Dir))
	}
	if c.Backup.Keep > 0 {
		opts = append(opts, sso.WithBackupRetention(c.Backup.Keep))
	}
	// Only wired when the operator touched at least one feature_gates key —
	// an all-nil FeatureGatesConfig is functionally identical to omitting
	// the option (every gate already defaults to on), so skipping the call
	// keeps ServerOptions' output byte-identical to a pre-gate build.
	if c.FeatureGates.anySet() {
		opts = append(opts, sso.WithFeatureGates(c.FeatureGates.toSSOGates()))
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

// serverOption returns the sso.Option implied by a
// security.client_registration_rate_limit block, and ok=false when the
// section carries no EXPLICIT override — leaving sso.NewServer's built-in
// default limiter in place untouched (see the type's doc for why the zero
// value here is not "disabled", unlike every other security.* block).
func (r *ClientRegistrationRateLimitConfig) serverOption() (opt sso.Option, ok bool) {
	if r.Disabled {
		return sso.WithClientRegistrationRateLimit(nil), true
	}
	if r.PerSec > 0 && r.Burst > 0 {
		return sso.WithClientRegistrationRateLimit(ratelimit.NewMemoryLimiter(r.PerSec, r.Burst)), true
	}
	return nil, false
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
