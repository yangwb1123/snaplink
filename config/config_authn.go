package config

import (
	"errors"
	"time"

	"github.com/yangwb1123/snaplink/domains/authenticators"
)

// AuthenticatorsConfig toggles and tunes each available authenticator.
// All sub-sections are nullable — omit a section to disable that method.
type AuthenticatorsConfig struct {
	Password       *PasswordConfig             `yaml:"password,omitempty"`
	Phone          *PhoneConfig                `yaml:"phone,omitempty"`
	Email          *CodeAuthConfig             `yaml:"email,omitempty"`
	MagicLink      *MagicLinkConfig            `yaml:"magic_link,omitempty"`
	TempToken      *TempTokenConfig            `yaml:"temp_token,omitempty"`
	KeyPair        *KeyPairConfig              `yaml:"keypair,omitempty"`
	APIKey         *APIKeyConfig               `yaml:"apikey,omitempty"`
	Certificate    *CertificateConfig          `yaml:"certificate,omitempty"`
	TOTP           *TOTPConfig                 `yaml:"totp,omitempty"`
	OIDCFederation []*OIDCFederationAuthConfig `yaml:"oidc_federation,omitempty"`
	CodeSendQuota  CodeSendQuotaConfig         `yaml:"code_send_quota,omitempty"`
	CodeDelivery   CodeDeliveryConfig          `yaml:"code_delivery,omitempty"`
}

// CodeSendQuotaConfig bounds paid/out-of-band OTP and magic-link delivery.
// Limits are per fixed window; -1 disables a dimension and zero selects the
// secure stock default.
type CodeSendQuotaConfig struct {
	IdentityLimit int           `yaml:"identity_limit,omitempty"`
	TenantLimit   int           `yaml:"tenant_limit,omitempty"`
	Window        time.Duration `yaml:"window,omitempty"`
}

// CodeDeliveryConfig moves OTP and magic-link transport waits off the request
// path. The queue is deliberately memory-only so plaintext codes are never
// persisted; CodeStore remains Redis-backed in multi-replica deployments.
type CodeDeliveryConfig struct {
	Async          bool          `yaml:"async,omitempty"`
	QueueSize      int           `yaml:"queue_size,omitempty"`
	Workers        int           `yaml:"workers,omitempty"`
	Attempts       int           `yaml:"attempts,omitempty"`
	AttemptTimeout time.Duration `yaml:"attempt_timeout,omitempty"`
	RetryBackoff   time.Duration `yaml:"retry_backoff,omitempty"`
}

func (c CodeDeliveryConfig) validate() error {
	if c.QueueSize < 0 || c.Workers < 0 || c.Attempts < 0 || c.AttemptTimeout < 0 || c.RetryBackoff < 0 {
		return errors.New("config: authenticators.code_delivery values must not be negative")
	}
	if c.QueueSize > authenticators.MaxCodeDeliveryQueueSize || c.Workers > authenticators.MaxCodeDeliveryWorkers ||
		c.Attempts > authenticators.MaxCodeDeliveryAttempts || c.AttemptTimeout > authenticators.MaxCodeDeliveryTimeout ||
		c.RetryBackoff > authenticators.MaxCodeDeliveryBackoff {
		return errors.New("config: authenticators.code_delivery value exceeds its safe maximum")
	}
	return nil
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

	// ACRMapping normalizes this provider's upstream `acr` claim onto the
	// SDK's own acr vocabulary (see authenticators.ACRMapper /
	// domains/authenticators/acrmap.PatternACRMapper — the reference
	// exact -> regex -> prefix -> default cascade this config translates
	// into). nil (the default) ⇒ no mapping is wired: AuthResult.AchievedACR
	// is never set from this provider, byte-identical to a build without
	// ACRMapper.
	ACRMapping *ACRMapConfig `yaml:"acr_mapping,omitempty"`
}

// ACRMapConfig is the YAML projection of acrmap.Config: the operator-declared
// rule set + default fallback a federation entry's upstream `acr` claim is
// normalized through. Mirrors acrmap.Config's shape as an independent DTO
// (matching OIDCFederationAuthConfig's own relationship to
// authenticators.OIDCFederationConfig) rather than importing the domain
// package directly, so the wire/YAML schema can evolve independently of the
// runtime mapper's Go API.
type ACRMapConfig struct {
	// Rules are evaluated in PRIORITY order — every exact rule, then every
	// regex rule, then every prefix rule — REGARDLESS of the order they
	// appear in this list. See acrmap.Config.Rules.
	Rules []ACRMapRuleConfig `yaml:"rules,omitempty"`
	// Default is the mapped ACR returned when no rule matches (or Rules is
	// empty). "" (the default) means "no claim" — AchievedACR stays unset.
	Default string `yaml:"default,omitempty"`
}

// ACRMapRuleConfig is one {match_type, pattern, mapped_acr} rule. MatchType
// MUST be "exact" | "regex" | "prefix"; an unknown value — or, for "regex", an
// unparseable Pattern — fails LOUDLY wherever this config is translated into a
// live acrmap.PatternACRMapper (acrmap.New), never a panic discovered later at
// request time.
type ACRMapRuleConfig struct {
	MatchType string `yaml:"match_type"`
	Pattern   string `yaml:"pattern"`
	MappedACR string `yaml:"mapped_acr"`
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

	// ImportedHashDummyCost pins the bcrypt cost of the anti-enumeration dummy
	// hash the imported-hash verifier runs on a miss. It MUST match the cost of
	// the imported bcrypt corpus so an unknown-username login takes comparable
	// time to a real one — a too-low dummy is a timing oracle that distinguishes
	// known from unknown usernames. 0 (default) uses
	// authenticators.DefaultStoredHashDummyCost (12, above bcrypt's cost-10
	// default). Only consulted when imported_hash_login is true. A non-bcrypt
	// imported corpus (argon2id / PBKDF2) can't be matched exactly — import at a
	// uniform KDF for full timing parity.
	ImportedHashDummyCost int `yaml:"imported_hash_dummy_cost,omitempty"`
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

// PhoneConfig configures the phone (SMS one-time-code) authenticator.
// Embeds CodeAuthConfig inline (code length/TTL, the same shape shared with
// the email-OTP authenticator) and adds the SMS-specific transport
// sub-section, which email has no use for.
type PhoneConfig struct {
	CodeAuthConfig `yaml:",inline"`
	// SMS selects and configures the transport that actually delivers the
	// code. Unset (nil) preserves the pre-SMSConfig behavior byte-for-byte:
	// the code is logged, never sent (see SMSConfig.Provider). Only set
	// this to switch to a real SMS gateway.
	SMS *SMSConfig `yaml:"sms,omitempty"`
}

// SMSConfig configures the SMS transport the phone authenticator dials.
// Provider is a discriminator:
//
//   - "" or "log" (the default): logs the code instead of sending it —
//     byte-identical to the stub that shipped before this config section
//     existed. Every field below is ignored.
//   - "http": dispatches over the generic Twilio-Messages-API-compatible
//     REST sender in infrastructure/sms. AccountSID, AuthToken, and
//     FromNumber are then required; a misconfigured "http" provider fails
//     the boot loudly rather than silently falling back to the log stub.
//
// An unrecognized Provider value is also a loud boot failure (fail fast on
// operator typos, matching authenticators.totp.backend's convention).
type SMSConfig struct {
	Provider   string `yaml:"provider,omitempty"`
	AccountSID string `yaml:"account_sid,omitempty"`
	// AuthToken supports secret:// resolution (config/secrets.go) and an
	// SSO_AUTHENTICATORS__PHONE__SMS__AUTH_TOKEN env override — never
	// commit a plaintext token (mirrors SMTPConfig.Password).
	AuthToken  string `yaml:"auth_token,omitempty"`
	FromNumber string `yaml:"from_number,omitempty"`
	// MessageTemplate must contain the literal substring "{code}", replaced
	// with the generated verification code. Empty uses the SDK default
	// ("Your verification code is: {code}").
	MessageTemplate string `yaml:"message_template,omitempty"`
	// HTTPTimeout bounds a single outbound request; 0 uses the SDK default
	// (10s).
	HTTPTimeout time.Duration `yaml:"http_timeout,omitempty"`
	// BaseURL overrides the REST API origin — set only to point at a
	// Twilio-compatible gateway (or a test double); empty uses the real
	// Twilio API origin.
	BaseURL string `yaml:"base_url,omitempty"`
}

// MagicLinkConfig configures the magic-link (passwordless emailed-link)
// authenticator. A variant of CodeAuthConfig's shape rather than an embed of
// it: TokenLength is a crypto/rand BYTE count (base64url-encoded), not a
// digit count, and BaseURL has no equivalent in the numeric-code flows at
// all — the emailed value here is a clickable URL, not something the user
// types back in.
type MagicLinkConfig struct {
	Enabled bool `yaml:"enabled"`
	// BaseURL is the login-UI landing page the emailed link points at (e.g.
	// "https://sso.example.com/login/"). REQUIRED when Enabled: an enabled
	// magic-link authenticator with no landing page can never be completed,
	// so cmd fails the boot loudly rather than silently shipping a dead
	// feature (see appendMagicLinkAuthenticator).
	BaseURL string `yaml:"base_url"`
	// TokenLength is the crypto/rand BYTE length of the opaque token before
	// base64url encoding; 0 uses authenticators.DefaultMagicLinkTokenBytes
	// (32 = 256 bits of entropy).
	TokenLength int `yaml:"token_length,omitempty"`
	// TTL bounds how long the emailed link remains valid; 0 uses
	// authenticators.DefaultMagicLinkTTL.
	TTL time.Duration `yaml:"ttl,omitempty"`
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
	// Backend selects the enrollment-secret store: "" (infer: sqlite_dsn set ->
	// sqlite, else memory) | "memory" | "sqlite" | "postgres". The secret MUST
	// be shared across replicas in a multi-replica deployment — "memory" is
	// per-pod (a factor enrolled on one replica is invisible at login on
	// another, breaking MFA for ~(N-1)/N of logins). Use "postgres" (the shared
	// db-cluster, cluster-shared) or "sqlite" (shared volume) for HA.
	Backend string `yaml:"backend,omitempty"`
	// SQLiteDSN enables durable TOTP secret + factor storage backing both
	// login verification and self-service enrollment (/me/mfa/totp). Used when
	// backend=sqlite (or backend is empty and this is set). The secret is
	// MUST-encrypt material: use an encrypted DSN or full-disk encryption.
	SQLiteDSN string `yaml:"sqlite_dsn,omitempty"`
}
