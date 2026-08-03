package serverbuildauthn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/cmd/sso-server/serverbuildplatform"
	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/domains/authenticators"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	sqlitestores "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/sqlite"
	postgresbackend "github.com/yangwb1123/snaplink/infrastructure/postgres"
	"github.com/yangwb1123/snaplink/infrastructure/sms"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/shared/security"
	"github.com/yangwb1123/snaplink/shared/spi"
	"golang.org/x/crypto/bcrypt"
)

// SMS provider discriminators (config.SMSConfig.Provider) — no literal
// leaks (AGENTS.md §4).
const (
	smsProviderLog  = "log"
	smsProviderHTTP = "http"
)

// authReplayStoreFn lazily resolves the shared keypair/TOTP replay-defense
// store on first use. See BuildAuthenticators for why it is shared + lazy.
type authReplayStoreFn func() (security.JTIReplayStore, string, error)

func newAuthReplayStore(cfg config.JTIReplayConfig, rdb goredis.Cmdable) authReplayStoreFn {
	var replayStore security.JTIReplayStore
	var replayMode string
	return func() (security.JTIReplayStore, string, error) {
		if replayStore != nil {
			return replayStore, replayMode, nil
		}
		s, mode, err := buildAuthenticatorReplayStore(cfg, rdb)
		if err != nil {
			return nil, "", err
		}
		replayStore, replayMode = s, mode
		return replayStore, replayMode, nil
	}
}

// buildPasswordAuthVerifier resolves the primary password verifier (store-backed
// or in-memory) and, when opted in, chains the imported-hash verifier after it.
func buildPasswordAuthVerifier(a *config.PasswordConfig, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, logger spi.Logger) (authenticators.PasswordVerifier, int, error) {
	var verifier authenticators.PasswordVerifier
	var seeded int
	if passwordStore != nil {
		// Self-service password store wired: seed it from the YAML users
		// (by bcrypt hash) and serve login FROM the store, so a password
		// changed via /me/password takes effect on the next login.
		v, n, err := BuildStoredPasswordVerifier(passwordStore, a.Users, logger)
		if err != nil {
			return nil, 0, fmt.Errorf("password store seed: %w", err)
		}
		verifier, seeded = v, n
	} else {
		verifier, seeded = BuildBcryptPasswordVerifier(a.Users, logger)
	}
	verifier = chainRuntimeStoreVerifier(verifier, passwordStore, userProvider)
	// Imported-user login: chain an attribute-backed multi-format verifier
	// after the primary so users migrated via cmd/sso-import (whose hash
	// lives on User.Attributes in bcrypt/argon2id/PBKDF2) can authenticate.
	// Wrapped in lazy bcrypt re-hashing so a verified legacy hash is upgraded
	// to bcrypt on first login. Inert (byte-identical) without both the
	// opt-in flag and a UserProvider.
	if a.ImportedHashLogin && userProvider != nil {
		needs, update := authenticators.StoredHashRehashHooks(userProvider)
		// Match the miss-path dummy bcrypt cost to the imported corpus so an
		// unknown-username login isn't measurably faster than a real verify
		// (enumeration timing oracle). 0 = DefaultStoredHashDummyCost.
		var shOpts []authenticators.StoredHashOption
		if a.ImportedHashDummyCost > 0 {
			shOpts = append(shOpts, authenticators.WithStoredHashDummyCost(a.ImportedHashDummyCost))
		}
		// Wire a Hasher so the dummy cost tracks the operator's target cost
		// automatically when no explicit pin is set. Use bcrypt.DefaultCost
		// (matching HashPassword) as the hasher's report — the lazy rehash
		// path re-mints imported hashes at this cost, so the miss-path dummy
		// should match it in steady state.
		if a.ImportedHashDummyCost <= 0 {
			shOpts = append(shOpts, authenticators.WithHasher(authenticators.NewBcryptHasher(bcrypt.DefaultCost)))
		}
		lazyStored := &authenticators.LazyRehashVerifier{
			Underlying:  authenticators.NewStoredHashVerifier(userProvider, shOpts...),
			NeedsRehash: needs,
			Updater:     update,
			Logger:      logger,
		}
		verifier = authenticators.NewChainPasswordVerifier(verifier, lazyStored)
		logger.Info("imported-hash login enabled (sso-import users can authenticate)", "dummy_bcrypt_cost", a.ImportedHashDummyCost)
	}
	return verifier, seeded, nil
}

// chainRuntimeStoreVerifier chains a UserProvider-resolving store verifier onto
// base so runtime-created users — self-service signup, admin user-create/reset,
// and the first-run setup wizard, all of which write a credential to the store
// keyed by userID (== the login username) — can authenticate. The YAML verifier
// (base) only knows usernames seeded from authenticators.password.users at boot,
// so without this those users could never log in. NewStoredPasswordVerifier
// resolves username -> userID via GetByID and spends a cost-matched dummy
// compare on an unknown user (no enumeration oracle); ChainPasswordVerifier runs
// every verifier on a failed login regardless, so base stays byte-identical and
// first. No-op when either dependency is absent.
func chainRuntimeStoreVerifier(base authenticators.PasswordVerifier, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider) authenticators.PasswordVerifier {
	if passwordStore == nil || userProvider == nil {
		return base
	}
	resolve := func(ctx context.Context, username string) (string, error) {
		u, err := userProvider.GetByID(ctx, username)
		if err != nil || u == nil {
			return "", err // -> the verifier's timing-parity dummy-compare miss path
		}
		return u.ID, nil
	}
	return authenticators.NewChainPasswordVerifier(base, authenticators.NewStoredPasswordVerifier(passwordStore, resolve))
}

func appendPasswordAuthenticator(auths []sso.Authenticator, a *config.PasswordConfig, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, logger spi.Logger) ([]sso.Authenticator, error) {
	if a == nil || !a.Enabled {
		return auths, nil
	}
	verifier, seeded, err := buildPasswordAuthVerifier(a, passwordStore, userProvider, logger)
	if err != nil {
		return nil, err
	}
	var pwOpts []authenticators.PasswordOption
	if h := a.Health; h != nil && h.Enabled {
		checker, err := BuildPasswordHealthChecker(h, logger)
		if err != nil {
			return nil, fmt.Errorf("password health checker: %w", err)
		}
		// Pass the logger alongside the checker so a malfunctioning
		// custom checker (e.g. an HIBP lookup) is observable in
		// production; the health check stays fail-open regardless.
		pwOpts = append(pwOpts, authenticators.WithPasswordHealthChecker(checker), authenticators.WithPasswordLogger(logger))
	}
	auths = append(auths, authenticators.NewPasswordAuthenticator(verifier, pwOpts...))
	logger.Info("password authenticator enabled", "seeded_users", seeded)
	return auths, nil
}

func appendPhoneAuthenticator(auths []sso.Authenticator, a *config.PhoneConfig, codeStore authenticators.CodeStore, logger spi.Logger, delivery ...config.CodeDeliveryConfig) ([]sso.Authenticator, error) {
	if a == nil || !a.Enabled {
		return auths, nil
	}
	sender, err := buildPhoneSMSSender(a.SMS, logger)
	if err != nil {
		return nil, fmt.Errorf("phone sms sender: %w", err)
	}
	if len(delivery) > 0 {
		sender = wrapSMSCodeSender(sender, delivery[0], logger)
	}
	return append(auths, authenticators.NewPhoneAuthenticator(
		codeStore,
		sender,
		authenticators.WithPhoneCodeLength(a.CodeLength),
		authenticators.WithPhoneCodeTTL(a.CodeTTL),
	)), nil
}

// buildPhoneSMSSender resolves the SMS transport the phone authenticator
// dials, keyed on cfg.Provider: "" / "log" (default — logs the code instead
// of sending it, byte-identical to the stub that shipped before SMSConfig
// existed) or "http" (the built-in Twilio-Messages-API-compatible REST
// sender in infrastructure/sms). A misconfigured "http" provider (missing
// required field, or an unrecognized Provider value) fails loud here rather
// than silently falling back to the log stub — the same fail-fast contract
// buildTOTPEnrollmentStore applies to an unknown authenticators.totp.backend.
func buildPhoneSMSSender(cfg *config.SMSConfig, logger spi.Logger) (authenticators.SMSSender, error) {
	provider := smsProviderLog
	if cfg != nil && strings.TrimSpace(cfg.Provider) != "" {
		provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	}
	switch provider {
	case smsProviderLog:
		return authenticators.SMSSenderFunc(func(_ context.Context, phone, code string) error {
			logger.Info("sms stub", "phone", phone, "code", code)
			return nil
		}), nil
	case smsProviderHTTP:
		sender, err := sms.New(sms.Config{
			AccountSID:      cfg.AccountSID,
			AuthToken:       cfg.AuthToken,
			FromNumber:      cfg.FromNumber,
			MessageTemplate: cfg.MessageTemplate,
			HTTPTimeout:     cfg.HTTPTimeout,
			BaseURL:         cfg.BaseURL,
		})
		if err != nil {
			return nil, fmt.Errorf("authenticators.phone.sms: %w", err)
		}
		return authenticators.SMSSenderFunc(sender.Send), nil
	default:
		return nil, fmt.Errorf("unknown authenticators.phone.sms.provider %q (supported: log, http)", cfg.Provider)
	}
}

func appendEmailAuthenticator(auths []sso.Authenticator, a *config.CodeAuthConfig, codeStore authenticators.CodeStore, smtpCfg config.SMTPConfig, logger spi.Logger, delivery ...config.CodeDeliveryConfig) ([]sso.Authenticator, error) {
	if a == nil || !a.Enabled {
		return auths, nil
	}
	sender, err := buildEmailOTPSender(smtpCfg, logger)
	if err != nil {
		return nil, err
	}
	if len(delivery) > 0 {
		sender = wrapEmailCodeSender(sender, delivery[0], logger, "email")
	}
	return append(auths, authenticators.NewEmailAuthenticator(
		codeStore,
		sender,
		authenticators.WithEmailCodeLength(a.CodeLength),
		authenticators.WithEmailCodeTTL(a.CodeTTL),
	)), nil
}

// buildEmailOTPSender resolves the email-OTP transport EmailAuthenticator
// dials: the built-in SMTP sender when smtp.enabled and a host is configured,
// else the pre-existing log-only stub (byte-identical to before this
// existed). Reuses serverbuildplatform.BuildEmailSender (same translation +
// nil-on-disabled semantics as the four shared/spi token senders) rather than
// duplicating the config.SMTPConfig -> emailsmtp.Config mapping here.
func buildEmailOTPSender(smtpCfg config.SMTPConfig, logger spi.Logger) (authenticators.EmailSender, error) {
	sender, err := serverbuildplatform.BuildEmailSender(smtpCfg, logger)
	if err != nil {
		return nil, fmt.Errorf("email-otp smtp sender: %w", err)
	}
	if sender == nil {
		return authenticators.EmailSenderFunc(func(_ context.Context, email, code string) error {
			logger.Info("email stub", "email", email, "code", code)
			return nil
		}), nil
	}
	return authenticators.EmailSenderFunc(sender.Send), nil
}

// appendMagicLinkAuthenticator wires the magic-link (passwordless emailed
// link) authenticator. Reuses the SAME email-OTP SMTP sender as
// appendEmailAuthenticator (buildEmailOTPSender): EmailSender is "deliver
// this string to this address" regardless of whether the string is a short
// numeric code or a magic-link URL (see MagicLinkAuthenticator.SendCode's own
// doc comment for why the interface needed no changes). base_url is REQUIRED
// when enabled: a magic-link authenticator with no landing page can never be
// completed, so this fails the boot loudly rather than silently shipping a
// dead feature — mirrors buildPhoneSMSSender's fail-fast contract for a
// misconfigured "http" SMS provider.
func appendMagicLinkAuthenticator(auths []sso.Authenticator, a *config.MagicLinkConfig, codeStore authenticators.CodeStore, smtpCfg config.SMTPConfig, logger spi.Logger, delivery ...config.CodeDeliveryConfig) ([]sso.Authenticator, error) {
	if a == nil || !a.Enabled {
		return auths, nil
	}
	if strings.TrimSpace(a.BaseURL) == "" {
		return nil, errors.New("authenticators.magic_link.base_url is required when enabled")
	}
	sender, err := buildEmailOTPSender(smtpCfg, logger)
	if err != nil {
		return nil, fmt.Errorf("magic link smtp sender: %w", err)
	}
	if len(delivery) > 0 {
		sender = wrapEmailCodeSender(sender, delivery[0], logger, "magic_link")
	}
	auths = append(auths, authenticators.NewMagicLinkAuthenticator(
		codeStore,
		sender,
		a.BaseURL,
		authenticators.WithMagicLinkTokenLength(a.TokenLength),
		authenticators.WithMagicLinkTTL(a.TTL),
	))
	logger.Info("magic link authenticator enabled", "base_url", a.BaseURL)
	return auths, nil
}

func appendKeyPairAuthenticator(auths []sso.Authenticator, a *config.KeyPairConfig, replay authReplayStoreFn, logger spi.Logger) ([]sso.Authenticator, error) {
	if a == nil || !a.Enabled {
		return auths, nil
	}
	store := authenticators.NewMemoryPublicKeyStore()
	seeded := 0
	for _, k := range a.PublicKeys {
		if k.KeyID == "" || k.PublicKeyFile == "" || k.SubjectID == "" {
			logger.Error("keypair seed skipped (missing field)",
				"key_id", k.KeyID, "subject_id", k.SubjectID)
			continue
		}
		pub, err := LoadEd25519PublicKeyPEM(k.PublicKeyFile)
		if err != nil {
			logger.Error("keypair seed skipped (load pub key)",
				"key_id", k.KeyID, "file", k.PublicKeyFile, "error", err)
			continue
		}
		store.Register(k.KeyID, pub, &sso.Subject{ID: k.SubjectID})
		seeded++
	}
	// Nonce-replay defense: without it the SAME (key_id, nonce, timestamp)
	// signature replays within the clock-skew window. Always wired so the
	// shipped binary is not replay-vulnerable by default.
	nonceStore, replayMode, err := replay()
	if err != nil {
		return nil, fmt.Errorf("keypair nonce store: %w", err)
	}
	auths = append(auths, authenticators.NewKeyPairAuthenticator(store, a.MaxClockSkew,
		authenticators.WithKeyPairNonceStore(nonceStore),
		authenticators.WithKeyPairLogger(logger)))
	logger.Info("keypair authenticator enabled", "seeded_keys", seeded, "nonce_replay_store", replayMode)
	return auths, nil
}

func appendAPIKeyAuthenticator(auths []sso.Authenticator, a *config.APIKeyConfig, logger spi.Logger) []sso.Authenticator {
	if a == nil || !a.Enabled {
		return auths
	}
	store := authenticators.NewMemoryAPIKeyStore()
	seeded := 0
	for _, k := range a.Keys {
		if k.KeyID == "" || k.SecretFile == "" || k.SubjectID == "" {
			logger.Error("apikey seed skipped (missing field)",
				"key_id", k.KeyID, "subject_id", k.SubjectID)
			continue
		}
		secret, err := LoadSecretFile(k.SecretFile)
		if err != nil {
			logger.Error("apikey seed skipped (load secret)",
				"key_id", k.KeyID, "file", k.SecretFile, "error", err)
			continue
		}
		store.Register(k.KeyID, secret, &sso.Subject{ID: k.SubjectID})
		seeded++
	}
	auths = append(auths, authenticators.NewAPIKeyAuthenticator(store))
	logger.Info("apikey authenticator enabled", "seeded_keys", seeded)
	return auths
}

func appendCertificateAuthenticator(auths []sso.Authenticator, a *config.CertificateConfig, logger spi.Logger) []sso.Authenticator {
	if a == nil || !a.Enabled {
		return auths
	}
	roots, err := LoadCertPool(a.TrustedCAFiles)
	if err != nil {
		logger.Error("certificate authenticator skipped (trusted_ca_files)", "error", err)
		return auths
	}
	var certOpts []authenticators.CertOption
	if len(a.IntermediateFiles) > 0 {
		inter, err := LoadCertPool(a.IntermediateFiles)
		if err != nil {
			logger.Error("certificate authenticator: intermediate_files", "error", err)
		} else {
			certOpts = append(certOpts, authenticators.WithCertIntermediates(inter))
		}
	}
	auths = append(auths, authenticators.NewCertificateAuthenticator(roots, certOpts...))
	logger.Info("certificate authenticator enabled",
		"trusted_cas", len(a.TrustedCAFiles),
		"intermediates", len(a.IntermediateFiles))
	return auths
}

// appendTOTPAuthenticator wires the TOTP authenticator + its unified enrollment
// store (also the self-service /me/mfa list + enrollment writer). Returns the
// updated auths slice plus the built *TOTPAuthenticator and MFAEnrollmentStore
// (both nil when TOTP is off) for the caller to surface.
func appendTOTPAuthenticator(auths []sso.Authenticator, a *config.TOTPConfig, replay authReplayStoreFn, pg *sql.DB, dialect postgresbackend.Dialect, logger spi.Logger) ([]sso.Authenticator, *authenticators.TOTPAuthenticator, sso.MFAEnrollmentStore, error) {
	if a == nil || !a.Enabled {
		return auths, nil, nil, nil
	}
	// MemoryTOTPEnrollmentStore is the dev / demo tier — secrets are
	// MUST-encrypt material in production, so operators with durable needs
	// should fork cmd and supply their own store. The unified store plays
	// THREE roles off one instance: the authenticator's secret source, the
	// self-service /me/mfa list, and the TOTP enrollment writer — so a
	// factor enrolled via /me/mfa/totp is immediately usable at login.
	var totpOpts []authenticators.TOTPOption
	if a.SkewSteps > 0 {
		totpOpts = append(totpOpts, authenticators.WithTOTPSkew(a.SkewSteps))
	}
	// Consumed-code defense: without it a captured 6-digit code replays for
	// the rest of its step window. Always wired so the shipped binary
	// enforces one-time-use by default.
	consumedStore, replayMode, err := replay()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("totp consumed store: %w", err)
	}
	totpOpts = append(totpOpts,
		authenticators.WithTOTPConsumedStore(consumedStore),
		authenticators.WithTOTPLogger(logger))
	logger.Info("totp one-time-use enforcement enabled", "consumed_store", replayMode)
	totpAuth, totpEnrollStore, err := buildTOTPEnrollmentStore(a, pg, dialect, totpOpts, logger)
	if err != nil {
		return nil, nil, nil, err
	}
	auths = append(auths, totpAuth)
	return auths, totpAuth, totpEnrollStore, nil
}

// buildTOTPEnrollmentStore resolves the unified TOTP enrollment store +
// authenticator for the configured backend. The store plays three roles off one
// instance: the authenticator's secret source, the /me/mfa list, and the TOTP
// enrollment writer. Empty backend infers sqlite (when a dsn is set) else
// memory; postgres reaches the shared db-cluster so a factor enrolled on one
// replica is usable at login on every replica (the secret MUST be cluster-shared
// in HA). Fails loud when a cluster-shared backend is requested without its
// pool — mirrors BuildPairwiseSubjectStore.
func buildTOTPEnrollmentStore(a *config.TOTPConfig, pg *sql.DB, dialect postgresbackend.Dialect, totpOpts []authenticators.TOTPOption, logger spi.Logger) (*authenticators.TOTPAuthenticator, sso.MFAEnrollmentStore, error) {
	backend := strings.ToLower(strings.TrimSpace(a.Backend))
	if backend == "" {
		if a.SQLiteDSN != "" {
			backend = "sqlite"
		} else {
			backend = "memory"
		}
	}
	switch backend {
	case "postgres":
		if pg == nil {
			return nil, nil, errors.New("authenticators.totp.backend=postgres but no postgres block configured (set postgres.dsn)")
		}
		pgStore, err := postgresbackend.NewTOTPEnrollmentStoreWithDB(pg, dialect)
		if err != nil {
			return nil, nil, fmt.Errorf("totp.postgres: %w", err)
		}
		logger.Info("totp authenticator enabled (postgres store; cluster-shared)")
		return authenticators.NewTOTPAuthenticator(pgStore, totpOpts...), pgStore, nil
	case "sqlite":
		if a.SQLiteDSN == "" {
			return nil, nil, errors.New("authenticators.totp.backend=sqlite requires authenticators.totp.sqlite_dsn")
		}
		sqliteStore, err := sqlitestores.NewTOTPEnrollmentStore(a.SQLiteDSN)
		if err != nil {
			return nil, nil, fmt.Errorf("totp.sqlite: %w", err)
		}
		logger.Info("totp authenticator enabled (sqlite store)")
		return authenticators.NewTOTPAuthenticator(sqliteStore, totpOpts...), sqliteStore, nil
	case "memory":
		enrollStore := defaultimpl.NewMemoryTOTPEnrollmentStore()
		logger.Info("totp authenticator enabled (memory store; set authenticators.totp.backend=postgres for multi-replica)")
		return authenticators.NewTOTPAuthenticator(enrollStore, totpOpts...), enrollStore, nil
	default:
		return nil, nil, fmt.Errorf("unknown authenticators.totp.backend %q (supported: memory, sqlite, postgres)", a.Backend)
	}
}

// appendOIDCFederationAuthenticators wires each configured federation entry.
// linker, when non-nil, is passed to EVERY entry via
// authenticators.WithUserLinker — see the call site in BuildAuthenticatorsDurable
// for why this binary always passes nil today (no identitylink.Store is
// built here yet). A nil linker is a no-op (authenticators.WithUserLinker's
// doc): behavior is byte-identical to before UserLinker existed.
func appendOIDCFederationAuthenticators(auths []sso.Authenticator, feds []*config.OIDCFederationAuthConfig, logger spi.Logger, linker authenticators.UserLinker) []sso.Authenticator {
	for _, fed := range feds {
		if fed == nil {
			continue
		}
		auth, err := authenticators.NewOIDCFederationAuthenticator(authenticators.OIDCFederationConfig{
			Name:                  fed.Name,
			AuthorizationEndpoint: fed.AuthorizationEndpoint,
			TokenEndpoint:         fed.TokenEndpoint,
			UserinfoEndpoint:      fed.UserinfoEndpoint,
			ClientID:              fed.ClientID,
			ClientSecret:          fed.ClientSecret,
			RedirectURI:           fed.RedirectURI,
			Scopes:                fed.Scopes,
			SubjectFieldOverride:  fed.SubjectFieldOverride,
			Timeout:               fed.Timeout,
		}, authenticators.WithUserLinker(linker))
		if err != nil {
			logger.Error("oidc_federation skipped (bad config)", "name", fed.Name, "error", err)
			continue
		}
		auths = append(auths, auth)
		logger.Info("oidc_federation enabled", "provider", fed.Name, "authorization_endpoint", fed.AuthorizationEndpoint)
	}
	return auths
}
