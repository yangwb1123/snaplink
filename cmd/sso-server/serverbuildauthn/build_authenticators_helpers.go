package serverbuildauthn

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/domains/authenticators"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
	postgresbackend "github.com/snaplink/sso/postgres"
	"github.com/snaplink/sso/shared/security"
	"github.com/snaplink/sso/shared/spi"
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

func appendPhoneAuthenticator(auths []sso.Authenticator, a *config.CodeAuthConfig, codeStore authenticators.CodeStore, logger spi.Logger) []sso.Authenticator {
	if a == nil || !a.Enabled {
		return auths
	}
	return append(auths, authenticators.NewPhoneAuthenticator(
		codeStore,
		authenticators.SMSSenderFunc(func(_ context.Context, phone, code string) error {
			logger.Info("sms stub", "phone", phone, "code", code)
			return nil
		}),
		authenticators.WithPhoneCodeLength(a.CodeLength),
		authenticators.WithPhoneCodeTTL(a.CodeTTL),
	))
}

func appendEmailAuthenticator(auths []sso.Authenticator, a *config.CodeAuthConfig, codeStore authenticators.CodeStore, logger spi.Logger) []sso.Authenticator {
	if a == nil || !a.Enabled {
		return auths
	}
	return append(auths, authenticators.NewEmailAuthenticator(
		codeStore,
		authenticators.EmailSenderFunc(func(_ context.Context, email, code string) error {
			logger.Info("email stub", "email", email, "code", code)
			return nil
		}),
		authenticators.WithEmailCodeLength(a.CodeLength),
		authenticators.WithEmailCodeTTL(a.CodeTTL),
	))
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

func appendOIDCFederationAuthenticators(auths []sso.Authenticator, feds []*config.OIDCFederationAuthConfig, logger spi.Logger) []sso.Authenticator {
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
		})
		if err != nil {
			logger.Error("oidc_federation skipped (bad config)", "name", fed.Name, "error", err)
			continue
		}
		auths = append(auths, auth)
		logger.Info("oidc_federation enabled", "provider", fed.Name, "authorization_endpoint", fed.AuthorizationEndpoint)
	}
	return auths
}
