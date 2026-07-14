package serverbuildauthn

import (
	"database/sql"

	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/domains/authenticators"

	"github.com/snaplink/sso/config"
	postgresbackend "github.com/snaplink/sso/infrastructure/postgres"
	redisbackend "github.com/snaplink/sso/infrastructure/redis"
)

// BuildAuthenticators returns the configured authenticators, the temp
// token store (when wired), and the *TOTPAuthenticator handle (when
// TOTP is enabled). Both ancillary returns are separated so admin /
// MFA wiring downstream can reuse the same backing instances —
// admin TokenAdminService issues against the temp store; MFA
// orchestration wraps the TOTP authenticator with TOTPMFAProvider so
// step-up and primary auth share one secret store + skew policy.
// Both return nil when the corresponding authenticator is disabled.
//
// Returns an error when an authenticator's config is invalid (e.g. a
// missing weak-password extension file) — a misconfigured authenticator
// should fail the boot loudly, not silently degrade.
// BuildAuthenticators is the no-durable-pool entry point (the in-process /
// sqlite / redis backends only). It forwards to BuildAuthenticatorsDurable with
// a nil Postgres pool so existing call sites stay unchanged.
func BuildAuthenticators(cfg *config.Config, logger spi.Logger, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, rdb goredis.Cmdable) ([]sso.Authenticator, authenticators.TempTokenStore, *authenticators.TOTPAuthenticator, sso.MFAEnrollmentStore, error) {
	return BuildAuthenticatorsDurable(cfg, logger, passwordStore, userProvider, rdb, nil, "")
}

// BuildAuthenticatorsDurable is BuildAuthenticators plus the shared Postgres
// durable pool + dialect, so an authenticator whose state MUST be cluster-shared
// (today: TOTP enrollment secrets) can select the postgres db-cluster backend.
// pg may be nil (no postgres block) — backends that require it then fail loud at
// boot rather than silently using per-pod state.
func BuildAuthenticatorsDurable(cfg *config.Config, logger spi.Logger, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, rdb goredis.Cmdable, pg *sql.DB, dialect postgresbackend.Dialect) ([]sso.Authenticator, authenticators.TempTokenStore, *authenticators.TOTPAuthenticator, sso.MFAEnrollmentStore, error) {
	var auths []sso.Authenticator
	var tempStore authenticators.TempTokenStore
	var totpAuth *authenticators.TOTPAuthenticator
	// totpEnrollStore is the unified TOTP store (also a TOTPEnrollmentWriter +
	// MFAEnrollmentStore) when TOTP is enabled — surfaced so the caller can wire
	// self-service /me/mfa + TOTP enrollment over the SAME secret store the
	// authenticator reads. Nil when TOTP is off.
	var totpEnrollStore sso.MFAEnrollmentStore
	codeStore := buildCodeStore(rdb)

	// Replay-defense store for the keypair (nonce) + TOTP (consumed-code)
	// authenticators, built once and shared (their keys live in disjoint
	// namespaces). Resolved lazily so a binary with neither authenticator
	// enabled opens no extra backend. Reuses the jti-replay backend when the
	// operator enabled it (cluster-shared sqlite) and otherwise defaults to a
	// memory store so the shipped binary is replay-safe out of the box.
	authReplayStore := newAuthReplayStore(cfg.Security.JTIReplay, rdb)

	auths, err := appendCodeBasedAuthenticators(auths, cfg, codeStore, passwordStore, userProvider, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	if a := cfg.Authenticators.TempToken; a != nil && a.Enabled {
		tempStore = buildTempTokenStore(rdb)
		auths = append(auths, authenticators.NewTempTokenAuthenticator(tempStore, a.TTL))
	}

	auths, err = appendKeyPairAuthenticator(auths, cfg.Authenticators.KeyPair, authReplayStore, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	auths = appendAPIKeyAuthenticator(auths, cfg.Authenticators.APIKey, logger)
	auths = appendCertificateAuthenticator(auths, cfg.Authenticators.Certificate, logger)

	auths, totpAuth, totpEnrollStore, err = appendTOTPAuthenticator(auths, cfg.Authenticators.TOTP, authReplayStore, pg, dialect, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	// linker nil: no identitylink.Store is built in this binary yet (see
	// appendOIDCFederationAuthenticators's doc for the wiring seam this leaves).
	auths = appendOIDCFederationAuthenticators(auths, cfg.Authenticators.OIDCFederation, logger, nil)
	return auths, tempStore, totpAuth, totpEnrollStore, nil
}

// appendCodeBasedAuthenticators wires password, phone, email, and magic-link
// — grouped into one helper (rather than inline call+error-check blocks in
// BuildAuthenticatorsDurable) so that function stays under the
// maintainability function-length budget as each grows its own config
// surface (e.g. phone's SMS provider discriminator, magic-link's base_url).
func appendCodeBasedAuthenticators(auths []sso.Authenticator, cfg *config.Config, codeStore authenticators.CodeStore, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, logger spi.Logger) ([]sso.Authenticator, error) {
	auths, err := appendPasswordAuthenticator(auths, cfg.Authenticators.Password, passwordStore, userProvider, logger)
	if err != nil {
		return nil, err
	}
	auths, err = appendPhoneAuthenticator(auths, cfg.Authenticators.Phone, codeStore, logger)
	if err != nil {
		return nil, err
	}
	auths, err = appendEmailAuthenticator(auths, cfg.Authenticators.Email, codeStore, cfg.SMTP, logger)
	if err != nil {
		return nil, err
	}
	// Magic-link shares the SAME CodeStore + SMTP sender as email-OTP — the
	// two flows use disjoint key namespaces (keyPrefixEmail vs
	// keyPrefixMagicLink) so requesting both for one address never collides.
	return appendMagicLinkAuthenticator(auths, cfg.Authenticators.MagicLink, codeStore, cfg.SMTP, logger)
}

// buildCodeStore selects the passwordless email/phone OTP code store. Send and
// verify span two requests that can land on different replicas, so the store
// MUST be cluster-shared on a multi-replica deploy — auto-select redis when a
// cluster is wired; the single-process binary keeps the in-memory store.
func buildCodeStore(rdb goredis.Cmdable) authenticators.CodeStore {
	if rdb != nil {
		return redisbackend.NewCodeStore(rdb)
	}
	return authenticators.NewMemoryCodeStore()
}

// buildTempTokenStore selects the single-use temp-token store (also backs the
// admin TokenAdminService). Issue and redeem span two requests, so it must be
// cluster-shared on a multi-replica deploy — redis when a cluster is wired.
func buildTempTokenStore(rdb goredis.Cmdable) authenticators.TempTokenStore {
	if rdb != nil {
		return redisbackend.NewTempTokenStore(rdb)
	}
	return authenticators.NewMemoryTempTokenStore()
}
