package serverbuildauthn

import (
	goredis "github.com/redis/go-redis/v9"

	"github.com/snaplink/sso/interfaces/sso"
	"github.com/snaplink/sso/shared/spi"

	"github.com/snaplink/sso/domains/authenticators"

	"github.com/snaplink/sso/config"
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
func BuildAuthenticators(cfg *config.Config, logger spi.Logger, passwordStore sso.PasswordCredentialStore, userProvider sso.UserProvider, rdb goredis.Cmdable) ([]sso.Authenticator, authenticators.TempTokenStore, *authenticators.TOTPAuthenticator, sso.MFAEnrollmentStore, error) {
	var auths []sso.Authenticator
	var tempStore authenticators.TempTokenStore
	var totpAuth *authenticators.TOTPAuthenticator
	// totpEnrollStore is the unified TOTP store (also a TOTPEnrollmentWriter +
	// MFAEnrollmentStore) when TOTP is enabled — surfaced so the caller can wire
	// self-service /me/mfa + TOTP enrollment over the SAME secret store the
	// authenticator reads. Nil when TOTP is off.
	var totpEnrollStore sso.MFAEnrollmentStore
	codeStore := authenticators.NewMemoryCodeStore()

	// Replay-defense store for the keypair (nonce) + TOTP (consumed-code)
	// authenticators, built once and shared (their keys live in disjoint
	// namespaces). Resolved lazily so a binary with neither authenticator
	// enabled opens no extra backend. Reuses the jti-replay backend when the
	// operator enabled it (cluster-shared sqlite) and otherwise defaults to a
	// memory store so the shipped binary is replay-safe out of the box.
	authReplayStore := newAuthReplayStore(cfg.Security.JTIReplay, rdb)

	auths, err := appendPasswordAuthenticator(auths, cfg.Authenticators.Password, passwordStore, userProvider, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	auths = appendPhoneAuthenticator(auths, cfg.Authenticators.Phone, codeStore, logger)
	auths = appendEmailAuthenticator(auths, cfg.Authenticators.Email, codeStore, logger)

	if a := cfg.Authenticators.TempToken; a != nil && a.Enabled {
		tempStore = authenticators.NewMemoryTempTokenStore()
		auths = append(auths, authenticators.NewTempTokenAuthenticator(tempStore, a.TTL))
	}

	auths, err = appendKeyPairAuthenticator(auths, cfg.Authenticators.KeyPair, authReplayStore, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	auths = appendAPIKeyAuthenticator(auths, cfg.Authenticators.APIKey, logger)
	auths = appendCertificateAuthenticator(auths, cfg.Authenticators.Certificate, logger)

	auths, totpAuth, totpEnrollStore, err = appendTOTPAuthenticator(auths, cfg.Authenticators.TOTP, authReplayStore, logger)
	if err != nil {
		return nil, nil, nil, nil, err
	}

	auths = appendOIDCFederationAuthenticators(auths, cfg.Authenticators.OIDCFederation, logger)
	return auths, tempStore, totpAuth, totpEnrollStore, nil
}
