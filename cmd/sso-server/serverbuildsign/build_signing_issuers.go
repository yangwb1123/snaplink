package serverbuildsign

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	goredis "github.com/redis/go-redis/v9"

	"github.com/yangwb1123/snaplink/config"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
	"github.com/yangwb1123/snaplink/infrastructure/defaultimpl/cryptosigner"
	"github.com/yangwb1123/snaplink/interfaces/sso"
	"github.com/yangwb1123/snaplink/platform/metrics"
	"github.com/yangwb1123/snaplink/shared/spi"
)

// resolveExternalSigner resolves the optional KMS/HSM signer named in
// keys.signing.external up front; its kid names the key in JWKS + token
// headers. Returns (nil, "", nil) when no external signer is configured.
func resolveExternalSigner(sc config.SigningConfig, m *metrics.Metrics, logger spi.Logger) (crypto.Signer, string, error) {
	name := strings.TrimSpace(sc.External)
	if name == "" {
		return nil, "", nil
	}
	f, ok := lookupExternalSigner(name)
	if !ok {
		return nil, "", fmt.Errorf("keys.signing.external %q is not registered (registered: %v; call RegisterExternalSigner in your cmd binary)", name, registeredExternalSigners())
	}
	s, kid, err := f(context.Background())
	if err != nil {
		return nil, "", fmt.Errorf("keys.signing.external %q: %w", name, err)
	}
	if s == nil {
		return nil, "", fmt.Errorf("keys.signing.external %q returned a nil signer", name)
	}
	// Instrument the KMS/HSM round-trip (no-op when metrics disabled).
	extSigner := InstrumentSigner(s, normalizeAlgLabel(sc.Alg), m, logger)
	logger.Info("signing key: external signer", "name", name, "kid", kid)
	return extSigner, kid, nil
}

func buildEd25519SigningIssuer(sc config.SigningConfig, srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore, m *metrics.Metrics) (SigningIssuer, string, crypto.Signer, error) {
	opts := []defaultimpl.Ed25519Option{
		defaultimpl.WithEd25519Issuer(srv.Issuer),
		defaultimpl.WithEd25519TokenTTL(srv.TokenTTL),
		defaultimpl.WithEd25519MaxClockSkew(srv.MaxClockSkew),
		defaultimpl.WithEd25519Metrics(m),
	}
	if extSigner != nil {
		sgn, pub, err := cryptosigner.Ed25519(extSigner)
		if err != nil {
			return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
		}
		opts = append(opts, defaultimpl.WithEd25519ExternalSigner(sgn, pub, extKID))
	}
	if revStore != nil {
		opts = append(opts, defaultimpl.WithEd25519RevocationStore(revStore))
	}
	if sc.KeyFile != "" {
		opts = append(opts, defaultimpl.WithEd25519KeyFile(sc.KeyFile))
	}
	iss := defaultimpl.NewEd25519JWTIssuer(opts...)
	if serr := seedRevocations(iss, revStore); serr != nil {
		return nil, "", nil, serr
	}
	return iss, "EdDSA", extSigner, nil
}

func buildECDSASigningIssuer(srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore, m *metrics.Metrics) (SigningIssuer, string, crypto.Signer, error) {
	opts := []defaultimpl.ECDSAOption{
		defaultimpl.WithECDSAIssuer(srv.Issuer),
		defaultimpl.WithECDSATokenTTL(srv.TokenTTL),
		defaultimpl.WithECDSAMaxClockSkew(srv.MaxClockSkew),
		defaultimpl.WithECDSAMetrics(m),
	}
	if extSigner != nil {
		sgn, pub, err := cryptosigner.ECDSA(extSigner)
		if err != nil {
			return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
		}
		opts = append(opts, defaultimpl.WithECDSAExternalSigner(sgn, pub, extKID))
	}
	if revStore != nil {
		opts = append(opts, defaultimpl.WithECDSARevocationStore(revStore))
	}
	iss := defaultimpl.NewECDSAJWTIssuer(opts...)
	if serr := seedRevocations(iss, revStore); serr != nil {
		return nil, "", nil, serr
	}
	return iss, "ES256", extSigner, nil
}

func buildRSASigningIssuer(alg string, srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore, m *metrics.Metrics) (SigningIssuer, string, crypto.Signer, error) {
	signingAlg := "RS256"
	if alg == "ps256" {
		signingAlg = "PS256"
	}
	opts := []defaultimpl.RSAOption{
		defaultimpl.WithRSAIssuer(srv.Issuer),
		defaultimpl.WithRSAAlg(signingAlg),
		defaultimpl.WithRSATokenTTL(srv.TokenTTL),
		defaultimpl.WithRSAMaxClockSkew(srv.MaxClockSkew),
		defaultimpl.WithRSAMetrics(m),
	}
	if extSigner != nil {
		sgn, pub, err := cryptosigner.RSA(extSigner, signingAlg)
		if err != nil {
			return nil, "", nil, fmt.Errorf("keys.signing.external: %w", err)
		}
		opts = append(opts, defaultimpl.WithRSAExternalSigner(sgn, pub, extKID))
	}
	if revStore != nil {
		opts = append(opts, defaultimpl.WithRSARevocationStore(revStore))
	}
	iss := defaultimpl.NewRSAJWTIssuer(opts...)
	if serr := seedRevocations(iss, revStore); serr != nil {
		return nil, "", nil, serr
	}
	return iss, signingAlg, extSigner, nil
}

// BuildIDTokenAlgOptions wires the additional per-client id_token signing
// keys (config keys.id_token_algs) as sso.Option: for each wired alg it
// constructs a DEDICATED signing issuer and registers it BOTH via
// sso.WithTokenIssuer (the per-client-alg design requires this — the
// issuer's public key lands in the aggregated /.well-known/jwks.json and
// validateAnyToken can verify id_token hints it signs at silent renewal /
// end_session) and via sso.WithIDTokenIssuerAlg (clients declaring
// id_token_signed_response_alg resolve to it). This is the config-facing
// form of the SDK option and the product-level FAPI 2.0 conformance unblock:
// a plain-OIDC RS256 login client can coexist with ES256/PS256 FAPI clients
// on one issuer.
//
// The strategy name mirrors the design's test convention (jwt-<alg>); the
// primary "jwt" strategy is untouched, so default issuance stays
// byte-identical when no client declares the field. FIPS + external-signer
// semantics are inherited from the primary keys.signing block (the boot gate
// in config.validateIDTokenAlgs already rejected a duplicate of the primary
// alg). Appends to opts; returns opts unchanged when no id_token_algs are
// configured.
func BuildIDTokenAlgOptions(opts []sso.Option, cfg *config.Config, rdb goredis.Cmdable, m *metrics.Metrics, logger spi.Logger) ([]sso.Option, error) {
	for _, algCfg := range cfg.Keys.IDTokenAlgs {
		iss, algName, extSigner, err := BuildSigningIssuer(config.SigningConfig{
			Alg:             algCfg.Alg,
			KeyFile:         algCfg.KeyFile,
			External:        algCfg.External,
			FIPSMode:        cfg.Keys.Signing.FIPSMode,
			FIPSAllowedAlgs: cfg.Keys.Signing.FIPSAllowedAlgs,
		}, cfg.Server, rdb, m, logger)
		if err != nil {
			return nil, fmt.Errorf("keys.id_token_algs %q: %w", algCfg.Alg, err)
		}
		strategy := "jwt-" + strings.ToLower(algName)
		opts = append(opts,
			sso.WithTokenIssuer(strategy, iss),
			sso.WithIDTokenIssuerAlg(algName, iss),
		)
		logger.Info("additional id_token signing issuer configured", "alg", algName, "strategy", strategy)
		opts = AppendReadyCheck(opts, strategy+"-external-signer", extSigner)
	}
	return opts, nil
}
