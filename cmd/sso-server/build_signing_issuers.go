package main

import (
	"context"
	"crypto"
	"fmt"
	"strings"

	"github.com/snaplink/sso/config"
	"github.com/snaplink/sso/infrastructure/defaultimpl"
	"github.com/snaplink/sso/infrastructure/defaultimpl/cryptosigner"
	"github.com/snaplink/sso/platform/metrics"
	"github.com/snaplink/sso/shared/spi"
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
	extSigner := instrumentSigner(s, normalizeAlgLabel(sc.Alg), m, logger)
	logger.Info("signing key: external signer", "name", name, "kid", kid)
	return extSigner, kid, nil
}

func buildEd25519SigningIssuer(srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore) (signingIssuer, string, crypto.Signer, error) {
	opts := []defaultimpl.Ed25519Option{
		defaultimpl.WithEd25519Issuer(srv.Issuer),
		defaultimpl.WithEd25519TokenTTL(srv.TokenTTL),
		defaultimpl.WithEd25519MaxClockSkew(srv.MaxClockSkew),
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
	iss := defaultimpl.NewEd25519JWTIssuer(opts...)
	if serr := seedRevocations(iss, revStore); serr != nil {
		return nil, "", nil, serr
	}
	return iss, "EdDSA", extSigner, nil
}

func buildECDSASigningIssuer(srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore) (signingIssuer, string, crypto.Signer, error) {
	opts := []defaultimpl.ECDSAOption{
		defaultimpl.WithECDSAIssuer(srv.Issuer),
		defaultimpl.WithECDSATokenTTL(srv.TokenTTL),
		defaultimpl.WithECDSAMaxClockSkew(srv.MaxClockSkew),
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

func buildRSASigningIssuer(alg string, srv config.ServerConfig, extSigner crypto.Signer, extKID string, revStore defaultimpl.RevocationStore) (signingIssuer, string, crypto.Signer, error) {
	signingAlg := "RS256"
	if alg == "ps256" {
		signingAlg = "PS256"
	}
	opts := []defaultimpl.RSAOption{
		defaultimpl.WithRSAIssuer(srv.Issuer),
		defaultimpl.WithRSAAlg(signingAlg),
		defaultimpl.WithRSATokenTTL(srv.TokenTTL),
		defaultimpl.WithRSAMaxClockSkew(srv.MaxClockSkew),
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
