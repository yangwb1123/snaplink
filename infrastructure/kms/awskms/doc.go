//go:build !no_kms_awskms

// Package awskms provides a concrete AWS KMS-backed [crypto.Signer] for
// the snaplink/sso JWT signing seam, so token signing private keys never
// leave the AWS KMS HSM — the #1 compliance requirement for FIPS 140-2/3,
// PCI-DSS, and SOC 2 (private key material is non-exportable by design).
//
// # Why a separate Go module
//
// This package lives in its own nested module
// (github.com/yangwb1123/snaplink/kms/awskms) so the heavy, vendor-specific
// aws-sdk-go-v2 dependency NEVER enters the core sso module's go.mod. The
// core module's zero-external-(non-stdlib-adjacent)-SDK invariant is a
// firm property of the repo; operators who need KMS opt in by importing
// this submodule from their own cmd binary. This mirrors how etcd and
// push-transport SDKs are kept in cmd rather than the SPI.
//
// # Wiring
//
// awskms.Signer is a stdlib [crypto.Signer]; it is bridged into the
// issuers via defaultimpl/cryptosigner, which converts the KMS ECDSA DER
// signature to the JWS R||S form and validates the public-key shape at
// startup. ES256 example:
//
//	cfg, err := config.LoadDefaultConfig(ctx)         // aws-sdk-go-v2/config
//	if err != nil { ... }
//	kmsClient := kms.NewFromConfig(cfg)
//
//	signer, err := awskms.New(kmsClient, keyARN)      // keyARN names a P-256 KMS key
//	if err != nil { ... }
//	if _, err := signer.PublicKey(ctx); err != nil {  // fail loud at startup
//	    log.Fatalf("kms key unreachable: %v", err)
//	}
//
//	bridge, pub, err := cryptosigner.ECDSA(signer)
//	if err != nil { ... }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyARN),
//	)
//	srv := sso.NewServer(sso.WithTokenIssuer("jwt", iss), sso.WithIDTokenIssuer(iss))
//
// RSA (RS256 default, PS256 for FAPI) is identical via cryptosigner.RSA:
//
//	bridge, pub, err := cryptosigner.RSA(signer, cryptosigner.AlgPS256)
//	iss := defaultimpl.NewRSAJWTIssuer(
//	    defaultimpl.WithRSAAlg(cryptosigner.AlgPS256 /* "PS256" */),
//	    defaultimpl.WithRSAExternalSigner(bridge, pub, keyARN),
//	)
//
// # Supported algorithms
//
//   - ECDSA: P-256 -> ES256, P-384 -> ES384, P-521 -> ES512.
//   - RSA:   RS256 (PKCS#1 v1.5) and PS256 (PSS), both over SHA-256.
//
// Note: the defaultimpl ECDSA issuer + the cryptosigner ECDSA bridge
// currently support only P-256 (ES256) end to end; the awskms.Signer
// itself can drive P-384/P-521 for any other crypto.Signer consumer.
//
// AWS KMS has NO Ed25519/EdDSA asymmetric key spec. An EdDSA request
// (crypto.Signer with HashFunc()==0) is rejected with [ErrUnsupportedKey]
// rather than mis-signed. Use the in-process Ed25519 issuer when EdDSA is
// required.
//
// # Latency
//
// Every Sign is a network round-trip to KMS (typically 5-50 ms, vs
// microseconds in-process). Operators SHOULD:
//
//   - extend the access-token TTL so the per-request signing cost is
//     amortized over a longer token lifetime;
//   - consider caching minted tokens / id_tokens where the claim set is
//     stable, or front KMS with a short-lived in-process signing cache;
//   - run a single signing leader (or share one KMS key across replicas)
//     so JWKS stays consistent — the KMS public key is fetched once and
//     cached for the process lifetime.
//
// Fail-closed: any KMS error from Sign aborts token issuance rather than
// emitting an unsigned token.
package awskms
