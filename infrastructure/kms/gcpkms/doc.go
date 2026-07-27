//go:build !no_kms_gcpkms

// Package gcpkms provides a concrete GCP Cloud KMS-backed [crypto.Signer]
// for the snaplink/sso JWT signing seam, so token signing private keys
// never leave the Cloud KMS HSM — the #1 compliance requirement for FIPS
// 140-2/3, PCI-DSS, and SOC 2 (private key material is non-exportable by
// design when the key version is HSM-protected).
//
// # Why a separate Go module
//
// This package lives in its own nested module
// (github.com/yangwb1123/snaplink/kms/gcpkms) so the heavy, vendor-specific
// cloud.google.com/go/kms dependency NEVER enters the core sso module's
// go.mod. The core module's zero-external-(non-stdlib-adjacent)-SDK
// invariant is a firm property of the repo; operators who need Cloud KMS
// opt in by importing this submodule from their own cmd binary. This
// mirrors the kms/awskms and redis nested modules, and how etcd and
// push-transport SDKs are kept in cmd rather than the SPI.
//
// # Wiring
//
// gcpkms.Signer is a stdlib [crypto.Signer]; it is bridged into the
// issuers via defaultimpl/cryptosigner, which converts the KMS ECDSA DER
// signature to the JWS R||S form and validates the public-key shape at
// startup. The key reference is a fully-qualified CryptoKeyVersion resource
// name (GCP signs against a specific VERSION; the version's algorithm fixes
// the scheme — there is no per-request algorithm selector). ES256 example:
//
//	client, err := kms.NewKeyManagementClient(ctx)   // cloud.google.com/go/kms/apiv1
//	if err != nil { ... }
//	defer client.Close()
//
//	keyVersion := "projects/P/locations/L/keyRings/R/cryptoKeys/K/cryptoKeyVersions/1"
//	signer, err := gcpkms.New(client, keyVersion)    // a P-256 key version
//	if err != nil { ... }
//	if _, err := signer.PublicKey(ctx); err != nil {  // fail loud at startup
//	    log.Fatalf("kms key unreachable: %v", err)
//	}
//
//	bridge, pub, err := cryptosigner.ECDSA(signer)
//	if err != nil { ... }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyVersion),
//	)
//	srv := sso.NewServer(sso.WithTokenIssuer("jwt", iss), sso.WithIDTokenIssuer(iss))
//
// RSA (RS256 default, PS256 for FAPI) is identical via cryptosigner.RSA —
// the padding MUST match the key version's algorithm (RSA_SIGN_PKCS1_* for
// RS256, RSA_SIGN_PSS_* for PS256):
//
//	bridge, pub, err := cryptosigner.RSA(signer, cryptosigner.AlgPS256)
//	iss := defaultimpl.NewRSAJWTIssuer(
//	    defaultimpl.WithRSAAlg(cryptosigner.AlgPS256 /* "PS256" */),
//	    defaultimpl.WithRSAExternalSigner(bridge, pub, keyVersion),
//	)
//
// Ed25519 (EdDSA) — the GCP advantage over AWS KMS (see below) — via
// cryptosigner.Ed25519 over an EC_SIGN_ED25519 key version:
//
//	bridge, pub, err := cryptosigner.Ed25519(signer)
//	iss := defaultimpl.NewEd25519JWTIssuer(
//	    defaultimpl.WithEd25519ExternalSigner(bridge, pub, keyVersion),
//	)
//
// # Supported algorithms
//
//   - ECDSA: P-256 -> ES256, P-384 -> ES384.
//   - RSA:   RS256 (RSA_SIGN_PKCS1_*) and PS256 (RSA_SIGN_PSS_*), both over
//     SHA-256, key sizes 2048/3072/4096.
//   - Ed25519: EdDSA (EC_SIGN_ED25519).
//
// Note: the defaultimpl ECDSA issuer + the cryptosigner ECDSA bridge
// currently support only P-256 (ES256) end to end; the gcpkms.Signer itself
// can drive P-384 (ES384) for any other crypto.Signer consumer. GCP Cloud
// KMS has no NIST P-521 sign algorithm, and its SECP256K1 spec is not a JWS
// curve — both are out of scope.
//
// # Ed25519: the GCP advantage over AWS KMS
//
// Unlike AWS KMS (which has NO Ed25519/EdDSA asymmetric key spec, so the
// kms/awskms peer rejects EdDSA), GCP Cloud KMS supports Ed25519 via the
// EC_SIGN_ED25519 key version. This package therefore drives EdDSA end to
// end through the existing cryptosigner.Ed25519 bridge +
// WithEd25519ExternalSigner seam. Ed25519 is NOT prehashed: the stdlib
// crypto.Signer contract passes the raw message as the digest argument with
// opts.HashFunc()==0, and gcpkms sends that raw message in the KMS
// AsymmetricSignRequest's Data field (EC/RSA send the precomputed digest in
// the Digest oneof instead).
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
//   - run a single signing leader (or share one KMS key version across
//     replicas) so JWKS stays consistent — the KMS public key is fetched
//     once and cached for the process lifetime.
//
// Fail-closed: any KMS error from Sign aborts token issuance rather than
// emitting an unsigned token.
package gcpkms
