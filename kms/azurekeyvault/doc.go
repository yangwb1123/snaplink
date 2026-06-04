// Package azurekeyvault provides a concrete Azure Key Vault-backed
// [crypto.Signer] for the snaplink/sso JWT signing seam, so token signing
// private keys never leave the vault — the #1 compliance requirement for FIPS
// 140-2/3, PCI-DSS, and SOC 2 (HSM-protected Key Vault keys are
// non-exportable by design). It completes the cloud-KMS trio alongside
// kms/awskms (AWS KMS) and kms/gcpkms (GCP Cloud KMS); kms/pkcs11 covers
// on-prem HSMs / smart cards.
//
// # Why a separate Go module
//
// This package lives in its own nested module
// (github.com/snaplink/sso/kms/azurekeyvault) so the heavy, vendor-specific
// Azure SDK (github.com/Azure/azure-sdk-for-go) NEVER enters the core sso
// module's go.mod. The core module's zero-external-(non-stdlib-adjacent)-SDK
// invariant is a firm property of the repo; operators who need Key Vault opt
// in by importing this submodule from their own cmd binary. This mirrors the
// kms/awskms, kms/gcpkms, and redis nested modules, and how etcd and
// push-transport SDKs are kept in cmd rather than the SPI.
//
// # Wiring
//
// azurekeyvault.Signer is a stdlib [crypto.Signer]; it is bridged into the
// issuers via defaultimpl/cryptosigner, which converts the ECDSA DER
// signature the Signer returns into the JWS R||S form and validates the
// public-key shape at startup. The key is addressed by (key name, key
// version) within a vault; an empty version signs the current version, but
// operators SHOULD pin an explicit version so a vault-side rotation does not
// silently change the signing key (and JWKS kid) under running replicas.
// ES256 example:
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil) // sdk/azidentity
//	if err != nil { ... }
//	client, err := azkeys.NewClient(vaultURL, cred, nil)   // sdk/security/keyvault/azkeys
//	if err != nil { ... }
//
//	signer, err := azurekeyvault.NewSigner(client, "signing-key", keyVersion)
//	if err != nil { ... }
//	if _, err := signer.PublicKey(ctx); err != nil {       // fail loud at startup
//	    log.Fatalf("key vault key unreachable: %v", err)
//	}
//
//	bridge, pub, err := cryptosigner.ECDSA(signer)
//	if err != nil { ... }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, "signing-key"),
//	)
//	srv := sso.NewServer(sso.WithTokenIssuer("jwt", iss), sso.WithIDTokenIssuer(iss))
//
// The convenience constructor builds the azkeys.Client for you from a vault
// URL + an azidentity credential:
//
//	cred, err := azidentity.NewDefaultAzureCredential(nil)
//	signer, err := azurekeyvault.NewSignerFromVaultURL(
//	    "https://my-vault.vault.azure.net", "signing-key", keyVersion, cred, nil)
//
// RSA (RS256 default, PS256 for FAPI) is identical via cryptosigner.RSA — the
// padding is chosen by the cryptosigner alg, mapped to Key Vault's PS256 /
// RS256 SignatureAlgorithm:
//
//	bridge, pub, err := cryptosigner.RSA(signer, cryptosigner.AlgPS256)
//	iss := defaultimpl.NewRSAJWTIssuer(
//	    defaultimpl.WithRSAAlg(cryptosigner.AlgPS256 /* "PS256" */),
//	    defaultimpl.WithRSAExternalSigner(bridge, pub, "signing-key"),
//	)
//
// # Supported algorithms
//
//   - ECDSA: P-256 -> ES256, P-384 -> ES384, P-521 -> ES512.
//   - RSA:   RS256 (RSASSA-PKCS1-v1_5) and PS256 (RSASSA-PSS), both over
//     SHA-256, key sizes 2048/3072/4096. RSA-HSM / EC-HSM keys (the
//     non-exportable, FIPS-gate variants) are accepted identically.
//
// Note: the defaultimpl ECDSA issuer + the cryptosigner ECDSA bridge
// currently support only P-256 (ES256) end to end; the azurekeyvault.Signer
// itself can drive P-384/P-521 for any other crypto.Signer consumer. The
// non-JWS P-256K (secp256k1) curve is rejected.
//
// # ECDSA signature format: the R||S <-> DER inversion
//
// Azure Key Vault returns ECDSA signatures as RAW fixed-width R||S — the JWS
// / IEEE-P1363 form (RFC 7518 §3.4), NOT the ASN.1 DER that the stdlib
// [crypto.Signer] ECDSA contract mandates (and that AWS KMS / GCP Cloud KMS
// return). This Signer therefore converts the vault's R||S into DER, the
// INVERSE of what the cryptosigner bridge then does (DER -> R||S for the JWS
// wire). The two conversions cancel on the wire, but performing R||S -> DER
// here keeps this type a faithful, reusable crypto.Signer that round-trips
// against ecdsa.VerifyASN1, and lets it plug into the SAME cryptosigner
// bridge as the awskms/gcpkms peers with zero bridge changes. The split is
// per-curve fixed-width (P-256 -> 32-byte R + 32-byte S, P-384 -> 48, P-521
// -> 66). RSA signatures pass through raw (already the crypto.Signer / JWS
// form).
//
// # No Ed25519 (like AWS KMS)
//
// Azure Key Vault has NO Ed25519/EdDSA key type. An EdDSA request
// (crypto.Signer with HashFunc()==0) is rejected with [ErrUnsupportedKey]
// rather than mis-signed — the same posture as the AWS KMS peer (GCP Cloud
// KMS and PKCS#11 do support EdDSA). Use the in-process Ed25519 issuer, GCP
// Cloud KMS, or a PKCS#11 token when EdDSA is required.
//
// The ECDSA hash<->curve pairing is enforced fail-closed (P-256 demands
// SHA-256, P-384 SHA-384, P-521 SHA-512), mirroring the pkcs11/awskms/gcpkms
// peers: a direct crypto.Signer caller cannot sign a digest under a hash that
// disagrees with the curve's ES* alg the JWKS publishes.
//
// # Latency
//
// Every Sign is a network round-trip to Key Vault (typically 5-50 ms, vs
// microseconds in-process). Operators SHOULD:
//
//   - extend the access-token TTL so the per-request signing cost is
//     amortized over a longer token lifetime;
//   - consider caching minted tokens / id_tokens where the claim set is
//     stable, or front the vault with a short-lived in-process signing cache;
//   - run a single signing leader (or share one Key Vault key across
//     replicas) so JWKS stays consistent — the public key is fetched once and
//     cached for the process lifetime.
//
// Fail-closed: any vault error from Sign aborts token issuance rather than
// emitting an unsigned token.
package azurekeyvault
