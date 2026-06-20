// Package pkcs11 provides a concrete PKCS#11-backed [crypto.Signer] for the
// snaplink/sso JWT signing seam, so token-signing private keys never leave
// the cryptographic token (an on-prem HSM, a smart card, a YubiHSM, a Thales
// or Entrust appliance, or SoftHSM for testing). The private key material is
// non-exportable by design — the #1 compliance requirement for FIPS 140-2/3,
// PCI-DSS, and SOC 2 deployments where key residency must stay inside a
// certified boundary that no cloud KMS can satisfy (air-gapped / data-
// sovereignty estates).
//
// # Why a separate Go module
//
// This package lives in its own nested module
// (github.com/snaplink/sso/kms/pkcs11) so the cgo PKCS#11 binding
// (github.com/miekg/pkcs11) NEVER enters the core sso module's go.mod. The
// core module's zero-external-SDK invariant is a firm property of the repo;
// operators who need a hardware token opt in by importing this submodule
// from their own cmd binary. This mirrors kms/awskms (aws-sdk-go-v2), the
// redis hot-path peer (go-redis), and how etcd / push-transport SDKs are
// kept in cmd rather than the SPI.
//
// # cgo
//
// github.com/miekg/pkcs11 is a cgo binding over the PKCS#11 C API, so a
// build of THIS module (and the production [New] path) needs CGO_ENABLED=1
// and a C toolchain. The crypto logic ([Signer] over the [Session]
// interface) is exercised entirely through an in-process fake in tests, so
// the unit suite needs neither a real HSM nor SoftHSM — but it still links
// the cgo binding, so a fully cgo-less environment cannot build the module.
//
// # Wiring
//
// pkcs11.Signer is a stdlib [crypto.Signer]; it is bridged into the issuers
// via defaultimpl/cryptosigner, which converts the ECDSA ASN.1 DER signature
// the Signer returns into the JWS fixed-width R||S form and validates the
// public-key shape at startup. ES256 example:
//
//	signer, err := pkcs11.New(pkcs11.Config{
//	    ModulePath: "/usr/lib/softhsm/libsofthsm2.so",
//	    TokenLabel: "sso-signing",
//	    PIN:        os.Getenv("SSO_HSM_PIN"),
//	    KeyLabel:   "es256-2026",
//	})
//	if err != nil { ... }
//	defer signer.Close()                              // C_Logout + C_CloseSession + C_Finalize
//	if _, err := signer.PublicKey(ctx); err != nil {  // fail loud at startup
//	    log.Fatalf("hsm key unreachable: %v", err)
//	}
//
//	bridge, pub, err := cryptosigner.ECDSA(signer)
//	if err != nil { ... }
//	iss := defaultimpl.NewECDSAJWTIssuer(
//	    defaultimpl.WithECDSAExternalSigner(bridge, pub, "es256-2026"),
//	)
//	srv := sso.NewServer(sso.WithTokenIssuer("jwt", iss), sso.WithIDTokenIssuer(iss))
//
// RSA (RS256 default, PS256 for FAPI) is identical via cryptosigner.RSA, and
// Ed25519 (EdDSA, where the token implements CKM_EDDSA) via cryptosigner.Ed25519:
//
//	bridge, pub, err := cryptosigner.Ed25519(signer)  // token must support CKM_EDDSA
//	iss := defaultimpl.NewEd25519JWTIssuer(
//	    defaultimpl.WithEd25519ExternalSigner(bridge, pub, "eddsa-2026"),
//	)
//
// # The ECDSA R||S -> DER -> R||S round-trip
//
// This is the one PKCS#11-specific impedance mismatch. The PKCS#11 CKM_ECDSA
// mechanism returns the signature as the RAW fixed-width R||S concatenation
// (PKCS#11 v2.40 §2.3.1) — NOT ASN.1 DER. But the stdlib [crypto.Signer]
// contract for an ECDSA key REQUIRES the returned signature to be ASN.1 DER
// (SEQUENCE{r,s}), exactly as crypto/ecdsa.SignASN1 produces and
// ecdsa.VerifyASN1 consumes. So [Signer.Sign] converts the token's R||S into
// DER before returning. The cryptosigner.ECDSA bridge then converts that DER
// back into R||S for JWS ES256 (RFC 7518 §3.4). The double conversion is
// deliberate and correct: it keeps [Signer] a faithful, reusable
// crypto.Signer (it round-trips against x509/tls/ecdsa.VerifyASN1), exactly
// as kms/awskms returns DER from KMS for the same reason. RSA signatures
// (CKM_RSA_PKCS / CKM_RSA_PKCS_PSS) are already raw PKCS#1 / PSS bytes — the
// JWS form — and pass through unconverted.
//
// # Supported algorithms
//
//   - ECDSA: P-256 -> ES256, P-384 -> ES384, P-521 -> ES512 (CKM_ECDSA over
//     the precomputed digest; raw R||S is converted to DER here).
//   - RSA:   RS256 (CKM_RSA_PKCS over the DigestInfo) and PS256
//     (CKM_RSA_PKCS_PSS), both over SHA-256.
//   - EdDSA: Ed25519 -> EdDSA (CKM_EDDSA over the raw message), IF the token
//     implements the mechanism. Unlike AWS KMS — which has no EdDSA key spec
//     — many PKCS#11 v3.0 tokens (and SoftHSM2) do, and defaultimpl already
//     exposes WithEd25519ExternalSigner + cryptosigner.Ed25519, so the seam
//     is wired here. Tokens without CKM_EDDSA simply reject SignInit; use an
//     EC or RSA key on those.
//
// # Latency
//
// Every Sign is a round-trip into the token. A networked HSM is comparable to
// a cloud KMS (single-digit-to-tens of ms); a local PCIe/USB token is faster
// but still far above an in-process key. Operators SHOULD extend the access-
// token TTL to amortize the per-request signing cost, and run a single
// signing leader (or share one token) so JWKS stays consistent — the public
// key is read from the token once and cached for the process lifetime.
//
// Fail-closed: any token error from Sign aborts token issuance rather than
// emitting an unsigned token.
//
// # Scope
//
// This module covers the synchronous JWT/JWS signing path only — a single
// signing key located by label/id, with the public key read from the token's
// public-key object (or supplied at construction). Key generation, wrapping,
// rotation ceremonies, the asynchronous Workload-API, and X.509 / non-signing
// mechanisms are out of scope (perform them with the operator's HSM tooling;
// this signer only consumes an already-provisioned key).
package pkcs11
