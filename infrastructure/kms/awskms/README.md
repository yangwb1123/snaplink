# awskms — AWS KMS signer for snaplink/sso

> **Wiring boundary:** this is an opt-in nested module at
> `infrastructure/kms/awskms/`, with published module path
> `github.com/yangwb1123/snaplink/kms/awskms`. The stock `sso-server` contains the
> generic external-signer registry but does not register an AWS client or read
> AWS credentials. Use a custom composition binary that registers/builds this
> signer before selecting it in signing configuration.

A concrete [`crypto.Signer`](https://pkg.go.dev/crypto#Signer) backed by an
**AWS KMS asymmetric key**, so JWT signing private keys **never leave the
KMS HSM**. Non-exportable key custody is a common control for **FIPS 140-2/3,
PCI-DSS, and SOC 2** deployments: the SSO process
holds only the public half and a key reference, and every signature is a
KMS round-trip.

## Why a separate module

This is a **separate nested Go module** stored at
`infrastructure/kms/awskms/` (`github.com/yangwb1123/snaplink/kms/awskms`) so the
heavy, vendor-specific
`aws-sdk-go-v2` dependency **never enters the core `sso` module's
`go.mod`** — the core's zero-external-SDK invariant stays intact. Operators
who need KMS-backed signing opt in by importing this submodule from their
own `cmd` binary.

It plugs into the SSO signing seam that was already complete: the issuers
expose `With{ECDSA,RSA}ExternalSigner`, and
`infrastructure/defaultimpl/cryptosigner` bridges any stdlib `crypto.Signer`
into them (handling the ECDSA DER → JWS `R‖S` conversion). This package
supplies the concrete AWS KMS `crypto.Signer` for that seam.

## Install

```bash
# from your operator cmd module
go get github.com/yangwb1123/snaplink/kms/awskms
```

## Wiring (ECDSA / ES256)

```go
import (
    "github.com/aws/aws-sdk-go-v2/config"
    "github.com/aws/aws-sdk-go-v2/service/kms"

    "github.com/yangwb1123/snaplink/infrastructure/defaultimpl"
    "github.com/yangwb1123/snaplink/infrastructure/defaultimpl/cryptosigner"
    sso "github.com/yangwb1123/snaplink/interfaces/sso"
    "github.com/yangwb1123/snaplink/kms/awskms"
)

cfg, err := config.LoadDefaultConfig(ctx)
if err != nil { /* ... */ }
kmsClient := kms.NewFromConfig(cfg)

// keyARN names a P-256 KMS key (ECC_NIST_P256).
signer, err := awskms.New(kmsClient, keyARN)
if err != nil { /* ... */ }

// Fail loud at startup if the key id / IAM permissions are wrong.
if _, err := signer.PublicKey(ctx); err != nil {
    log.Fatalf("kms key unreachable: %v", err)
}

bridge, pub, err := cryptosigner.ECDSA(signer) // DER -> R‖S, validates P-256
if err != nil { /* ... */ }

iss := defaultimpl.NewECDSAJWTIssuer(
    defaultimpl.WithECDSAExternalSigner(bridge, pub, keyARN),
)
srv := sso.NewServer(
    sso.WithTokenIssuer("jwt", iss),
    sso.WithIDTokenIssuer(iss),
)
```

## Wiring (RSA / RS256 or PS256)

```go
signer, _ := awskms.New(kmsClient, keyARN) // keyARN names an RSA_* KMS key

// PS256 (FAPI-preferred); use cryptosigner.AlgRS256 for RS256.
bridge, pub, err := cryptosigner.RSA(signer, cryptosigner.AlgPS256)
if err != nil { /* ... */ }

iss := defaultimpl.NewRSAJWTIssuer(
    defaultimpl.WithRSAAlg(cryptosigner.AlgPS256), // "PS256"
    defaultimpl.WithRSAExternalSigner(bridge, pub, keyARN),
)
```

## Supported algorithms

| KMS key spec    | JWS alg | Notes                                   |
|-----------------|---------|-----------------------------------------|
| `ECC_NIST_P256` | ES256   | end-to-end through cryptosigner + issuer |
| `ECC_NIST_P384` | ES384   | signer-level only*                       |
| `ECC_NIST_P521` | ES512   | signer-level only*                       |
| `RSA_2048/3072/4096` | RS256 | PKCS#1 v1.5 over SHA-256             |
| `RSA_2048/3072/4096` | PS256 | PSS over SHA-256 (FAPI)             |

\* The `defaultimpl` ECDSA issuer + the cryptosigner ECDSA bridge currently
support **P-256 (ES256)** end to end. The `awskms.Signer` itself is a
faithful `crypto.Signer` that can drive P-384/P-521 for any other consumer.

**AWS KMS has no Ed25519/EdDSA key spec.** An EdDSA request (a
`crypto.Signer` call with `HashFunc()==0`) is rejected with
`awskms.ErrUnsupportedKey` rather than mis-signed. Use the in-process
Ed25519 issuer when EdDSA is required.

## crypto.Signer contract

- `Public()` fetches the public key from KMS once (DER `SubjectPublicKeyInfo`,
  parsed via `x509.ParsePKIXPublicKey`) and caches it for the process
  lifetime. `PublicKey(ctx)` is the error-returning form for startup checks.
- `Sign(rand, digest, opts)` signs the **already-hashed** digest
  (`MessageType=DIGEST`). For **ECDSA it returns ASN.1 DER** (the stdlib
  `crypto.Signer` ECDSA contract — the cryptosigner bridge converts it to
  the fixed-width `R‖S` JWS form). For **RSA it returns the raw** PKCS#1
  v1.5 / PSS bytes (already the JWS form). The `rand` reader is ignored —
  the HSM owns signing randomness.

## Latency

Every signature is a KMS network round-trip (typically **5–50 ms**, vs
microseconds in-process). Mitigations:

- **Extend the access-token TTL** so the per-request signing cost is
  amortized over a longer token lifetime.
- Cache minted tokens / id_tokens where the claim set is stable, or front
  KMS with a short-lived in-process signing cache.
- Share one KMS key across replicas, or configure the platform signing-key
  registry so every replica can publish/adopt the complete verification set.
  The public key is cached independently in each process.

**Fail-closed:** any KMS error from `Sign` aborts token issuance rather than
emitting an unsigned token.

## Testing

```bash
# from the repo root (the core module's Makefile runs this under `make ci`):
make ci-modules

# or directly:
cd infrastructure/kms/awskms
go build ./...
go test -race ./...
```

The unit tests use an **in-process fake KMS client** (a locally generated
key that answers `GetPublicKey`/`Sign` exactly as KMS would — DER for ECC,
raw for RSA). They cover the public-key cache, ES256/RS256/PS256 round
trips, the EdDSA rejection, fail-closed on a KMS error, and an
**end-to-end** test that mints a token through the real `ECDSAJWTIssuer` /
`RSAJWTIssuer` and asserts `Validate` passes. **No real AWS is touched in
CI.** A live integration test can be added behind a
`//go:build awskms_integration` tag (skipped by default).
