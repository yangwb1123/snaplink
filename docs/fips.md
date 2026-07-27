# FIPS 140-3 build mode

How to build and run snaplink/sso against Go's native FIPS 140-3
Cryptographic Module, and what the server's own `keys.signing.fips_mode`
config flag adds on top of it. Both are **opt-in and default-off** — a
deployment that does neither is byte-identical to a build without this
document.

> **Compliance boundary:** enabling the Go Cryptographic Module and
> `keys.signing.fips_mode` does not certify the snaplink product or an
> operator's deployment. A compliance claim must name the exact Go toolchain,
> `GOFIPS140` module version/CMVP certificate, build artifact and runtime
> configuration that were assessed. `GOFIPS140=latest` may select module code
> that is not yet covered by an issued certificate.

## What "FIPS mode" actually is here

Since Go 1.24, the Go toolchain ships a FIPS 140-3 validated Cryptographic
Module **in the standard library** — no cgo, no BoringCrypto, no external C
dependency. This repo is pure-Go (`CGO_ENABLED=0` in the `Dockerfile` and
`make build-small`), so the native module is the only FIPS mechanism that
fits its "no CGO" invariant, and it's the one this repo uses.

There are two independent layers:

1. **Go's own FIPS mode** (`GOFIPS140` at build time, or `GODEBUG=fips140=on`
   at runtime) — makes `crypto/ecdsa`, `crypto/rsa`, and `crypto/ed25519`
   run through the Go Cryptographic Module's self-tested implementations
   instead of the ordinary stdlib code path. This is entirely Go's
   responsibility; snaplink/sso does not (and cannot) change how these
   packages behave once FIPS mode is active.
2. **This server's `keys.signing.fips_mode` config flag** — adds two things
   Go's own mode does not provide: (a) a **startup assertion** that the
   running binary is actually FIPS-enabled (so a config typo or a build
   that forgot `GOFIPS140` fails loudly instead of silently running
   non-FIPS crypto while claiming otherwise), and (b) an **optional
   narrower algorithm allowlist** for a compliance posture stricter than
   what Go itself approves.

## Which signing algorithms are FIPS-approved

`keys.signing.alg` selects the JWT-signing issuer (`eddsa` | `es256` |
`rs256` | `ps256`). All four are **FIPS 186-5 approved digital-signature
algorithms**, and Go's Cryptographic Module implements + self-tests all of
them (each has its own known-answer self-test —
`crypto/internal/fips140/{ecdsa,rsa,ed25519}` — verified directly against
this repo's Go 1.26 toolchain source, not assumed):

| `keys.signing.alg` | Algorithm | FIPS 186-5 approved? |
|---|---|---|
| `eddsa` (default) | Ed25519 | Yes |
| `es256` | ECDSA P-256 | Yes |
| `rs256` | RSA PKCS#1 v1.5 | Yes |
| `ps256` | RSA-PSS | Yes |

**Note on Ed25519**: older commentary (and the version of this feature
originally scoped) assumed Ed25519/EdDSA was NOT FIPS-approved. That was
true under FIPS 186-4 but is **stale** — FIPS 186-5 (published 2023) added
EdDSA, and Go's own `crypto/tls` FIPS-mode-allowed signature list
(`crypto/tls/defaults_fips140.go`) includes `Ed25519` for exactly this
reason. This server's default FIPS-mode allowlist follows that current
guidance and does **not** reject Ed25519.

If your organization's compliance program is pinned to a specific
CMVP-certified module version that predates EdDSA validation (see
"Module maturity levels" below), set `keys.signing.fips_allowed_algs` to
exclude it:

```yaml
keys:
  signing:
    alg: es256
    fips_mode: true
    fips_allowed_algs: [es256, rs256, ps256]   # excludes eddsa
```

## Building

```bash
# Native Go FIPS module, no cgo, no BoringCrypto:
GOFIPS140=latest CGO_ENABLED=0 go build -o sso-server ./cmd/sso-server

# Docker (see Dockerfile's GOFIPS140 build ARG, default "off"):
docker build --build-arg GOFIPS140=latest -t snaplink/sso-server-fips .
```

### Module maturity levels (`GOFIPS140` values)

| Value | Meaning |
|---|---|
| `off` (default) | No FIPS module; ordinary stdlib crypto. Byte-identical to every existing deployment. |
| `latest` | Newest Go Cryptographic Module, including algorithms not yet CMVP-certified (e.g. freshly-added ones). Best for "we want the module's behavior" without a hard certificate requirement. |
| `v1.0.0` (or another pinned version) | Reproducible builds against a frozen module snapshot. |
| `inprocess` | Latest version that has reached NIST's CMVP "Modules In Process" list (submitted, under review). |
| `certified` | Latest version with an **issued** CMVP validation certificate — the strictest option; may lag behind `latest` in which algorithms it includes. |

Pick `certified` if an auditor needs to cite an actual NIST certificate
number; pick `latest` (or `inprocess`) if you want current FIPS-approved
algorithm behavior without waiting on certification lag.

Record the resolved Go version and module selection in the release evidence;
do not document only the symbolic selector because its target can change with
the toolchain.

## Running

Go's FIPS mode can also be toggled at runtime without a special build,
since the module code is always compiled in — just gated:

```bash
GODEBUG=fips140=on ./sso-server --config config.yaml     # permissive FIPS mode
GODEBUG=fips140=only ./sso-server --config config.yaml   # strict: non-approved algs error/panic
```

`GOFIPS140` at build time additionally sets the `fips140` GODEBUG default to
`on` and pins the module version, which is what you want for a
reproducible, auditable build — prefer it over runtime-only `GODEBUG` for
anything beyond local testing.

## Server-side config

```yaml
keys:
  signing:
    alg: es256               # or eddsa/rs256/ps256 — see the table above
    fips_mode: true           # default false; see below
    fips_allowed_algs: []     # optional narrower allowlist; default = all 4
```

`fips_mode: true` makes `BuildSigningIssuer`
(`cmd/sso-server/serverbuildsign/build_signing.go`) call
`shared/security/fipspolicy.ValidateIssuerAlg` before constructing any
issuer:

1. If the binary's Go Cryptographic Module is not active
   (`crypto/fips140.Enabled() == false`), the server fails to start with an
   error naming the config key and pointing back to this doc — a config
   flag alone does not make anything actually FIPS-compliant, so this
   catches the mismatch immediately rather than silently running ordinary
   crypto while operators believe otherwise.
2. The configured `keys.signing.alg` is checked against the effective
   allowlist (the default four algorithms, or `fips_allowed_algs` if set).
   An alg outside the allowlist fails issuer construction with a clear
   error before any key material is generated.

This check runs **once**, at issuer-construction time — it is the single
place FIPS-awareness exists in the codebase (see AGENTS.md's dependency-
direction and don't-scatter-crypto-awareness conventions). No other file
in this repo branches on FIPS mode.

## What FIPS mode does NOT change

- `keys.signing.fips_mode: false` (the default, or the key simply absent):
  zero behavior change, zero overhead, byte-identical to every existing
  deployment and to every existing test.
- The wire format, JWKS shape, and JWT claims are unaffected either way —
  FIPS mode only gates which *algorithm* is allowed at startup, never the
  token shape.
- TLS transport hardening (cipher suites, curves, TLS version) is entirely
  governed by Go's own `crypto/tls` FIPS-mode filters
  (`crypto/tls/defaults_fips140.go`) once `GOFIPS140`/`GODEBUG=fips140` is
  active — this repo does not duplicate that policy.
