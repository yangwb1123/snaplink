# OIDC Conformance Status

Last verified against the code on 2026-08-15.

## Certification status

Snaplink has **no recorded OpenID Foundation certification listing or official
conformance result**. The repository contains protocol tests and a
**headless, repeatable** Docker Compose harness for the OIDF suite
(`test/oidc-conformance/run-headless.sh`), plus a smoke-topology run archive
under `test/oidc-conformance/results/<commit>/` (git-ignored; regenerate with
the script). The harness is not part of default CI.

Therefore:

- Do not use “OpenID Certified,” “FAPI Certified” or an equivalent badge.
- “Implemented” below means code/tests exist, not that an OIDF profile passed.
- An RFP response must name the exact server commit, configuration and official
  result it relies on.

## Smoke run evidence (local topologies)

`test/oidc-conformance/run-headless.sh` against the pinned suite image
`release-v5.2.1` produced, for the `oidcc-server` module of the Basic
certification plan (discovery + dynamic-client variants), across two local
topologies:

- HTTP issuer (`results/af3bc485/` baseline; same-commit re-run
  `results/7400ba0c/`): **59 SUCCESS + 1 FAILURE** in both. The sole
  failure, `VerifyClientManagementCredentials`, requires an `https`
  client-management URL, which an HTTP-only local issuer cannot provide.
- HTTPS issuer behind a self-signed local proxy (`results/7400ba0c-https/`):
  **60 SUCCESS + 0 FAILURE**. The HTTPS issuer satisfies the https-URI
  requirement and `VerifyClientManagementCredentials` passes
  (registration_client_uri `https://sso-issuer:8181/register/...`).

Both runs cover discovery fetch/validation, JWKS fetch and validation,
dynamic client registration, the authorization-code round trip
(browser-driven login against the local OP), ID-token verification,
userinfo and resource-endpoint calls, and carry the same three non-fatal
WARNINGs (non-requested `ext`/`scope` id-token claims).

This is smoke evidence only — not an OIDF result. The local HTTPS issuer is
still a self-signed, non-externally-reachable topology; certification
language still requires an official suite run against an externally
reachable HTTPS issuer with archived plan/result artifacts and, for
"certified", an issued OIDF listing.

### Latest run (2026-08-15, HEAD `7400ba0c` — HTTPS issuer topology)

`./run-headless.sh --timeout 900 --issuer-https` completed at HEAD
`7400ba0c` on 2026-08-15. The HTTPS topology adds an nginx `issuer-proxy`
(reusing the self-signed `certs/` pair, host 8181 -> sso-server:8080) and
sets the issuer to `https://sso-issuer:8181`; the suite JVM validates the
self-signed cert through a truststore built from the pinned image's default
CAs plus the harness cert. The run executed the full `oidcc-server` module
of the Basic certification plan and archived the evidence under
`results/7400ba0c-https/` (plan.json, oidcc-server.log.json,
oidcc-server.info.json, config.yaml, commit.txt, worktree.txt):

- **60 SUCCESS + 0 FAILURE**, same step sequence as the `af3bc485` HTTP
  baseline except that `VerifyClientManagementCredentials` now passes
  (`URL for client management point does not use https scheme` no longer
  fires: the dynamically registered client's `registration_client_uri` is
  `https://sso-issuer:8181/register/...`).
- Run note (environment, both topologies): the script's curl calls to the
  `sso-issuer` hostname must bypass the ambient HTTP(S) proxy — with
  `HTTP_PROXY` set and `sso-issuer` absent from `no_proxy`, the proxy
  answers the login POST with 502 and the suite login cannot complete.
  The archived runs were executed with the proxy environment variables
  unset; everything else (server build, containers, headless Chrome) is
  localhost/container-network traffic.

### Previous run (2026-08-15, HEAD `af3bc485` — HTTP issuer topology)

`./run-headless.sh --timeout 900` completed at HEAD `af3bc485` on
2026-08-15, after the harness fix in that same commit removed the
fail-closed gRPC blocker recorded in `b465301a` (empty `-grpc-listen`
disables the gRPC plane, which the harness does not exercise). The run
executed the full `oidcc-server` module of the Basic certification plan
(discovery + dynamic-client variant, 38 plan modules) and archived the
evidence under `results/af3bc485/` (plan.json, oidcc-server.log.json,
oidcc-server.info.json, config.yaml, commit.txt, worktree.txt):

- **59 SUCCESS + 1 FAILURE** — identical counts and step sequence to the
  2026-07-31 baseline archive at `results/34ea1d3d/` (60 steps total in
  both runs).
- The failure is the expected `VerifyClientManagementCredentials`
  (`URL for client management point does not use https scheme`): the
  HTTP-only local issuer cannot provide the `https` client-management URL
  that step requires. The HTTPS issuer topology (see above) closes this
  gap; an externally reachable HTTPS issuer is still required before any
  certification claim.
- Run note (environment, not harness): the script's curl calls to the
  `sso-issuer` hostname must bypass the ambient HTTP(S) proxy — with
  `HTTP_PROXY` set and `sso-issuer` absent from `no_proxy`, the proxy
  answers the login POST with 502 and the suite login cannot complete.
  The archived run was executed with the proxy environment variables
  unset; everything else (server build, containers, headless Chrome) is
  localhost/container-network traffic.

A same-commit HTTP re-run at HEAD `7400ba0c` (`results/7400ba0c/`, after
this commit added the HTTPS topology) reproduced the identical
59 SUCCESS + 1 FAILURE counts and step sequence, confirming the default
HTTP path is unchanged.

## Current response-type boundary

The authorization handler and discovery metadata accept:

| Runtime mode | `response_types_supported` | Notes |
|---|---|---|
| Default | `code`, `token` | `token` is the server's direct-mint branch. |
| OAuth 2.1 strict | `code` | Direct-mint `token` and an omitted response type are rejected. |

`id_token`, `id_token token`, `code id_token`, `code token` and
`code id_token token` are rejected with `unsupported_response_type`.
Consequently, this implementation must **not** claim OIDC OP Implicit or OP
Hybrid profile support. ID Tokens are issued on the authorization-code token
exchange when `openid` is granted and an ID-token issuer is wired.

## Implemented OIDC/OAuth capability

### Core authorization-code deployment

- Authorization Code flow through `/auth/login` and `/token`.
- PKCE, with S256-only behavior in OAuth 2.1 strict mode.
- ID Token issuance for `openid`, including `nonce`, authentication context,
  and required `at_hash` when an access token shares the response.
- `/userinfo` JSON or signed/encrypted response according to client metadata
  and wired signers/encrypter.
- `/.well-known/openid-configuration`,
  `/.well-known/oauth-authorization-server` and
  `/.well-known/jwks.json`.
- Discovery metadata derived from live server state and feature gates.
- `prompt=none`, `login_hint`, `claims`, `form_post` and JARM options.
- RP-initiated logout, back-channel logout, front-channel logout and
  `check_session_iframe` when their dependencies are wired.

### Client and request features

- Dynamic Client Registration at `POST /register` plus RFC 7592
  registration-management endpoints when DCR is enabled.
- Client metadata validation and registration-access-token protection.
- **No software-statement assertion processing is implemented.**
- PAR at `POST /par`.
- JAR and encrypted JAR when fetch/decryption options are wired.
- private_key_jwt, mTLS and workload-identity client-authentication options.

### Advanced profiles/extensions

- FAPI 2 inspection/enforcement primitives, PAR/JAR/JARM, DPoP and mTLS.
  This is implementation coverage, not an FAPI certification claim.
- CIBA at `POST /backchannel-authentication` plus `/token`: poll is the base
  flow, with optional ping and push notification seams. CIBA `user_code` mode
  is not implemented.
- Device Authorization Grant at `POST /device/code`, with
  `GET|POST /device/verify` and polling at `/token`.
- DPoP, encrypted ID Token/UserInfo, pairwise subjects, signed metadata and
  OpenID Federation are separately opt-in.

## Cryptographic boundary

The stock signing configuration selects one of EdDSA, ES256, RS256 or PS256.
Inbound JWS verification has a broader asymmetric allowlist where the relevant
protocol permits it. Discovery is derived from the signers actually wired; do
not copy a static algorithm list into procurement material.

`alg=none` and symmetric algorithms are not accepted by the asymmetric
verification paths. Algorithm selection is checked before signature
verification to prevent key/algorithm confusion.

## Local test coverage

The project has unit, integration, race and cross-wire tests:

```bash
go test ./...
go test ./test/ -run TestE2E -v
go test ./... -race
```

These commands do not yield an OIDF certification result. This document does
not state a coverage percentage because repository coverage thresholds are
package-specific engineering floors, not protocol-conformance percentages.

## OIDF conformance harness

The manual scaffold lives in
[`test/oidc-conformance/`](../../test/oidc-conformance/README.md) and is now
runnable as checked in: it pins the official suite image to a release tag
(`registry.gitlab.com/openid/conformance-suite:release-v5.2.1`), mounts a
committed, `--validate-only`-checked server configuration, and defines the
supported-profile allowlist. The workflow runs headless via
`./run-headless.sh` (with `--issuer-https` for the HTTPS issuer topology)
and is not part of `make ci`; there are no OIDC-conformance Make targets.

**Supported OIDF modules** (only code-based profiles; implicit and hybrid
are rejected by the runtime and must never be selected): `basic` (code),
`config`, `dynamic`, `formpost`, `session`, `logout`; `jarm`, `fapi`
(FAPI 2.0 code) and `ciba` only when their wiring is enabled.

Before treating a run as release evidence:

1. Use the pinned conformance-suite image (never `:latest`); record its digest.
2. Use an externally reachable HTTPS issuer with a CA-trusted certificate for
   the certification run (the committed harness is a local smoke topology —
   HTTP or HTTPS behind a self-signed local proxy).
3. Select only modules from the allowlist above, matching the response types
   and options actually configured.
4. Archive the suite version, plan, configuration, server commit and complete
   result export under `test/oidc-conformance/results/<commit>/` (see the
   harness README's Evidence section).
5. Resolve failures without weakening oracle-leak, anti-enumeration or
   signature-validation invariants.
6. Submit to the OpenID Foundation and wait for an issued listing before
   changing the certification status above.

## Interoperability evidence

No versioned matrix of external relying-party test artifacts is committed.
Auth0, Okta, Keycloak, Entra ID, Google and client-library compatibility should
only be claimed when a reproducible test records product/library version,
flow, server configuration and result.

## References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Foundation Certification](https://openid.net/certification/)
- [OIDF Conformance Suite](https://gitlab.com/openid/conformance-suite)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126)
