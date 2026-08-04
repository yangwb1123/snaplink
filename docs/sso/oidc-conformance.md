# OIDC Conformance Status

Last verified against the code on 2026-07-31.

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

## Smoke run evidence (HTTP-only local topology)

`test/oidc-conformance/run-headless.sh` against the pinned suite image
`release-v5.2.1` produced, for the `oidcc-server` module of the Basic
certification plan (discovery + dynamic-client variants):

- 59 SUCCESS steps covering discovery fetch/validation, JWKS fetch and
  validation, dynamic client registration, the authorization-code round
  trip (browser-driven login against the local OP), ID-token verification,
  userinfo and resource-endpoint calls.
- One expected FAILURE: `VerifyClientManagementCredentials` requires an
  `https` client-management URL, which an HTTP-only local issuer cannot
  provide. An externally reachable HTTPS issuer is required before any
  certification claim (see the harness README).

This is smoke evidence only — not an OIDF result. Certification language
still requires an official suite run against an HTTPS topology with archived
plan/result artifacts and, for "certified", an issued OIDF listing.

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
supported-profile allowlist. The workflow remains browser-interactive and
not part of `make ci`; there are no OIDC-conformance Make targets.

**Supported OIDF modules** (only code-based profiles; implicit and hybrid
are rejected by the runtime and must never be selected): `basic` (code),
`config`, `dynamic`, `formpost`, `session`, `logout`; `jarm`, `fapi`
(FAPI 2.0 code) and `ciba` only when their wiring is enabled.

Before treating a run as release evidence:

1. Use the pinned conformance-suite image (never `:latest`); record its digest.
2. Use HTTPS and issuer/redirect URIs valid for the selected plan for the
   certification run (the committed harness is an HTTP-only smoke topology).
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
