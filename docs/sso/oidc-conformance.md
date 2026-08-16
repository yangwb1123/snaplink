# OIDC Conformance — Certification-Readiness Evidence Kit

Last verified against the code and the archived run artifacts on
2026-08-16 at HEAD `39ecdf7a`. Every count in this document was re-read
from the archives listed in [§2](#2-evidence-table); the reproduction
commands were re-checked against `test/oidc-conformance/run-headless.sh`
and the harness [README](../../test/oidc-conformance/README.md).

## 1. Certification status (read this first)

Snaplink has **no recorded OpenID Foundation certification listing or
official conformance result**. What exists is a headless, repeatable local
harness (`test/oidc-conformance/run-headless.sh`) plus archived smoke runs
of the OIDF suite's `oidcc-server` module. The harness is not part of
`make ci`.

- Do not use “OpenID Certified,” “FAPI Certified” or an equivalent badge.
- “Implemented” below means code/tests exist, not that an OIDF profile
  passed.
- Local evidence (an HTTP issuer, or an HTTPS issuer behind a self-signed
  local proxy) cannot be presented as an official certification claim: the
  suite has not run against an externally reachable, CA-trusted HTTPS
  issuer, and no OIDF listing has been issued. The exact remaining steps
  are in [§5](#5-remaining-blockers-for-an-official-run).
- An RFP response must name the exact server commit, configuration and
  official result it relies on.

## 2. Evidence table

All archives live under
`test/oidc-conformance/results/<commit>[-https][-fapi]/` (git-ignored; the
archival contract is the harness README's Evidence section). Every basic/HTTPS
archive contains `plan.json`, `oidcc-server.log.json`,
`oidcc-server.info.json`, `config.yaml` (byte-identical pinned config, md5
`932b860b…`), `commit.txt` and `worktree.txt`; `commit.txt` matches the
archive name in all five runs. The FAPI archive (`results/39ecdf7a-fapi/`)
contains config/discovery/jwks/suite-login-failure/commit/worktree plus a
`BLOCKER.md` root-cause record — no plan/log/info because the run was
blocked before plan creation (§2 note).

All runs pin the suite image
`registry.gitlab.com/openid/conformance-suite:release-v5.2.1` (suite
version `5.2.1` recorded in every `oidcc-server.info.json`), create the
Basic certification plan (`oidcc-basic-certification-test-plan`) with the
`server_metadata=discovery` + `client_registration=dynamic_client` variant
(38 plan modules) and execute the `oidcc-server` module.

| Run | Date (UTC, suite start) | Server commit | Topology | Result (`oidcc-server`, 60 steps) | Archive | Reproduce |
|---|---|---|---|---|---|---|
| HTTP baseline (initial) | 2026-07-31 | `34ea1d3d` | HTTP issuer `http://sso-issuer:8180` | **59 SUCCESS + 1 FAILURE**; 2 WARNING | `results/34ea1d3d/` | `./run-headless.sh --timeout 900` |
| HTTP baseline (post gRPC fix) | 2026-08-15 | `af3bc485` | HTTP issuer | **59 SUCCESS + 1 FAILURE**; 3 WARNING | `results/af3bc485/` | `./run-headless.sh --timeout 900` |
| HTTP same-commit re-run | 2026-08-15 | `7400ba0c` | HTTP issuer | **59 SUCCESS + 1 FAILURE**; 3 WARNING | `results/7400ba0c/` | `./run-headless.sh --timeout 900` |
| HTTP fallback re-run (B12-2) | 2026-08-16 | `78bb614f` | HTTP issuer | **59 SUCCESS + 1 FAILURE**; 3 WARNING | `results/78bb614f/` | `./run-headless.sh --timeout 900` |
| HTTPS milestone | 2026-08-15 | `7400ba0c` | HTTPS issuer (self-signed local proxy) | **60 SUCCESS + 0 FAILURE**; 3 WARNING | `results/7400ba0c-https/` | `./run-headless.sh --timeout 900 --issuer-https` |
| FAPI 2.0 SP attempt | 2026-08-16 | `39ecdf7a` | HTTP issuer, FAPI variant (`--fapi`) | **blocked** — no plan created, no module ran (see the blocker note below) | `results/39ecdf7a-fapi/` | `./run-headless.sh --fapi --timeout 600` |

FAPI 2.0 attempt (blocked): the `--fapi` run passed config validation, the
harness start, DCR registration of the suite login client and the admin
signup, then **failed at the suite's own admin login** on all eight
retries: the pinned suite (`release-v5.2.1`) validates its login ID token
with Spring Security's default `OidcIdTokenDecoderFactory`, whose
`jwsAlgorithmResolver` is hard-coded to **RS256**, while the FAPI 2.0
Security Profile requires a non-RS256 ID-token alg (the suite's own
`FAPI2CheckDiscEndpointIdTokenSigningAlgValuesSupported` demands ≥1 of
PS256/ES256/EdDSA/Ed25519 in discovery). Snaplink correctly signs ES256 in
the FAPI variant, and the suite rejects that login ID token with
`invalid_id_token: Signed JWT rejected: Another algorithm expected, or no
matching key(s) found`. A control decode using the suite's jars proves the
token itself verifies; the rejection is the factory's RS256-only resolver.
Consequently **no FAPI module has ever run against this harness** — the
`fapi` allowlist row below must not be reported as passing. The archive
`results/39ecdf7a-fapi/` contains the run-time evidence and a root-cause
record (`BLOCKER.md`); the recommended unblock (separate RS256 issuer for
the suite's own login, or per-client `id_token_signed_response_alg`) is
described there.

B12-2 fallback (2026-08-16): the per-client `id_token_signed_response_alg`
unblock was implemented in the B12-1 worktree but not merged at HEAD
`78bb614f`, so the FAPI run was not attempted (contract fallback — no
fabricated result). The harness variant was verified intact and the basic
plan was re-run at `78bb614f` with a byte-identical result (59 SUCCESS + 1
FAILURE; 3 WARNING — see the evidence row above), proving zero regression.
The blocker record is `docs/campaigns/reports/b12-fapi-conformance.md`;
the FAPI run proceeds once B12-1 lands.

Notes:

- The sole HTTP failure is the expected `VerifyClientManagementCredentials`
  step (`URL for client management point does not use https scheme`): an
  HTTP-only local issuer cannot provide the https client-management URL
  that step requires. The HTTPS topology closes this gap — the dynamically
  registered client's `registration_client_uri` becomes
  `https://sso-issuer:8181/register/...`, so the step passes.
- WARNING events are non-fatal
  `EnsureIdTokenDoesNotContainNonRequestedClaims` notices: the 2026-07-31
  baseline records the `ext` claim; the three 2026-08-15 runs record
  `ext` + `scope` plus the suite's generic explanation. No run reports a
  FAILURE beyond the http-only client-management check.
- Step counts are the per-step result events inside each
  `oidcc-server.log.json` (60 steps per run: 59+1 or 60+0). The
  `oidcc-server.info.json` `result` field is `FAILED` for the HTTP runs
  and `WARNING` for the HTTPS run (the overall WARNING reflects the
  non-fatal claim notices).
- All runs cover discovery fetch/validation, JWKS fetch/validation,
  dynamic client registration, the authorization-code round trip
  (browser-driven login against the local OP), ID-token verification,
  userinfo and resource-endpoint calls.
- Run environment (both topologies, not a harness defect): the script's
  curl calls to the `sso-issuer` hostname must bypass the ambient HTTP(S)
  proxy — with `HTTP_PROXY` set and `sso-issuer` absent from `no_proxy`,
  the proxy answers the login POST with 502 and the suite login cannot
  complete. The archived runs were executed with the proxy environment
  variables unset; everything else (server build, containers, headless
  Chrome) is localhost/container-network traffic.

This is smoke evidence only — **not an OIDF result**. Certification
language still requires an official suite run against an externally
reachable HTTPS issuer with archived plan/result artifacts and, for
"certified", an issued OIDF listing ([§5](#5-remaining-blockers-for-an-official-run)).

## 3. Reproduction manual (zero → archive)

Prerequisites (harness README): Docker with compose v2, google-chrome,
python3 (`websocket-client`); `--issuer-https` additionally requires
`keytool` (JDK). All commands run from `test/oidc-conformance/`.

1. **Validate the pinned server config** (fails fast on schema drift; the
   empty `-grpc-listen` disables the gRPC plane, which the harness does
   not exercise — see `docker-compose.yml`):

   ```bash
   docker compose --env-file config.env run --rm --no-deps sso-server \
     --validate-only -grpc-listen "" --config /etc/sso/conformance.yaml
   ```

   Expected: `{"...","level":"INFO","msg":"config valid",...}` with exit 0.
   `run-headless.sh` runs this same command internally before starting the
   harness, so step 1 is both the standalone check and part of step 2.

2. **Run the module headless and archive the evidence** (default module
   `oidcc-server`; the script creates the Basic-certification
   discovery+dynamic plan, DCR-registers the suite's login client, signs
   up the admin user, drives headless Chrome through the JSON logins, and
   archives plan/log/info/config/commit under
   `results/<commit>[-https]/`):

   ```bash
   ./run-headless.sh                # HTTP issuer topology
   ./run-headless.sh --issuer-https # HTTPS issuer topology (self-signed proxy)
   ```

   Flags (from the script usage line): `--module oidcc-server`
   (default), `--timeout 450` (default; the archived runs used
   `--timeout 900`), `--issuer-https`. A different module can be selected
   as `MODULE=oidcc-config-certification-test-plan ./run-headless.sh`.

3. **Verify the archive**:

   ```bash
   ls -la results/<commit>[-https]/   # plan.json, oidcc-server.log.json,
                                      # oidcc-server.info.json, config.yaml,
                                      # commit.txt, worktree.txt
   cat results/<commit>[-https]/commit.txt   # must equal the archive name
   python3 - <<'PY'
   import json, collections
   log = json.load(open("results/<commit>[-https]/oidcc-server.log.json"))
   print(collections.Counter(d.get("result") for d in log))
   PY
   # e.g. Counter({'SUCCESS': 60, 'WARNING': 3, ...}) for the HTTPS run.
   ```

## 4. Module coverage matrix

README allowlist (only code-based profiles; implicit and hybrid are
rejected by the runtime) versus what the archived evidence actually ran.
The archived plan is the OIDC Core basic-certification plan with
discovery + dynamic registration; only `oidcc-server` was executed by the
archived runs.

| README allowlist module | Allowed | In archived evidence | Evidence mapping / notes |
|---|---|---|---|
| `basic` (code) | ✅ | ✅ | `oidcc-basic-certification-test-plan`, `response_type=code` variant; all 60 `oidcc-server` steps incl. PKCE, ID Token, UserInfo, refresh, prompt/claims. |
| `config` | ✅ | ✅ | plan variant `server_metadata=discovery` — discovery fetch/validation against `/.well-known/openid-configuration` (HTTP and HTTPS issuers). |
| `dynamic` | ✅ | ✅ | plan variant `client_registration=dynamic_client` — RFC 7591 DCR + RFC 7592 registration management (`registration_client_uri`). |
| `formpost` | ✅ | ⚠️ not run | the archived plan variant is `response_mode=default`; form-post coverage needs its own plan and archived run. |
| `session` | ✅ | ⚠️ not run | session-management plan (`check_session_iframe`); not part of the archived plan. |
| `logout` | ✅ | ⚠️ not run | RP-initiated logout plan; not part of the archived plan. |
| `jarm` | ✅* | ❌ not run | requires `oauth.jar`/JARM wiring (opt-in); no archive exists. |
| `fapi` | ✅* | ⚠️ blocked | `--fapi` harness wiring exists (plan/variant/module + config variant) and the run reaches suite login, then blocks: the pinned suite's RS256-only login decoder rejects the FAPI-required ES256 ID token. No plan created, no module ran. Evidence + root cause: `results/39ecdf7a-fapi/` (see §2). |
| `ciba` | ✅* | ❌ not run | only when a CIBA store is wired; no archive exists. |
| `implicit` | ❌ | — | runtime rejects `id_token` response types; must never be selected. |
| `hybrid` | ❌ | — | runtime rejects `code id_token` response types; must never be selected. |
| `userinfo` (standalone) | ⚠️ | — | only as part of `basic`; no standalone module. |

\*Allowed by the harness only when the corresponding wiring is enabled
(README). They remain "implemented ≠ certified" and each requires its own
plan, run and archive before it can feed any certification claim.

## 5. Remaining blockers for an official run

1. **Externally reachable HTTPS issuer (deployment required).** The
   archived runs use an HTTP issuer or an HTTPS issuer behind a self-signed
   local proxy (`certs/server.crt` plus a suite JVM truststore built by
   `prepare_tls`). OIDF guidance for certification runs requires a
   publicly reachable HTTPS issuer with a CA-trusted certificate. The
   committed harness cannot satisfy this on its own — it is a local smoke
   topology by design.
2. **OIDF account and listing submission.** No OpenID Foundation account
   or submitted certification request exists. Listing requires an
   organizational OIDF account, submission through the OIDF certification
   portal (official run's plan + result export + server commit/version),
   and an issued listing before any "certified" language may be used.
3. **Self-signed certificate limitation.** The local HTTPS evidence
   (60 SUCCESS + 0 FAILURE) proves the https-URI-dependent step passes in
   a truststore-augmented local topology. It is not an official result:
   the certificate is self-signed and the issuer is not externally
   reachable, so this document must not be cited as an OIDF certification.
4. **Archive upload strategy.** `results/` is git-ignored; the evidence
   table references local archives. A release that claims a run must
   attach the archive (plan, log, info, config, commit — per the harness
   README's Evidence section) and record the suite image digest
   (`docker inspect --format '{{.Image}}'` at run time).

## 6. Current response-type boundary

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

## 7. Implemented OIDC/OAuth capability

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

## 8. Cryptographic boundary

The stock signing configuration selects one of EdDSA, ES256, RS256 or PS256.
Inbound JWS verification has a broader asymmetric allowlist where the relevant
protocol permits it. Discovery is derived from the signers actually wired; do
not copy a static algorithm list into procurement material.

`alg=none` and symmetric algorithms are not accepted by the asymmetric
verification paths. Algorithm selection is checked before signature
verification to prevent key/algorithm confusion.

## 9. Local test coverage

The project has unit, integration, race and cross-wire tests:

```bash
go test ./...
go test ./test/ -run TestE2E -v
go test ./... -race
```

These commands do not yield an OIDF certification result. This document does
not state a coverage percentage because repository coverage thresholds are
package-specific engineering floors, not protocol-conformance percentages.

## 10. OIDF conformance harness

The manual scaffold lives in
[`test/oidc-conformance/`](../../test/oidc-conformance/README.md) and is
runnable as checked in: it pins the official suite image to a release tag
(`registry.gitlab.com/openid/conformance-suite:release-v5.2.1`), mounts a
committed, `--validate-only`-checked server configuration, and defines the
supported-profile allowlist (reproduced in [§4](#4-module-coverage-matrix)).
The workflow runs headless via `./run-headless.sh` (with `--issuer-https`
for the HTTPS issuer topology) and is not part of `make ci`; there are no
OIDC-conformance Make targets.

Before treating a run as release evidence:

1. Use the pinned conformance-suite image (never `:latest`); record its
   digest.
2. Use an externally reachable HTTPS issuer with a CA-trusted certificate
   for the certification run (the committed harness is a local smoke
   topology — HTTP or HTTPS behind a self-signed local proxy).
3. Select only modules from the allowlist in
   [§4](#4-module-coverage-matrix), matching the response types and options
   actually configured.
4. Archive the suite version, plan, configuration, server commit and
   complete result export under `test/oidc-conformance/results/<commit>/`
   (see the harness README's Evidence section).
5. Resolve failures without weakening oracle-leak, anti-enumeration or
   signature-validation invariants.
6. Submit to the OpenID Foundation and wait for an issued listing before
   changing the certification status in [§1](#1-certification-status-read-this-first).

## 11. Interoperability evidence

No versioned matrix of external relying-party test artifacts is committed.
Auth0, Okta, Keycloak, Entra ID, Google and client-library compatibility
should only be claimed when a reproducible test records product/library
version, flow, server configuration and result.

## 12. References

- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
- [OpenID Connect Discovery 1.0](https://openid.net/specs/openid-connect-discovery-1_0.html)
- [OpenID Foundation Certification](https://openid.net/certification/)
- [OIDF Conformance Suite](https://gitlab.com/openid/conformance-suite)
- [RFC 7636 — PKCE](https://www.rfc-editor.org/rfc/rfc7636)
- [RFC 9126 — PAR](https://www.rfc-editor.org/rfc/rfc9126)
