# Requirements: Deploy-tree B4 live sweep subcommand built on apiclient (T-2 truthiness + T-8/T-9 probe surface)

Requirements specification for the selected direction "Deploy-tree B4 live sweep
subcommand built on apiclient (T-2 truthiness + T-8/T-9 probe surface)". Doc-only
artifact; no `.go` edits, so no build gates are triggered by this file.

Module: `cmd/sso-ctl/apiclient` (composition layer; dispatch table
`cmd/sso-ctl/main.go`). Source analysis:
`docs/architect-analysis/auto/analyses/cmd-sso-ctl-apiclient-12aa9498.json`,
direction 1. Every citation below was re-checked against the working tree; the
supplied acceptance is preserved verbatim in section 3 and made testable.

## 1. Verification outcome — citations checked against the repository

| Citation | Verdict |
|---|---|
| `cmd/sso-ctl/apiclient/apiclient.go` — `Client.Do`, `DefaultAddr=127.0.0.1:8443` | **Verified** — 188 lines, exactly one file in the package (zero `_test.go` files). `DefaultAddr = "http://127.0.0.1:8443"` (apiclient.go:24); `New` (47-62) falls back to `SSO_ADMIN_TOKEN`/`SSO_ADMIN_ADDR` env when options are absent; `Do` (81-111) JSON-encodes any non-nil body, sets `Authorization: Bearer` only when `c.token != ""`, and always sets `Accept: application/json`; `ReadBody` (134-142) caps at 1MB. |
| `cmd/sso-ctl/main.go:45-62` — subcommands map | **Verified** — map-based dispatch `var subcommands = map[string]func([]string) int` (main.go:46-63, 16 entries); a new subcommand costs exactly one map entry plus one usage line. |
| `cmd/sso-ctl/auditverify/main.go:414` — existing live-API pattern, `--from-url` + bearer | **Verified** — `--from-url` / `--bearer` flags bound at main.go:102-103; `readFromURL(base, bearer, ...)` at 403-448 (line 414 is inside it); `fetchEventPage` (450-473) hand-rolls a raw `http.Client` with `Authorization: Bearer` + `Accept: application/json`. This is the precedent for the sweep's bare-client T-9 probe (REQ-5). |
| `test/oidc_discovery_test.go:61-88` — `TestDiscovery_AdvertisesRequiredFields` / `IssuerComesFromWithIssuer` / `EndpointsAreAbsoluteURLs` | **Verified** — tests at exactly lines 61, 80, 88, all against `httptest` servers; 13 `TestDiscovery_*` tests total, none probes for 404s (no `404`/`NotFound` reference in the file). The "no 404-sweep test exists" gap is confirmed. |
| `interfaces/sso/server_discovery_config.go:139-152` — `buildBaseMetadata` | **Verified** — function at line 142; `AuthorizationEndpoint: base + PathLogin`, `TokenEndpoint: base + PathToken`, `JWKSURI: base + PathJWKS`, `RevocationEndpoint: base + PathRevoke`, `IntrospectionEndpoint: base + PathIntrospect` (146-149); `UserInfoEndpoint`/`EndSessionEndpoint` only when `oidcGateOn()` (155-163, `omitempty` — matches "when advertised"). JSON field names pinned in `protocols/oidc/metadata.go:14-19` (`token_endpoint`, `authorization_endpoint`, `jwks_uri`, `introspection_endpoint`, `revocation_endpoint`, `userinfo_endpoint`, `end_session_endpoint`). |
| `shared/core/consts.go:21` — `PathToken="/token"` | **Verified** — line 21 exactly: `PathToken = "/token"`. Also `PathIntrospect="/token/introspect"`, `PathRevoke="/token/revoke"`, `PathLogin="/auth/login"` in the same block. |
| `interfaces/sso/server_token.go:190-207` — `rejectUnregisteredScopes` seam, plain `invalid_scope` body | **Verified** — function at line 203; the seam runs inside `dispatchTokenGrant` (server_token.go:106-124) which is reached **only after** `authenticateTokenClient` (29-33) — an unauthenticated scope probe can never reach the seam. The plain body is emitted at `protocols/oauth/scoperegistry/reject.go:37` (`ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))`); the per-client allowlist fallback (`oauthvalidate.GrantedScopes`, scope.go:80-131; cc branch at `internal/handler/tokengrant/token_client_credentials.go:36`) emits the **same** bytes. `core.ErrorBody` = `{ "error": code }` (shared/core/error_body.go:11-16); `ErrInvalidScope = "invalid_scope"` (shared/core/errors.go:170). |
| `docs/campaigns/implementation-gate.md:13` — T-2 sweep definition | **Verified (content)** — B4-3 row: "T-2：sweep 全绿（广告端点绝不 404）；`metadata.token_endpoint == "/token"`". The file is paragraph-per-line markdown, so the "line 13" citation has no line-level meaning; the definition itself is confirmed. |

Additional facts verified during this pass (load-bearing for the requirements):

1. **Router 404 semantics force canonical-method probes.** `StdRouter.ServeHTTP`
   (shared/core/router.go:376-412) returns `http.NotFound` when *either* the
   method or the path fails to match (`if req.Method != route.method { continue }`
   → fall-through → `http.NotFound`). A GET against a mounted POST-only route
   therefore returns **404**, indistinguishable from an unmounted path. The sweep
   MUST probe each endpoint with its canonical method (REQ-2 table) or the
   truthiness assertion proves nothing.
2. **`/token` accepts JSON bodies.** `oauthwire.BindParams` (protocols/oauth/
   oauthwire/bind.go:22-39) dispatches on Content-Type; `apiclient.Do` sends
   `application/json`, which is accepted. The sweep needs **zero** apiclient
   changes for the credential-bearing probes; body credentials (`client_id` +
   `client_secret` fields) work — HTTP Basic only *wins over* body creds when both
   are present (server_token.go / handle_introspect.go:130-133).
3. **T-8a claim emission is wiring-conditional.** `buildAccessPayload`
   (infrastructure/defaultimpl/issue_payload.go:24-51) and `applyOptionalClaims`
   (65-113): `iss`, `sub`, `scope`, `client_id`, `jti` are always emitted;
   `tenant_id` only when `Subject.TenantID != ""` (client tenant-bound);
   `aud` only when resource indicators were requested (`Subject.Resources`);
   `roles` only when `Subject.Roles` is non-empty — and `Subject.Roles` is set
   **only** on user-token paths (server_login.go:120, server_oauth.go:90,
   token_refresh.go:279,310), **never** on the client-credentials path
   (`token_client_credentials.go:47-58` builds a Subject without Roles; the
   admin `IssueTempToken` path likewise, grpcadmin/admin_tokens.go:174-175). The
   acceptance's claim list therefore needs the expectation-flag matrix in REQ-3
   to stay deterministic. `kid` is present in all three issuers' headers
   (ed25519_issue.go:33 `header := ed25519Header{Alg, Typ, Kid}`;
   ecdsa_jwt_issuer.go:439; rsa_jwt_issuer.go:436); the payload claim names are
   pinned in ed25519_types.go (`client_id`, `jti`, `tenant_id`, `roles`, `aud`
   polymorphic string/array).
4. **T-8d needs authenticated client + restricted client or wired registry.**
   `GrantedScopes` rule 2 (oauthvalidate/scope.go:94-99): empty `AllowedScopes`
   = unrestricted pass-through. With an unrestricted client AND an unwired scope
   registry the probe scope would mint a token (200) instead of 400. Both
   enforcement layers produce byte-identical bodies
   `{"error":"invalid_scope"}\n` (`ctx.JSON` uses `json.Encoder.Encode`, which
   appends `\n` — shared/core/router.go:143-148). A 200 probe response is a
   genuine "enforcement absent" failure (REQ-4).
5. **T-9 probe must carry a parseable body and zero credentials.**
   `HandleIntrospect` binds the body BEFORE client auth (handle_introspect.go:
   111-134): an empty body → 400 `invalid_request`. With a parseable body and no
   credentials, `authenticateIntrospectionClient` (389-404: `id == "" ||
   secret == ""` → error) → 401 `{"error":"invalid_client"}` (216-234). The
   probe body is `{"token":"<dummy>"}`.
6. **`apiclient.New` cannot express "no bearer token".** The env fallback
   (apiclient.go:50-52: `if c.token == "" { c.token = os.Getenv(EnvToken) }`) means a sweep operator with `SSO_ADMIN_TOKEN` exported
   would leak a bearer into the T-9 probe. The T-9 probe uses a bare
   `http.Client` (auditverify precedent), never `apiclient`.
7. **The "ops/deploy tree contains no probe" claim is overstated.** 
   `ops/deploy/baremetal-ha/smoke.sh` (55 lines) exists: it greps the discovery
   doc for `"issuer"` and, when `CLIENT_ID`/`CLIENT_SECRET` are passed, runs a
   curl client-credentials → introspect → revoke round trip. It has **no**
   404-sweep, no `token_endpoint == /token` assertion, no JWT claims/kid check,
   no `invalid_scope` probe, and no credential-less 401 probe. The gap stands;
   the new subcommand is the operator artifact that closes it (the deploy tree
   can call `sso-ctl check` and gate on its exit code).

## 2. Core invariants

1. **Truthiness over liveness.** The sweep asserts the *advertised contract is
   real*: every endpoint the discovery document advertises resolves to a mounted
   route (non-404 when probed with its canonical method), and
   `token_endpoint`'s path suffix is `/token`. It never asserts server behavior
   the server does not promise (claim emission is asserted only against
   operator-declared expectations, invariant 4).
2. **Canonical-method probing.** Because the router collapses method mismatch to
   `http.NotFound` (router.go:376-412), every endpoint is probed with the method
   its wire contract uses (REQ-2 table). A wrong-method probe result is never
   interpreted.
3. **Byte-exact error-body assertions.** `invalid_scope` (T-8d) and
   `invalid_client` (T-9) are compared byte-for-byte against
   `{"error":"<code>"}\n` — the exact bytes `ctx.JSON(status,
   core.ErrorBody(code))` produces (`json.Encoder.Encode` newline, router.go:
   143-148). Any extra field (e.g. a `trace_id` wrapper) is a failure.
4. **Declared-expectation claim checks.** The sweep asserts only what the mint
   path guarantees plus what the operator declares: unconditional claims
   (kid/typ/iss/sub/client_id/jti), request-conditional claims (scope, aud), and
   operator-declared wiring-conditional claims (`--expect-tenant-id`,
   `--expect-roles`). Absence of an undeclared claim is never a failure.
5. **Exit-code discipline for deploy gating.** 0 = every executed check passed;
   1 = any executed check failed (with per-failure stderr diagnostics); 2 = CLI
   misuse. Checks that need client credentials are skipped with a stderr notice
   (not a failure) when the operator supplies none — a credential-less run still
   gates T-2 + T-9.
6. **No server changes.** This direction is operator-tooling only; nothing in
   `interfaces/sso`, `protocols/oauth`, or the stores changes, and no new server
   endpoint, error code, or config key is introduced.

## 3. Requirements

Acceptance (supplied, preserved verbatim): **New `sso-ctl` subcommand (e.g.
`sso-ctl check`)**: (T-2) fetches `/.well-known/openid-configuration` via
apiclient, asserts every advertised endpoint (token_endpoint,
authorization_endpoint, jwks_uri, introspection_endpoint, revocation_endpoint,
userinfo/end_session when advertised) returns non-404 and token_endpoint path
suffix == "/token"; (T-8a) mints/revokes through the admin or client-credentials
path and asserts the access token carries kid header plus
iss/aud/scope/client_id/tenant_id/roles claims; (T-8d) POSTs an unregistered
scope to /token and asserts byte-identical 400 `{"error":"invalid_scope"}`;
(T-9) calls introspection without client credentials and asserts 401 — exit
nonzero on any failure so the deploy tree can gate on it.

| # | Acceptance sentence | Requirement(s) |
|---|---|---|
| A1 | new `sso-ctl` subcommand | REQ-1 |
| A2 | (T-2) fetches `/.well-known/openid-configuration` via apiclient | REQ-2 |
| A3 | (T-2) every advertised endpoint returns non-404 (userinfo/end_session when advertised) | REQ-2 |
| A4 | (T-2) token_endpoint path suffix == `/token` | REQ-2 |
| A5 | (T-8a) mints/revokes via client-credentials path; token carries kid + iss/aud/scope/client_id/tenant_id/roles | REQ-3 |
| A6 | (T-8d) unregistered scope → byte-identical 400 `{"error":"invalid_scope"}` | REQ-4 |
| A7 | (T-9) introspection without client credentials → 401 | REQ-5 |
| A8 | exit nonzero on any failure (deploy-tree gateable) | REQ-1 (exit codes) |

### REQ-1 — `sso-ctl check` subcommand registration and CLI contract

- **Registration.** One map entry in `cmd/sso-ctl/main.go`:
  `"check": apiclient.CheckRun` (map at main.go:46-63), plus one usage line in
  `usage()` and a one-line doc comment in main.go's header block. The sweep
  lives in the `apiclient` package (see §4 — `cmd/sso-ctl/` is at the 16-directory
  fan-out ceiling, so no new subpackage).
- **Flags.** `--addr` (base URL; default `apiclient.DefaultAddr`; `SSO_ADMIN_ADDR`
  env honored via `apiclient.New`), `--client-id`, `--client-secret` (both
  required for the T-8 checks; omission of exactly one is misuse, exit 2),
  `--scope` (space-separated list, optional), `--resource` (optional, repeatable
  or space-separated), `--expect-tenant-id` (optional), `--expect-roles`
  (optional), `-h`/`--help` (usage, exit 0). `--expect-*`, `--scope`, and
  `--resource` require `--client-id` + `--client-secret` (misuse, exit 2).
- **Exit codes.** 0 all executed checks pass; 1 any executed check fails; 2 CLI
  misuse. Skipped checks (T-8a/T-8d without client credentials) never fail the
  run and are reported on stderr.
- **Output.** Deterministic ordering; stdout carries exactly one line per check
  group and a final `check OK` / `check FAIL` line; stderr carries per-failure
  diagnostics naming the endpoint/claim and the observed vs expected value.
  Same deployment + flags ⇒ byte-identical stdout.
- **HTTP posture.** All credential-bearing probes go through `apiclient`
  (JSON bodies accepted by `BindParams` — verified §1.2). The T-9 probe uses a
  bare `http.Client` with no `Authorization` header (verified §1.6). The 30s
  client timeout already set by `apiclient.New` applies; the bare T-9 client
  uses the same 30s timeout.

Testable criteria:

1. Given the `sso-ctl` binary help output, then `check` appears in the command
   list and `sso-ctl check -h` prints the sweep usage.
2. Given `--client-id` without `--client-secret` (or vice versa), or
   `--expect-roles` without credentials, then exit is 2 with a usage
   diagnostic on stderr.
3. Given a live deployment where every check passes, then exit is 0 and stdout
   ends with `check OK`.
4. Given the same deployment with one probe failing, then exit is 1, stdout
   ends with `check FAIL`, and stderr names the failing assertion.
5. Given the same deployment run twice with identical flags, then stdout is
   byte-identical (determinism).

### REQ-2 — T-2 discovery sweep (A2/A3/A4)

- **Fetch.** `apiclient.Get("/.well-known/openid-configuration")` (constant
  `PathOIDCDiscovery = "/.well-known/openid-configuration"`,
  server_discovery.go:18; GET mounted at server_discovery.go:27). Status 200 and
  a decodable JSON object are required; anything else fails the sweep.
- **Endpoint matrix.** For each of the seven fields that is present and
  non-empty in the doc, probe with the canonical method and assert status != 404
  (invariant 2):

  | Field | Canonical method | Deterministic status when mounted (verified) |
  |---|---|---|
  | `token_endpoint` | POST, empty body | 400 `invalid_request` (bind fails before client auth, server_token.go:26-30) |
  | `authorization_endpoint` | GET | non-404 (415/400/302 possible; `handleLogin`, server_login.go:19+) |
  | `jwks_uri` | GET | 200 (`handleJWKS`, server_discovery.go:386) |
  | `introspection_endpoint` | POST, `{"token":"<dummy>"}`, no creds | 401 `invalid_client` — this probe IS the T-9 check (REQ-5) |
  | `revocation_endpoint` | POST, empty body, no creds | 401 `invalid_client` (handle_revoke.go:135-145) |
  | `userinfo_endpoint` | GET, no bearer | 401 (mounted only when advertised — buildBaseMetadata 155-163) |
  | `end_session_endpoint` | GET | non-404 (3xx/400/200; `handleEndSession`, handlers.go:171) |

  The `userinfo_endpoint` / `end_session_endpoint` rows run only when the field
  is advertised (the doc omits them when the OIDC gate is off — the sweep never
  assumes presence).
- **`token_endpoint` suffix (A4).** Parse the advertised `token_endpoint` URL;
  assert `strings.HasSuffix(u.Path, "/token")`. This tolerates a base-path
  prefix (e.g. `https://host/sso/token`) while pinning the T-2 contract
  `metadata.token_endpoint == "/token"` (implementation-gate.md B4-3 row) in
  relative-path terms.
- **No-credential operation.** T-2 + the T-9 introspection probe run without
  client credentials; T-8a/T-8d are skipped with a stderr notice (exit code
  unaffected).

Testable criteria:

1. Given an httptest server serving a discovery doc whose seven fields all
   resolve to mounted handlers (real `sso.NewServer` via the testkit pattern of
   `test/oidc_discovery_test.go:61-88`), then the T-2 sweep passes.
2. Given a stub server whose discovery doc advertises one endpoint that returns
   404 (unmounted), then that endpoint's row fails, exit is 1, and stderr names
   the endpoint URL and the 404 status.
3. Given a discovery doc whose `token_endpoint` path is not `/token`-suffixed
   (e.g. `https://host/oauth2/token`), then the A4 assertion fails with the
   observed vs expected suffix on stderr.
4. Given a discovery doc WITHOUT `userinfo_endpoint` / `end_session_endpoint`,
   then no probe is issued for either field and the sweep passes (advertised-only
   semantics).
5. Given a discovery doc with an absolute non-`http(s)` endpoint URL (e.g.
   `file:///`), then the sweep fails that row (unparseable/unsupported scheme)
   rather than attempting the request.
6. Given a token_endpoint probed with POST and an empty body returning 400
   `invalid_request`, then the row passes (non-404) — and a 405/500 response
   also passes (the assertion is strictly "not 404", per A3).

### REQ-3 — T-8a mint / claims / revoke round trip (A5)

- **Mint.** `apiclient.Post(PathToken, {...})` with JSON body
  `{"grant_type":"client_credentials","client_id":C,"client_secret":S,
  "scope":<--scope when given>,"resource":<--resource when given>}` (JSON
  accepted — verified §1.2; Basic auth is not required because body creds are
  honored). Require status 200 and a JSON body carrying a non-empty
  `access_token`. This is the client-credentials branch of the acceptance's
  "mints/revokes through the admin or client-credentials path" (the admin
  `IssueTempToken` path mints no access-token claim set, and break-glass is
  store-gated, so cc is the deterministic live mint — verified §1.3).
- **JWT decode.** Split on `.` (3 parts required), base64url-raw-decode header
  and payload. The sweep performs NO signature verification (it is a truthiness
  probe, not a verifier; signature verification is the resource server's
  contract).
- **Claims matrix** (invariant 4 — emission facts verified §1.3):

  | Claim | Assertion | Condition |
  |---|---|---|
  | header.`kid` | non-empty AND present in the JWKS served at `jwks_uri` (fetch once; a freshly minted token's kid is the current signing key, which must be published) | always |
  | header.`typ` | `at+jwt` (RFC 9068 §2.1) | always |
  | `iss` | equals the discovery doc's `issuer` (both derive from the server's configured issuer; a mismatch is exactly the B4 item 1 Host-derived-issuer drift this sweep must surface) | always |
  | `sub` | equals `--client-id` | always |
  | `client_id` | equals `--client-id` | always |
  | `jti` | non-empty | always |
  | `scope` | contains every requested `--scope` value | when `--scope` given |
  | `aud` | contains every `--resource` value (polymorphic string/array both accepted — audClaim, ed25519_types.go) | when `--resource` given |
  | `tenant_id` | present and equal to `--expect-tenant-id` | when flag given |
  | `roles` | present, non-empty array of strings | when `--expect-roles` given |

  Documented behavior: `--expect-roles` against a cc-path mint deterministically
  fails, because cc mints never resolve `Subject.Roles` (verified §1.3 — roles
  is a user-token-path claim). That is the correct truthiness outcome for a
  deployment whose policy requires roles at mint time; the flag exists so the
  operator can declare the expectation rather than have the sweep silently skip
  the claim.
- **Revoke.** `apiclient.Post(PathRevoke, {"token":<access_token>,
  "client_id":C,"client_secret":S})` → assert 200 (AGENTS.md: `/token/revoke`
  with valid client credentials is 200 regardless of token existence).
- **Post-revoke introspection.** `apiclient.Post(PathIntrospect,
  {"token":<access_token>,"client_id":C,"client_secret":S})` → assert 200 and
  `"active":false` (the minted token was genuinely revoked — the revoke half of
  "mints/revokes").
- **No refresh_token assertion.** The cc response must not contain
  `refresh_token` (cc never issues one — token_client_credentials.go:21 comment;
  asserted as a negative check on the mint response).

Testable criteria:

1. Given a live server with a seeded client (ID `C`, secret `S`,
   `AllowedScopes` containing the requested scope) and `WithIssuer` set, then
   the mint passes, the decoded header has a non-empty `kid` present in the
   `jwks_uri` JWKS, `typ == "at+jwt"`, and `iss` equals the discovery issuer.
2. Given `--scope read write` with `C` allowed both, then the token's `scope`
   claim contains `read` and `write`.
3. Given `--resource https://api.example` then the token's `aud` claim contains
   it (string or array form).
4. Given a tenant-bound client and `--expect-tenant-id T`, then the token's
   `tenant_id` equals `T`; given a non-tenant-bound client and the same flag,
   the check fails with "tenant_id absent" (the flag is a declaration, not a
   guess).
5. Given `--expect-roles` on the cc path, then the check fails with a diagnostic
   stating that cc-path mints carry no `roles` claim (documented semantics), and
   without the flag the sweep passes.
6. Given the revoke + post-revoke introspect sequence, then revoke returns 200
   and the second introspect reports `"active":false`.
7. Given a mint response that includes a `refresh_token` field, then the sweep
   fails the no-refresh-token negative assertion.

### REQ-4 — T-8d unregistered-scope probe (A6)

- **Probe scope.** `"sweep-probe-"` + 12 random alphanumeric characters
  (generated per run; never `openid` or `device_sso`, which bypass the allowlist
  — oauthvalidate/scope.go:103-107). Randomization guarantees the scope cannot
  be registered in any deployment.
- **Probe.** `apiclient.Post(PathToken, {"grant_type":"client_credentials",
  "client_id":C,"client_secret":S,"scope":<probe>})` — authenticated, so the
  dispatcher reaches the scope gates (verified §1: `rejectUnregisteredScopes`
  runs only after client auth).
- **Assertion (A6).** Status 400 AND body byte-identical to
  `{"error":"invalid_scope"}\n` — the exact bytes both enforcement layers emit
  (`scoperegistry/reject.go:37` and `token_client_credentials.go:36`, both via
  `ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))`; invariant 3). A body
  with any extra field (e.g. `trace_id`) fails the byte-identical check.
- **200 response = enforcement-absent failure.** A successful mint means the
  deployment reached the grant branch unchecked (unrestricted client allowlist
  AND unwired scope registry — verified rule 2, scope.go:94-99). The sweep fails
  with: `invalid_scope not enforced: probe scope was granted — the client's
  AllowedScopes is empty or no global scope registry is wired` (exit 1).
- **Precondition documentation.** The probe's validity requires either a wired
  global scope registry or a probe client with a non-empty `AllowedScopes`; the
  usage banner and the failure diagnostic both state this.

Testable criteria:

1. Given a stub server returning status 400 and body `{"error":"invalid_scope"}\n`
   for the probe, then the check passes.
2. Given the same stub returning `{"error":"invalid_scope","trace_id":"x"}\n`,
   then the check fails (byte-identical requirement) with the observed body on
   stderr.
3. Given a stub returning 200 with an access token for the probe scope, then the
   check fails with the enforcement-absent diagnostic.
4. Given a stub returning 400 with a non-`invalid_scope` code (e.g.
   `invalid_request`), then the check fails.

### REQ-5 — T-9 credential-less introspection probe (A7)

- **Probe.** Bare `http.Client` (30s timeout), POST
  `<base>/token/introspect` with JSON body `{"token":"sweep-probe-dummy"}` and
  NO `Authorization` header, NO `client_id`/`client_secret` in the body, NO
  assertion fields. The parseable body is required so `BindParams` succeeds and
  the handler reaches the client-auth gate (verified §1.5); a bare client is
  required because `apiclient.New` inherits `SSO_ADMIN_TOKEN` (verified §1.6).
- **Assertion (A7).** Status 401 AND body byte-identical to
  `{"error":"invalid_client"}\n` (`authenticateIntrospectionClient` with empty
  id/secret → 401 `core.ErrorBody(core.ErrInvalidClient)`,
  handle_introspect.go:216-234, 389-404; invariant 3).
- The T-9 probe doubles as the `introspection_endpoint` row of the T-2 matrix
  (REQ-2) — it is issued exactly once per run.

Testable criteria:

1. Given a live server, the probe returns 401 `{"error":"invalid_client"}\n`
   and the check passes.
2. Given a stub that returns 200 for the probe (endpoint does not enforce client
   auth), then the check fails with the observed status.
3. Given the `SSO_ADMIN_TOKEN` env var set, the probe request still carries no
   `Authorization` header (asserted in the sweep's httptest contract test).
4. Given a 400 `invalid_request` response (body-binding failure), the check
   fails (the assertion is 401 specifically, not non-404).

### REQ-6 — apiclient contract tests and sweep tests (closes the zero-test gap)

The direction's problem statement names the zero-test state of
`cmd/sso-ctl/apiclient/` (only apiclient.go, 188 lines). The sweep's probes are
only as trustworthy as the client's header/body contract, so the module gains
contract tests pinning exactly the behaviors the sweep depends on, plus the
sweep's own unit/integration tests.

- **apiclient contract tests** (`apiclient_test.go`, httptest):
  `Do` sends `Authorization: Bearer <token>` when `WithToken` is set and omits
  the header when no token is configured (env unset in the test); body-bearing
  requests send `Content-Type: application/json` and `Accept:
  application/json`; `New` honors `WithAddr`/`WithToken` before env fallback;
  `ReadBody` caps at 1MB and closes the body; `Do` returns the raw response for
  non-2xx statuses (no hidden error mapping).
- **Sweep tests** (`check_test.go`): against a stub server serving a crafted
  discovery doc (REQ-2 criteria 2-6, REQ-4 criteria 1-4, REQ-5 criteria 2-3)
  and against a real `sso.NewServer` (testkit pattern from
  `test/oidc_discovery_test.go`) for the green path (REQ-2 criterion 1, REQ-3
  criteria 1-7 with `defaultimpl` memory stores + Ed25519 issuer + seeded
  client), plus the exit-code/misuse criteria of REQ-1. No live network, no
  `SSO_TEST_*` env required.

Testable criterion:

1. Given `go test ./cmd/sso-ctl/apiclient/ -race`, then all contract and sweep
   tests pass without external services.

## 4. Budgets and design constraints (checked before editing)

- `cmd/sso-ctl/` has exactly **16 subdirectories** today (apiclient,
  auditexport, auditverify, clientscmd, configcmd, entitiescmd, generate,
  hashcmd, importcmd, legacysync, migratecmd, sessionscmd, snapshotcmd,
  soc2report, tokenscmd, tui) and `maxSubdirsPerDir = 16`
  (directory_fanout_test.go:35) with no `cmd/sso-ctl` entry in
  `dirSubdirExemptions` (70-73). **A new subpackage would trip
  `TestArchitecture_DirectorySubdirFanout` — the sweep MUST live in the
  existing `cmd/sso-ctl/apiclient` package** (the direction's "natural carrier"),
  keeping the directory count at 16.
- `apiclient` goes from 1 to 2 non-test files (≤ 10/dir); each file ≤ 500 lines
  (apiclient.go is 188; `check.go` target ≤ 450; split the sweep into
  focused files if it would exceed the budget — e.g. `discovery.go`/`token.go` —
  still within the same package, keeping non-test files ≤ 10).
- New functions ≤ 50 lines, complexity ≤ 15, if-nesting ≤ 3 (the probe matrix is
  data-driven — a table of {field, method, expected} rows — not nested
  branches, mirroring the existing `readFromURL` shape).
- `interfaces/sso` is at its 60-file ceiling and is NOT touched; `shared/core`,
  `protocols/oauth`, `internal/handler/tokengrant`, `infrastructure/defaultimpl`
  are all read-only references for the sweep's assertions (no edits).
- Import flow: `cmd/sso-ctl/apiclient` → `net/http`/`net/url`/`encoding/json`
  only; no new upward imports, no `protocols/*` involvement.
- `docs/openapi.yaml`, `docs/error-codes.md`, `docs/config-reference.md` are
  unchanged: CLI-only surface, no new server endpoints, errors, or config keys.

## 5. Files

### Create

```text
cmd/sso-ctl/apiclient/check.go          — CheckRun(args []string) int: flag parsing, check-group
                                         orchestration (T-2 sweep, T-8a mint/claims/revoke, T-8d
                                         probe, T-9 probe), exit-code mapping, stdout/stderr
                                         discipline (REQ-1..REQ-5); may be split within the package
                                         (discovery.go / token.go) if the line budget demands it
cmd/sso-ctl/apiclient/check_test.go     — REQ-1 criteria 1-5, REQ-2 criteria 1-6, REQ-3 criteria
                                         1-7, REQ-4 criteria 1-4, REQ-5 criteria 1-4 (stub server +
                                         real sso.NewServer green path)
cmd/sso-ctl/apiclient/apiclient_test.go — REQ-6 contract tests: bearer header present/absent,
                                         JSON Content-Type/Accept, New option-vs-env precedence,
                                         ReadBody 1MB cap + close
```

### Modify

```text
cmd/sso-ctl/main.go   — one map entry ("check": apiclient.CheckRun), one usage line, one header
                        doc-comment line (REQ-1)
```

### Do not modify

```text
cmd/sso-ctl/apiclient/apiclient.go — client reused as-is (JSON bodies accepted by the server via
                                     oauthwire.BindParams; no helper additions — typed
                                     FetchDiscovery/TokenRequest/Introspect helpers are the other
                                     direction's scope, see §7)
interfaces/sso/*                   — 60-file ceiling; no server change
shared/core/router.go              — 404 semantics reused as the probe's oracle, not changed
protocols/oauth/*, internal/handler/tokengrant/*, infrastructure/defaultimpl/* — referenced only
```

Optional adoption (not required by the acceptance): wire `sso-ctl check
--addr $base_url --client-id $CLIENT_ID --client-secret $CLIENT_SECRET` into
`ops/deploy/baremetal-ha/smoke.sh` (or the deploy tree's CI) so the gate is
enforced on every deploy — the subcommand is the probe smoke.sh lacks
(§1.7). Any such wiring is a separate deploy-tree change and does not block
this direction.

Confirm file/function/directory/fan-out ceilings before implementation (per
AGENTS.md budgets: 500-line files, 50-line functions, complexity 15, if-nesting
3, non-test files/dir 10, subdirs 15 — with the verified 16/16 state of
`cmd/sso-ctl` making any new directory a gate violation).

## 6. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/... -race
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests beside the code: REQ-1 criteria 1-5 (dispatch + usage + exit-code
discipline); REQ-2 criteria 1-6 (advertised-only sweep, 404 row failure,
`/token` suffix, canonical-method matrix); REQ-3 criteria 1-7 (cc mint against a
real `sso.NewServer` with `defaultimpl` stores, claims matrix, revoke +
post-revoke introspect, no-refresh-token); REQ-4 criteria 1-4 (byte-exact
`{"error":"invalid_scope"}\n`, enforcement-absent 200 case); REQ-5 criteria 1-4
(401 `invalid_client`, env-leak guard); REQ-6 criterion 1 (apiclient contract
tests). All tests run without external services (httptest only).

## 7. Explicit non-goals (scope guard)

- No server-side changes: no new endpoints, no `interfaces/sso` edits, no
  discovery/config/OpenAPI/error-code changes. B4 items T-8b/T-8c/T-8e
  (JSON Content-Type rejection, constant-time comparisons, cc no-store
  verification) are other directions' acceptance, not this one.
- No typed apiclient helpers (`FetchDiscovery`, `TokenRequest` with
  form-urlencoded support, `Introspect`) — that is the "Harden apiclient into
  the single trust-path client" direction's scope; this direction reuses
  `apiclient` as-is and adds only `check.go` + tests.
- No issuer-allowlist / `resolveIssuer` changes and no new config knob; the
  sweep only *surfaces* issuer drift via the `iss == discovery.issuer`
  assertion (REQ-3).
- No JWT signature verification in the sweep (resource servers verify; the
  sweep attests presence and shape).
- No changes to `ops/deploy/*` scripts in this direction (the exit code makes
  them gateable; wiring them is optional adoption).
- No new subpackage under `cmd/sso-ctl/` (fan-out ceiling, §4).
