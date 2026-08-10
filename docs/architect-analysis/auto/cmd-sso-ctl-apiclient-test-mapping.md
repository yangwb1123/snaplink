# Test mapping + testkit verification for the `sso-ctl check` design — rev 2

Companion to [cmd-sso-ctl-apiclient-design.md](cmd-sso-ctl-apiclient-design.md).
Rev 2 re-maps the **amended failure surface**: the security-review amendments
(no-redirect pin, `--addr`/endpoint-URL validation incl. the env value,
redactURL/sanitizeBody redaction, crypto/rand failure handling) introduce
failure modes that rev 1 had no test entries for. Every row of the 25-row
failure table and every acceptance A1–A8 is re-verified mapped after the
revision. Doc-only artifact; no `.go` edits.

## 0. Amendment surface mapped in this revision

| Amendment (source) | New failure mode(s) | Mapped at |
|---|---|---|
| Security review §5 item 1 — no-redirect pin (`WithNoRedirect`, `http.ErrUseLastResponse`); content rows fail on any 3xx; truthiness rows pass on 3xx without following | M-1 content-row 3xx → row fail; M-2 truthiness-row 3xx → row pass, never followed; M-7 `WithNoRedirect` contract | §4 Table B |
| Security review §5 item 2 — URL validation: non-empty host, reject userinfo, reject query/fragment (flag **and** env-sourced value) | M-3 `--addr` userinfo/empty-host/query/fragment → exit 2; M-4 bad `SSO_ADMIN_ADDR` env → exit 2 (env wins); M-5 advertised-endpoint userinfo → row failed-as-skipped (row-2 extension) | §4 Table B, rows 2/24 |
| Security review §5 item 3 — R7 body-echo pin (non-2xx only, never the token string) + shared `redactURL`/`sanitizeBody` in every stderr diagnostic | M-6 redaction behavior (unit + integration never-echo) | §4 Table B, rows 1/4/7/19/22 |
| Security review §5 item 4 — crypto/rand failure → exit 1, never math/rand fallback; probe scope never printed | M-8 scope-generation failure | §4 Table B |
| CLI-conventions F-3 — preflight must validate the *effective* addr (env wins per `apiclient.New`) | M-4 (same) | §4 Table B, row 24 |

Identifiers M-1..M-8 are used here for mapping only; the design doc's §5 table
gains these rows when amended (see §5 corrections).

## 1. Testkit reuse — verified against the tree

Rev-1 rows all re-verified (no drift since):

| Claim (design §7 / §1) | Verdict | Evidence (this tree) |
|---|---|---|
| In-process `sso.NewServer` testkit exists in `test/oidc_discovery_test.go` | ✅ (line drift) | `newDiscoveryServer` spans **:21-50** (design says :31-50): `sso.NewServer(opts...)` + `defaultimpl.NewMemoryClientStore` + `AddSeed` + `defaultimpl.NewEd25519JWTIssuer` + `httptest.NewServer(srv.Handler())` (`srv.Handler()` = `interfaces/sso/server_routes.go:354`). Option functions confirmed: `WithIssuer`/`WithClientStore`/`WithTokenIssuer`/`WithDefaultTokenStrategy` (interfaces/sso/options.go:35,251,32, + options_admin.go). |
| Seeded restricted client doubles as T-8d precondition | ✅ | `clients.AddSeed(&sso.Client{ID:"demo", Secret:"s", Active:true, AllowedScopes:["read","write"]})` at :34-36 — non-empty `AllowedScopes` is exactly the restricted-client shape T-8d needs (`GrantedScopes` rule 2 pass-through only fires for nil/empty allowlist, `protocols/oauth/oauthvalidate/scope.go:93-96`). |
| 13 discovery tests, zero 404/NotFound refs | ✅ (line drift) | 13 `TestDiscovery_*` funcs at :61-281 (design's ":61-296" drifts; file is 290 lines). `grep -c "404\|NotFound"` = 0. The "no 404-sweep test" gap stands. |
| `dispatch_test.go` registration precedent | ✅ | `cmd/sso-ctl/dispatch_test.go` (package main): `TestSubcommands_GenerateIsWired` :9-15 asserts `subcommands["generate"]` directly; `TestSubcommands_EveryEntryHasARunFunc` :18-22. `subcommands` map at `main.go:46-63`, 16 entries :47-62. |
| apiclient non-test file ceiling | ✅ | `maxGoFilesPerDir = 10` (`directory_fanout_test.go:34`); `cmd/sso-ctl/apiclient` holds exactly 1 non-test file (`apiclient.go`, 188 lines) and is not in `dirFileCountExemptions` → growth 1→4 (`check.go` + `discovery.go`/`token.go` + the amended `apiclient.go` remains 1 file) is inside the cap. |
| 16/16 subdir ceiling | ✅ | `maxSubdirsPerDir = 16` (:35); `cmd/sso-ctl` has exactly 16 subdirs; `dirSubdirExemptions` = `{".": 21}` only → a new subpackage fails `TestArchitecture_DirectorySubdirFanout` (:127-131). Sweep must live in `apiclient` — confirmed. |
| 500-line file budget | ✅ | `maxFileLines = 500` (`maintainability_budget_test.go`), `fileSizeExemptions` empty, exemption cap 0 (`TestMaintainability_FileSizeExemptionsDoNotGrow`) → `check.go` ≤500 is gate-enforced; the design's ≤450 target with in-package split is sound. |
| 50-line / 15-complexity function budgets | ✅ | `maxFuncLines = 50`, `maxFuncComplexity = 15` (`maintainability_complexity_test.go:43-44`); both exemption lists empty, caps 0 → binding for every new helper in `check.go`. |
| `if` nesting ≤3 | ⚠️ discipline, not gate | AGENTS.md budget table only; no committed nesting gate exists (`maxdepth_test.go` caps directory depth at 3, not if-nesting). Design §4.2 presents it as a design constraint — accurate as written, but it is review-enforced, not `make ci`-enforced. |
| Layer legality of apiclient tests importing the server | ✅ | `layerName("test")` = `"composition"` (architecture_layer_test.go:71) and `layerName("cmd/...")` = `"composition"`; the gate rejects only `layerRank[to] > layerRank[from]` (:151), so composition→composition is legal. `interfaces/sso` (rank 5) and `infrastructure/defaultimpl` (rank 4) are strictly downward from `cmd` (rank 6). |
| Byte-exact body target `{"error":"invalid_scope"}\n` | ✅ | Both enforcement layers emit `ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))` (`protocols/oauth/scoperegistry/reject.go:37`, `internal/handler/tokengrant/token_client_credentials.go:40`); `ErrorBody` = `{"error":code}` (shared/core/error_body.go:11-16); `ctx.JSON` = `json.NewEncoder(c.w).Encode(v)` → trailing `\n` (shared/core/router.go:143-148). |

New rev-2 rows (amendment grounding):

| Claim | Verdict | Evidence (this tree) |
|---|---|---|
| `WithNoRedirect()` injection point exists in `apiclient.New` | ✅ | `Client` struct :33; `http.Client{Timeout: 30s}` constructed at :50-52; `Option func(*Client)` type :67; options applied in the `for _, o := range opts` loop :53-56 → an additive `WithNoRedirect()` setting `c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }` needs **zero changes to `New` itself** — one option function (~4 lines) plus a doc-comment line. `grep CheckRedirect` over the package: zero hits today. Design §3.3's "apiclient.go untouched" narrows to `Do/Get/Post/ReadBody/New` (the security review's required amendment 1). |
| `http.ErrUseLastResponse` no-follow pattern is tree precedent | ✅ | `interfaces/ssoclient/quotaprojection/http_client.go:81-82`; `infrastructure/auditgovernance/http_client.go:137-138`; `infrastructure/saml/idp/fanout.go:98-99`; `interfaces/sso/server_backchannel_logout.go:101,124` — same `copyClient.CheckRedirect = func(...) error { return http.ErrUseLastResponse }` shape the contract test pins. |
| crypto/rand failure path is testable | ✅ (pin added) | `crypto/rand.Reader` is a **package var** (`crypto/rand/rand.go:34`, go1.26.5) — a white-box test can swap it via `t.Cleanup`. **Load-bearing**: `crypto/rand.Read` "never returns an error" — it calls `io.ReadFull(Reader, b)` and **crashes the program irrecoverably** on error (rand.go, `Read` doc). The implementation MUST use `io.ReadFull(crypto/rand.Reader, buf)` (returnable error → exit 1), never `rand.Read` (crash) and never a `math/rand` fallback (amendment 4). The test pins this by construction. |

Reuse mechanics note (unchanged from rev 1): `newDiscoveryServer` is
**unexported** in `package ssotest`, so `check_test.go` cannot literally call
it. Reuse is by pattern: `check_test.go` constructs its own in-process server
with the same fixture shape (real `sso.NewServer`, memory stores, seeded
restricted client). This is what design §4.3 already says ("Tests may import
interfaces/sso + infrastructure/defaultimpl"). A literal `import "…/test"` is
layer-legal (composition→composition) but useless today; exporting a fixture
helper from `test/` would be an optional additive change, not required.

## 2. Byte-determinism — golden-testable without flakes: confirmed, with pins

The stdout contract (design §3.1) is the load-bearing part: stdout carries
exactly one line per executed check group in **fixed order** plus the final
`check OK`/`check FAIL` line; all per-run variable data — absolute URLs
(httptest random port), status numbers, byte dumps, the `crypto/rand` probe
scope, `jti`, `kid`, `iat`/`exp` — lives on stderr or is never printed.

- A checked-in golden string is therefore viable **without normalization** if
  and only if the implementation pins: (a) group lines are constant literals
  (no embedded URLs/status/counts), (b) probe order comes from a fixed slice,
  never map iteration, (c) skip notices go to stderr only. These three pins are
  stated in design §4.6; the golden test (`TestStdoutDeterministic`) should
  assert both two-run byte-equality AND equality against a checked-in constant
  for the standard fixture (ID-token issuer wired → 7 advertised endpoints →
  fixed group count).
- Rev-2 note: the redaction helpers (`redactURL`/`sanitizeBody`) affect stderr
  only — stdout determinism is untouched by the amendment (no stdout line ever
  carries a URL, body, or credential, and the redaction pins do not change
  that).
- Flake sources ruled out: httptest ports never reach stdout; the probe scope
  is random per run but unprinted; the Ed25519 `kid` is stable within one
  in-process server instance (key generated once at issuer construction), and
  even so it is stderr-only; minted `jti`/`iat`/`exp` are asserted, not
  printed. `t.Setenv` restores env (no cross-test pollution) and `CheckRun` is
  single-threaded — no output interleaving. Swapping `crypto/rand.Reader` for
  the M-8 test is likewise restored via `t.Cleanup` and never prints.
- `TestStdoutDeterministic` must run both invocations against the **same**
  server instance (second mint/revoke round trip against a live server is
  deterministic; nothing on stdout depends on token state).

## 3. A1–A8 → concrete tests (rev 2)

All in `cmd/sso-ctl/apiclient/` **except A1's registration test** (see the
placement correction below). `package apiclient_test` (black-box) for
`CheckRun`; `package apiclient` for the REQ-6 contract tests and the unit tests
of unexported helpers (`redactURL`, `sanitizeBody`, scope generation).

| Acceptance | Test(s) | Criterion |
|---|---|---|
| A1 new `sso-ctl` subcommand | `TestSubcommands_CheckIsWired` — **`cmd/sso-ctl/dispatch_test.go`, package main** (design §7's "all in apiclient/" header is wrong here: `subcommands` is package-private in main; this test is the direct heir of `TestSubcommands_GenerateIsWired`). Plus `TestCheck_HelpExitsZero` (apiclient): `CheckRun(["-h"])` → usage on stderr, exit 0 | `subcommands["check"]` registered, non-nil; `-h` exit 0. **Rev-2 pin:** with `flag.ContinueOnError`, `-h` yields `flag.ErrHelp` and every existing `ContinueOnError` subcommand exits 2 (configcmd precedent; zero `ErrHelp` special-cases in the tree) — `TestCheck_HelpExitsZero` makes `check`'s deliberate `errors.Is(err, flag.ErrHelp) → return 0` mapping (CLI-conventions F-2) mandatory, with usage on stderr per tree convention |
| A2 discovery fetched via apiclient | `TestSweep_GreenPath` | discovery fetched through `apiclient.Get`; 200 + decodable JSON required; green exit 0. **Rev-2:** a 3xx discovery response (e.g. 302) is a content-row failure, not a redirect-follow — added as a case in `TestSweep_DiscoveryFetchFail` |
| A3 every advertised endpoint non-404 | `TestSweep_GreenPath`; `TestSweep_AdvertisedOnly` (doc w/o userinfo/end_session → zero probes); `TestSweep_404RowFails`; `TestSweep_BadSchemeRow`; **rev-2:** `TestSweep_3xxTruthinessPasses`; `TestSweep_RedirectNotFollowed` | canonical-method matrix; strictly "not 404" (405/500 **and 3xx** pass — 3xx without following, preserving the login-page 302 case); no request on bad scheme; no redirect target ever receives a second request |
| A4 `token_endpoint` path suffix `/token` | `TestSweep_TokenEndpointSuffix` (`https://host/oauth2/token` → fail, observed vs expected suffix on stderr) | `strings.HasSuffix(u.Path, "/token")`; base-path prefix tolerated |
| A5 mint/revoke cc round trip + claims | `TestMint_ClaimsMatrix`; `TestMint_ScopeContainsRequested`; `TestMint_AudContainsResource` (string + array); `TestMint_TenantIDExpectation` (pass + "tenant_id absent" fail); `TestMint_RolesExpectationFailsOnCC`; `TestRevoke_RoundTrip`; `TestMint_NoRefreshToken` | kid∈JWKS, `typ=="at+jwt"`, iss==discovery issuer, sub/client_id==client, jti non-empty; undeclared claims never asserted absent |
| A6 byte-identical `invalid_scope` | `TestInvalidScope_ByteExact`; `TestInvalidScope_ExtraFieldFails`; `TestInvalidScope_EnforcementAbsent` (200 → enforcement-absent diagnostic); `TestInvalidScope_WrongCode` | `{"error":"invalid_scope"}\n` byte-for-byte; probe scope random per run, never `openid`/`device_sso` |
| A7 credential-less introspect → 401 | `TestIntrospect_NoCreds401`; `TestIntrospect_NoAuthHeaderLeak` (`t.Setenv("SSO_ADMIN_TOKEN", ...)` → recorded request has no `Authorization`); `TestIntrospect_200Fails`; `TestIntrospect_400Fails` | bare `http.Client`; parseable body; 401 specifically; `{"error":"invalid_client"}\n` bytes. **Rev-2:** the bare T-9 client carries the same no-redirect pin (its own `CheckRedirect`) — asserted in `TestSweep_RedirectNotFollowed` |
| A8 exit nonzero gates | `TestExitCodes` (0/1/2 matrix: partial creds, expectation flags w/o creds, bad `--addr`); `TestSkippedChecksNoCredentials` (exit 0 + stderr notices); `TestStdoutDeterministic` (two-run byte equality + checked-in golden constant); **rev-2:** `TestCheck_AddrValidation`; `TestCheck_EnvAddrValidation` | 0/1/2 contract; skip ≠ failure; golden stdout; addr misuse (flag or env) is exit 2 with the value never echoed |
| — (closes the zero-test gap) | REQ-6: `TestDo_BearerHeader` (present with `WithToken`, absent without — env unset); `TestDo_JSONHeaders` (`Content-Type: application/json` + `Accept`); `TestNew_OptionEnvPrecedence`; `TestReadBody_CapAndClose` (1MB cap, body closed); **rev-2 amendment tests:** `TestWithNoRedirect_StopsFollowing`; `TestRedactURL_RedactsUserinfo`; `TestSanitizeBody_RedactsSensitiveFields`; `TestDiagnostics_NeverEchoSecrets`; `TestMint_RandReadFailure` | contract tests pin exactly the behaviors the sweep depends on, incl. the amendment surface (§4 Table B) |

Green-path sweep tests run against the real `sso.NewServer` (defaultimpl
memory stores, Ed25519 issuer, seeded client `demo/s` with
`AllowedScopes: ["read","write"]` — the same fixture as
`test/oidc_discovery_test.go`, whose non-empty allowlist also satisfies T-8d's
restricted-client precondition).

## 4. Failure-mode rows 1–25 → tests (rev 2)

Rev-1 verdict: 12/25 fully mapped, 8 gaps closed by six new tests + two
data-driven extensions. Rev-2 keeps that closure and adds the amendment
surface. All tests are stub-based where noted; every stub is an httptest
server, deterministic, no external services.

### Table A — design §5 rows 1–25 (rev-2 updates flagged)

| Row | Failure mode | Concrete test (criterion) |
|---|---|---|
| 1 | Discovery non-200 / undecodable / empty body | `TestSweep_DiscoveryFetchFail` (data-driven stub: 500, `not json`, empty body, **rev-2: 302** → exit 1, stderr names status/parse error; stderr goes through `redactURL` — no raw URL credentials ever) |
| 2 | Endpoint URL unparseable or non-http(s) scheme | **rev-2 (extended):** `TestSweep_AdvertisedURLRejection` — data-driven over `file:///x`, `%zz` (unparseable), **userinfo `https://u:p@h/token` (M-5)**, **relative `/token`**, **empty-host `http:///token`** → row failed-as-skipped, **zero requests sent** (asserted via recorded requests), stderr diagnostic shows the redacted URL (never `u:p`) |
| 3 | Advertised endpoint returns 404 (the T-2 truthiness failure) | `TestSweep_404RowFails` (stub advertises one 404 endpoint → exit 1, stderr `observed 404, expected non-404` with field+method+URL). **Rev-2:** 3xx on a truthiness row is NOT this failure — it passes (`TestSweep_3xxTruthinessPasses`) |
| 4 | Transport error (timeout, refused, TLS) | `TestSweep_TransportErrorRow` (stub `Close()`d listener → per-row error → exit 1, stderr `endpoint …: <err>`); **rev-2:** the echoed URL passes through `redactURL` — asserted in `TestDiagnostics_NeverEchoSecrets` (belt-and-braces even though preflight already rejects userinfo) |
| 5 | `token_endpoint` suffix ≠ `/token` | `TestSweep_TokenEndpointSuffix` (fail with observed vs expected suffix) |
| 6 | userinfo/end_session absent | `TestSweep_AdvertisedOnly` (not a failure; zero probes issued) |
| 7 | Mint non-200 / no `access_token` / malformed JWT | `TestMint_ResponseFail` (data-driven: 400; 200 w/o `access_token`; 2-part JWT; bad base64url → exit 1, stderr `mint: …`). **Rev-2 pin:** body echo only for non-2xx, truncated (~200B) and sanitized via `sanitizeBody`; the 200-with-missing-`access_token` branch (whose body *contains* the real token) never echoes the body, only the decode error — asserted in `TestMint_ResponseFail` + `TestDiagnostics_NeverEchoSecrets` |
| 8 | `refresh_token` in cc response | `TestMint_NoRefreshToken` (green-path negative) + stub variant in `TestMint_ResponseFail` (200 body carrying `refresh_token` → exit 1) |
| 9 | `kid` missing / not in JWKS | `TestClaimsMatrix_FailureDiagnostics` — one data-driven test over a stub-issued JWT per row: bad/absent kid, bad `typ`, wrong `iss`, wrong `sub`/`client_id`, missing requested `scope`, missing `aud` → each exits 1 with its row-specific stderr line. Six rows, one shared verification function — exactly the matrix shape design §4.2 mandates |
| 10 | `typ` ≠ `at+jwt` | (same data-driven test) |
| 11 | `iss` ≠ discovery issuer | (same) |
| 12 | `sub`/`client_id` ≠ `--client-id` | (same) |
| 13 | `scope` misses a requested `--scope` value | (same) |
| 14 | `aud` misses a `--resource` value | (same) |
| 15 | `tenant_id` absent / mismatch | `TestMint_TenantIDExpectation` (pos + neg) |
| 16 | `roles` absent under `--expect-roles` | `TestMint_RolesExpectationFailsOnCC` (documented deterministic failure) |
| 17 | Revoke non-200 | `TestRevoke_Non200Fails` (stub revoke 500 → exit 1, `revoke: status 500`) |
| 18 | Post-revoke introspect ≠ `active:false` | `TestRevoke_StillActiveFails` (stub introspect returns `active:true` after revoke → exit 1, `revoke: token still active`) |
| 19 | T-8d 400 wrong bytes | `TestInvalidScope_ExtraFieldFails`; **rev-2:** observed-body echo goes through `sanitizeBody` (`TestSanitizeBody_RedactsSensitiveFields`) |
| 20 | T-8d 200 (enforcement absent) | `TestInvalidScope_EnforcementAbsent` (enforcement-absent diagnostic; fail). Rev-2: the diagnostic stays body-less — a 200 there would carry a real token for the probe scope |
| 21 | T-8d wrong code | `TestInvalidScope_WrongCode` (`invalid_request` → fail with expected-vs-observed code) |
| 22 | T-9 status ≠ 401 or wrong body | `TestIntrospect_NoCreds401` / `TestIntrospect_200Fails` / `TestIntrospect_400Fails`; **rev-2:** body echo sanitized (same helper as row 19) |
| 23 | `SSO_ADMIN_TOKEN` exported during T-9 | `TestIntrospect_NoAuthHeaderLeak` (by construction + recorded request has no `Authorization`). **Rev-2 (design option):** if the design adopts the security review's stderr-notice suggestion ("`SSO_ADMIN_TOKEN` is set — the bearer rides to advertised hosts on T-2 GET rows"), extend this test to assert the notice line; if instead the T-2 GET rows are routed through bare clients, `TestSweep_GreenPath`/`TestSweep_AdvertisedOnly` gain a recorded-request no-bearer assertion. Either variant is mapped here; the design must pick one |
| 24 | Flag misuse | `TestExitCodes` (partial creds, expectation flags w/o creds → exit 2 + stderr usage); **rev-2 (extended):** `TestCheck_AddrValidation` + `TestCheck_EnvAddrValidation` — bad `--addr` **and** bad env `SSO_ADMIN_ADDR` are exit-2 misuse; the rejection message never echoes the value; the exit-2-on-bad-URL classification is a deliberate deviation from auditverify's exit-1-on-parse-error precedent (`readFromURL` → `errorf`), documented in §5 |
| 25 | No credentials supplied | `TestSkippedChecksNoCredentials` (exit 0; T-8a/T-8d skip notices on stderr; T-2 + T-9 still run). Note: reflects the design **as written**; if the design adopts CLI-conventions F-1 (no-creds → exit 2 or "incomplete" verdict), this test's criterion changes with it (see §5) |

### Table B — amendment-introduced failure modes (M-1..M-8)

| ID | Failure mode | Detection | Exit | Concrete test (criterion) |
|---|---|---|---|---|
| M-1 | Content row returns 3xx under the no-redirect pin: discovery, `jwks_uri`, mint, revoke, introspect-401, invalid_scope-400 all **fail** on any 3xx (no follow) | per-row status check | 1 | `TestSweep_3xxContentRowFails` — data-driven stub: discovery 302, jwks 302, mint 302, revoke 302, introspect 302, invalid_scope 302 → each exits 1 with the row-specific diagnostic (e.g. `discovery: GET … -> status 302; expected 200 + JSON object`); a 302 is reported as observed status, never followed |
| M-2 | Truthiness row (authorization_endpoint, token_endpoint, revocation_endpoint, userinfo, end_session) returns 3xx — **passes** ("non-404" without following; preserves A3 and the login-page 302 case) | per-row status check | 0 | `TestSweep_3xxTruthinessPasses` — credential-less run against a stub: discovery 200, jwks 200, introspection 401, and 302 on the five truthiness rows → exit 0; each 3xx endpoint is hit exactly once (recorded-request count == 1, no second hop). `TestSweep_RedirectNotFollowed` — stub endpoints 302/307 to a second httptest server; assert the target receives **zero** requests (covers the 307/308 method+body-forwarding exfiltration vector and the same-hostname bearer-forwarding vector in one assertion); `Location` values are never fetched |
| M-3 | `--addr` with userinfo, empty host, query, or fragment | preflight | 2 | `TestCheck_AddrValidation` — data-driven: `8443` (no scheme), `http://` (empty host), `http://user:pass@host` (userinfo), `https://host/path?x=1` (query), `https://host/path#f` (fragment), `file:///x`, `https://host:badport` → each exit 2, usage on stderr, **zero network requests**, rejection message never echoes the raw value; `http://127.0.0.1:<httptest port>/` passes preflight |
| M-4 | Bad `SSO_ADMIN_ADDR` env value — bypasses flag-only preflight and would produce five per-row transport failures (the exact failure mode §2.1 exists to prevent); env wins over `--addr` (apiclient.go:58-61) | preflight on effective addr | 2 | `TestCheck_EnvAddrValidation` — `t.Setenv("SSO_ADMIN_ADDR", "http://user:pass@host")` (no flag) → exit 2, zero requests; invalid env + valid `--addr` flag → exit 2 (env wins); valid env httptest URL + no flag → preflight passes and the discovery request lands on the env URL (asserts the sweep targets the env value); rejection message never echoes the value |
| M-5 | Advertised endpoint URL carries userinfo — Go's transport would auto-attach `Authorization: Basic` (attacker-chosen creds on the wire) | per-row URL preflight (row-2 extension) | 1 | `TestSweep_AdvertisedURLRejection` (extends `TestSweep_BadSchemeRow`): doc advertises `https://u:p@h/token` → row failed-as-skipped, **zero requests** (recorded), stderr shows `redactURL`-processed URL without `u:p` |
| M-6 | Redaction failure: any stderr diagnostic echoes a URL with credentials, a minted token, `access_token`/`refresh_token`/`id_token`/`client_secret` bodies, or a raw flag value | helper contract + integration | n/a (unit) / 1 (integration) | `TestRedactURL_RedactsUserinfo` (unit, package apiclient): `redactURL("https://user:pass@host/path?q=1")` → `https://host/path?q=1`; no-userinfo URL unchanged; unparseable string returned unchanged (diagnostics never crash). `TestSanitizeBody_RedactsSensitiveFields` (unit): JSON with `access_token`/`refresh_token`/`id_token`/`client_secret` fields → values replaced, other fields byte-preserved; non-JSON body passed through; >200B truncated with a marker. `TestDiagnostics_NeverEchoSecrets` (integration): failing run (`--client-secret TOPSECRET`, mint 500 with a body carrying `"access_token":"MINTED"`, a transport-error row) → stderr contains neither `TOPSECRET` nor `MINTED`; 200-with-missing-token branch prints only the decode error, never the body |
| M-7 | `WithNoRedirect` contract: the option stops redirect-following; absence preserves default following (existing subcommands' behavior untouched) | contract test | n/a | `TestWithNoRedirect_StopsFollowing` (apiclient_test.go): `New(WithAddr(ts.URL), WithNoRedirect())` → `Do` returns the 302 response as-is, redirect target (second httptest) records zero requests, body readable; `New(WithAddr(ts.URL))` without the option → follows (target receives the request) — pins that the amendment does not change existing callers; same-host 307 from the mint probe → target never receives the body carrying `client_secret` (exfiltration vector closed) |
| M-8 | Probe-scope generation failure — `crypto/rand` read error | preflight of T-8d scope | 1 | `TestMint_RandReadFailure` (package apiclient, white-box): swap `crypto/rand.Reader` with a failing reader (`t.Cleanup` restore) → exit 1, stderr names scope generation, **no /token probe request is sent** (recorded), and no fallback path exists — the implementation must call `io.ReadFull(crypto/rand.Reader, buf)` (returnable error), never `crypto/rand.Read` (crashes, never errors — verified rand.go) and never `math/rand` (amendment 4). The probe scope never appears on stdout or stderr in any test |

### Coverage verification — no 25-row entry and no acceptance lacks a mapped test

- **Rows 1–25:** every row of design §5 maps to ≥1 test (rows 1,2,4,7,9–14,17,18
  closed in rev 1; rows 2,7,19,22,23,24 extended in rev 2; rows 3,5,6,8,15,16,
  20,21,25 unchanged). Zero gaps.
- **Amendment rows M-1–M-8:** all mapped above. Zero gaps.
- **A1–A8:** all mapped in §3. Zero gaps.
- Rev-2 net new tests: `TestSweep_3xxContentRowFails`, `TestSweep_3xxTruthinessPasses`,
  `TestSweep_RedirectNotFollowed`, `TestCheck_AddrValidation`,
  `TestCheck_EnvAddrValidation`, `TestSweep_AdvertisedURLRejection`,
  `TestRedactURL_RedactsUserinfo`, `TestSanitizeBody_RedactsSensitiveFields`,
  `TestDiagnostics_NeverEchoSecrets`, `TestWithNoRedirect_StopsFollowing`,
  `TestMint_RandReadFailure` — plus data-driven extensions to
  `TestSweep_DiscoveryFetchFail` (302 case), `TestMint_ResponseFail` (body-echo
  pin), `TestSweep_BadSchemeRow` (folded into `TestSweep_AdvertisedURLRejection`),
  `TestExitCodes` (addr misuse), `TestIntrospect_NoAuthHeaderLeak` (notice
  variant per design decision).

## 5. Corrections to the design doc (rev 2)

Rev-1 corrections (A1 placement; testkit line numbers; `usageErr` symbol; `if`
nesting discipline) all stand. Rev-2 additions:

1. **§3.2/§3.3 — apiclient.go gains one additive option.** The security review's
   required amendment 1 (no-redirect pin) forces one change to the file the
   requirements marked "do not modify": `func WithNoRedirect() Option` setting
   `c.http.CheckRedirect = func(*http.Request, []*http.Request) error { return
   http.ErrUseLastResponse }` (~4 lines; applied by the existing option loop
   `apiclient.go:53-56`, zero changes to `New`). §3.3's "untouched" claim
   narrows to `Do/Get/Post/ReadBody/New`. The bare T-9 client gets the same pin
   inline. REQ-6 gains the `TestWithNoRedirect_StopsFollowing` contract test.
2. **§2.1 — `--addr` validation extends to the effective addr.** `apiclient.New`
   applies `SSO_ADMIN_ADDR` after `WithAddr` (env wins, apiclient.go:58-61), so
   flag-only preflight is half-honored: the env-sourced value must be validated
   in `CheckRun` (read `apiclient.EnvAddr`), and rejection messages must never
   echo the value. Validation set: absolute URL, http(s) scheme, non-empty
   Host, no userinfo, no query/fragment (M-3/M-4). Exit-2-for-bad-URL is a
   deliberate deviation from auditverify's exit-1-on-parse-error precedent and
   should be stated as such in §5 row 24.
3. **§2.2 — crypto/rand pin corrected.** Implementation must use
   `io.ReadFull(crypto/rand.Reader, buf)`; `crypto/rand.Read` never returns an
   error (crashes instead — rand.go), so it cannot satisfy "failure → exit 1".
   Failure → exit 1 with stderr diagnostic; no `math/rand` fallback; scope
   never printed (M-8).
4. **§5 — rows 2 and 24 extended; new rows M-1..M-8.** Row 2 gains
   userinfo/relative/empty-host advertised URLs (failed-as-skipped, zero
   requests, redacted diagnostics); row 24 gains the effective-addr cases;
   new rows for content-row 3xx (fail), truthiness-row 3xx (pass, no follow),
   and the redaction contract. Row 23's `SSO_ADMIN_TOKEN` handling gets one of
   the two mapped variants (stderr notice, or bare-client T-2 GET rows) — the
   design must pick one.
5. **F-1/F-2 are design decisions with mapped tests either way.** The mapping
   reflects the design as written: row 25 = exit 0 + skip notices
   (`TestSkippedChecksNoCredentials`), `-h` = exit 0
   (`TestCheck_HelpExitsZero` pins the deliberate `ErrHelp` → 0 special-case
   under `ContinueOnError`, the tree's first). If the design adopts F-1
   (credential-less run → exit 2 misuse, or exit 1 with an "incomplete"
   verdict and no `check OK` line), the row-25/A8 criteria change with it —
   the tests are written so only the expected-value constants move.
