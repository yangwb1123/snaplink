# Design: Input-harden entity ID interpolation and add the admin-entity leg to the deploy-tree sweep

Design for the direction "Input-harden entity ID interpolation and add the
admin-entity leg to the deploy-tree sweep (B4-3 truthiness + B4-4 hardening)",
built from the requirements spec
[`cmd-sso-ctl-entitiescmd-requirements.md`](cmd-sso-ctl-entitiescmd-requirements.md)
and an independent re-verification of every load-bearing claim against the
working tree (commit `61b81c89` + uncommitted sweep work).

Module: `cmd/sso-ctl/entitiescmd` (composition layer) plus the sweep surface it
drives, `cmd/sso-ctl/apiclient`. Server behavior is verified, not changed.

## 1. Verification outcome — the evidence was checked, not trusted

### 1.1 Claims confirmed with exact lines (substance, not just existence)

| Claim | Verdict on the working tree |
|---|---|
| `tenants.go` guards only `len(args) < 1 \|\| args[0] == ""` before splicing `args[0]` into `/api/v1/admin/tenants/`+id | **Confirmed.** Guard/splice: get :136/:141, update :175/:180, delete :199/:204, set-status :224/:229. Evidence cited :135/174/198/223 — off by one on the guard line, substance exact. |
| `users.go:145` `runUserGet` same pattern; `runUserUpdate`/`runUserDelete` splice identically | **Confirmed (superset).** get :146/:151, update :182/:187, delete :206/:211. All seven sites share one shape; the create paths carry ids in the request body only. |
| `attrFlag` malformed-pair rejection | **Confirmed, line drift disclosed by the evidence.** users.go:40-49; the requirements spec's :88-98 range is stale. |
| `validateTenantStatus` at tenants.go:248 | **Confirmed, drift 5:** actual :243, before any request. |
| `build_http.go` "`{id}` also catches `{id}:set-status`" | **Confirmed.** Comment at :190-192; full rationale :118-141; `runtime.NewServeMux()` with no custom error handler at :228. Routing test pins `/api/v1/admin/tenants/t1:set-status` (admin_gateway_routing_test.go:141). |
| ZERO `admin/tenants`/`admin/users` probes in the sweep | **Confirmed by grep** — no matches in `cmd/sso-ctl/apiclient/*.go`. |
| `token.go:211-233` `verifyClaims` asserts tenant_id/roles | **Confirmed.** `verifyTenantID` :227-235 ("claims: tenant_id absent" / `tenant_id %q != %q`), `verifyRolesClaims` :247+. |
| `error-codes.md:298` `invalid_scope` registry gate | **Confirmed, exact line.** |
| `issue_payload.go:46,83-87` B4-1 claims | **Confirmed, path drift disclosed:** `infrastructure/defaultimpl/issue_payload.go`; `TenantID: subject.TenantID` :46; Roles copy under the non-empty guard :86-90. |
| `RejectUnregistered`; `config_load.go:220` | **Confirmed, path drift not disclosed:** the file is `protocols/oauth/scoperegistry/reject.go:31` (evidence said `scoperegistry/reject.go`) and `config/config_load.go:220` (`validateScopeRegistry()`). |
| Suspension gate in `validateAnyToken` at server_token_clientauth.go:400 | **Confirmed, exact line.** The full chain introspect → `introspectOne` → `resolveIntrospection` → `ValidateAnyToken` (introspect_cache.go:169) → `checkTenantNotSuspended` → `{active:false}` (introspect_cache.go:130-131) is wired. `DefaultIntrospectionCacheTTL` = 60s; `DefaultTenantSuspensionCacheTTL` = 30s. |
| `tenant.suspension_check` wiring | **Confirmed:** `cfg.Tenant.SuspensionCheck.Enabled` at cmd/sso-server/build_app_oauth.go:100; config struct config_geo_tenant.go:258-264. Doc citation `config-reference.md:393` covers `tenant.suspension_check.cache_ttl`; the `enabled` key is documented in code, not the table — minor, non-blocking. |
| Unknown-id set-status → `codes.NotFound "tenant not found"`; unmounted store → 400 `"tenant store not configured"` | **Confirmed.** admin_tenants.go:318-320 / :327-329. The flip path (:344-355) does `recordAdmin` + `invalidateSuspensionCache` + `revokeTenantTokens` on a real transition to Suspended; the invalidation callback is wired to `a.server.InvalidateTenantSuspensionCache` (build_http.go:456), so an immediate post-flip introspect is not masked by the 30s suspension cache. |
| No introspection-wire suspension test exists | **Confirmed.** test/tenant_suspension_test.go asserts `ValidateToken` errors only; test/handle_introspect_test.go has no suspension case; the e2e suite only GETs `/api/v1/admin/tenants` (admin_gateway_routing_e2e_test.go:162). |
| OpenAPI set-status entry documents only 200/401 | **Confirmed.** :7847-7872; no 404 row (the tenants/{id} rows carry `tenant_not_found` at :6865). |
| `tenant.Validate` imposes no id charset | **Confirmed.** domains/tenant/tenant.go:137-143: non-empty id and slug only. |
| Threat-model routes: `PathTenantUsage` at server_routes_admin.go:88; users sub-surfaces router-owned (build_http.go:211-215); custom verb in tenants.proto:41-47 | **Confirmed.** |
| Admin client API `tenant_id` read-only | **Confirmed.** admin_clients.go:409 "Read-only projection of the stored binding", :422 "binding is established at registration time". The cc grant stamps `Subject.TenantID = client.TenantID` (internal/handler/tokengrant/token_client_credentials.go:52), so a tenant-bound client's minted token carries `tenant_id` — probe (b)'s approach works. |
| No-redirect predecessor shipped; suite green | **Confirmed.** `apiclient.New(apiclient.WithNoRedirect())` at tenants.go:254/275/298 (evidence cited :253/274/297 — off by one). `go test ./cmd/sso-ctl/entitiescmd/` green; 20 test funcs = 16 mock-admin + 4 no-redirect. |
| Pre-existing failures: `TestIntrospect_Non401Fails` (trace_id fixture); `check` missing from main.go dispatch | **Confirmed.** check_test.go:1347; the `wrong-bytes` case carries `"trace_id":"x"` in the mock body, which the byte-identity assertion rejects. main.go's subcommands map (:56-61) has `config`/`tenants`/`users` but no `check`. |
| Pipeline artifact + fingerprint | **Confirmed.** `runs/input-harden-entity-id-interpolation-and-add-the-077a1671/artifacts/requirements-10762e10/requirements.md` + `.meta.json` (sha256 `6cd75866…`). |

### 1.2 Material discrepancy found — the sweep suite is red far beyond the disclosed baseline

The evidence's §1.7 discloses exactly one failing apiclient test. The current
tree has **13 failing tests in 6 failure classes** (run on 2026-08-08, files
predate the requirements doc's mtime, so the failures predate the evidence):

1. **Live-server fixture issuer mismatch (10 tests)** — `newLiveServer`
   (check_test.go:79-93) sets `sso.WithIssuer(addr)` (discovery) but the
   Ed25519 issuer keeps its package default `sso.DefaultIssuer` =
   `"snaplink-sso"` (`buildAccessPayload(j.issuer, ...)`,
   ed25519_issue.go:43). T-8a's unconditional iss assertion
   (token.go:188-190) fails: `iss "snaplink-sso" != discovery issuer
   "http://127.0.0.1:PORT"`. Tests: `TestMint_ClaimsMatrix`,
   `TestMint_ScopeContainsRequested`, `TestMint_AudContainsResource`,
   `TestMint_RolesConditional`, `TestMint_ExpectNoRoles`,
   `TestRevoke_RoundTrip`, `TestSweep_GreenPath`, `TestStdoutDeterministic`,
   `TestSweep_TokenEndpointSuffix`, `TestSweep_AdvertisedURLRejection`.
   Fix: one line — `defaultimpl.NewEd25519JWTIssuer(WithEd25519Issuer(addr),
   WithEd25519TokenTTL(...))` in the fixture.
2. **`TestCheck_AddrValidation` (no-scheme, empty-host)** — the "stderr must
   not echo the raw addr" assertion is a false positive: the usage banner's
   default value `http://127.0.0.1:8443` contains the substrings `8443` and
   `http://`. Test expectation bug, not a code bug.
3. **`TestSweep_AdvertisedURLRejection` (file-scheme, userinfo, relative,
   empty-host)** — expects row-2 diagnostics `"scheme must be http or
   https"`/`"must not embed credentials"`, but for base-concatenated malformed
   advertised URLs `validateAdvertisedURL` returns `"not a valid absolute
   URL"`, and the sweep then continues to mint against the bad URL, adding
   secondary `invalid port` diagnostics. Expectation/diagnostic mismatch.
4. **`TestMint_ResponseFail/status-400`** — the test case is mislabeled: it
   sends the body `{"error":"invalid_request"}` with HTTP **200** (only the
   `redirect-302` case overrides the status variable), so the sweep correctly
   prints `"mint: response has no access_token"` while the case expects
   `"mint: status 400"`. The sweep's status check exists (token.go:84-89) and
   is pinned by the passing `redirect-302` case; the fix is the test case
   sending a real 400.

Root gate suite is also red on the tree, for unrelated reasons (verified,
pre-existing): `TestArchitecture_DirectoryDepth` (700 dirs — the campaign's
own `docs/architect-analysis/auto/runs/...` artifacts), `TestArchitecture_
DirectorySubdirFanout` (root 24 > frozen 21; docs tree), `TestMaintainability_
FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539
lines). `go build ./...` and `go vet ./...` are green.

**Design consequence:** REQ-2's A9 ("no-flag runs byte-identical to HEAD, the
existing golden runs pass unchanged") is not evaluable while
`TestSweep_GreenPath`/`TestStdoutDeterministic` are red for the fixture
reason — a red suite cannot distinguish "byte-identical" from "still red".
The fixture repair (1.2.1) is therefore a **mandatory prerequisite commit**:
one line in `newLiveServer`, no behavior change, makes 10 tests green and
restores the compatibility baseline the opt-in design depends on. The other
three classes (1.2.2-1.2.4) are separate pre-existing test bugs: fix them in
the same prerequisite commit if cheap (each is a test-only expectation
correction), or defer explicitly with this document cited; they must not be
silently absorbed into the feature commit.

## 2. Design summary

Three layers, all server-wire-neutral:

1. **CLI boundary (REQ-1):** one `validEntityID` predicate in `entitiescmd`
   guards all seven path-interpolating sites. Hazard ids never leave the
   process; exit 2, no request, no usage dump.
2. **Sweep truthiness (REQ-2):** opt-in `sso-ctl check --admin-entities`
   group T-8f probing the two documented server contracts the entity admin
   surface owns: 404 `tenant not found` on unknown-id set-status, and
   `{"active":false}` introspection after a real suspend flip.
3. **Composed-gateway regression (REQ-3) + doc closure (REQ-4):** e2e pins
   of both contracts through the real admin gateway and `/token/introspect`
   wire; one OpenAPI 404 row added to the set-status entry.

## 3. API changes

### 3.1 `sso-ctl tenants` / `sso-ctl users` (behavioral, CLI-only)

No flag, no wire change. New local validation: an id containing `:`, `/`, or
`?` fails with exit 2 before any flag parsing, `--yes` gate, client
construction, or request:

```
sso-ctl tenants: invalid tenant id "acme:set-status": must not contain ':', '/', or '?'
sso-ctl users: invalid user id "u1/x": must not contain ':', '/', or '?'
```

- The id is echoed with `%q` on stderr only; it never appears in a URL.
- Only the three hazard characters are rejected; no charset allowlist is
  invented (server `tenant.Validate` accepts any non-empty id — the CLI is
  not inventing a server contract).
- Create paths are out of scope: ids travel in the request body.
- Exit code 2, no usage dump — mirrors `TestRunTenants_DeleteRefusesWithoutYes`
  (tenants_test.go:294-310).

Placement: `validEntityID` in tenants.go next to `validateTenantStatus` (:243),
`strings.ContainsAny`; tenants.go gains the `strings` import (users.go already
has it). Package-scoped, so both files use it.

### 3.2 `sso-ctl check` (additive CLI surface)

New optional flag `--admin-entities`; new probe group T-8f:

```
T-8f  Admin-entity truthiness (opt-in): unknown-id tenant set-status yields
      the documented 404 "tenant not found"; suspending a tenant makes a
      previously minted token introspect {"active":false}. Requires
      SSO_ADMIN_TOKEN.
```

- `parseCheckConfig` (check.go:109): add the flag. When set and
  `os.Getenv(EnvToken)` empty → exit 2 + usage (mirror the missing-credentials
  misuse rule). When unset → T-8f does not run; the sweep is byte-identical
  to HEAD.
- `CheckRun` (check.go:71-104): run T-8f after T-9; wire `ok/skipped` into the
  existing INCOMPLETE/FAIL plumbing exactly like `runT8d`.
- New file `cmd/sso-ctl/apiclient/admin_entities.go` (token.go is at 478/500 —
  the 500-line budget is load-bearing): `runT8f` orchestrated as ≤50-line
  helpers `t8fProbeUnknownID` and `t8fProbeSuspension` (cyclomatic gate).
  Non-test file count in apiclient goes 5 → 6, under the 10/directory budget;
  no new package, no layer classification change.
- Update the coverage header (check.go:6-31) and `usage()` (:162).

**Probe (a) — unknown-id set-status.** `id := probeScope()` (existing
crypto/rand generator, check.go:300; `sweep-probe-` prefix + 12 alphanumerics
makes collision with a real tenant effectively impossible). `POST ck.base +
"/api/v1/admin/tenants/" + id + ":set-status"` with `{"status":"suspended"}`
through `ck.client` (New(WithAddr(base), WithNoRedirect()) — inherits
`SSO_ADMIN_TOKEN` via the env fallback, apiclient.go:44-47). Assert:

- 404 with parsed `message == "tenant not found"` (and `code == 5` when
  present) → group OK.
- 400 with `message == "tenant store not configured"` → group SKIPPED with a
  diagnostic ("entity-admin surface not mounted"); per the sweep contract the
  run prints `check INCOMPLETE`, exit 1.
- Anything else → FAIL with a diagnostic naming the observed status/body
  (redactURL/sanitizeBody only).

**Probe (b) — suspension truthiness (conditional sub-leg).** Mint a fresh
client-credentials token for `--client-id`/`--client-secret` via `probeClient`
(body credentials only — a bearer Authorization header makes /token reject the
request outright, token.go:401-417; `probeClient` is structurally
bearer-less). Parse claims with the T-8a machinery (token.go:171-218) and read
`tenant_id`:

- Empty → sub-leg SKIPPED with a diagnostic ("minted token carries no
  tenant_id — client not tenant-bound; declare --expect-tenant-id to make this
  leg runnable"); INCOMPLETE per contract.
- Otherwise, in this exact order:
  1. stderr warning: suspending tenant `<id>` fires the server's irreversible
     refresh-token/session revocation for that tenant (admin_tenants.go:344-
     355); then `POST .../tenants/{id}:set-status` `{"status":"suspended"}` →
     expect 200.
  2. `POST` the advertised `introspection_endpoint` with the minted token +
     client credentials → expect 200 and parsed `active == false` (mirror the
     post-revoke assertion style, token.go:333-338; not byte-identical).
  3. `POST .../tenants/{id}:set-status` `{"status":"active"}` → expect 200
     (restore).

Never introspect the minted token before the suspend: the introspection cache
(60s default) would mask the flip. The `{id}` is the minted token's OWN
`tenant_id` — the only tenant the operator's bearer is authorized to flip.

### 3.3 Server: no wire changes

- `POST /api/v1/admin/tenants/{id}:set-status` behavior is verified existing
  contract: 404 `tenant not found` on unknown ids, 200 on real flips, 400
  `tenant store not configured` when unmounted, cache invalidation + token
  revocation on the Suspended transition. T-8f and the e2e tests assert it;
  `build_http.go` routing is a test target, not a change target.
- OpenAPI (REQ-4): add the missing 404 row to the set-status entry
  (docs/openapi.yaml:7847-7872): `"404": { description: 'tenant_not_found',
  content: ErrorResponse }`, mirroring the tenants/{id} rows (:6865).
  Validate with `python cli.py docs-check`. No proto/message changes, so
  proto-openapi parity is unaffected.

## 4. Compatibility constraints

1. **No flag → byte-identical to HEAD.** This is the hard constraint that
   forces opt-in: the sweep's tests clear `SSO_ADMIN_TOKEN` (check_test.go:37-
   41) and golden runs assert `check OK` + exit 0 with no admin credential
   (:32, :475-488). A default-on T-8f would flip every token-less run to
   INCOMPLETE/exit 1. Constraint survives even though the golden runs are
   currently red for the fixture reason (see 1.2) — the prerequisite repair
   restores the evaluable baseline.
2. **Flag without `SSO_ADMIN_TOKEN` → exit 2 misuse**, before any request.
3. **Exit contract unchanged** for existing groups: 0 all-passed; 1 any
   failure or any skipped group (`check INCOMPLETE`); 2 misuse. T-8f
   participates via the existing plumbing.
4. **No new config knob, no new `Err*`, no storage change.**
   `tenant.suspension_check.enabled` already exists and is documented
   (config_geo_tenant.go:258; config-reference.md:393 covers cache_ttl).
   error-codes.md untouched (`tenant_not_found` is an OpenAPI-documented
   google.rpc status, not an `Err*`).
5. **Server wire contracts untouched** — every assertion in REQ-2/REQ-3 pins
   verified existing behavior; the only contract-doc delta is the OpenAPI 404
   row.
6. **Budget headroom verified:** tenants.go 332 → ~355, users.go 228 → ~240
   (both under 500); apiclient non-test files 5 → 6 (under 10); no new
   package; `interfaces/sso` untouched (its 60-file ceiling is not involved).

## 5. Failure modes

| Surface | Failure | Behavior |
|---|---|---|
| REQ-1 guard | Id contains `:`, `/`, `?` | Exit 2, stderr `%q` diagnostic, zero requests. Id is operator-supplied path data; never echoed into a URL. |
| REQ-1 guard | Id empty / missing | Existing empty-string check unchanged (exit 2 + usage). |
| Probe (a) | 404 `tenant not found` | OK — the documented contract. |
| Probe (a) | 400 `tenant store not configured` | SKIPPED + diagnostic; `check INCOMPLETE`, exit 1 (documented skip contract, check.go:27-31). |
| Probe (a) | Other status/body (e.g. 401, 404 with different body, 500) | FAIL, diagnostic names the observed status; a truthful "admin REST surface not mounted or set-status routing broken" finding — same semantics as T-8d's enforcement-absence handling. |
| Probe (b) | Minted token carries no `tenant_id` | Sub-leg SKIPPED + diagnostic; INCOMPLETE, exit 1. |
| Probe (b) | `SSO_ADMIN_TOKEN` set but operator's client not tenant-bound | Same skip — the sweep never flips a tenant it cannot prove it owns. |
| Probe (b) | Suspend → non-200 | FAIL naming the step; tenant state unknown — the sweep does NOT attempt restore (restore could itself fail and would flip an unknown state). stderr warning precedes the flip so the operator accepted the side effect. |
| Probe (b) | Introspect returns `{"active":true}` after a 200 suspend | FAIL — "suspension not enforced on already-issued bearers" (trees without `tenant.suspension_check.enabled` land here; truthful, consistent with T-8d semantics). |
| Probe (b) | Restore → non-200 | FAIL naming the restore step; the tenant stays suspended (operator intervention required). The probe's own warning covered this. |
| Probe (b) | Introspection cache would mask the flip | Prevented structurally: the minted token is never introspected before the suspend, and the admin flip invalidates the server's suspension cache synchronously (build_http.go:456). |
| Probe (b) | Irreversible revocation side effect | Documented, warned on stderr before the flip, opt-in flag; restoration reactivates the tenant but cannot resurrect revoked refresh tokens/sessions. |
| `--admin-entities` without token | CLI misuse | Exit 2 + usage before any request. |
| A10/A11 e2e | Memory tenant store unmounted in a future config drift | A10 would return 400 → the e2e assertion fails loudly; A11's seed requires `Tenant.Enabled` + `Backend: "memory"` (build_app_oauth.go:27) which `fullFeatureConfig` already sets (:182-184). |
| Skip vs fail | Unmounted surface vs broken surface | Distinct: 400 store-not-configured is the documented unmounted signal (FailedPrecondition, admin_tenants.go:318-320); everything else fails. This prevents a broken deployment from being masked as a skip. |

## 6. Migration steps

- **Operators:** none for config/storage. Behavior change to document in the
  next release notes: `sso-ctl tenants|users get|update|delete|set-status`
  with an id containing `:`, `/`, or `?` now exits 2 locally instead of
  issuing a request against a different resource. Any script that today
  (mis)uses such ids must fix the id; scripts with well-formed ids are
  unaffected. The new `check --admin-entities` flag is additive; existing
  `check` invocations are byte-identical.
- **Rollout:** two commits.
  1. Prerequisite (test-only): repair `newLiveServer`'s issuer wiring
     (`WithEd25519Issuer(addr)`) so the sweep's own golden baseline is green
     (10 tests); correct the three disclosed expectation-level test bugs
     (1.2.2-1.2.4) or explicitly defer them with this document cited.
  2. Feature: REQ-1 tables + predicate, REQ-2 group + flag + file, REQ-3 e2e
     cases, REQ-4 OpenAPI row.
- **No data migration, no config migration, no storage change, no server
  rollout.** The server half of the acceptance is already shipped behavior.
- **Doc deltas in the same change:** OpenAPI set-status 404 row (A12);
  usage()/coverage header T-8f rows. `docs/error-codes.md` untouched.

## 7. Testable acceptance mapping

Requirements A1-A13 are preserved; each maps to a concrete test with a
pre-fix red proof where the requirements demand it. Baseline prerequisites
B1-B3 are new, forced by the verification findings.

| ID | Criterion | Test | Pre-fix proof |
|---|---|---|---|
| A1 | tenants get/update/delete/set-status × `:`,`/`,`?` (12 cases): exit 2, mock `called == false` | Table in tenants_test.go using `withMockAdmin` (:15-21) and the `DeleteRefusesWithoutYes` shape (:294-310); `--yes` passed for delete, valid status for set-status | Red today: `get "acme?x"` exits 0 and fetches `acme`; `delete "acme/x" --yes` exits 1 after a wire round trip |
| A2 | users get/update/delete × 3 chars (9 cases): exit 2, no request | Same table in users_test.go | Red today (same mechanics) |
| A3 | Positive control: clean ids still reach the mock, exit 0; full entitiescmd suite green | Existing `GetNotFound`/`SetStatus` tests + `go test ./cmd/sso-ctl/entitiescmd/ -count=1` | N/A (gate) |
| A4 | `--admin-entities` without `SSO_ADMIN_TOKEN` → exit 2, zero stub requests, usage on stderr | check_test.go `TestExitCodes` misuse row + stubCheck fixture (:96-150) | Red today: no flag exists |
| A5 | Probe (a) green: stub answers 404 `{"code":5,"message":"tenant not found","details":[]}` on the sweep-probe path; suspension stubs wired; exit 0, stdout contains `entity admin: OK` | Stub-driven test in check_test.go | Red today |
| A6 | Unmounted surface: stub answers 400 `{"code":9,"message":"tenant store not configured","details":[]}` → skipped, `check INCOMPLETE`, exit 1 | Stub-driven | Red today |
| A7 | Suspension leg green: stub `/token` mints a locally-signed JWT carrying `tenant_id` (defaultimpl issuer precedent, check_test.go:67-90); set-status 200; introspect `{"active":false}`; exit 0; stderr warning names the tenant | Stub-driven | Red today |
| A8 | Suspension not enforced: introspect `{"active":true}` after 200 suspend → FAIL, exit 1, diagnostic names the introspect step | Stub-driven | Red today |
| A9 | No-flag byte-identity: `TestSweep_GreenPath`, `TestExitCodes`, `TestStdoutDeterministic` pass unchanged with `EnvToken` cleared; stdout equals `goldenGreenStdout` | Existing golden tests | **Blocked until B1** (currently red for the fixture iss mismatch — the undisclosed baseline finding) |
| A10 | Composed gateway: admin bearer + `POST /api/v1/admin/tenants/sweep-probe-e2e:set-status` `{"status":"suspended"}` → 404, body contains `"tenant not found"` | admin_gateway_routing_e2e_test.go via `buildAdminGatewayE2EServer` (:102) + `adminAuthedRequest` (:122) | Red today: no set-status e2e case (suite GETs only, :162) |
| A11 | Wire truthiness: seed confidential client `TenantID:"t1"`, `Active`, `TokenStrategy:"jwt"`, `AllowedScopes:["read"]` via `cfg.Clients` (seedClients maps TenantID, build_app_core.go:79-100; t1 seeded at build_app_coverage_test.go:184); `cfg.Tenant.SuspensionCheck.Enabled = true` (precedent :273); real `POST /token` cc mint; suspend t1 → 200; `POST /token/introspect` → 200 `"active":false`; restore → 200 | e2e test; minted token's `tenant_id` comes from the client binding (token_client_credentials.go:52) | Red today: no introspect-wire suspension test anywhere (test/tenant_suspension_test.go asserts ValidateToken only) |
| A12 | OpenAPI set-status entry gains the 404 `tenant_not_found` row; `python cli.py docs-check` green | kin-openapi validation | Red today: entry at :7847 documents only 200/401 |
| A13 | `go build ./... && go vet ./...` clean; `TestMaintainability_\|TestArchitecture_` delta-free (no new packages, no import-direction change); touched suites green; no new `Err*`, no config knob | Gates | Root gates currently red pre-existing (campaign docs depth/fanout, ed25519_jwt_issuer.go 539 lines) — must be reported separately, not absorbed |
| **B1** | `newLiveServer` mints tokens whose `iss` equals the discovery issuer: add `WithEd25519Issuer(addr)` to the fixture | 10 mint/sweep tests green | Red today: `iss "snaplink-sso" != discovery issuer` |
| **B2** | `TestCheck_AddrValidation` no-scheme/empty-host: assert non-echo of the *input* without colliding with the usage banner's default `http://127.0.0.1:8443` (e.g. assert the raw addr is absent from the *diagnostic line* rather than the whole stderr, or drop the substring check for these two shapes) | Test-only fix | Red today: false positive |
| **B3** | `TestSweep_AdvertisedURLRejection` row-2 diagnostics and `TestMint_ResponseFail/status-400`: align expectations with the actual sweep diagnostics ("not a valid absolute URL" for base-concatenated malformed URLs; make the status-400 case send a real 400 — the sweep's status check is already correct, pinned by the passing redirect-302 case) | Test-only fix or explicit deferral | Red today |

## 8. Files

### Prerequisite commit (test-only)

```text
cmd/sso-ctl/apiclient/check_test.go — newLiveServer: WithEd25519Issuer(addr) (+
                                     WithEd25519TokenTTL(time.Minute) as today);
                                     B2/B3 expectation corrections (or defer)
```

### Feature commit

```text
Modify:
  cmd/sso-ctl/entitiescmd/tenants.go      — validEntityID (next to :243); guards at
                                           :137, :176, :200, :225; strings import
  cmd/sso-ctl/entitiescmd/users.go        — guards at :147, :183, :207
  cmd/sso-ctl/entitiescmd/tenants_test.go — A1 table (12 cases), A3 gate
  cmd/sso-ctl/entitiescmd/users_test.go   — A2 table (9 cases)
  cmd/sso-ctl/apiclient/check.go          — --admin-entities flag + misuse rule;
                                           header (:6-31) T-8f row; usage(); CheckRun
                                           wiring after T-9 (:97-98)
  cmd/sso-ctl/apiclient/check_test.go     — A4-A9 (T-8f stub tests; TestExitCodes row)
  cmd/sso-server/admin_gateway_routing_e2e_test.go — A10, A11
  docs/openapi.yaml                       — 404 tenant_not_found row on set-status
                                           entry (:7847-7872)
Add:
  cmd/sso-ctl/apiclient/admin_entities.go — runT8f + t8fProbeUnknownID +
                                           t8fProbeSuspension (≤50-line helpers)
Do not modify:
  cmd/sso-ctl/entitiescmd/tenants.go:254/275/298 — no-redirect pin (shipped)
  cmd/sso-ctl/apiclient/token.go   — at 478/500; new code goes in admin_entities.go
  cmd/sso-server/build_http.go     — gateway routing is the asserted contract
  docs/error-codes.md, docs/config-reference.md — no new Err*/knob
  cmd/sso-ctl/main.go              — missing `check` dispatch is a pre-existing gap;
                                     report separately, do not fold into this change
```

## 9. Open decisions

1. **B3 semantics:** `TestMint_ResponseFail/status-400` is a test bug, not a
   sweep bug — the case sends HTTP 200 with an error body while expecting the
   400 diagnostic; the sweep's status check exists (token.go:84-89) and is
   pinned by the passing `redirect-302` case. Fix the case to send a real
   400. For `TestSweep_AdvertisedURLRejection`, decide whether the row-2
   diagnostic should name the specific rule ("scheme must be http or
   https") — which requires `validateAdvertisedURL` to classify the failure —
   or the test should accept the generic "not a valid absolute URL" for
   base-concatenated malformed values. The sweep-side behavior (validate,
   fail the row, and do NOT continue probing with the bad URL) is the
   substantive fix if the continued mint attempts are judged wrong; pin one
   behavior in the prerequisite commit.
2. **B2/B3 deferral:** if the prerequisite commit is kept strictly to the
   fixture line, the three expectation bugs must be documented in the commit
   message with this design cited, per AGENTS.md's report-separately rule.
3. **`--admin-entities` naming:** the flag gates a group that both probes
   admin endpoints AND flips tenant state; `--admin-entities` matches the
   acceptance's wording ("new sweep group (T-8f ...)"). Keep it.
4. **A11 client seed:** `fullFeatureConfig` already seeds connection `c1`
   (TenantID t1) — that is a connection, not an OAuth client; A11 adds its own
   `cfg.Clients` seed (confidential, with secret) as the requirements
   specify. No conflict with the connection seed.
