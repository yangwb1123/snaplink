# Requirements: Input-harden entity ID interpolation and add the admin-entity leg to the deploy-tree sweep (B4-3 truthiness + B4-4 hardening)

Requirements specification for the selected direction "Input-harden entity ID
interpolation and add the admin-entity leg to the deploy-tree sweep (B4-3
truthiness + B4-4 hardening)". Doc-only artifact; no `.go` edits, so no build
gates are triggered by this file.

Module: `cmd/sso-ctl/entitiescmd` (composition layer) plus the sweep surface it
drives, `cmd/sso-ctl/apiclient`. Source analysis:
`docs/architect-analysis/auto/analyses/cmd-sso-ctl-entitiescmd-631f0c1d.json`,
direction 3. Every citation was re-checked against the working tree; the
supplied acceptance is preserved verbatim in section 3 and made testable.

## 1. Verification outcome — citations checked against the repository

| Citation | Verdict |
|---|---|
| `tenants.go:135,174,198,223` — `runTenantGet`/`runTenantUpdate`/`runTenantDelete`/`runTenantSetStatus` splice `args[0]` into `/api/v1/admin/tenants/`+id | **Verified, exact lines** — :135, :174, :198, :223. All four guard only `len(args) < 1 \|\| args[0] == ""` before interpolating the id into the path and calling `fetchOne`/`doWrite`. |
| `users.go:145` — `runUserGet` same pattern | **Verified, exact line** — :145. **Correction (superset):** `runUserUpdate` (:181) and `runUserDelete` (:205) splice `args[0]` identically; the direction names only `runUserGet`, but the acceptance's wording ("RunTenants/RunUsers reject ids") covers all id-bearing subcommands. REQ-1 hardens all seven sites with one shared predicate. |
| "only an empty-string check exists" | **Verified** — every site's guard is exactly `len(args) < 1 \|\| args[0] == ""`; no charset/character check anywhere in the module. |
| Module's own fail-fast patterns — `attrFlag` malformed-pair rejection (`users.go:88-98`) | **Verified, line drift** — `attrFlag.Set` rejecting a missing `=` is at users.go:40-49 (the :88-98 range is stale). Substance confirmed: a malformed `--attr` fails at parse time, exit 2, no request. |
| `validateTenantStatus` (`tenants.go:248`) | **Verified, line drift 5** — actual :243. Substance confirmed: status is validated before any request. |
| `cmd/sso-server/build_http.go:191-193` — "`{id}` also catches `{id}:set-status`" | **Verified** — comment at :190-192 with the full rationale at :118-141 ("grpc-gateway's custom-verb shapes ... colon-suffix GLUED to the SAME wildcard segment ... Go's ServeMux treats a colon as ordinary segment text"); the routing test pins `/api/v1/admin/tenants/t1:set-status` (admin_gateway_routing_test.go:141). The custom-verb collision is real and reachable. |
| `check.go:9-19` — coverage header lists T-2/T-8a/T-8d/T-9 only | **Verified** — header at check.go:6-31 documents exactly T-2, T-8a, T-8d, T-9. |
| "ZERO probes of /api/v1/admin/tenants or /api/v1/admin/users" | **Verified by grep** — zero matches for `admin/tenants`/`admin/users` in `cmd/sso-ctl/apiclient/*.go` (the only repo matches outside entitiescmd/tui are cmd/sso-server routing docs and tests). |
| `token.go:211-233` — `verifyClaims` asserts tenant_id/roles | **Verified** — `verifyTenantID` at token.go:216-232 ("claims: tenant_id absent" / `tenant_id %q != %q`), `verifyRolesClaims` at :233+. These are cc-mint claim assertions, not admin-endpoint probes. |
| `docs/error-codes.md:298` — `invalid_scope` row documents the registry gate | **Verified, exact line** — :298 ("when `oauth.scope_registry.enabled` is set, an effective `/token` scope is not registered by the global scope registry ... oracle-safe"). |
| `issue_payload.go:46,83-87` — B4-1 claims landed | **Verified, path drift** — the file is `infrastructure/defaultimpl/issue_payload.go`; `TenantID: subject.TenantID` at :46, `Roles` copy guarded by the non-empty guard at :86-90. |
| `scoperegistry/reject.go` `RejectUnregistered`; `config_load.go:220` | **Verified** — reject.go:31; config_load.go:220 `validateScopeRegistry()`. B4-2 landed. |

Additional load-bearing facts established during this pass:

1. **The direction-1 predecessor (no-redirect opt-in) has shipped.** The three
   helpers now construct `apiclient.New(apiclient.WithNoRedirect())`
   (tenants.go:253, 274, 297), and the module's 16-test mock-admin suite is
   green on HEAD. The current direction is the only remaining B4-3/B4-4 gap for
   this module; nothing in this spec re-touches the no-redirect pin.
2. **Threat model is concrete, with verified target routes.** The server's
   tenant validation imposes NO id charset — `tenant.Validate` checks only
   non-empty id and slug (domains/tenant/tenant.go:137-143) — so a crafted id
   is a plausible resource id, and each hazard character reaches a real
   surface:
   - `?` — query truncation: `delete "acme?x=1" --yes` sends
     `DELETE /api/v1/admin/tenants/acme?x=1`, the gateway ignores the query,
     and tenant `acme` is silently deleted while the operator believes the id
     was `acme?x=1`. Same class: `get "acme?status=suspended"` fetches tenant
     `acme`.
   - `/` — segment injection into SSO-router-owned sub-surfaces:
     `get "acme/usage"` → `GET /api/v1/admin/tenants/acme/usage`
     (`PathTenantUsage`, interfaces/sso/server_routes_admin.go:88) — the
     operator's bearer rides to a different admin endpoint than the one named
     on the command line; `get "u1/mfa"` hits the SSO-router-owned
     users sub-surface (build_http.go:211-213 lists the gateway users shapes;
     everything else is router-owned).
   - `:` — grpc-gateway custom-verb glue: `…/tenants/{id}:set-status` is a
     REAL POST route (proto/admin/v1/tenants.proto:43-48), matched by the
     plain `{id}` ServeMux pattern and re-resolved by the gateway's own
     pattern compiler (build_http.go:118-141). Any id containing `:` lands the
     bearer on the gateway's custom-verb surface, and `set-status` appended
     after a colon collides with the tenant status RPC.
3. **Server half of the acceptance is verified behavior, not roadmap prose.**
   - Unknown id on `POST /api/v1/admin/tenants/{id}:set-status` →
     `codes.NotFound, "tenant not found"` (interfaces/grpcserver/grpcadmin/
     admin_tenants.go:328-330) → grpc-gateway default mapping, HTTP 404 body
     `{"code":5,"message":"tenant not found","details":[]}` (the gateway is
     `runtime.NewServeMux()` with no custom error handler,
     cmd/sso-server/build_http.go:228). OpenAPI documents this family's 404 as
     `tenant_not_found` (docs/openapi.yaml:6865, Get/PUT/DELETE rows) — but the
     set-status entry (:7847-7867) documents only 200/401; REQ-4 closes that
     doc gap so the probe asserts a *documented* error.
   - Suspended tenant → previously minted token introspects `{"active":false}`:
     `checkTenantNotSuspended` runs inside `validateAnyToken`
     (interfaces/sso/server_token_clientauth.go:400, "hard-fails tokens whose
     owning client belongs to a now-suspended tenant"), which is exactly what
     `introspectAccess` calls via `ValidateAnyToken`; failure falls through
     `resolveIntrospection` → `introspectOne` returns `200 {"active":false}`
     (protocols/oauth/introspect_cache.go:130-131, "Unknown / expired / revoked
     → §2.2 mandates {active: false} only"). The gate is wired by
     `tenant.suspension_check.enabled` (cmd/sso-server/build_app_oauth.go:100;
     docs/config-reference.md:393). No wire-level suspension-introspection test
     exists: test/handle_introspect_test.go has no suspension case, and
     test/tenant_suspension_test.go asserts `ValidateToken` errors only — the
     introspect-wire assertion in REQ-3 is genuinely new coverage.
   - The flip fires the admin status-change hook on a real transition to
     Suspended (admin_tenants.go:344-355: `recordAdmin` +
     `revokeTenantTokens`), which **irreversibly revokes the tenant's refresh
     tokens and member sessions** — the sweep probe must warn before the flip
     and restore afterwards, and restoration does not resurrect revoked
     credentials.
4. **The sweep cannot create a tenant-bound disposable client.** The admin
   client API's `tenant_id` is read-only ("binding is established at
   registration time", admin_clients.go:414-422; proto/admin/v1/clients.proto:
   96-97); only config/DCR/federation seeding binds clients. The T-8f
   suspension leg therefore uses the operator's own minted token and its
   `tenant_id` claim, and skips (with a diagnostic) when the operator's client
   is not tenant-bound — a conditional group, like T-8d's precondition.
5. **Compatibility finding — T-8f must be opt-in.** The sweep's existing tests
   explicitly clear `SSO_ADMIN_TOKEN` (check_test.go:38) and the golden runs
   assert `check OK` + exit 0 without any admin credential (check_test.go:32).
   A default-on T-8f group would flip every token-less run to INCOMPLETE/exit 1
   and break the existing suite. REQ-2 therefore gates T-8f behind a new flag
   (`--admin-entities`) that requires `SSO_ADMIN_TOKEN`; without the flag the
   sweep is byte-identical to HEAD.
6. **Budget check for the sweep side.** token.go is at 478/500 lines — a new
   `runT8f` (orchestrator + unknown-id probe + suspension leg) does not fit
   there; it goes in a new `cmd/sso-ctl/apiclient/admin_entities.go`
   (non-test file count 5 → 6, under the 10/directory budget; no new package,
   no layer classification change). The orchestrator must be split into
   ≤50-line functions (cyclomatic gate).
7. **Baseline suite state on HEAD.** `go test ./cmd/sso-ctl/entitiescmd/`
   green (16 tests). Pre-existing, unrelated failures (reported per AGENTS.md
   §5.7, not touched by this change): apiclient `TestIntrospect_Non401Fails`
   (mock error bodies carry a `trace_id` the sweep's byte-identity assertion
   rejects — sweep-surface fixture issue) and the `check` subcommand not being
   registered in cmd/sso-ctl/main.go's dispatch (pre-existing wiring gap;
   T-8f lands behind `CheckRun` and its own tests regardless).

## 2. Core invariants

1. **Ids are validated at the CLI boundary before any client construction.**
   No request leaves the process for an id containing `:`, `/`, or `?`; the
   failure is a local exit 2 (CLI misuse), never a wire round trip with the
   operator's bearer.
2. **One shared predicate, all seven interpolation sites.** A single
   `validEntityID` predicate (package `entitiescmd`) guards
   tenants get/update/delete/set-status and users get/update/delete. The
   create paths are deliberately NOT in scope: their ids travel in the request
   body, never in the URL path, so they cannot redirect the bearer to another
   endpoint. No charset allowlist is invented beyond the three hazard
   characters the direction names.
3. **The sweep stays additive.** No flag → byte-identical behavior to HEAD
   (golden stdout, exit codes). Flag without `SSO_ADMIN_TOKEN` → exit 2 misuse.
   Flag + token → the T-8f entity leg runs after T-9 and participates in the
   documented exit contract (0 all-passed; 1 any failure or any skipped group;
   2 misuse).
4. **T-8f asserts documented, verified server behavior** — the 404
   `tenant not found` on an unknown id and the suspension gate
   (`{"active":false}`) — and **skips rather than fails** when the surface is
   unmounted (no tenant store) or the minted token is not tenant-bound. The
   suspension flip warns on stderr before it happens and is always restored.
5. **Truthiness is pinned at two levels**: the composed-gateway e2e in
   cmd/sso-server (REQ-3) proves the server half through the real admin
   gateway and `/token/introspect` wire; the sweep group (REQ-2) proves the
   same contract from the operator tool's side against a live tree.

## 3. Requirements

Acceptance (supplied, preserved verbatim): **Verified: unit tests asserting
RunTenants/RunUsers reject ids containing ':', '/', or '?' with exit 2 and NO
request sent (mirrors TestRunTenants_DeleteRefusesWithoutYes tenants_test.go);
new sweep group (T-8f or extend T-8a/T-9) asserting POST
/api/v1/admin/tenants/{id}:set-status with an unknown id yields the documented
error and that suspending a tenant makes a previously minted token introspect
{'active':false} — deploy-tree truthiness for the entity admin surface, mapping
to T-2/T-8(a-e)/T-9.**

### REQ-1 — Reject path-hazard entity ids at every interpolation site

Add one predicate to `cmd/sso-ctl/entitiescmd` (tenants.go, next to
`validateTenantStatus` at :243):

```go
// validEntityID reports whether id may be interpolated into an admin REST
// path. ':' is grpc-gateway's custom-verb glue (the gateway's "{id}" pattern
// also matches "{id}:set-status"), '/' injects a second path segment onto
// SSO-router-owned sub-surfaces (tenants/{id}/usage, users/{id}/...), and '?'
// truncates the id into a query string so the request silently targets a
// different resource. Ids are operator-supplied path data, never query or
// verb text.
func validEntityID(id string) bool { return !strings.ContainsAny(id, ":/?") }
```

Guard every path-interpolating site immediately after its existing
empty-string check and BEFORE flag parsing, the `--yes` gate, and any client
construction: `runTenantGet` (tenants.go:135), `runTenantUpdate` (:174),
`runTenantDelete` (:198), `runTenantSetStatus` (:223), `runUserGet`
(users.go:145), `runUserUpdate` (:181), `runUserDelete` (:205). On rejection
print a diagnostic to stderr and return 2 (no usage dump, mirroring the
delete-refusal pattern):

```text
sso-ctl tenants: invalid tenant id "acme:set-status": must not contain ':', '/', or '?'
sso-ctl users: invalid user id "u1/x": must not contain ':', '/', or '?'
```

The id is echoed with `%q` on stderr only (operator-supplied, not a secret);
it never appears in a URL. `strings.ContainsAny` is the only new import in
tenants.go (or move the predicate to users.go's existing `strings` import —
either file works, package-scoped; tenants.go keeps it for symmetry with
`validateTenantStatus`).

Testable criteria (A1–A3), in `tenants_test.go`/`users_test.go` using the
`withMockAdmin` harness (tenants_test.go:15-21) and the exact
`TestRunTenants_DeleteRefusesWithoutYes` shape (:294-310) — handler sets a
`called` flag, assertions check exit code and that no request was sent:

- **A1 (tenants):** table-driven over subcommands × hazard characters —
  `get`, `update`, `delete` (with `--yes`, so only the id guard can fire),
  `set-status` (with a valid status) × ids containing `:`, `/`, `?` (12
  cases). Each: exit **2** and the mock's `called` flag **false**. Pre-fix
  these fail: `get "acme?x"` exited 0 (fetched tenant `acme`), `delete
  "acme/x" --yes` exited 1 after a wire round trip, etc.
- **A2 (users):** same table over `get`, `update`, `delete` (with `--yes`) ×
  the three characters (9 cases). Exit **2**, no request.
- **A3 (positive control):** `get acme` / `get u1` with a clean id still
  reaches the mock and exits 0 (existing `GetNotFound`/`SetStatus` tests cover
  this; A3 is the full-suite gate: `go test ./cmd/sso-ctl/entitiescmd/
  -count=1` green, all 16 existing tests unchanged).

### REQ-2 — T-8f: the admin-entity leg of the deploy-tree sweep (opt-in)

Add a new probe group `T-8f` to `cmd/sso-ctl/apiclient`, gated on a new flag
`--admin-entities` and the admin bearer:

- `parseCheckConfig` (check.go:110-149): add the flag. When set, require
  `os.Getenv(EnvToken)` non-empty — otherwise exit 2 + usage, mirroring the
  missing-client-credentials rule (TestCheck_NoCredentialsMisuse shape). When
  unset, T-8f does not run at all and the sweep is byte-identical to HEAD
  (golden `check OK` runs unaffected — invariant §2.3).
- New file `cmd/sso-ctl/apiclient/admin_entities.go` (token.go is at
  478/500): `func (ck *checker) runT8f() (ok, skipped bool)` called from
  `CheckRun` after T-9, split into ≤50-line helpers (cyclomatic gate):
  `t8fProbeUnknownID` and `t8fProbeSuspension`. Wire `ok/skipped` into
  CheckRun's existing INCOMPLETE/FAIL plumbing exactly like `runT8d`
  (check.go:89-104).
- Update the coverage header (check.go:6-31) and `usage()` with the T-8f row
  and the `--admin-entities` flag.

**Probe (a) — unknown-id set-status yields the documented error.** Generate
`id := probeScope()` (reuse the existing crypto/rand generator at check.go:
268-290 — the `sweep-probe-` prefix + 12 random alphanumerics makes collision
with a real tenant effectively impossible, the same reasoning as T-8d's probe
scope). POST `ck.base + "/api/v1/admin/tenants/" + id + ":set-status"` with
body `{"status":"suspended"}` through `ck.client` (`New(WithAddr(base),
WithNoRedirect())`, which inherits `SSO_ADMIN_TOKEN` — the admin endpoints are
not advertised in discovery, so the operator's `--addr` is the admin origin,
mirroring the T-2 GET-row discipline). Assert: HTTP **404** and the JSON body's
`message` equals `"tenant not found"` (grpc-gateway google.rpc.Status shape
`{"code":5,"message":"tenant not found","details":[]}`; assert `message`, and
`code` == 5 when present). A **400** with body message `"tenant store not
configured"` (SetTenantStatus' FailedPrecondition, admin_tenants.go:318-320)
means the entity-admin surface is unmounted → group **skipped** with a
diagnostic (per the sweep contract a skipped group reports `check INCOMPLETE`,
exit 1). Any other status/body → **FAIL** ("admin REST surface not mounted or
set-status routing broken" — a truthful finding, the same semantics T-8d uses
when a documented enforcement is absent).

**Probe (b) — suspension truthiness (conditional sub-leg).** Mint a fresh
client-credentials token for `--client-id`/`--client-secret` via `probeClient`
(body credentials only — a bearer would make /token reject the request
outright, token.go:401-417), parse its claims with the T-8a claims machinery
(token.go:211-233) and read `tenant_id`. If empty → **skip** the sub-leg with a
diagnostic ("minted token carries no tenant_id — client not tenant-bound;
declare --expect-tenant-id to make this leg runnable"); the run reports
INCOMPLETE per contract. Otherwise, in this exact order:

1. Print a stderr warning that suspending tenant `<id>` fires the server's
   irreversible refresh-token/session revocation for that tenant
   (admin_tenants.go:346-355), then `POST …/tenants/{id}:set-status` with
   `{"status":"suspended"}` → expect 200.
2. `POST` the advertised `introspection_endpoint` with the minted token +
   client credentials → expect 200 and parsed `active == false` (mirror the
   post-revoke assertion style at token.go:333-338; do NOT require a
   byte-identical body).
3. `POST …/tenants/{id}:set-status` with `{"status":"active"}` → expect 200
   (restore).

Never introspect the minted token before the suspend: on trees with an
introspection cache (default TTL 60s, introspect_cache.go:112-122), a cached
active result would mask the flip. Any deviation from the expect values →
FAIL with a diagnostic naming the failing step. The `{id}` here is the
minted token's OWN `tenant_id` — the operator's client's tenant, which is the
only tenant the sweep is authorized to flip with the operator's bearer.

Testable criteria (A4–A9) in `cmd/sso-ctl/apiclient/check_test.go` (stubCheck
fixture, :96-150; runCheck/cleanSweepEnv harness):

- **A4 (misuse):** `--admin-entities` without `SSO_ADMIN_TOKEN` → exit 2, stub
  receives zero requests, usage on stderr.
- **A5 (probe a green):** flag + `SSO_ADMIN_TOKEN` set; stub answers
  `POST /api/v1/admin/tenants/sweep-probe-…:set-status` with
  `404 {"code":5,"message":"tenant not found","details":[]}` and the mint/introspect
  stubs for the suspension leg; run exits 0 and prints `entity admin: OK`.
- **A6 (unmounted surface):** stub answers 400
  `{"code":9,"message":"tenant store not configured","details":[]}` → group
  skipped, run prints `check INCOMPLETE`, exit 1.
- **A7 (suspension leg green):** stub's `/token` returns a real locally-signed
  JWT whose payload carries `tenant_id` (test mints it with the defaultimpl
  issuer, the check_test.go:67-90 precedent); set-status returns 200;
  introspection returns `{"active":false}`; run exits 0 and the stderr warning
  names the tenant.
- **A8 (suspension not enforced):** introspection returns `{"active":true}`
  after a 200 suspend → FAIL, exit 1, diagnostic names the introspect step.
- **A9 (no-flag byte-identity):** the existing golden runs (TestSweep_GreenPath,
  TestExitCodes, TestStdoutDeterministic) pass unchanged with `EnvToken`
  cleared — no flag, no T-8f, `check OK` + exit 0 byte-identical.

### REQ-3 — Composed-gateway regression: the documented error and the suspension flip through the real wire

Add tests to `cmd/sso-server/admin_gateway_routing_e2e_test.go` using the
existing full-composition harness (`buildAdminGatewayE2EServer` +
`adminAuthedRequest`, :102-143; `fullFeatureConfig` seeds tenant `t1` at
build_app_coverage_test.go:184):

- **A10:** with the admin bearer, `POST /api/v1/admin/tenants/sweep-probe-e2e:
  set-status` with `{"status":"suspended"}` against an id that cannot exist →
  HTTP 404, body contains `"tenant not found"`. Pins the documented error and
  the custom-verb routing through the real gateway (today the e2e suite only
  GETs `/api/v1/admin/tenants`, :162).
- **A11:** seed a confidential client bound to `t1` via the config
  (`cfg.Clients` with `TenantID: "t1"`, `Active`, `TokenStrategy: "jwt"`,
  `AllowedScopes: ["read"]` — config seeding at build_app_core.go:79-100) and
  set `cfg.Tenant.SuspensionCheck.Enabled = true` (precedent:
  build_app_coverage_test.go:273). Mint a cc token via the real `POST /token`
  (client credentials, scope `read`); `POST /api/v1/admin/tenants/t1:set-status`
  `{"status":"suspended"}` → 200; `POST /token/introspect` with the minted
  token + client credentials → 200 with `"active": false`; restore
  `{"status":"active"}` → 200. Assert each step; the minted-token
  introspect-inactive assertion is new wire coverage (no existing test
  exercises suspension through introspection).

### REQ-4 — Contract docs and universal gates

- **A12:** add the missing 404 response to the set-status entry in
  docs/openapi.yaml (:7847-7867): `"404": { description: '`tenant_not_found`',
  content: ErrorResponse }`, mirroring the tenants/{id} rows (:6865) — the
  probe asserts this documented error, so the endpoint's own row must carry it.
  Validate with `make docs-check` (kin-openapi) or `python cli.py
  docs-check`; the proto-openapi-parity check is unaffected (no message
  changes).
- **A13:** `go build ./... && go vet ./...` clean;
  `go test -run 'TestMaintainability_|TestArchitecture_' .` unchanged (no new
  packages, no import-direction change; tenants.go ~332 → ~355 lines, users.go
  ~228 → ~240, both under 500; apiclient non-test file count 5 → 6, under the
  10/directory budget); `go test ./cmd/sso-ctl/entitiescmd/ ./cmd/sso-ctl/
  apiclient/ ./cmd/sso-server/ -run '…'` for the touched suites. No new
  `Err*` (error-codes.md untouched), no config knob (config-reference.md
  untouched — `tenant.suspension_check.enabled` already documented at :393).
- Do not "fix" the pre-existing failures listed in §1.7 as part of this
  change; report them separately if they block CI.

## 4. Files

### Modify

```text
cmd/sso-ctl/entitiescmd/tenants.go    — add validEntityID (next to validateTenantStatus :243);
                                       guard runTenantGet/Update/Delete/SetStatus after the
                                       empty-string checks (:136, :175, :199, :224); strings import
cmd/sso-ctl/entitiescmd/users.go      — guard runUserGet/Update/Delete (:146, :182, :206)
cmd/sso-ctl/entitiescmd/tenants_test.go — A1 table (12 cases), A3 gate
cmd/sso-ctl/entitiescmd/users_test.go   — A2 table (9 cases)
cmd/sso-ctl/apiclient/check.go        — --admin-entities flag + misuse rule; coverage header
                                       (:6-31) T-8f row; usage() flag+group text; CheckRun
                                       wiring after T-9 (:97-98)
cmd/sso-ctl/apiclient/check_test.go   — A4-A9 (T-8f group tests; TestExitCodes misuse row)
cmd/sso-server/admin_gateway_routing_e2e_test.go — A10, A11 (tenant-bound seeded client,
                                       SuspensionCheck.Enabled=true, real /token + introspect)
docs/openapi.yaml                     — 404 tenant_not_found row on set-status entry (:7847-7867)
```

### Add

```text
cmd/sso-ctl/apiclient/admin_entities.go — runT8f + t8fProbeUnknownID + t8fProbeSuspension
                                          (package apiclient; ≤50-line functions)
```

### Do not modify

```text
cmd/sso-ctl/entitiescmd/tenants.go:253/274/297 — no-redirect pin already shipped (direction 1);
                                                 not part of this direction
cmd/sso-ctl/apiclient/token.go      — runT8d/runT9/claims machinery stay put (file at 478/500;
                                      new code goes in admin_entities.go)
cmd/sso-ctl/apiclient/sweep.go      — T-2 untouched
cmd/sso-server/build_http.go        — gateway routing is the verified contract the probes
                                      assert, not a change target
docs/error-codes.md                 — no new Err* introduced (tenant_not_found already
                                      documented in openapi.yaml; error-codes.md gap noted
                                      in §5, out of scope)
cmd/sso-ctl/main.go                 — the missing `check` dispatch is a pre-existing gap (§1.7)
```

## 5. Dependencies and compatibility

- **CLI surface:** `sso-ctl check` gains one optional flag. Without it,
  behavior is byte-identical to HEAD (existing golden tests and token-less
  deployments unaffected — the compatibility constraint that forced the
  opt-in design, §1.5). With it and no `SSO_ADMIN_TOKEN`, exit 2 misuse.
- **Wire contract:** nothing changes server-side. T-8f and the e2e tests
  assert existing, verified behavior: 404 `tenant not found` on unknown
  set-status ids (admin_tenants.go:328-330) and
  `{"active":false}` introspection for suspended tenants (server_token_
  clientauth.go:400 + introspect_cache.go:130-131). The only contract-doc
  delta is the missing 404 row on the set-status OpenAPI entry (A12).
- **Operator-visible side effect (documented, unavoidable):** probe (b) flips
  a real tenant to suspended for a few round trips. On trees with the
  suspension hook wired (admin_tenants.go:346-355), that flip irrevocably
  revokes the tenant's refresh tokens and sessions; restoration reactivates
  the tenant but cannot resurrect credentials. The probe prints a warning
  before the flip, and the group is opt-in — an operator who runs
  `--admin-entities` accepts the side effect as the price of truthiness, the
  same trade the acceptance specifies. Trees without `tenant.suspension_
  check.enabled` will FAIL probe (b) (introspection stays active) — a truthful
  finding, consistent with T-8d's enforcement-absence semantics.
- **Skip semantics:** a skipped T-8f (unmounted surface, no tenant binding)
  reports `check INCOMPLETE` and exits 1, per the documented sweep contract
  (check.go:27-31). This is existing contract behavior, not a new carve-out.
- **Rollout:** single commit; two unit-test tables + one new sweep file + two
  e2e cases + one OpenAPI row. No migration, no config, no storage change.
