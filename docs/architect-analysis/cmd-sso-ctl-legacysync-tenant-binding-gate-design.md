# Design: Tenant-binding gate on mapped clients (cmd/sso-ctl/legacysync)

Companion to `docs/architect-analysis/cmd-sso-ctl-legacysync-tenant-binding-gate-requirements.md`.
This document treats the requirements doc (and the evidence it cites) as
untrusted claims, records what was independently re-verified against HEAD,
corrects the drift found, and turns the requirements into a concrete, ordered
design with API changes, compatibility constraints, failure modes, migration
steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every cited symbol was re-checked against the working tree. All eight claims
survive; two have minor line-number drift that does not change substance.

| # | Claim | Verdict |
|---|---|---|
| E1 | `target.go:166-180` — `loadTargetClients` id-only select (line 167) | Confirmed. `SELECT id FROM clients WHERE active=1` at `target.go:167`; `targetSnapshot.Clients` is `map[string]struct{}` (`target.go:29`) carrying no binding. Snapshot `Clients` is touched at exactly three sites in `target.go`: initialization (`inspectTarget`, target.go:98), `loadTargetClients:177`, and the existence check in `buildReport:186` — plus a fourth mechanical site, the composite literal `Clients: map[string]struct{}{}` at `target_test.go:42` (mandatory compile fix, same change). A representation change is fully contained in `target.go` plus that one literal. |
| E2 | `target.go:182-215` — `buildReport` existence-only mapped-client check (185-189) | Confirmed. Lines 185-189 fail only with `mapped target client %q does not exist or is inactive`; no tenant check exists anywhere in the package (`grep tenant_id` over `cmd/sso-ctl/legacysync` is empty). |
| E3 | `syncReport` has no tenant field (originally cited at `target.go:116-131`) | Confirmed as self-corrected: the struct is `model.go:104-114` (Source, Create/Update/DeactivateUsers, Credentials, Roles, Assignments, Mode). The cited target.go lines are inside `loadTargetAssignments`. |
| E4 | `sqlite/clients.go:37-48` — `tenant_id TEXT NOT NULL DEFAULT ''` (line 46, partial index 49-51); binding resolves at `clients_scan.go:190` | Confirmed. Column at `infrastructure/defaultimpl/sqlite/clients.go:46` inside the Version-1 migration (lines 36-52); partial index `idx_clients_tenant ... WHERE tenant_id <> ''` at lines 49-51; `clients_scan.go:190` is exactly `c.TenantID = r.tenantID` (scalar copy in `clientScanRow.scalars`). |
| E5 | `issue_payload.go:46` unconditional `TenantID` stamp; `:108-131` dedup | Confirmed. `TenantID: subject.TenantID` at `infrastructure/defaultimpl/issue_payload.go:46` with a comment documenting the omitempty discipline; `claimsWithoutEmittedKeys` spans 116-131 (doc comment starts ~108), stripping `tenant_id`/`roles` from the attribute-bag copy so the mint-time literal appears exactly once. |
| E6 | `server_token_clientauth.go:193` binding resolution; grants stamp `TenantID: client.TenantID` | **Drift (line numbers only).** `server_token_clientauth.go:193` is the declaration of `authenticateTokenClient`; the binding is resolved by `clientStore.Get` at 204-206 and the tenant gate is `clientTenantOK(ctx, client)` at 218-221 (not line 193). Grant stamps confirmed at `internal/handler/tokengrant/token_authcode.go:136`, `token_refresh.go:292` (cited 288), `token_client_credentials.go:52`, `token_device.go:99`, `token_ciba.go:124`, `token_jwt_bearer.go:112`, `token_saml2_bearer.go:123`, `token_exchange_stages.go:399`; login mint at `interfaces/sso/server_login.go:119` (cited 114), `server_native_sso.go:193`, `server_login_client.go:329`. Substance holds: every mint path stamps the client's binding. |
| E7 | `testTargetSchema` lacks `tenant_id` (`target_test.go:145-155`) | Confirmed. `CREATE TABLE clients(id TEXT PRIMARY KEY,active INTEGER NOT NULL DEFAULT 1);` at 145-155; `seedTarget` (`target_test.go:64-67`) inserts only `(id,active)` for `sverp-web`. |
| E8 | "today exit 0" for an unbound mapped client | Confirmed. `main.go:52-54` (`buildReport` error → `reportError` → return 1) is the only pre-write failure path; `cfg.Apply` write branch is at 56-60 (after `buildReport`), `return 0` at 62. `reportError` prints `sso-ctl legacy-sync: %v` to stderr and returns 1. |

Additional claims checked for this design:

- `KeyTenantID = "tenant_id"` at `shared/core/consts_wire.go:169` — confirmed, the wire-visible claim name.
- No doc-contract update is needed: `legacy-sync`/`legacysync` is absent from `docs/config-reference.md`, `docs/feature-matrix.md`, `docs/error-codes.md`, and `docs/openapi.yaml` (grep verified) — the change introduces no `Err*`, endpoint, or config knob, so AGENTS.md §5.6 imposes no contract edit.
- `run()`-level exit-code test is impossible without a live legacy MySQL source: `openLegacyDB` (`source.go:43-66`) hard-codes `sv_sso` DB name and TCP ping with no injection seam. Confirmed; the exit-code acceptance is discharged at the `buildReport` boundary plus the verified `run()` control flow.
- Harness patterns for REQ-5 exist: `test/auth_password_expiry_test.go:37-85` (real `sqlitestores.PasswordCredentialStore` + `MemoryUserProvider` + `NewPasswordAuthenticator` + Ed25519 issuer + `httptest` server), `test/client_tenant_binding_test.go:82-91` (client store + issuer), `test/auth_code_test.go:253` (`jwtAllClaims`).
- Budgets: `target.go` is 403 lines (403→~416 under the 500 ceiling); `buildReport` is 34 lines (182-215) and grows to ~44 (under 50); no new package files; `_test.go` additions do not count against the 10-file fan-out ceiling; `interfaces/sso` untouched (60-file ceiling preserved).

## 2. Design overview

`legacy-sync` produces offline SQLite deployments whose clients must carry a
tenant binding: the mint side stamps `tenant_id` into every access token
unconditionally from `client.TenantID` (`issue_payload.go:46`), and an
unbound client silently mints tokens without the mandatory claim (B4-1/T-8a
trust-path gate). The sync tool never reads the binding, so it can produce
exactly that broken deployment today, exiting 0.

The design closes the gap with a read-only validation gate in the plan
reporting stage:

1. `loadTargetClients` selects `tenant_id` alongside `id` and the snapshot
   retains, per active client, its binding (`targetSnapshot.Clients` becomes
   `map[string]string` id → tenant_id; SQL `NULL` collapses to `''`).
2. `buildReport` fails the plan, after the existing existence/inactivity
   check, when a **mapped** client has an empty binding — naming every
   offending client id, one per line. The gate runs before the `--apply`
   write branch, so dry-run and apply behave identically: exit 1, no write,
   no stdout report.
3. Success-path output is byte-identical to today: `syncReport` and
   `printReport` gain nothing; the per-client diagnostic appears only in the
   failure stderr.

Non-goals preserved from the requirements: no mint-side change, no server or
wire-surface change, no storage migration, no new `syncReport` field, no
`run()`-level MySQL harness.

## 3. API changes

There is no exported API. `cmd/sso-ctl/legacysync` is a command package; all
types involved are unexported. The change surface is:

| Surface | Change |
|---|---|
| `targetSnapshot.Clients` (target.go:29) | `map[string]struct{}` → `map[string]string` (client id → tenant binding; `""` = unbound). Four touch sites: init at :98, write at :177, read at :186 (all in target.go), plus the `Clients: map[string]struct{}{}` literal at `target_test.go:42`, which must become `map[string]string{}` (compile fix — see the REQ-4 row). |
| `loadTargetClients` (target.go:166-180) | Select becomes `SELECT id, COALESCE(tenant_id,'') FROM clients WHERE active=1`; scan gains one string. `COALESCE` makes SQL `NULL` and `''` collapse to the same unbound state (the real schema is `NOT NULL DEFAULT ''`, so `''` is the operative case; `NULL` occurs only in hand-made schemas). |
| `buildReport` (target.go:182-215) | After the existing existence check (185-189, text unchanged), collect every mapped client whose binding is empty, sort the ids, and return `errors.Join` of one `fmt.Errorf("mapped target client %q has no tenant binding (tenant_id empty)", id)` per client. `errors.Join`'s `%v` rendering gives exactly "one per-client line per offending client" under the existing `reportError` prefix. |
| `syncReport` / `printReport` / CLI flags / exit codes | Unchanged. Exit 1 via the existing `reportError` path for the new failure; exit 0 unchanged on success. |
| `testTargetSchema` + `seedTarget` (target_test.go) | Fixture `clients` table gains `tenant_id TEXT NOT NULL DEFAULT ''` mirroring the real v1 migration; the seed binds `sverp-web` to a non-empty tenant. Existing test names and final assertions unchanged. `openTestTarget` (target_test.go:49) is refactored into `openTestTargetWithSchema(t, schema)`; three schemas then exist: the parity schema above, `testTargetSchemaNullableClients` (`tenant_id TEXT` with no NOT NULL — insertable NULL rows, used only by U4/U6; the parity schema is `NOT NULL` and cannot hold NULL), and the existing column-less schema (used only by U7). |

Proposed `buildReport` gate (aggregation is the load-bearing part — the
requirements demand *every* offending id named, so it cannot return on the
first violation):

```go
var unbound []string
for clientID := range plan.MappedClients {
    tenantID, ok := target.Clients[clientID]
    if !ok {
        return syncReport{}, fmt.Errorf("mapped target client %q does not exist or is inactive", clientID)
    }
    if tenantID == "" {
        unbound = append(unbound, clientID)
    }
}
if len(unbound) > 0 {
    sort.Strings(unbound)
    errs := make([]error, 0, len(unbound))
    for _, id := range unbound {
        errs = append(errs, fmt.Errorf("mapped target client %q has no tenant binding (tenant_id empty)", id))
    }
    return syncReport{}, errors.Join(errs...)
}
```

Deterministic sorted order matters: the multi-client test asserts every id is
named, and sorted output keeps the assertion (and any operator triage) stable.

## 4. Compatibility constraints

- **Target schema requirement (new, intentional).** The gate's SELECT
  requires a `clients.tenant_id` column. Every real deployment has it — the
  column is created in the server's Version-1 migration
  (`sqlite/clients.go:36-52`), so no server-created target can lack it.
  Hand-made targets (all existing test fixtures) must add the column in the
  same change. A target without the column now fails with a SQL query error
  (exit 1) instead of the old id-only read; this is the stricter contract and
  is reported, not papered over — a `clients` table without `tenant_id` is
  not a Snaplink deployment.
- **Behavioral break is the point.** A plan whose mapped clients are unbound
  today exits 0; after this change it exits 1 in both modes, with no writes
  even under `--apply` (the gate runs before the write branch, `main.go:52-60`).
  Operators must bind tenants before syncing. Dry-run fails first, so the
  failure is discoverable without touching the target (dry-run opens the
  target with `mode=ro`, `readOnlyDSN`).
- **Unmapped unbound clients pass.** The gate covers only `plan.MappedClients`
  — the managed surface (`writeAssignments` rewrites assignments only for
  mapped clients). An unbound client outside the sync's scope is not the sync
  tool's problem and must not block the plan.
- **Exact-match binding semantics.** Only `''` and SQL `NULL` are unbound. No
  trimming: `' '` is a bound (though almost certainly wrong) value. The server
  compares the column value literally against the request tenant
  (`clientTenantOK` → `tenant.ClientOK`, handlers.go:407-408), and trimming
  in the sync tool could mask an operator mistake the server would reject.
  Single-value semantics only — the column is one tenant id, same as the
  server.
- **Backward compatibility of artifacts.** Targets produced with the new gate
  (all mapped clients bound) are readable by older binaries (which ignore
  `tenant_id`). The change is one-directional: newer tool refuses, older tool
  accepts. Rollback is a revert of two files; a deployment created under the
  gate is strictly safer than one created before it (the claim emission itself
  predates this change at `issue_payload.go:46`).
- **No doc-contract updates.** No new `Err*`, endpoint, or config knob;
  `legacy-sync` is absent from config/feature/error/openapi docs (verified).
  The new diagnostic is a CLI stderr line, not a documented API.

## 5. Failure modes

| Mode | Behavior | Notes |
|---|---|---|
| Mapped client bound (`tenant_id='tenant-acme'`) | Plan proceeds; output byte-identical to today | Success path (T-9). |
| Mapped client unbound (`tenant_id=''`) | Exit 1, stderr `sso-ctl legacy-sync: mapped target client "web" has no tenant binding (tenant_id empty)`; no writes, no stdout report; identical in dry-run and `--apply` | The new gate. One line per client. |
| Mapped client `tenant_id` SQL NULL | Treated as unbound via `COALESCE` | Hand-made schemas only; real schema is `NOT NULL DEFAULT ''`. |
| Multiple unbound mapped clients | All named, sorted, one per line, single exit 1 | Aggregation requirement (REQ-4). |
| `clients` table lacks `tenant_id` column | SQL error `target clients query: SQL logic error: no such column: tenant_id (1)` → exit 1 | Expected for non-Snaplink schemas; fixture updated in the same change. |
| Mapped client missing/inactive | Unchanged error `mapped target client %q does not exist or is inactive`, exit 1 | Pre-existing path, text preserved. `loadTargetClients` filters `WHERE active=1`, so an inactive mapped client is absent from the snapshot and hits this check. When several mapped clients are missing/inactive, only the first one encountered (map iteration order) is named per run — the runbook cross-checks the app map against the inventory rather than relying on the error to enumerate. |
| Unmapped unbound client | Passes | Out of the sync's managed scope. |
| No apps mapped (`MappedClients` empty) | Loop no-ops; no behavioral change | App-less plans unaffected. |
| `tenant_id=' '` (whitespace) | Treated as bound | Exact-match semantics; server would reject the tenant at request time — operator error surfaced there, not in the sync tool. |

No new oracle/security surface: the gate introduces one failure cause with a
uniform response (stderr + exit 1), adds no distinguishing information across
internal causes, and runs read-only against the target.

## 6. Migration steps

No repository migration exists or is needed (the real schema already has the
column; `syncReport`/`printReport`/mint side are untouched). The migration is
operational, for deployments whose target clients are unbound:

1. Build and deploy the new `sso-ctl` (or build from this change).
2. Inventory the target binding state:
   ```sql
   SELECT id, tenant_id, active FROM clients;
   ```
3. For every client id named in the sync config's app map (the planned mapped
   clients) — **including currently inactive ones** — bind the tenant if
   empty:
   ```sql
   UPDATE clients SET tenant_id = '<tenant-id>' WHERE id = '<client-id>' AND tenant_id = '';
   ```
   (The admin API/UI cannot write this column: `TenantID` is read-only on the
   admin wire, surfaced by `clientToProto`, never consumed by a mutation
   (`grpcadmin/admin_clients.go:59`; `protoToClient` and
   `applyProtoToExistingClient` never set it; the admin HTTP layer has no
   client endpoints). The only write paths are config re-seed
   (`config/config_client.go:20-24` → `seedClients` → `ClientStore.Put`), DCR
   `POST /register` (`handle_register.go:72,114`), or direct SQL like the
   statement above.)

   Inactive mapped clients must be handled explicitly. Binding alone does not
   unblock the sync: `loadTargetClients` filters `WHERE active=1`, so an
   inactive mapped client is absent from the snapshot and fails the
   pre-existing `does not exist or is inactive` check. Either reactivate it
   (it then falls under the tenant gate, which the UPDATE above has already
   satisfied) or remove it from the app map. Skipping an inactive mapped
   client now and reactivating it later makes the next sync fail loudly with
   the new tenant-binding error — the intended safety property, not a
   regression.
4. Run `sso-ctl legacy-sync` (dry-run first). The gate names every still-
   unbound mapped client; bind and re-run until exit 0. Two convergence
   conditions beyond unbound rows: a missing/inactive mapped client is named
   by the pre-existing existence check (one client per run, nondeterministic
   when several are missing — cross-check the app map against the step-2
   inventory), and reactivating a previously skipped client re-introduces the
   tenant gate for it. Dry-run exits 1 on the first failing condition with no
   writes, so the loop is safe to repeat.
5. Run with `--apply`. Post-check: mint a token for an imported user and
   verify the `tenant_id` claim is present exactly once with the expected
   value — codified as the REQ-5 integration test.
6. Rollback path: revert `target.go` and `target_test.go`; old behavior
   (silent acceptance) returns. No data cleanup required — the gate never
   writes.

## 7. Testable acceptance mapping

### Unit — `cmd/sso-ctl/legacysync/tenant_gate_test.go` (new; `_test.go` does not count against the fan-out ceiling)

| Acceptance | Test |
|---|---|
| REQ-1: snapshot carries binding | U6 — `loadTargetClients` on a seeded fixture (nullable schema variant via `openTestTargetWithSchema`): bound client yields its tenant id; empty yields `""`; NULL yields `""` (COALESCE). |
| REQ-2 positive (bound passes) | U2 — `buildReport(plan, target, "dry-run")` and `buildReport(plan, target, "applied")` return nil error for a bound mapped client. |
| REQ-2 negative (unbound fails, both modes) | U1 — for mode `"dry-run"` and `"applied"`: error non-nil and contains the client id; error contains `tenant_id`. |
| REQ-2 multi-client (every id named) | U3 — two unbound mapped clients → error text contains both ids; deterministic (sorted) order. |
| REQ-2 missing/inactive mapped client (failure-mode row 6) | M6 — mapped client absent from `target.Clients` → error containing `does not exist or is inactive` (pins the pre-existing path this change preserves). |
| REQ-4 unmapped unbound passes (failure-mode row 7) | M7 — mapped client bound, plus an unbound `"other":""` client outside `plan.MappedClients` → nil error (out of the sync's managed scope). |
| REQ-4 empty app map (failure-mode row 8) | M8 — `buildReport(syncPlan{}, targetSnapshot{Clients: map[string]string{}}, "dry-run")` → nil error (loop no-ops). |
| REQ-4 whitespace bound (failure-mode row 9) | M9 — `buildReport(plan, target, "dry-run")` with `Clients: {"web": " "}` → nil error (`' '` counts as bound; no trimming). |
| REQ-2 NULL treated as unbound | U4 — fixture row with `tenant_id NULL` (nullable schema variant via `openTestTargetWithSchema`; the parity schema is `NOT NULL DEFAULT ''` and cannot hold NULL) fails identically to `''`. |
| REQ-2 no writes | Implied by gate position: `buildReport` precedes the `cfg.Apply` branch (`main.go:52-60`, verified); covered by control-flow documentation, not a MySQL harness (no seam, `source.go:43-66`). |
| REQ-3 byte-identical success | U5 — `printReport` golden: stdout bytes equal today's **three-line** format (main.go:71, 72-74, 75-77) for a passing plan; `syncReport` has no new field (compile-time: struct untouched). Exact templates: `legacy-sync mode=%s`, `source users=%d active=%d inactive=%d roles=%d grants=%d overrides=%d`, `target create_users=%d update_users=%d deactivate_users=%d credentials=%d roles=%d assignments=%d`. Two goldens needed (line 1 differs by mode `dry-run` vs `applied`) or parameterize the expected first line. The output is byte-deterministic — counts only; the random bcrypt salt in `legacyFixture` never reaches the report. |
| REQ-4 fixture | Existing `TestApplyPlanPreservesNativeAuthorizationAndMenus` and `TestBuildReportRejectsNativeUserCollision` keep names and final assertions; fixtures gain the column and `sverp-web` binding. Disclosed compile fix: the `Clients: map[string]struct{}{}` literal at `target_test.go:42` must become `map[string]string{}` in the same change — behaviorally unchanged (nil `MappedClients` → gate loop no-ops → collision error still returned). |
| Missing-column drift | U7 — fixture `clients` table without `tenant_id` → `loadTargetClients` returns the SQL error (documents the M4 mode). |

### Integration — `test/legacy_sync_tenant_claim_test.go` (new, package `ssotest`)

| Acceptance | Test |
|---|---|
| T-8a positive | I1/I2 — build the harness in the exact shape `legacy-sync --apply` produces: real `sqlitestores.NewClientStore` (clients row active, `tenant_id='tenant-acme'`, password authenticator allowed), `NewPasswordCredentialStore` (bcrypt hash for the imported user), `MemoryUserProvider` (user id == username, provider-agnostic), `NewPasswordAuthenticator` (resolve: username → id), Ed25519 issuer — per `auth_password_expiry_test.go:37-85` + `client_tenant_binding_test.go:82-91`. `POST /auth/login` → 200; decode the access token per `jwtAllClaims` (`auth_code_test.go:253`); assert raw payload `strings.Count(payloadJSON, "\"tenant_id\":") == 1` and decoded `tenant_id == "tenant-acme"`. Exactly-once is the dedup guarantee of `claimsWithoutEmittedKeys` (`issue_payload.go:116-131`). Implementation note: `jwtAllClaims` returns only the decoded map, so the raw-count assertion needs a sibling base64 decode of JWT segment 1 (or a helper returning the raw payload string); the count is a structural exactly-once pin — a decoded-assertion alone would silently last-win on duplicate keys (`json.Unmarshal` into `map[string]any`). Keep both assertions. |
| T-8a negative (server side) | Out of scope: the gate lives in the sync tool; the server's stamping behavior is already correct and is asserted by existing tests (`client_tenant_binding_test.go`). The negative assertion is the unit gate (U1/U3) plus the documented exit-1 control flow. |
| T-9 | U5 golden pin; U2 nil-error path; fixture updates with unchanged existing assertions. |

### Gates

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/legacysync/ -run 'TestApplyPlan|TestBuildReport|TestTenant|TestLegacySync' -v
go test ./test/ -run 'TestLegacySyncTenantClaim' -v
go test ./... -race
make ci
```

Budgets after the change: `target.go` ~416 lines (< 500), `buildReport` ~44
lines (< 50), cyclomatic complexity unchanged in kind (+1 loop over mapped
clients, well under 15), `if` nesting unchanged (guards), no new package
files, no layer changes, `interfaces/sso` untouched.

## 8. Files

Create:

```text
cmd/sso-ctl/legacysync/tenant_gate_test.go
test/legacy_sync_tenant_claim_test.go
docs/architect-analysis/cmd-sso-ctl-legacysync-tenant-binding-gate-design.md  (this document)
```

Modify:

```text
cmd/sso-ctl/legacysync/target.go        — REQ-1 (select + snapshot shape) and REQ-2 (gate)
cmd/sso-ctl/legacysync/target_test.go   — fixture column + seed binding
```

Do not modify: `infrastructure/defaultimpl/issue_payload.go`,
`infrastructure/defaultimpl/sqlite/clients.go`, `interfaces/sso/*`,
`internal/handler/tokengrant/*`, `cmd/sso-ctl/legacysync/{plan,source,config,model,main}.go`,
any contract doc.
