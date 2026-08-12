# Requirements: scope-registry pre-flight for the offline deploy tree (cmd/sso-ctl/legacysync)

Source direction (B4-2 / T-8d):

> Scope-registry pre-flight for the offline deploy tree: reject mapped clients
> whose allowed_scopes or imported legacy scopes are unregistered in
> scope-matrix-v2.

This document verifies every cited file/symbol against HEAD, states the
requirements in testable form, and preserves the supplied acceptance checks
unchanged.

## 1. Goal and user outcome

`legacy-sync` is the deployment path for offline SQLite targets. Under B4-2,
an enabled `oauth.scope_registry` makes `/token` reject any request-borne or
effective scope the registry does not register, with the plain `400
invalid_scope`, before any grant branch. The sync tool is the only gate
between a legacy source and such a deployment, but it never reads
`clients.allowed_scopes`, never consults the registry, and writes
scope-shaped legacy strings (role codes, role permissions, menu/override
fabrications) straight into SQLite — so a synced deployment can ship a client
whose scopes 400 at mint time with zero signal from the tool that created it.

Completion: when the operator wires the registry (`--scope-registry`, with
optional `--scope-registry-extra` reconciliation), `legacy-sync` dry-run and
`--apply` refuse (exit 1, naming the client id and the scope) any plan whose
mapped clients declare, or whose imported roles write, an unregistered scope.
Without the wiring — or with every scope registered — output is byte-identical
to the pre-change binary. An integration assertion proves a `/token` mint
against the synced deployment shape returns 200 for a registered scope and
400 `invalid_scope` for an unregistered one.

## 2. Evidence verification (every cited symbol checked against HEAD)

The repository has drifted since the source analysis was written: the
tenant-binding gate (sibling direction, B4-1/T-8a) has landed, so
`loadTargetClients` now also selects `tenant_id` and `buildReport` runs
`validateMappedClientBindings` (existence/active + tenant). Every substantive
claim of this direction still holds: `allowed_scopes` is still never read,
and no scope-registry consultation exists anywhere in the tool.

| Cited evidence | Verified status | Note |
|---|---|---|
| `target.go:166-180` — `loadTargetClients` "id-only select, active=1" | CORRECTED LOCATION, SUBSTANCE VERIFIED | Now at `target.go:169-190`; the SELECT is `SELECT id,COALESCE(tenant_id,'') FROM clients WHERE active=1` (lines 173-174) — id + tenant binding only. `allowed_scopes` is never read; the tenant column was added by the merged sibling gate. The claim "never reads allowed_scopes, never consults the scope registry" stands |
| `target.go:182-215` — `buildReport` "existence-only client check" | CORRECTED LOCATION, SUBSTANCE VERIFIED | Now at `target.go:216-249`; the mapped-client check is `validateMappedClientBindings` (`target.go:194-214`, existence/active error text at :199, tenant error at :211). No scope check exists |
| `target.go:197-200` — `'mapped target client does not exist or is inactive'` | VERIFIED (shifted) | Text at `target.go:199` |
| `plan.go` — `legacyRoleCode`, `menuPermission`, `overridePermission`, `planGrants` roleMap | VERIFIED | `legacyRoleCode` at :186 (shape `legacy:APP:ROLE` via `managedPrefix` :185); `menuPermission` at :196-198 (`legacy:menu:ID:action`); `overridePermission` at :200-204 (`legacy:action:ID:action`); `planGrants` at :118-141 reconciles only assignment codes via `roleMap` (lines 130-133) — never permission/scope registration; `makePlannedRole` :109-116 copies source `role.Permissions` verbatim into the plan |
| `interfaces/sso/server_token.go:128-136` and `189-204` — registry seam before grant branches, plain 400 `invalid_scope` | CORRECTED LOCATION, SUBSTANCE VERIFIED | `dispatchTokenGrant` at :122-155 calls `s.rejectUnregisteredScopes(ctx, scopes)` at :132, before `denyTokenScopeCombo`, custom grants, and every grant branch; `rejectUnregisteredScopes` at :189-207 delegates to `scoperegistry.RejectUnregistered` and its doc pins the "plain invalid_scope body, never errorBody" shape |
| `protocols/oauth/scoperegistry/reject.go` — `RejectUnregistered` | VERIFIED | `reject.go:31-43`: nil registry or empty set = no-op; else writes `400 core.ErrorBody(core.ErrInvalidScope)` = `{"error":"invalid_scope"}` (byte-identical plain body, no trace_id — pinned by `registry_test.go:191-192`) |
| `interfaces/scopecontract/consts.go:25` — nine-scope `Matrix` | VERIFIED | `Matrix()` at `consts.go:25-36` returns the nine scope-matrix-v2 scopes (`admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `billing:checkout:create`, `metering:write`, `billing:entitlement:read`, `audit:event:write`, `admin:*`) |
| `config/config_oauth2.go:11-61` — `scope_registry` block; membership check "YAML only" | CORRECTED LOCATION, SUBSTANCE VERIFIED | `validateScopeRegistry` at `config_oauth2.go:30-66`: grammar/duplicate checks always; the client `allowed_scopes` membership check runs only when `Enabled` (:49) and iterates `c.Clients` (:58) — the YAML config, never the offline DB. `MatrixOrDefault` at :138-143. The direction's claim "config-side pre-flight does not cover the DB" stands |
| `docs/config-reference.md` `oauth.scope_registry` row | VERIFIED | Row at line 20; enablement order pinned: land `matrix`/`extra_scopes` with `enabled: false` → staging `config validate` pre-flight surfaces dirty clients → fleet-wide flip |
| Real target schema has `allowed_scopes` | VERIFIED (supplementary) | `infrastructure/defaultimpl/sqlite/clients.go:42`: `allowed_scopes TEXT NOT NULL DEFAULT '[]'` (JSON-encoded `[]string`; marshaled at `clients_scan.go:41`, scanned at :289; `json.Marshal` of a nil slice yields `null`, so `'null'` occurs in real rows) |
| Dirty `allowed_scopes` 400s at mint time | VERIFIED (supplementary) | `protocols/oauth/oauthvalidate/scope.go` `GrantedScopes`: a requested scope must be in `client.AllowedScopes` (else `invalid_scope`); an empty request defaults to the allowlist (minus `openid`) — so an unregistered entry is minted by default and then rejected by the registry seam; `internal/handler/tokengrant/token_client_credentials.go:36-55` shows the post-resolution `RejectUnregistered` for client_credentials |
| Registry construction site | VERIFIED (supplementary) | `cmd/sso-server/build_stores.go:306`: `scoperegistry.NewMemory(cfg.OAuth.ScopeRegistry.MatrixOrDefault(), cfg.OAuth.ScopeRegistry.ExtraScopes)`; `interfaces/sso/options_misc.go:482-494` `WithScopeRegistry`; `scoperegistry/registry.go` `NewMemory` :68, `ProtocolScopes` :48, `Registered` :115 (exact-or-`domain:*`), `ValidatePattern` :136 |
| "Today exit 0" | VERIFIED | `main.go:35-62`: `buildReport` error → `reportError` → exit 1 (:52-55, :65-68), before the `cfg.Apply` write branch (:56-60); with no scope check the dirty plan reaches `printReport` and returns 0 (:61-62) |
| Import legality (cmd → scopecontract/scoperegistry) | VERIFIED (supplementary) | `architecture_layer_test.go:71`: `cmd` classifies as `composition` (rank 6, top) — downward imports of `interfaces/scopecontract` and `protocols/oauth/scoperegistry` are legal, no `layerExemptions` entry needed |

Consequence chain (all links verified): the target stores the scope allowlist
(`clients.go:42`) → the sync tool never reads it (`target.go:173-174`) → the
plan writes unregistered scope-shaped strings into `permissions_roles`
(`plan.go:109-116`, :186, :196-204) → under an enabled registry, `/token`
rejects them with 400 `invalid_scope` (`server_token.go:132` →
`scoperegistry/reject.go:31-43`) because `GrantedScopes` either defaults the
request to the dirty allowlist or admits only allowlisted entries
(`oauthvalidate/scope.go`), and the registry registers only matrix ∪ protocol
∪ extra (`build_stores.go:306`). The config-side gate catches this only for
YAML clients (`config_oauth2.go:58`), never for the offline DB. The single
gap is the sync tool.

## 3. Product boundary

- Surface: `sso-ctl legacy-sync` CLI (`cmd/sso-ctl/legacysync`); a read-only
  validation over the plan and the target SQLite database. No server, SDK,
  protocol, or wire-surface change.
- Default: gate OFF. `--scope-registry` is an explicit opt-in flag, mirroring
  `oauth.scope_registry.enabled` semantics and the enablement doctrine in
  docs/config-reference.md:20 (pre-flight precedes the fleet flip; default-off
  is byte-identical). An unconditional gate would fail every existing legacy
  deployment (its role codes/permissions are `legacy:*` strings) and
  contradicts the T-9 pin.
- Explicit non-goals (do not expand scope):
  - No change to `/token`, the registry, the matrix, or discovery: do-not-modify
    `interfaces/sso/server_token.go`, `protocols/oauth/scoperegistry/*`,
    `interfaces/scopecontract/*`, `config/config_oauth2.go`,
    `cmd/sso-server/build_stores.go` (T-2: no discovery-surface change).
  - No matrix-provisioning flag: the pre-flight uses the built-in
    `interfaces/scopecontract.Matrix()` plus `--scope-registry-extra` only;
    a config-file input or `--scope-registry-matrix` would be new scope.
  - No new `syncReport` field, no `printReport` change (T-9 byte-identical
    report; the tenant gate's `TestPrintReportGolden` stays the golden pin).
  - No audit/outbox rows, no source-TLS change, no tenant-gate rework (these
    are separate directions in the source analysis).
  - No `run()`-level MySQL harness: `run()` requires a live legacy MySQL
    source (`source.go` `openLegacyDB`) with no injection seam; the exit-code
    acceptance is discharged at the `buildReport` boundary plus the
    documented `run()` control flow (§6), exactly as the tenant gate did.
  - Role codes are gated because the direction names them as fabricated
    scope-shaped strings (`plan.go:186`); an operator reconciles the whole
    `legacy:*` family with one `--scope-registry-extra legacy:*` entry.

## 4. Requirements

### REQ-1 — CLI wiring (opt-in, fail-closed flags)

`parseFlags` (config.go:30-74) gains:

- `--scope-registry` (bool, default false): enable the scope-registry
  pre-flight; equivalent of `oauth.scope_registry.enabled: true` for the
  offline tree.
- `--scope-registry-extra` (string, default ""): comma-separated extra
  registered patterns (exact scope or `domain:*`), equivalent of
  `oauth.scope_registry.extra_scopes`. Providing it without `--scope-registry`
  is a parse error (exit 2) — a deliberate difference from config, where
  inert `extra_scopes` is tolerated for rollback; a per-invocation CLI flag
  must never silently no-op.
- Extra patterns are validated fail-closed at parse time by constructing the
  registry (`scoperegistry.NewMemory`; bare `*` and misplaced wildcards
  error), so a typo exits 2 like the existing `--role-map` validation
  (config.go:68-73) instead of silently widening the gate. To keep
  `parseFlags` under the 50-line budget, the flag-value validation lives in
  an extracted helper (e.g. `parseScopeRegistryFlags(cfg *commandConfig)
  error`).

`commandConfig` carries the built `scoperegistry.Registry` (nil when
unwired). `run()` (main.go:35-38) assigns it to the plan after `buildPlan`:
`plan.ScopeRegistry = cfg.ScopeRegistry` (nil default = unwired no-op).

### REQ-2 — snapshot carries raw allowed_scopes

`loadTargetClients` (target.go:169-190) extends its SELECT to
`SELECT id,COALESCE(tenant_id,''),COALESCE(allowed_scopes,'[]') FROM clients
WHERE active=1` and stores, per active client, the raw `allowed_scopes` text
in a new `targetSnapshot` field `ClientScopes map[string]string` (id → raw
JSON; `COALESCE` folds SQL NULL, which only hand-made schemas can hold — the
real schema is `NOT NULL DEFAULT '[]'`, clients.go:42).

Constraints:

- The `tenant_id` column stays BEFORE `allowed_scopes` in the SELECT list:
  the pinned missing-`tenant_id` failure (`TestLoadTargetClientsMissingTenantColumnFailsLoudly`,
  tenant_gate_test.go:163-172, fixture `testTargetSchemaNoTenantColumn` which
  lacks both columns) asserts the SQL error names `tenant_id`, and SQLite
  reports the first unknown column.
- The existing `Clients map[string]string` (id → tenant) is untouched, so the
  tenant-gate unit tests that construct `targetSnapshot{Clients: ...}`
  literally (tenant_gate_test.go) compile and pass unchanged.
- Raw text is parsed lazily inside the gate (REQ-3), never in
  `loadTargetClients`: an unwired run must not newly fail on a malformed
  JSON value (T-9 byte-identical).

### REQ-3 — the pre-flight gate

New function in a new file `scope_gate.go`:

```go
// validateScopeRegistration fails the plan when a mapped client declares, or
// an imported role writes, a scope the wired registry does not register.
// plan.ScopeRegistry == nil (unwired default) is a no-op.
func validateScopeRegistration(plan syncPlan, target targetSnapshot) error
```

Called from `buildReport` (target.go:216-249) immediately after
`validateMappedClientBindings` (line ~219-221), giving deterministic error
precedence: tenant/existence gate → scope gate → role-validation
(`validateMappedRoles`, :249). `buildReport` runs before the write branch in
both modes (main.go:52-60), so dry-run and `--apply` behave identically.

Checked sets, one uniform predicate `reg.Registered(s)` (exact-or-`domain:*`,
registry.go:115) for every string:

1. **S1 — client declarations**: for each mapped client (`plan.MappedClients`)
   present in `target.ClientScopes`, every entry of the parsed `allowed_scopes`
   JSON array. `'[]'` and `'null'` (both occur in real rows) parse to the
   empty set — no violation. A JSON parse error on a mapped client is a gate
   error naming that client (fail-closed: the real server would fail to load
   such a client too).
2. **S2 — imported role permissions**: for every `plan.Roles` entry, every
   member of `role.Permissions` (source permissions copied verbatim by
   `makePlannedRole` plan.go:109-116, plus the fabricated
   `menuPermission`/`overridePermission` strings plan.go:196-204). All planned
   roles belong to mapped clients by construction (buildPlan only plans roles
   for `appMap` clients), so no additional filtering is needed.
3. **S3 — imported role codes**: for every `plan.Roles` entry, `role.Code`
   (the `legacyRoleCode` shape `legacy:APP:ROLE`, plan.go:186) — a fabricated
   scope-shaped string the direction names; a token request could carry it.

Violations are deduplicated and sorted deterministically by (clientID, scope),
one error line per violation, joined with `errors.Join` (mirroring the tenant
gate's shape). Every line names the client id AND the scope. Proposed shape
(implementer may reword; must keep both names and the sorted one-line-per-
violation determinism):

```text
sso-ctl legacy-sync: mapped target client "web" scope "legacy:menu:1:view" is not registered by the scope registry (matrix + protocol scopes + extra_scopes)
```

The registry itself is built by `buildScopeRegistry(extra []string)
(scoperegistry.Registry, error)` = `scoperegistry.NewMemory(scopecontract.Matrix(), extra)`
— the exact construction the server uses (build_stores.go:306 with the
built-in matrix), so the pre-flight predicate can never disagree with `/token`.
The seven protocol scopes are pre-seeded by `NewMemory` (registry.go:48, :68)
and need no explicit extras.

### REQ-4 — success path and report are byte-identical (T-9)

- Unwired (`plan.ScopeRegistry == nil`): `validateScopeRegistration` returns
  nil immediately. `loadTargetClients` reads one extra column; the report,
  stdout, and exit code are byte-for-byte the pre-change behavior for every
  input that succeeds today (including malformed `allowed_scopes` JSON).
- Wired with everything registered: `buildReport` passes, `syncReport` gains
  no field, `printReport` (main.go:70-78) output is byte-identical (the
  tenant gate's `TestPrintReportGolden` remains the pin).
- Wired with violations: exit 1 via `reportError` (main.go:65-68) in both
  modes, no report printed, no write performed (buildReport precedes the
  `cfg.Apply` branch at main.go:56).
- Error texts of the existing gates (existence :199, tenant :211, role
  validation :249) are unchanged.

### REQ-5 — unit tests (cmd/sso-ctl/legacysync)

New file `scope_gate_test.go` (mirroring tenant_gate_test.go structure), with
a helper `wireRegistry(t, extra ...string) scoperegistry.Registry`:

- **S1 negative**: `plan.MappedClients{"web"}`, wired registry,
  `target.ClientScopes{"web": `["legacy:menu:1:view"]`}` →
  `buildReport(plan, target, "dry-run")` and `"applied"` both error; the error
  names `"web"` AND `"legacy:menu:1:view"` (T-8d negative).
- **S1 positive, matrix-covered**: `allowed_scopes = ["admin:read"]` → both
  modes pass.
- **S1 positive, extra-covered**: same unregistered string, registry wired
  with extra `legacy:*` → both modes pass (extra_scopes reconciliation).
- **S2/S3 negative**: a planned role whose `Code` or `Permissions` contains an
  unregistered string → error names the client and the string; with extra
  `legacy:*` (and, for a source permission like `content:read`, extra
  `content:read`) → passes.
- **Unwired no-op**: `plan.ScopeRegistry == nil` with unregistered
  `allowed_scopes` → both modes pass (T-9).
- **Parse-error fail-closed**: `allowed_scopes = "not-json"` on a mapped
  client, wired → error names the client.
- **Determinism**: two violations across clients/scopes → both named, sorted
  (assert relative order, as tenant_gate_test.go U3 does).
- **Malformed extra flag**: `--scope-registry-extra "*"` → parse error
  (exit-2 path via `parseFlags`), mirroring the grammar fail-closed tests in
  `config/scope_registry_test.go`.

Fixture updates (target_test.go): `testTargetSchema` (:150-160) and
`testTargetSchemaNullableClients` (:166-176) gain
`allowed_scopes TEXT NOT NULL DEFAULT '[]'` on `clients` (real-schema parity,
clients.go:42); `seedTarget`'s `INSERT INTO clients(id,active,tenant_id)`
(:72) needs no change (column default). New fixture
`testTargetSchemaNoAllowedScopesColumn` (clients with `tenant_id`, without
`allowed_scopes`) plus a test asserting `loadTargetClients` fails loudly with
a SQL error naming `allowed_scopes` (mirrors U7, tenant_gate_test.go:163-172).
The existing tests keep their names and final assertions unchanged.

### REQ-6 — integration assertion in test/ (T-8d positive)

New `test/legacy_sync_scope_registry_test.go` (package `ssotest`), reusing
the synced-deployment shape of `test/legacy_sync_tenant_claim_test.go`
(real `sqlitestores.NewClientStore`/`NewPasswordCredentialStore`,
`MemoryUserProvider`, password authenticator, Ed25519 JWT issuer) and the
`/token` driving pattern of `test/handle_token_test.go` (`postToken`, body
`client_id`/`client_secret`):

- Deployment: clients row active, `AllowedScopes: []string{"admin:read"}`,
  secret set (confidential client), `TokenStrategy: "jwt"`; server wired with
  `sso.WithScopeRegistry(reg)` where
  `reg, _ := scoperegistry.NewMemory(scopecontract.Matrix(), nil)`.
- Positive leg: `POST /token` with `grant_type=client_credentials`,
  `scope=admin:read` → 200 with an `access_token` (the "subsequent /token
  mint against the synced deployment returns 200" check; `admin:read` is a
  matrix scope, so the dispatch seam and the post-resolution check both pass).
- Negative leg: same request with `scope=legacy:menu:1:view` → 400
  `{"error":"invalid_scope"}` — pins the exact runtime predicate the sync
  tool's pre-flight mirrors, so the two halves of T-8d are mutually
  consistent.
- Optional extra-reconciliation leg: server wired with
  `NewMemory(scopecontract.Matrix(), []string{"legacy:*"})` →
  `scope=legacy:menu:1:view` returns 200, proving `--scope-registry-extra`
  tracks the runtime predicate end-to-end.

## 5. Acceptance criteria (preserved, with testable form)

1. **T-8d (negative):** given a target clients row whose `allowed_scopes`
   contains an unregistered scope (e.g. `'legacy:menu:1:view'`),
   `legacy-sync --apply` exits 1 and buildReport names the client id and
   scope — today it exits 0.
   Testable form: REQ-5 S1-negative unit test calls
   `buildReport(plan, target, "applied")` with a wired registry and asserts
   the error contains both `"web"` and `"legacy:menu:1:view"`; the exit-1
   path follows from the unchanged `run()` control flow (main.go:52-55 →
   `reportError` :65-68 → return 1, before the write branch :56), the same
   discharge used by the tenant-gate spec; "today exit 0" is pinned by the
   REQ-5 unwired no-op test (nil registry → pass) and the byte-identical
   report test.
2. **T-8d (positive):** given the same `allowed_scopes` covered by matrix
   (`interfaces/scopecontract.Matrix`) or `extra_scopes`, dry-run and apply
   pass unchanged, and a subsequent `/token` mint against the synced
   deployment returns 200 (integration in test/).
   Testable form: REQ-5 S1-positive matrix/extra tests for both modes; REQ-6
   integration test drives `/token` client_credentials with a matrix scope
   against the synced-deployment shape and asserts 200 (and 400
   `invalid_scope` for the unregistered string, pinning the mirrored
   predicate).
3. **T-2:** no discovery-surface change.
   Testable form: no file under `interfaces/`, `protocols/`,
   `infrastructure/`, `config/`, or `cmd/sso-server` is modified (REQ-6 wires
   the registry only through the existing `sso.WithScopeRegistry` option);
   discovery snapshot tests are untouched and stay green.
4. **T-9:** with no registry wiring (or scopes all registered) the
   report/stdout stays byte-identical to the pre-change binary.
   Testable form: REQ-4 unwired no-op and pass-through pins; REQ-5 unwired
   test; the unchanged `TestPrintReportGolden` golden; existing
   plan/target/tenant tests keep names and assertions, with fixtures only
   gaining the `allowed_scopes` column (REQ-5).

## 6. Files

### Create

```text
cmd/sso-ctl/legacysync/scope_gate.go — buildScopeRegistry + validateScopeRegistration (REQ-1, REQ-3)
cmd/sso-ctl/legacysync/scope_gate_test.go — gate + flag-validation unit tests (REQ-5); _test.go does not count against the package file ceiling
test/legacy_sync_scope_registry_test.go — /token mint integration, synced-deployment shape (REQ-6)
docs/architect-analysis/cmd-sso-ctl-legacysync-scope-registry-preflight-requirements.md — this spec
```

### Modify

```text
cmd/sso-ctl/legacysync/config.go — two flags + extracted parseScopeRegistryFlags helper (REQ-1). Budget: parseFlags is 45 lines today; the helper extraction keeps it under 50; config.go ~79 → ~100 lines (under 500)
cmd/sso-ctl/legacysync/model.go — targetSnapshot.ClientScopes map[string]string and syncPlan.ScopeRegistry scoperegistry.Registry fields (REQ-2, REQ-3); +1 import, ~2 lines
cmd/sso-ctl/legacysync/target.go — loadTargetClients SELECT + ClientScopes fill (REQ-2); buildReport calls validateScopeRegistration after validateMappedClientBindings (REQ-3). Budget: 435 → ~445 lines (under 500); gate function lives in scope_gate.go; loadTargetClients stays under 50; no new nested branching beyond 3
cmd/sso-ctl/legacysync/main.go — plan.ScopeRegistry = cfg.ScopeRegistry after buildPlan (REQ-1), ~2 lines
cmd/sso-ctl/legacysync/target_test.go — fixtures gain allowed_scopes column; new NoAllowedScopesColumn fixture (REQ-5)
```

Package budget check: non-test Go files go 7 → 8 (≤ 10 per directory);
`interfaces/sso` untouched (60-file ceiling intact).

### Do not modify

```text
interfaces/sso/server_token.go — dispatch seam and invalid_scope shape already correct (:132, :189-207)
protocols/oauth/scoperegistry/*, interfaces/scopecontract/* — registry, matrix, predicate unchanged
config/config_oauth2.go, cmd/sso-server/build_stores.go — YAML-side gate and server wiring unchanged (the DB-side gap this direction closes)
cmd/sso-ctl/legacysync/plan.go, source.go — plan shape and source load unchanged (the gate reads the plan as-is)
infrastructure/defaultimpl/sqlite/clients.go — real schema already has allowed_scopes (:42); no migration
```

## 7. Dependencies and compatibility

- New SPI / option / YAML key / storage migration: none. Two CLI flags on
  `legacy-sync`; the pre-flight reuses `scoperegistry.NewMemory` +
  `scopecontract.Matrix()` unchanged.
- HTTP/proto compatibility: none — no endpoint, no wire error code, no
  discovery change (T-2). The failure is a stderr diagnostic plus exit 1.
  Per AGENTS.md §5.6 no doc-contract update is required (no new `Err*`,
  endpoint, or config knob; the flags' help text in config.go is the
  contract; `legacy-sync` is absent from docs/config-reference.md and
  docs/feature-matrix.md). This spec lands in docs/architect-analysis/
  alongside the tenant-gate spec.
- Oracle/security posture: unchanged — the gate introduces no new response
  surface. When wired, the sync tool's predicate is construction-identical
  to the runtime registry (`NewMemory(Matrix(), extra)` at build_stores.go:
  306 vs REQ-3), so it can never disagree with `/token`; when unwired it is
  a strict no-op (byte-compat pin, T-9).
- Rollout/rollback: the gate is opt-in. A deployment synced with
  `--scope-registry` is strictly safer than before (dirty `allowed_scopes`
  or unregistered imported strings fail pre-apply); reverting the change
  restores today's behavior exactly. Rollout order mirrors
  docs/config-reference.md:20: wire `--scope-registry-extra` first in a
  dry-run, fix flagged clients, then flip `--scope-registry` fleet-wide.

## 8. Verification plan

Mandatory after every `.go` edit:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Targeted:

```bash
go test ./cmd/sso-ctl/legacysync/ -run 'TestScope|TestBuildReport|TestLoadTargetClients|TestParseFlags|TestPrintReportGolden' -v
go test ./test/ -run 'TestLegacySyncScopeRegistry' -v
```

Handoff (proportional to a small, self-contained CLI change):

```bash
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```
