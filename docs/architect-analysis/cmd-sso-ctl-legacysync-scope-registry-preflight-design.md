# Design: scope-registry pre-flight for the offline deploy tree (cmd/sso-ctl/legacysync)

Companion to
`docs/architect-analysis/cmd-sso-ctl-legacysync-scope-registry-preflight-requirements.md`.
This document treats that spec (and the evidence summary that cites it) as
untrusted claims, records what was independently re-verified against the
worktree, and turns the requirements into a concrete, ordered design with API
changes, compatibility constraints, failure modes, migration steps, and
testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against the worktree (HEAD). All substantive
claims are **verified**; the spec's own location corrections (the merged
tenant-binding gate moving `loadTargetClients`/`buildReport`) are confirmed
against the actual code. Two findings are recorded below: one test-mechanism
defect (D2) that the design repairs, and one non-material arithmetic slip
(D1).

| # | Claim | Verdict |
|---|---|---|
| E1 | `loadTargetClients` never reads `allowed_scopes`; SELECT is `SELECT id,COALESCE(tenant_id,'') FROM clients WHERE active=1` at target.go:173-174 | Confirmed exactly. The tenant column is the merged sibling gate; `allowed_scopes` is still absent |
| E2 | `buildReport` has no scope check; `validateMappedClientBindings` at target.go:194-214 (existence error :199, tenant error :211), `buildReport` :216-249, `validateMappedRoles` call at :249 | Confirmed exactly |
| E3 | plan.go fabrications: `legacyRoleCode` :186 (`legacy:APP:ROLE` via `managedPrefix` :185), `menuPermission` :196 (`legacy:menu:ID:action`), `overridePermission` :200-204 (`legacy:action:ID:action`), `planGrants` roleMap :130 (reconciles only assignment codes), `makePlannedRole` :109-116 copies `role.Permissions` verbatim | Confirmed exactly (plan.go lines match) |
| E4 | Registry seam: `dispatchTokenGrant` at server_token.go:122 calls `s.rejectUnregisteredScopes` at :132 before all grant branches; `rejectUnregisteredScopes` comment :189, func :203; plain 400 `invalid_scope` body | Confirmed. `scoperegistry/reject.go:31-43` (`RejectUnregistered`): nil/empty = no-op, else `400 core.ErrorBody(core.ErrInvalidScope)`; byte-identical body pinned by registry_test.go:191-192 |
| E5 | Nine-scope `Matrix` at interfaces/scopecontract/consts.go:25-36 | Confirmed exactly (nine scope-matrix-v2 scopes incl. `admin:*`) |
| E6 | Config gate is YAML-only: `validateScopeRegistry` config_oauth2.go:30-66; membership check only when `Enabled` (:49), iterates `c.Clients` (:58) | Confirmed exactly |
| E7 | docs/config-reference.md:20 scope_registry row with the enablement order (land matrix/extra with `enabled:false` → staging `config validate` pre-flight → fleet flip) | Confirmed exactly (row at line 20) |
| E8 | Real schema `allowed_scopes TEXT NOT NULL DEFAULT '[]'` at sqlite/clients.go:42; marshaled at clients_scan.go:41, scanned at :289; `json.Marshal(nil)` yields `'null'` in real rows | Confirmed. clients_scan.go:41 marshals, :289 scans |
| E9 | `GrantedScopes` (oauthvalidate/scope.go:80) — rule 4: empty request defaults to the allowlist minus `openid`; rule 1: requested must be allowlisted | Confirmed |
| E10 | Registry construction at build_stores.go:306 (`NewMemory(MatrixOrDefault(), ExtraScopes)` when enabled); `WithScopeRegistry` at options_misc.go:494; `NewMemory` registry.go:68 (fail-closed grammar), `Registered` :115 (exact-or-`domain:*`), `ValidatePattern` :136 | Confirmed exactly |
| E11 | Post-resolution `RejectUnregistered` in token_client_credentials.go (grantCCScopes after `GrantedScopes`) | Confirmed (lines 36-55 region) |
| E12 | "Today exit 0": main.go buildReport error → `reportError` → 1 (:52-55, :65-68) before the `cfg.Apply` write branch (:56-60); dirty plan reaches `printReport` and returns 0 | Confirmed. `run()` at main.go:30-63 |
| E13 | Import legality: architecture_layer_test.go:71 classifies `cmd` as `composition` (top); downward imports of `interfaces/scopecontract` and `protocols/oauth/scoperegistry` legal, no `layerExemptions` entry | Confirmed (cmd/sso-server already imports `scoperegistry` at build_stores.go:306) |
| E14 | Fixtures: `testTargetSchema` :150, `testTargetSchemaNullableClients` :166, `testTargetSchemaNoTenantColumn` :182 (lacks BOTH `tenant_id` and `allowed_scopes`), `seedTarget` INSERT :72; U7 test tenant_gate_test.go:162-172 | Confirmed exactly — the U7 pin (`SQL error names tenant_id`) is why the new column must trail `tenant_id` in the SELECT list |
| E15 | Harnesses: test/legacy_sync_tenant_claim_test.go (`newLegacySyncDeployment`: real sqlite client/password stores, `MemoryUserProvider`, password authenticator, Ed25519 issuer) and test/handle_token_test.go `postToken` (:56, body `client_id`/`client_secret`) | Confirmed. `newLegacySyncDeployment` does NOT set `AllowedScopes` (defaults empty) and does not wire `WithScopeRegistry` — the new harness extends it |
| E16 | Budgets: target.go 435 lines, config.go 79, `parseFlags` 45 (config.go:30-74), `TestPrintReportGolden` at tenant_gate_test.go:179 | Confirmed |
| D1 | Spec §6: "non-test Go files go 7 → 8" | **Arithmetic slip, non-material**: the package has 6 non-test files today (config, main, model, plan, source, target). Correct statement: 6 → 7 with `scope_gate.go`, still ≤ 10 |
| D2 | REQ-6 negative leg: deployment with `AllowedScopes: ["admin:read"]`, request `scope=legacy:menu:1:view` → 400 `invalid_scope` "pins the exact runtime predicate" | **Mechanism defect**: the 400 would come from the *allowlist* gate (`GrantedScopes` rule 1 — requested not in allowlist), not the registry seam. Same byte-identical body, so the acceptance text holds, but the test would not pin what it claims to pin. The design (§7.3) seeds the dirty-client shape (`AllowedScopes: ["admin:read","legacy:menu:1:view"]`) so the registry seam is the rejecting gate, and the extra-reconciliation leg (registry with `legacy:*`) then returns 200 |

Consequence chain (all links verified): target stores the allowlist
(clients.go:42) → the tool never reads it (target.go:173-174) → the plan
writes unregistered scope-shaped strings into `permissions_roles`
(plan.go:109-116, :186, :196-204) → under an enabled registry `/token`
rejects them with 400 `invalid_scope` (server_token.go:132 →
reject.go:31-43) because `GrantedScopes` either defaults the request to the
dirty allowlist or admits only allowlisted entries (oauthvalidate/scope.go:80)
and the registry registers only matrix ∪ protocol ∪ extra
(build_stores.go:306). The config-side gate covers only YAML clients
(config_oauth2.go:58). The single gap is the sync tool. The requirements
spec is **sound**; the design below implements it with the D2 repair.

## 2. Design overview

`legacy-sync` gains an opt-in, fail-closed scope-registry pre-flight: when
the operator passes `--scope-registry` (with optional
`--scope-registry-extra` reconciliation), `buildReport` refuses — exit 1,
one deterministic line per violation naming the client id and the scope —
any plan whose mapped clients declare, or whose imported roles write, a
scope the registry does not register. Unwired, the tool is byte-identical
to today.

The predicate is construction-identical to the runtime server registry:
`scoperegistry.NewMemory(scopecontract.Matrix(), extras)` — the exact
expression at build_stores.go:306 with the built-in matrix — so the
pre-flight can never disagree with `/token`. The registry is built once at
flag-parse time (typos exit 2, never silently widening the gate) and carried
on the plan into `buildReport`.

Data flow:

```text
parseFlags ──(--scope-registry, --scope-registry-extra)──▶ parseScopeRegistryFlags
                                                              │  builds (exit 2 on grammar errors)
                                                              ▼
                                              commandConfig.ScopeRegistry (nil = unwired)
                                                              │
run() ── plan.ScopeRegistry = cfg.ScopeRegistry ─────────────┘
                                                              │
inspectTarget ──▶ loadTargetClients ──▶ targetSnapshot.ClientScopes (id → raw allowed_scopes text)
                                                              │
buildReport ── validateMappedClientBindings (tenant/existence)   (unchanged, :194-214)
           └─▶ validateScopeRegistration (plan, target)          (new; nil registry = no-op)
           └─▶ user-collision loops + validateMappedRoles        (unchanged)
```

Error precedence is deterministic: existence/tenant gate → scope gate →
user-collision → role-assignment. The gate runs before the `cfg.Apply` write
branch in both modes (main.go:52-60), so dry-run and `--apply` behave
identically and a failing plan never writes.

## 3. API changes

No server, SDK, protocol, discovery, or wire-surface change (T-2). The only
API surface is the `sso-ctl legacy-sync` CLI plus package-internal Go
symbols in `cmd/sso-ctl/legacysync`.

### 3.1 CLI (config.go)

Two flags registered in `parseFlags` (config.go:30-74):

| Flag | Type | Default | Meaning |
|---|---|---|---|
| `--scope-registry` | bool | `false` | Enable the pre-flight; the offline-tree equivalent of `oauth.scope_registry.enabled: true`. Absent/false = nil registry = byte-identical no-op |
| `--scope-registry-extra` | string | `""` | Comma-separated extra registered patterns (exact scope or `domain:*`), the equivalent of `oauth.scope_registry.extra_scopes`. Providing it without `--scope-registry` is a parse error (exit 2) — deliberate difference from YAML config, where inert `extra_scopes` is tolerated for rollback; a per-invocation flag must never silently no-op |

Help text (the flag contract; `legacy-sync` is absent from
docs/config-reference.md and docs/feature-matrix.md, so no doc-contract
update is required per AGENTS.md §5.6) mirrors the `oauth.scope_registry`
row's doctrine: the gate checks mapped clients' `allowed_scopes` and
imported role codes/permissions against matrix ∪ protocol scopes ∪ extras;
protocol scopes (`openid`, `device_sso`, `profile`, `email`, `address`,
`phone`, `offline_access`) are pre-seeded and need no extras.

New internal symbols:

```go
// commandConfig (config.go)
ScopeRegistry scoperegistry.Registry // nil = unwired no-op

// parseScopeRegistryFlags validates the two flags fail-closed and builds
// the registry via buildScopeRegistry. Called from parseFlags after the
// existing role-map validation (config.go:68-73); every error path exits 2
// through the established parseFlags → run() return-2 flow (main.go:30-34).
func parseScopeRegistryFlags(cfg *commandConfig) error
```

`parseScopeRegistryFlags` ordering (deterministic error precedence):
1. `--scope-registry-extra` present (non-empty after trim) without
   `--scope-registry` → error, exit 2.
2. Split on `,`, trim spaces, drop empty segments.
3. `cfg.ScopeRegistry, err = buildScopeRegistry(extras)` — a bare `*` or
   any non-`:*` wildcard fails `ValidatePattern` at construction (exit 2),
   so a typo never silently widens the gate.

Budget: `parseFlags` is 45 lines today; the two `fs.Var`/`fs.BoolVar`
registrations plus one helper call add ~3 lines (48 ≤ 50). The helper
(~15 lines) and the registry field (~2 lines) bring config.go to ~100 lines
(< 500).

### 3.2 Model (model.go)

```go
// syncPlan gains:
ScopeRegistry scoperegistry.Registry // nil = unwired no-op (T-9)

// targetSnapshot gains:
// ClientScopes carries each active client's raw allowed_scopes JSON text
// (id → raw). Parsed lazily inside the gate only: an unwired run never
// looks at it, so malformed values cannot regress the byte-compat baseline.
ClientScopes map[string]string
```

`syncPlan.ScopeRegistry` is the carrier rather than a `buildReport`
parameter so the function signature is untouched and every existing
`buildReport(plan, target, mode)` call (tenant_gate_test.go, target_test.go)
compiles unchanged. `targetSnapshot.ClientScopes` is additive: existing
literal constructions (`targetSnapshot{Clients: ...}`) keep compiling.

### 3.3 Target load (target.go)

`loadTargetClients` (target.go:169-190) SELECT becomes:

```sql
SELECT id,COALESCE(tenant_id,''),COALESCE(allowed_scopes,'[]') FROM clients WHERE active=1
```

- `tenant_id` stays BEFORE `allowed_scopes`: the pinned
  `TestLoadTargetClientsMissingTenantColumnFailsLoudly` fixture
  (`testTargetSchemaNoTenantColumn`, target_test.go:182) lacks BOTH
  columns, and SQLite reports the first unknown column — the error must
  keep naming `tenant_id` (U7 pin, tenant_gate_test.go:162-172).
- `COALESCE(allowed_scopes,'[]')` folds SQL NULL (only hand-made schemas;
  real schema is `NOT NULL DEFAULT '[]'`, clients.go:42). `'[]'` and
  `'null'` (`json.Marshal(nil)` legacy rows) both parse to the empty set
  at gate time.
- Raw text only: no JSON parsing here, so unwired runs never newly fail
  (T-9).
- Nil-map guard: `if s.ClientScopes == nil { s.ClientScopes = ... }` before
  filling, because direct-call tests (e.g. U7) construct snapshots without
  the new map. `inspectTarget` also initializes it at construction.

### 3.4 The gate (new file scope_gate.go)

```go
// buildScopeRegistry is the single construction site for the pre-flight:
// the exact server expression (build_stores.go:306) with the built-in
// matrix, so the predicate can never disagree with /token. Grammar is
// fail-closed (bare "*" and misplaced wildcards error).
func buildScopeRegistry(extra []string) (scoperegistry.Registry, error) {
    return scoperegistry.NewMemory(scopecontract.Matrix(), extra)
}

// validateScopeRegistration fails the plan when a mapped client declares,
// or an imported role writes, a scope the wired registry does not register.
// plan.ScopeRegistry == nil (unwired default) is a strict no-op (T-9).
// Called from buildReport immediately after validateMappedClientBindings.
func validateScopeRegistration(plan syncPlan, target targetSnapshot) error
```

Gate algorithm (single uniform predicate `reg.Registered(s)`, exact-or-
`domain:*`, registry.go:115, for every string):

1. **S1 — client declarations**: for each `plan.MappedClients` id, parse
   `target.ClientScopes[id]` as a JSON `[]string` (`'[]'`/`'null'` → empty;
   a parse error on a mapped client is a gate error naming that client —
   fail-closed, the real server would fail to load such a client too) and
   check every entry.
2. **S2 — imported role permissions**: for every `plan.Roles` entry, every
   member of `role.Permissions` (verbatim source permissions plus the
   `menuPermission`/`overridePermission` fabrications). All planned roles
   belong to mapped clients by construction (buildPlan appends roles only
   for `appMap` clients, plan.go:34; `planOverrides` likewise, plan.go:138-141),
   so no additional filtering is needed.
3. **S3 — imported role codes**: for every `plan.Roles` entry, `role.Code`
   (the `legacy:APP:ROLE` fabrication, plan.go:186) — the direction names
   these as scope-shaped strings a token request could carry.

Violations are deduplicated on (clientID, scope) — the same string can
appear in S1 and S2 for one client — sorted deterministically by clientID
then scope, one error line per violation, joined with `errors.Join`
(mirroring the tenant gate's shape). Line shape, keeping the config-side
parenthetical verbatim so operators recognize the doctrine (config_oauth2.go:60):

```text
mapped target client "web" scope "legacy:menu:1:view" is not registered by the scope registry (matrix + protocol scopes + extra_scopes)
```

(`reportError`, main.go:65-68, prefixes `sso-ctl legacy-sync: ` and returns
1.)

`buildReport` (target.go:216-249) gains one call after
`validateMappedClientBindings` (:221):

```go
if err := validateScopeRegistration(plan, target); err != nil {
    return syncReport{}, err
}
```

target.go stays ~435 → ~445 lines (< 500); the gate function lives in
scope_gate.go (~45 lines, ≤ 50, cyclo ~8 ≤ 15, nesting ≤ 2).

### 3.5 Wiring (main.go)

After `buildPlan` (:36-38):

```go
plan.ScopeRegistry = cfg.ScopeRegistry
```

No import change in main.go; the field is on the plan already.

## 4. Compatibility constraints

1. **Unwired byte-identical (T-9)**: nil registry short-circuits the gate;
   `allowed_scopes` is read as one extra SELECT column but never parsed;
   the report, stdout, and exit code are byte-for-byte pre-change behavior
   for every input that succeeds today, including malformed `allowed_scopes`
   JSON. `TestPrintReportGolden` (tenant_gate_test.go:179) stays the golden
   pin. `syncReport` gains no field; `printReport` is untouched.
2. **U7 pin preserved**: `tenant_id` precedes `allowed_scopes` in the
   SELECT list, so the missing-`tenant_id` SQL error text is unchanged
   (target_test.go:182 fixture lacks both columns).
3. **Existing tests compile and pass unchanged**: `buildReport` signature
   unchanged; `targetSnapshot.Clients` untouched; fixture inserts rely on
   the new column's default (`INSERT INTO clients(id,active,tenant_id)` at
   target_test.go:72 needs no change); existing tests keep names and final
   assertions. `testTargetSchema` (:150) and `testTargetSchemaNullableClients`
   (:166) gain `allowed_scopes TEXT NOT NULL DEFAULT '[]'` (real-schema
   parity).
4. **Error texts of existing gates unchanged**: existence (:199), tenant
   (:211), role-assignment (target.go:262).
5. **No server-side change (T-2)**: `interfaces/sso/server_token.go`,
   `protocols/oauth/scoperegistry/*`, `interfaces/scopecontract/*`,
   `config/config_oauth2.go`, `cmd/sso-server/build_stores.go` are not
   modified. The integration test wires the registry only through the
   existing `sso.WithScopeRegistry` option.
6. **Import legality**: `cmd` classifies as `composition` (architecture_layer_test.go:71, top rank); the new downward edges to
   `interfaces/scopecontract` and `protocols/oauth/scoperegistry` are legal
   (cmd/sso-server already imports `scoperegistry`). No `layerExemptions`
   entry, no new package.
7. **Oracle/security posture unchanged**: the gate is a CLI diagnostic, not
   a response surface; it names the client id and scope in stderr exactly
   as `sso-ctl config validate` already does for YAML clients. When wired,
   the predicate is construction-identical to the runtime registry; when
   unwired it is a strict no-op.
8. **Budgets**: parseFlags 45 → 48 (helper extraction); config.go 79 → ~100;
   target.go 435 → ~445; scope_gate.go new (~45-line function); non-test
   files 6 → 7 (≤ 10; correction of the spec's 7 → 8); `interfaces/sso`
   60-file ceiling untouched; no function exceeds 50 lines, cyclo 15, or
   nesting 3.
9. **CLI semantics are intentionally stricter than YAML**: `extra_scopes`
   without `enabled` is tolerated in config (rollback-friendly); the same
   combination on the CLI is an exit-2 error (a per-invocation flag must
   not silently no-op). Documented in the flag help text.

## 5. Failure modes

| # | Condition | Behavior | Containment |
|---|---|---|---|
| F1 | Unwired (`--scope-registry` absent) | Gate no-ops; `allowed_scopes` never parsed | Byte-identical baseline (T-9); malformed JSON in real rows cannot regress unwired runs |
| F2 | `--scope-registry-extra` without `--scope-registry` | Exit 2 at parse time, message names the flag | No silent no-op; operator corrects the invocation |
| F3 | Extra pattern violates grammar (`"*"`, `"admin*"`, empty) | Exit 2 at parse time via `NewMemory`/`ValidatePattern` | Fail-closed at parse: a typo can never silently widen the gate (mirrors config boot behavior, config_oauth2.go:33-48) |
| F4 | Target `clients` lacks `allowed_scopes` column (pre-gate hand-made schema) | `loadTargetClients` SQL error naming `allowed_scopes` → exit 1 via `reportError` | Loud failure; server-created targets always have the column (clients.go:42). New fixture + test pin this (mirrors U7) |
| F5 | Target `clients` lacks `tenant_id` column | Unchanged existing error naming `tenant_id` (U7 pin) | Column-order constraint in the SELECT |
| F6 | Mapped client's `allowed_scopes` is malformed JSON | Gate error naming the client, exit 1 | Fail-closed: the real server would fail to load the client's scopes too |
| F7 | Mapped client declares / role writes an unregistered scope | Exit 1 in both modes; deduped sorted lines naming client id AND scope; no report printed, no write performed (gate precedes the `cfg.Apply` branch, main.go:56) | The exact acceptance T-8d negative |
| F8 | SQL NULL `allowed_scopes` (hand-made schemas) | `COALESCE` folds to `'[]'` → empty set → pass | Consistent with tenant-column handling |
| F9 | `'null'` / `'[]'` legacy JSON | Parse to empty set → pass | Real rows (json.Marshal(nil)) cannot false-fail |
| F10 | Registry construction error mid-run | Impossible by construction: the registry is built at parse time (exit 2) and only carried; `buildScopeRegistry` errors surface in F3 | Single construction site, one failure window |
| F11 | Multiple violations | All reported (deduped, sorted), `errors.Join`; deterministic order for tests | Mirrors the tenant gate's shape |
| F12 | Pre-existing gate failures (existence/tenant/role) | Their error texts and precedence are unchanged; scope gate runs after tenant/existence, before role-assignment | Deterministic error precedence documented in §2 |

## 6. Migration steps

1. **No storage migration**: the real target schema has had
   `allowed_scopes TEXT NOT NULL DEFAULT '[]'` since v1 (clients.go:42); the
   tool only gains a read of an existing column. No new table, index, or
   default.
2. **No config migration**: two additive CLI flags; `legacy-sync` appears in
   neither docs/config-reference.md nor docs/feature-matrix.md, so no
   contract document changes (AGENTS.md §5.6). The requirements spec and
   this design land in docs/architect-analysis/ alongside the tenant-gate
   pair.
3. **Rollout** (adapted from the config enablement doctrine,
   docs/config-reference.md:20): the gate is opt-in, so the fleet flip is a
   per-run flag, not a coordinated config change:
   - Phase 1 — enumerate: dry-run with
     `--scope-registry --scope-registry-extra '<patterns>'`. Every
     violation names client id and scope; the operator learns the full
     `legacy:*` family plus any verbatim source permissions (S2 strings are
     not all `legacy:`-prefixed — e.g. a copied `content:read` permission
     must be registered too).
   - Phase 2 — reconcile: fix dirty clients' `allowed_scopes` or extend
     `--scope-registry-extra` until the dry-run passes. One
     `--scope-registry-extra legacy:*` entry reconciles the whole
     fabricated family (role codes, menu permissions, override
     permissions).
   - Phase 3 — apply: `--apply` with the same flags; a passing pre-flight
     guarantees no synced client 400s at mint time for the checked sets.
   - Rollback: drop the flags; the binary reverts to today's behavior
     exactly (no server-side state was touched — the gate is read-only over
     the plan and the target DB).
4. **Wire compatibility**: none — no endpoint, error code, discovery
   document, or option SPI changes. The `/token` 400 `invalid_scope` shape
   that motivates the gate is pre-existing and untouched.

## 7. Testable acceptance mapping

### 7.1 Acceptance check mapping

| Acceptance (spec §5) | Testable form |
|---|---|
| T-8d negative: `--apply` exits 1 and buildReport names client id + scope for a dirty `allowed_scopes`; today exit 0 | REQ-5 `TestScopeGate*` S1-negative unit test: `buildReport(plan, target, "applied")` (and `"dry-run"`) with wired registry errors containing both `"web"` and `"legacy:menu:1:view"`. Exit-1 follows from the unchanged `run()` control flow (main.go:52-55 → `reportError` :65-68 → return 1, before the write branch :56) — the same discharge the tenant-gate spec used; "today exit 0" is pinned by the unwired no-op test and the golden report test |
| T-8d positive: matrix- or extra-covered scopes pass; subsequent `/token` mint returns 200 | REQ-5 S1-positive matrix (`admin:read`) and extra (`legacy:*`) tests for both modes; REQ-6 integration drives `/token` client_credentials against the synced-deployment shape → 200 with `access_token` |
| T-2: no discovery-surface change | No file under `interfaces/`, `protocols/`, `infrastructure/`, `config/`, or `cmd/sso-server` modified; REQ-6 wires the registry only through existing `sso.WithScopeRegistry`; discovery snapshot tests untouched and green |
| T-9: no wiring (or all registered) → byte-identical report/stdout | Unwired no-op gate test; unchanged `TestPrintReportGolden`; existing plan/target/tenant tests keep names and assertions (fixtures only gain the column) |

### 7.2 Unit — `cmd/sso-ctl/legacysync/scope_gate_test.go` (new)

Helper `wireRegistry(t *testing.T, extra ...string) scoperegistry.Registry`
(= `buildScopeRegistry`; construction error fails the test). Test matrix
(REQ-5):

- S1 negative: `plan.MappedClients{"web"}`, wired, `ClientScopes{"web":
  '["legacy:menu:1:view"]'}` → both modes error naming `"web"` AND
  `"legacy:menu:1:view"`.
- S1 positive matrix: `["admin:read"]` → both modes pass.
- S1 positive extra: same unregistered string, registry with `legacy:*` →
  pass.
- S2/S3 negative: planned role with unregistered `Code` or `Permissions`
  member → error names client and string; with `legacy:*` (plus the
  verbatim permission, e.g. `content:read`, as an extra) → pass.
- Unwired no-op: `plan.ScopeRegistry == nil` with dirty `allowed_scopes` →
  pass both modes (T-9).
- Parse-error fail-closed: `allowed_scopes = "not-json"` on a mapped client,
  wired → error names the client (F6).
- `'null'` and `'[]'` raw values → pass, wired (F9).
- Determinism: two violations across clients → both named, sorted relative
  order asserted (as tenant_gate_test.go U3 does).
- Flag validation: `--scope-registry-extra "*"` → parse error; extra
  without `--scope-registry` → parse error (exit-2 paths via `parseFlags`),
  mirroring config/scope_registry_test.go's fail-closed grammar tests.

Fixture updates (target_test.go): `testTargetSchema` and
`testTargetSchemaNullableClients` gain `allowed_scopes TEXT NOT NULL
DEFAULT '[]'` on `clients`; new `testTargetSchemaNoAllowedScopesColumn`
(clients with `tenant_id`, without `allowed_scopes`) plus
`TestLoadTargetClientsMissingAllowedScopesColumnFailsLoudly` asserting the
SQL error names `allowed_scopes` (mirrors U7). `seedTarget` INSERT
unchanged. Existing test names and final assertions unchanged.

### 7.3 Integration — `test/legacy_sync_scope_registry_test.go` (new, package `ssotest`)

Extends the `newLegacySyncDeployment` shape (test/legacy_sync_tenant_claim_test.go:
real `sqlitestores.NewClientStore`/`NewPasswordCredentialStore`,
`MemoryUserProvider`, password authenticator, Ed25519 JWT issuer) plus
`postToken` (test/handle_token_test.go:56), with a confidential
client_credentials client and `sso.WithScopeRegistry(reg)` where
`reg, _ := scoperegistry.NewMemory(scopecontract.Matrix(), nil)`:

- **Positive leg**: clients row with `AllowedScopes: []string{"admin:read"}`;
  `POST /token` `grant_type=client_credentials`, `scope=admin:read` → 200
  with `access_token` (matrix scope clears the dispatch seam and the
  post-resolution check, token_client_credentials.go:44-47).
- **Negative leg (D2 repair)**: the same deployment seeded with the dirty
  shape `AllowedScopes: []string{"admin:read","legacy:menu:1:view"}`;
  `scope=legacy:menu:1:view` → 400 `{"error":"invalid_scope"}`. The dirty
  allowlist is essential: with a clean allowlist the 400 would come from
  `GrantedScopes` rule 1 (allowlist), masking the registry seam this test
  pins (server_token.go:132 → reject.go:31-43). Acceptance text unchanged —
  the mechanism is now faithful.
- **Extra-reconciliation leg**: server wired with
  `NewMemory(scopecontract.Matrix(), []string{"legacy:*"})` and the same
  dirty allowlist; `scope=legacy:menu:1:view` → 200, proving
  `--scope-registry-extra` tracks the runtime predicate end-to-end.

### 7.4 Gates

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

Handoff:

```bash
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

## 8. Files

### Create

```text
cmd/sso-ctl/legacysync/scope_gate.go       — buildScopeRegistry + validateScopeRegistration (§3.4); ~50 lines
cmd/sso-ctl/legacysync/scope_gate_test.go  — gate + flag-validation unit tests (§7.2); _test.go does not count against the fan-out ceiling
test/legacy_sync_scope_registry_test.go    — /token mint integration, synced-deployment shape (§7.3)
docs/architect-analysis/cmd-sso-ctl-legacysync-scope-registry-preflight-design.md — this design
```

### Modify

```text
cmd/sso-ctl/legacysync/config.go   — two flags + parseScopeRegistryFlags helper; 79 → ~100 lines (§3.1)
cmd/sso-ctl/legacysync/model.go    — syncPlan.ScopeRegistry + targetSnapshot.ClientScopes; +1 import, ~3 lines (§3.2)
cmd/sso-ctl/legacysync/target.go   — SELECT + ClientScopes fill + one buildReport call; 435 → ~445 (§3.3, §3.4)
cmd/sso-ctl/legacysync/main.go     — plan.ScopeRegistry = cfg.ScopeRegistry; ~2 lines (§3.5)
cmd/sso-ctl/legacysync/target_test.go — fixtures gain allowed_scopes; new missing-column fixture + test (§7.2)
```

### Do not modify

```text
interfaces/sso/server_token.go            — dispatch seam and invalid_scope shape already correct
protocols/oauth/scoperegistry/*           — registry, matrix, predicate unchanged
interfaces/scopecontract/*                — matrix unchanged
config/config_oauth2.go                   — YAML-side gate unchanged
cmd/sso-server/build_stores.go            — server registry wiring unchanged
cmd/sso-ctl/legacysync/plan.go, source.go — plan shape and source load unchanged (the gate reads the plan as-is)
infrastructure/defaultimpl/sqlite/clients.go — real schema already has allowed_scopes (:42); no migration
```
