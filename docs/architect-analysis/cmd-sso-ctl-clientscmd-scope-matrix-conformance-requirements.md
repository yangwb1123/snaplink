# Requirements Spec: sso-ctl clients validate — scope-matrix conformance gate

- Direction: cmd/sso-ctl `clientscmd` scope-matrix conformance (composition-layer CLI; source evidence verified against HEAD)
- Module: `cmd/sso-ctl/clientscmd` (composition layer)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the supplied evidence was re-checked against the repository.
Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `interfaces/scopecontract/consts.go:22-36` — `Matrix()` | `func Matrix()` at lines 25-33; 9 rows = 8 structural aliases (commerce ×5, metering ×2, admin wildcard ×1) + pinned literal `ScopeAuditEventWrite = "audit:event:write"` (lines 35-36) | Confirmed, exact |
| `cmd/sso-server/build_stores.go:306` — `NewMemory(MatrixOrDefault(), ExtraScopes)` | Line 306 exactly: `scoperegistry.NewMemory(cfg.OAuth.ScopeRegistry.MatrixOrDefault(), cfg.OAuth.ScopeRegistry.ExtraScopes)` inside the `Enabled` branch (295-314) | Confirmed, exact line |
| `cmd/sso-server/scope_registry_wiring_test.go:28,79` | Matrix pin at 28 (`for _, sc := range scopecontract.Matrix()`), extras at 57, provisioned-replaces-builtin at 78-90 (`custom:scope` registered, `admin:read` NOT) | Confirmed |
| `cmd/sso-ctl/clientscmd/clients.go:25-30` — no conformance signal | `Run` dispatch (30-48) handles only `list`/`get`/help; `clientListItem` at 74-85 with `AllowedScopes` at line 80 (`json:"allowedScopes,omitempty"`); no `validate` anywhere in the package | Confirmed — no such command exists today |
| `cmd/sso-ctl/apiclient/check.go:18` — T-8d | T-8d documented at line 20 (drift 2); `probeScope` at 300-314 (`sweep-probe-` + 12 rand) | Confirmed (2-line drift, symbol exact) |
| `cmd/sso-ctl/apiclient/token.go:282+` — dynamic probe | `runT8d` at 351-395; byte-identical pin `wantBody = {"error":"invalid_scope"}\n` at 375; 200 ⇒ "enforcement absent" diagnostic at 379 | Confirmed |
| "No such command or flag exists today" | `rg validate cmd/sso-ctl/clientscmd/` → 0 hits; `Run` switch has no `validate` case | Confirmed — the direction's hedge was necessary |
| `Memory.Registered` exact-or-`":*"` (registry.go:115-125) | `func (m *Memory) Registered` at 115-125: exact match OR `strings.CutSuffix(p, ":*")` prefix match; empty scope false; construction rejects bare `*` and non-`":*"` wildcards | Confirmed, exact |
| Protocol scopes pre-seeded (registry.go:48-57) | `ProtocolScopes()` at 48-60: openid, device_sso, profile, email, address, phone, offline_access; `NewMemory` at 68 registers them unconditionally, matrix second, extras third | Confirmed |
| `test/scope_registry_test.go:41-48` — `srRegistry` construction | `srRegistry` at 41-49: `scoperegistry.NewMemory(scopecontract.Matrix(), nil)` — the exact construction the spec locks | Confirmed |
| `test/e2e_test.go:70-130` — fixture wires no registry | `buildE2E` at 80-170; `sso.NewServer` options block 124-132 has no `WithScopeRegistry` (grep: 0 hits in file); fixture is shared by `test/risk_test.go` too | Confirmed (span drift 10-40 lines) |

### Two decisive findings — verified and one refined

1. **The predicate must reuse the registry, not a slice lookup** — CONFIRMED and
   load-bearing. `Memory.Registered` is exact-or-`":*"` (registry.go:115-125)
   and always pre-seeds the 7 protocol scopes (48-60). A naive "member of
   `Matrix()`" check would false-flag every concrete `admin:read`/`admin:write`
   (covered only by the `admin:*` pattern) and every client carrying
   `openid`/`profile` — while disagreeing with the server's own gate. The spec
   locks `scoperegistry.NewMemory(scopecontract.Matrix(), nil)` — the exact
   `srRegistry` construction (test/scope_registry_test.go:41-49) and the exact
   composition used by `build_stores.go:306` with an empty `extra_scopes`.

2. **Where the R3 oracle-agreement test lives — REFINED.** The evidence's
   suggestion to wire `WithScopeRegistry` into `test/e2e_test.go`'s `buildE2E`
   (lines 80-170) is rejected in favor of a dedicated fixture in
   `cmd/sso-ctl/clientscmd`:
   - The server oracle side is **already pinned** in
     `test/scope_registry_test.go` (`newScopeRegistryHarness` + A-1b
     byte-identical `{"error":"invalid_scope"}`), so no new server-side
     agreement is missing.
   - The CLI side must live in `cmd/sso-ctl/clientscmd`: `test/` (package
     `ssotest`) cannot be imported from `cmd/` (stated in
     `clientscmd/e2e_test.go`'s `adminValidator` comment), and `test/` cannot
     import `cmd/` (AGENTS.md: no package imports `cmd/`).
   - Mutating `buildE2E` perturbs every consumer including `test/risk_test.go`
     (7+ tests) for zero gain; the registry is only needed by the new
     agreement test.
   - The R3 triple is therefore driven against `PathToken` (`/token`) mounted
     by a **new** registry-wired fixture in `clientscmd` (mirror of
     `newCLIDeployment`, which today mounts `srv.Handler()` at `/` — the
     `"/"` catch-all already exposes `/token`), leaving E-4/E-5/E-6 and
     `test/e2e_test.go` untouched and green.

## 2. Goal and user outcome

The server's global scope registry (`oauth.scope_registry.enabled` +
scope-matrix-v2) gates every `/token` mint against the nine-scope tenant
matrix. A client whose `allowedScopes` drift outside that matrix fails at
runtime with a byte-identical `400 invalid_scope` — indistinguishable from a
typo, and invisible to the offline `config validate` gate (which validates
config-declared clients only, never the admin-registry state the CLI
surfaces). The `clients list`/`clients get` output shows `allowedScopes` but
renders no conformance signal.

Completion marker: an operator can run

```bash
sso-ctl clients validate client_abc123
```

and get a hard pass/fail (exit 0/1) that agrees with the server's own gate:
a scope the CLI rejects is exactly a scope `/token` would 400 for, and a
matrix member the CLI accepts is exactly a scope `/token` would mint.

## 3. Product boundary

- Surface: `sso-ctl` operator toolbelt (`cmd/sso-ctl/clientscmd`), read-only
  admin-API consumer — same credentials/env (`SSO_ADMIN_TOKEN`,
  `SSO_ADDR`) as `clients list`/`get`.
- Default: new `validate` subcommand is opt-in (never invoked unless
  requested); `list`/`get` behavior and output are untouched, byte-identical.
- Explicit non-goals (do not implement):
  - **No server changes**: no `sso.Server`, `interfaces/sso`, proto, OpenAPI,
    config-schema, or error-code changes. `validate` consumes the existing
    admin GET endpoint and the existing registry constructor.
  - **No deployment-specific matrices**: provisioned `oauth.scope_registry.matrix`
    (which REPLACES the built-in nine rows — `build_stores.go:306`,
    `TestBuildApp_ScopeRegistryProvisionedMatrixReplacesBuiltin`) and
    operator `extra_scopes` are out of scope. The CLI gate targets the
    built-in matrix — the drift source the direction identifies, which the
    offline config gate cannot see. Provisioned/extra deployments are covered
    by `config validate` (config-declared clients) and the T-8d live probe
    (`sso-ctl check`) at runtime; `validate` on such a deployment may report
    false positives (see §9 FM-5) and operators must gate with `check`
    instead.
  - **No list-flag variant**: `validate` is a subcommand, not a `--validate`
    flag on `list` — `list`'s byte-pinned JSON/table output (pinned by
    `TestRunList_DecodesGatewayCamelCaseShape` and downstream consumers)
    stays untouched.
  - **No runtime probing**: `validate` never mints, never POSTs `/token`,
    never needs client secrets. Runtime enforcement probing stays in
    `sso-ctl check` (T-8d).
  - **No multiple clients per invocation**: one `<client-id>` positional,
    shell-loop friendly; no `--scope` overrides.
  - **No evaluation of unrestricted clients**: an empty `allowedScopes` is a
    legitimate "registry is the only gate" client (see §9 FM-6).

## 4. Module classification

- [x] Infrastructure/config/deployment (operator tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/clientscmd` (composition layer — `layerName`
classifies `cmd` as composition, which "may import anything"). New imports:
`interfaces/scopecontract` and `protocols/oauth/scoperegistry`, both downward
edges (composition → interfaces → protocols); precedent exists in the module
(`cmd/sso-ctl/generate`, `importcmd` import `interfaces/sso`). No new
top-level package, no `subcommands` map change in `cmd/sso-ctl/main.go`, no
`layerExemptions` entry, no `interfaces/sso` file (60-file ceiling untouched).

## 5. Requirements

### R1 — `sso-ctl clients validate <client-id>` subcommand

New `validate` case in `clientscmd.Run`'s switch (alongside `list`/`get`),
with usage banner updated (one added line in `usage()`:

```text
sso-ctl clients validate <client-id>
```

Semantics — mirror `runGet`'s fetch path exactly:
1. `<client-id>` positional, required; missing/empty or unknown flag ⇒ usage +
   exit 2.
2. `GET /api/v1/admin/clients/<client-id>` via `apiclient.New()` (same env
   credentials as `list`/`get`).
3. Non-200 ⇒ stderr diagnostic naming the client-id and HTTP status, exit 1
   (404 is a failure, not a usage error — same family as `get`).
4. Decode with the same nested-shape tolerance as `runGet`: `{"client":{...}}`
   when present, else the top-level object; read `allowedScopes` (camelCase —
   the gateway's protojson shape, already the `clientListItem` convention).
5. Build the gate: `reg, err := scoperegistry.NewMemory(scopecontract.Matrix(),
   nil)` — the exact `srRegistry` construction. A construction error (not
   reachable with the built-in matrix; all 9 patterns are valid, `admin:*` is
   a legal domain wildcard) fails loudly, exit 1 — fail closed.
6. For every declared `allowedScopes` entry: `reg.Registered(scope)`. Collect
   the unregistered ones, dedupe, sort lexically for deterministic output.
   Each offender prints one stderr line naming the scope:
   `sso-ctl clients: validate: scope "billing:typo" is not in the built-in
   scope matrix`.
7. Exit contract (mirrors `check` and the package's 0/1/2 family):
   - `0` — every declared scope registered (or none declared); stdout line
     `validate: OK`.
   - `1` — any unregistered scope (each named on stderr), any fetch/parse
     failure, or registry-construction failure.
   - `2` — usage error (missing client-id, unknown flag).

### R2 — Predicate is the registry, not a slice lookup

`Registered` semantics, verbatim from `scoperegistry.Memory`:
- exact match on any registered pattern (matrix rows + 7 pre-seeded protocol
  scopes), or
- `":*"` prefix match: `admin:*` covers every concrete `admin:...` scope
  (mirrors `permissions.Matches` and tokenpolicy `scopePresent`).

Consequences locked by tests: a client declaring `admin:read`/`admin:write`
passes (via the `admin:*` pattern) even though `admin:*` is not itself in the
client's allowlist; a client declaring `openid`/`profile`/`email`/`address`/
`phone`/`offline_access`/`device_sso` passes (protocol pre-seed) even though
those are not matrix rows. No space-splitting of entries: `allowedScopes` is a
`[]string` of individual scopes (token-request scope parsing is a `/token`
concern, not a client-declaration concern).

Directionality: one-way subset check (declared ⊆ registered). A client
declaring fewer scopes than the matrix passes — least privilege is never a
violation. Duplicates in `allowedScopes` are a no-op (set semantics in the
violation collector).

### R3 — Oracle agreement with the live server

In the `clientscmd` e2e fixture (registry-wired deployment, `/token` mounted
via `srv.Handler()` at `/`):

| CLI verdict (`clients validate`) | Server verdict (POST `/token`, cc grant) |
|---|---|
| exit 1 naming scope `s` | `400` + body byte-identical `{"error":"invalid_scope"}` for the same `s` |
| exit 0 | `200` mint for a matrix member (and for `admin:read` via `admin:*`) |

The server-oracle half is already pinned at `test/scope_registry_test.go`
(A-1b, `newScopeRegistryHarness`); the new test re-proves the two verdicts
agree on the same scope value through the real CLI path.

### R4 — Offender and coverage matrix of the unit gate

Unit-level (httptest admin fixture, no server):
- offender (matrix-unregistered scope in `allowedScopes`) → exit 1, offender
  named on stderr, conformant scopes not named;
- all nine matrix scopes declared → exit 0;
- protocol scopes only → exit 0;
- `admin:*` in the client's allowlist, and concrete `admin:read` via the
  pattern → exit 0;
- empty `allowedScopes` → exit 0 (vacuous; stderr notice only);
- multiple offenders → exit 1, sorted, deduped;
- client 404 → exit 1 naming the client-id;
- usage errors → exit 2.

### R5 — Regression floor

`clients list` and `clients get` are untouched: `runList`, `runGet`,
`printClients`, `clientListItem` are not modified; the only pre-existing code
change is one usage-text line. Existing pinned tests
(`TestRunList_DecodesGatewayCamelCaseShape`, `TestClientsGet_*`,
`TestCheck_*` E-4/E-5/E-6) stay green without modification.

## 6. Testable acceptance mapping

### Unit tests — `cmd/sso-ctl/clientscmd/validate_test.go`

httptest fixture serving `GET /api/v1/admin/clients/<id>` with controlled
JSON (nested `{"client":{...}}` and flat shapes).

| ID | Given | When | Then |
|---|---|---|---|
| U1 | fixture returns client with all 9 `Matrix()` scopes | `Run(["validate","c1"])` | exit 0; stdout contains `validate: OK`; stderr empty |
| U2 | fixture returns client with `["openid","profile","email","address","phone","offline_access","device_sso"]` | `Run(["validate","c1"])` | exit 0 (protocol pre-seed passes — proves registry predicate, not matrix membership) |
| U3a | fixture returns `["admin:read","admin:write"]` | `Run(["validate","c1"])` | exit 0 (`admin:*` pattern covers concrete rows) |
| U3b | fixture returns `["admin:*"]` | `Run(["validate","c1"])` | exit 0 (wildcard pattern itself is registered) |
| U4 | fixture returns `["admin:read","billing:typo"]` | `Run(["validate","c1"])` | exit 1; stderr names exactly `billing:typo`; stderr does not name `admin:read` |
| U5 | fixture returns `["openid","billing:typo","z:zz"]` | `Run(["validate","c1"])` | exit 1; stderr names `billing:typo` then `z:zz` (lexical, deduped) |
| U6 | fixture returns 404 | `Run(["validate","ghost"])` | exit 1; stderr contains `ghost` and HTTP status |
| U7a | no args | `Run(["validate"])` | exit 2; usage on stderr |
| U7b | `--nope` flag | `Run(["validate","c1","--nope"])` | exit 2 |
| U8 | fixture returns `"allowedScopes":[]` | `Run(["validate","c1"])` | exit 0 (vacuous pass; notice on stderr, not a failure) |
| U9 | fixture returns flat (un-nested) `{"id":"c1","allowedScopes":[...]}` | `Run(["validate","c1"])` | exit 0 (mirrors `runGet`'s nested-shape tolerance) |

### E2E tests — `cmd/sso-ctl/clientscmd/validate_e2e_test.go`

New fixture `newValidateDeployment(t)` mirroring `newCLIDeployment`
(`clientscmd/e2e_test.go:70-110`) plus `sso.WithScopeRegistry(scoperegistry.
NewMemory(scopecontract.Matrix(), nil))`; seeds:
- `client-v` — `AllowedScopes: ["openid","profile","billing:typo","admin:read"]`,
  `GrantTypes: ["client_credentials"]` (T-C invariant: cc-mintable);
- `client-m` — `AllowedScopes: scopecontract.Matrix()`.

| ID | Given | When | Then |
|---|---|---|---|
| E1a | `client-v` on registry-wired deployment | `Run(["validate","client-v"])` | exit 1; stderr names `billing:typo`; stderr does not name `openid`/`profile`/`admin:read` |
| E1b | same deployment | POST `/token` cc `scope=billing:typo` | `400`; body trimmed byte-identical `{"error":"invalid_scope"}` (A-1b pin) |
| E1c | same deployment | POST `/token` cc `scope=admin:read` | `200` mint (matrix member via `admin:*`) |
| E2a | `client-m` | `Run(["validate","client-m"])` | exit 0 |
| E2b | same deployment | POST `/token` cc `scope=<each matrix row>` | `200` for all nine rows (server agrees with the CLI pass) |
| E3 | same deployment, `client-v` | `sso-ctl check --client-id client-v --client-secret s` (T-8d sweep) | `invalid_scope: OK` — registry-wired deployment keeps the live probe green (no regression) |
| E4/E5/E6 | unmodified `newCLIDeployment` (no registry) | existing `TestClientsGet_*`, `TestCheck_*` | unchanged and green — fixture untouched |

### Server-side oracle (pre-existing, cited not re-created)

`test/scope_registry_test.go` — `TestScopeRegistry_MatrixScopesMintable`
(row 2: all nine rows mint 200; `admin:read`/`admin:write` via `admin:*`),
`TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (A-1b), and the
`srRegistry` construction (41-49) — already pin the server half of R3; no
edits to `test/` are required by this spec.

### Mandatory gates

- `go build ./... && go vet ./...` after every `.go` edit
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — no new
  packages, no new upward edges, no exemptions
- Handoff: `go test ./... -race`; `go test ./test/ -run TestE2E -v`;
  `go test ./cmd/sso-ctl/...`; `make ci`

## 7. API changes

### CLI surface (the only public change)

```
sso-ctl clients validate <client-id>
```

| Aspect | Contract |
|---|---|
| Exit 0 | all declared `allowedScopes` registered in the built-in matrix registry (or none declared); stdout `validate: OK` |
| Exit 1 | any unregistered scope (stderr, one per line, sorted, naming the scope); fetch/parse/404 failure; registry-construction failure (unreachable, fail closed) |
| Exit 2 | missing/unknown argument or flag; usage on stderr |
| Credentials | identical to `list`/`get` — `SSO_ADMIN_TOKEN` + `SSO_ADDR` (admin API only; never `/token`, never a client secret) |
| Output | offenders on stderr only; stdout carries only `validate: OK` on pass (script-safe) |
| Determinism | offender order lexical; deduped; no timestamps/randoms |

No server, proto, config, OpenAPI, error-code, or feature-matrix contract
changes: the subcommand adds no endpoint (consumes `GET
/api/v1/admin/clients/{id}`), no config key, no `Err*`.

## 8. Compatibility constraints

1. **`list`/`get` byte-identical**: no changes to `runList`, `runGet`,
   `printClients`, `clientListItem`, or the admin-gateway wire shape. The only
   modification to existing code is one usage-text line in `usage()` (stderr,
   not pinned by any test).
2. **Predicate must agree with the server**: both sides must evaluate the
   same scope under the same rule — `Registered`'s exact-or-`":*"` over
   `NewMemory(Matrix(), nil)`. Any other predicate (slice membership,
   substring, prefix-only) diverges from the server gate and violates R3.
3. **Import direction**: `clientscmd` gains `interfaces/scopecontract` +
   `protocols/oauth/scoperegistry` (composition → interfaces → protocols,
   downward). No `interfaces/sso` change; the 60-file ceiling is untouched.
   No new top-level package; `main.go`'s `subcommands` map unchanged.
4. **Budgets**: `validate.go` ≤ 500 lines, functions ≤ 50 lines, complexity
   ≤ 15, nesting ≤ 3; `clientscmd` non-test files 2 ≤ 10; directory files
   5 ≤ 15. The `validate` case in `Run` is one switch arm (no complexity
   growth in `clients.go`).
5. **Old-binary/new-server and new-binary/old-server**: both directions safe —
   `validate` reads only the existing admin endpoint, which has shipped; no
   server version pairing requirement.

## 9. Failure modes

| # | Mode | Behavior | Rationale |
|---|---|---|---|
| FM-1 | Admin API unreachable/timeout | exit 1, stderr `validate failed: <err>` (same family as `list`/`get`) | operator-visible, no false pass |
| FM-2 | Unknown/deleted client (404) | exit 1 naming the client-id | matches `get`; distinct from usage (2) |
| FM-3 | Malformed/undecodable admin response | exit 1, parse diagnostic | fail closed; never a silent pass |
| FM-4 | Registry construction error | exit 1 (guard only; unreachable — all 9 built-in patterns pass `ValidatePattern`, `admin:*` is legal) | fail closed on impossible state |
| FM-5 | Deployment uses provisioned `matrix` (replaces built-in rows) or drops built-ins | `validate` may report false positives: a scope served by the provisioned matrix is not in the built-in gate | documented non-goal (§3); operators on provisioned deployments gate with `config validate` + `sso-ctl check` T-8d. Extra-only deployments (built-in matrix + `extra_scopes`) are sound: extras add, never remove |
| FM-6 | Unrestricted client (empty `allowedScopes`) | vacuous pass (exit 0) + stderr notice; runtime enforcement depends on the registry being wired | registry wiring is a boot config, not client state; T-8d probes it live. A false *pass* here is a documented property, not a bug |
| FM-7 | Client declares a scope that is registered in the server only via `extra_scopes` | false positive (exit 1) on extra-only deployments | same family as FM-5; covered by the T-8d probe at runtime |

Fail-open/fail-closed posture: every `validate` verdict path is fail-closed
(uncertain ⇒ exit 1) except the documented vacuous pass (FM-6) and the
documented matrix-scope non-goal (FM-5/FM-7), both of which are covered by
`check` T-8d at deploy time. No audit events, no server state, no writes —
nothing to leak, nothing to roll back.

## 10. Migration steps

1. **Code**: add `validate.go` (+ `validate_test.go`, `validate_e2e_test.go`);
   add the `validate` case + usage line in `clients.go`.
2. **Ship**: new `sso-ctl` binary only. No server redeploy, no config change,
   no storage migration, no proto/config/OpenAPI regeneration.
3. **Adoption**: operators add `sso-ctl clients validate <id>` to CI/deploy
   pre-checks alongside `config validate`; the e2e agreement (R3) guarantees
   the gate's verdicts match `/token` behavior, so adoption cannot introduce
   a check that passes while runtime mints 400 (or fails while runtime mints
   200) for built-in-matrix deployments.
4. **Rollback**: revert to the previous `sso-ctl` binary; `list`/`get` and
   server behavior are byte-identical either way. No data or config state is
   touched by `validate`, so rollback is trivially clean.
5. **Docs**: this spec; no `docs/openapi.yaml`, `docs/error-codes.md`, or
   `docs/config-reference.md` updates (no wire/config/error changes).

## 11. Files

### Create

```text
cmd/sso-ctl/clientscmd/validate.go — runValidate: fetch client via admin API,
  build scoperegistry.NewMemory(scopecontract.Matrix(), nil), report
  unregistered allowedScopes (sorted, deduped), 0/1/2 exit contract
cmd/sso-ctl/clientscmd/validate_test.go — U1..U9 httptest admin-fixture unit tests
cmd/sso-ctl/clientscmd/validate_e2e_test.go — newValidateDeployment
  (registry-wired mirror of newCLIDeployment) + E1/E2 oracle-agreement tests, E3 sweep regression
```

### Modify

```text
cmd/sso-ctl/clientscmd/clients.go — one switch arm ("validate" → runValidate)
  + one usage line; nothing else
```

### Do not modify

```text
cmd/sso-ctl/clientscmd/clients_test.go — pins list/get decoding (R5 floor)
cmd/sso-ctl/clientscmd/e2e_test.go — E-4/E-5/E-6 fixture and tests untouched
test/e2e_test.go, test/risk_test.go, test/scope_registry_test.go — buildE2E and
  harness untouched; A-1b/row-2 pins stay as the server oracle
interfaces/scopecontract, protocols/oauth/scoperegistry, interfaces/sso,
  cmd/sso-server, config/, gen/ — no changes; the registry and matrix are
  consumed, not modified
```

## 12. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/... -v          # U1..U9, E1..E3, E-4..E-6 regression
go test ./test/ -run 'TestScopeRegistry|TestE2E' -v   # server oracle unchanged
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

Targeted e2e expectation: E1a exit 1 names `billing:typo` ⇔ E1b `/token`
returns byte-identical `400 {"error":"invalid_scope"}` ⇔ E1c/E2b matrix
members mint `200` — the R3 triple, driven through the real CLI and the real
`PathToken` in one deployment.
