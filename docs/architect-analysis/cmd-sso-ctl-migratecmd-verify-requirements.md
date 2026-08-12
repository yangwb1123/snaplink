# Requirements Spec: sso-ctl migrate verify — fail-closed namespace/version floor gate

- Direction: entry 1 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-migratecmd-8522976b.json`
  ("Add a fail-closed 'verify' mode asserting required namespaces at minimum versions — B4-3 deploy-tree truthiness for the B4-5 governance schema")
- Module: `cmd/sso-ctl/migratecmd`
- Status: requirements (evidence re-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/migratecmd/main.go:25-40` — status-only dispatch, no assertion mode | `Run` is at 41; `switch args[0]` at 47–55 handles only `"status"` (48) and `-h/--help` (50); the `default` branch (53–55) prints `unknown subcommand` and returns 2. No `verify`/`--expect` path exists anywhere in the package (`rg -n "expect\|verify" cmd/sso-ctl/migratecmd/` → only the word "verify" in non-code comments) | Confirmed (line drift 16) |
| `cmd/sso-ctl/migratecmd/main.go:72-77` — empty DB renders green, exit 0 | `renderStatus` at 109–128: `if len(st) == 0` prints `(no migrated namespaces — empty or non-SSO database)` at 116 and `return nil` at 117 → exit 0 | Confirmed (function moved to 109) |
| `platform/migrate/migrate.go:286-297` — Status `nil,nil` for non-SQLite | `Status` (283) runs `SELECT name FROM sqlite_master …` (288); on query error it returns `nil, nil` at 296 with the comment (291–295): "sqlite_master exists on EVERY SQLite database, so a failure here means the handle is not a SQLite DB … Report no migrate-tracked schema rather than a spurious error". A non-SQLite file therefore renders green with exit 0 | Confirmed (return at 296) |
| `platform/audit/sqlite/sink.go:48-78, 78` — audit namespace migrations v1–v3, `migrationNamespace='audit'` | `migrations` at 163–168: `{Version:1, "baseline_audit_events"}`, `{Version:2, "add_tenant_id"}`, `{Version:3, "add_server_version"}`; `const migrationNamespace = "audit"` at 178. `New` runs `migrate.Run(…, migrationNamespace, migrations)` (169) at construct time | Confirmed (sink.go:163–178) |
| `infrastructure/auditgovernance/managed_relay.go` + `relay.go` — B4-5 outbox/governance building block, not wired | Both files exist in `infrastructure/auditgovernance/` along with `provisioner.go`, `provision_manifest.go`, `control_client.go`; `rg -n auditgovernance cmd/` → zero references (no `WithTxAppender` wiring anywhere in sso-server); B4-5 is marked [PROPOSED] in `docs/proposals/audit-contract-batch-snaplink.md` ("outbox + in-tx … 复用 managed_relay.go + backend 默认 memory→sqlite"). No governance/outbox migration namespace exists in the tree today | Confirmed |
| `cmd/sso-ctl/main.go:55` — `'migrate': migratecmd.Run` registration | `"migrate": migratecmd.Run` at line 53; banner lists `migrate  Offline schema-migration status for a SQLite store.` at line 99 | Confirmed (53, not 55) |
| `infrastructure/defaultimpl/sqlite/*` namespaces a manifest would enumerate | `migrate.Run` call sites: `auth_codes.go:215` (`"auth_codes"`), `authz_stores.go:48/148/310/397` (`"rebac_tuples"`, `"providers"`, `"devices"`, `"ssf_streams"`), `ciba.go:79` (`"ciba_requests"`), `clients.go:126,140` (`"clients"`), `consent.go:53,63` (`"consent"`); plus `"audit"` (sink.go:178) — 9 namespaces today | Confirmed (line numbers shifted, symbols exact) |
| `cmd/sso-ctl/migratecmd/main_test.go` seedDB pattern | `seedDB` at 16–30 opens the DSN and runs `migrate.Run(…, "audit", []migrate.Migration{{Version:1, Name:"baseline", SQL:…}})`, returns the DSN. Tests call `runStatus`/`renderStatus` directly (31–85) | Confirmed |
| `migrate.CurrentVersion` ready for offline assertion | `func CurrentVersion(ctx, db, namespace) (int, error)` at migrate.go:379–396: absent version table → `(0, nil)`; any other probe error propagates. Read-only, no migration definitions needed — usable by migratecmd without importing backend packages | Confirmed |
| Deploy-tree context: T-2 sweep / T-9 | `docs/campaigns/implementation-gate.md` rows 1–4: T-2 = sweep/truthiness 全绿 in the deploy repo; G5 row (part 77): "B4-2..5 → T-2、T-8(b–e)、T-9、L0 持久化、P2 parity". The deploy pre-check currently has no way to fail: `docs/proposals/devops_engineer.md:127` explicitly calls the gap: "the offline `sso-ctl migrate status` is SQLite-only — a gap for Postgres pre-checks" | Confirmed |
| B4-3 deploy-tree truthiness | `docs/architect-analysis/cmd-sso-ctl-b4-3-t2-requirements.md` — the deploy-tree sweep discipline already established for T-2 in `sso-ctl` (configcmd `check-discovery`): operator-facing hard pass/fail (exit 0/1) checks owned by `sso-ctl`, no server-side change | Confirmed (precedent pattern for this spec) |

## 2. Goal and user outcome

`sso-ctl migrate` is documented (main.go:1–10) as "useful for deploy pre-checks", but it is report-only and cannot fail: a Postgres audit store, a wiped DB, a fresh file, or a missing file all render `(no migrated namespaces — empty or non-SSO database)` and exit 0. When B4-5 lands (stock audit backend memory→sqlite, hash_chain, governance outbox), the deploy tree needs a gate that asserts the audit namespace is at least v3 (sink.go:163–168) and that the governance/outbox namespace exists — before boot accepts traffic.

Completion marker: from a deploy pre-check or the B4-3 deploy-tree CI sweep

```bash
sso-ctl migrate verify --dsn 'file:/var/lib/sso/sso.db?mode=ro' \
  --expect audit=3 --expect governance_outbox=1 [--json]
```

returns exit 0 only when every expected namespace is present at or above its minimum version, exit 1 when any expectation is unmet or the file is not a SQLite database, and never exits 0 on an absent schema. The existing `status` surface is untouched (byte-compatible output and exit codes).

## 3. Product boundary

- Surface: `sso-ctl` operator toolbelt, `cmd/sso-ctl/migratecmd` (composition layer). Opt-in subcommand: never invoked unless requested; `status` behavior is unchanged.
- Dependencies introduced: none beyond stdlib + `platform/migrate` (already imported). migratecmd still imports no backend packages ("no migration definitions needed", migrate.go:277–284).
- Explicit non-goals (do not implement in this change):
  - No read-only-open enforcement, missing-file probe, or empty-DB-special exit code (rejected direction 2 of the same analysis: "Enforce read-only opens…"). `verify` reads via the same read-only queries as `status`; the DSN stays advisory `?mode=ro` as documented today.
  - No "DB ahead of binary" drift detection (rejected direction 3). `verify` asserts a minimum, not a maximum: a DB at v4 with `--expect audit=3` passes — that is the floor contract from the direction title ("at minimum versions").
  - No embedded manifest compiled into the binary. Embedding an expectations manifest would force importing backend packages (migration slices/namespaces) into migratecmd, breaking the "no migration definitions" design (migrate.go:277–284); the deploy tree already supplies explicit `--expect` pairs, and those live in the tree, not the binary.
  - No Postgres/other-engine support: a non-SQLite DSN is a distinct, loud failure (see A2), and remains non-inspectable — the pre-check is closed-loop, not magenta.
  - No `platform/migrate` changes (Status/CurrentVersion already provide everything needed), no new config keys, no OpenAPI / error-codes changes (CLI-only, no new HTTP surface or `Err*` sentinel), no new package/directory under `cmd/sso-ctl` (16/16 subdir ceiling — must not grow).

## 4. Module classification

- [x] Infrastructure/config/deployment (operator tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/migratecmd` (composition). Dependency direction: `cmd/*` → `platform/migrate` → … → `shared`, no upward import, no new package.

## 5. Requirements

### R1 — `verify` subcommand dispatch

New sub-subcommand in `migratecmd.Run`'s switch (main.go:47–55), alongside `status` and `help`:

```
sso-ctl migrate verify --dsn <sqlite-dsn> --expect <namespace>=<min-version> [--expect …] [--json]
```

- At least one `--expect` flag is required; zero `--expect` flags is a usage error.
- Usage errors exit 2 (the existing usage-error code, shared with `Run`'s `unknown subcommand` and status missing `--dsn` paths — verify itself reuses `fs` error handling so unknown flags behave identically to status).
- Package doc comment (main.go:1–22) and `usage()` (main.go:62–78) list the new subcommand. `cmd/sso-ctl/main.go:99` banner text is extended to mention `verify`.
- `-h`/`--help`/`help` for `verify` prints the subcommand usage and exits 0, mirroring `status`'s behavior.

### R2 — `--expect` flag parsing and validation

Repeatable string flag, grammar `namespace=min-version`:

- Namespace must match `^[a-z][a-z0-9_]*$` — the same charset `migrate.versionTable` enforces (migrate.go:168–183); the regexp literal is duplicated in migratecmd with a cross-reference comment (namespace validation is never interpolated — reusing the identical charset keeps `schema_migrations_<ns>` lookups tight).
- `min-version` must be an integer ≥ 1.
- Malformed value → usage error exit 2 with a message naming the offending `--expect` value.
- Duplicate namespace across repeated `--expect` flags → usage error exit 2 (fail-closed, deterministic; a duplicate would otherwise hide the tested intent).

### R3 — Non-SQLite diagnosis

`verify` first proves the handle is a SQLite database with a probe identical in intent to `Status`'s own: `SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'schema_migrations_%'` (migrate.go:287–288) executed directly by migratecmd. If the probe query fails, `verify` returns a distinct error of the form `not a SQLite database: <driver error>` (exit 1) instead of the current silent green (`Status` swallows the same error into `nil,nil` at migrate.go:291–296; renderStatus then prints the empty message at 116). This covers:
- a garbage/non-SQLite file (e.g. a Postgres store mounted to the same path — SQLite driver: `file is not a database`);
- a Postgres-shaped or otherwise non-dialect DSN that happens to pass `Ping` but fails the `sqlite_master` query (Status behavior is unchanged — status keeps rendering "no migrated namespaces" and exiting 0, as today).

The probe runs after the existing `sql.Open` + `PingContext` (main.go:91–98). A DSN that fails `Ping` (missing file with `?mode=ro`, missing directory) keeps the existing non-SQLite generic `open:` error — `verify` does not need to re-parse it.

### R4 — Verification semantics (fail closed)

For each `--expect namespace=min` in flag order (sorted by namespace for deterministic reports):

1. `actual, err := migrate.CurrentVersion(ctx, db, namespace)` (migrate.go:379–394). It returns 0 when the version table is absent — the "namespace not migrated / pre-B4-5 DB" case;
2. **pass** iff `actual >= min` (a floor: a DB ahead of the floor passes, matching the direction "at minimum versions");
3. **fail** otherwise. **The behavior is fail-closed**: any failing expectation yields exit 1, including an empty-but-valid SQLite DB (every expected `actual=0`) and a DB lacking the governance namespace entirely — the exact pre-B4-5 shape.

Report (stdout):
- Human mode: one line per namespace: passes `NAMESPACE expected >=N recorded M`, failures `NAMESPACE expected >=N got M` plus the namespace-missing mark (`got 0 (namespace absent or not migrated)`); final `verify: N namespaces, M failed` line.
- `--json`: a single JSON object (documented shape, sorted by namespace):

```json
{"ok":true,"namespaces":[{"namespace":"audit","expected":3,"actual":3,"ok":true}]}
```

Exit code rule (both modes): 0 = all pass, 1 = at least one fail (or non-SQLite/DB error), 2 = usage. `--json` emits the report on stdout in every case and still exits non-zero on fail, so pipelines can diff regardless of parsing.

### R5 — `status` byte-compat (T-9 / regression pin)

- `runStatus`, `renderStatus`, and `migrate.Status` are not touched: table rendering, `--json` (marshal of `[]NamespaceStatus`), empty-DB message (main.go:116), and exit codes (0 report, 1 error, 2 usage) stay byte-identical.
- Existing tests (`TestRunStatus_RequiresDSN`, `TestRunStatus_HappyPath`, `TestRunStatus_BadDSN`, `TestRenderStatus_Table/JSON/Empty`, seedDB) run unchanged.

### R6 — T-9 manifest bump (readiness for B4-5)

The strict "manifest" is the deploy tree's `--expect` set, bumped in the same change that lands the B4-5 outbox migration:

- Today: the tree pins current known floors (e.g. `--expect audit=3`).
- B4-5: lands a governance/outbox namespace (proposed `governance_outbox=1`) and, if the hash_chain lands as audit v4+, raises `--expect audit=4`. `verify` on a pre-B4-5 database (no `schema_migrations_governance_outbox` row) then fails by the *same predicate this spec ships* — an absent namespace yields 0 and fails. The upgrade documentation/PR template must carry the bump rule: add or raise `--expect` exactly when a backend's migration slice grows or a new namespace appears, never silently (the deploy-tree CI sweep, implementation-gate.md G5, is the enforcement point).

## 6. Acceptance criteria

The direction's four checks, preserved and made testable:

### T-2 (sweep/truthiness) — hard gate

- **A1**: `sso-ctl migrate verify --dsn <ro-db> --expect audit=3 --expect governance_outbox=1` exits non-zero on a DB missing the governance namespace or with audit below v3, and 0 on a correctly migrated DB. Test table in `cmd/sso-ctl/migratecmd/verify_test.go`:
  1. seed v3 audit (three `migrate.Migration{Version:1,2,3}` rows via `migrate.Run`, exactly mirroring `seedDB` main_test.go:16) + v1 governance baseline → verify exit 0;
  2. seed audit v2 only → exit 1 (below the floor, output shows `audit expected >=3 got 2`);
  3. seed audit v3 only → exit 1 (governance_outbox expected >=1, got 0 — namespace absent);
  4. seed audit v3 + governance v1, run verify against the *same file* with `?mode=ro` appended → exit 0 (proves the read-only deployment form works);
  5. floor semantics: seed audit v4 → `--expect audit=3` exits 0 (ahead of the floor passes).
- **A2**: `verify` against a non-SQLite target fails with a distinct `not a SQLite database` error and exit 1, never the silent green. Two cases: (a) a garbage file (e.g. `garbage.db` containing the bytes "not a sqlite database") — driver accepts the handle, `sqlite_master` probe fails, distinct error; (b) a Postgres-shaped DSN (`postgres://u:p@host:5432/db`) — fails at `Ping` with the existing generic `open:` error, still exit 1 (fail-closed; the distinct message is reserved for handles that pass `Ping`, per R3). Regression proof of the gap: plain `status` on the same garbage file still renders the green empty line with exit 0 (CLI contract: status stays report-only, verify must not).
- **A3**: `--json` output contains per-namespace `expected`/`actual`/`ok` (`audit/3/3/true`, `governance_outbox/1/0/false`) so pipelines can diff; the existing `status --json` output and table output are byte-compatible (existing tests unchanged). `--expect` grammar suite: `audit` (missing `=`), `AUDIT=3`, `audit=0`, `audit=abc`, duplicated `--expect audit=3 --expect audit=2` → each is a usage error exit 2.
- **A4** (fail-closed): a fresh, valid, empty SQLite DB (no migrate tables) with any expectation exits 1, never 0.

### T-9 — regression retention

- **A5**: All existing migratecmd tests run unchanged (status exit codes, table/JSON rendering, `(no migrated namespaces)` message) — verified by running `go test ./cmd/sso-ctl/…` after the change with no test edits.
- **A6**: the report's fail path carries per-namespace binding expected/actual in both modes (human line + JSON fields), so CI diffs name the exact namespace and version; the deploy-tree sweep records the JSON report as its diffable artifact.

## 7. Files

### Modify

```text
cmd/sso-ctl/migratecmd/main.go — Run dispatch case "verify" (R1), usage() and package doc; existing runStatus/renderStatus untouched (R5)
cmd/sso-ctl/main.go — banner line 99 updated to mention the new `verify` subcommand in the CLI surface (R1)
```

### Create

```text
cmd/sso-ctl/migratecmd/verify.go — verify flag parsing (R2), SQLite probe (R3), floor check via migrate.CurrentVersion (R4), human + JSON report rendering (R4)
cmd/sso-ctl/migratecmd/verify_test.go — A1–A6 tests (seeded via migrate.Run mirroring main_test.go seedDB)
```

Budget check: `main.go` 128 lines stays < 500; `verify.go` lands ~150 lines; functions stay < 50 lines, complexity < 15; existing budget exemptions are untouched; no new directories.

## 8. Implementation and verification order

1. `verify.go` (R2→R4) + `verify_test.go` (A1–A4, A6);
2. wire dispatch/doc/README (R1, main.go + sso-ctl main.go banner);
3. run the committed gates: `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, `go test ./cmd/sso-ctl/… ./platform/migrate/…` — no test edits to existing migratecmd tests (A5);
4. handoff: `go test ./... -race`, `make ci`.

## 9. Risks and mitigations

| Risk | Mitigation |
|---|---|
| A DB legitimately ahead of the binary (migration in some replicas) — floor passes v4 vs v3 | This is a *minimum* floor; the "DB ahead of binary" drift detector is rejected direction 3, deliberately not implemented; the operator's expected pair controls strictness |
| Duplicating the namespace regex instead of sharing | One-time deliberate coexistence (migratecmd must not import backend; the regex is 1 line); both sides validated by the same charset is written down at both sites |
| Deploy tree forgets to bump expectations at B4-5 | enforcement is in-tree: `--expect-governance_outbox=1` fails on any pre-B4-5 DB (A1 case 3), and existing T-9 pinned tests keep `status` stable while the floor list lives in the deploy-tree sweep (implementation-gate.md row 13) |
| True "not a SQLite database" detection on live files | Only the sqlite_master probe ever triggers it; mode=ro reads on live files remain supported (A1 case 4), which is the pre-check's primary use |