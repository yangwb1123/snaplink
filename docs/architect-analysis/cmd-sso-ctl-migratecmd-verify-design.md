# Design: sso-ctl migrate verify — fail-closed namespace/version floor gate

- Requirements: `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-requirements.md`
  (direction entry 1 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-migratecmd-8522976b.json`)
- Module: `cmd/sso-ctl/migratecmd` (composition layer; no new package)
- Status: design (every evidence claim re-verified against HEAD, incl. two empirical
  probes against `modernc.org/sqlite`; deltas recorded below)

## 1. Evidence verification (all inputs treated as untrusted)

| # | Claim | Verified reality | Verdict |
|---|---|---|---|
| 1 | `migratecmd/main.go:25-40` — status-only dispatch, no assert mode | `Run` at 41; switch at 47–55: `"status"` (48), `-h/--help/help` (50, returns 0), `default` (53–55) prints `unknown subcommand` and returns 2. No `verify`/`--expect` anywhere in the package | Confirmed (drift 16 lines) |
| 2 | `main.go:72-77` — empty DB renders green exit 0 | `renderStatus` at 100–128; empty branch prints `(no migrated namespaces — empty or non-SSO database)` (116) then `return nil` (117) | Confirmed |
| 3 | `migrate.go:286-297` — `Status` returns `nil, nil` on non-SQLite | `Status` at 283–330; the `SELECT name FROM sqlite_master …` probe (288) failure returns `nil, nil` at 302 with the Postgres-swap comment at 291–295 | Confirmed (return at 302, not 296) |
| 4 | `audit/sqlite/sink.go:48-78` — audit ns migrations v1–v3, `migrationNamespace = "audit"` at 78 | File is `platform/audit/sqlite/sink.go` (path drift: `audit/` vs `platform/audit/`). `migrations` v1 `baseline_audit_events` / v2 `add_tenant_id` / v3 `add_server_version` at 46–51; `const migrationNamespace = "audit"` at 78; `New`/`OpenReadOnly` run `migrate.Run(…, migrationNamespace, migrations)` (169, 183) | Confirmed (symbols exact; path and the spec's own 163–178 line reference both drifted) |
| 5 | `auditgovernance/managed_relay.go` + `relay.go` exist; `rg auditgovernance cmd/` → zero references | Files exist. **The "zero references in cmd/" claim is false**: `cmd/snaplink-audit-provisioner/*.go`, `cmd/snaplink-billing/{relay,commands,quota_relay}.go`, and `cmd/sso-ctl/auditexport/main_test.go` all import `infrastructure/auditgovernance`. The *functional* half holds: no auditgovernance wiring in sso-server, and no `governance*`/outbox migration namespace exists in the migration tree (`rg 'migrate.Run\(…, "(governance|outbox)'` → 0). B4-5 is [PROPOSED] in `docs/proposals/audit-contract-batch-snaplink.md` (pre-existing `auditoutbox` namespaced mock is `infrastructure/auditoutbox`, ns `"auditoutbox"` — a different surface) | Partially refuted (citation); functional claim confirmed |
| 6 | `sso-ctl/main.go:55` — `'migrate': migratecmd.Run` registration; banner at 99 | Registration at 53, banner `migrate  Offline schema-migration status for a SQLite store.` at 99 | Confirmed (53, not 55) |
| 7 | `defaultimpl/sqlite` inventory — exactly 9 namespaces | The 9 listed (auth_codes, rebac_tuples, providers, devices, ssf_streams, ciba_requests, clients, consent, audit) are real `migrate.Run` call sites, but the enumeration is not an inventory: the same package also migrates `users`, `sessions`, `refresh_tokens`, `revocations`, `ip_failure_counter`, `recent_login`, `device_codes` (device_codes.go:75); `saml/idpsqlite`, `saml/spsqlite`, and `auditoutbox` add more. Which namespaces land in a given DB file is config/build-dependent (per-store DSNs, `§4` toggles) | Refuted as an inventory; immaterial to design (verify is declarative, §3.1) |
| 8 | `migrate.CurrentVersion` (379–396) — exported, 0 for absent table, read-only | Function at 374 (doc 369–375, body 376–396): absent version table → `(0, nil)`; probe errors propagate; no migration definitions needed | Confirmed |
| 9 | `seedDB` at main_test.go:16–30 mirror | Confirmed at 16-31: opens temp DSN, `migrate.Run(…, "audit", Migration{1, baseline})`, returns DSN | Confirmed |
| 10 | `devops_engineer.md` documents the pre-check gap | Confirmed, §4 preflight: "the offline `sso-ctl migrate status` is SQLite-only — a gap for Postgres pre-checks" | Confirmed |
| 11 | Empirical driver behavior behind A2(a): garbage file passes `Ping` and fails the `sqlite_master` probe with the distinct message | **Refuted by probe**: with `modernc.org/sqlite` a garbage file (`this is not a sqlite database file`) fails at `PingContext` with `file is not a database (26)` — the probe never runs. Empty/zero-byte file and `/dev/null` are opened as valid empty SQLite DBs (probe succeeds, 0 tables). Missing file/dir and Postgres-style DSN (`postgres://u:p@host:5432/db`) fail Ping with `unable to open database file (14)`. `?mode=ro` on an existing DB: Ping and probe both succeed | Refuted; forces design change in §3.4 |
| 12 | Empirical exit-code probe on the current CLI | `status -h` → 1, `status --bogus` → 1, `status --dsn <bad>` → 1 (flag-package errors propagate through `Run`'s generic `err → 1` path; only unknown-subcommand and empty args → 2). The requirements' R1 "usage errors exit 2 … shared with status missing --dsn" is therefore a **contract change for verify only**, not a continuation of status behavior | Input for §4 exit-code contract |

The two empirical deltas (rows 11–12) change the design in exactly two places and nothing else: the distinct non-SQLite diagnosis (3.4) and verify's usage-error exit code (3.2, 4). All other ratified decisions are adopted as written: floor-only semantics, no read-only enforcement, no DB-ahead-of-binary check, no embedded manifest, status byte-compat, 16-subdir ceiling respected.

## 2. Requirements recap (binding)

- `sso-ctl migrate verify --dsn <sqlite-dsn> --expect <ns>=<min-version> [--expect …] [--json]`; exit 0 iff every expected namespace exists (migrate-tracked) at `CurrentVersion >= min`; exit 1 on any unmet expectation or DB/non-SQLite failure; exit 2 on usage errors.
- Missing/sloppy `--expect` grammar, duplicates, and zero `--expect` are usage errors; repeated `--expect` is the only repeatable form; `--json` prints the report on stdout even on failure.
- `status` surface untouched byte-for-byte (tests unchanged, zero edits).
- Non-goals honored: no `platform/migrate` changes, no read-only enforcement, no max-version (ahead-of-binary) check, no embedded manifest, no new packages/directories, no config keys, no HTTP surface, no OpenAPI/error-codes edits.

## 3. Design

### 3.1 API surface

**CLI** (the only public API; no exported Go API changes):

```
sso-ctl migrate verify --dsn <dsn> --expect namespace=min-version [--expect …] [--json]
```

| Element | Contract |
|---|---|
| `--dsn` | As `status`: SQLite DSN, `?mode=ro` advisory for live DBs (doc + A-tests keep this). Required; missing → usage error (exit 2 — see §3.2). open/Ping errors → exit 1 with `open: …` unless classified as not-a-DB (§3.4) |
| `--expect` | repeatable (`flag.Var` slice value). Grammar: `namespace` must match `^[a-z][a-z0-9_]*$` — the identical charset `platform/migrate.versionTable` enforces (migrate.go:94–99); the regexp literal is duplicated here with a cross-reference comment, never shared (migratecmd must not import the backend, and the charset is 1 line — documented trade-off). `min-version` must parse as integer ≥ 1. Violations name the offending value on stderr, exit 2 |
| duplicates | any two `--expect` sharing a namespace (regardless of version) → usage error exit 2; determinism requires a set, and a duplicate would silently hide the intended assertion |
| zero `--expect` | usage error exit 2 (missing floor list — the tool refuses to bless an unasserted DB) |
| `--json` | emit report object on stdout (always, pass or fail); exit codes unchanged; DB/non-SQLite errors are stderr-only (no JSON body — nothing to diff) |
| `-h/--help/help` | `verify`'s own FlagSet runs **`flag.ContinueOnError`** with `fs.Usage = usage` (our help text, not `Usage of verify:`); the flag package prints the usage and returns `flag.ErrHelp`; `runVerify` maps `errors.Is(err, flag.ErrHelp)` → exit 0 and prints nothing more (usage already printed — never print twice). FlagSet choice is forced: `ExitOnError` would `os.Exit(0/2)` inside the process, killing the in-process acceptance tests (§7) on every usage-error row. Same pattern as the tree's first help→0 case, `apiclient/check.go:123-125` — this is its second instance, not novel |
| Extension and exit-stability: parse-stage errors (unknown flag, missing value, Set-time grammar) and post-parse usage errors (duplicate/zero `--expect`, missing `--dsn`, extra positional args) **all exit 2, all print the `verify` usage block on stderr, all leave stdout empty** — see the stage table in §3.2. `-help` (single dash) also hits `ErrHelp` — stdlib treats `-h`/`-help` alike |
| extra positional args | post-parse check `fs.NArg() > 0` → `sso-ctl migrate: unexpected argument %q` + `usage()` → exit 2. `status` silently ignores unknown positionals today; `verify` refuses (documented deviation, §3.2) |

**Report shapes** (deterministic: expectations are checked in namespace-sorted order; duplicates rejected so namespaces are unique):

Human mode (one line per expectation, then a summary):

```
audit             expected >= 3   got 3
governance_outbox expected >= 1   got 0 (namespace absent or not migrated)
verify: 2 namespaces checked, 1 failed
```

- pass line: `%-28s expected >= %d   got %d` (namespaces are ≤ 24 chars today; padding absorbs growth)
- fail line: same but `got %d` suffixed with `(namespace absent or not migrated)` when `actual == 0` — the marker covers both absent table and empty version table; `migrate.CurrentVersion` deliberately collapses them (§4, row "absent vs empty"), and the deploy-tree predicate only cares: not ≥ min.
- summary `verify: %d namespaces checked, %d failed`, newline-terminated. Fail mode is stderr or stdout? The report is the diffable artifact → stdout in both pass and fail; errors (DB/open/probe) are stderr; usage errors print nothing on stdout. Exit 1 on any failed row or transport/non-SQLite error.
- `actual >= expected` for every row → summary `0 failed` and exit 0.

JSON mode (one object; keys lowercase, documented shape):

```json
{"ok":true,"namespaces":[{"namespace":"audit","expected":3,"actual":3,"ok":true}]}
```

Cast the human example with one failure: `"ok":false` and `"actual":0,"ok":false` on the governance row. **Rendering mechanism (pinned): `json.NewEncoder(os.Stdout).Encode(&report)` with no `SetIndent`** — the compact one-line form above plus exactly one trailing newline. Do NOT copy `renderStatus`'s `SetIndent("", "  ")` mechanics: that path indents and would produce a different artifact shape. Field order is the report struct's declaration order (`ok`, `namespaces`; per row `namespace`, `expected`, `actual`, `ok`) — the report type must be a struct, **never a map** (map key order would leak into the encoding and break byte-diffing). `expected`/`actual` are ints; `ok` is bool; the namespace charset `^[a-z][a-z0-9_]*$` guarantees no characters `encoding/json` would escape. The object is emitted even when `ok:false` so pipelines can diff regardless of exit status (the exit code remains the gate).

**Testing seams** — internal functions in `verify.go` (matching the `runStatus`/`renderStatus` split so tests never capture os.Stdout):

| Function | Responsibility | Budget |
|---|---|---|
| `type expect struct{ namespace string; min int }` | parsed pair | — |
| `func parseExpectValue(s string) (expect, error)` | **Set-time stage**, runs inside the flag `Value.Set`: charset regexp + `strconv.Atoi` + `min >= 1`. Errors surface through the flag package's standard wrapper (`invalid value %q for flag -expect: …` + usage block) — "names the offending value" comes free. Parse stops at the first failing flag, so Set-time precedence follows argv order (deterministic per invocation, not stable under reordering — §3.5) | ~12 lines |
| `func finalizeExpects(es []expect) ([]expect, error)` | **post-parse stage**: duplicate namespaces rejected (any version), sort by namespace, zero-count check; run by `runVerify` as `sso-ctl migrate: <reason naming the namespace>` + `usage()`, exit 2 — shape differs from the Set-stage wrapper by necessity (a duplicate spans two flag values the flag package never sees together). Invariant across both stages: **exit 2, usage block printed, stdout empty** | ~15 lines |
| `func runVerify(args []string) int` | owns its `flag.ContinueOnError` FlagSet (`fs.Usage = usage`, `errors.Is(err, flag.ErrHelp) -> 0`, other parse errors -> wrap line + 2) + open/ping/classify/probe + floors + render + exit-code mapping (§3.2). Returns int, never calls `os.Exit` — in-process testable | < 45 lines |
| `func verifyDB(ctx, db, expects) (report, error)` | probe + per-namespace `migrate.CurrentVersion`; builds `report` | < 30 lines |
| `func renderReport(w, report, asJSON)` | both modes | < 30 lines |

**Run wiring** (`cmd/sso-ctl/migratecmd/main.go`):

```go
switch args[0] {
case "status":
    err = runStatus(args[1:])
case "verify":
    // verify has its own exit-code taxonomy (0 pass, 1 fail, 2 usage)
    // where status conflates every sub-error into 1; the divergence is
    // deliberate and pinned by verify_test.go.
    return runVerify(args[1:])  // int return; the internal ContinueOnError
    // FlagSet (fs.Usage = usage, ErrHelp→0, parse errors→2 — §3.1) is
    // what makes the exit taxonomy possible without os.Exit in-process.
case "-h", "--help", "help":
    usage(); return 0
default:
    ... exit 2 (unchanged)
}
```

`usage()` gains a `verify   ...` line and the `Examples:` block; the package doc comment (main.go:1–22) gains one sentence: "verify asserts a minimum applied version per namespace and exits non-zero when any floor is unmet — the deploy pre-check form". `cmd/sso-ctl/main.go:99` banner becomes `migrate        Offline schema-migration status/verification for a SQLite store.` Keeping one line and the column width.

No new package: `verify.go` + `verify_test.go` live in `migratecmd` (cmd/sso-ctl at its 16-subdirectory ceiling — the change adds files, not directories).

### 3.2 Exit-code contract (deliberate divergence, documented)

| Situation | `status` today (pinned) | `verify` (new) | Rationale |
|---|---|---|---|
| pass | 0 | 0 | — |
| DB error / floor unmet | 1 (report) | 1 (report or stderr) | — |
| unknown subcommand / empty args | 2 | 2 | shared `Run` path |
| `-h/--help` | **1** (flag.ErrHelp propagates through the generic `err→1` path — a quirk; verified empirically) | **0** | help is not a failure; aligns with `Run`-level `help`, and the pre-check surface must be gentle in interactive use |
| missing `--dsn` / malformed `--expect` / duplicate / zero `--expect` / extra positional | **1** (generic error path) | **2** | the requirements' acceptance tests (§A3) pin grammar failures = usage = 2; a strict grammar lets CI distinguish "called wrong" (2, infra bug) from "schema below floor" (1, real deploy signal) |

The divergence is contained entirely inside the new `verify` case: `Run`'s `err → 1` path still covers `status`, and nothing in it changes.

**CLI-stage stderr shapes (all usage errors: exit 2, usage block printed, stdout empty):**

| Stage | Where stderr comes from | Example (probe-verified with stdlib `flag`) |
|---|---|---|
| flag parse (unknown flag, missing value, Set-time grammar) | the flag package prints its diagnostic then the usage block (via `fs.Usage = usage`) and returns the error; `runVerify` prints the wrap line `sso-ctl migrate: <err>` (same prefix status prints, so existing greps keep matching) and returns 2 | `flag provided but not defined: -bogus` ‖ `invalid value "audit=0" for flag -expect: min version must be >= 1` ‖ usage block |
| post-parse (missing `--dsn`, duplicate `--expect`, zero `--expect`, extra positional) | `runVerify` itself: `sso-ctl migrate: <reason naming the value>` then `usage()`, exit 2 | `sso-ctl migrate: governance_outbox duplicated` ‖ usage block |
| `-h`/`--help`/`-help` | the flag package prints the usage block (fs.Usage) and returns `flag.ErrHelp`; `runVerify` returns 0 printing **nothing further** — no wrap line, no duplicate usage, and (unlike status) no `flag: help requested` error line | usage block only, exit 0 |

Message text differs between the two error stages by design — the flag package wraps only single-value failures, while a duplicate spans two values it never sees together. What is identical and pinned by `TestVerify_UsageErrors` on every row: **exit 2, usage block on stderr, empty stdout**.

### 3.3 Non-SQLite diagnosis (empirically grounded)

Order of operations in `runVerify`:

1. `sql.Open("sqlite", dsn)` — error → `open: <err>` stderr, exit 1 (identical error text to status).
2. `db.PingContext` — on error, classify: if the error begins with `file is not a database` (modernc sqlite error 26, `SQLITE_NOTADB`; verified message shape `file is not a database (26)`), emit `sso-ctl migrate: not a SQLite database: <err>` and exit 1. Any other Ping error (missing file, missing dir, an unreadable file — chmod 0200/000 surfaces `unable to open database file (14)` while a read-only-but-readable 0400 file falls back to a read-only open and is not an error — and Postgres-shaped URIs) → `open: <err>`, exit 1 (fail-closed; no overclaiming). A *busy* database — EXCLUSIVE holder via journal-commit window, VACUUM, or backup — surfaces `database is locked (5) (SQLITE_BUSY)` **at Ping**, not at open; `?mode=ro` does not bypass it.
3. `migrate.Status`-identical probe (`SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'schema_migrations_%'` — same shape as migrate.go:288, executed by verify directly). A probe error gets the *same* two-bucket classification as Ping: the `file is not a database` prefix is the only not-a-DB marker; anything else (including SQLITE_BUSY arriving between Ping and the probe — an EXCLUSIVE holder can appear at any point) stays in the generic `open:` bucket with its real message — verify must never mislabel a busy-but-valid database as "not a SQLite database". Kept: it is the semantic boundary that makes `verify` insensitive to a future driver/Ping change, it satisfies the requirements' R3 wording, and it costs one read-only query.
4. Floors (below).

Why both `2` classification and `3` probe: `migrate.Status` swallows probing failures into `nil,nil` (migrate.go:302) — `verify` must not ride that path; it calls `migrate.CurrentVersion` per namespace, has no `Status` swallow, and the classification at Ping is what actually provides the "distinct message" on the realistic garbage-file input (the requirements' A2 case (a) predicted the wrong stage; the acceptance test below pins the *outcome*, not the internal stage).

Failure input table (in actual out-of-the-box order):

| Input | Ping | probe | floors | stdout | stderr | exit |
|---|---|---|---|---|---|---|
| valid DB, all floors met | ok | ok | pass | report | — | 0 |
| valid DB, floor unmet / ns absent | ok | ok | fail | report | — | 1 |
| fresh empty DB (`:memory:`, zero-byte file, `/dev/null`) | ok | ok | every ns = 0 → fail | report (`got 0 …`) | — | 1 |
| garbage file (non-SQLite bytes) | `not a DB` | — | — | — | `not a SQLite database: …` | 1 |
| missing file `?mode=ro` / missing dir | `unable to open database file (14)` | — | — | — | `open: …` | 1 |
| Postgres URI | `unable to open database file (14)` | — | — | — | `open: …` | 1 |
| SQLite file with `?mode=ro` (live unlocked DB) | ok | ok | per floors | report | — | 0/1 |
| locked DB — EXCLUSIVE holder (journal-commit window, VACUUM, backup): plain DSN **or** `?mode=ro` | `database is locked (5) (SQLITE_BUSY)` at the first statement — i.e. at Ping — **never** `unable to open database file` | — | — | — | `open: database is locked (5) (SQLITE_BUSY)` | 1 |
| locked DB — actually mid-migration (`BEGIN IMMEDIATE` / RESERVED, migrate.Run's real shape) | ok — reads a consistent snapshot; only writers are blocked | ok | per floors | report | — | 0/1 |
| missing file, plain rw-DSN (not `?mode=ro`) | ok — sqlite **creates the file** on open | ok | every ns = 0 → fail | report (`got 0 …`) | — | 1 |
| directory as DSN (plain path or `file:` URI) | `unable to open database file (14)` | — | — | — | `open: …` | 1 |
| read-only filesystem with an existing DB, **rw DSN** | no failure at all — reads succeed; a write would say `attempt to write a readonly database (8)` but verify never writes | ok | per floors | report | — | 0/1 |
| permission-denied file (no read bit — chmod 000/0200), rw or `?mode=ro` | `unable to open database file (14)` | — | — | — | `open: …` | 1 |
| read-only file (`0400`, readable) | ok — Ping succeeds: modernc falls back to a read-only open (P1) | ok | per floors | report | — | 0/1 |
| WAL store with an active uncommitted writer — plain or `?mode=ro` (incl. missing `-shm`) | ok — readers see the pre-write snapshot | ok | per floors | report | — | 0/1 |
| usage errors (grammar, zero/dup expects, bad flags, no dsn) | n/a | n/a | n/a | — | usage | 2 |

Empirical basis: all lock/permission/fs rows above were probed against `modernc.org/sqlite` v1.50.1 (the pinned dependency), the lock holder in a second process and the reader running the exact open → Ping → probe → `CurrentVersion`-style pipeline. A held `BEGIN EXCLUSIVE` blocks readers at Ping with `database is locked (5) (SQLITE_BUSY)` in 9/9 clean runs (plain DSN and `?mode=ro`; `_pragma=busy_timeout(N)` in the DSN waits N ms then returns the same error); the RESERVED (`BEGIN IMMEDIATE`) holder never blocked a reader (2/2); the read-only-tmpfs, chmod-000, missing-file, directory-as-DSN, and WAL-active-writer rows as tabled.

Fail-closed invariant: no input reaches exit 0 unless the DB is a real, readable SQLite database whose every asserted namespace records `version >= min`. A wiped file, an empty DB, a misnamed DSN, `/dev/null`, a pre-B4-5 DB, and a locked/exclusive-held DB all exit 1 (the last one with `open: database is locked …`; the rest with report or `open:`/`not a SQLite database: …`).

### 3.4 Floor semantics

Per namespace in sorted order: `actual, err := migrate.CurrentVersion(ctx, db, ns)` — 0 when the version table is absent (the pre-B4-5 database) or when `schema_migrations_<ns>` exists but holds no rows; pass iff `actual >= min` (purge ahead-of-floor databases, the direction's "at minimum versions" contract); DB errors abort with exit 1 (fail closed — no partial blessing). The check is a pure read (no BEGIN, no locks, no DDL, no `migrate.Run`) — one caveat: with a *plain* (write) file DSN, sqlite's own open materializes a missing DB file, so `verify` on a mistyped rw path **creates an empty file** (§3.3 table row); the deploy form always passes `?mode=ro` and the tool has no create/DDL statements of its own. `CurrentVersion` interpolates `schema_migrations_<namespace>` (migrate.go:374) — the strict duplicated charset (§3.1) is what keeps that interpolation injection-free, exactly the property migrate.command centers on.

### 3.5 Determinism and idempotence

- Report order = namespace sort; expectation set is a set (duplicates rejected); JSON field order fixed by the struct declaration; numbers decimal; both streams newline-terminated. Two runs against the same DB file and flags → byte-identical stdout, identical stderr, identical exit code. Cross-stage caveat: parse stops at the first failing flag, so *which* Set-time error message wins depends on argv order — the CI promise is per-invocation byte-stability (same invocation → same bytes); reordering `--expect` flags keeps exit code and stdout identical (output is sorted) but stderr message precedence may change. Rendering depends only on Go's `encoding/json` and `fmt` — no maps (struct order), no timestamps, no locale; the sqlite driver version plays no role in the output bytes.
- `verify` is a pure read — statements only, no locks, DDL, or writes — safe to run concurrently with a live server against `?mode=ro`. Two caveats, both covered by the §3.3 table: a plain (write) DSN on a nonexistent path materializes the DB file at open (the only mutation; the deploy form always uses `?mode=ro`), and an EXCLUSIVE lock window in flight surfaces as `open: database is locked (5) (SQLITE_BUSY)`, exit 1 (fail closed).
- No state, no cache, no signals; nothing changed in the binary or DB by invoking it.

## 4. Failure modes (beyond the input table)

| Failure mode | Behavior | Mitigation |
|---|---|---|
| Backend adds a migration, deploy tree forgets to bump `--expect` | `verify` still passes (floor satisfied); the bump rule is procedural (R6) | the *semantic* gap is closed by B4-5's new namespace (`governance_outbox` ≙ 0 until seeded → exit 1). Enforcement in the deploy-tree sweep (implementation-gate.md G5 row) |
| Operator typos a namespace (e.g. `--expect goverance_outbox=1`) | `verify` exits 1 with `got 0 (namespace absent or not migrated)` — an un-asserted typo is NOT detectable (tool has no inventory by design) | the error message names exactly what was asked; `status` on the same DB shows the actual inventory for cross-checking in the deploy runbook — documented, not tooled (rejected embedded-manifest direction) |
| Driver upgrades and changes the Ping error text | classification string match misses → falls into generic `open:` path, still exit 1 (fail-closed preserved, message degrades) | string match is to the stable `SQLITE_NOTADB` prefix; the probe remains the independent second net; a unit test pins current driver behavior |
| `verify` runs against a SQLite file whose version table exists but whose migration content is corrupted after application | `CurrentVersion` reads `MAX(version)`; corrupt rows → error → exit 1 (fail-closed) | covered by migrate's own read path; no new logic |
| Live server is mid-migration (deploy drill) | Two empirically pinned phases: (a) **during the migration** — `migrate.Run` holds `BEGIN IMMEDIATE` (RESERVED), which blocks only writers; `verify` reads a consistent pre-migration snapshot, Ping/probe/floors all pass, exit per floors (2/2 clean runs). (b) **in the migration-commit EXCLUSIVE window** (also VACUUM/backup holders) — the first statement (Ping) fails `database is locked (5) (SQLITE_BUSY)` → emitted as `open: database is locked …`, exit 1; **never** `unable to open database file`, and `?mode=ro` does not bypass it (readers need the shared lock too); `_pragma=busy_timeout(N)` in the verify DSN waits and re-tries before failing with the same string (9/9 clean runs) | pre-check before traffic cutover stays; busy-window mitigation is a busy_timeout DSN knob; WAL stores never block readers (verified) — the migration-phase claim that "reads a consistent snapshot" is the normal case, not a fallback |
| Operator runs without `--expect` / with `--expect audit=0` | usage error 2 / usage error 2 (≥ 1 required) | pinned tests |
| `--json` + DB error | no JSON body; stderr error; exit 1 | documented so pipelines don't parse empty stdout |

## 5. Compatibility constraints

Untouched and verified byte-identical after the change:

- `platform/migrate` (Status, CurrentVersion, versionTable, Run, CheckSchema) — zero edits.
- `status` paths: `runStatus`, `renderStatus`, `migrate.Status`, empty-DB message, exit codes → all existing migratecmd tests run with **zero `_test.go` edits** (this is the A5/T-9 pin; a dedicated `TestRunStatus_…` set already covers table/JSON/empty).
- `cmd/sso-ctl` dispatch: only the banner text line changes; the `subcommands` map, dispatch order, and other 15 subcommand behaviors untouched.
- No new dependencies: stdlib + `platform/migrate` already imported. `modernc.org/sqlite` already in the package's import set.
- Directory count of `cmd/sso-ctl`: 16/16 unchanged (files added under `migratecmd`, no new dirs).
- No `docs/openapi.yaml` / `docs/error-codes.md` / `docs/config-reference.md` changes (no HTTP surface, no `Err*`, no config keys) — the contractual additions are the two CLI help surfaces and the report shape documented in §3.1 and this doc.

## 6. Migration steps

Implementation order (each step leaves the tree green):

1. `cmd/sso-ctl/migratecmd/verify.go` — parse/floors/report/probe (`~150` lines; each function under 50 lines, cyclomatic ≤ 15).
2. `cmd/sso-ctl/migratecmd/verify_test.go` — acceptance tests §7.
3. `main.go` — add `case "verify"` (returns `runVerify(args[1:])`), update `usage()` and the package doc.
4. `cmd/sso-ctl/main.go` — banner line 15 (doc) + line 99 (usage text).
5. Gates (after every `.go` step): `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; then `go test ./cmd/sso-ctl/... ./platform/migrate/...` (proves A5). Handoff: `go test ./... -race`; `make ci`.

Deployment/campaign sequence (the product's migration story, unchanged by this change):

- The change ships in the sso-ctl binary only; the server's boot-time migration model (`infrastructure/postgres/migrate.go`, per-store forward-only at construction) is untouched — there is no schema migration for this change itself.
- Deploy-tree adoption: manifest adds the pre-check step `sso-ctl migrate verify --dsn 'file:/var/lib/sso/sso.db?mode=ro' --expect audit=3` (+`--expect clients=1` style lines as the tree's own inventory demands); the deploy-tree CI sweep (T-2/G5) records the JSON report as its diffable artifact.
- B4-5 bump rule (procedural, written into the requirements doc §R6): when a backend's migration slice grows → raise that namespace's `--expect` in the same change; when a new namespace appears (proposed `governance_outbox=1`) → add the line in the same change; never silently. Pre-B4-5 databases then fail the same predicate this design already ships (namespace absent → 0), which is exactly the T-9 predicate.
- Rollback: reverting the sso-ctl change is a binary-only rollback (no schema, no config, no server contract); the report shape is documentation-stable.

## 7. Testable acceptance mapping

`cmd/sso-ctl/migratecmd/verify_test.go` (seeding mirrors `seedDB` — `migrate.Run` with explicit `Migration{}` slices; no backend imports):

| Acceptance | Concrete test (function) | Setup & assertion |
|---|---|---|
| A1 pass: floors met | `TestVerify_Pass_FloorsMet` | seed ns `audit` v1–v3 (three `Migration{Version:1/2/3}`) + `governance_outbox` v1; `runVerify([]{"--dsn", <ro-dsn>, "--expect", "audit=3", "--expect", "governance_outbox=1", "--json"})` → exit 0, stdout contains `"ok":true` and both rows `"ok":true` |
| A1 fail: below floor | `TestVerify_Fail_BelowFloor` | audit v1–v2 only; `--expect audit=3` → exit 1, stdout contains `audit expected >= 3   got 2` |
| A1 fail: absured ns | `TestVerify_Fail_AbsentNamespace` | audit v1–v3 only; `--expect governance_outbox=1` → exit 1, `got 0 (namespace absent or not migrated)` |
| A1 live-DB form | `TestVerify_ReadOnlyDSN` | seed rw, re-run with `?mode=ro` appended → exit 0 (empirically verified viable: Ping + probe succeed on `mode=ro`) |
| A1 floor semantics | `TestVerify_AheadOfFloorPasses` | audit v1–v4; `--expect audit=3` → exit 0 |
| A2 non-SQLite | `TestVerify_NotSQLite_GarbageFile` | write `this is not a sqlite database file`; `Run(["verify","--dsn","file:"+f,"--expect","audit=3"])` → exit 1, stderr contains `not a SQLite database` (empirical: the Ping classification; the probe test below pins the internal path) |
| A2 probe path | `TestVerify_ProbeFailure` | simulated via an injected `*sql.DB` whose Ping succeeds but whose probe query fails (test double on `verifyDB`) → `not a SQLite database` |
| A2 busy/locked DB | `TestVerify_LockedDB_BusyIsNotNotSQLite` | test-double `*sql.DB` whose Ping fails with `database is locked (5) (SQLITE_BUSY)` (the exact modernc string; an EXCLUSIVE holder window) → exit 1, stderr contains `open: ` and `database is locked`, and **does not contain** `not a SQLite database` — pins the §3.3 busy classification introduced by the adversarial probe |
| A2 postgres-shaped DSN | `TestVerify_PostgresDSN_FailClosed`| `--dsn postgres://u:p@host:5432/db` → exit 1, stderr contains `open: ` (generic; no overclaim) |
| A2 regression proof | `TestStatusStillGreenOnGarbage`| `Run(["status","--dsn",garbageFile])` → exit 0 and `(no migrated namespaces…` (untouched `status` test family, added one cross-check) |
| A3 grammar suite | `TestVerify_UsageErrors` (table-driven) | `audit` (no `=`), `AUDIT=3`, `audit=0`, `audit=abc`, `audit=-1`, duplicate `audit=3 audit=2`, zero `--expect`, unknown flag → every row **exit 2, empty stdout, usage block on stderr**; per-stage message pins: Set-stage rows assert the flag package's `invalid value … for flag -expect:` prefix; post-parse rows (duplicate, zero, extra positional) assert `sso-ctl migrate: ` prefix naming the namespace. Mirrors the §3.2 stage-table |
| A3 JSON shape | `TestVerify_JSON` | `--json` on fail: **golden-bytes equality** — stdout bytes identical to `{"ok":false,"namespaces":[{"namespace":"audit","expected":3,"actual":2,"ok":false}]}\n` (field order + trailing newline pinned); parse with `encoding/json` and assert fields as a secondary check |
| A4 fail-closed empty | `TestVerify_FailClosed_EmptyDB` | fresh empty file + any `--expect` → exit 1 |
| A5 status pin | existing tests, zero edits | run `go test ./cmd/sso-ctl/migratecmd/` fails on any change to status output/exit |
| A6 diffable binding | `TestVerify_ReportNamesNamespace` | fail output contains the exact ns, expected, actual in both modes; JSON is the recorded artifact |
| Help & exit pins | `TestVerify_Help`, `TestVerify_UnknownFlag` | `-h` (and `--help`, `-help`) → 0 with usage on stderr, **empty stdout, no `flag: help requested` line**; `--bogus` → 2 with `flag provided but not defined` + usage block; `-expect audit=-1` → 2 with `invalid value …` — the §3.2 table's deliberate divergences |
| Determinism | `TestVerify_SortedOrder` | two `--expect` given in reverse order → identical stdout bytes both orders; run the same invocation twice → byte-identical stdout and identical exit code (no timestamps, no map order) |

Gate evidence at handoff: new tests + existing migratecmd tests + `platform/migrate` tests all run in the same invocation; the maintainability gates (file ≤ 500 lines each, per-function ≤ 50 / complexity ≤ 15 / nest ≤ 3) exercised by the repo's committed harness, and `make ci` for the full gate.

## 8. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Evidence's A2 stage model was empirically wrong (garbage fails at Ping) | Design pins the *outcome* (distinct message, exit 1) through Ping classification + probe; both paths tested; the message is identical regardless of which stage raises it |
| `status -h` exits 1 historically — verify diverges | explicit §3.2 table; pinned tests; zero impact on status |
| `--expect` namespace typo silently asserts the wrong name | report names the failing expectation; the runbook cross-checks with `status`; the JSON artifact makes the typo diffable against the tree's manifest review |
| Driver-coupled error text | prefix match on the fixed `SQLITE_NOTADB` message; fail-closed fallback; probe independence |
| Deploy tree forgets floor bumps | B4-5 new-namespace predicate (absence → 1) and G5 wiring as procedural enforcement |
| Two regexp copies of the namespace charset | one-line literal, cross-referenced comment; both sites enforce the same `^[a-z][a-z0-9_]*$`; `migrate.versionTable` rejects any mismatch as defense-in-depth for `CurrentVersion` interpolation |

## 9. Verification trail

Claim refutations with evidence: row 5 (cmd/ references exist — 27 repo hits incl. provisioner/billing/tests), row 7 (13+ migrate run sites beyond the 9 listed), row 11 (empirical probe results quoted in §3.3 tables), row 12 (exit-code probe results quoted in §3.2). Adversarial lock/permission/fs probe (this session, against `modernc.org/sqlite` v1.50.1, the pinned dependency): a second-process holder ran `BEGIN EXCLUSIVE` and `BEGIN IMMEDIATE` while the reader executed the verify pipeline open → Ping → probe → version query — `database is locked (5) (SQLITE_BUSY)` at Ping in 9/9 runs (plain + `?mode=ro`; `_pragma=busy_timeout(N)` only delays), RESERVED never blocked a reader (2/2); plus a read-only tmpfs (rw-DSN reads succeed; writes would be `attempt to write a readonly database (8)`), a chmod-000 file, a directory used as DSN, a missing file (rw-DSN creates an empty DB; `?mode=ro` says CANTOPEN), and a WAL-active-writer reader (snapshot ok). Those results are folded into §3.3's table/steps, §3.4/§3.5 caveats, §4's mid-migration row, and the new `TestVerify_LockedDB_BusyIsNotNotSQLite` pin. All other claims confirmed with line drift noted, per the table in §1. The 9-section, 171-line requirements spec's decisions survive in full except the two adjustments derived from the empirical probes; both adjustments are strictly strengthening (distinct message on the realistic input, strict usage-vs-failure exit taxonomy; the lock-row corrections keep every input on a fail-closed exit and never weaken a guarantee).