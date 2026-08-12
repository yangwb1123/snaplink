# Failure-pin matrix: §3.3 / §4 row audit against §7 tests (migrate verify)

- Design under audit: `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-design.md`
  — the §3.3 failure input table, the §4 failure-mode table, and the §7 testable
  acceptance mapping. This document is the pre-implementation pin set: every row of
  the two tables is mapped either to a concrete §7 test or to a written
  justification; rows with no dedicated test get one, specified with the exact
  exit code and stdout/stderr streams the table prescribes.
- Status: pins (design stage; implementation not started — `cmd/sso-ctl/migratecmd`
  still holds only `main.go`, `main_test.go`, `coverage_test.go`).
- Method: row-by-row audit of both tables against the §7 function list; the six
  rows the task names (missing file, missing directory, write-permission failure,
  mid-migration busy DB, corrupt/empty version table after application,
  Postgres-shaped DSN in `--json` mode) plus two adjacent uncertainties (the
  empty-DB input variants and the `?mode=ro` failure branch) were empirically
  re-probed against `modernc.org/sqlite v1.50.1` (the module's pinned version,
  go.mod:35) before specifying the pins.

## 1. Empirical grounding (fresh probes, Aug 2026, modernc.org/sqlite v1.50.1)

All probes ran against the same driver the package imports. "Ping" means
`PingContext` with a 3s timeout on a fresh `sql.Open("sqlite", dsn)`.

| Probe | Input | Result |
|---|---|---|
| P1 write-permission | seeded valid DB, `chmod 0400`, open WITHOUT `?mode=ro` | Ping nil — modernc falls back to a read-only open; a `0400` file is NOT a write-permission failure |
| P1 write-permission | same DB, `chmod 0200` / `0000` | Ping `unable to open database file (14)` |
| P2 missing file | `file:/tmp/absent.db?mode=ro` | Ping `unable to open database file (14)` |
| P3 missing dir | `file:/tmp/no-such-dir/x.db` | Ping `unable to open database file (14)` |
| P4 mid-migration busy | conn A `BEGIN EXCLUSIVE` over a seeded file; fresh reader | Ping `database is locked (5) (SQLITE_BUSY)` |
| P4 busy + `?mode=ro` | same lock, reader DSN `...?mode=ro` | Ping `database is locked (5)` — read-only mode does NOT bypass the lock |
| P4 busy + `busy_timeout(5000)` | same lock | still `database is locked (5)` — the exclusive transaction blocks Ping outright |
| P5 corrupt version table | `migrate.Run`-shaped table (`version INTEGER PRIMARY KEY`), then drop/recreate with `version TEXT` and a row `version='abc'`; run `SELECT COALESCE(MAX(version),0)` | Scan error `sql: Scan error on column index 0 ... converting driver.Value type string ("abc") to a int: invalid syntax` — deterministic; `migrate.CurrentVersion` errors → fail-closed exit 1 |
| P5 empty version table | same table shape, zero rows | `COALESCE(MAX(version),0)` = 0 → `CurrentVersion` returns `(0, nil)` → floor fails via the `got 0` marker |
| P6 empty DBs | `:memory:` / `/dev/null` / zero-byte file | Ping nil on all three; `sqlite_master` probe clean, 0 tables → every floor 0 → exit 1 with report |

Probe deltas that materially shape the pins:

1. The write-permission pin must use `0200`/`0000` (plus a root guard), never
   `0400` — `0400` opens read-only and the test would silently pass.
2. "Mid-migration busy" is reproducible: `BEGIN EXCLUSIVE` on one connection
   makes the next connection's Ping fail with `database is locked (5)`, so the
   failure surfaces through §3.3 step 2 (generic Ping error → `open: …`, exit 1)
   — exactly the "live server mid-migration" row, including under the documented
   `?mode=ro`.
3. A corrupt version table errors inside `CurrentVersion`; the empty-table
   variant returns `(0, nil)`. The two collapse into the same report surface
   only for the empty case — the corrupt case is a stderr error with no report.

## 2. §3.3 failure input table — row-by-row pin map

| §3.3 row (input) | Table-specified exit / stdout / stderr | Pin | Status |
|---|---|---|---|
| valid DB, all floors met | 0 / report / none | §7 `TestVerify_Pass_FloorsMet` + `TestVerify_AheadOfFloorPasses` (floor semantics: actual > min still passes); **extension**: additionally assert stderr empty in both | pinned |
| valid DB, floor unmet / ns absent | 1 / report / none | §7 `TestVerify_Fail_BelowFloor`, `TestVerify_Fail_AbsentNamespace`; **extension**: assert stderr empty in both | pinned |
| fresh empty DB (`:memory:`, zero-byte file, `/dev/null`) | 1 / report / none | §7 `TestVerify_FailClosed_EmptyDB` drives the zero-byte file only; `:memory:` and `/dev/null` untested | **gap → pin N-E1** |
| garbage file | 1 / none / `not a SQLite database: …` | §7 `TestVerify_NotSQLite_GarbageFile` (stdout empty, stderr message, exit 1) | pinned |
| missing file `?mode=ro` / missing dir | 1 / none / `open: …` | no §7 test | **gap → pin N-E2** |
| Postgres URI | 1 / none / `open: …` | §7 `TestVerify_PostgresDSN_FailClosed` (assert stderr `open: `, stdout empty — add the stdout-empty if not already asserted) | pinned |
| SQLite file `?mode=ro` (live DB) | 0/1 / report / none | §7 `TestVerify_ReadOnlyDSN` pins the 0 branch; the 1 branch (ro + floor unmet) has no test | **gap → pin N-E7** |
| write-permission failure | 1 / none / `open: …` | no §7 test — and a naive `chmod 0400` would not even produce the failure (P1) | **gap → pin N-E3** |
| usage errors (grammar, zero/dup, bad flags, no dsn) | 2 / none / usage | §7 `TestVerify_UsageErrors`, `TestVerify_UnknownFlag`, `TestVerify_Help`; **extension**: assert stdout empty in the usage tests | pinned |

## 3. §4 failure-mode table — row-by-row pin map

| §4 row | Behavior | Pin / justification |
| --- | --- | --- |
| Backend adds migration, tree forgets `--expect` bump | verify still passes | **Written justification (no test)**: undetectable by construction — a satisfied floor is indistinguishable from a floor the tree never raised. Enforcement is the procedural bump rule (R6) plus the B4-5 new-namespace predicate (or absent → exit 1, pinned by `TestVerify_Fail_AbsentNamespace`). |
| Operator typos a namespace | exit 1 with the failing row named | pinned: `TestVerify_Fail_AbsentNamespace` asserts exactly `got 0 (namespace absent or not migrated)`; the marker also carries the empty-version-table case (P5) |
| Driver upgrades change the Ping error text | generic `open:` path, still exit 1 | pinned two-way: `TestVerify_NotSQLite_GarbageFile` pins the classification hit; `TestVerify_PostgresDSN_FailClosed` plus pins N-E2/N-E3/N-E5 pin the generic fallback. A text change only degrades the message; the exit code is asserted unchanged by the fallback sets. |
| Version table corrupted after the migration was applied | exit 1 (fail closed) | no §7 test | **gap → pin N-E4** |
| Live server mid-migration (deploy drill) | lock → exit 1 `open: …`, or a consistent snapshot | no §7 test; the lock branch is deterministic (P4), the snapshot branch is the undisturbed-floor code path | **gap → pin N-E5** |
| No `--expect` / `--expect audit=0` | usage error 2 | pinned: `TestVerify_UsageErrors` covers zero-expect and `audit=0` rows | pinned |
| `--json` + DB error (Postgres-shaped DSN in JSON mode) | no JSON body, stderr error, exit 1 | no §7 test | **gap → pin N-E6** |

## 4. Missing pins (add to §7's `verify_test.go`; no API or design change)

Each pin names the §7 function it adds (or the function it extends), then fixes
the exit code and the stdout/stderr allocations exactly per the audited row.

### N-E1 — `TestVerify_FailClosed_EmptyDB`: extend to the three documented empty inputs

The row lists three inputs; the §7 test drives only the zero-byte file. Make the
test table-driven over:

| input | construction |
| --- | --- |
| `:memory:` | DSN `:memory:`, no file |
| `/dev/null` | DSN `/dev/null` as-is |
| zero-byte file | `os.WriteFile(tmp, nil, 0600)` |

Assertion per row: `Run(["verify","--dsn",dsn,"--expect","audit=1"])` → exit 1;
stdout non-empty containing `got 0 (namespace absent or not migrated)`;
stderr empty. P6 grounds that all three behave identically.

### N-E2 — `TestVerify_FailClosed_MissingFileDir` (new)

Two sub-cases pinning the "missing file `?mode=ro` / missing dir" row:

1. `--dsn file:<tmpdir>/absent-<n>.db?mode=ro` → exit **1**; stderr contains
   `open:` and `unable to open database file`; stdout **empty** (P2).
2. `--dsn file:<tmpdir>/no-such-dir/x.db` → exit **1**; stderr contains `open:`;
   stdout empty (P3). Assert on the prefix, not the `(14)` code (driver text).

### N-E7 — `TestVerify_ReadOnlyDSN`: add the failure branch

The `?mode=ro` row is `0/1 per floors`; §7 covers 0. Add: seed `audit` v1–v2,
run with `?mode=ro` and `--expect audit=3` → exit **1**; stdout contains
`expected >= 3   got 2`; stderr **empty**. The read-only form must render the
fail-closed report and must not mask floors.

### N-E3 — `TestVerify_FailClosed_WritePermission` (new)

Setup: seed a temp DB (any table), then `os.Chmod(file, 0200)` — per P1, `0400`
opens read-only and cannot pin the row; `0200` (no read bit) → SQLITE_CANTOPEN.
Guard: `if os.Geteuid() == 0 { t.Skip("permission bits do not block root") }`.
Assert: exit **1**; stdout **empty**; stderr contains `open:` and `unable to
open database file`.

### N-E4 — `TestVerify_FailClosed_CorruptVersionTable` (new)

Setup (mirrors `seedDB`, no backend imports): `migrate.Run(ctx, db, "audit",
{Migration{1,SQL}, Migration{2,SQL}, Migration{3,SQL}})` — table
`schema_migrations_audit (version INTEGER PRIMARY KEY, name TEXT NOT NULL,
applied_at TEXT)` (exact DDL at migrate.go:214). Then corrupt in place:

```
DROP TABLE schema_migrations_audit;
CREATE TABLE schema_migrations_audit (version TEXT PRIMARY KEY, name TEXT NOT NULL, applied_at TEXT);
INSERT INTO schema_migrations_audit VALUES ('abc','corrupt','x');
```

Sub-cases:
1. corrupt content, `--expect audit=3` → exit **1**; stdout **empty**; stderr
   contains `migrate(audit): read current version` (the P5 scan error surfaced
   via `migrate.CurrentVersion`, aborting before any report or partial blessing
   — §3.4 fail-closed).
2. empty version table (DDL created, zero rows) — the pre-B4-5 invariant →
   exit **1**; stdout report contains `got 0 (namespace absent or not
   migrated)`; stderr empty. Pins the "empty version table after application"
   reading of the row; the 0-vs-error split contradicts any attempt to collapse
   the two cases.

### N-E5 — `TestVerify_FailClosed_BusyDB` (the mid-migration row)

Setup: seed the DB; hold the write lock on a separate handle:

```go
conn, err := db.Conn(ctx)
conn.ExecContext(ctx, "BEGIN EXCLUSIVE")
defer conn.Close() // close releases the lock
// verify opens its OWN *sql.DB on the same file
```

Sub-case (a) plain DSN (operator race with the migration transaction): exit **1**;
stderr contains `open:` and `database is locked`; stdout **empty**.
Sub-case (b) `?mode=ro` under the lock — the documented live-DB form is still
locked (P4): exit **1**, stderr contains `open:` and `database is locked`,
stdout empty. The consistent snapshot outcome (0/1 per floors, un-locked read)
is the same code path as the undisturbed floor read pinned by N-E7's 0-branch;
no third sub-case needed.

### N-E6 — `TestVerify_JSON_DriverError` (the `--json` + DB-error row)

Sub-case (a) Postgres-shaped DSN with `--json`: exit **1**; stdout **empty**
(no JSON object — pipelines must not parse an empty body); stderr contains
`open: `.
Sub-case (b) busy DB with `--json`: same exit and streams, stderr contains
`database is locked`.

## 5. Written justifications for rows without a new test (implicit coverage)

| Row | Justification |
| --- | --- |
| §3.3 garbage file | has its dedicated test (`TestVerify_NotSQLite_GarbageFile`: stderr `not a SQLite database`, stdout empty, exit 1); the probe-stage path is independently pinned by §7 `TestVerify_ProbeFailure`. No new test. |
| §4 driver-driven Ping text | the generic fallback outcome (exit 1, stderr `open: `, stdout empty) is asserted by `TestVerify_PostgresDSN_FailClosed` and by pins N-E2/N-E3/N-E5, which are exactly the outputs any unclassified Ping error must produce. Text degradation cannot change the exit code; the row is the behavior these pins assert. |
| §4 deploy tree forgot the bump | cannot be a unit test: a satisfied floor is indistinguishable from an un-raised floor. Enforcement is the absent-namespace predicate (B4-5 `governance_outbox` → 0 → exit 1, pinned by `TestVerify_FailAbsentNamespace`) plus the R6 procedural rule. |

## 6. Assertion-compliance checklist (per row, exact)

Every pin asserts all three channels: exit code (exact 0/1/2), stdout (empty or
the mandated report fragments), stderr (empty or the mandated `open: ` /
`not a SQLite database` / `database is locked` / usage text). The two streams
are mutually exclusive in every row — a row either emits the diffable report on
stdout or diagnostics on stderr, never both. Report-path tests assert stderr
empty explicitly; diagnostic-path tests assert stdout empty explicitly; the
three usage tests assert stdout empty explicitly.

## 7. Handoff effect

- §7 grows from 16 named functions to 21: new `TestVerify_FailClosed_MissingFileDir`
  (N-E2), `TestVerify_FailClosed_WritePermission` (N-E3),
  `TestVerify_FailClosed_CorruptVersionTable` (N-E4),
  `TestVerify_JSON_DriverError` (N-E6); extensions to
  `TestVerify_FailClosed_EmptyDB` (N-E1) and `TestVerify_ReadOnlyDSN` (N-E7);
  stderr-empty / stdout-empty assertions woven into the existing pass/fail/usage
  tests. All live in `cmd/sso-ctl/migratecmd/verify_test.go` (implementation
  order step 2); no new packages, directories, or `migratecmd` file budget
  changes.
- The remaining §7 functions are not failure-table rows and are untouched:
  `TestStatusStillGreenOnGarbage` (A2 status-compat cross-check), `TestVerify_JSON`
  (report shape), `TestVerify_ReportNamesNamespace` (A6), `TestVerify_SortedOrder`
  (determinism), `TestVerify_ProbeFailure` (probe-stage pin).
- No change to the §3.2/§3.3/§3.4 contracts or the A1–A6 acceptance split;
  N-E1…N-E7 only add rows the audit found blank. The N-E3 guard (root skip)
  names the repo gate in its skip message so a root CI cannot silently drop it.
- The pins run in the same invocation as the rest of §7: `go test
  ./cmd/sso-ctl/migratecmd/...` (design §6 step 2).

## 8. Verification trail

Probe results P1–P6 are quoted verbatim in §1; each pin's assertion derives from
one of them (the `open: ` family from P1–P3; `database is locked` from P4; the
corrupt/empty division from P5; the three-input identity from P6). The
`0400-opens-readonly` finding (P1) is the single probe delta that materially
changes a test shape (N-E3), so its wording is quoted verbatim for the
implementer.
## 9. Addendum — adversarial re-probe of the §3.3/§4 rows (same session as the design's §3.3 table rewrite)

A second adversarial probe (cross-process holder; the reader runs the exact
open → Ping → probe → `CurrentVersion` pipeline) against the same driver and
version confirmed the pins and corrected the remaining exact strings. Deltas
folded into the design doc's §3.3 steps/table (§3.4/§3.5 caveats, §4
mid-migration row, and the new `TestVerify_LockedDB_BusyIsNotNotSQLite` pin):

1. **Exact busy string**: both the plain and the `?mode=ro` reader DSNs fail at
   Ping with `database is locked (5) (SQLITE_BUSY)` — the `(SQLITE_BUSY)`
   descriptor suffix is always present (9/9 runs; N-E5's substring assertion on
   `database is locked` is unaffected, but pin the suffix in the golden string).
   `_pragma=busy_timeout(N)` delays the same error by N ms — it never converts
   the window into a pass.
2. **Mid-migration splits in two phases** (`migrate.Run`'s real lock is
   `BEGIN IMMEDIATE` → RESERVED): readers are never blocked during the
   migration body (consistent snapshot, 2/2 runs) — only the migration-commit
   EXCLUSIVE window (and VACUUM/backup holders) yields the P4 busy error.
   N-E5's "snapshot branch is the undisturbed code path" justification is now
   primary empirical: the pinned `?mode=ro` + locked read still exits 1 with the
   busy message.
3. **New input rows** for the design's table, all empirically grounded:
   a directory used as DSN (plain path or `file:` URI) → Ping
   `unable to open database file (14)`, generic `open: …` bucket; a missing
   file with a plain rw DSN is NOT an error — sqlite **creates the file** and
   the run continues (all floors 0 → exit 1 with report) — the only mutation
   `verify` can perform, so the deploy form stays `?mode=ro`; an existing DB on
   a read-only filesystem is also not an error — reads
   succeed (writes would be `attempt to write a readonly database (8)`, which
   verify never emits); a WAL store with an active uncommitted writer is
   transparent to readers (pre-write snapshot; `-shm`-absent `mode=ro` opens
   also work).
4. N-E3's permission pin and P1's 0400 fallback confirmed: only files without
   the read bit (0200/000) produce `unable to open database file (14)`;
   `0400` files fall back to a read-only open. No pin in N-E1..N-E7 changes;
   the design's row labels were precision-tightened to match.

All assertions the pins make (exit codes, stream exclusivity) still hold;
nothing in this addendum changes N-E1…N-E7.
