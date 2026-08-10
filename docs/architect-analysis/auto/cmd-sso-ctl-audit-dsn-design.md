# Design: durable-store `--dsn` verification (sqlite AND postgres) + `auth.token.issue` L1 aggregation (cmd/sso-ctl)

Design for the direction "B4-5/G5: add durable-store `--dsn` verification (sqlite
AND postgres) plus `auth.token.issue` L1 aggregation attestation to
audit-verify/audit-export". Supersedes the file-layout choices of
[cmd-sso-ctl-audit-dsn-requirements.md](cmd-sso-ctl-audit-dsn-requirements.md)
in exactly two places (§2), each backed by a hard gate; everything else follows
the requirements spec. Doc-only artifact; no `.go` edits, so no build gates are
triggered by this file.

Module: `cmd/sso-ctl` (composition layer; dispatch `cmd/sso-ctl/main.go:47-50`).

## 1. Evidence verification — untrusted claims re-checked against the tree

Every claim in the supplied evidence was independently re-verified. All are
TRUE; line numbers drift by 0-2 lines in a few places and one structural
constraint (subdir fan-out) contradicts the requirements doc's file plan (§2).

| # | Claim | Verdict | Evidence (this tree) |
|---|---|---|---|
| C1 | `auditverify` `verifyOptions` has no `dsn` (fromFile/fromURL/bearer/limit/pageSize/timeout/checkpoint/notaryKey/anchorHash) | ✅ | `cmd/sso-ctl/auditverify/main.go:82-92` struct; flags at 99-112; source exclusivity in `checkMisuse` at 203-210 ("one of --from-file or --from-url is required"; "--from-file and --from-url are mutually exclusive"). `grep dsn` over the package: none. |
| C2 | `auditexport` is sqlite-only `--dsn` via `auditsqlite.OpenReadOnly`, never migrating | ✅ | Import block: `auditsqlite "…/platform/audit/sqlite"` is the only store import; `--dsn` help at main.go:145 "SQLite DSN to export from … append ?mode=ro"; open at 182-186 with comment "OpenReadOnly never migrates"; package doc 16-17 states the never-migrate contract. `grep postgres cmd/sso-ctl/auditexport cmd/sso-ctl/auditverify`: none. |
| C3 | sqlite + postgres backends store `prev_hash`/`hash` | ✅ | `platform/audit/sqlite/sink.go:103-104` (`prev_hash TEXT, hash TEXT` in DDL); `infrastructure/postgres/audit_sink.go:49-50` (DDL) and :162 (`metadata_json, prev_hash, hash, server_version` in `auditInsert`); `audit_query.go:24` (`selectAuditColumns`) and 213-214 (`e.PrevHash = prev.String; e.Hash = hash.String`). Both `Query` implementations return newest-first (`ORDER BY ts_unix_ns DESC`; sqlite query.go:82-85, postgres audit_query.go:85-86). |
| C4 | chainer anchoring primitives exist | ✅ | `platform/audit/chainer.go`: `GenesisHash = ""` :141, `VerifyChain` :157, `VerifyChainSegment` :172, `NewEd25519CheckpointSigner` :255, `VerifyChainAgainstCheckpoint` :469. Verification core consumes `[]*audit.Event` in chain order — store-agnostic. |
| C5 | `RecordTokenIssued` + L1 aggregation absent repo-wide | ✅ | `platform/audit/recorder_events.go:19-24` emits `Type = EventTokenIssued` (`"token_issued"`, `auditspi/event_types.go:15`), `Outcome = OutcomeSuccess`, always (one stored row per call — `rec.Record` once). `auth.token.issue` appears in `.go` **code**: zero (one `.go` *comment*, `cmd/sso-ctl/auditexport/main_test.go:297`, mentions the string; no code uses it); only `docs/proposals/audit-contract-batch-snaplink.md:16` carries the mapping and L1 aggregation position, marked `[PROPOSED]`. |
| C6 | No postgres `--dsn` in either audit tool; `importcmd --backend postgres` targets the user store | ✅ | `cmd/sso-ctl/importcmd/main.go:123-125` (`--backend sqlite\|postgres`), `importer.go:36,42-47` builds `sqlite.NewUserProvider` / postgres user provider (`postgres.NewUserProvider` path) — the user store, not audit. Neither audit tool imports `infrastructure/postgres`. |
| C7 | URL API path pages newest-first at 1000/page | ✅ | `readFromURL` at auditverify/main.go:403-444 pages with `pageSize` capped at `audit.MaxQueryLimit` (`auditspi/query.go:9` = 1000), probes a page at exact-`--limit` fill, slices newest-N, then `reverseEvents` (:482-487) into chain order. |
| C8 | `postgres.NewAuditSink` migrates — a read-only tool must not call it | ✅ | `infrastructure/postgres/audit_sink.go:107-110` ("opens cfg.DSN, migrates the schema"); `NewAuditSinkWithDB` :121-128 runs `Run(ctx, db, "audit", auditMigrations, dialect)`. Version table `schema_migrations_audit` via `versionTable("audit")` (migrate.go:35-39). `postgres.Open` (pool.go:53-73) only dials/sizes/pings — no DDL. `migrate.MaxVersion` (`platform/migrate/migrate.go:339`) and postgres-local `CurrentVersion` (infrastructure/postgres/migrate.go:198-218) are the primitives for a fail-closed check. |
| C9 | `auditexport.QueryPager` — one method, both stores satisfy it structurally | ✅ | `platform/audit/auditexport/auditexport.go:68-76`; `pageAll` (:173-197) reverses newest-first pages (:195). `*sqlite.Sink` (sqlite/query.go:75) and `*postgres.AuditSink` (audit_query.go:79) both have `Query(ctx, audit.Query) ([]*audit.Event, error)` — `BuildExportBundle` needs zero changes for postgres. |
| C10 | `auditverify/main.go` is 499 lines — DSN code must not grow it | ✅ | `wc -l` = 499. Adding the ~20-line `--dsn` wiring would exceed 500 (§2.2). `auditexport/main.go` = 442. |
| C11 | Postgres integration tests skip without `SSO_TEST_POSTGRES_DSN` | ✅ | `infrastructure/postgres/postgres_test.go:13-19` (`testDSN`, `t.Skip("SSO_TEST_POSTGRES_DSN not set …")`). |
| C12 | Dispatch table maps `audit-verify`/`audit-export` to in-process `Run(args) int` | ✅ | `cmd/sso-ctl/main.go:47-48`; both `Run` return the exit code (no `os.Exit` in the new paths; legacy `usageErr`/`errorf` still exit, binary behavior identical via `os.Exit(run(args))`). |
| C13 | `audit.Query` semantics: half-open window, `NormalizedLimit` clamping | ✅ | `auditspi/query.go:9-11` ("inclusive for Since and exclusive for Until"), :84-91 (Limit clamped to `(0, MaxQueryLimit]`, default 100). |
| C14 | `audit-export` `parseTime` accepts RFC3339 or unix seconds | ✅ | `cmd/sso-ctl/auditexport/main.go:330-341`. |

Additional facts the design relies on (verified): `audit.Event` has `Type`,
`ClientID`, `Timestamp` (auditspi/event.go:21-53); `checkSchemaCurrent` is the
sqlite fail-closed version probe (sqlite/sink.go:191-200); `OpenReadOnly` is at
sqlite/sink.go:169; `postgres.Config{DSN, Dialect, pool}` at pool.go:35-51;
postgres `CheckSchema` (migrate.go:222-233) only rejects schema-too-new — a
*stale* store must be compared for equality, not via `CheckSchema`.

## 2. Design corrections to the requirements spec (gate-backed)

The requirements doc's file plan would violate two committed gates. Both are
corrected here without changing any requirement's semantics.

### 2.1 Zero new subdirectories under `cmd/sso-ctl` (fan-out ceiling is 16/16)

`directory_fanout_test.go`: `maxSubdirsPerDir = 16` (:35), no exemption for
`cmd/sso-ctl`, and `TestArchitecture_DirectorySubdirFanout` fails on the 17th
subdir. `cmd/sso-ctl` already has exactly **16** subdirectories (apiclient,
auditexport, auditverify, clientscmd, configcmd, entitiescmd, generate,
hashcmd, importcmd, legacysync, migratecmd, sessionscmd, snapshotcmd,
soc2report, tokenscmd, tui). The requirements doc's `cmd/sso-ctl/auditstore/`
+ `cmd/sso-ctl/auditagg/` would make 18 → gate failure.

**Correction:** both new units fold into existing packages; subdir count stays
16; no new Go package means no `layerName()` classification change either.

**Subdir drift note (three-way).** The committed Go gate is 16 (`maxSubdirsPerDir`, directory_fanout_test.go:35), but `engineering.yaml` `directory_fanout.max_subdirs` is 15 and AGENTS.md states 15 with an explicit note not to exploit the Go gate's `>16` drift; the Python mirror (`checks/directory_fanout.py`, max 15, run via `adr-compliance`, *not* `make ci`) already flags `cmd/sso-ctl` at 16 > 15. "16/16" is correct for the committed Go gate only; the folding keeps the count at 16 under either number, and no new subdirectory is added.

- Shared store reader + dialect classifier → `cmd/sso-ctl/auditexport/store.go`
  (package `auditexport`). Rationale: that package already owns the
  store-open/read-only/never-migrate contract (main.go:16-17, 182-186) and the
  open-ordering discipline; the opener is an extension of its responsibility.
- `audit-agg` → `cmd/sso-ctl/auditexport/agg.go` as `RunAgg(args []string) int`;
  dispatch entry `"audit-agg": auditexport.RunAgg`. It shares the opener with
  zero cross-package imports.
- `audit-verify` consumes the shared reader by importing
  `cmd/sso-ctl/auditexport` (sibling composition-layer import; allowed — the
  "no package imports `cmd/`" rule governs other layers importing cmd, and
  `cmd/` is the outermost composition layer; everything is one binary anyway).

Non-test Go file counts stay within `maxGoFilesPerDir = 10`:
`cmd/sso-ctl/auditexport`: main.go + store.go + agg.go = 3;
`cmd/sso-ctl/auditverify`: main.go + segment.go + url_source.go = 3.

### 2.2 `auditverify/main.go` at 499 lines — move, then wire

Adding `--dsn` (flag ~3 lines, exclusivity ~8, `loadEvents` branch ~3, usage
banner ~4) to a 499-line file crosses the 500-line Go-file budget.

**Correction:** move `readFromURL`, `fetchEventPage`, and `reverseEvents`
(auditverify/main.go:395-487, ≈90 lines) verbatim into a new file
`cmd/sso-ctl/auditverify/url_source.go` **first** (pure relocation, zero
behavior change — the T-9 suite proves it), leaving main.go at ~410 lines with
headroom for the ~20-line `--dsn` wiring.

## 3. API changes

### 3.1 CLI surface (`sso-ctl`)

**`audit-verify`** — new flag `--dsn <dsn>`, a third mutually exclusive source:

```text
--dsn <dsn>  read-only audit store (sqlite file path / file: URI, or postgres://
             | postgresql:// URL); mutually exclusive with --from-file/--from-url;
             opened read-only, NEVER migrated; --timeout-sec does not apply
```

- `verifyOptions` gains `dsn string`; `parseFlags` binds `--dsn`.
- `checkMisuse` additions (all return 2, in-process-testable, matching the
  existing `checkMisuse` pattern — not `os.Exit`): `--dsn` with `--from-file` or
  `--from-url` → "`--dsn` is mutually exclusive with `--from-file` and
  `--from-url`"; `--dsn` with `--bearer` → "`--bearer` applies only to
  `--from-url`"; source-required message becomes "one of --from-file,
  --from-url, or --dsn is required".
- `loadEvents` gains: `if o.dsn != "" { return readFromStore(o.dsn, o.limit, o.pageSize) }`
  (3 lines).
- `--checkpoint`, `--notary-key`, `--anchor-hash`, `--limit`, `--page-size`
  compose identically for the DSN source (one verification core, no fork).

**`audit-export`** — existing `--dsn` accepts postgres URLs:

```text
--dsn <dsn>  audit store to export from: sqlite file path (read-only, append
             ?mode=ro for a live DB) or postgres://|postgresql:// URL (opened
             read-only, never migrated; enforce read-only via a DB role /
             default_transaction_read_only)
```

- `run(o)` replaces the direct `auditsqlite.OpenReadOnly(o.dsn)` call with the
  shared `OpenStoreReadOnly(ctx, o.dsn)`; the sqlite branch underneath is the
  same function, so sqlite behavior is byte-identical (T-9).
- Open ordering unchanged: `--anchor` loads and signature-checks before the
  store opens (main.go:169-181); schema-version check inside the opener.

**`audit-agg`** — new subcommand, registered in the dispatch table
(`cmd/sso-ctl/main.go`: `"audit-agg": auditexport.RunAgg`):

```text
sso-ctl audit-agg --dsn <dsn> --interval 1h [--since <RFC3339|unix>] [--until …]
                  [--event token_issued] [--client-id <id>]

Proposed surface: the auth.token.issue mapping and L1 aggregation position are
PROPOSED (docs/proposals/audit-contract-batch-snaplink.md:16); this command
attests stored token_issued rows only and makes no tamper-evidence claim.
```

- `--dsn` required (same classifier); `--interval` required (`time.ParseDuration`,
  > 0); `--since`/`--until` optional half-open `[since, until)` reusing
  auditexport `parseTime`; `--event` default `token_issued`, only accepted
  value; `--client-id` optional filter.
- stdout: deterministic TSV `interval_start<TAB>client_id<TAB>count`, sorted by
  (interval_start, client_id), RFC3339 UTC bucket start; stderr: one summary
  line (event/client/interval counts). Exit 0 incl. empty window.

`RunAgg` is implemented as a thin parse/collect/emit decomposition — `parseAggFlags` / `aggCollect` / `aggEmit` (§3.2) — because a monolithic `RunAgg` (~90 lines, cyclo ~18) fails the ≤50-line and ≤15-cyclo function gates (verified in full-tree simulation; the design's blanket §4.5 budget claim is only guaranteed by this decomposition).

### 3.2 Go API

**`infrastructure/postgres`** — one new exported constructor (new file
`audit_readonly.go`, root module):

```go
// OpenAuditReadOnly opens cfg.DSN for query-only audit reads and returns the
// audit sink. It NEVER migrates: the migration runner is not invoked, and the
// audit schema version recorded in schema_migrations_audit must equal this
// binary's expected version or the open fails closed (mirrors sqlite's
// OpenReadOnly/checkSchemaCurrent contract). The tool issues SELECTs only;
// operators should additionally use a read-only role or
// default_transaction_read_only.
func OpenAuditReadOnly(cfg Config) (*AuditSink, error)
```

Implementation: `postgres.Open(cfg)` (pool.go:53) → `CurrentVersion(ctx, db,
"audit")` (migrate.go:198) vs `migrate.MaxVersion(auditMigrations)`
(platform/migrate/migrate.go:339); mismatch → close + error naming found vs
expected versions, **no DDL**. Note the postgres-local `CheckSchema` is NOT
reused: it only rejects schema-too-new; a stale store must be a hard error too
(fail-closed, mirroring sqlite). Additive — `audit_sink.go` untouched.

**`cmd/sso-ctl/auditexport`** (new files `store.go`, `agg.go`):

```go
type StoreKind int // StoreSQLite | StorePostgres
func ClassifyDSN(dsn string) StoreKind          // TrimSpace(dsn) first (importcmd precedent, importer.go:34), then postgres://|postgresql:// (case-insensitive) → postgres; else sqlite
func OpenStoreReadOnly(ctx context.Context, dsn string) (auditexport.QueryPager, io.Closer, error)
func ReadAll(ctx context.Context, dsn string, q audit.Query, pageSize int) ([]*audit.Event, error)      // pages newest-first, reverses to chain order
func ReadChain(ctx context.Context, dsn string, limit, pageSize int) ([]*audit.Event, bool, error)      // ReadAll + --limit cap + truncation probe + newest-N slice
func RunAgg(args []string) int                                                                          // audit-agg entry (thin: parseAggFlags/aggCollect/aggEmit)
```

`ReadChain` mirrors `readFromURL` exactly (auditverify/main.go:403-444,
420-428): page `audit.Query{Offset, Limit: pageSize}` newest-first, cap
pageSize at `audit.MaxQueryLimit` (1000), default 500; at exact-`limit` fill
probe one page at the same offset to decide truncation; slice `collected[:limit]`
**before** reversing (newest-N prefix semantics identical to URL mode).

**Same-offset probe quirk (documented, pre-existing).** The exact-fill probe re-reads the **same offset** the page was just fetched from — the code comment at main.go:421-423 claims "next offset" but `offset` is not advanced before the probe (main.go:429). Consequence: any run where `len(collected) == limit` exactly reports `truncated=true`, even when the chain ends exactly at `limit` (fail-closed; pre-existing URL-mode semantics — `TestReadFromURL_ProbeDetectsTruncation`, checkpoint_test.go:570, cannot discriminate it). The verbatim `url_source.go` move carries both the behavior and the stale comment. Test consequences: truncation tests use `limit` strictly less than the chain length; A1's clean test uses N far below `--limit` so the probe never fires.

## 4. Compatibility constraints

1. **T-9 byte-identical surfaces.** Every existing `audit-verify` flag/output
   line (`--from-file`, `--from-url`, `--bearer`, `--limit`, `--page-size`,
   `--timeout-sec`, `--checkpoint`, `--notary-key`, `--anchor-hash`) and every
   `audit-export` behavior (sqlite `--dsn` bundle, `--verify`, filters,
   `--anchor`) is unchanged when the new flags are absent. Proof: the existing
   suites (`cmd/sso-ctl/auditverify/{main,checkpoint,segment,coverage}_test.go`,
   `cmd/sso-ctl/auditexport/main_test.go`) pass unmodified, plus the verbatim
   `url_source.go` move lands before any wiring. **Worktree state (F4):** the evidence base is a dirty worktree (827 modified files; the frozen `platform/audit/auditexport/auditexport.go` already carries an uncommitted +8/-3 edit from another in-flight task). The verbatim move and the T-9 proof must run against that same state; the frozen-file guarantee means this design adds no edits to it, not that it is pristine. **Bundle qualification:** "sqlite export bundle bytes unchanged" overstates the existing tests — they assert structure / `"anchor"`-key absence / self-verify / `EventCount`, not golden bytes, and the bundle embeds `GeneratedAt: time.Now()` (auditexport.go:133), so byte-golden is impossible; the correct claim is "structurally identical modulo GeneratedAt".
2. **Never-migrate is a hard contract on all three surfaces.** sqlite reuses
   `OpenReadOnly` (never migrates, fail-closed `checkSchemaCurrent`);
   postgres uses `OpenAuditReadOnly` (no `Run(...)` call). A version-mismatched
   store is reported (exit 1), never migrated, never read through a wrong
   query path.
3. **No upward imports, no new layers.** New imports only:
   `cmd/sso-ctl/auditexport` → `infrastructure/postgres` (+ existing
   platform/audit, platform/audit/sqlite, platform/audit/auditexport);
   `cmd/sso-ctl/auditverify` → `cmd/sso-ctl/auditexport`. Zero new packages →
   no `layerName()` change, no `layerExemptions` entry.
4. **Frozen files untouched:** `platform/audit/chainer.go`,
   `recorder_events.go`, `auditexport/auditexport.go`, `sqlite/sink.go`,
   `infrastructure/postgres/audit_sink.go`, `interfaces/sso/*` (60-file
   ceiling). `docs/openapi.yaml`, `docs/error-codes.md`,
   `docs/config-reference.md`: no changes (CLI-only, no new server endpoints,
   errors, or config keys). The `[PROPOSED]` marker in
   `docs/proposals/audit-contract-batch-snaplink.md:16` is untouched.
5. **Budgets.** Subdirs: 16/16 (no new dirs). Non-test files per dir: ≤ 3/10.
   `auditverify/main.go` ≤ 500 after the move; `auditexport/main.go` 442 + ~15
   (opener call + help text) stays under 500. New functions ≤ 50 lines,
   complexity ≤ 15, if-nesting ≤ 3 (the reader mirrors `readFromURL`'s proven
   shape, ~40 lines; `RunAgg` is pinned as `parseAggFlags`/`aggCollect`/`aggEmit` — a monolithic version fails both function gates). No root `go.mod` change (pgx is already a root-module
   dependency).
6. **Dialect rule is total and unambiguous.** `postgres://`/`postgresql://`
   (case-insensitive) prefix → postgres; everything else → sqlite. Documented
   limitation: pgx keyword/value connection strings (`host=… user=…`) carry no
   scheme and are therefore treated as sqlite paths — the sqlite-open failure
   diagnostic must add "did you mean a postgres:// URL?" guidance (§5 FM-3).

## 5. Failure modes

| # | Failure | Surface | Exit | Behavior |
|---|---|---|---|---|
| FM-1 | Misuse: `--dsn` + `--from-file`/`--from-url`/`--bearer`; missing source; `--dsn` missing (agg); bad `--interval`; bad `--since`/`--until`; `--event` ≠ `token_issued` | verify / export / agg | 2 | Diagnostic + usage banner. Unknown `--event` adds the PROPOSED-status line. New verify misuse paths return 2 (testable), never `os.Exit`. |
| FM-2 | Store open failure (missing/junk sqlite file, permissions, unreachable postgres, bad credentials) | all | 1 | sqlite: `sql.Open`+ping **create** a missing file (modernc driver) and the failure surfaces at the `checkSchemaCurrent` version probe — an empty file IS left behind (zero DDL, but "nothing written" is false; empirically verified on modernc v1.50.1). postgres: dial/ping/version-probe diagnostic naming found vs expected. |
| FM-3 | Scheme-less postgres conn string misclassified as sqlite | verify/export/agg | 1 | sqlite **schema-version-probe** diagnostic (the string creates a junk file, then fails `checkSchemaCurrent`) + guidance "postgres DSNs must use postgres:// or postgresql:// URLs; keyword/value forms are not supported" — the guidance attaches to the version-mismatch diagnostic, not to an open error. |
| FM-4 | Schema version mismatch (stale or too-new audit schema) | verify/export/agg | 1 | sqlite: `checkSchemaCurrent` message; postgres: found-vs-expected versions. Zero DDL executed (asserted via the pinned mechanism in §7 REQ-5: read-only-transaction DSN + post-run schema-state assertion — a `QueryTracer` DDL-free trace is NOT implementable, `OpenAuditReadOnly` has no tracer hook). |
| FM-5 | Read-only role violation (SELECT denied) | verify/export/agg | 1 | Page error diagnostic. |
| FM-6 | Single flipped `hash` (or `prev_hash`) row | verify | 1 | `chain BROKEN: …`; stdout never claims a clean chain. Export: `BuildExportBundle` self-verify fails (auditexport.go:142), exit 1, no bundle file left behind. Agg: unaffected by design (no tamper claim — non-goal). |
| FM-7 | `--limit` truncation | verify | 1 | Unanchored/`--anchor-hash`: `prefix verified: N event(s) — truncated by --limit N; head=… is not the full chain` (main.go:272 format); `--checkpoint`: fail-fast "event list truncated by --limit N before the attested head" with no verification output (main.go:159 format). |
| FM-8 | Empty store / empty window | verify / agg / export | 0 | verify: `no events to verify`; agg: empty stdout + zero-count summary; export: `EventCount == 0` bundle (existing contract). |
| FM-9 | Checkpoint/anchor load failure | verify / export | 1 | Loads before the store opens (fail-fast ordering preserved). |
| FM-10 | Mid-read page error (store removed, connection drop) | all | 1 | `load events: …` / `query (offset=N): …`; no partial claim printed. |
| FM-11 | Hanging DB | verify/export/agg | – | `--timeout-sec` documented as not applicable (no HTTP client); local/DB reads block. Ctrl-C is the operator lever; a timeout knob is an explicit non-goal. |

## 6. Migration steps

**Database: none.** All three surfaces never migrate; there is no schema change
and no migration tooling in this direction. An operator pointing a tool at a
version-mismatched store gets exit 1 with a version diagnostic; the remediation
is either to run the stock `sso-server` against the store (its boot path runs
the audit migrations) or to use a binary whose expected version matches the
store — never a tool flag.

**Code, in dependency order (each step leaves the tree green):**

1. `infrastructure/postgres/audit_readonly.go` + `audit_readonly_test.go`
   (fail-closed version check; SELECT-only; skip convention
   `SSO_TEST_POSTGRES_DSN`). Gates: build/vet + postgres tests.
2. `cmd/sso-ctl/auditexport/store.go` + `store_test.go`: `ClassifyDSN`
   table test, sqlite read/reverse/paging tests, misuse-free classifier
   without a live DB. Gate: `go test ./cmd/sso-ctl/auditexport/`.
3. `cmd/sso-ctl/auditverify/url_source.go` — verbatim move of
   `readFromURL`/`fetchEventPage`/`reverseEvents`; run the full auditverify
   suite to prove byte-identical behavior; THEN wire `--dsn` in main.go
   (flag, `checkMisuse`, `loadEvents` branch, usage banner) + `dsn_test.go`.
4. `cmd/sso-ctl/auditexport/agg.go` (RunAgg decomposed: `parseAggFlags`/`aggCollect`/`aggEmit`) + `agg_test.go`; `"audit-agg"` dispatch
   entry in `cmd/sso-ctl/main.go`.
5. `auditexport/main.go` postgres wiring (help text + `OpenStoreReadOnly`
   call); usage banners; full gates below.

**Rollout/rollback:** additive flags in one binary; rollback = previous binary
(new flags absent → old behavior). No server restart, no config, no store
mutation, no wire-format change. `audit-agg` ships without changing the
`[PROPOSED]` status of the mapping.

## 7. Testable acceptance mapping

Acceptance (verbatim from T-9/G5) → requirements → tests → gates:

| Acceptance | Requirements | Test (new) | Assertion |
|---|---|---|---|
| A1: `audit-verify --dsn <sqlite\|postgres>` exits 0 clean / 1 on a single flipped hash | REQ-1 c1-2, REQ-2 c3 | `TestVerifyDSNSQLiteClean`, `TestVerifyDSNSQLiteFlippedHash`, `TestVerifyDSNPostgresFlippedHash` | Clean: exit 0, stdout exactly `chain verified: N event(s), head=<H>`, `<H>` = last stored row's `hash` (N « `--limit` so the exact-fill probe never fires — §3.2 quirk). Flipped: `UPDATE audit_events SET hash='deadbeef' WHERE id=<i>` only; exit 1, stderr contains `chain BROKEN`. Postgres variant under `SSO_TEST_POSTGRES_DSN` (skips otherwise). |
| A2: byte-consistent with `audit.VerifyChain` over the same rows | REQ-1 c3 — the literal iff is **split** here and supersedes c3's wording for truncated stores | `TestVerifyDSNByteConsistency` (+ truncated half in `TestVerifyDSNTruncation`) | **Untruncated** (clean/flipped): `exit==0 ⟺ audit.VerifyChain(full)==nil`; printed head == `events[len-1].Hash`. **Truncated** (the iff is false there — the CLI deliberately exits 1 while the verified prefix is clean): `exit==1 ∧ VerifyChain(prefix)==nil ∧ stdout contains "truncated by --limit" ∧ head == prefix tip`. |
| REQ-1 c5 (sqlite `--dsn` truncation honesty — G2) | REQ-1 c5 | `TestVerifyDSNTruncation` | 10-event store, `--limit 5`: exit 1, stdout contains `prefix verified: 5 event(s) — truncated by --limit 5`; with `--checkpoint` added: exit 1, fail-fast `event list truncated by --limit 5 before the attested head`, no `chain verified` output. Use `limit` strictly less than chain length (an exact-fill boundary always reports truncated — §3.2 quirk). |
| FM-8 empty-store verify (G5) | REQ-1 exit-code clause | `TestVerifyDSNEmptyStore` | Unanchored: exit 0, stdout exactly `no events to verify`. `--checkpoint` (GenesisHash path, main.go:149-152): exit 0, `chain verified: 0 event(s), head=, checkpoint seq=N`. |
| A3: postgres DSN reuses the same paginated/anchored verification path | REQ-2 c1 | `TestVerifyDSNPostgresSharesPath` | REQ-1 criteria 1-2, c3 (split predicate per A2), and c5 run verbatim against a postgres store; plus `--checkpoint`/`--anchor-hash`/`--limit` composition identical. |
| A4: no postgres `--dsn` exists today; net-new | REQ-2 (verified C6) | **Static evidence (G4):** §1 C6 grep, re-verified at implementation time before wiring — plus `TestClassifyDSN` for the new capability | Table: `postgres://`, `postgresql://`, mixed case → postgres; `file:…?mode=ro`, bare path, `:memory:` → sqlite; runs without a live DB. (A literal "historical absence" claim has no concrete unit-test gate; the honest gate is the static source-state evidence plus the classifier test.) |
| A5: `auth.token.issue` L1 aggregation = count per client per interval from stored rows matching `RecordTokenIssued` volume; proposed, flagged | REQ-4 c1-7 | `TestAggSQLiteVolume`, `TestAggWindow`, `TestAggPostgres`, `TestAggProposedMisuse`, `TestAggMisuse`, `TestAggEmpty`, `TestAggDeterminism` | Volume: K events across 2 clients × 3 hour buckets → exactly the occupied (bucket, client) rows, sum == K == `RecordTokenIssued` call count. Window: `[since, until)` subset. Determinism: byte-identical stdout across runs. `--event login` → exit 2 + PROPOSED diagnostic. Empty window → empty stdout, exit 0, **and stderr carries the summary line with zero counts** (REQ-4 c6 — asserted in `TestAggEmpty`). |
| T-9 regression: existing behavior byte-identical | REQ-3 c1, REQ-6 c1 | Existing suites unmodified | `go test ./cmd/sso-ctl/auditverify/ ./cmd/sso-ctl/auditexport/ -race` — all pass with new code in place; sqlite export bundle structurally identical **modulo GeneratedAt** (auditexport.go:133 embeds `time.Now()` — byte-golden is impossible; the existing tests assert structure/`"anchor"`-key absence/self-verify/`EventCount`, not bytes). Proof runs against the current dirty worktree (827 modified files; frozen `auditexport/auditexport.go` carries an uncommitted in-flight edit) — §4.1. |
| REQ-3 postgres export | REQ-3 c2-3 | `TestExportPostgresBundleVerifies`, `TestExportPostgresFlipped` | Bundle verifies via `audit-export --verify` (exit 0), `EventCount == N`, `Contiguous == true`, `BoundaryPrevHash` == first row's `prev_hash`; flipped row → exit 1, no bundle file. |
| REQ-5 never-migrate | REQ-5 | `TestOpenAuditReadOnlyNoMigration`, `TestVerifyDSNSchemaMismatch` | Stale `schema_migrations_audit` → exit 1 + found-vs-expected version diagnostic, zero DDL — **pinned mechanism (G3):** (1) run under a read-only-transaction DSN (`options=-c default_transaction_read_only=on` or a SELECT-only role): any DDL attempt fails loudly *before* the version check could pass, so asserting the exact version diagnostic itself proves no DDL was attempted (a migration would produce a different error); (2) post-run schema-state assertion over the writable test DSN: `schema_migrations_audit` `MAX(version)` unchanged and no new `information_schema` tables; (3) sqlite side: assert the DB file byte-identical before/after (`hashFile` pattern, auditexport/main_test.go:373-391; `mode=ro` write-failure precedent `TestRun_ExportModeROSucceeds`). A `QueryTracer` DDL-free trace is NOT implementable — `OpenAuditReadOnly` wraps `postgres.Open` with no tracer hook. |
| REQ-6 CLI contract | REQ-6 | `TestVerifyDSNMisuse` | `--dsn` + `--from-file`/`--from-url`/`--bearer` → exit 2, mutual-exclusion diagnostic. |

Gate sequence (AGENTS.md §2, §6) — executable exactly as written; every command resolves on this tree (`make ci` = Makefile:265; `TestE2E` = test/e2e_test.go:258; the postgres `-run` regex covers every named test above, incl. the new `TestVerifyDSNTruncation`/`TestVerifyDSNEmptyStore`):

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .        # pre-existing reds expected: DirectorySubdirFanout / DirectoryDepth / FileSizeBudget — cmd/sso-ctl adds none
go test ./cmd/sso-ctl/... ./platform/audit/... -race
SSO_TEST_POSTGRES_DSN=postgres://user@localhost:5432/sso_test?sslmode=disable \
  go test ./cmd/sso-ctl/... ./infrastructure/postgres/ -run 'TestVerifyDSN|TestOpenAuditReadOnly|TestAgg|TestExport|TestClassifyDSN' -v
go test ./test/ -run TestE2E -v
make ci
```

**Baseline note — the sequence does not imply a green baseline.** Three gates already fail on this tree, pre-existing and unchanged by this design (per AGENTS.md §2, report them separately): `TestArchitecture_DirectorySubdirFanout` (docs = 18 subdirs, `docs/architect-analysis/auto/runs` = 267, root = 34 > frozen 21 — `cmd/sso-ctl` is NOT a cause), `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go` = 539 lines), and `TestArchitecture_DirectoryDepth` (536 dirs, batch-artifact runs). Step 2 is expected to show exactly those failures and **no new ones from `cmd/sso-ctl`**. The Python mirror (`checks/directory_fanout.py`, max 15, run via `adr-compliance`) also flags `cmd/sso-ctl` 16 > 15 today — the three-way drift (committed Go gate 16 vs engineering.yaml/AGENTS.md 15) documented in §2.1; this design adds no subdirectory under either number.

## 8. Non-goals (scope guard, per the requirements spec)

No server-side changes; no `--from-url` postgres source or SSRF surface; no
audit-agg chain verification, checkpoint integration, or metric emission; no
change to the `[PROPOSED]` status of the mapping; no migration tooling; no
keyword/value postgres connection strings; no `--timeout-sec` application to
DSN mode.
