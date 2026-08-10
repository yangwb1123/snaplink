# Requirements: durable-store `--dsn` verification (sqlite AND postgres) + `auth.token.issue` L1 aggregation attestation (cmd/sso-ctl)

Requirements specification for the selected direction "B4-5/G5: add durable-store
`--dsn` verification (sqlite AND postgres) plus `auth.token.issue` L1 aggregation
attestation to audit-verify/audit-export — the operator attestation surface for the
stock memory->sqlite/postgres backend flip". Doc-only artifact; no `.go` edits, so
no build gates are triggered by this file.

Module: `cmd/sso-ctl` (composition layer; dispatch table `cmd/sso-ctl/main.go:47-48`).
Source analysis: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-7e52c2bb.json`,
direction 1. Every citation below was re-checked against the working tree; the
supplied acceptance (T-9/G5) is preserved verbatim in section 3 and made testable.

## 1. Verification outcome — citations checked against the repository

| Citation | Verdict |
|---|---|
| `cmd/sso-ctl/auditverify/main.go` — `verifyOptions` has no `dsn` | **Verified** — struct at main.go:82-92: `fromFile`, `fromURL`, `bearer`, `limit`, `pageSize`, `timeout`, `checkpoint`, `notaryKey`, `anchorHash`, `anchorHashSet`. No DSN field; `parseFlags` (main.go:94-132) binds no `--dsn`. Source exclusivity is enforced at main.go:204 (`one of --from-file or --from-url is required`) and 206-208 (mutually exclusive). |
| `cmd/sso-ctl/auditexport/main.go:68,145,182-186` — sqlite-only `--dsn` via `auditsqlite.OpenReadOnly`, never migrating | **Verified** — line 68 imports `auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"` (the only store import); line 145 binds `--dsn` with help "SQLite DSN to export from (required for export; opened read-only, append ?mode=ro for a live DB)"; lines 182-186 open via `auditsqlite.OpenReadOnly(o.dsn)` with the comment "OpenReadOnly never migrates". `dispatch` (main.go:128-143) has exactly two modes: `--verify <bundle>` or `--dsn`; no backend/dialect flag exists. The never-migrate contract is in the package doc at main.go:16-17 ("The export is strictly READ-ONLY ... NEVER migrates the schema"). |
| `platform/audit/sqlite/sink.go:103` — `prev_hash`/`hash` columns | **Verified** — sink.go:103-104: `prev_hash TEXT, hash TEXT` in the `audit_events` DDL; `OpenReadOnly` at sink.go:169; `checkSchemaCurrent` (fail-closed schema-version check) at sink.go:191. |
| `infrastructure/postgres/audit_sink.go:49,162` — `prev_hash`/`hash` columns | **Verified** — audit_sink.go:49-50: `prev_hash TEXT, hash TEXT` in the DDL; line 162: `metadata_json, prev_hash, hash, server_version` in `auditInsert`. |
| `infrastructure/postgres/audit_query.go:24,213` — postgres reads the chain columns | **Verified** — audit_query.go:24: `selectAuditColumns` includes `prev_hash, hash`; lines 213-214: `e.PrevHash = prev.String; e.Hash = hash.String`. Postgres `AuditSink.Query` (audit_query.go:79-108) returns newest-first (`ORDER BY ts_unix_ns DESC`, line 85-86) exactly like the sqlite sink (`platform/audit/sqlite/query.go:82-85`). |
| `platform/audit/chainer.go:157,172,255` — anchoring primitives | **Verified** — chainer.go:157 `VerifyChain`; 172 `VerifyChainSegment`; 255 `NewEd25519CheckpointSigner`; additionally 469 `VerifyChainAgainstCheckpoint` (used by audit-verify's `--checkpoint` path) and 141 `GenesisHash = ""`. The verification core is store-agnostic: it consumes `[]*audit.Event` in chain order. |
| `platform/audit/recorder_events.go:19` — `RecordTokenIssued` | **Verified** — recorder_events.go:19-24 emits `Type = EventTokenIssued` (`"token_issued"`, `auditspi/event_types.go:15`), `Outcome = OutcomeSuccess`, always. Emitters repo-wide all route through this helper (interfaces/sso/server_helpers.go:432, server_token.go:481, internal/handler/tokengrant/*). L1 aggregation (count per client per interval) is **absent repo-wide**: `auth.token.issue` appears only in docs — `docs/proposals/audit-contract-batch-snaplink.md:16` marks the mapping and L1 aggregation position `[PROPOSED]` — and zero `.go` files. |
| "URL API path pages newest-first at 1000/page" | **Verified** — `readFromURL` (auditverify/main.go:403-444) pages `/api/v1/audit/events` with `pageSize` capped at `audit.MaxQueryLimit = 1000` (`auditspi/query.go:15`) and reverses the collected buffer (`reverseEvents`, main.go:482-487) because both sinks and the API return newest-first. |
| "No postgres `--dsn` exists today in either tool" | **Verified** — grep of `cmd/sso-ctl/` shows postgres DSN handling only in `importcmd` (`--backend postgres --dsn ...`, importcmd/main.go:123-125, importer.go:42-47), which targets the *user store* (`postgres.NewUserProvider`), not the audit store. Neither audit-verify nor audit-export has any postgres path. |
| `auditexport.QueryPager` — the read-only slice both stores satisfy | **Verified** — auditexport.go:68-76: single method `Query(ctx, audit.Query) ([]*audit.Event, error)`; doc says "Every audit sink (MemorySink, sqlite.Sink) satisfies it structurally, and a remote HTTP-backed adapter can implement just this one method". `BuildExportBundle` (auditexport.go:123) pages via `pageAll` (173-197) and reverses newest-first pages (line 195) — so a postgres source needs **zero** changes in the export core. |
| Migration hazard: `NewAuditSink` migrates | **Verified** — `infrastructure/postgres/audit_sink.go:107-110` "opens cfg.DSN, **migrates the schema**, and returns the sink"; `NewAuditSinkWithDB` (121-128) runs `Run(..., "audit", auditMigrations, ...)`. `postgres.Open` alone (pool.go:53-73) only dials (pgx stdlib driver), applies pool sizing, and pings — no DDL. Migration version table is `schema_migrations_audit` (`migrate.go:35-39` `versionTable("audit")`). A postgres read path must therefore NOT reuse `NewAuditSink*` as-is. |
| Budget ceiling: `auditverify/main.go` | **Verified** — 499 lines, at the 500-line Go-file budget. The DSN source must live in a new file, not main.go. `auditexport/main.go` is 442 lines. |
| Postgres integration test convention | **Verified** — `infrastructure/postgres/postgres_test.go:13-19`: tests skip unless `SSO_TEST_POSTGRES_DSN` is set (e.g. `postgres://user@localhost:5432/sso_test?sslmode=disable`). |
| Dispatch table | **Verified** — `cmd/sso-ctl/main.go:47-48`: `"audit-verify": auditverify.Run`, `"audit-export": auditexport.Run`; both `Run(args []string) int` return the exit code in-process (testable without os.Exit). |

## 2. Core invariants

1. **Offline read-only store access.** All three surfaces (`audit-verify --dsn`,
   `audit-export --dsn`, the new aggregation command) read the audit store and
   NEVER write: sqlite via `auditsqlite.OpenReadOnly` (existing, sink.go:169, never
   migrates), postgres via a new non-migrating constructor (REQ-5). A schema whose
   version does not match the binary is reported, never migrated, never guessed.
2. **Chain-order discipline.** Both sinks return newest-first; every DSN reader
   pages newest-first and reverses into chain order before `audit.VerifyChain` /
   `audit.VerifyChainSegment` / `audit.VerifyChainAgainstCheckpoint` — identical to
   the existing `readFromURL` discipline (auditverify/main.go:403-444, 482-487).
3. **Honest truncation.** `--limit` caps report truncation exactly as the existing
   paths do: unanchored/`--anchor-hash` runs print `prefix verified ... not the full
   chain` and exit 1; `--checkpoint` runs fail fast before verification. A DSN run
   must never assert a prefix head is the chain tip.
4. **One verification core.** `--dsn` is a third *source* beside `--from-file` and
   `--from-url`; `--checkpoint`, `--notary-key`, `--anchor-hash`, `--limit`,
   `--page-size`, `--timeout-sec` compose identically for all three sources (a
   `--timeout-sec` note: not applicable to DSN mode, see REQ-1). No behavioral fork
   of the anchored/segment/legacy verify paths.
5. **L1 aggregation is a proposed surface.** `auth.token.issue` is `[PROPOSED]`
   (`docs/proposals/audit-contract-batch-snaplink.md:16`); the aggregation command
   operates on the real stored rows (`token_issued`, `EventTokenIssued`) and
   self-flags the proposed status in its usage text and misuse diagnostics. It
   attests volume only; chain integrity is `audit-verify`'s job (explicit non-goal
   below).

## 3. Requirements

Acceptance (supplied, preserved verbatim): **T-9/G5** — `sso-ctl audit-verify
--dsn <sqlite|postgres>` over a stock-backend-written store exits 0 on a clean
chain and 1 on a single flipped hash, byte-consistent with `audit.VerifyChain` over
the same rows; a postgres DSN source reuses the same paginated/anchored
verification path (proposed: no postgres `--dsn` exists today — verified);
`auth.token.issue` L1 aggregation (count per client per interval derived from
stored rows, matching `RecordTokenIssued` volume) is a proposed new command
surface, flagged as such.

| # | Acceptance sentence | Requirement(s) |
|---|---|---|
| A1 | `audit-verify --dsn <sqlite\|postgres>` exits 0 clean / 1 on a single flipped hash | REQ-1, REQ-2 |
| A2 | byte-consistent with `audit.VerifyChain` over the same rows | REQ-1 (consistency clause) |
| A3 | postgres DSN reuses the same paginated/anchored verification path | REQ-2 |
| A4 | no postgres `--dsn` exists today (proposed surface) | Verified in §1; REQ-2 is net-new |
| A5 | `auth.token.issue` L1 aggregation: count per client per interval from stored rows, matching `RecordTokenIssued` volume; proposed surface, flagged | REQ-4 |

### REQ-1 — `sso-ctl audit-verify --dsn <sqlite-dsn>` (store source, sqlite)

Add `--dsn` to `audit-verify` as a third mutually exclusive source.

- **Flags.** `--dsn <dsn>`; mutually exclusive with `--from-file` and `--from-url`
  (CLI misuse, exit 2, same diagnostic style as main.go:204-208). `--bearer` with
  `--dsn` is misuse (exit 2). `--page-size` and `--limit` apply to DSN paging with
  the existing semantics (page cap `audit.MaxQueryLimit` = 1000). `--timeout-sec`
  is not applicable to DSN mode and is ignored there (documented in the usage
  banner), because a local/DSN read has no HTTP client.
- **Dialect classification (shared, REQ-3/REQ-4 reuse).** A DSN is postgres iff it
  begins with `postgres://` or `postgresql://` (case-insensitive); otherwise it is
  a sqlite DSN (file path or `file:` URI). Rationale: postgres connection strings
  always carry a scheme in this repo (`importcmd` examples, pool.go), sqlite DSNs
  never do; auto-detection avoids a second state flag. (The `importcmd
  --backend` precedent was considered and rejected: audit stores have no
  cockroach dialect and the classifier is total and unambiguous.)
- **Read path.** sqlite: `auditsqlite.OpenReadOnly` (existing; never migrates,
  fail-closed `checkSchemaCurrent`). Page via `audit.Query{Offset, Limit}`
  newest-first, collect, reverse into chain order (mirror `readFromURL`,
  auditverify/main.go:403-444,482-487). Apply the `--limit` cap with the same truncation honesty
  (invariant 3).
- **Verification.** Unchanged core: `audit.VerifyChain` (chainer.go:157) for
  unanchored runs; `--anchor-hash` → `VerifyChainSegment` (chainer.go:172);
  `--checkpoint`/`--notary-key` → `VerifyChainAgainstCheckpoint` (chainer.go:469)
  with the existing fail-fast truncation rule and Phase-A posture notice.
- **Exit codes.** 0 clean chain (including empty store: `no events to verify`,
  matching main.go:263-265), 1 chain break / store-open / page error, 2 CLI
  misuse. Stderr diagnostics; stdout carries only the `chain verified:` /
  `prefix verified:` / `chain BROKEN:` lines exactly as today.
- **Byte-consistency (A2).** For identical rows, the CLI result equals running
  `audit.VerifyChain` over the same `[]*audit.Event`: exit 0 iff
  `VerifyChain(events) == nil`, and the printed `head=` equals
  `events[len(events)-1].Hash`.

Testable criteria:

1. Given a sqlite audit store written by the stock backend (Recorder with hash
   chain → `sqlite.Sink`, N events), when `Run(["--dsn", store])` executes, then
   exit is 0 and stdout is exactly `chain verified: N event(s), head=<H>` with
   `<H>` equal to the last stored row's `hash`.
2. Given the same store with exactly one row's `hash` column overwritten
   (`UPDATE audit_events SET hash='deadbeef' WHERE id=<i>`, no other change —
   the next row's `prev_hash` untouched), when the same command runs, then exit
   is 1 and stderr contains `chain BROKEN`.
3. Given the same store, when rows are loaded in-process through the same
   QueryPager and `audit.VerifyChain` is run, then the CLI exit equals
   `0` iff `VerifyChain` returned nil (property asserted over clean, flipped,
   and truncated stores).
4. Given `--dsn` with `--from-file`, `--from-url`, or `--bearer` alone, then
   exit is 2 with a mutual-exclusion diagnostic.
5. Given `--dsn` with `--limit 5` over a 10-event store, then stdout contains
   `prefix verified: 5 event(s) — truncated by --limit 5` and exit is 1; with
   `--checkpoint` added, exit is 1 with the fail-fast truncation message and no
   `chain verified` output.
6. Given a store whose sqlite schema version does not match the binary, then
   exit is 1 with a schema diagnostic and no verification output.

### REQ-2 — `sso-ctl audit-verify --dsn <postgres-dsn>` (store source, postgres)

Postgres DSN support through the **same** paginated/anchored verification path
(A3): the only difference from REQ-1 is the store opener.

- **Read path.** New non-migrating constructor in `infrastructure/postgres`
  (root module; see REQ-5) wrapping `postgres.Open` (pool.go:53) + the existing
  `AuditSink` query methods. No `Run(...)` migration call. Paging, reversal,
  truncation, anchoring, exit codes, and stdout/stderr formats are identical to
  REQ-1 (shared reader code; one implementation, not a copy).
- **Dialect detection** as REQ-1 (`postgres://` / `postgresql://` prefix).
- **Read-only posture.** The tool issues SELECTs only (`AuditSink.Query`/`Get`
  are SELECT-only, audit_query.go:27,79). Operators enforce server-side
  read-only via a read-only role or `default_transaction_read_only` — there is
  no `?mode=ro` equivalent for postgres; this is documented in the usage
  banner. The tool itself never executes DDL or DML.
- **Schema fail-closed.** Before paging, verify the audit schema version
  (`schema_migrations_audit` `MAX(version)`, migrate.go:35-39,140) equals the
  binary's expected version; mismatch → exit 1 with a diagnostic naming the
  found vs expected version, mirroring sqlite's `checkSchemaCurrent`.

Testable criteria:

1. Given `SSO_TEST_POSTGRES_DSN` set (repo convention, postgres_test.go:13-19)
   and an audit store written by the stock postgres backend (`postgres.AuditSink`
   with hash chain), then the clean-run / flipped-hash / byte-consistency /
   truncation criteria of REQ-1 hold verbatim against the postgres store
   (criteria 1-3, 5). Without `SSO_TEST_POSTGRES_DSN`, the postgres integration
   tests skip; the dialect classifier and misuse cases (criterion 4) run without
   a live DB.
2. Given a postgres DSN whose `schema_migrations_audit` version is behind the
   binary, then exit is 1 with a version diagnostic and zero DDL executed
   (asserted via a `CREATE TABLE`-free trace or a read-only role).
3. Given a postgres DSN with a single flipped `hash` row, then exit is 1 and
   stderr contains `chain BROKEN` (A1 for postgres).

### REQ-3 — `sso-ctl audit-export --dsn <postgres-dsn>` (same read source)

`audit-export`'s existing `--dsn` gains postgres support through the shared
classifier and the REQ-5 read-only opener; the export core is untouched
(`BuildExportBundle` takes any `QueryPager`, auditexport.go:68-76,123, and
`pageAll` already reverses newest-first pages, 173-197).

- **T-9 byte-identical guard.** Existing sqlite `--dsn` behavior is unchanged:
  same flags, same bundle bytes for the same store/filters, same read-only and
  never-migrate guarantees (documented invariant, auditexport/main.go:16-17,
  182-186). The `--dsn` help text gains the postgres case
  (`postgres://`/`postgresql://` DSNs supported; opened read-only, never
  migrated).
- **Open ordering.** Postgres open + schema-version check happen in the same
  position as the sqlite open (after `buildQuery`, before `BuildExportBundle`),
  and `--anchor` still loads and signature-checks before the store opens
  (fail-fast, auditexport/main.go:169-181).

Testable criteria:

1. Given the existing sqlite export tests (`cmd/sso-ctl/auditexport/main_test.go`),
   then all pass unchanged (T-9 regression).
2. Given `SSO_TEST_POSTGRES_DSN` and a postgres store written by the stock
   backend, then `audit-export --dsn postgres://...` produces a bundle that
   verifies with `audit-export --verify <bundle>` (exit 0), with
   `EventCount == N`, `Contiguous == true`, and `BoundaryPrevHash` equal to the
   first row's `prev_hash` (genesis for a full chain).
3. Given a postgres store with one flipped `hash` row, then `--dsn` export exits
   1 (BuildExportBundle's fail-closed self-verification) and no bundle file is
   left behind.

### REQ-4 — `sso-ctl audit-agg`: `auth.token.issue` L1 aggregation (proposed surface, flagged)

New subcommand `sso-ctl audit-agg` registered in the dispatch table
(`cmd/sso-ctl/main.go`). **Proposed surface**: the `auth.token.issue` mapping and
L1 aggregation position are `[PROPOSED]` in
`docs/proposals/audit-contract-batch-snaplink.md:16`; the CLI operates on the
real stored event type and says so in its usage banner and diagnostics.

- **Flags.** `--dsn <dsn>` (required; same classifier as REQ-1), `--interval`
  (required; `time.ParseDuration`, e.g. `1h`, `15m`), `--since` / `--until`
  (optional; RFC3339 or unix seconds, reusing auditexport's `parseTime`
  semantics, auditexport/main.go:330-341; half-open `[since, until)` matching
  `audit.Query` semantics, auditspi/query.go:9-11,74-81), `--event` (default
  `token_issued`; the only accepted value today), `--client-id` (optional
  filter).
- **Semantics.** Count stored rows with `type == token_issued`
  (`EventTokenIssued`, event_types.go:15) grouped by (interval bucket,
  `client_id`); bucket = UTC-aligned floor of `timestamp` to `--interval`
  boundaries. Aggregation is derived in-process from QueryPager pages (shared
  reader), store-agnostic — no per-backend SQL, no GROUP BY. Half-open window
  semantics match `audit.Query` (auditspi/query.go:9-11, 74-81).
- **Volume match (A5).** Every `RecordTokenIssued` call
  (recorder_events.go:19-24) produces exactly one stored `token_issued` event,
  so the sum of all reported counts equals the number of stored matching rows —
  and equals the `RecordTokenIssued` volume in the window.
- **Output.** stdout: deterministic TSV, one row per (interval_start, client_id),
  sorted by interval_start then client_id: `interval_start<TAB>client_id<TAB>count`
  (RFC3339 UTC interval start). stderr: one summary line with totals (event
  count, client count, interval count) — no event contents. Same store + flags ⇒
  byte-identical output.
- **Exit codes.** 0 success (including an empty window: empty stdout, summary
  line, exit 0 — mirrors the empty-window contract of audit-export), 1
  store-open / read error, 2 CLI misuse (`--dsn` missing, bad `--interval`,
  bad `--since`/`--until`, `--event` not `token_issued`). Misuse for an unknown
  `--event` prints: `only token_issued is defined for L1 aggregation today; the
  auth.token.issue mapping is PROPOSED (docs/proposals/audit-contract-batch-snaplink.md:16)`
  and exits 2.
- **Explicit non-goals.** `audit-agg` performs no chain verification and makes
  no tamper-evidence claim (that is `audit-verify`'s contract); it adds no
  checkpoint/anchor integration; it does not emit metrics, only the attestation
  table.

Testable criteria:

1. Given a sqlite store seeded via `audit.RecordTokenIssued` through the stock
   backend with K events across 2 clients and 3 distinct hour buckets, when
   `audit-agg --dsn <store> --interval 1h` runs, then stdout has exactly the
   (bucket, client, count) rows for the occupied pairs, the sum of counts is K,
   and exit is 0.
2. Given the same store, when `--since`/`--until` bound a window containing a
   strict subset, then only rows in the half-open window are counted.
3. Given a postgres store (under `SSO_TEST_POSTGRES_DSN`), then criteria 1-2
   hold verbatim (same classifier, same reader).
4. Given `--event login` (or any value other than `token_issued`), then exit is
   2 with the PROPOSED-status diagnostic.
5. Given `--dsn` missing, an unparsable `--interval`, or an unparsable
   `--since`, then exit is 2.
6. Given an empty matching window, then stdout is empty, exit is 0, and stderr
   carries the summary line with zero counts.
7. Given identical store + flags run twice, then stdout is byte-identical
   (determinism).

### REQ-5 — shared read-only opener with never-migrate guarantee

- **sqlite.** Reuse `auditsqlite.OpenReadOnly` (sink.go:169) as today — no new
  code.
- **postgres.** Add one exported constructor in `infrastructure/postgres`
  (root module, allowed): it wraps `postgres.Open` (pool.go:53), runs NO
  migration (`Run` at migrate.go:75 is not invoked), performs the
  fail-closed schema-version check against `schema_migrations_audit`
  (migrate.go:35-39), and returns the existing `*AuditSink` (whose
  `Query`/`Get` are SELECT-only). The constructor's doc comment states the
  never-migrate contract and the read-only-role recommendation, mirroring
  `OpenReadOnly`'s contract comment (auditexport/main.go:16-17).
- **Shared reader.** The paginate-and-reverse reader (REQ-1) and the dialect
  classifier live in one place reused by audit-verify, audit-export, and
  audit-agg (see §5); no tool carries its own copy.
- **Failure modes.** Open error, schema-version mismatch, and page errors are
  exit-1 diagnostics naming the store; a broken chain is reported only by the
  verification step, never by the reader.

### REQ-6 — CLI contract and documentation updates

- Usage banners updated for `audit-verify` (new `--dsn` + exclusivity +
  `--timeout-sec`-not-applicable note) and `audit-export` (postgres DSN case in
  `--dsn` help); new usage banner for `audit-agg` including the PROPOSED flag.
- `cmd/sso-ctl/main.go` dispatch table gains `"audit-agg": auditagg.Run`.
- **T-9 byte-identical regressions:** every existing flag and output line of
  `audit-verify` (`--from-file`, `--from-url`, `--bearer`, `--limit`,
  `--page-size`, `--timeout-sec`, `--checkpoint`, `--notary-key`,
  `--anchor-hash`) and of `audit-export` (sqlite `--dsn`, `--verify`, filters,
  `--anchor`) is unchanged when the new flags are absent; existing
  `cmd/sso-ctl/auditverify/*_test.go` (main, checkpoint, segment, coverage) and
  `auditexport/main_test.go` pass unmodified.
- No `docs/openapi.yaml`, `docs/error-codes.md`, or `docs/config-reference.md`
  changes: CLI-only surfaces, no new server endpoints, errors, or config keys.
  The `[PROPOSED]` marker in `docs/proposals/audit-contract-batch-snaplink.md:16`
  is untouched (the aggregation surface ships without changing the mapping's
  status).

Testable criterion:

1. Given the full pre-change test suites of `cmd/sso-ctl/auditverify` and
   `cmd/sso-ctl/auditexport`, then all pass with the new code in place (T-9).

## 4. Budgets and design constraints (checked before editing)

- `cmd/sso-ctl/auditverify/main.go` is **499 lines — at the 500-line ceiling**.
  The DSN source (reader, classifier, opener wiring) MUST go in a new file; the
  main.go delta is limited to flag binding, exclusivity checks, and source
  dispatch (target < 20 net lines, staying under 500).
- `cmd/sso-ctl/auditexport/main.go` is 442 lines; postgres wiring must stay
  minimal (classifier + opener call); if the change would cross 500, move the
  opener call into the shared reader package.
- New functions stay ≤ 50 lines and complexity ≤ 15 (the pager mirrors
  `readFromURL`'s shape, auditverify/main.go:403-444, which is already at ~40
  lines).
- `interfaces/sso` is at its 60-file ceiling and is NOT touched. No changes to
  `platform/audit/chainer.go`, `platform/audit/recorder_events.go`,
  `platform/audit/auditexport/auditexport.go`, or `platform/audit/sqlite/sink.go`
  (all reused as-is).
- New package `cmd/sso-ctl/auditstore` (or equivalent shared reader home) is a
  composition-layer sibling of the existing `cmd/sso-ctl/*` subpackages; no
  `layerExemptions` entry and no `layerName()` change is needed (cmd/ is
  composition). If the shared reader is placed in `infrastructure/postgres`
  instead, it is exported and reusable without upward imports.
- Import flow: `cmd/sso-ctl/*` → `platform/audit` + `infrastructure/postgres`;
  no new upward imports, no `protocols/*` involvement.

## 5. Files

### Create

```text
cmd/sso-ctl/auditstore/store.go            — dialect classifier (postgres://|postgresql:// vs sqlite) +
                                            OpenReadOnly(dsn) returning a QueryPager + Closer over both
                                            backends; paginate-and-reverse reader (chain order); shared
                                            by audit-verify/audit-export/audit-agg
cmd/sso-ctl/auditstore/store_test.go       — classifier table test; sqlite read+reverse+paging tests;
                                            misuse cases without a live DB
cmd/sso-ctl/auditverify/dsn_source.go      — audit-verify --dsn wiring: flag, exclusivity, opener, and
                                            the readFromURL-equivalent paging entry (keeps main.go
                                            under the 500-line budget)
cmd/sso-ctl/auditagg/main.go               — audit-agg subcommand: flags, in-process aggregation over
                                            the shared reader, TSV output, PROPOSED-flag diagnostics
cmd/sso-ctl/auditagg/main_test.go          — REQ-4 criteria 1-7 (sqlite; postgres under
                                            SSO_TEST_POSTGRES_DSN)
cmd/sso-ctl/auditverify/dsn_test.go        — REQ-1 criteria 1-6 incl. flipped-hash and byte-consistency
infrastructure/postgres/audit_readonly.go  — non-migrating constructor (REQ-5): postgres.Open +
                                            schema-version fail-closed check + *AuditSink; SELECT-only
infrastructure/postgres/audit_readonly_test.go — REQ-2 criteria under SSO_TEST_POSTGRES_DSN
```

### Modify

```text
cmd/sso-ctl/auditverify/main.go    — --dsn flag + exclusivity (--from-file/--from-url/--bearer) + source
                                    dispatch into the shared reader; usage banner; minimal net lines
cmd/sso-ctl/auditexport/main.go    — --dsn help text gains postgres case; opener call routes through the
                                    shared classifier/reader; open ordering unchanged
cmd/sso-ctl/main.go                — dispatch entry "audit-agg": auditagg.Run
```

### Do not modify

```text
platform/audit/chainer.go                 — verification core, reused as-is
platform/audit/recorder_events.go         — RecordTokenIssued, reused as-is
platform/audit/auditexport/auditexport.go — BuildExportBundle/QueryPager, reused as-is
platform/audit/sqlite/sink.go             — OpenReadOnly/checkSchemaCurrent, reused as-is
interfaces/sso/*                          — 60-file ceiling; no server change in this direction
infrastructure/postgres/audit_sink.go     — DDL/insert/Query untouched (new constructor is additive)
```

Confirm file/function/directory/fan-out ceilings before implementation (per
AGENTS.md budgets: 500-line files, 50-line functions, complexity 15, if-nesting
3, non-test files/dir 10, subdirs 15).

## 6. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/... -race
go test ./platform/audit/... ./infrastructure/postgres/ -race
SSO_TEST_POSTGRES_DSN=postgres://user@localhost:5432/sso_test?sslmode=disable \
  go test ./cmd/sso-ctl/... ./infrastructure/postgres/ -run 'TestAudit|DSN|Agg|ReadOnly' -v
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests beside the code: REQ-1 criteria 1-6 (sqlite, stock-backend-written
store: clean exit 0 / single flipped hash exit 1 / byte-consistency vs
`audit.VerifyChain` / truncation honesty / misuse / schema mismatch); REQ-2
criteria 1-3 (postgres, `SSO_TEST_POSTGRES_DSN`, skips otherwise per repo
convention); REQ-3 criteria 1-3 (sqlite T-9 regression + postgres bundle
verify); REQ-4 criteria 1-7 (volume match = `RecordTokenIssued` count,
bucket/client grouping, determinism, PROPOSED-flag misuse); REQ-6 criterion 1
(full existing audit-verify/audit-export suites pass unchanged). Postgres cases
follow the `SSO_TEST_POSTGRES_DSN` skip convention
(infrastructure/postgres/postgres_test.go:13-19); sqlite cases run everywhere.

## 7. Explicit non-goals (scope guard)

- No server-side changes: no new endpoints, no `interfaces/sso` edits, no
  discovery/config/OpenAPI changes, no anchor or checkpoint schema changes.
- No `--from-url` postgres source, no relay/federation involvement, no SSRF
  surface (DSN sources are offline).
- No audit-agg chain verification, checkpoint integration, or metric emission.
- No changes to the `[PROPOSED]` status of the `auth.token.issue` mapping in
  `docs/proposals/audit-contract-batch-snaplink.md:16`.
- No migration tooling: a version-mismatched store is reported (exit 1), never
  migrated, by any of the three surfaces.
