All five points validated against code and — for the behavioral claims — against the pinned driver (modernc.org/sqlite v1.50.1) empirically. No repo files were touched (`/tmp` scratch only), so no gates were triggered.

# Validation report: verification semantics in the design

## 1. Tie-break: sqlite `ts_unix_ns DESC` vs pg `seq` — **claim holds, but the asymmetry is narrower than stated**

| Surface | sqlite | pg |
|---|---|---|
| Paging `Query` (`sqlite/query.go`, `postgres/audit_query.go`) | `ORDER BY ts_unix_ns DESC LIMIT n [OFFSET o]` — **no tie-break** | identical — **no tie-break** |
| `LastHash` tip query | `... DESC, rowid DESC LIMIT 1` (`maintenance.go:78`) | `... DESC, seq DESC LIMIT 1` (`audit_sink.go:258`) |

So the design's "sqlite no tie-break (pg has `seq`)" is only true at the schema/tip level: pg materializes the insertion ordinal (`seq BIGSERIAL`), sqlite relies on implicit `rowid` — and **both** tip queries tie-break. The paging query both backends page the chain with is tie-break-less on both sides.

Why this doesn't break chain order: `chainer.stamp` (`chainer.go`) bumps non-monotonic timestamps to `lastTS+1ns`, guaranteeing **ts order == chain order** for any chainer-stamped store. Ties are impossible for chained rows, so tie-break-less paging is deterministic *per snapshot*. Caveat the design should note: the monotonicity guarantee is **per-Recorder-process**; two processes stamping into one file (the sqlite sink's documented multi-replica model) can still invert ts vs chain order across the seam → a spurious `VerifyChain` break (fail-closed direction, never a false pass).

## 2. Offset-paging stability under concurrent appends — **claim confirmed, and it's worse than "instability": it is a FALSE-PASS vector**

Empirical demo (pinned driver, 50 rows seeded, LIMIT 10, append 3 rows between pages, "loop until empty page" termination):

```
total rows in db: 53, rows observed across pages: 53
DUPLICATE: rows 31, 32, 33 seen 2 times   → 3 rows silently SKIPPED = the 3 newest
```

The skipped rows are the **newest tail** (appends land at the head of a newest-first scan; the OFFSET window shifts toward older rows and the loop terminates on an empty page before ever re-reading the head). A chain prefix verifies *cleanly* — so under a live store, `audit-verify --dsn` can exit 0 while the last N events were never read. This is the same false-pass shape as the clamp trap, and it means the design's FM-3 pin must be stronger than "concurrent-write paging instability": the correct mitigation is a **single read transaction around the whole paging loop** (WAL snapshot isolation; `Query` issues each page as an independent statement with no txn, so pages see different snapshots today), or keyset resume (`WHERE ts_unix_ns < lastSeenTS`), or a post-loop count cross-check. Note the design's L1 parity line (`token_issued events: N` vs chain-derived count) can serve as that cross-check **only if the count and the pages come from the same snapshot** — otherwise both race independently.

## 3. sqlite WAL read-only lock behavior — **empirically validated, with two corrections**

Scratch harness against modernc.org/sqlite v1.50.1 (pinned in go.mod):

- **`_journal=WAL` is a silent no-op** under the pinned driver: `file:x?_journal=WAL&_busy_timeout=5000` opens with `journal_mode="delete"`. Only `_pragma=journal_mode(WAL)` works. Consequence: the "typical production DSN" documented in `platform/audit/sqlite/sink.go` does **not** produce WAL mode — the design's FM-4 WAL failure mode only applies to deployments that set WAL via `_pragma` (or an external `PRAGMA`). This is doc/code drift worth reporting per AGENTS.md §1; the design should pin the `_pragma` form in any WAL test.
- **`mode=ro` is safe in every tested WAL shape**: live writer with uncheckpointed frames (reads all frames, n=3), and a hot copy of db+`-wal` without `-shm` (also reads all frames — no `SQLITE_READONLY_CANTINIT` under this port, so the classic C-SQLite copy-without-shm failure does not reproduce).
- **`immutable=1` is the real trap**: with uncheckpointed frames it returned `no such table` — a completely stale view (table creation itself was WAL-only). If the schema had been checkpointed and only recent events were in the WAL, this would be a truncated-chain **false pass**. Pin: never open the verify DSN with `immutable=1`; `?mode=ro` is correct and sufficient.

## 4. Schema-version-checked `OpenReadOnly` contract — **verified for sqlite; pg peer is feasible as designed**

- sqlite (`sink.go`): `OpenReadOnly` skips `migrate.Run` entirely (no `BEGIN IMMEDIATE`, no DDL) and gates on `checkSchemaCurrent` → `migrate.CurrentVersion` (pure reads: `sqlite_master` probe + `SELECT MAX(version)`) vs `migrate.MaxVersion` — **exact equality**, not ≤. Tests pin all three contract faces: no file mutation (hash before/after), `mode=ro` works, version-0 DB rejected.
- Nuance worth documenting: a pre-versioning-era production DB (real v1 schema, no `schema_migrations_audit` table) reads as v0 and is **rejected** by the verify tool — operators must open read-write once to stamp/migrate, or use a matching binary. The "never-migrate" contract is exactly why; the error message ("database at v0") will look confusing for a populated store.
- pg peer: the building blocks exist and are read-only-safe — `infrastructure/postgres/migrate.go` has its own `CurrentVersion` using `information_schema.tables` + `SELECT MAX(version)` (no writes, no advisory lock; the advisory lock lives only in the write-path `Run`). The gap is exactly as stated: `NewAuditSinkWithDB` always migrates, so the deferred peer is a read-only constructor + exact-version check reusing pg `CurrentVersion`/`MaxVersion`. One design nit: pg DSNs arrive in two shapes (`postgres://...` URL and libpq `host=... dbname=...` keyword strings); the "deferred" error (FM-5) should sniff both, else keyword-form DSNs fall through to a confusing sqlite open error.

## 5. Per-page `Limit` clamp × resume-from-`LastHash` — **semantics verified; the clamp is one of two independent truncation vectors**

- Clamp verified exactly as cited: `auditspi/query.go:86-92` — `≤0 → 100`, `>1000 → 1000` (both sinks call `q.NormalizedLimit()`). `audit.Query` is an alias of `auditspi.Query` (`aliases_spi.go:19`).
- The false-pass mechanism: any termination rule of the form "stop when `len(page) < requestedPageSize`" false-passes when the clamp shrinks the effective page below the requested size and the chain fits in one clamped page (e.g., Limit=2000 → 1000; a 1500-event chain's first page is full at 1000, `1000 < 2000` → stop → the 1000-event prefix verifies). The design's pins — explicit per-page Limit inside (0,1000] and empty-page termination — are correct.
- Resume-from-`LastHash` (`recorder.go:67-68`, `WithHashChain` → `tip.LastHash` → `chain.seed`) is a **separate path from paging**: the recorder never pages, so the clamp cannot corrupt the resume itself. The interaction is one-way: if the verify loop uses a `VerifyChainSegment` anchored at a LastHash-derived checkpoint and pages toward it with short-page termination, the truncation lands at the newest end and the anchored segment still verifies → false pass. Same pin fixes it.
- **But** (see point 2): with OFFSET paging, "explicit Limit + until-empty" is *not* sufficient — concurrent appends truncate the tail independently of any clamp. The design should state the two truncation vectors (clamp + append-shift) and pin one snapshot-isolated read (or keyset) as the single fix for both.

## Bottom line

The design's eight evidence citations all check out; the five semantics validate with three sharpenings: (a) FM-3 must be elevated from "instability" to a **false-pass truncation** with a snapshot-isolation pin (empirically demonstrated); (b) the WAL failure mode should be scoped to `_pragma=journal_mode(WAL)` deployments — the documented `_journal=WAL` DSN is a no-op under the pinned driver (drift to report), and `immutable=1` must be explicitly forbidden; (c) the tie-break framing should say "both paging queries are tie-break-less; the rowid/seq asymmetry lives in the tip queries and the schema" — with the chainer's monotonic-ts guarantee making this benign for chained stores (modulo the cross-process seam).
