All verification complete. Here is the review of the four database-layer claims.

---

# Database-layer review: CLI audit-chain design (`cmd-sso-ctl-importcmd-audit-chain-design.md`)

## Q1 — Concurrent 'audit'-namespace migration over the provider pool vs a live server

**Migration mechanics: verified correct, with one behavioral difference between backends.**

- SQLite (`platform/migrate/migrate.go:133-186`): pinned connection, `PRAGMA busy_timeout=10000`, then `BEGIN IMMEDIATE` wrapping version-table read + all pending DDL + version stamps in **one transaction**. A concurrent migrator (e.g. a booting server) serializes on the write lock; the loser waits ≤10 s then errors → F1 fail-fast path is real. Idempotent re-run on a server-migrated DB is a true no-op under the same lock.
- Postgres (`infrastructure/postgres/migrate.go:73-140`): `pg_advisory_xact_lock(fnv64a("sso:migrate:audit"))` + one transaction; concurrent boots serialize on the advisory lock (waits indefinitely, no timeout); CockroachDB falls back to SERIALIZABLE + 40001 retry.
- Both run **per-namespace**, so the CLI's `"audit"` migration cannot collide with the server's `"users"`/`"clients"` namespaces even on the same file/DB. The "no lock is held between open and exit" claim (design §3.4) is correct — the migration transaction ends at `Run` return.

**Correction 1a — "newer file → fail fast" (§3.3) and F1's "newer schema version → fail fast" do not match the wired code.** `migrate.Run` and `postgres.Run` **silently no-op when the DB is ahead** (`applyPending` skips versions ≤ current; no `CheckSchema` anywhere in the CLI path). Only `auditexport`'s `OpenReadOnly` rejects (`checkSchemaCurrent`, sink.go:233-248). Notably, the *server* gates the sqlite audit schema at boot (`cmd/sso-server/build_app_core.go:264-271` `checkAuditSchema` → `CheckSQLiteSchema(..., "audit", auditsqlite.AuditMaxVersion())`) but **deliberately skips the postgres gate**. So the design as wired behaves like the ungated postgres-server path, while claiming the `OpenReadOnly` gate. Fix: add an explicit `CheckSchema` in `openDB` for the `"audit"` namespace on both backends (`migrate.CheckSchema` / `postgresbackend.CheckSchema`; `auditsqlite.AuditMaxVersion()` exists at `platform/audit/sqlite/maxversions.go:10`), or weaken §3.3/F1. If you gate postgres in the CLI, say explicitly that this is stricter than the server's own postgres boot.

**Correction 1b — F7/§3.4 "sqlite single-writer caveat applies" understates the real hazard: a chain fork.** The tip is read **once** at recorder construction (`WithHashChain`, recorder.go:55-77); every subsequent `Record` is a plain INSERT on both sinks (sqlite sink.go:231-241; postgres audit_sink.go:158-170) with no tip re-read and no conditional insert. Any server audit write between the CLI's `openDB` (tip seed) and the CLI's first `Record` produces **two events with the same PrevHash** — a fork that breaks whole-table `VerifyChain` at the seam. SQLite's single-writer serialization does not prevent this (the lock is held only per-INSERT, and tip-read+insert is not atomic). This is pre-existing for postgres multi-replica, but for sqlite it is **new**: the design's premise is exactly server+CLI on one file. The design must state the operational constraint — run imports with the server's audit writer quiesced, or accept a seam break with segment verification — rather than implying F7 is "documented and handled". Also note the CLI's own pool conns get busy_timeout **only from the DSN `_pragma=busy_timeout(...)`** (users.go:86-89; modernc ignores mattn-style `_busy_timeout`, migrate.go:107-108) — without that pragma, contention with a live server surfaces as immediate per-row SQLITE_BUSY errors (F5 path), not waits. F7 should require the DSN pragma for live-file runs.

## Q2 — Atomicity of the user-import row and its audit record

**Not a single transaction — crash-visible gap confirmed.**

- The (user + outbox) pair commits atomically on both backends: `ImportUser` (sqlite users.go:237-262) and `tenantcommerce.ImportUserTx` (import.go:25-48).
- The chain event is a **separate INSERT after commit** (design's `writeBatch`: `db.ImportUser(...)` → `recorder.Record(...)`). Process death between the two leaves: user imported + outbox event pending + **no chain event, no stderr** — a silent gap. F3 covers only sink `Record` *errors* (stderr-visible); it does not cover process death. This is consistent with the AGENTS.md fail-open audit posture (audit is the fail-open side; the outbox pair is the durable delivery surface), but the design should say so explicitly: add a crash row to the FM table stating the attestation is **eventual** — the crash window is real and silent.
- The chainer's monotonic ts bump (chainer.go:57-71) keeps in-process ordering sound; it does not help across the crash seam.

## Q3 — Recovery semantics on partial import

**Verified: re-run is idempotent for the pair, but appends duplicate chain events — the design never ties this to a crash row.**

- Per-row transactions, batches continue on error, errors accumulate (importer.go:93-142) — partial imports are the expected state after any crash.
- Re-run: user upsert is `ON CONFLICT(id) DO UPDATE` (users.go:199-211); outbox dedupes via the deterministic `import:<tenant>:<userID>` key (sqlite `DO NOTHING` keeps the original row; postgres bare `DO NOTHING` + fact-equality → `ErrIdempotencyConflict` only on changed facts). `TestImportGovernance_CrashRerunIsIdempotent` (test/:463) pins the pair side.
- The chain side is **not** idempotent: a crash + re-run appends a duplicate `admin_user_imported` event per already-attested row. The design acknowledges re-import append semantics (§3.4) and defers dedupe to direction 3, but the FM table has no crash-recovery row connecting F3's gap to the duplicate-on-rerun consequence. Recommend one FM row: "crash after pair commit, before Record → user un-attested; re-run attests but duplicates already-recorded rows; no checkpoint/resume marker exists (whole-file re-run)."

## Q4 — Postgres env-gated acceptance tests and same-table ChainTip resume

**The resume path is covered at the wiring level and the tests DO run in CI — but the proposed whole-table assertions are incompatible with the shared-DSN test convention.**

- CI is not a gap: `.github/workflows/ci.yml:111-116` sets `SSO_TEST_POSTGRES_DSN`/`DIALECT` for `go test -race -count=1 ./...`, which includes `test/` (root module) and `cmd/sso-ctl`. The env-gated tests are not dead code.
- The same-table resume path: AC2's fresh-recorder-on-same-sink simulation is shape-identical to the server→CLI seam (the server's recorder is the same `audit.New(sink, WithHashChain())`; `BuildPrimaryAuditSink` uses `NewAuditSinkWithDB` on the same pool). So the construction-time `LastHash`-seed resume is genuinely exercised on postgres. What is *not* covered end to end: the real-binary export→verify loop is sqlite-only (`auditexport` v1), and no test drives literal server-binary + CLI-binary — both correctly stated in the design as in-harness-only for postgres.
- **The flaw: whole-table assertions race the shared DSN.** `infrastructure/postgres` audit tests `TRUNCATE audit_events` at test start (audit_test.go:18) and run `t.Parallel()` in a separate package binary; the existing importcmd postgres test explicitly avoids whole-table assertions for this reason ("Unique IDs + Delete cleanup (not TRUNCATE) — the infrastructure/postgres package tests TRUNCATE this table and may run concurrently on the same DSN", main_test.go:782-790). The design's AC1-postgres ("exactly N rows; `VerifyChain` nil over the whole table") and AC2 ("exactly ONE genesis in the table") will false-fail under concurrent TRUNCATE/interleaved rows — exactly the CI invocation. Correction: anchor at test-start `LastHash` → `VerifyChainSegment` over **own events only** (robust to interleaving — the recorder's in-process stamp keeps own events internally linked, and the anchor is a value, not a row, so TRUNCATE of the anchor row is harmless), delete own rows by ID in cleanup, and drop the whole-table genesis/row-count assertions. Residual risk (another package's TRUNCATE landing mid-test) is the same residual the existing convention already accepts.

## Verdict

Sound architecture, three design-doc corrections required before implementation:

1. **F1/§3.3**: the newer-schema fail-fast claim is false as wired — add explicit `CheckSchema` gates in `openDB` (matching the server's sqlite boot gate) or weaken the claim.
2. **F7/§3.4**: replace the "single-writer caveat" framing with the chain-fork hazard (tip-read + INSERT not atomic across processes) and the quiesce-or-fork operational constraint, plus the `_pragma=busy_timeout` DSN dependency for live-file runs.
3. **FM table**: add the crash-consistency row (silent gap between pair-commit and Record; eventual attestation; duplicate chain rows on re-run) — and rework AC1-postgres/AC2 assertions to segment-anchored, own-row-scoped verification for the shared-DSN convention.

Nothing found contradicts the core claims: migration serialization per backend, pool ownership (D-2, both `Close`s close the wrapped `*sql.DB`), same-table resume semantics, and the sqlite-only export→verify constraint all verified as stated.
