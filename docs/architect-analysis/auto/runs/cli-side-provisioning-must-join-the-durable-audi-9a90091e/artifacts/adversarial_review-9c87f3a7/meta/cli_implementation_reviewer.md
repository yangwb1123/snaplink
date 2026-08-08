# Review: sso-ctl import command surface as designed

Baseline: working tree at `8598a26b`; design doc `docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-design.md` (380 lines); `EventAdminUserImported` does **not** yet exist anywhere (verified by grep) — the design is unimplemented, so this review checks the design's claims against the wired code.

**Verdict: the core seam (recorder-over-shared-sink, `importDB` bundle, dispatcher legality, metadata bounds) verifies as designed, but three of the six reviewed areas contain deltas the design promised and did not wire — the fail-loud exit-code delta, the CheckSchema gates, and the event-ts clamp are all absent from the design text — and one existing test would silently degrade, not break, under the bundle refactor.**

## 1. Flag set and parsing — verified, with one clarification

Actual flag set (main.go:132-139): `--dsn`, `--backend` (default `sqlite`, unknown value → error), `--dialect`, `--format` (required), `--file` (default `-`), `--tenant` (required unless `--dry-run`; validated ≤128 chars, no control chars, main.go:158-175), `--dry-run`, `--batch-size` (default 100). Exit discipline: parse/validation → `os.Exit(2)` via `ExitOnError` + explicit checks; runtime (open/parse/db) → `fatalf` exit 1 (main.go:96-127).

**`--provider` is not a flag and the design does not introduce one.** The design's "provider (the closed parser vocabulary: auth0|keycloak|okta|csv)" is the per-format parser tag `u.Provider` (importer.go:161, `newAuditEvent` metadata), whose closed vocabulary is enforced by `parseInput` rejecting unknown formats (runtime error → exit 1). That is consistent with D-3 (`Event.Provider` stays empty; source format rides in metadata). No design change needed; the review prompt's "`--provider`" element does not exist in the design and should not be added.

One inherited nit worth one doc line: unknown `--backend` exits 1 (runtime path via `openDB` error), not 2 (misuse) — pre-existing, F1 sits on the same path, unchanged.

## 2. Exit-code discipline — the fail-loud delta (security finding 3) is NOT in the design

Current discipline: `runImport` always returns `nil` (batch errors print to stderr; skip accounting prints on stdout; exit stays 0). The design's F3 row keeps this: `WithErrorHandler` prints to stderr, batch continues, `Run` returns 0. Verified mechanism: recorder.go:176-179 — `if err := r.sink.Record(ctx, e); err != nil && r.onError != nil { r.onError(err) }` — the handler is a fire-and-forget callback; nothing propagates to `runImport`.

**Consequence (the exact silent-weakening case): a run where every `Record` fails commits all users + outbox events, writes zero chain rows, prints "imported N users" on stdout, and exits 0 — byte-identical to a fully attested run.** `auditverify` detects breaks and tampering, never omissions; the chain stays continuous. The design's F3 wording "attestation gap is operator-visible on stderr" is true only interactively; automation sees nothing.

Required delta (small, no architecture change):
- `importDB` gains an `atomic.Int64` recording-failure counter, incremented inside the `WithErrorHandler` closure in `newImportDB`.
- `runImport` (or `Run`) prints a **distinct stderr summary** when the counter > 0: e.g. `sso-ctl import: N audit record(s) FAILED — users were imported but are not chain-attested` — and `Run` returns 1.
- Update the package-doc exit contract (0 = import complete *and* attestation complete). Fail-open on the user write is preserved (no rollback); fail-loud on the attestation. This changes the documented exit-code contract, so it belongs in the same commit as the rest (§5.6 contract hygiene).
- Add the FM-table crash row the database reviewer required: process death between `ImportUser` commit and `Record` is a silent, unattested gap; re-run attests but duplicates chain rows for already-attested users (no checkpoint/resume marker exists).

## 3. stderr vs stdout separation and the F3 error-accumulation report — separation clean, report missing

Current convention is consistent across the family: progress/summaries → stdout (`runImport` "imported N users" line, dry-run preview), errors → stderr (`fatalf`, per-batch `"batch %d-%d: %v (skipped %d in this batch)"`); `auditexport` keeps stdout pure (bundle JSON) with summaries on stderr; `auditverify` prints results to stdout, diagnostics to stderr. The design's stderr error handler fits the convention.

**Gap:** there is no F3 error-accumulation report. Write errors accumulate per batch (importer.go `writeBatch` errs slice → batch line), but recording failures produce only unbounded per-error lines with no final count — and the stdout summary is identical whether zero or all attestations failed. The counter + distinct stderr summary from §2 closes this; the design should state explicitly that the stdout summary line stays machine-stable and the attestation failure lives on stderr only.

## 4. `importDB` bundle refactor — compiles, but one existing test silently degrades

Verified the compile-unchanged claim: `userStore` = `sso.UserProvider` (alias of `core.UserProvider`, shared/core/spi.go:42-53) + `ImportUser` + `Close`; embedding promotes `ImportUser`/`GetByID`/`List`/`Delete`/`Close` to `*importDB`, so all call sites compile — `runImport` (main.go:117), tests at main_test.go:409/452/557/575, `openDB`-based tests, helper return-type change at :347/:355 propagates mechanically (~7 sites, design's "~8" is accurate).

**Silent behavioral break the design misses:** `TestRunImport_Postgres_PersistsAndUpserts` does `p.(postgresUserStore)` (main_test.go:835) on `openDB`'s return. With `openDB` returning `*importDB`, the assertion always yields `ok == false`, so the governance-row cleanup `DELETE FROM tenant_commerce_outbox ...` never runs — leaking rows into the shared DSN that tenantcommerce tests claim. Compiles; degrades at runtime. Fix: `if s, ok := p.userStore.(postgresUserStore); ok` (the embedded field) and list this site in the design's changed-files.

Second nuance: `core.UserProvider` does **not** include `DB()` — the embedded interface cannot reach the pool. The design's "p.DB compiles unchanged" holds only where `p` is the concrete provider inside `openDB`. Anything needing the pool (CheckSchema gate, ts-clamp read — §6) must happen in `openDB` (concrete types) or via an explicit accessor; the design must not assume `db.DB()` on the bundle.

## 5. Dispatcher wiring / export→verify loop — legal, mechanics verified, two nuances to state

Verified: main.go:71-72 `os.Exit(run(args))`; `subcommands` maps `import`/`audit-export`/`audit-verify`. A test in `cmd/sso-ctl/importcmd/main_test.go` (package `importcmd`) importing `auditexport` + `auditverify` is legal — `importcmd` imports neither, and both import only `platform/audit*`, so no cycle. (The design's justification "main.go:22-23 imports both" is evidence of linkage, not the legality; the legality is cycle-freedom.)

Loop mechanics verified end to end: `auditexport.Run` returns 0 on a clean bundle (documented exit contract), writes bundle via `writeBundle` (stdout or `--out`), summary to stderr; `auditverify.Run --from-file` accepts the bundle's `{events:[...]}` envelope (`parseEventList`) and `VerifyChain` passes for a fresh file whose `events[0].PrevHash == ""` (genesis). AC1 needs `--out` (or stdout capture) for the "exactly N `admin_user_imported`" assertion.

Two nuances the design must add (security finding 2):
- **Mixed chainless→CLI tables fail at export, not verify:** `BuildExportBundle` self-verifies at build time (platform/audit/auditexport/auditexport.go:141-142) and fails on the server's empty-hash rows — `sso-ctl audit-export` exits 1 with **no bundle**. §3.6 step 4's "evidence collection is unchanged tooling" loop cannot run at all on a mixed deployment; the design must state this (fail-closed) and document chainless→chained as a one-way transition (enable `cfg.Audit.HashChain` on the server first).
- **The §3.3 "segment verifies via `VerifyChainSegment` anchored at the boundary" needs a concrete recipe:** `--anchor-hash ""` is rejected as misuse (auditverify `checkMisuse`). Workable path: `--since` window covering exactly the CLI rows → bundle `BoundaryPrevHash` is the boundary → plain `--from-file` verify when the boundary is genesis (`""`), `--anchor-hash <boundary>` only when the server was chained (real hash).

## 6. CheckSchema gates and the event-ts clamp — both promised, both absent

### 6a. CheckSchema gates (database reviewer Correction 1a) — unwired claim

The design's §3.3/F1 "newer file → fail fast with the OpenReadOnly-style version-mismatch error" is false as wired: `auditsqlite.NewWithDB`/`postgres.NewAuditSinkWithDB` run `migrate.Run`, whose `applyPending` **silently skips** versions ≤ current (platform/migrate/migrate.go; postgres/migrate.go:146-148). Only `OpenReadOnly` rejects (sink.go:206-218, `checkSchemaCurrent` :228) — and it demands *exact* equality, which is wrong for a migrating CLI (it would reject a legitimately older DB the CLI should migrate up).

Concrete placement in `openDB`, per branch, before `NewWithDB`/`NewAuditSinkWithDB`, error path identical to the existing outbox-migration failure (`_ = p.Close(); return nil, err` — preserves F1's fail-fast-before-any-row contract):

- **sqlite:** `migrate.CheckSchema(ctx, p.DB(), "audit", auditsqlite.AuditMaxVersion())` — same semantics as the server's own sqlite boot gate (`serverbuildsign.CheckSQLiteSchema` → `migrate.CheckSchema`, build_app_core.go:264-271; `AuditMaxVersion` at platform/audit/sqlite/maxversions.go:10).
- **postgres:** `postgres.CheckSchema(ctx, p.DB(), "audit", <max>)` exists (postgres/migrate.go:224) but **no exported audit max-version function exists** — `auditMigrations` is unexported (audit_sink.go:74; only `AuthCodesMaxVersion`-style helpers are exported). Two options: export `func AuditMaxVersion() int { return migrate.MaxVersion(auditMigrations) }` from audit_sink.go (one line — but the design's "Do not modify: infrastructure/postgres/audit_sink.go" list must be updated), or skip the postgres gate to mirror the server's deliberate skip (`checkAuditSchema` returns nil for postgres, build_app_core.go:264-271) and weaken §3.3/F1. Recommend the export + gate, with an explicit doc note that CLI postgres is stricter than the server's own postgres boot.
- Both `CheckSchema` variants return nil for fresh DBs (no version table yet), so fresh-file behavior is unchanged; only too-new DBs fail fast. Also correct the "OpenReadOnly-style" wording: the CLI gate is `CheckSchema` (reject only ahead), not exact-match.

### 6b. Event-ts clamp `max(now, durable-head-ts+1ns)` (security finding 1) — absent

The design stamps `time.Now().UTC()` in `newAuditEvent` and F6 dismisses cross-run step-back as "pre-existing behavior; not worsened by this change." That framing is wrong for the postgres path: `--backend postgres` legitimately runs the CLI on a different host with a persistent NTP offset δ. With the CLI clock behind the server head: CLI rows sort before the server head → next whole-table `VerifyChain` breaks at the first CLI row (false tamper alarm), and `LastHash` still returns the server head → a second CLI run seeds from it → a fork. The chainer's monotonic bump (chainer.go:86-89) is intra-process only (`lastTS` starts at zero per construction).

Concrete placement: one `SELECT COALESCE(MAX(ts_unix_ns), 0) FROM audit_events` read over `p.DB()` in `openDB` **after sink construction** (table exists by then; both sinks persist `ts_unix_ns`); pass `tsFloor` into `newImportDB(store, sink, tsFloor)`; `newAuditEvent` stamps `max(now, tsFloor.Add(time.Nanosecond))` (the chainer's bump then keeps strict in-run ordering). One read per run; preserves the seam promise; pin with a behind-clock recorder test in AC2. F6's row must be amended: this is a new exposure for the postgres path, not pre-existing.

## Adjacent deltas that must land in the same commit (carried from the reviewer evidence)

- **D-3's "never ... email" invariant is false:** `deriveID` falls back to `sanitizeID(provider + ":" + email)` (parsers.go:367-378; `TestDeriveID` pins `csv:x@y.z`), so `target_user` metadata **can be an email-derived identifier**, exported verbatim on bundle replay (CEF `meta.target_user=`, OCSF `unmapped.meta.target_user`). Fix the wording in `newAuditEvent`'s comment (align with server precedent of exporting raw target IDs) or hash at record time with the correlation cost spelled out — decide explicitly (security finding 4).
- **F7's "single-writer caveat" is the wrong hazard:** the real one is a chain fork — the tip is read once at recorder construction, every later `Record` is a plain INSERT with no tip re-check, so a server write between CLI `openDB` and first `Record` yields two events with the same `PrevHash`. State quiesce-or-fork as the operational constraint, plus the `_pragma=busy_timeout` DSN dependency for live-file runs (migrate.go's busy timeout arms only the migration connection).
- **SIEM conformance guard:** the design's C1 reproduces the stale `"+2"` guard as fact; the live guard has a 44-type bypass and a misleading `t.Logf`. Record the correction in §2 and fix the guard/comment in the same commit (the new transcription otherwise ships under a guard that already fails to cover shipped types).

## Bottom line

Sound seam; the six-registration API and `importDB` bundle shape verify against the code, and the export→verify loop is legal and mechanically workable. Before implementation the design needs: (1) the fail-loud recording-failure counter + non-zero exit + stderr summary (§2/§3), (2) the wired `CheckSchema` gates with a new postgres `AuditMaxVersion` export and a corrected "ahead-only" wording (§6a), (3) the ts-clamp read at `openDB` construction (§6b), (4) the `p.userStore.(postgresUserStore)` fix in the postgres test (§4), and (5) the export-time-refusal + anchor-recipe wording in §3.3/§3.6 (§5).
