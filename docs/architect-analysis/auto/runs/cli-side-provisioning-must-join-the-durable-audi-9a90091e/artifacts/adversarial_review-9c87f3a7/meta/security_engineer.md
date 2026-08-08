All claims verified against HEAD (`8598a26b`). Here is the review.

# Review: audit hash-chain integrity design (cmd-sso-ctl import)

**Verdict: the core seam is sound and the code citations check out** — `WithHashChain` construction-time seeding (recorder.go:55-77), `ChainTip.LastHash` (sqlite maintenance.go:75 `ts DESC, rowid DESC`; postgres audit_sink.go:252 `ts DESC, seq DESC`), the intra-process monotonic ts bump (chainer.go:57-71), and fail-closed `VerifyChain`/`VerifyChainSegment` (chainer.go:157-196) are exactly as cited. But four findings need design deltas: one **false claim about resume under cross-host clock skew**, one **exit-code hole that makes F3 omissions silent to automation**, one **correction to how the chainless boundary actually fails**, and one **incorrect PII invariant** (email-derived `target_user`).

## 1. ChainTip resume across server↔CLI — correct for same-host sqlite, unproven for postgres

Verified correct: seeding happens once at construction from `LastHash`; the chainer's monotonic bump (chainer.go:57-71) makes ts order == chain order *within a process*. Same-host sqlite (CLI shares the server's clock) → CLI rows get ts ≥ head ts → `LastHash` keeps returning the true head → resume is exact. AC2's fresh-recorder test pins this.

**Finding (material) — F6 understates the failure: the design introduces a second clock.** The monotonic bump is intra-process only (`lastTS` starts at zero per construction). AGENTS.md's "clocks slew, never step" governs *one* host; `--backend postgres` legitimately runs the CLI on a different host with a persistent NTP offset δ. If the CLI clock is behind the server's head ts:

- the CLI's rows sort **before** the server head in ts order → the next whole-table `VerifyChain` breaks at the *first CLI row* (`prev_hash=H2, expected H1`) — a false tamper alarm; and
- `LastHash` still returns the server head (max ts) → a second CLI run seeds from H2 → a fork, i.e. a second break.

The server alone never had this problem (single host, single clock); the design's "pre-existing behavior" framing is wrong for the postgres path. AC2 cannot catch it: one process, one clock. **Delta:** at recorder construction the CLI should clamp its event ts to `max(now, durable max ts + 1ns)` — one extra read over the provider pool (ChainTip returns only the hash, so `SELECT MAX(ts_unix_ns)`), passed into `newAuditEvent`. Cheap, preserves the seam's promise, and should be pinned by a test that injects a behind-clock recorder.

## 2. Mixed chainless-server boundary — fails *at export time*, not at verify time

Verified: chainless server rows carry empty `hash`; `VerifyChain` fails on them (message: "hash mismatch … **event was tampered with**" — the design's "reports the boundary break" is true but the wording is misleading). What the design misses is the failure ordering:

- `BuildExportBundle` **self-verifies at build time** (auditexport.go:141-142) — for a full/window export it runs `VerifyChainSegment(events, events[0].PrevHash)`; for filtered exports `VerifyEventIntegrity`. Both fail on empty-hash rows. So on a mixed chainless deployment, `sso-ctl audit-export` **exits 1 without producing a bundle** — §3.6 step 4's "evidence collection is unchanged tooling" loop cannot run at all. This is fail-closed (safe), but F4/AC1 describe verify-time behavior, not the export-time refusal.
- Segment verification of the CLI's genesis-anchored rows is **not expressible in auditverify**: `--anchor-hash ""` is rejected as misuse (main.go:141-144), and the CLI's first event PrevHash is exactly `""`. The only working path is a `--since` window covering exactly the CLI rows (anchor then equals the first CLI row's PrevHash). The design should say so.
- Because the chainless server keeps appending empty-hash rows, the boundary is **not one-time**: every subsequent chainless server write re-breaks the table, and the next CLI run seeds genesis again (LastHash returns `""`). The design should document chainless→chained as a one-way transition (enable `cfg.Audit.HashChain` on the server first), not a steady state. Note also the boundary is unattested by construction — F2's tip-error genesis and F4's chainless genesis produce the same observable with no in-chain marker distinguishing them.

## 3. F3 fail-open / F5 skips — chain integrity holds, but the omission is silent (exit 0)

Key mechanism verified: `Recorder.Record` swallows sink errors into the error handler (recorder.go:176-179); the design wires only a stderr print. Nothing propagates to `runImport` → `Run` returns 0.

- **F3 is the real finding.** User rows + outbox events commit, chain row missing, chain remains *continuous*, `audit-verify` returns 0, process exits 0. `VerifyChain` detects breaks and tampering — **not omissions**. A run that records zero chain events is byte-identical in its exit status to a fully attested one. For a direction whose entire purpose is the attestation surface, that's the silent-weakening case. **Delta:** count handler invocations in the bundle and make `runImport`/`Run` exit non-zero (or at least print a distinct failure summary line) when any recording failed — fail-open on the user write, fail-loud on the attestation.
- **F5** (skipped rows = `ImportUser` failures, pair semantics) records nothing consistently — no weakening, and nothing was committed. But note there is **no batch-level event at all**: an all-fail run is fully invisible in the chain, exit 0 (pre-existing direction-1 behavior, but the design inherits it). A single batch-summary event (same type, `OutcomeFailure` when any row failed) would close both F3-crash and F5 invisibility; at minimum, document the crash window between `ImportUser` commit and `Record` as an omission class equal to F3.

## 4. PII through SIEM/CEF/OCSF — no live path, but the "never email" invariant is false

- **No live-stream exposure, structurally**: SIEM sinks are fan-outs of the *server's* recorder (`BuildAuditSIEMSinks` → MultiSink). CLI events go straight into the DB and never pass the server's CEF/OCSF formatters — so D-6's curation registers names/activities that only matter for offline replay. (Worth stating explicitly: import events will *not* appear in live CEF/OCSF/syslog streams at all.)
- **The invariant is false**: `deriveID` (parsers.go:367-378) falls back to `sanitizeID(provider + ":" + email)` when the source lacks an opaque ID — and CSV's `username` column is commonly an email. `target_user` metadata **can be an email-derived identifier**, and both formatters export metadata verbatim: CEF `meta.target_user=<value>` (cef.go:272-289), OCSF `unmapped.meta.target_user` (ocsf.go:140-160). Any replay of bundles/API rows into the formatters (the only path CLI events take to SIEM) carries it. D-3's "Never the password hash, hash format, email, or any attribute material" is not guaranteed by construction — password hashes are safe (never in metadata), but email-derived IDs are not.
- Context that tempers severity: the server precedent already exports raw target IDs (`recordAdminMeta` → `Reason: "target="+id` → CEF `msg` / OCSF `Message`), so this is a *claim correction*, not a new leak class. Also note the CLI recorder wires **no redactor** (server uses `DefaultPIIRedactor` at build_app_core.go:381 — a no-op for CLI events since it touches only ActorID/IP/UA, but the asymmetry deserves one line). Since redaction precedes chaining, this must be decided at write time. **Delta:** either keep the raw ID and fix D-3's wording (aligning with server precedent), or hash `target_user` at record time — with the correlation cost spelled out.

## 5. Does auditverify detect CLI-side gaps?

- **Detects**: any break/tamper/gap in the chained region, including across the server↔CLI seam and between CLI runs — a deleted or overwritten link breaks the next row's PrevHash (fail closed, exit 1). CLI rows are stamped by the same chainer, so they are fully inside the verified region. ✓
- **Cannot detect**: omissions (F3, F5, crash window) — continuity holds. That is the gap the exit-code delta in §3 closes.
- The mixed chainless case fails closed *before* verify (export self-verify, §2), which is stronger than silent — but the design should describe it as such.

## Recommended design deltas (all small, no architecture change)

1. F6: CLI clamps event ts to `max(now, durable-head-ts+1ns)` on postgres; add a behind-clock test to AC2.
2. F3: recording-failure counter → non-zero exit (or distinct summary); document the crash-window omission class.
3. F4: correct the failure ordering (export refuses to build the bundle; segment verify requires a `--since` window, `--anchor-hash ""` is rejected); document chainless→chained as one-way.
4. D-3: fix the "never email" claim (email-derived `target_user` is exported verbatim on replay); decide raw-vs-hashed explicitly.
5. Consider one batch-summary event so an all-fail/all-skip run leaves *some* chain evidence.

Everything else — the six registration points, no-DDL claim, pool ownership (sinks never Closed), AC1/AC2 testability, budgets — verified accurate as written.
