All verification done. Here is my assessment.

---

# §7 Acceptance-mapping assessment — verdict: mostly sound, 5 real gaps (one test would fail as specified)

I re-verified every named test against the actual code, the existing suites, and the gate tests. The gate commands are correct, `Run(args) int` is in-process-testable, the stock-backend seeding pattern exists (`auditexport/main_test.go:23-43` — `audit.New(sink, WithHashChain(), WithClock(...))`), and `Recorder.WithClock` (recorder.go:38) makes the A5 bucket scenario constructible without sleeping. But three acceptance rows do not hold up as written, and two criteria have no named test at all.

## G1 — A2's `TestVerifyDSNByteConsistency` would fail on its own "truncated stores" sub-case (the iff is false there)

§7 A2 (and its source, REQ-1 criterion 3) asserts: *CLI exit == 0 iff `audit.VerifyChain(events) == nil`*, "property asserted over clean, flipped, and truncated stores". Trace the designed behavior from `Run` (auditverify/main.go):

| Store | VerifyChain(events) | CLI exit |
|---|---|---|
| clean, full read | nil | 0 ✓ |
| flipped, full read | non-nil | 1 ✓ |
| **truncated, prefix clean** | **nil** | **1** (`prefix verified … not the full chain`, main.go:272-275) ✗ |

On a truncated-but-otherwise-clean store the CLI *deliberately* exits 1 while `VerifyChain` over the verified prefix returns nil — that is the truncation-honesty contract (FM-7), which directly contradicts the iff as written. The named test, implemented literally, fails against the designed behavior.

**Fix §7 (and REQ-1 c3):** split the predicate — untruncated runs: `exit==0 ⟺ VerifyChain(full)==nil`; truncated runs: `exit==1 ∧ VerifyChain(prefix)==nil ∧ stdout contains "truncated by --limit" ∧ head==prefix tip`. The sub-claim "printed head == events[len-1].Hash" survives both cases.

## G2 — REQ-1 criterion 5 (sqlite DSN truncation honesty) has no named test in §7

The A1 row names only clean/flipped tests; A2 touches truncation only through the broken iff (G1); the truncation criterion appears only as the postgres variant inside `TestVerifyDSNPostgresSharesPath`. The sqlite `--dsn` truncation path (REQ-1 c5: `--limit 5` over 10 events → `prefix verified: 5 event(s) — truncated by --limit 5`, exit 1; `--checkpoint` → fail-fast with no verification output) is a distinct new-code path with **no named gate**. Add `TestVerifyDSNTruncation`.

Caveat for whoever writes it: the exact-fill probe (main.go:427-428) re-reads the **same offset** the page was just fetched from (the code comment claims "next offset" — the comment is wrong; the verbatim move will carry it). Consequence: any run where `len(collected) == limit` exactly reports truncated=true, even when the chain ends exactly at `limit` (pre-existing URL-mode semantics; `TestReadFromURL_ProbeDetectsTruncation` at checkpoint_test.go:570 can't discriminate it — with 6 events/limit 5/page 5 both offsets return non-empty). §3.2's "probe one page at the same offset" is faithful to the code; just write the truncation tests with limit strictly less than chain length and don't be surprised by the boundary case.

## G3 — REQ-5 "zero DDL" is testable, but §7 under-specifies the mechanism and one offered option is unimplementable as designed

The row says *"zero DDL (read-only role or DDL-free trace)"*. pgx v5.10.0 does have `QueryTracer`, but `OpenAuditReadOnly(cfg Config)` wraps `postgres.Open(cfg)` with no tracer hook — a DDL-free trace is **not implementable** without constructor plumbing the design doesn't add. Pin the mechanism instead:

1. **Test DSN with `options=-c default_transaction_read_only=on`** (or a SELECT-only role). Any DDL attempt fails loudly with a read-only-transaction violation *before* the version check could pass — so asserting the **exact** "found vs expected version" diagnostic (migrate.go:198-218 + `migrate.MaxVersion`) itself proves no DDL was attempted: a migration would produce a different error.
2. **Post-run state assertion** over the writable test DSN: `schema_migrations_audit` `MAX(version)` unchanged, no new tables in `information_schema` (catches committed DDL).
3. **Sqlite side:** extend `TestVerifyDSNSchemaMismatch` to assert the DB file is byte-identical before/after (`hashFile` pattern already exists at auditexport/main_test.go:373-391; `TestRun_ExportModeROSucceeds` proves `mode=ro` write-failure precedent).

The criterion *does* have a gate in the named list; the gate as specified is just not executable as-is.

## G4 — A4's literal claim has no concrete testable gate

"no postgres `--dsn` exists today (proposed surface)" is a static source-state fact; `TestClassifyDSN` proves the classifier, not the historical absence. Per your instruction to flag criteria lacking a concrete gate: **A4 is that criterion**. The honest mapping is: A4's gate = the §1 C6 grep evidence (static inspection at implementation time, re-verify before wiring) + `TestClassifyDSN` for the new capability. Either annotate §7 that way or add a static source-scan test (brittle; not recommended).

## G5 — empty-store verify has no named test

FM-8's `no events to verify` exit-0 (main.go:263-265) and the `--checkpoint` empty-chain GenesisHash path (verifyAnchored main.go:149-152) are new DSN-read behavior (empty store → `ReadChain` returns 0 events, truncated=false). Only `TestAggEmpty` exists. Add `TestVerifyDSNEmptyStore` (unanchored: exit 0, stdout exactly `no events to verify`; optionally anchored: `chain verified: 0 event(s), head=, checkpoint seq=N`).

## G6 — minor: `TestAggEmpty` assertion omits the stderr summary line

REQ-4 criterion 6 requires "stderr carries the summary line with zero counts"; §7's assertion says only "empty stdout, exit 0". Add the stderr assertion to the named test.

## What is genuinely well-gated (checked, not just asserted)

- **A1** — exact-golden stdout is proven feasible (`TestRun_Golden_HappyUnanchored`, checkpoint_test.go:485, does exact-string comparison); flipped-hash via raw `UPDATE` breaks the chain at row i *and* row i+1 (`prev_hash` untouched, per REQ-1 c2 wording) → `chain BROKEN` guaranteed; postgres variant correctly inherits the `SSO_TEST_POSTGRES_DSN` skip convention (postgres_test.go:13-19).
- **A3** — constructible: `NewEd25519CheckpointSigner` (chainer.go:255) + existing checkpoint/URL/anchor test precedents; "REQ-1 c1-3,5 verbatim on postgres" is one table test.
- **A5** — fully testable: `WithClock` + `RecordTokenIssued` (recorder_events.go:19-24, one row per call) gives "2 clients × 3 hour buckets, sum==K==call count" without sleeping; determinism byte-compare is meaningful for sorted TSV (catches Go map-iteration nondeterminism); misuses return 2 in-process.
- **T-9** — actually strong: the existing auditverify suite exercises `readFromURL` byte-for-byte (`PagesAndReverses`, `LimitStopsPagination`, `ProbeDetectsTruncation`, `Checkpoint_URLHonestChain`/`URLForgedChain`, `Anchor_URLWindow`, `Checkpoint_LimitTruncationURL`), so the verbatim `url_source.go` move is genuinely guarded; banner tests are substring-based (`Contains`), so the REQ-6 banner change does **not** break "suites pass unmodified". One qualification: "sqlite export bundle bytes unchanged" overstates the existing tests — they assert structure/`"anchor"`-key absence/self-verify/EventCount, not golden bytes, and the bundle contains `GeneratedAt: time.Now()` (auditexport.go:137) so byte-golden is impossible; say "structurally identical modulo GeneratedAt".
- **REQ-3** — `BuildExportBundle` self-verify fails closed (auditexport.go:142) and the write happens after build+anchor enforcement in `run()` (main.go:169-200), so "no bundle file left behind" is assertable, with the existing `TestRun_ExportAnchorHeadMismatchExitsOne` precedent.
- **REQ-6** — `TestVerifyDSNMisuse` is sound: `checkMisuse` returns 2 in-process (main.go:203-225), matching the `--notary-key` pattern.
- **§2's fan-out correction** — independently confirmed: `maxSubdirsPerDir = 16` (directory_fanout_test.go:35) and `cmd/sso-ctl` has exactly 16 subdirs today; the "fold into existing packages" correction is the right call.

## Bottom line

| Criterion | Gate status |
|---|---|
| A1 | ✓ proved by named tests |
| A2 | ✗ named test would fail as specified — fix the iff predicate for truncated stores (G1) |
| A3 | ✓ proved |
| A4 | ✗ **no testable gate for the literal claim** — annotate as static-evidence + TestClassifyDSN (G4) |
| A5 | ✓ proved; add stderr-summary assertion to TestAggEmpty (G6) |
| T-9 | ✓ proved, with "modulo GeneratedAt" qualification |
| REQ-1 c5 (sqlite truncation) | ✗ **no named test** (G2) |
| FM-8 empty store (verify) | ✗ **no named test** (G5) |
| REQ-5 never-migrate | △ gate exists but is not executable as written — pin read-only-transaction DSN + post-run schema-state assertion (G3) |

Three concrete edits to §7 close everything: fix the A2 predicate, add `TestVerifyDSNTruncation` + `TestVerifyDSNEmptyStore` to the table, and replace "read-only role or DDL-free trace" with the pinned zero-DDL mechanism.
