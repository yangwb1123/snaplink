Map written to `docs/architect-analysis/auto/runs/add-boundary-anchored-segment-verification-ancho-d746c8c5/artifacts/task-1-implement-keep-conflict-map.md`. Verified against the actual dirty tree: `auditverify/main.go` 453 lines (checkpoint wiring at 126/160/179/200), untracked `checkpoint_test.go` 641 lines with `runVerify` at 133, `auditexport/main.go` 442 lines with the `--anchor` signed-checkpoint flag + `ExportBundle.Anchor`, kernel clean (chainer 500, platform/audit 16 files, cmd/sso-ctl 16 subdirs). Nothing of the design (`--anchor-hash`, `segment.go`) exists yet — zero collisions, but one arithmetic gap.

## Keep (reuse the leftovers)

| Asset | Serves |
|---|---|
| `checkMisuse` return-2 pattern (main.go:160) — `Fprintf + usage() + return 2`, in-process testable | New misuse rules must copy it; `runVerify` can't hit `usageErr`'s `os.Exit` |
| `Run` pipeline (200): checkMisuse → `loadCheckpointIfRequested` (anchor loads before events) → `loadEvents` → `cp != nil` branch → legacy tail | Anchor branch slots after `cp != nil`, **before** the empty early-return (anchored-empty must be F6 exit 1, not legacy exit 0) |
| `verifyAnchored` (126) checkpoint branch + truncation fail-fast | F13 untouched; 23 checkpoint tests pin its strings — no rename, no merge |
| `truncated` plumbing through `readFromFile`/`readFromURL`/`loadEvents` | Both honest-reporting rows consume existing plumbing — zero loader changes |
| `reverseEvents` (436), genesis heuristic (321) | `normalizeSegmentOrder` cases 1–2 reuse both |
| Harness: `runVerify`, `chainedEvents`, `writeEventsFile`, `urlServer`, `captureStdout/Stderr` | All of AC-1..AC-10; only `midChainWindow` + a newest-first writer are new |
| auditexport worktree state (`--anchor`, `ExportBundle.Anchor`, dispatch refactor, +869 test lines) | Complete tested half of the same failed stage — **do not revert, do not re-implement**; design's "zero auditexport changes" covers its own plan, and §7.2 depends only on untouched `boundary_prev_hash` |

## Conflicts (reconcile, don't clobber)

- **C1 — the real gap**: design says checkMisuse "+6 lines" and never mentions `flag.Visit`. `checkMisuse(o verifyOptions)` cannot distinguish `--anchor-hash ""` from absent; the rule pattern costs 5 lines each. Resolution: `anchorHashSet` field + `fs.Visit` after `fs.Parse` (+4). Realistic delta +25, not +22.
- **C2**: the R4 comment in `Run` ("byte-identical when no checkpoint flag is present") becomes false when the truncated-unanchored tail changes — amend in the same edit.
- **C3**: `verifyAnchored` vs `verifyAnchoredSegment` adjacency — add alongside, never rename the checkpoint one.
- **C4**: `auditexport --anchor` (notary checkpoint, head) vs `--anchor-hash` (boundary PrevHash, start) — no code conflict, distinct binaries; document the distinction in the package doc. They compose, they don't collide.
- **C5**: existing pins stay green (`TestRun_VerifyHappyPath` `chain verified`; checkpoint golden/truncation tests). No test pins the false-tip truncated behavior — AC-7 breaks nothing.
- **C6**: `Run`'s `errorf` os.Exit load-error path stays legacy; don't "unify" it in this change.

## Adds

`segment.go` (~70 lines: `verifyAnchoredSegment` + `normalizeSegmentOrder`), `--anchor-hash` + Visit plumbing, two checkMisuse rules (empty → 2; with `--checkpoint` → 2), Run anchor branch + truncated tail, package doc example, `segment_test.go` (AC-1..AC-10, `TestRun_*` names free of collisions).

## Budget arithmetic — holds, with one correction

Itemized: +2 doc, +2 options, +4 parseFlags (1 flag + 3 Visit), +10 checkMisuse, +3 Run branch, +4 truncated tail = **+25 → 478**. Design claimed ~475 with +6 rules and no Visit — optimistic by ~3 lines, but the conclusion survives: 478 ≤ 500 gate (`maintainability_budget_test.go:87` fails only `> 500`), 22 lines headroom. Function budgets: Run 34→41, checkMisuse 19→29, parseFlags 27→31, all ≤ 50; complexity ≤ 6 ≤ 15; segment.go ~70 ≤ 500; package 2 non-test files ≤ 10; 16 subdirs unchanged; chainer/audit 16-file ceiling untouched; auditexport/main.go 442 (kept) ≤ 500.

One gate note carried forward: the maintainability/architecture run still fails on pre-existing fan-out drift from untracked parallel-campaign dirs (root/runs/docs) — unrelated, report separately per AGENTS.md §7.
