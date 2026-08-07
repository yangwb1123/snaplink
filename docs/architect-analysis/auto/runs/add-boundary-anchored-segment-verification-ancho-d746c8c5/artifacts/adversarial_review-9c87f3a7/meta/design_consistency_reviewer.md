Verification complete. Here is the full report.

---

# Verification report: design evidence vs. HEAD (`d73b3d0e`)

## 1. Kernel budget claims — all CONFIRMED, constraints are real

| Claim | Verdict | Evidence |
|---|---|---|
| `platform/audit/chainer.go` at exactly 500 lines | **CONFIRMED** (HEAD == worktree, zero diff) | `wc -l` = 500 = `maxFileLines` in `maintainability_budget_test.go`; gate fails only at `>500`, so any added line fails `TestMaintainability_FileSizeBudget`. Exemption map is empty and capped at zero. Zero-kernel-change is mandatory, not optional. |
| `VerifyChainSegment` at 172-180 | **CONFIRMED, ±1 line** | Signature 172, body 173-174; doc comment 161-**171** (artifacts say 161-170). Semantics exactly as claimed: seeds `verifyChainFrom(events, expectedPrevHash)`; anchor bound cryptographically via `eventHash` covering `PrevHash`. |
| Index-0 break at 208 | **CONFIRMED** | `verifyChainFrom` 200-**217** (design.md correct; requirements.md's "200-215" is wrong). Chain-break check 205-208 (`if` at 205, error return 206-207, close 208); fires at index 0 for unanchored mid-chain segments. |
| `platform/audit` 16-file ceiling | **CONFIRMED** | Exactly 16 non-test `.go` files = frozen `dirFileCountExemptions["platform/audit"] = 16` (`directory_fanout_test.go`). Any new file → `TestArchitecture_DirectoryFileFanout` regression. |
| `cmd/sso-ctl` 16-subdir ceiling | **CONFIRMED for the committed Go gate** | Exactly 16 subdirs = `maxSubdirsPerDir = 16`. Any new subdir fails. **Drift**: `engineering.yaml`/Python mirror (`checks/directory_fanout.py`) use `max_subdirs: 15` and *already fail* on `cmd/sso-ctl`, `platform/`, `docs/`, `dist/` today — pre-existing config/gate disagreement, not part of `make ci`. |
| `segment.go` split keeps `main.go` under 500 | **CONFIRMED** | `auditverify` has 1 non-test file; +1 file = 2 ≤ 10. See §3 for the file-size caveat. |

## 2. Harness claims

| Claim | Verdict |
|---|---|
| `chainedEvents(t, n)` | **CONFIRMED in HEAD** — `cmd/sso-ctl/auditverify/main_test.go:174` (committed; worktree +10 lines of mechanical `_`-consumption edits only) |
| `captureStdout`/`captureStderr` | **CONFIRMED in HEAD** — `coverage_test.go:156` / `:195` (committed) |
| `runVerify(t, args...)` | **NOT in HEAD** — lives in `checkpoint_test.go:131-139`, which is **uncommitted worktree state** (see §3) |

## 3. CRITICAL: the "verified against HEAD" claim is false for main.go — the citations describe the dirty worktree

The worktree carries the **uncommitted output of the failed `wire-checkpoint-anchored-verification-into-audit-181192ed` implement stage** (its DECISIONS shows `implement — FAIL` at 18:16, no commit). `git status` shows ~20 dirty files including `auditverify/main.go` (+271 lines), `checkpoint_test.go` (new), `auditexport.go` (+Anchor field), plus unrelated files (`cmd/sso-server/build_stores.go`, `config/config_load.go`, `.pi/settings.json`, …).

| Location | HEAD (`d73b3d0e`) | Worktree (what the design cites) |
|---|---|---|
| `auditverify/main.go` size | **240 lines** | 453 lines |
| auto-reverse | `readFromFile` if at **126**, `reverseEvents` at **127** | if 322, call 323 (design says 321-323) |
| truncation | **129-130** | 325-327 (**exact**) |
| head print | **104** (`chain verified: … head=%s`); empty path 95-97 | 229; `return 0` at 230 (design says 230 — off by one; the print is at 229) |
| `Run` | **63**, no `--checkpoint`/`--notary-key` flags, no `checkMisuse`/`verifyAnchored`/`parseFlags`/`verifyOptions` | 200 (design "Run at 200" = worktree only) |
| `verifyAnchored` / `checkMisuse` | **do not exist** | 126 / 160 |
| `auditexport.go` `VerifyChainSegment` call | **159** | 164 (design cites 164; `BoundaryPrevHash` field at 104 correct in both) |
| relay claims (`Relay` drains `commerce.OutboxEvent`, no PrevHash/Hash, `store.go:74-93`; `auth.*` `[PROPOSED]` at `audit-contract-batch-snaplink.md:16`) | **CONFIRMED** — `relay.go:167/202/212/227/266`, `managed_relay.go` is the lifecycle wrapper holding `Relay *Relay` | identical |

**Consequences for implementation:**
- The direction's own citations (138-144 / 146-149 / 113) match **neither** HEAD nor the worktree — they were already stale. The design's "checkpoint wiring shifted the file" explanation misattributes uncommitted worktree state as shipped.
- Design decisions F8/decision-1 (`--anchor-hash` + `--checkpoint` mutual exclusion, `--notary-key` misuse exit 2) and §3.4 ("extend `checkMisuse`", "route in `Run` to `verifyAnchoredSegment`") assume the checkpoint CLI exists. It exists **only in the worktree**. The kernel dependency (`VerifyChainAgainstCheckpoint` at `chainer.go:463-469`, `SignedCheckpoint` at 233) **is** committed (HEAD), so the design is executable in the current worktree but breaks entirely on a clean checkout/reset.
- `make ci`'s `vet` gate also runs the dirty tree; the failed implement stage already reported pre-existing gate failures, and the wire-checkpoint review noted `go test -run 'TestMaintainability_|TestArchitecture_' .` fails on the current worktree (environment-dependent, reported separately per AGENTS.md §7).

## 4. Requirements artifact reconciliation (R1-R8 / AC-1..AC-10 vs. pipeline.yaml)

**Line count: the file is 21 lines** (`wc -l`, confirmed with `cat -n`) — not the claimed 132 (inside the artifact's own text), and not 23 (as in your brief; off by two either way). It is byte-identical to the evidence summary and is NOT a spec. `DECISIONS.md` shows the requirements stage passed with exactly that file.

**R1-R8**: enumerated nowhere in either artifact. The requirements.md bullet mentions R1-R8 semantics (flag string-equality vs `events[0].PrevHash`, both sources; order normalization never dual-order; byte-identical legacy path as "R4"; empty-value/`--checkpoint` misuse exit 2; empty-list exit 1; honest reporting; `segment.go` split). design.md §3 reconstructs all of these consistently — but both artifacts reference "R4" without ever defining the R1-R8 set. The only authoritative source is the direction in `pipeline.yaml`; the reconstruction is faithful to it.

**AC-1..AC-10 vs. pipeline.yaml's five T-2 checks — the two artifacts DISAGREE:**

| T-2 check (pipeline.yaml) | design.md | requirements.md |
|---|---|---|
| #1 anchor → exit 0 | AC-1 ✓ | AC-1 ✓ |
| #2 no anchor → exit 1 | AC-2 ✓ | AC-2 ✓ |
| #3 mismatch → exit 1 | AC-3 ✓ | AC-3 ✓ |
| #4 truncated → `prefix verified`/checkpoint-head, never false tip | **AC-7** ✓ | **AC-5** (but calls AC-5 "URL-window" in the same sentence — double-counted) |
| #5 relay-shaped batch | AC-6 ✓ (batch-shape only; literal `ManagedRelay` integration documented as impossible) | AC-6 ✓ |

**design.md's AC-1/2/3/6/7 mapping is the correct one; requirements.md's "AC-1/2/3/5/6 preserved 1:1" is wrong.** AC-4/5/8/9/10 are the design's legitimate additions (order normalization, URL window, misuse, empty-set, regression); AC-11 pins the build/vet/maintainability gates. All five T-2 checks are covered by design.md.

## 5. Complete drift ledger

1. `requirements.md` says "132 lines" — file is 21 lines. **Material.**
2. `requirements.md` `verifyChainFrom` "200-215" — actual 200-217 (design.md correct).
3. `requirements.md` AC↔T-2 mapping "AC-1/2/3/5/6" — wrong; should be AC-1/2/3/6/7. **Artifact disagreement.**
4. Both artifacts: `VerifyChainSegment` doc "161-170" — actual 161-171.
5. Both artifacts: "main.go 453 lines / 321-323 / 325-327 / 230" — **worktree only**; HEAD is 240 lines with the semantics at 126-127 / 129-130 / 104. The "checked against HEAD" claim is false for every main.go citation. **Material.**
6. design.md: head print "at 230" — print is at 229.
7. design.md: "`auditexport.go:164`" — HEAD 159 (worktree 164, itself uncommitted).
8. design.md: "Run at 200, `verifyAnchored` at 126, `checkMisuse`" — symbols absent from HEAD.
9. design.md: harness reuse includes "`runVerify` (checkpoint_test.go)" — `checkpoint_test.go` is uncommitted.
10. `engineering.yaml` `max_subdirs: 15` vs committed Go gate `maxSubdirsPerDir: 16` — pre-existing; Python mirror already fails on `cmd/sso-ctl` today (not in `make ci`).
11. Direction's original citations (main.go:138-144/146-149/113) match neither HEAD nor worktree — stale at the source.
12. Requirements.md says "no new packages / no chainer-relay-auditexport changes" — consistent, and consistent with the real ceilings.

**Bottom line**: the design's *constraints and semantics* are sound and all five T-2 checks are covered, but its evidence base is the uncommitted worktree, not HEAD; the two design artifacts agree with each other except the AC mapping; the requirements artifact is a 21-line summary, not a 132-line spec; and every kernel/budget claim (500-line chainer, 16-file audit, 16-subdir sso-ctl, no-new-package) is real against the committed gates. The implement stage must be warned: it depends on the dirty worktree's checkpoint wiring — do not reset, and preserve the unrelated dirty files.
