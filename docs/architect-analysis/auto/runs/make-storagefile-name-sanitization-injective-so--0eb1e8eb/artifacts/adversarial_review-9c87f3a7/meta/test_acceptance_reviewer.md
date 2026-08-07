Audit complete. All findings resolved in the design doc; no code changed (design-only, per repo convention).

## Audit result

**Verdict: PASS with 3 blocking findings (B1–B3) and 3 minor ones (B4–B6) — all resolved.** The §4 failure modes now have a 1:1 committed-test mapping.

### Blocking findings

**B1 — F4 had no mapped test.** §3's claim that "A1 asserts the post-upgrade semantics" was wrong: `TestEncodeInjective_Coexist` only exercises fresh Puts; a legacy `a_b.snap` can no longer be produced by the new `Put`, so the post-upgrade path was untestable. Added `TestEncodeInjective_LegacyCollapsedNotFound` (seeds `a_b.snap` via `os.WriteFile`): original-name `Get` → `errors.Is(err, snapshot.ErrSnapshotNotFound)`, sanitized-spelling `Get("a_b")` readable, `List` == `["a_b"]`, and new `Put`/`Delete` never clobber the legacy file.

**B2 — F5 had no mapped test.** Added `TestEncodeInjective_ForeignBarePercent` pinning all three designed behaviors: bare-`%` file lists literally without error and `Get` misses (`ErrSnapshotNotFound`); `Put("a%zz")` writes `a%25zz.snap` while the foreign file's bytes stay byte-identical; `List` then shows `"a%zz"` twice (pinned duplicate semantics, benign for retention/snapshotcmd). Also pins the lowercase-hex consequence: foreign `a%2f.snap` decodes to `"a/b"`, `Get("a/b")` misses.

**B3 — the "249 vs 250" boundary was wrong on both counts.** The draft was self-inconsistent (§2.1 formula ⇒ 245/246; §6 test text ⇒ 249/250) and **both ignored the tempfile**. Verified against Go 1.26.5 sources: `os.CreateTemp` appends a decimal uint32 (up to **10 digits**) to `.tmp-<encoded>-*`, so worst-case temp name = `encoded + 16` ≤ NAME_MAX 255 (verified 255 on this FS) ⇒ **`maxEncodedName = 239`**. At 240–245 bytes the draft guard passed and `CreateTemp` still failed with ENAMETOOLONG — the very failure F2 promises to remove (and ~7% of draws are 10 digits, so it would fail intermittently). 239 also equals the old code's deterministic envelope, so "nothing previously accepted is rejected" holds precisely. `TestEncodeInjective_TooLong` now pins 239-OK/240-error with the exact error string, the 3×-expansion case (41×`é` → 246 encoded), Get/Delete surfacing the same guard error, and no partial state.

### Minor findings

- **B4 (F3)**: `TestEncodeInjective_RenameBackstop` — a directory pre-created at `x.snap` forces a portable, root-proof rename failure asserting the wrapped `"rename:"` backstop surface + no `.tmp-*` leftover (unreachable on standard FS once the guard is 239; this pins the contract).
- **B5 (F1)**: `TestEncodeInjective_DegenerateNames` pins the unchanged empty/`.`/`..` error strings.
- **B6 (hex-decode risk)**: escape-lookalike names (`a%2f`, `a%AB`, `a%ab`, `a%zz`, `a%2`, `a%`) added to `TestEncodeInjective_ListRoundTrip` with an exact-set assertion — pins the single-pass decode as a left inverse of canonical-uppercase encode.
- **B7 (verified non-issues)**: A4 feasibility re-verified (`restorer.go:39-50`, `snapshotter.go:463-476`, `aliases_memory.go:62`, `memory.go:45`, `none.go:14`); existing 7 tests remain compatible.

## Files

- `docs/architect-analysis/auto/runs/.../artifacts/adversarial_review-9c87f3a7/task-1-acceptance-audit.md` — full audit (new)
- `docs/architect-analysis/auto/interfaces-snapshot-storagefile-sanitize-injective-design.md` — amended §2.1 (guard), §3, §4 (F1–F7 committed-test column), §6 (5 new/rewritten rows + coverage map), §7 (`maxEncodedName=239`), §8 (risks re-verified and pinned)
- Run design stub — audit-resolution pointer appended for the design_gate stage
