All defects fixed and verified. Summary of the amendments to `docs/architect-analysis/auto/interfaces-snapshot-storagefile-sanitize-injective-design.md`:

## The four cross-reviewer defects

1. **§3 rollback row** — now states the correct asymmetry: new-written `%` files are **List-visible but unaddressable under the old binary in any spelling** (old `sanitize` maps `%`→`_` and `/`→`_`, so `Get("a%2Fb")`→`a_2F_b.snap` and `Get("a/b")`→`a_b.snap` both miss; `Delete` same mapping — file is inert, never clobbered). Contrasted with the old-written legacy class (F4: `a_b.snap` *is* addressable by new binaries via `a_b`) and the operational consequence (re-home/re-export before reverting, or filesystem-level cleanup; clean-name default path rolls back trivially).
2. **§5 step 5** — corrected to: new binaries read new-written files via their **original** name (`Get("a/b")` encodes once); the "encoded spelling" is **not** an address under either binary (`Get("a%2Fb")` double-encodes and misses under new code). Explicitly: they are *not* the old legacy class.
3. **§2.4 caller enumeration** — added `interfaces/grpcserver/grpcadmin/admin_snapshots.go` (verified: `List` at :92 sorts names then `Get(name)` per page-window item at :112 — round-trips decoded names exactly like `snapshotcmd list`). Also added a matching §0 evidence row and §7 Do-not-modify entry for consistency.
4. **§8 E2E note** — now says `test/` snapshot flows run on `storageinline` (verified: `test/admin_grpc_base_test.go:16` imports storageinline; zero storagefile imports in `test/`), so storagefile coverage is package-test-only (A1–A4/F1–F5 in `file_test.go`).

## Added items

5. **F3 mixed-version sentence** (§3 Mixed-version row): an old-binary retention loop over new-written `snap_`-prefixed unsafe files (e.g. `snap_a%2Fb.snap`) **reports them as pruned while the files survive** — idempotent `Delete` miss returns nil and the name is appended to the pruned list; false positive, no data loss. Verified against `retention.go:36-68` (`snap_` prefix filter + idempotent delete).
6. **Implementation-time doc actions**, flagged in three places: §5 step 3 (the only doc-contract delta is one new `docs/error-codes.md` entry), §7 Modify list (`error-codes.md` moved out of "Do not modify", with the SDK Go error-section precedent), and §8 check (4) — the exact string `"snapshot/storage/file: name too long after encoding"` is pinned by `TestEncodeInjective_TooLong` so the entry cannot drift.

## Cross-section consistency pass (2.1/3/4/5/6/7/8)

- **239 boundary** consistent everywhere: §2.1 tempfile math (`≤239`, target `≤244`), §3 Name-length row, §4 F2, §6 `TestEncodeInjective_TooLong` (239 OK / 240 error), §7 `maxEncodedName=239`, §8 audit note. The only remaining "250" mentions are the descriptive 240–250 ENAMETOOLONG range (§2.1) and the historical draft-correction note (§8) — both intentional.
- **Guard error string** byte-identical in §2.1, §6, §8.
- **grpcadmin** consistent across §0/§2.4/§7; no stale "addressable via encoded spelling by old binaries", "by new binaries only", or "if wired into E2E" phrasing remains anywhere in the doc.

Design-only change; no code touched. No gates run (no `.go` edits).
