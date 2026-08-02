Design doc complete. `docs/auto/interfaces-snapshot-diff-design.md` (543 lines, same directory as the spec, house naming convention `interfaces-snapshot-diff-design.md`). Pure documentation — no Go code touched; the worktree's pre-existing unrelated modifications were left untouched.

**Structure** — house style matching `interfaces-snapshot-restore-safety-design.md`: a header with "Verified corrections to the spec's assumptions" plus three `##` decisions, each covering API surface, storage model, failure modes, and what could break the design, followed by contract updates, verification plan, and a separate pre-existing-failures report.

**Key findings from re-verifying every evidence claim against code:**

1. **The spec cites the wrong gate.** `engineering.yaml:43` is the *complexity* ignore (snapshot/ is in it — true), but the committed directory fan-out gate (`directory_fanout_test.go`) does **not** ignore `interfaces/snapshot` — it has a frozen ceiling of 14 non-test files, and the directory is at **16, already red on the current commit**. `diff.go` cannot land without a 3-merge consolidation (verified candidates: codec+codec_json, safety→stage, roles+assignments) to land at exactly 14.
2. **grpcadmin is at the 10-file cap** — the Compare handler's new file requires a one-file merge (admin_keys 156 + admin_tokens 192 = 348), and `admin_snapshots.go` (581 lines, already red) must not grow.
3. **Four pre-existing red gates** reported separately (fan-out, filesize, function-length ×2, cyclo ×2) — all in the snapshot/restore area; the `restoreTracked` extraction required by D3 serves two of them.
4. **Dry-run semantics gap confirmed**: roles/menus dry-run counts are optimistic today (no existence probe); the design makes the diff engine the single source of truth via a mode-aware count projection, with documented per-category coverage limits (no MenuLister → fallback). All five existing dry-run tests verified green fixture-by-fixture.
5. **Digest correctness is load-bearing**: `SnapshotDigest` must exclude envelope metadata and sort by identity key, or cross-node drift detection produces false alarms.
6. **ADR-0008 additive rules, interfaces→platform import legality, and `SourceNodeID` having zero consumers** all confirmed as the spec claims.
