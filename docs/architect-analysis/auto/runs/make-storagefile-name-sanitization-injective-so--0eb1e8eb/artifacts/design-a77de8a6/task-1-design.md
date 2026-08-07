Design written to `docs/architect-analysis/auto/interfaces-snapshot-storagefile-sanitize-injective-design.md`. No code changed (design-only, per repo convention).

## Evidence verification (all claims re-checked against repo)

The requirements spec's citations are substantially accurate. Verified ✅: non-injective `sanitize` (`file.go:142`), Put's `os.Rename` silent overwrite (50-86), Get/Delete routing through sanitize, `TestSanitisesNames` at 68-88 with no collision case, Storage contract `pipeline.go:15-18`, `buildAccessPayload` TenantID literal, `spi.go:171`, `server_login_client.go:329`, `types.go:47`, T-8(a) at `implementation-gate.md:11`, snapshotcmd/retention original-name addressing, loader `?name=` basename derivation, and all A4 symbols (`NewMemoryClientStore`, `NewMemoryProvider`, `encryptionnone`, `ModeMerge`). Two immaterial line-nits: Delete is 124-137 (not 107-120), `ed25519_types.go` Roles field at 57 (comment at 53).

## Design highlights

**API changes** — zero exported: `Storage` interface, `New`, `Put/Get/List/Delete` signatures unchanged; all in-repo callers (snapshotcmd, retention, server default store) need no edits since they address by original name. Contract deltas: `sanitize` → injective `encodeName` (`%`→`%25` first, then `%XX`/byte — a prefix code, hence provably injective); `List` decodes back to original names.

**New elements beyond the spec**: D1-a encoded-length guard (250 bytes max → clear error instead of ENAMETOOLONG from 3× expansion; clean names never expand, so nothing previously accepted is rejected).

**Compatibility** — clean names (`snap_*`) are fixed points: byte-identical on disk, existing 7 tests pass unmodified. Legacy collapsed files are ambiguous by construction → no migration possible, operator re-export only. Mixed-version fleets are safe for clean-name workloads; unsafe names need coordinated cutover.

**Failure modes** — table of 7 (F1-F7): pre-existing unchanged (empty-name, concurrency, partial-write), plus deterministic handling of too-long names (F2), legacy misses surfaced as `ErrSnapshotNotFound` (F4), and foreign bare-`%` files best-effort (F5). The silent-overwrite security failure is eliminated for distinct names.

**Migration** — 5 steps: inventory via `snapshotcmd list`, re-export any unsafe names (old binary), deploy two files, post-deploy round-trip verification, code-revert rollback (no state migration).

**Acceptance mapping** — A1→`TestEncodeInjective_Coexist`, A2→`_Table`, A3→`_ListRoundTrip`, A4→`_RestoreIsolation` (restore-side T-8(a) precondition), plus `_TooLong` for D1-a and an unmodified-regression column; gate commands per AGENTS.md §2 listed in §8.

Three implementation-time re-check risks are flagged at the end (Restore call shape, List single-pass decode, case-insensitive hex decode).
