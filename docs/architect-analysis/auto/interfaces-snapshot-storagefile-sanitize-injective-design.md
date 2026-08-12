# Design: interfaces/snapshot/storagefile — 名称净化单射化（percent-encoding）

> Companion to `interfaces-snapshot-storagefile-sanitize-injective-spec.md`. Design only —
> no code was modified. Every evidence claim was re-verified against the executable code
> at the current commit before writing (see §0). One decision, one acceptance set, no
> exported API change; compatibility and migration are the risk surface and are treated
> as first-class sections.

## 0. Evidence re-verification (spec claims vs. repo, current commit)

| Spec citation | Verdict | Note |
|---|---|---|
| `file.go:130-153` `sanitize` 非单射 | ✅ | Func at 142 (doc 139-141). `"a/b"`→`a_b`, `"a_b"`→`a_b`: collapse confirmed by reading the rune loop (148-153) |
| `file.go:50-86` Put 经 `os.Rename` 静默覆盖; Get 88-105; Delete 同经 sanitize | ✅ | Put 50-86, Get 88-105 exact. Delete is 124-137 (spec's "107-120" range is the tail of List) — substance correct: `Delete` calls `sanitize` at 126 |
| `file_test.go:68-88` `TestSanitisesNames` 无碰撞用例 | ✅ | Exact; test only asserts substitution + original-name Get |
| `pipeline.go:15-18` Storage 契约（overwrite allowed; MAY reject unsafe names） | ✅ | Interface 15-28; clause at 16-18 |
| `issue_payload.go:26` `buildAccessPayload`（func 27, `TenantID: subject.TenantID` 无条件字面量） | ✅ | Literal at line 46; roles projected from `Subject.Roles` (`ed25519_types.go:57` field; spec's ":53" is the comment block — near-miss) |
| `shared/core/spi.go:171` `Subject.TenantID` | ✅ | Exact line |
| `server_login_client.go:329` / `shared/core/types.go:47` client→subject tenant stamp | ✅ | Exact lines |
| `restorer_permissions.go:37-74` 恢复重播种 clients/roles | ✅ | Region contains prune/re-seed (`pruneRoles`, `indexRolesByClient`, `pruneClientRoles`) |
| `implementation-gate.md:11` T-8(a) claims gate | ✅ | `{iss/aud/scope/client_id/tenant_id/roles}` |
| `snapshotcmd` list/inspect/verify 以原名寻址 | ✅ | `main.go:100-110` List→Get by returned name; `runInspect`/verify `Get(*id)` |
| gRPC admin snapshot `List` 以原名寻址 | ✅ | `interfaces/grpcserver/grpcadmin/admin_snapshots.go:92` (`List`), `Get(name)` per page-window item at 112 — round-trips decoded names exactly like `snapshotcmd list` |
| `retention.go:42-68` List→Get/Delete; `snap_` filter | ✅ | `PruneOldest` at 43; `retentionVictims` filters `snap_` prefix, sorts, `pruneSnapshotVictims` Get/Delete |
| `loader.go:60-68` 无 `?name=` 时以 URI path basename 派生名 | ✅ | `fromFile` at 60; `filepath.Base(u.Path)` at 68; `?name=` documented at line 10 |
| `build_stores_helpers.go:135-144` 服务器默认 file store | ✅ | `storagefile.New` at 144 (func `buildSnapshotStorage` 135) |
| `snapshot_v2_test.go:53-57` 手构 Snapshot 先例 | ✅ | Literal `&snapshot.Snapshot{...}` at 56-60 |
| A4 依赖符号：`defaultimpl.NewMemoryClientStore`, `permissions.NewMemoryProvider` (`domains/permissions/memory.go:45`), `encryptionnone`, `RestoreOptions{Mode: ModeMerge}` | ✅ | All exist; `Restorer` fields are all optional (`restorer.go:39-50`), so nil backends skip per contract |

No blocking discrepancy found. One line-range nit (Delete 107-120 vs 124-137) and one
field-line nit (`ed25519_types.go:53` vs 57) — both immaterial to the design.

## 1. Problem restated (what the design must fix)

`sanitize` maps every non-`[A-Za-z0-9_.-]` byte to `_`, which is not injective:
`Put("a/b", v1)` then `Put("a_b", v2)` both address `a_b.snap`; the second `os.Rename`
silently replaces the first. Snapshots carry `Resources.Clients[].TenantID` and
`Resources.Roles`; after restore these become the `tenant_id`/`roles` claims minted by
`buildAccessPayload` (T-8(a), `implementation-gate.md:11`). A silently overwritten
snapshot therefore feeds wrong tenant bindings/roles into a restore node's trust path —
a silent cross-read, not an operator-visible failure. The Storage contract permits
overwrites (`pipeline.go:16-18`), but this is name-collision ambiguity, not an intended
overwrite; the storage layer must eliminate the ambiguity.

## 2. Decision D1 — injective byte-level percent-encoding, `List` decodes originals

### 2.1 Encoding (`sanitize` → `encodeName`)

Single pass over raw bytes (UTF-8 transparent — multibyte runes encode per byte):

- `[A-Za-z0-9_.-]` → verbatim (fixed point).
- `%` → `%25` (escape char escaped **first**, so the output is a prefix code: a `%` in
  output can only start an escape; no ambiguity in decode ⇒ injective).
- Every other byte → `%XX`, uppercase hex (`é` → `%C3%A9`, space → `%20`, `/` → `%2F`).

Guards preserved byte-for-byte from today: empty name → error; result `.`/`..` → error.
Existing error strings stay identical (`"snapshot/storage/file: empty name"`,
`"snapshot/storage/file: sanitised name is invalid (%q)"`) — no new `Err*` sentinels.

New guard (D1-a): `maxEncodedName = 239` bytes; after encoding, if
`len(encoded) > maxEncodedName`, return the wrapped error
`"snapshot/storage/file: name too long after encoding"`. The bound is the
**tempfile-constrained** NAME_MAX math, not the rename target's: `Put` creates
`.tmp-<encoded>-*` via `os.CreateTemp`, and Go 1.26 appends a decimal uint32 (up to 10
digits) there, so the worst-case temp filename is `5 + len(encoded) + 1 + 10` bytes and
must stay ≤ 255 (NAME_MAX on ext4/xfs/btrfs; verified 255 on this FS) ⇒
`len(encoded) ≤ 239`. The final target name is then ≤ `239 + 5 = 244` (11 bytes of
headroom under NAME_MAX). Rationale: encoding expands a name up to 3×, so a name the old
lossy sanitize accepted (e.g. 100 non-ASCII bytes → 100 `_` chars) can become 300 bytes
and fail deep inside `os.CreateTemp`/`os.Rename` with a confusing ENAMETOOLONG. The
pre-check turns it into a deterministic, addressable error **before any file op**. Clean
names never expand, and the old code's deterministic acceptance envelope was already
`len ≤ 239` (identical tempfile math), so no previously-deterministically-accepted name
is rejected; 240–250-byte names were intermittently/always ENAMETOOLONG at
`CreateTemp` and now fail fast with a clear error. The rename error remains the backstop
for exotic filesystems with smaller NAME_MAX — no behavioral dependence on the guard.

### 2.2 Decoding (`decodeName`, used by `List` only)

- `%` followed by exactly two hex digits (case-insensitive) → that byte.
- Bare `%` (not followed by two hex) → kept literally (defensive: files not written by
  this implementation, e.g. operator-created `a%zz.snap`, remain listable and do not
  break the loop).
- `List` applies `decodeName` after `TrimSuffix(n, fileExt)`; Put/Get/Delete never
  decode (they encode, exactly as they sanitize today).

### 2.3 Invariants (must hold, asserted in tests)

1. **Injective encode**: `encodeName(a) == encodeName(b) ⇒ a == b` (prefix-code
   property). Collision table from the old scheme (`a/b` vs `a_b`, `a:b` vs `a_b`,
   `a b` vs `a_b`, `a%b` vs `a_b`, `a//b` vs `a__b`, `ø` vs `ñ`) all separate.
2. **Decode round-trip**: `decodeName(encodeName(n)) == n` for all `n`.
3. **List→Get round-trip**: for every file written by `Put`, `Get(name)` hits the same
   file that `List` reported under `name` (no double encoding: List returns originals,
   Get encodes once).
4. **Fixed points**: `encodeName(n) == n` iff `n` contains only allowlist bytes —
   production default names (`snap_*` from the exporter, retention's `snap_` filter)
   map to identical on-disk filenames ⇒ zero byte-level change for the default path.
5. **No path traversal**: encoded names contain no `/` (encoded `%2F`) and cannot be
   `.`/`..`, so `filepath.Join(baseDir, encoded+ext)` stays inside baseDir — the
   traversal posture is strictly better than today (today `..` inside a name also gets
   flattened, but the invariant was implicit; now it is structural).

### 2.4 API changes (complete enumeration)

Exported surface: **zero changes**.
- `Storage` interface (`pipeline.go`), `file.New`, `file.Storage{BaseDir,Put,Get,List,Delete}`
  signatures and error types unchanged; `snapshot.Storage` compile-time assertion intact.

Observable contract deltas (both internal to `interfaces/snapshot/storagefile`):
- `List` return values: sanitized filenames → decoded original names. Identical for all
  clean names; differs only for names with non-allowlist bytes.
- `Put/Get/Delete` filename mapping: `sanitize(name)` → `encodeName(name)`. Identical
  for clean names.

Callers (`snapshotcmd` list/inspect/verify, `retention.go`, server default store, and
the gRPC admin snapshot service `interfaces/grpcserver/grpcadmin/admin_snapshots.go` —
its `List` sorts names, then calls `Get(name)` per item in the page window, so it
round-trips decoded names exactly like `snapshotcmd list`) need **no code change**: they
already address storage by original names and consume `List` output verbatim. This is
the load-bearing compatibility fact — verified in §0.

## 3. Compatibility constraints

| Constraint | Behavior | Verification |
|---|---|---|
| Clean names (`snap_*`, UUID-ish IDs) | Fixed points; on-disk bytes unchanged; List output unchanged | Invariant 4; existing 7 tests must pass unmodified |
| All in-repo callers | Original-name addressing; no change needed | §2.4; `go build` + snapshot package tests |
| Legacy files from old code (name had non-allowlist bytes) | Ambiguous by construction: `a_b.snap` cannot be attributed to input `a/b` vs `a_b`. Post-upgrade `Get("a/b")` → `ErrSnapshotNotFound`; the file remains readable via the sanitized name `Get("a_b")`. **No automated migration possible** — operator re-exports any snapshot whose original name contained non-allowlist bytes | Documented in upgrade notes; `TestEncodeInjective_LegacyCollapsedNotFound` (F4) asserts the post-upgrade semantics on a seeded legacy file |
| Mixed-version fleet | Safe for clean-name workloads (both sides see identical filenames). Unsafe names break cross-version: old `List` returns `a%2Fb`, old `Get` sanitizes `%`→`_` and misses. Edge: an old-binary retention loop over a directory containing new-written `snap_`-prefixed unsafe files (e.g. `snap_a%2Fb.snap`) **reports them as pruned while the files survive** — the idempotent `Delete` miss returns nil, so the name is appended to the pruned list — a false-positive report with no data loss. Deployment must be a coordinated cutover for unsafe-name workloads (or, per §4, eliminate them first) | — |
| Rollback (revert the two files) | Code-level revert; no state migration. Files written by new code containing `%` are **List-visible but unaddressable under the old binary in any spelling**: old `sanitize` maps every non-allowlist byte to `_`, so `Get("a%2Fb")`→`a_2F_b.snap` and `Get("a/b")`→`a_b.snap` both miss, and `Delete` has the same mapping — the file is inert (not Get-able, not Delete-able by name, never clobbered). This is the asymmetry with the old-written legacy class (F4: old `a_b.snap` stays addressable by new binaries via `a_b`): a new-written `a%2Fb.snap` has **no** fallback spelling under old binaries, so rollback is complete only if the operator re-homes/re-exports unsafe-name files created during the new-version window before reverting (or accepts filesystem-level cleanup). Clean names are byte-identical across versions, so the default production path (only `snap_*` clean names) rolls back trivially | `TestEncodeInjective_Coexist`/`_ForeignBarePercent` pin the encode/decode surface the old binaries cannot address |
| Name length | New D1-a guard rejects names whose **encoded** form exceeds 239 bytes with a clear error (tempfile-constrained bound, see §2.1). No clean name ≤ 239 bytes is affected; the old deterministic acceptance envelope was identical, so previously-deterministically-accepted names keep working | `TestEncodeInjective_TooLong` (F2); existing tests unaffected |

## 4. Failure modes

| # | Failure | Trigger | Detection | Mitigation | Committed test |
|---|---|---|---|---|---|
| F1 | `Put`/`Get`/`Delete` error for empty / `.` / `..` names | Caller passes degenerate name | Existing error strings, unchanged | Caller contract: same as today | `TestEncodeInjective_DegenerateNames` (new) |
| F2 | Name-too-long error (D1-a) | Name whose encoded form > 239 bytes (`maxEncodedName`) | Deterministic error before any file op | Caller shortens name; no partial state (guard runs before CreateTemp) | `TestEncodeInjective_TooLong` (new) |
| F3 | ENAMETOOLONG on exotic FS | NAME_MAX < 255 | Wrapped rename error (backstop) | Same as today's error surface; D1-a covers common FS | `TestEncodeInjective_RenameBackstop` (new; backstop surface, see §6) |
| F4 | `Get` misses after upgrade on legacy unsafe names | Old collapsed file, original-name lookup | `ErrSnapshotNotFound` | Operator re-export (§5 step 2); explicit in upgrade notes. Every in-repo caller degrades gracefully — per-row flag (`snapshotcmd list`), named error (`inspect`/`verify`), retention unaffected (legacy files never start with `snap_` unless they did pre-upgrade) — verified in §4.1 | `TestEncodeInjective_LegacyCollapsedNotFound` (new) |
| F5 | Foreign file with bare `%` (e.g. `a%zz.snap`) | External tool wrote into baseDir | `List` shows literal `a%zz`; `Get("a%zz")` → `ErrSnapshotNotFound` | Documented best-effort: decode is lossless for everything our `Put` writes; foreign malformed names are out of contract. Not silently overwritten, not crash. Caller degradation verified in §4.1: per-row flag in `snapshotcmd list`; page-level `NotFound` in gRPC `List` (pre-existing class); phantom prune-report in retention (pre-existing class) | `TestEncodeInjective_ForeignBarePercent` (new) |
| F6 | Concurrency: same-name concurrent Put | Two writers | None (last-rename-wins) | Intentional overwrite semantics preserved per contract — now only reachable for **identical** names | `TestPutAtomic` (existing, unmodified) |
| F7 | Partial write | Crash between CreateTemp and Rename | `.tmp-*` leftover | Unchanged existing mechanism (tempfile+rename); no new exposure | `TestPutAtomic` leftover check + `TestEncodeInjective_RenameBackstop` no-leftover assertion |

F1/F6/F7 are pre-existing semantics, unchanged. F2/F4/F5 are new or newly-surfaced and
are all operator-visible, deterministic, and non-silent — the design's whole point is
that the old silent-overwrite mode (the actual security failure) no longer exists for
distinct names.

### 4.1 Operator-facing caller behavior under F4/F5 (verified end-to-end)

Every in-repo consumer of `Storage.List`/`Get`/`Delete` was traced against the new
decode-on-List semantics (current code; **no caller code change is required** — this
section pins the degradation behavior the committed F4/F5 tests imply, so
implementation can cite it instead of re-deriving it).

**`snapshotcmd list` (`cmd/sso-ctl/snapshotcmd/main.go:100-110`) — per-row graceful
error; no abort, no crash.** The loop `Get(name)`s each `List` row; on error it prints
`<name>  ?  ?  ?  (get error: <err>)` and `continue`s, per its documented intent
("a single bad file doesn't hide the rest from operators triaging a backup"). Traced
rows:

- F4 legacy `a_b.snap`: `List` returns `a_b` (decode is identity for allowlist-only
  names), and `Get("a_b")` **hits** — legacy files render normally under their
  sanitized spelling; `list` never misses on them. The miss only occurs when the
  operator addresses the original name directly (`inspect`/`verify`, below).
- F5 foreign bare-`%` `a%zz.snap`: `List` returns literal `a%zz`; `Get("a%zz")`
  (→ `a%25zz.snap`) misses with `ErrSnapshotNotFound` → row flagged
  `(get error: snapshot: not found)`, all other rows still render, exit code 0.
- F5 foreign lowercase-hex `a%2f.snap`: decodes to `a/b`; `Get("a/b")` hits the
  canonical `a%2Fb.snap` when present (row renders the canonical envelope — mislabeled
  row, no error) or misses otherwise (flagged row). Duplicate rows render
  independently; no crash either way.

Note: rows that fail still exit 0 (pre-existing behavior); the per-row flag is the
operator signal, appropriate for backup triage.

**gRPC admin `List` (`interfaces/grpcserver/grpcadmin/admin_snapshots.go:96-121`) —
duplicate decoded names cannot break page-window cursoring; page-level `NotFound` is a
pre-existing class.** Paging is pure index math over a fully materialized sorted slice
(`decodeOffset` decimal offset, `pageBounds` clamped window, `encodeOffset` next offset
or `""` — `admin_paginate.go:116-157`); there is no name-based cursor. Duplicate
decoded names (foreign `a%2f.snap` + canonical `a%2Fb.snap` → `"a/b"` twice) become
adjacent equal strings after `sort.Strings`; cursor arithmetic is value-independent,
termination (`""` once `hi >= total`) is unaffected, and `TotalSize` (a row count)
stays consistent with what clients page over. Each duplicate row `Get`s and renders
the canonical envelope. The only failure is a page row whose `Get` misses entirely
(foreign file with no canonical twin): the whole page request fails with `NotFound`
via `mapSnapshotError` (whole page, not per-row), deterministic and named in the error
prefix (`"get <name>"`), and **pre-existing** — today's code fails identically for the
same file (raw name → sanitize miss → `ErrSnapshotNotFound`). New code introduces no
new page-failure class and no panic.

**`PruneOldest` (`interfaces/snapshot/retention.go:42-68`) — no data loss, no unbounded
per-run loop; one pre-existing phantom-report artifact.** The `snap_` prefix filter
(`retentionVictims`) means the design's own F5 duplicates (`a%zz`, `a/b`) are never
victims. Only a `snap_`-prefixed foreign twin (e.g. `snap_a%2fb.snap` next to canonical
`snap_a%2Fb.snap`) is affected: `Delete(decoded)` deterministically removes the
canonical file only, and the foreign twin's bytes are never addressed by Get/Delete/Put
→ **no data loss**. Within a run the victims slice is computed once and iterated once
(with `ctx.Done` checks per iteration); duplicate victim entries merely double-report in
the `deleted` slice — no retry, no loop. Across runs the surviving twin re-lists,
re-selects as victim, `Get` misses (`ErrSnapshotNotFound` → classified deletable per the
doc comment at `retention.go:31-36`), `Delete` idempotent-no-ops, and the name is
re-reported as pruned every tick — a **phantom report artifact**: no crash, no data
loss, bounded per run. This exact artifact exists in today's code for any
unaddressable `snap_*` file (same Get-miss → idempotent-delete path), so the change
neither introduces nor widens it; the server loop (`RunSnapshotRetention` →
`pruneSnapshotSafe`, `build_background.go:177-208`) already logs errors and `recover()`s,
so a phantom adds one false count to `RetentionPrunedTotal` / one log line per interval
while the file exists.

**`snapshotcmd inspect`/`verify` on legacy names (`main.go:140,195`) — deterministic
non-crashing miss with a documented workaround.** Post-upgrade `--id a/b` (original
spelling of a legacy file): `Get("a/b")` → `a%2Fb.snap` miss → `ErrSnapshotNotFound` →
`sso-ctl snapshot: get "a/b": snapshot not found`, exit 1, before any peek/decrypt.
`--id a_b` (sanitized spelling) hits, and inspect/verify run fully (PeekEnvelope +
pipeline.Load use only the loaded bytes). The inherent ambiguity remains: if a
legitimately-named `a_b` snapshot also exists, `--id a_b` reads it — operators cannot
distinguish the two by name, which is the no-migration rationale of §3.

## 5. Migration steps

1. **Pre-flight inventory** (before deploy): run `snapshotcmd list` on every snapshot
   directory. Confirm all production names are clean (`snap_*` / `[A-Za-z0-9_.-]*`).
   Any name with other bytes → proceed to step 2.
2. **Re-export legacy unsafe names** (only if step 1 found any): with the old binary
   still running, re-export those snapshots under clean names
   (`snap_<...>`), or export after upgrade and address them via their sanitized
   spelling. After re-export, delete the legacy files. Collided pairs (`a/b` and `a_b`
   both present) are unrecoverable by any tooling — the later write already replaced
   the earlier one; restore from off-site backup if the earlier snapshot matters.
3. **Deploy** the storagefile change as one release. No config, no schema changes; the
   only doc-contract delta is one new `docs/error-codes.md` entry for the D1-a guard
   error (see §7).
4. **Post-deploy verification**: `snapshotcmd list` returns the same clean names as
   step 1; one `inspect --id <clean-id>` round-trips; retention prune dry-run on a
   scratch dir.
5. **Rollback**: revert `file.go` + `file_test.go`. New-code-written unsafe-name files
   become inert under the old binary (List-visible, unaddressable in any spelling —
   see §3). They are **not** the old legacy class: new binaries read them via their
   **original** name (`Get("a/b")` encodes once), and the "encoded spelling" is not an
   address under either binary (`Get("a%2Fb")` double-encodes and misses under new
   code). Re-home/re-export any such files before reverting, or accept
   filesystem-level cleanup. Clean-name files are byte-identical across versions and
   unaffected.

## 6. Testable acceptance mapping

| Acceptance (from spec) | Test (new, in `file_test.go`) | Assertions |
|---|---|---|
| A1 storage-level main | `TestEncodeInjective_Coexist` | `Put("a/b","v1")` + `Put("a_b","v2")`: `Get` both hit own values; `List` sorted == `[a/b, a_b]`; `Delete("a/b")` leaves `Get("a_b")=="v2"`; no `.tmp-` leftovers |
| A2 injectivity table | `TestEncodeInjective_Table` | For each pair `(a,b)` in `[("a/b","a_b"),("a:b","a_b"),("a b","a_b"),("a%b","a_b"),("a//b","a__b"),("ø","ñ")]`: `encodeName(a)!=encodeName(b)`; both values retrievable independently |
| A3 List↔Get round-trip | `TestEncodeInjective_ListRoundTrip` | Names `"site-A/backup"`, `"备份/2024"`, `"a%b"` **plus escape-lookalikes** `"a%2f"`, `"a%AB"`, `"a%ab"`, `"a%zz"`, `"a%2"`, `"a%"`: `List` returns exactly the original set (no duplicates, no reorder, no drop); `Get` per listed name returns that name's data (no double encoding). The lookalike set pins the case-insensitive-hex-decode risk: a single-pass decode is the left inverse of canonical-uppercase encode even when the original name contains `%`+hex-like sequences (prefix code ⇒ `%` in encoded output is always `%25` or `%XX`, never re-scanned) |
| A4 restore-level isolation | `TestEncodeInjective_RestoreIsolation` | Hand-built S1 (`c1`/`tenant-A`/`admin`) and S2 (`c2`/`tenant-B`/`viewer`) (precedent `snapshot_v2_test.go:56-60`), `Pipeline{Sealer: encryptionnone}` → `Save` as `"site-A/backup"` / `"site-A_backup"`; `Load` + `Restore` (`ModeMerge`) into two fresh `defaultimpl.NewMemoryClientStore()` + `permissions.NewMemoryProvider()` targets: target 1 has only `c1`/`tenant-A`/`admin`, target 2 only `c2`/`tenant-B`/`viewer`, no cross-read either way |
| F4 legacy-collapsed post-upgrade | `TestEncodeInjective_LegacyCollapsedNotFound` | Seed `a_b.snap` via `os.WriteFile` (exactly what the old binary wrote for input `"a/b"`; the new `Put` can no longer produce it): `Get("a/b")` → `errors.Is(err, snapshot.ErrSnapshotNotFound)`; `Get("a_b")` → legacy bytes; `List` == `["a_b"]`; `Put("a/b", v1)` → `a%2Fb.snap` on disk, both files coexist, `Get("a_b")` still returns legacy bytes (new code cannot clobber the legacy file); `Delete("a/b")` leaves `Get("a_b")` intact |
| F5 foreign bare-`%` files | `TestEncodeInjective_ForeignBarePercent` | Seed `a%zz.snap` (foreign): `List` shows the literal name `"a%zz"` and does not error; `Get("a%zz")` → `ErrSnapshotNotFound` (encode maps it to `a%25zz.snap`); `Put("a%zz", v)` writes `a%25zz.snap` while the foreign file's bytes stay byte-identical (direct `os.ReadFile` check — not overwritten); `List` then contains `"a%zz"` **twice** (foreign literal + decoded own file — pinned duplicate semantics, benign for retention/snapshotcmd). Seed `a%2f.snap` (lowercase hex, foreign): `List` decodes it to `"a/b"` (pins the case-insensitive-hex decision) and `Get("a/b")` → `ErrSnapshotNotFound` (hits `a%2Fb.snap`, not the lowercase file — documented out-of-contract miss, non-crashing) |
| D1-a guard / F2 boundary | `TestEncodeInjective_TooLong` | Boundary pinned at the tempfile-constrained limit: 239-byte encoded name (239×`"a"`) → `Put` succeeds and round-trips via `Get`; 240-byte encoded name → error with exact string `"snapshot/storage/file: name too long after encoding"`; 3×-expansion case: 41×`"é"` (82 raw bytes → 246 encoded) → error, though the old lossy sanitize accepted it (41 `_` chars); `Get`/`Delete` on an oversized name surface the **same** guard error (Get: not `ErrSnapshotNotFound`; Delete: non-nil); guard fires before any file op → baseDir contains no `.snap` and no `.tmp-*` after the error |
| F3 ENAMETOOLONG backstop | `TestEncodeInjective_RenameBackstop` | `os.MkdirAll(dir/"x.snap")` (rename file→existing-dir fails on every OS incl. root — portable stand-in for exotic-FS NAME_MAX): `Put("x")` → error contains `"rename:"` (the wrapped backstop surface ENAMETOOLONG would take); no `.tmp-*` leftover; `x.snap` still a directory. With the §2.1 guard (temp ≤ 255, target ≤ 244) the backstop is unreachable on standard FS — this test pins the error surface and no-partial-state contract, which is all the F3 row promises |
| F1 degenerate names | `TestEncodeInjective_DegenerateNames` | `Put`/`Get`/`Delete` with `""`, `"."`, `".."` → existing unchanged error strings (`"snapshot/storage/file: empty name"`, `"snapshot/storage/file: sanitised name is invalid (%q)"`); no file created in baseDir |
| Regression | Existing 7 tests untouched | `TestPutGet`, `TestList`, `TestDeleteIdempotent`, `TestPutAtomic`, `TestNew_RequiresBaseDir`, `TestBaseDirReturnsAbs` use clean names → fixed points → must pass unmodified; `TestSanitisesNames` original-name Get assertion continues to hold (`ok/with..bad chars*` → `ok%2Fwith..bad%20chars%2A.snap`) |

Failure-mode coverage: F1→`TestEncodeInjective_DegenerateNames`, F2→`TestEncodeInjective_TooLong`,
F3→`TestEncodeInjective_RenameBackstop`, F4→`TestEncodeInjective_LegacyCollapsedNotFound`,
F5→`TestEncodeInjective_ForeignBarePercent`, F6→`TestPutAtomic` (existing, unmodified),
F7→`TestPutAtomic` + `TestEncodeInjective_RenameBackstop`. Every acceptance and every
failure mode maps to at least one committed test run in the same change; none requires
a new mock (memory stores already exist and are the repo's preferred implementations
per AGENTS.md §4). A4 additionally re-links to T-8(a): it proves the restore side can
no longer feed one snapshot's tenant/role data into another snapshot's restore target
— the precondition for `/token` claims correctness after restore.

## 7. Files

### Modify
```text
interfaces/snapshot/storagefile/file.go      — sanitize → encodeName (+decodeName, +D1-a
                                               guard, +const maxEncodedName=239); List
                                               decodes; package/sanitize doc comments
                                               rewritten to injective-encoding semantics
interfaces/snapshot/storagefile/file_test.go — A1–A4 + F1–F5/D1-a tests above
                                               (Coexist, Table, ListRoundTrip,
                                               RestoreIsolation, LegacyCollapsedNotFound,
                                               ForeignBarePercent, TooLong, RenameBackstop,
                                               DegenerateNames)
docs/error-codes.md          — add the D1-a guard error surface: it is a new observable
                               error even though it is not an HTTP code (precedent: the
                               SDK Go error sections already catalogued there); exact
                               string pinned by TestEncodeInjective_TooLong
```

### Do not modify
```text
interfaces/snapshot/pipeline.go   — Storage contract; encoding lives inside the
                                    implementation, contract text already allows it
interfaces/snapshot/loader/loader.go — fromFile basename derivation of encoded names is
                                    a separate follow-up (spec §2 compatibility note);
                                    explicit ?name=<original> works today
interfaces/snapshot/{snapshot.go,restorer*.go}, infrastructure/defaultimpl/issue_payload.go,
shared/core/spi.go, cmd/sso-ctl/snapshotcmd, interfaces/snapshot/retention.go — untouched
interfaces/grpcserver/grpcadmin/ — untouched (List→Get per page window round-trips
                               decoded names; see §2.4)
docs/{openapi.yaml,config-reference.md} — no contract surface change
```

Budget check: `file.go` grows ~+45 lines (167 → ~212, well under 500); no new files in
`interfaces/snapshot/storagefile` (non-test file count 1, unchanged); function
complexity and nesting unchanged (single-pass loops). `interfaces/sso` 60-file ceiling
untouched.

## 8. Verification plan (per AGENTS.md §2)

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/snapshot/... -run 'TestEncodeInjective|TestSanitises|TestPutGet|TestList|TestDelete|TestPutAtomic|TestRestore' -v
go test ./... -race
go test ./test/ -run TestE2E -v        # test/ snapshot flows run on storageinline, so
                                       # storagefile coverage is package-test-only
                                       # (A1–A4/F1–F5 in file_test.go)
make ci
```

Implementation-time checks, re-verified in the acceptance audit (commit e346454d) and
now pinned by committed tests: (1) A4's `Restore` call shape — `Restorer` fields are all
optional (`restorer.go:39-50`), `Snapshot.Validate` needs only `SchemaVersion` +
non-empty `SourceNamespace` (`snapshotter.go:463-476`); symbols
`defaultimpl.NewMemoryClientStore` (`infrastructure/defaultimpl/aliases_memory.go:62`),
`permissions.NewMemoryProvider` (`domains/permissions/memory.go:45`),
`encryptionnone.New()` (`interfaces/snapshot/encryptionnone/none.go:14`) — all verified
present. (2) `List` decode is a single pass, no reorder/filter — pinned by the exact-set
assertion in `TestEncodeInjective_ListRoundTrip`. (3) Case-insensitive hex decode for
foreign files vs canonical-uppercase encode — pinned by the escape-lookalike name set in
`TestEncodeInjective_ListRoundTrip` (left-inverse property) and the lowercase-hex row of
`TestEncodeInjective_ForeignBarePercent` (documented out-of-contract miss). Resolved in
the audit: the D1-a guard bound is tempfile-constrained at `maxEncodedName = 239` (§2.1),
not the 250-byte figure in the original draft — the acceptance audit found the draft's
`encoded+ext > 250` formula (boundary 245/246) and its §6 test text (249/250) mutually
inconsistent and both too loose for the `.tmp-<encoded>-*` + 10-digit-random tempfile
name. (4) Implementation-time doc action: F2's new guard error surface must get a
`docs/error-codes.md` entry (new observable error string; the doc is already the
catalog for non-HTTP SDK Go errors); the exact string
`"snapshot/storage/file: name too long after encoding"` is pinned by
`TestEncodeInjective_TooLong` (§6), so the entry cannot drift from the code.
