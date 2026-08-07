All claims are now verified against the code. Here's the end-to-end validation report.

# Validation: no-caller-change claim (design §2.4/§3/§5/§7)

**Verdict: the no-caller-change claim HOLDS for every in-repo caller, with two doc-level defects (a factually wrong rollback row in §3, and a consumer omitted from §2.4's enumeration) and one E2E nuance. No code change is required by any in-repo caller.**

## 1. Loader basename derivation (§7 deferred follow-up) — SAFE to defer

Production callers of `loader.FromURI` (loader.go:60 `fromFile`, `filepath.Base` at 68, `?name=` at doc line 10):
- **Only production caller**: `platform/bootstrap/builtin/builtin.go:78` via `cmd/sso-server/build_bootstrap.go:111` — URI comes from operator config `snapshot.restore_from`. No in-repo code constructs it from `List` output.
- Test callers (`builtin_test.go` `stageSnapshot`, `loader_test.go`) all use clean names (`snap_test_loader`, `snap_<id>`), which are encode fixed points → basename derivation unchanged.

Key corroboration: the **only** name producer is `newSnapshotID()` (`snapshotter.go:451`): `snap_<RFC3339>_<base64url>` — all allowlist bytes, always clean. **No in-repo path can ever write an unsafe name in production**, so the basename path is never exercised with encoded names.

Verified deferral direction: for unsafe names the URI-path form can **never** work under new code even with escaping — `file:///dir/a%252Fb.snap` → `url.Parse` gives path basename `a%2Fb` → `Get` re-encodes → `a%252Fb.snap` miss (double-encoding). Only `?name=<original>` works (query values are decoded before use) — exactly what §7 claims. The follow-up must apply `decodeName` to the derived basename.

## 2. List-output consumers vs decoded names — all round-trip

| Consumer | Location | Uses `List` output for | Verdict |
|---|---|---|---|
| `snapshotcmd list` | `main.go:100-110` | `Get(name)` per row | ✓ decoded name → encode-on-Get hits |
| `snapshotcmd inspect/verify` | `main.go:140,195` | operator `--id` (original name) | ✓ |
| Retention `PruneOldest` | `retention.go:42-68` | `snap_` filter, Get, Delete | ✓ round-trips; decoded sort order only meaningful for clean timestamp IDs anyway |
| **gRPC admin `List`** | `grpcadmin/admin_snapshots.go:96` | `Get(name)` per page window | ✓ round-trips — **not enumerated in design §2.4/§7** (gap: add it) |
| Server retention loop | `build_background.go:189` | `PruneOldest` on file store | ✓ |
| E2E (`test/`) | `admin_grpc_base_test.go:68`, `admin_grpc_snapshots_test.go` | — | ✓ **E2E snapshot flows run on `storageinline`, not `storagefile`** — unaffected; storagefile has zero E2E coverage, so A1–A4 package tests are the only coverage (design's §8 "if wired" note is accurate but should say "inline-wired") |
| DR replicator | `platform/lifecycle/dr/replicator.go` | — | ✓ raw `os.ReadDir`/`snap_` prefix, no storagefile |

Corroborations: `TestSanitisesNames` passes unmodified — it asserts only absence of `*/` in the on-disk name + original-name Get; `ok%2Fwith..bad%20chars%2A` satisfies both (`%` isn't in the `ContainsAny` check). Pipeline contract `pipeline.go:15-18` matches ("MAY reject unsafe characters", overwrite allowed). No published doc (config-reference/openapi/error-codes) promises the underscore mapping — no doc drift.

## 3. Mixed-version cutover + rollback steps 1-5 — one factual error, otherwise reversible

- **Steps 1/3/4**: read-only or code-revert — fully reversible and complete. ✓
- **Step 2**: destructive (legacy delete) but data survives — re-exported clean files are byte-identical under *both* binaries (old sanitize maps allowlist verbatim). Improvement: hold legacy files until step-4 verification passes; collided-pair backup note already present. ✓
- **Step 5 — finding (contradiction + factual error)**: §3 says new-written unsafe files become "addressable only via their encoded spelling **by old binaries**"; §5 says "readable via encoded spelling **by new binaries only**". Both are wrong in different ways:
  - Old binaries **cannot** address `a%2Fb.snap` in *any* spelling: old `sanitize` output never contains `%` — `Get("a%2Fb")`→`a_2F_b.snap` miss, `Get("a/b")`→`a_b.snap` miss, and `Delete` has the same mapping, so the file is List-visible but inert (not Get-able, not Delete-able by name).
  - New binaries read it via its **original** name (`Get("a/b")` encodes); the "encoded spelling" `a%2Fb` as a Get argument double-encodes and misses.
  - The two legacy classes are **asymmetric**: old-written `a_b.snap` stays addressable by new binaries via `a_b` (design §3 F4 is correct), but new-written `a%2Fb.snap` has *no* fallback spelling under old binaries. Rollback is complete only if operators re-home/re-export unsafe-name files created during the new-version window *before* reverting — or accept filesystem-level cleanup. (In practice production never writes unsafe names, so the default-path rollback is trivially safe.)
- **Mixed-version edge found**: an old-binary retention loop over a dir containing new-written `snap_`-prefixed unsafe files (`snap_a%2Fb.snap`) would report them pruned (idempotent `Delete` miss returns nil → appended to `deleted`) while the file survives — false-positive reporting, no data loss. Supports the design's "coordinated cutover" advice; worth one sentence in the upgrade notes.

## Suggested design deltas (all doc-only)

1. §3 rollback row: replace "addressable only via their encoded spelling by old binaries" with the correct asymmetry (List-visible but unaddressable/un-deletable by name under old binaries; re-home before reverting).
2. §2.4/§7: add `interfaces/grpcserver/grpcadmin/admin_snapshots.go` to the no-change caller list.
3. §8 E2E line: note `test/` snapshot flows use `storageinline`, so storagefile coverage is package-test-only.
