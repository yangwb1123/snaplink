All measurements complete. Let me compile the numbers into the assessment.

## Latency assessment: `sdk-drift` check on `make ci`

**Environment**: Go 1.26.5 linux/amd64, repo at HEAD `038e1765`, `GOPROXY=off` where stated, `make ci` runs serially (no `-j`). Timings via `/usr/bin/time` (best-of-3 where variance mattered).

### 1. The check's own cost — measured

| Leg | Component | Time |
|---|---|---|
| Regen | `go run ./cmd/gensdk --lang=all` → temp dirs, **warm build cache** | **0.10–0.12s** |
| Regen | same, after real `docs/openapi.yaml` content change (recompiles the `go:embed` docs pkg) | 0.22s |
| Regen | **cold build cache**, module cache warm, `GOPROXY=off` | **3.85s** |
| Cleanliness | `git status --porcelain -- docs/sdks/ ':(exclude)docs/sdks/typescript/dist'` | ~0.01s (full-tree scan on this 130MB-`.git` dirty repo: 0.02s; the pathspec exclusion costs nothing extra) |
| Deploy | 3 byte-compares (683KB + 158KB + 133KB = 974KB total) + `os.path` checks | <0.01s |
| Overhead | `python cli.py` interpreter startup | ~0.05s (cf. `capabilities check` = 0.06s total) |

**Total: ~0.15–0.25s warm; ~3.9–4.0s cold-cache worst case.**

Key enabler verified: the generator's dep footprint is only `goccy/go-yaml` + the embedded `docs` package, and `ci:` runs `build` (3rd of 16 steps) before `sdk-drift-check` would sit (after `sdk-surface-check`, step 14) — so the cache is always warm in the gate, and the 3.85s cold figure only occurs for a standalone `make sdk-drift-check` on a fresh cache (one-off, then warm).

### 2. The added pytest suite

- Baseline `python cli.py check-test`: **203 tests / 26.9s**.
- The new suite (~15–20 tests) is cheap: git-init fixtures measured at **7ms each**, fake-generator subprocesses ~50ms each → ~2–4s warm total. The only non-trivial member is the real-gensdk determinism test (case 8): 2× `go run` = 0.2s warm / 7.7s cold.
- **Critical finding: `check-test` is not a `ci:` prerequisite** (Makefile:268 ends at `adapters-check`; verified). The pytest suite lands on the developer loop only, not the gate. Even so, it pushes check-test to ~30–35s warm — acceptable, and only the determinism test needs Go (skipif-guarded per design).

### 3. Comparison vs existing gate checks (all timed, same invocation as `ci:`)

| Check | Time |
|---|---|
| `race` (go test -race ./...) | 183.9s |
| `ci-modules` | 111.5s |
| `modules-smoke` | 35.6s |
| `build` (cli.py) | 16.1s |
| `proto-lint` | 14.6s |
| `vet` | 8.8s |
| `adapters-check` | 2.69s |
| `check-routes` | 1.45s |
| `profiles-evidence` | 1.08s |
| `config-validate-all` | 1.03s |
| `sdk-surface-check` | 0.83s |
| `check-proto-openapi-parity` | 0.79s |
| `fmt` / `capabilities-check` / `modules-check` | 0.28 / 0.06 / 0.07s |
| **sdk-drift (proposed)** | **~0.15s warm / 3.9s cold** |

Full `make ci` envelope ≈ **380s** (~6.3 min), of which `race`+`ci-modules`+`modules-smoke` = 87%. The Python check block (`route-contract` → `adapters-check`) sums to ~7s; sdk-drift at ~0.15s warm is the second-cheapest check in that block.

### 4. Cost-control recommendations

**None of the three proposed controls is needed; two micro-recommendations:**

1. **Prebuilt gensdk binary reuse — reject.** `go run` warm is 0.10s because the gate's own `build` step warms the cache; a `bin/gensdk` target adds Makefile staleness/versioning complexity to save ~0.1s. The only scenario where prebuilding pays is if `sdk-drift-check` is ever reordered *before* `build` in `ci:` or invoked standalone on cold caches repeatedly — neither is the design. Keep `go run`; the determinism pin already guarantees byte-identical output so cache-key reuse is stable.
2. **Deploy-leg skip when tree absent — already designed (F3/case 4) and its guard is ~free**; the presence check is one `Path.is_dir()` before the byte-compares. No change.
3. **Keeping the regen leg out of the hot path — reject.** It *is* the gate's purpose (future-drift blocking, GWT5); at 0.10s warm there is no hot path to protect. The deploy leg (3 byte-compares) is also ~free and must stay — it's the R2 contract.
4. **Micro-recommendation (latency-adjacent correctness, not speed):** the case-8 determinism test with `GOPROXY=off` requires a populated module cache — on a fresh dev machine it fails rather than skips. Suggest the skipif also probe `go env GOMODCACHE` for the `goccy/go-yaml` module (or `GOFLAGS` fallback), so check-test never hard-fails on a cold machine; its cold cost (7.7s) is a one-time dev-loop hit, fine.
5. **No action on the git leg**: the pathspec-excluded porcelain scan measures ~0.01–0.02s on this repo (even fully dirty) — far below noise; `dist/` exclusion is confirmed cost-free.

### 5. Verdict

**The check stays well within the gate's latency envelope.** Added cost: **~0.15s (0.04%) warm** in `make ci` — the realistic case, guaranteed by `ci:`'s existing ordering — and **~3.9s (1%)** only in the cold-cache standalone worst case, which the gate ordering prevents. That is comparable to `sdk-surface-check` (0.83s) and far under `adapters-check` (2.69s), its neighbors in the check block. The pytest suite adds ~2–4s to `check-test` but is *not* in `ci:`. No cost control is warranted; the design's "one extra `go run` per `make ci` (~seconds), cache warm because `build` runs first" claim (section 4) is confirmed with the warm figure actually being a tenth of a second.

One measurement caveat: `race`/`ci-modules` ran on the mid-campaign dirty tree (`race` ended with a test failure), so their absolute times are indicative, not canonical — but the envelope is dominated by them by 2 orders of magnitude either way, so the conclusion is insensitive to that noise.
