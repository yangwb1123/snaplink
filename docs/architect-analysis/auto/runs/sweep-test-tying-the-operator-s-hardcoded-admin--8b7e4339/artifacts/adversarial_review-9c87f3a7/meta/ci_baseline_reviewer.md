All measurements complete. Here is the full baseline report.

---

# `make ci` baseline — verified pre-change state (worktree `main` @ aef62123, go1.26.5)

## 1. Full `make ci` result: **FAIL (exit 2)** — single failing gate: `race`

| Gate (in order) | Result |
|---|---|
| `fmt` | ✅ |
| `vet` | ✅ |
| `race` (`go test -race -count=1 ./...`) | ❌ **3 root-gate test failures** (see §2); all 100+ other root packages pass, incl. `test/` (103s) |
| `build` | ✅ |
| `examples` | ✅ |
| `proto-lint` | ✅ |
| `ci-modules` (13 nested modules, incl. operator) | ✅ EXIT=0 |
| `config-validate-all` | ✅ |
| `modules-check` | ✅ |
| `modules-smoke` | ✅ |
| `route-contract` | ✅ |
| `capabilities-check` | ✅ |
| `sdk-surface-check` | ✅ |
| `profiles-evidence` | ✅ |
| `adapters-check` | ✅ |

The 3 failures are the **only** red in the entire pipeline; everything after `race` was re-run individually (race short-circuits `make ci`).

## 2. Every failing gate, classified

**F1 — `TestMaintainability_FileSizeBudget`**: `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 > 500)
→ **PRE-EXISTING, unrelated to this campaign.** Committed at 7586c6b3, worktree-unmodified, last touched by non-campaign work.

**F2 — `TestArchitecture_DirectoryDepth`**: 271 dirs > depth 3, all under `docs/architect-analysis/auto/runs/...` (artifacts at depth 7–8)
→ **PRE-EXISTING structural violation, campaign-artifact class, amplified by the live campaign.** At a clean HEAD the gate already counts ~161 violations: 24 pbatch run dirs (with `artifacts/<stage>` trees) are *committed* by earlier `[pi-batch]` commits; `ops/deploy`, `gen`, `testdata`, dot-dirs are exempted by the walker, so the docs tree alone fails HEAD. The worktree adds ~110 more from untracked current-run dirs (71 fully-untracked run dirs). The adminpaths design's own files (`docs/architect-analysis/cmd-sso-operator-controller-b4-3-*.md`) sit at depth 3 and contribute **zero**.

**F3 — `TestArchitecture_DirectorySubdirFanout`** (three sub-reports):
- `docs` (18 > 16): **campaign-caused.** HEAD has exactly 16 tracked subdirs (at cap, green); the 2+ over-cap dirs are untracked campaign docs (`docs/campaigns`, `docs/results`; `docs/auto` appeared mid-measurement — see concurrency note).
- `docs/architect-analysis/auto/runs` (95 > 16): **pre-existing at HEAD (24 committed run dirs, already over), campaign-amplified** to 95–96 by untracked runs.
- root `.` (24 > frozen ceiling 21): **worktree-caused.** HEAD is 20 (green). The 4 extra on-disk dirs are `.pi-batch` + `examples` (campaign artifacts) and `.venv` + `logs` (local env).

**Concurrency caveat**: this is a live campaign worktree — other pbatch tasks created `docs/auto/` during my measurement. Gate counts are moving targets; counts above are point-in-time.

## 3. Design §6 step 4 / §7 case 8 / §8 — achievable as written?

| Design claim | Verdict |
|---|---|
| §6 step 4 "Full gates … must pass" + §8 `make ci` | **NOT achievable as written.** `make ci` exits 2 today on F1–F3, none of which this change causes or fixes. The §8 "Pre-existing conditions: none found" is accurate only for the operator module (verified: controller `ok 0.098s`) and R3 (verified: `--- PASS`). **Needs a documented caveat**: verify the root-gate failure *set* is unchanged before/after (no new failures), don't demand green; the campaign's pbatch runs tree is the root cause, not this change. |
| §7 case 8 (full operator `./...` suite green) | **Achievable as written** ✅ — `cd cmd/sso-operator && go build ./... && go test -race -count=1 ./...` is green today (ci-modules) and stays green post-promotion (§4). Minor: E12's "10 package-wide" is stale — 14 `TestReconcile_*` (8 + 6); case 8's wording is unaffected. |
| §8 line 1 `go mod tidy && go build ./... && go vet ./...` (operator) | ✅ all pass (tidy is a no-op today; vet EXIT=0). |
| §8 line 2 `… go test -race -count=1 ./… # ci-modules gate, Makefile:263` | ✅ green, but the **label is trimmed**: `Makefile:263` is `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` — §8 omits the `go build ./... &&` segment (design §1 E9 quotes it correctly; coverage unaffected). |
| §8 line 3 focused `-run 'TestAdminPaths'` | ✅ passes today ("no tests to run" — the net-new test lands in step 1; then it matches and runs). |
| §8 line 5 R3 pin | ✅ `PASS` (0.00s). |
| §8 line 6 `go test -run 'TestMaintainability_|TestArchitecture_' .` | ❌ **RED today** (F1–F3). The "root gates unaffected" framing is misleading: they are already red; the honest claim is "the failure set is unchanged". |
| §8 line 7 `python cli.py modules check` | ✅ (also passes with the promoted go.mod, all 6 profiles). |

## 4. yaml.v3 promotion — real-pipeline experiment (performed, then byte-restored)

On the real worktree (real go.mod/go.sum, go1.26.5, `GOPROXY=goproxy.cn`): added a probe test importing `gopkg.in/yaml.v3`, ran `go mod tidy`, ran the real gate, then restored byte-for-byte (sha256-verified; probe deleted; worktree diff unchanged).

- **go.mod**: exactly one line moved — `gopkg.in/yaml.v3 v3.0.1 // indirect` (line 58) → direct `require gopkg.in/yaml.v3 v3.0.1`. Sibling lines untouched (cbor v2.9.2, x/net v0.53.0, the test-only root require/replace all intact). Design's §3.2/§6 step-2 claim **confirmed exactly**.
- **go.sum**: **byte-identical — zero additions/removals** (both hashes already at lines 146–147). **Confirmed.**
- **Gate-clean under the real pipeline**: with the promoted go.mod, `cd cmd/sso-operator && go build ./... && go test -race -count=1 ./...` → **EXIT=0** (controller `ok 1.603s`), and `python cli.py modules check` → **OK** (full/minimal/prototype/standard-kafka/standard).
- Ordering nuance confirmed: the promotion only sticks once the importer exists (step 1 → step 2 ordering in §6 is correct; tidy would demote an orphaned direct require).

## 5. Bottom line

- **One caveat must be documented** (design §6 step 4 / §8 "Pre-existing conditions"): `make ci` cannot pass today; F1 is unrelated-to-campaign, F2/F3 are the campaign's own pbatch runs tree (pre-existing in committed form, growing per run) plus untracked worktree dirs. The change's real obligation is **no new failures** — which is achievable and verified for every command the design runs inside the operator module.
- **§7 case 8 and all operator-scoped §8 commands are achievable as written**; the Makefile:263 label needs the `go build` segment; E12's count needs 14.
- **yaml.v3 promotion is gate-clean under the real pipeline**: one-line go.mod move, zero go.sum diff, operator build/race-test and `cli.py modules check` green.

No waiver is required — a one-paragraph caveat in §8 plus the §7 case-8 count fix suffices; I did not edit the design doc since this was a baseline-establishment task. Worktree restored to its exact pre-experiment state.
