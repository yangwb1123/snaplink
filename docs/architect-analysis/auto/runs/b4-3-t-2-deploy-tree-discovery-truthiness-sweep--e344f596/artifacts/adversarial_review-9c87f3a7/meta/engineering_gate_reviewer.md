All verification complete. Here is the audit.

---

# Verification: design feasibility under engineering gates + AGENTS.md §5.6

**Verdict: the placement plan is sound and fully budget-compatible (verified with measured numbers); the migration plan has two real ordering hazards (one intra-pipeline in step 2, one in step 3 exactly as you flagged); the contract-update list has one correction (config-reference.md applies); the quarantine list is incomplete and must be re-pinned.**

## 1. File placement, fan-out, and budgets — VERIFIED

**`cmd/sso-ctl` is at exactly 16 subdirs = Go cap** (`maxSubdirsPerDir = 16`, directory_fanout_test.go:35; `skipDirs` — maintainability_budget_test.go:43 — excludes none of the 16: apiclient, auditexport, auditverify, clientscmd, configcmd, entitiescmd, generate, hashcmd, importcmd, legacysync, migratecmd, sessionscmd, snapshotcmd, soc2report, tokenscmd, tui). A 17th subdir is a *new* gate failure. The design's "extend configcmd" choice is the only legal one; nothing may be added at `cmd/sso-ctl/` root (2 non-test files, unchanged) and `cmd/sso-ctl/main.go`'s `subcommands` map must stay at 16 entries (dispatch_test.go pins only generate-wiring + non-nil `Run` funcs — no size pin).

**Where the code and all 18 new test functions land** (no new subdir anywhere, no root-level files):

| File | Status | Non-test file count (cap 10) | Measured budget |
|---|---|---|---|
| `cmd/sso-ctl/configcmd/discovery_check.go` | **new** — `runCheckDiscovery`, `fetchDiscoveryDoc`, `checkDiscoveryDoc`, `probeEndpoint`, `violation` | 2 → 3 | ≤ 500 lines gate (non-test only); design est. ≤ 300. Every func ≤ 50 lines / cyclo ≤ 15 (gate counts nested literals) |
| `cmd/sso-ctl/configcmd/main.go` | **modified** — +1 `Run` case, `--issuer-allowlist` in `runValidate`, usage/package-doc lines | — | **121 lines now** (measured) → ~151 after +30, ≪ 500. `Run` cyclo 7 / 21 lines → 8 after case; `runValidate` cyclo 6 / 27 lines → ~8–9 after gate; `usage` 1/27; `printConfig` 1/5 — all ≪ 15/50 |
| `cmd/sso-ctl/configcmd/discovery_check_test.go` | **new** — 13 test funcs: StockServerGreen, TokenPathMismatch, PathMismatchPerField (table), AdvertisedEndpoint404, AuthenticateSegment, ZeroPort, MalformedPort, MethodMismatchProbe, Fetch500, NonJSON, ReadOnlyBodyIdentity, MissingURL, BadTimeout | test files **uncounted** by all three gates | no budget applies |
| `cmd/sso-ctl/configcmd/main_test.go` | **modified, append** — 5 test funcs: Match, Mismatch, DefaultFails, MultiEntry, EmptyIsUsage | test file | **299 lines now**; test files excluded from the 500-line gate (maintainability_budget_test.go excludes `_test.go`) |

Note on the count: it's **18 new test functions, not ~12** (13 + 5; three of the 13 are table-driven sub-cases). Even if the acceptance reviewer's ~9 additional pin tests are adopted, they land in the same two files — placement unchanged.

Also verified: `go build ./...` and `go vet ./...` are **green at HEAD** (clean per-edit baseline). The new `configcmd → interfaces/sso` edge is downward (composition → interfaces), precedented in the module (importcmd/importer.go:11, generate/templates.go:12), already transitively present (`config/config.go:13` imports it), and the layer gate skips `_test.go` (architecture_layer_test.go:147). `config.Load(path) (*Config, error)` and `cfg.Server.Issuer` (config/config_server.go:17) are the right anchors; `PathOIDCDiscovery` exists at interfaces/sso/server_discovery.go:18; auditverify's `usageErr` exits 2 (main.go:488-489).

## 2. Migration-step audit — 2 real ordering hazards, 1 contract correction

**Step 1 (checker core, no wiring):** no hazard — unused unexported functions are legal Go; `Run` untouched so every existing test passes. One restatement: "the tree stays green" is false at HEAD (see §3); the criterion must be *failure-set identical to baseline*.

**Step 2 (CLI wiring):** two hazards, both unpinned by the design's tests:
- **`--timeout <= 0`**: `flag.Duration` accepts `0s`/`-1s`; an immediately-expired shared ctx turns this into "every probe fails → exit 1 timed out". Must-pin 3 appears only in the summary — §2.1, §4 F7, and case 16 cover only *unparseable*. Fold the `<= 0 → exit 2` check + two sub-case tests into step 2.
- **Trailing-slash/path-component base vs pipeline order**: fetch runs *before* any base check, so a trailing-slash `--url` produces a double-slash fetch-404 diagnostic, not the promised "trailing slash → base violation (exit 1)"; a path-component base cascades 4 equality violations after the fetch 404s. The base canonicalization/short-circuit must be specified *before* the fetch pass — and the exit-1-vs-exit-2 split must be implemented in the checker (a flag-parser validation returning 2 would pass every mapped test).

**Step 3 (allowlist gate) — the hazard you flagged is confirmed real, and worse than the design states:** current `runValidate` order is `config.Load` (main.go:99) → **`config OK` print to stdout (:104)** → `--print` render (:105). The gate must sit between :99 and :104. The design's own wording — "Check runs before `--print` rendering" — is **insufficient**: `--print` is *after* the stdout print, so that phrasing permits a gate placed after "config OK", and cases 11/12 assert stderr only, never stdout emptiness (the acceptance reviewer caught this too). Step 3 must: (i) anchor the check explicitly between Load and the print; (ii) add `stdout == ""` assertions to cases 11/12 plus a failing-allowlist-with-`--print` variant; (iii) run the empty-value/`",,"` usage check (exit 2) at flag-parse time **before** `config.Load`, else bad-file+bad-allowlist returns 1 or 2 depending on placement; (iv) keep loader-error-first (automatic if the membership check is post-Load). T-9 (flag absent ⇒ byte-identical) is structurally safe if the block is gated on the flag string.

**Step 4:** `make ci` = `fmt vet race build …` where `race` is `go test -race ./...` — red at HEAD. Handoff criterion must be "failure set identical to pinned baseline + `cmd/sso-ctl/configcmd` absent from every violation list", not "make ci green".

**Contract updates for a CLI-only change (AGENTS.md §5.6):**

| Doc | Applies? | What to add |
|---|---|---|
| `docs/error-codes.md` | **No** | No new `Err*`; file covers SDK Go errors only; exit codes are the existing 0/1/2 CLI convention |
| `docs/openapi.yaml` | **No** | No server endpoint (out-of-band operator fetch) |
| `docs/feature-matrix.md` | **No** | Matrix is server-capability-scoped (line 10); zero sso-ctl rows exist; feature tracking is the B4-3 campaign row |
| `docs/config-reference.md` | **Yes — design is wrong to exclude it** | Its "Config JSON Schema & Validation" table (lines 449–450) already documents `sso-ctl config schema` and `validate-schema` in a "Key / Command" column. Add two same-family rows: `sso-ctl config check-discovery --url … [--timeout]` and `sso-ctl config validate --issuer-allowlist <list>`. Under AGENTS.md §1 (satisfy the stricter contract), "no config knob ⇒ don't touch" doesn't survive the file's own CLI-documentation convention |

## 3. Quarantine — failures exist and are larger than the design's C3 list

Measured at HEAD this session:

- **Go gates** (`go test -run 'TestMaintainability_|TestArchitecture_' .`) — **3 failing tests**: `TestArchitecture_DirectorySubdirFanout` (docs 18 > 16; `docs/architect-analysis/auto/runs` **268** > 16; root `.` exempt regression 24 > frozen 21), `TestArchitecture_DirectoryDepth` (hundreds of violations under `docs/architect-analysis/auto/runs/**` at depth 5–8 — *including this run's own artifacts*), `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539 > 500).
- **Python mirror** (`python checks/directory_fanout.py`): 5 violations — **`cmd/sso-ctl` (16 > 15, the design's own home, pre-existing)**, dist 37, docs 19, runs 268, platform 16.
- `go build`/`go vet`: green.

Findings: (a) the design's C3 list is **incomplete** — it omits `DirectoryDepth` and `FileSizeBudget`, and its runs count (80) is stale (268 now, growing because the pipeline writes its own artifacts into that dir); (b) the mandated commands (`go test -run 'TestMaintainability_|TestArchitecture_' .`, `go test ./... -race`, `make ci`) are **all red at HEAD**, so every step's "tree stays green" claim must be restated as *diff against a baseline pinned at implementation time*; (c) the change is structurally incapable of touching any pinned violation (all code lands at `cmd/sso-ctl/configcmd`, depth 2; no root files; no new subdirs; configcmd's file count goes 2→3 ≪ 10), so quarantine is achievable: pin test names + counts before step 1, diff after each step, and confirm `cmd/sso-ctl`'s subdir count stays 16 (Go) / unchanged at 16 (Python). The Go gate (cap 16) is the committed authority; the Python 15-cap line on `cmd/sso-ctl` is pre-existing and must be reported separately, never "fixed" in this change.

**Net:** the design's file plan passes every gate with margin (measured); the migration steps need the two step-2/step-3 ordering fixes, the base-check-before-fetch pipeline order, `--timeout <= 0` folded into the body, one config-reference.md row pair, and a re-pinned, diff-based quarantine including the depth and file-size failures.
