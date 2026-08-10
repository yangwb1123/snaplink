# Design: SDK regeneration-drift and deploy-tree sweep gate (T-9)

Companion to `docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-requirements.md`.
This document treats that spec (and the pipeline summary it cites) as
untrusted evidence, records what was independently verified, and turns the
requirements (R1–R5 + 9 acceptance cases) into a concrete, ordered design
with API changes, compatibility constraints, failure modes, migration steps,
and testable acceptance mapping.

## 1. Evidence verification verdict

Every citation was re-checked against HEAD by execution, not by reading the
claim. All six direction citations and both corrections confirm; three
precision notes (P1–P3) refine the design.

| # | Claim | Measured reality | Verdict |
|---|---|---|---|
| E1 | Deploy `client.ts` 2857-line diff vs canonical (832 vs 3494 lines) | `diff docs/sdks/typescript/client.ts ops/deploy/openresty/fullstack/static/docs/sdks/client.ts \| wc -l` = **2857**; sizes 3494 / 832 | Confirmed |
| E2 | Deploy `openapi.yaml` 5686-line diff (13052 vs 18236 lines) | `diff docs/openapi.yaml ops/deploy/openresty/fullstack/static/docs/openapi.yaml \| wc -l` = **5686**; sizes 18236 / 13052 | Confirmed |
| E3 | Deploy `client.py` drift 2268 lines (new fact folded into R2) | `diff docs/sdks/python/client.py ops/deploy/openresty/fullstack/static/docs/sdks/client.py \| wc -l` = **2268**; sizes 2772 / 616 | Confirmed |
| E4 | Deploy `static/` tree untracked, not gitignored, external-pipeline output | `git status --porcelain ops/deploy/openresty/fullstack/` → `?? static/`; `git check-ignore ...` exit 1; `git ls-files ops/deploy/openresty/` = 17 files, none under `static/` (sibling tree `conf.d/gateway.conf` is tracked — the untracked claim is scoped to `static/`) | Confirmed (scope precision: only `static/` is untracked, not all of `ops/deploy/openresty/`) |
| E5 | `Makefile:268` `ci:` ends at `sdk-surface-check`; no drift/deploy check | Line 268: `ci: fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract proto-openapi-parity capabilities-check sdk-surface-check profiles-evidence adapters-check`; no target references `fullstack/static` | Confirmed |
| E6 | `cli.py:275` `sdk-surface check` registry-only; `generate` (sdk_surface.py:146-151) not wired into ci | `cmd_sdk_surface` (cli.py:275-278) → `sdk_surface.run`; `check` (129-137) validates registry vs operationIds + capabilities + file existence; `generate` (146-151) runs `go run ./cmd/gensdk --lang=all`; no Make target invokes it | Confirmed |
| E7 | `cmd/gensdk/main.go` defaults `--out-ts=docs/sdks/typescript/client.ts`, `--out-py=docs/sdks/python/client.py`; `--lang=all` writes both; deterministic | `parseFlags` defaults confirmed (main.go:99-105); `generate` writes both for `all` (67-74); double regeneration to separate temp dirs → `cmp` byte-identical for both languages | Confirmed |
| E8 | Discovery already truthful: `TokenEndpoint: base + PathToken` (server_discovery_config.go:146), `PathToken = "/token"` (consts.go:21); Go-tree sweeps exist; zero legacy-defect test names | `buildBaseMetadata` emits `base + PathLogin/PathToken/PathJWKS/PathRevoke/PathIntrospect` (145-149); `consts.go:21` = `"/token"`; `rg TestOIDCDiscovery` in `*.go` → 0 hits; `test/oidc_discovery_test.go` has 13 `TestDiscovery_*` | Confirmed |
| E9 | Committed `docs/sdks/*` stale at HEAD (missing `client_secret_expires_at`/`grant_types`/`tenant_id`, 4 hunks) | Regenerate-to-temp vs committed: TS 8 diff lines / 2 hunks (`client_secret_expires_at?: number`, `grant_types?: string[]`, `tenant_id?: string`); PY 5 diff lines / 2 hunks (`client_secret_expires_at: int`, `grant_types: List[str]`, `tenant_id: str`). 4 hunks total across both files | Confirmed (hunk phrasing = 4 across the pair) |
| E10 | cli.py dispatch points: help ~24-40, COMMANDS 323-359, passthrough tuple 388 | `cmd_check_routes` :171-173 imports `checks.route_contract.run`; `"sdk-surface"` :356; tuple `("skill", "configure", "modules", "capabilities", "sdk-surface", "profiles")` :388 | Confirmed |
| E11 | CHECKS_REGISTRY.md rows ~31 and ~45 | `sdk_surface.py` row at :31; "Specific checks" group at :45-48 | Confirmed |
| E12 | Check-module precedent: `run() -> int`, pytest via `cli.py check-test` | `checks/route_contract.py:217 run() -> int`; `checks/adapters_check.py:137 run() -> int`; cli.py:200-204 runs pytest on `checks/` | Confirmed |
| E13 | Generator does not consume the spec's `servers:` list (sibling-direction interaction is nil) | `grep servers cmd/gensdk/*.go` → 0 hits; regeneration embeds the working-tree `docs/openapi.yaml` via `go:embed` (docs/openapi_embed.go:28) at build time | Confirmed — the drift leg therefore always reflects the current working-tree spec, which is exactly the future-drift-blocking property GWT5 needs |

### Precision notes incorporated into the design

- **P1 (untracked scope)**: only `ops/deploy/openresty/fullstack/static/` is
  untracked; `conf.d/gateway.conf` etc. are tracked. The sweep asserts on the
  `static/` subtree only, and skip-when-absent applies to that subtree.
- **P2 (git-status check scope)**: `docs/sdks/typescript/dist/` is committed
  TS-toolchain output. The R1 cleanliness check must exclude `dist/` so a
  local `npm run build` cannot false-positive the gate (this reconciles R1's
  "any modified/new file" with the non-goal "no dist/ staleness check").
- **P3 (exit-code contract)**: verdicts are 0/1; an unknown action is a usage
  error and returns 2 (argparse convention), which still satisfies the
  acceptance's "exit ≠ 0". This explicitly reconciles R5's literal "only 0/1"
  (requirements :111): the verdict contract is 0/1, and the 2 is the documented
  usage-error deviation, matching the live `sdk-surface` behavior (verified
  empirically: `sdk-surface check` → 0, `sdk-surface bogus` → 2 via argparse
  `choices`, unknown top-level command → 1).

### Review findings incorporated (N1–N3, P4, accepted gaps)

- **N1 (test phrasing)**: argparse raises `SystemExit(2)` rather than
  returning, so acceptance case 6 asserts `pytest.raises(SystemExit)` with
  `code == 2` (section 7, row 6); the observable CLI exit is 2 either way, so
  the acceptance's "exit ≠ 0" holds.
- **N2 (registry row grouping)**: the table lists all `checks/*` rows before
  `ops/scripts/*` rows, so the new `checks/sdk_drift.py` row goes at the end
  of the checks block — after `self_test.py` (:28) — not after
  `ops/scripts/sdk_surface.py` (:31), which would drop it into the
  ops/scripts block.
- **N3 (Make target help)**: `sdk-drift-check` gets a `##` help comment like
  `sdk-surface-check` (Makefile :125), so `make help` (checks/make_help.py:27-29
  parses `##`) lists it.
- **P4 (wire-compat citation)**: the regenerated optional keys land in
  `AdminClient` (`docs/sdks/python/client.py:64`, `TypedDict(total=False)`),
  not `ClientMetadata` (:299, which already carries all three fields in both
  committed and regenerated files). The compatibility conclusion is unchanged
  (both classes are `total=False`; TS `AdminClient` members are all
  `?`-optional); only the class name in the changed-surfaces table was wrong
  and is corrected.
- **Accepted gap — committed `dist/` stale after R3**: the committed
  `docs/sdks/typescript/dist/` is built from the stale `client.ts`, so after
  R3 refreshes `client.ts` the committed dist `AdminClient` lacks the three
  optional fields until a maintainer runs `npm run build` and commits. The
  npm-published `@snaplink/sso-client` (`main: dist/index.js`) therefore ships
  without the three optional type declarations until then. Additive-optional
  only — no consumer break — but a real, intended gap, deliberately outside
  the gate (non-goal: "no `dist/` staleness check"). The commit message
  records it (section 6, step 9) so a future maintainer does not "fix" the
  gate by re-enabling dist checks.

## 2. Design decisions

- **D1 — Regenerate to a temp dir, never in place.** `run()` creates a
  `tempfile.TemporaryDirectory`, runs `go run ./cmd/gensdk --lang=all
  --out-ts=<tmp>/client.ts --out-py=<tmp>/client.py`, byte-compares, and lets
  the context manager delete the temp dir. Semantically identical to
  regenerate-then-`git diff` (the acceptance's wording), but a failing gate
  leaves the working tree byte-for-byte untouched — `make ci` failure states
  stay clean and reproducible.
- **D2 — Two legs, one command.** `sdk-drift check` runs the regeneration
  leg (R1) then the deploy-tree sweep (R2). Both must pass for exit 0. The
  deploy leg prints `SKIP` and returns success when `static/` is absent
  (fresh CI checkout), fails when present-but-partial or stale.
- **D3 — Cleanliness check scoped to generator-relevant paths.** After the
  byte compares, run `git status --porcelain -- docs/sdks/` with pathspec
  exclusion `:(exclude)docs/sdks/typescript/dist` and fail on any output.
  This catches new/renamed files the generator might emit in the future
  (e.g., an extra language) and uncommitted SDK edits, without reacting to
  the TS build toolchain.
- **D4 — Test seams via monkeypatchable module constants.** `ROOT` (repo
  root) and `REGEN_CMD` (`["go", "run", "./cmd/gensdk", "--lang=all"]`) are
  module-level; unit tests monkeypatch both to a fixture tree and a fake
  generator (a `python -c` snippet that copies fixture bytes to the
  `--out-*` paths). Inner functions take explicit `root`/`tmp` parameters so
  they are pure and directly unit-testable, matching the
  `checks/adapters_check.py` style.
- **D5 — Byte compare via `difflib`-capped samples.** Equality is
  `bytes.read_bytes() == expected.read_bytes()` (no `cmp(1)` dependency, no
  CRLF/encoding surprises). Failure output names the pair and shows the
  first 10 unified-diff lines per file (capped for the 18k-line spec).
- **D6 — Deployment order is sibling-agnostic.** The generator ignores the
  spec's `servers:` list (E13), so the sibling direction's `docs/openapi.yaml`
  purge cannot change generator output; R3's refresh simply copies whichever
  canonical `docs/openapi.yaml` is current. If the sibling lands after this
  change, its spec edit makes the deploy copy stale and the sweep fails until
  the copy is refreshed — a deliberate, visible consequence of the gate.

## 3. API changes

### New surfaces

| Surface | Shape | Contract |
|---|---|---|
| CLI command | `python cli.py sdk-drift check` | exit 0 = both legs pass; 1 = any drift/failure (messages name the offending path pairs); 2 = unknown action/usage error (argparse raises `SystemExit(2)`; verdict contract stays 0/1, P3) |
| Python module | `checks/sdk_drift.py` — `run(args: list[str]) -> int`; `check_regen(root: Path, tmp: Path, regen_cmd: list[str]) -> list[str]`; `check_deploy(root: Path) -> tuple[list[str], bool]` (failures, skipped); `run_git(args: list[str], cwd: Path)` thin subprocess seam | Pure functions; module constants `ROOT`, `REGEN_CMD`; verdict only 0/1/2; `run_git` is the monkeypatch target for F8 |
| Make target | `sdk-drift-check: ## <help text>` → `$(CLI) sdk-drift check` | New prerequisite of `ci:` (line 268, after `sdk-surface-check`); added to `.PHONY` (line 16); `##` comment so `make help` lists it (N3) |
| Registry doc | `docs/agent-os/CHECKS_REGISTRY.md` | Table row after `self_test.py` (end of the checks block, :28) + `sdk-drift check` in the "Specific checks" group (:45) (N2) |

### Changed surfaces

| File | Change | Compatibility |
|---|---|---|
| `cli.py` | help block entry (:40, beside `sdk-surface`), `cmd_sdk_drift(args)` (pattern `cmd_sdk_surface` :275-278), `"sdk-drift"` in COMMANDS (:356 area), `"sdk-drift"` in the arg-passthrough tuple (:388) | Additive; existing commands untouched |
| `Makefile` | `.PHONY` (:16), new target beside `sdk-surface-check` (:125-126), `ci:` (:268) | Additive; `sdk-surface-check` semantics unchanged |
| `docs/sdks/typescript/client.ts` | R3 regeneration: +8 lines (2 hunks) | Additive optional TS fields (`?`-suffixed) — source-compatible for consumers |
| `docs/sdks/python/client.py` | R3 regeneration: +5 lines (2 hunks) | `AdminClient` is `TypedDict(total=False)` (client.py:64) — new keys are optional; source-compatible (P4) |
| `ops/deploy/openresty/fullstack/static/docs/{openapi.yaml,sdks/client.ts,sdks/client.py}` | R3 refresh: `cp` from canonical (working tree only; untracked by design) | Not committed; restores byte-identity with canonical |

### Explicitly unchanged

`cmd/gensdk/*.go`, `ops/scripts/sdk_surface.py` (check semantics frozen),
`docs/openapi.yaml` content (sibling direction's scope), `interfaces/sso/*`,
`shared/core/*`, no new `Err*` codes, no config keys, no routes.

## 4. Compatibility constraints

- **No wire/security surface**: the gate compares artifacts only; no
  credential-endpoint, discovery, or oracle behavior is touched.
- **Fresh checkout must pass**: the deploy leg SKIPs when `static/` is
  absent, so `make ci` on a clean clone is green without the external
  pipeline output.
- **Determinism is load-bearing**: a nondeterministic generator would flap
  the gate. It is verified deterministic today (E7) and pinned by a test
  (acceptance case 8); a future generator change that introduces
  nondeterminism fails the pin, not `make ci` with a confusing diff.
- **Rollback is trivial**: the gate is additive; reverting the commit
  removes the wiring and the artifact refresh. The refreshed SDKs are
  forward-only in the additive-field sense — old consumers still compile.
- **CI cost**: one extra `go run` per `make ci` (~seconds); the Go build
  cache is warm because `ci:` runs `build` first, and `go run` build-cache
  concurrency is safe if `-j` is used.
- **Interaction with sibling direction** (`cmd-gensdk-b4-3-discovery-truthiness`):
  that change edits `docs/openapi.yaml` only; the generator ignores
  `servers:`, so no regeneration is needed on either ordering. If the sibling
  lands second, its spec edit makes the deploy copy stale and the sweep fails
  until the copy is refreshed (D6) — coordination note in section 6.

## 5. Failure modes

| # | Mode | Gate behavior | Design response | Coverage test |
|---|---|---|---|---|
| F1 | Go toolchain missing / `go run` build failure | Fail leg 1 with the generator's stderr | CI always has Go (`ci:` builds first); message distinguishes generator failure from drift | `test_generator_failure_reports_stderr` |
| F2 | Generator nondeterminism | Flapping gate | Determinism pin test (case 8) catches it at `check-test` time | `test_real_gensdk_determinism` (case 8) |
| F3 | Deploy tree absent (fresh checkout) | SKIP, exit 0 with note | Required by design; asserted by case 4 | `test_absent_deploy_tree_skips` (case 4) |
| F4 | Deploy tree partial (one target missing) | FAIL naming the missing target | Present-but-incomplete is drift by contract | `test_deploy_tree_missing_target_fails` (parametrized over the 3 targets) |
| F5 | Deploy tree stale (external pipeline regenerated without refresh) | FAIL naming each stale pair | Intended; remediation = `cp` canonical copies (section 6) | `test_stale_deploy_{openapi,ts,py}_fails` (case 3) |
| F6 | Local TS build dirties `docs/sdks/typescript/dist/` | Would fail a blanket `git status` scan | P2: `dist/` excluded from the cleanliness pathspec | `test_dist_dirt_does_not_fail` |
| F7 | Uncommitted edits / stray files under `docs/sdks/` (excl. `dist/`) | FAIL naming the paths | The R1 cleanliness check; also catches future extra languages | `test_stray_file_under_docs_sdks_fails` |
| F8 | `git` unavailable in the environment | Cleanliness leg reports failure with a clear message | Fail-closed (repo discipline requires git; `check-test` runs in a git checkout) | `test_git_unavailable_fails_closed` |
| F9 | Working-tree spec edited without regenerating SDKs | Regeneration embeds the working-tree spec (E13) → mismatch → FAIL | This is GWT5: the future-drift block the direction exists for | `test_stale_committed_{ts,py}_fails_naming_path` + `test_makefile_ci_includes_sdk_drift_check` (case 5) |
| F10 | Temp-dir leak on failure | None | `TemporaryDirectory` context manager deletes on all paths | `test_temp_dir_cleaned_on_failure` |
| F11 | Huge diff sample (18k-line spec) | Report bloat | Sample capped at 10 unified-diff lines per pair | `test_diff_sample_capped` |

## 6. Migration steps (ordered)

1. **Create `checks/sdk_drift.py`** — `ROOT`/`REGEN_CMD` constants, `run`,
   `check_regen`, `check_deploy`, usage parsing (`check` action only;
   argparse so unknown actions exit 2). Output lines:
   `sdk-drift: OK (regen 2/2, deploy 3/3)` /
   `sdk-drift: SKIP deploy leg (static tree absent)` /
   `sdk-drift: FAIL <path> (regen|deploy mismatch)` + capped diff sample.
2. **Create `checks/test_sdk_drift.py`** — the 9 acceptance mappings plus the
   F1-F11 coverage matrix (section 7); fixture tree via git-initialized
   `tmp_path`, fake generator via `REGEN_CMD` monkeypatch with a payload
   file, real-generator determinism test `skipif` no `go` on `PATH` with
   `GOPROXY=off`.
3. **R3 remediation — committed SDKs**: `go run ./cmd/gensdk --lang=all`
   (defaults write `docs/sdks/typescript/client.ts`,
   `docs/sdks/python/client.py` in place). Diff is exactly the +8/+5 additive
   lines (E9). Commit these in the same change as the gate.
4. **R3 remediation — deploy copies** (working tree only, never committed):
   `cp docs/openapi.yaml static/docs/openapi.yaml`; `cp
   docs/sdks/typescript/client.ts static/docs/sdks/client.ts`; `cp
   docs/sdks/python/client.py static/docs/sdks/client.py`. If the sibling
   direction has not yet landed, run this step again after it does (D6).
5. **Wire `cli.py`**: help entry, `cmd_sdk_drift`, COMMANDS entry, passthrough
   tuple (section 3).
6. **Wire `Makefile`**: `.PHONY` token, `sdk-drift-check` target beside
   `sdk-surface-check` with a `##` help comment (N3), `ci:` prerequisite after
   `sdk-surface-check`.
7. **Wire `docs/agent-os/CHECKS_REGISTRY.md`**: table row after `self_test.py`
   (end of the checks block, N2) + "Specific checks" group entry.
8. **Verify**: `python cli.py check-test` (new tests green);
   `python cli.py sdk-drift check` → 0 on the remediated tree; seed-stale
   drills (delete one line from a committed SDK and from a deploy copy) →
   exit 1 naming the paths; restore; `make -n ci` shows `sdk-drift-check`;
   `python cli.py sdk-surface check` → still 0; full `make ci`.
9. **Commit** (conventional, imperative; AI co-author trailer):
   `feat(ci): add SDK regeneration-drift and deploy-tree sweep gate`.
   Commit body records the accepted gap: committed `docs/sdks/typescript/dist/`
   is stale w.r.t. the refreshed `client.ts`, so `@snaplink/sso-client` ships
   without the three optional `AdminClient` fields until a maintainer runs
   `npm run build` and commits — the gate deliberately excludes `dist/` and
   must not be "fixed" by re-enabling dist checks. Rollback = revert this
   commit; the gate is additive and the SDK refresh is additive-optional only.

## 7. Testable acceptance mapping

The spec's 9 Given/When/Then cases map to concrete pytest tests in
`checks/test_sdk_drift.py` (run via `python cli.py check-test`, cli.py:200-204):

| # | Acceptance case | Test | Assertion |
|---|---|---|---|
| 1 | Clean tree → exit 0 | `test_clean_tree_passes` (fixture tree: committed == fake-regen bytes, deploy copies == canonical) | `run(["check"]) == 0`; output has `OK (regen 2/2, deploy 3/3)` |
| 2 | Seeded stale committed TS / PY → fail, name path; after restore → exit 0 | `test_stale_committed_ts_fails_naming_path`, `test_stale_committed_py_fails_naming_path` | exit 1; message contains `docs/sdks/typescript/client.ts` / `docs/sdks/python/client.py`; after restoring the seeded byte, re-run → 0 |
| 3 | Seeded stale deploy copy → fail, name pair (3 targets); after restore → exit 0 | `test_stale_deploy_openapi_fails`, `test_stale_deploy_ts_fails`, `test_stale_deploy_py_fails` (parametrized over the 3 pairs) | exit 1; message contains the deploy path and its canonical source; after restoring, re-run → 0 |
| 4 | Deploy tree absent → skip, exit 0 | `test_absent_deploy_tree_skips` | exit 0; output contains `SKIP` |
| 5 | Future drift blocks `make ci` | `test_stale_*` (2/3) + `test_makefile_ci_includes_sdk_drift_check` (parse Makefile :268 prerequisites) | prereq list contains `sdk-drift-check`; stale seeds fail the gate itself |
| 6 | Wiring inspection | `test_cli_wiring` (COMMANDS dict, passthrough tuple, help text), `test_makefile_wiring` (`.PHONY` + target), `test_unknown_action_usage_error` | entries present; `pytest.raises(SystemExit)` from `run(["bogus"])` with code 2 (argparse `choices=["check"]` raises; run() may also catch and return 2 — either satisfies the CLI exit-2 contract, P3) |
| 7 | `check-test` green | the suite itself | pytest exit 0 under `cli.py check-test` |
| 8 | Determinism pin | `test_real_gensdk_determinism` (`skipif` no `go` on PATH; `monkeypatch.setenv("GOPROXY", "off")` so the no-network property is explicit): two `go run ... --out-ts=A --out-py=A` vs `--out-ts=B --out-py=B` | both outputs byte-identical |
| 9 | No regression to `sdk-surface check` | `test_sdk_surface_wiring_untouched` (cli.py still routes `sdk-surface` to `cmd_sdk_surface`; `sdk_drift` does not import `sdk_surface`) | source-level assertions; plus step-8 manual `sdk-surface check` → 0 |

### Failure-mode coverage matrix (F1–F11)

Every failure mode from section 5 has at least one coverage test asserting the
stated expected gate behavior; the four GWT-mapped ones reuse the case tests,
the seven standalone ones are added beside them:

| F | Coverage test | Expected gate behavior asserted |
|---|---|---|
| F1 | `test_generator_failure_reports_stderr` | fake REGEN_CMD exits 1 with stderr → `run(["check"]) == 1`; output contains the stderr text and does not claim drift |
| F2 | `test_real_gensdk_determinism` (case 8) | two temp-dir regenerations byte-identical |
| F3 | `test_absent_deploy_tree_skips` (case 4) | exit 0, `SKIP` note |
| F4 | `test_deploy_tree_missing_target_fails` | one of the 3 deploy targets absent (static/ present) → exit 1, message names the missing path |
| F5 | `test_stale_deploy_{openapi,ts,py}_fails` (case 3) | exit 1 naming the deploy path and its canonical source |
| F6 | `test_dist_dirt_does_not_fail` | untracked file under `docs/sdks/typescript/dist/` → still exit 0 |
| F7 | `test_stray_file_under_docs_sdks_fails` | untracked stray under `docs/sdks/` (outside dist/) → exit 1 naming it |
| F8 | `test_git_unavailable_fails_closed` | `run_git` seam returns exit 128 → exit 1 with a clear git-error message |
| F9 | `test_stale_committed_{ts,py}_fails_naming_path` + `test_makefile_ci_includes_sdk_drift_check` (case 5) | stale committed seed → exit 1 naming the SDK path; `ci:` prereq list contains `sdk-drift-check` |
| F10 | `test_temp_dir_cleaned_on_failure` | failing run() with `tempfile.tempdir` pointed into tmp_path → scratch dir empty afterward |
| F11 | `test_diff_sample_capped` | stale seed with a >10-line diff → failure output shows at most 10 diff lines plus a cap marker |

Deploy-leg fixture helpers: `make_deploy_tree(root)` builds the three
canonical/deploy pairs from the same bytes; `make_stale(path)` appends a byte
to one target. No test writes to the real repo tree (all under `tmp_path` with
`ROOT` monkeypatched; wiring tests read `Makefile`/`cli.py` only). Fixture
mechanics, each verified against the real cli.py/sdk_surface.py structure:

- **Git-in-fixture (required)**: the regen leg's cleanliness scan runs a real
  `git status --porcelain`; git exits 128 outside a repository (verified), so
  every run()-level test initializes the fixture as a repo first
  (`git init -q`; `git add -A`; `git -c user.name=t -c user.email=t@t commit
  -q -m init` — local only, no network, verified working). This keeps the
  F6/F7 assertions honest: the `:(exclude)docs/sdks/typescript/dist` pathspec
  exclusion and stray-file detection are exercised against real git output
  (both verified above), not a stub. F8 is the only test that stubs the seam
  (`sdk_drift.run_git`, simulating exit 128).
- **Non-tautological fake generator**: `REGEN_CMD` is monkeypatched to
  `[sys.executable, "-c", <snippet>, <payload-path>]`; the snippet parses the
  appended `--out-ts=`/`--out-py=` flags and copies the payload file (which
  lives outside the compared paths, e.g. `tmp_path/payload`) to each target.
  Clean tests set the committed fixture bytes equal to the payload, so the
  byte-compare is real, not self-referential; stale tests mutate the committed
  copy (or deploy copy) so the payload diverges.
- **Wiring tests resolve against the real tree**: check-test runs
  `python -m pytest checks/` with cwd=repo root (cli.py:200-204), which puts
  cwd on sys.path — `import cli` and `from checks.sdk_drift import ...` both
  resolve (verified). The passthrough tuple is inline in `main()` (cli.py:388),
  so the wiring assertion is source-text based (`'"sdk-drift"'` present in
  that region) plus `cli.COMMANDS["sdk-drift"] is cli.cmd_sdk_drift`.
- **Output capture**: run()-level tests use `capsys` for the `OK (regen 2/2,
  deploy 3/3)`, `SKIP`, and FAIL-path substring assertions; failure messages
  use repo-relative paths so assertions are root-independent.

## 8. Files

### Create

```text
checks/sdk_drift.py — gate module (section 3): regeneration leg to temp dir
    + byte compares + git-status cleanliness (dist/-excluded); deploy-tree
    sweep leg (3 pairs, SKIP-when-absent); run() -> int; run_git seam;
    capped diff samples.
checks/test_sdk_drift.py — pytest: 9 acceptance mappings + F1-F11 failure-
    mode coverage matrix (section 7); git-initialized tmp_path fixtures;
    fake generator via monkeypatched REGEN_CMD with a payload file; real-
    generator determinism test skipif no Go toolchain with GOPROXY=off.
docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-design.md — this document.
```

### Modify

```text
cli.py — help entry; cmd_sdk_drift; COMMANDS entry; passthrough tuple.
Makefile — .PHONY (:16); sdk-drift-check target (:125-126); ci: (:268).
docs/agent-os/CHECKS_REGISTRY.md — table row after self_test.py (:28); command group (:45).
docs/sdks/typescript/client.ts — regenerated (R3; +8 additive lines).
docs/sdks/python/client.py — regenerated (R3; +5 additive lines).
ops/deploy/openresty/fullstack/static/docs/{openapi.yaml,sdks/client.ts,
    sdks/client.py} — refreshed to canonical (working tree only, untracked).
```

### Do not modify

```text
cmd/gensdk/*.go — generator untouched; the gate guards its output.
ops/scripts/sdk_surface.py — sdk-surface check semantics frozen.
docs/openapi.yaml — content is the sibling direction's scope; the sweep
    compares against it as-is.
interfaces/sso/*, shared/core/*, docs/sdks/typescript/dist/ — untouched.
```

## 9. Engineering-gate posture

- No Go changes: Go budgets, `interfaces/sso` 60-file ceiling, import
  direction, and the architecture gates are unaffected; the mandatory
  post-edit Go verification is unchanged.
- `checks/` gains two files in the existing flat directory — no fan-out or
  depth change.
- The gate is fail-closed where it can verify and skip-only where the input
  is legitimately absent (F3); every failure names the offending path pair so
  remediation is mechanical (section 6, step 4).
