Review complete. All claims independently verified by direct inspection and execution.

## Verdict: conforms — all convention claims hold; no gate crossed

### 1. cli.py line references (all exact)

| Claim | Measured |
|---|---|
| `cli.py:40` | `sdk-surface` help entry — confirmed (line 40 of the docstring) |
| `cli.py:275` | `def cmd_sdk_surface(args: list):` → imports `sdk_surface.run`, returns it (:277–278) — confirmed |
| `cli.py:356` | `"sdk-surface": cmd_sdk_surface,` in COMMANDS — confirmed |
| `cli.py:388` | passthrough tuple `("skill", "configure", "modules", "capabilities", "sdk-surface", "profiles")` — confirmed |

The design's four cli.py edits (help entry, `cmd_sdk_drift`, COMMANDS entry, tuple) mirror this pattern exactly.

### 2. Exit-code semantics 0/1/2 — real, empirically verified

- `python cli.py sdk-surface check` → **0**; `sdk-surface bogus` → **2** (argparse `choices` → `parser.error` → uncaught `SystemExit`); unknown top-level command → **1** (cli.py:387).
- The design's P3 is accurate: `sdk_drift` unknown action → 2 via the identical `sdk_surface.py` precedent (argparse + `choices`). R5's literal "only 0/1" is reconciled by P3 and acceptance #6's weaker "≠ 0" — documented deviation, no conflict.
- **N1 (nit)**: acceptance case 6's `run(["bogus"]) != 0` is imprecise — argparse *raises* `SystemExit(2)` rather than returning; the test must use `pytest.raises(SystemExit)` with `code == 2` (or run() must catch and return 2). Observable CLI exit is 2 either way.

### 3. Registry rows — confirmed, one cosmetic nit

- `CHECKS_REGISTRY.md:31` = `sdk_surface.py` row; `:45` = "Specific checks" group. Correct group choice (`sdk-drift` is check-only; "Module builds" at :50 is for generate/list actions).
- **N2 (nit)**: the table lists all `checks/*` rows before `ops/scripts/*` rows; "after sdk_surface.py" drops a `checks/sdk_drift.py` row into the ops/scripts block. End of the checks block (after `self_test.py`) matches the grouping better.

### 4. Make wiring — confirmed

- `.PHONY` main list at :16 (the :547 `.PHONY` is a separate list — :16 placement correct); `sdk-surface-check` target :125–126 (`##` comment + `$(CLI) sdk-surface check`; `CLI = python cli.py` at :14); `ci:` at :268. `ci:` has no strict ordering (profiles-evidence, adapters-check already follow sdk-surface-check), so "after sdk-surface-check" is consistent. No existing test asserts the `ci:` line, so nothing breaks.
- **N3 (nit)**: give `sdk-drift-check` a `##` help comment so `make help` (make_help.py) lists it — implied by "beside sdk-surface-check" but worth stating explicitly.

### 5. `run() -> int` precedent — confirmed

`checks/route_contract.py:217`, `checks/adapters_check.py:137` (also `root_business_code.py:28`, `exemptions.py:14`). Note (consistent with sdk_surface.py): the unknown-action path raises SystemExit rather than returning — `run() -> int` holds for verdict paths.

### 6. Additive-only claim — independently re-verified

- Ran `go run ./cmd/gensdk --lang=all` to temp dirs: committed-vs-regenerated diff is exactly **TS +8 lines/2 hunks** (`client_secret_expires_at?`, `grant_types?`, `tenant_id?`, all optional) and **PY +5 lines/2 hunks** (`TypedDict` keys — `ClientMetadata` is `total=False`). Two runs **byte-identical** (determinism holds).
- `docs/sdks/typescript/dist/` is committed (6 files) → the P2 `:(exclude)docs/sdks/typescript/dist` pathspec is *required* and sanctioned by the explicit "no dist/ staleness check" non-goal (requirements :51). Deploy copies are untracked working-tree files — nothing new is committed beyond cli.py/Makefile/registry/checks/ + the two regenerated SDKs.
- Non-goals all respected: no `cmd/gensdk/*.go`, `sdk_surface.py` frozen, `docs/openapi.yaml` content untouched, no static/ tracking, no legacy-literal scanner.

### 7. No engineering gate crossed

- `checks/filesize.py` only scans `*.go` (`path.suffix != ".go": continue`) — the new Python module isn't budgeted; even if it were, ~200 lines ≪ 500.
- `root_policy` (`max_files: 15`, allowed_files/allowed_prefixes) governs root-level files only; new files land in `checks/` (flat, no subdirs — `directory_fanout` gates subdirs, untouched).
- No Go changes → Go budgets, `interfaces/sso` 60-file ceiling, import direction, architecture gates all unaffected. HARNESS.md's "Adding a check" requirements (unit test + cli.py exposure + blocking/reporting documentation) are all satisfied; the Makefile/CI split matches the registry's "Specific checks" category.

**Bottom line**: design conforms to HARNESS.md/CHECKS_REGISTRY.md conventions on every cited point; exit-code 0/1/2 matches the live `sdk-surface` behavior; additive-only verified byte-for-byte; no budget, root_policy, fan-out, or architecture gate is crossed. Three non-blocking nits (N1 pytest phrasing, N2 registry row grouping, N3 `##` help comment) are worth folding into the migration steps before implementation.
