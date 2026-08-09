Validation complete. The design document has been amended in place (it's the untracked campaign deliverable, `??` in git status; the other untracked entries are campaign bookkeeping I did not touch).

## Validation verdict

### A. 9 GWT cases → runnable pytest assertions: **confirmed, with 3 mechanical amendments (now incorporated)**

Verified against real structure: `sdk_surface.py:129-151` (`check` at 129-137, `generate` at 146-151 — confirmed), `cli.py:200-204` (`check-test` runs `python -m pytest checks/` with cwd=repo root), `cli.py:275-278` (`cmd_sdk_surface`), `cli.py:356` (COMMANDS), `cli.py:388` (inline passthrough tuple), `Makefile:16/125-126/268`, `CHECKS_REGISTRY.md:31/:45`, gensdk `--lang=all` + `--out-ts/--out-py` flags (main.go:67-74, 99-105). All 9 rows map to feasible tests, but three needed mechanism fixes:

1. **Git-in-fixture (required)** — proven: `git status` exits 128 outside a repo, so the regen leg's cleanliness scan would fail every `run(["check"])` test in a bare `tmp_path`. Fixture must `git init` + commit (`-c user.name/email` — verified working, offline). Bonus: F6's `:(exclude)docs/sdks/typescript/dist` pathspec and F7's stray-file detection were **proven against real git** (exclusion empty, `?? docs/sdks/python/extra.md` detected).
2. **Unknown action** — argparse `choices=["check"]` raises `SystemExit(2)`; assertion must be `pytest.raises(SystemExit)` (or `run()` catches it) — "run(["bogus"]) != 0" alone isn't an executable assertion.
3. **Inline passthrough tuple** — the tuple at cli.py:388 is a literal inside `main()`, not a module constant; wiring assertion must be source-text based. Also added: `GOPROXY=off` to the determinism test (no-network explicit, not incidental), restore-legs to GWT2/GWT3, `capsys` capture, and a `run_git` seam (section 3 API).

### B. Monkeypatched ROOT/REGEN_CMD fixtures: **feasible, no network, no repo writes**

Verified: `import cli` resolves under `python -m pytest` (cwd on sys.path — `cli.COMMANDS["sdk-surface"]` import succeeded), `checks/` is a regular package (`__init__.py`), pytest runs green (`checks/test_route_contract.py` 5 passed), fake generator via `python -c` snippet + payload file outside compared paths is non-tautological, all fixture state under `tmp_path`.

### C. F1–F11 coverage: **4 covered, 7 gaps found and fixed**

Covered as designed: F2 (case 8), F3 (case 4), F5 (case 3), F9 (case 5). **Missing: F1, F4, F6, F7, F8, F10, F11** — notably F4 (partial deploy tree) was required by the requirements' own R5 ("missing target → non-zero") but unmapped in the design's section 7.

**Fixes applied to `docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-design.md`:**
- Section 5: added a **Coverage test** column to the F1–F11 table (all 11 rows).
- Section 7: added the **Failure-mode coverage matrix (F1–F11)** with expected-gate-behavior assertions per mode; amended the fixture-strategy paragraph with the verified mechanics; fixed GWT rows 2/3/6/8.
- Sections 3/6/8: `run_git` seam in the API table, updated test-creation step and file manifest.

Only the design doc changed — no Go edits, so no `go build`/gates were triggered. The auto-run campaign snapshot (`auto/runs/.../task-1-design.md`) was left as the immutable record; the live deliverable now carries the corrections.
