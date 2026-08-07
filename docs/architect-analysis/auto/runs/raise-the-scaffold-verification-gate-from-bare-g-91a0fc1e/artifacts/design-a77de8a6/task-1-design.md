Design complete at `docs/architect-analysis/auto/runs/raise-the-scaffold-verification-gate-from-bare-g-91a0fc1e/artifacts/design-a77de8a6/task-1-design.md`.

## Evidence verification — all claims re-checked against HEAD, all hold

Every citation in the requirements was independently re-measured: `verify.go:35` bare `go build`; `scaffold_build_test.go:107-116` build-only isolated-module gate (baseline `ok, 0.088s`); `not_implemented`/`method_not_allowed`/`create_failed` zero hits in `docs/error-codes.md` + `shared/core`; sole `ctx.Bind` at `templates_handler.go:73` with no Content-Type guard; `TestOIDCDiscovery*` grep exit 1; `server_discovery.go:251`/`consts.go:9,21-23`; 250 doc rows, 143 `Path*` consts, 501+`ErrNotSupported` at `governance.go:462`. I additionally **empirically proved the R1a core feasibility**: `go vet ./...` passes in a `newBuildableModule`-identical scratch module (0.05s warm) and flags an injected unused variable.

## New constraints found (design resolves two spec inconsistencies)

- **C1**: R4a's "strings import joins the generated handler's import block" is unsatisfiable as written — an uncommented `strings` import used only inside the commented example fails `go build` ("imported and not used"), breaking the very compile gate R1a preserves. Resolved: the import joins the block **commented** with a pointer to the guard example.
- **C2**: `core.Context.Bind` is **JSON-only** (`router.go:138`), so the guard must be teaching text in the commented POST example, never active stub code — an active form-only guard would contradict the repo's business-handler posture and B4-4's credential-endpoint-only scope.
- **C3**: guard teaches `strings.HasPrefix(ct, "application/x-www-form-urlencoded")` (precedent `server_login_resolve.go:425`), tolerating `;charset=UTF-8` per B4-4's settled `normalizedMediaType`, and rejecting missing CT (T-8(c) mirror).
- **C4/C5**: pre-existing absolute-`--output` "outside main module" quirk (new unit test must chdir); caller message widened to "does not build or pass vet" (flagged micro-deviation).
- **Registry numbers corrected**: 133 string-valued `ErrX = "…"` consts (149 includes 16 `errors.New` sentinels).

## Design summary

- **API**: zero CLI/wire/config changes; `--skip-build-check` name+semantics unchanged (skips both); exit codes 0/1/2 unchanged; help text + one error sentence widened. `verifyGeneratedBuild` loops `go build` then `go vet` on the same target (40→~46 lines). Generated handler output: 4×501→`ErrNotSupported`, 405→`ErrInvalidRequest`, `create_failed`→`ErrInternal`, wiring comment cites `core.PathUserInfo` (no literals), commented guard+import. New test-only `scaffold_contract_test.go` (parsers + 4 named assertions + `TestVerifyGeneratedBuildVet` + `TestRunExitCodes`); kind subtests gain vet exec.
- **Failure modes**: 12 enumerated (F1–F12), including doc-format-drift parse floor (≥200 codes), template regression naming, operator-package vet blast radius (same as build today, bypass unchanged).
- **Migration**: 9 ordered steps ending in `make ci`; 9-mutation pass (m1–m9) with exact named-assertion mapping; single-commit rollback.
- **Acceptance mapping**: all 9 Given/When/Then cases mapped to concrete tests/mutations; R2's raw-string path kept live via the GET example's registered `"not_found"` (spec-permitted).
