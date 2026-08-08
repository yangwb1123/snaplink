Execution complete. Full report:

# Empirical execution report

**Final helper shape** (the run dir contained no `final_text_auditor` artifact, so the helper/template were assembled per the three reviewers' mandated corrections): `assertGrantScopeGateClaims` asserts 7 items — 4 ordering markers (`GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, `h.Roles(` — the test_plan_reviewer's vacuity fix) each before `issuer.Issue(`; `grantedScopes)` presence; `}, scopes)` ban; `TenantID: client.TenantID` pin; `Roles:\s+roles` projection (regexp, gofmt-safe). Template text applies all reviewer fixes: no backticks inside the raw string (F2), no `:46` line citation (F1), internal-mint `RejectUnregistered` scoping sentence + AMR-guard rewording + pattern-vs-mint-path/`role.Code`/deliberate-500 notes (security reviewer 1/2A/2B).

## (1) Red-first proof — FAILED AS DESIGNED (7 named errors, TenantID green)

`go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v` with helper+wiring only, template unedited:
```
scaffold_build_test.go:131: grant scaffold: missing per-client scope gate marker "GrantedScopes(" — ...
scaffold_build_test.go:131: grant scaffold: missing scope split marker "SplitScope(" — ...
scaffold_build_test.go:131: grant scaffold: missing invalid_scope error marker "core.ErrInvalidScope" — ...
scaffold_build_test.go:131: grant scaffold: missing roles source marker "h.Roles(" — ...
scaffold_build_test.go:131: grant scaffold: issuance does not pass the validated grantedScopes set — ...
scaffold_build_test.go:131: grant scaffold: issuance passes raw request scopes (}, scopes)) — the B4-2 bypass pattern is back
scaffold_build_test.go:131: grant scaffold: the Subject literal does not project the resolved roles (Roles: roles) — ...
--- FAIL: TestGeneratedScaffoldsCompile/grant
```
**Corrected premise confirmed with exact counts**: the final helper asserts 7 markers — 6 absent pre-edit (`GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, `h.Roles(`, `grantedScopes)`, `Roles: roles`), the banned `}, scopes)` present, and the `TenantID: client.TenantID` pin already green (its assertion did **not** fire). Authenticator/store/handler kinds PASS.

## (2) Template applied — GREEN

All 4 kinds pass (grant now runs gate claims + isolated build/vet). Artifact inspection: all four markers precede `issuer.Issue(` (3255/3275/3384/4547 vs 5138), `grantedScopes)` present, `}, scopes)` zero occurrences. `TestRunExitCodes` green (2/1/0). `gofmt -l` clean; `grantTemplate` contains zero backticks.

## (3) Full §9 suite

| Command | Result |
|---|---|
| `go build ./... && go vet ./...` | **PASS** |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | **FAIL — pre-existing** (proven byte-identical with my changes stashed): `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go` 539 lines, committed at HEAD `7586c6b3`, untouched); `TestArchitecture_DirectoryDepth` + `TestArchitecture_DirectorySubdirFanout` (docs fan-out 18/292 subdirs, root 24>21 — campaign artifacts/untracked dirs) |
| `go test ./cmd/sso-ctl/... -race` | `cmd/sso-ctl/generate` **ok** (1.491s). **FAIL — pre-existing** in `cmd/sso-ctl` (`TestSubcommands_CheckIsWired`) and `cmd/sso-ctl/apiclient` (check/sweep tests, `iss "snaplink-sso" != discovery issuer`) — the unrelated in-flight check-subcommand worktree change; identical with my changes stashed |
| `make ci` | `fmt`+`vet` pass; **`race` step fails on exactly those 3 pre-existing packages** (`make: *** [Makefile:28: race] Error 1`). All 14 steps after race run individually **PASS**: build, examples, proto-lint, ci-modules, config-validate-all, modules-check, modules-smoke, route-contract (241 routes/348 ops), proto-openapi-parity, capabilities-check, sdk-surface-check, profiles-evidence, adapters-check |

## (4) Two-commit sequence — verified empirically

- **Commit A `3f0dd692`** (5 files): verify-gate change + untracked `scaffold_contract_test.go`. Alone: package compiles, `TestGeneratedScaffoldsCompile` (4 kinds) + `TestRunExitCodes` green, zero grant markers in the diff (byte-reconstructed and diff-checked against the pre-Phase-1 state).
- **Commit B `7884230e`** (3 files: `templates_handler.go`, `scaffold_build_test.go`, `scaffold_contract_test.go`): green alone — `TestGeneratedScaffoldsCompile` (grant subtest with assertions + hermetic build/vet) + `TestRunExitCodes` PASS.
- **No committed scaffold regenerates**: no `*_grant.go`/`*_handler.go` generator artifacts exist in `git ls-files cmd/sso-ctl/generate/`; the test writes only to `t.TempDir()`.
- **No CLI surface touched**: `git diff --name-only 3f0dd692..7884230e` = exactly the 3 grant files; `cmd.go`/`verify.go` untouched by B.
- **`TestRunExitCodes` still 2/1/0**: PASS in both commit states.

**Gate failures (all pre-existing, none attributable to this change)**: the maintainability/architecture tests, `cmd/sso-ctl` + `apiclient` race failures, and the `make ci` race blocker — each reproduced identically with the generate-package changes stashed.
