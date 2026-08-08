All facts verified. Here is the gate audit of the plan as amended by the reviewer fixes.

## 1. Baseline measured (worktree at `3223d12a` + concurrent-task dirty files)

I ran the committed gates directly. Pre-existing failures at HEAD/worktree, all unrelated to this plan (report per AGENTS.md §2):

| Gate | Status | Cause |
|---|---|---|
| `TestMaintainability_FileSizeBudget` | RED | `infrastructure/defaultimpl/ed25519_jwt_issuer.go` 539 lines (539 at HEAD too) |
| `TestArchitecture_DirectoryDepth` | RED | `docs/architect-analysis/auto/runs/<id>` at depth 5 (harness artifacts) |
| `TestArchitecture_DirectorySubdirFanout` | RED | `docs` (18), `docs/architect-analysis/auto/runs` (287), root `.` 24 > frozen 21 |
| `TestSubcommands_CheckIsWired` | RED | `subcommands["check"]` not registered — confirmed F3 exactly |
| `cmd/sso-ctl/apiclient` suite | RED | `TestCheck_AddrValidation`, `TestSweep_GreenPath`, `TestIntrospect_Non401Fails` (exactly F3's list) |
| `TestArchitecture_ImportBoundaries`, `_LayerBoundaries`, `_DirectoryFileFanout` | GREEN | — |
| `clientscmd`, `configcmd` suites | GREEN | — |

Also confirmed: env vars are `SSO_ADMIN_ADDR`/`SSO_ADMIN_TOKEN` (`apiclient.go:27,30`; no `SSO_ADDR` anywhere) — F1 is real and still unfixed in the doc (§3, §7 say `SSO_ADDR`).

## 2. Budgets in `cmd/sso-ctl/clientscmd` — inside, with one wording fix

Key fact I verified in the gate code: **the file-size (500), function-length (50), and cyclo (15) gates exclude `_test.go` files** ("Scope: parent-module, non-generated, non-test .go files… test files are excluded" — `maintainability_budget_test.go`, `maintainability_complexity_test.go`). So all reviewer additions that land in test files (FM-1/FM-3/FM-5/FM-7 tests, stdout-empty assertion, E3 client swap) are not gate-measured. Budget table after the plan lands:

| Budget | After plan | Limit | Verdict |
|---|---|---|---|
| validate.go lines (est. 70–110; fetch + decode + collect + report) | < 500 | 500 | ✅ |
| validate.go functions | split into `runValidate` + fetch/decode + offender-collection helpers | 50 lines, cyclo 15 | ✅ (plan should say offender collection is a helper; the fetch path mirrors `runGet`'s 4 failure branches and would otherwise crowd 50) |
| clients.go | 185 + 1 switch arm + 1 usage line | 500 | ✅ |
| `if` nesting ≤ 3 | no committed nesting gate exists (checked gates + `checks/*.py`); discipline-only. Design is linear guards/early-returns | 3 | ✅ by construction |
| Non-test files/dir | clients.go + validate.go = 2 | 10 (`maxGoFilesPerDir`) | ✅ |
| Total files/dir | 6 | no total-file gate | ✅ |
| Subdirs/dir | 0 (clientscmd), 16 (cmd/sso-ctl — at the committed `maxSubdirsPerDir=16` ceiling, unchanged) | 16 | ✅ |

One correction to the plan's own §8.4: "directory files 5 ≤ 15" conflates the file gate with the subdirectory gate — after the change it's **non-test files 2 ≤ 10, subdirs 0 ≤ 16**. Cosmetic, but fix the wording. The `len(args)>1` guard (U7b) is one `if` in `runValidate` — no budget impact. Edge to pin explicitly: `Run(["validate","--nope"])` (flag as first positional) is treated as client-id → 404 → exit 1, mirroring `runGet`; the plan should say it locks that behavior so nobody "fixes" it later.

## 3. Directory fan-out — no delta

Plan adds zero new directories anywhere; no new top-level/internal package, so no `layerName()` classification and no `layerExemptions` entry. `interfaces/sso` 60-file ceiling untouched (consumed, not modified). `clientscmd` gains downward imports only (`interfaces/scopecontract`, `protocols/oauth/scoperegistry`; composition → interfaces/protocols — `architecture_layer_test.go:71` classifies `cmd` as composition).

## 4. consts.go placement — real gap in the current doc

The plan never says where the `validate: OK` message, offender-line template, and exit-code literals live. Facts: **no `consts.go` exists in clientscmd or in any `cmd/sso-ctl` subpackage** (checked all 16); the module convention is a package-level `const progName` in `clients.go` plus inline message/exit-code literals (identical in `configcmd`, `sessionscmd`, `tokenscmd`, `entitiescmd`). AGENTS.md §6's "put paths, headers, and error codes in consts.go" is not gate-enforced (the `consts.go` at `engineering.yaml:229` is an `interfaces/sso` naming/placement exemption list; `adapters_check.py` covers wire `Err*` consts only). Verdict: the final plan must make a one-sentence placement decision — a `const` block in `validate.go` for the message literals and exit-code ints (satisfies "avoid literal leaks" without adding a file, keeps non-test count at 2) — and state that it deliberately does not extract pre-existing literals in `clients.go` (no "while here" cleanup per AGENTS.md §6). As written, the doc is silent; that's the gap to close, not a budget violation.

## 5. Subcommands-map pin + check dispatch — the F3 repeat is in the current doc

- **validate needs no main.go pin**: verified `main.go:50` → `subcommands["clients"] = clientscmd.Run`, and validate is a switch arm inside `Run` (same as list/get). The plan's "subcommands map unchanged" (§4, §8.3) is correct, and the pin that prevents an F3-class recurrence is U1–U9 invoking `Run(["validate",…])` — the plan should say that explicitly rather than just asserting no-change.
- **F3 is currently repeated**: §3 and FM-5/FM-7 mitigation tell operators to "gate with `sso-ctl check`", but `check` is **unreachable from the binary at HEAD** (verified: no map entry, no usage line, `TestSubcommands_CheckIsWired` red; `apiclient.CheckRun` exists but only `dispatch_test.go` and `clientscmd/e2e_test.go` reference it). The plan must (a) state **fixing check's dispatch is OUT of scope** for this direction — it is a `main.go`/`apiclient` wiring change, a separate unit of work, and the only reason the "no main.go change" claim survives is that check-wiring is excluded; (b) reword §3/FM-5/FM-7 to "the T-8d live probe (`apiclient.CheckRun` — implemented, **CLI dispatch currently unwired at HEAD**, tracked separately)"; (c) keep the E3 note that it drives `CheckRun` in-process, so it is unaffected by the dispatch gap. None of this touches gates.

## 6. "No server/proto/config/OpenAPI changes" — holds under all fixes

Verified every amendment stays inside `cmd/sso-ctl/clientscmd`: E3 fix is a test-client choice (`client-m`, allowlist = all 9 matrix rows → defaulted scope mints 200; T-8d/T-9 green — I traced `mint()` in `token.go:21-80`, no `--scope` → no scope in body; confirmed reviewer's E3 defect and fix); `len(args)>1` guard is in `validate.go`; FM-5/FM-7 tests use `WithScopeRegistry(NewMemory(provisioned/extras, …))` — an existing option and constructor, no config file, no server code, no proto regen, no `Err*`, no `docs/openapi.yaml`/`error-codes.md`/`config-reference.md`. No `main.go` change (given the out-of-scope declaration above). `clientscmd/e2e_test.go` already imports everything the new fixture needs.

## 7. Verification commands cover the new tests — yes, with a required caveat

- `go build ./... && go vet ./...` — passes today; covers validate.go.
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — measures validate.go (test files excluded from budgets). Note: this command is **already red** for the pre-existing causes in §1.
- `go test ./cmd/sso-ctl/...` — runs U1–U9, E1–E3, FM tests, E-4–E-6. But the plan's §12 presents this command as green — it is **red at HEAD** for `TestSubcommands_CheckIsWired` + 3 apiclient failures; the final plan must scope its green claim to `clientscmd` and report the rest as pre-existing.
- `go test ./test/ -run 'TestScopeRegistry|TestE2E'` — server oracle unchanged ✓.
- `go test ./... -race` + `make ci` — full gates; will be red for the same pre-existing set until the unrelated tasks land. Plan should list them explicitly so handoff doesn't attribute them to this change.

## Conclusion

With the reviewer fixes applied, the plan stays inside every hard gate: clientscmd non-test files 2 ≤ 10, no new subdirs (cmd/sso-ctl remains at its frozen 16 ceiling), production code well under 500/50/15 (test files are gate-excluded, and the FM/E3/guard additions are all test-side), downward-only imports, no server/proto/config/OpenAPI delta, and the verification commands cover every new test. **Three amendments are still missing from the doc as it stands** and must land with the fixes: (1) the consts.go placement decision for the validate message/exit-code literals (§4 above); (2) the explicit out-of-scope statement for check's dispatch plus the §3/FM-5/FM-7 rewording (the doc currently repeats the F3 gap by pointing operators at an unreachable command); (3) the §7 env-var fix (`SSO_ADMIN_ADDR`) and §8.4 wording ("non-test files 2 ≤ 10, subdirs 0 ≤ 16"). Pre-existing reds to report separately: maintainability file-size, docs-tree depth/fanout, `TestSubcommands_CheckIsWired`, and the 3 apiclient tests.
