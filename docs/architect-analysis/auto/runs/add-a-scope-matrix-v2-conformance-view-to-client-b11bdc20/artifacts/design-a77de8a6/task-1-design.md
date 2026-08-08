Deliverable written and internally consistent. Summary of the work:

## Verification results (all evidence claims checked against HEAD)

| Evidence claim | Verdict |
|---|---|
| `scopecontract/consts.go:25-33` — `Matrix()` 9 rows (8 aliases + pinned `audit:event:write` literal) | ✅ Confirmed, exact |
| `build_stores.go:306` — `NewMemory(MatrixOrDefault(), ExtraScopes)` | ✅ Confirmed, exact line |
| `scope_registry_wiring_test.go:28,79` — matrix pin / provisioned-replaces-builtin | ✅ Confirmed |
| `clientscmd/clients.go` — no conformance signal; `AllowedScopes` at 80; `list`/`get` only | ✅ Confirmed |
| `check.go` T-8d, `probeScope` at 300, `runT8d` 351-395, byte-identical pin at 375 | ✅ Confirmed (2-line comment drift) |
| `registry.go:115-125` — `Registered` exact-or-`":*"`; 7 protocol scopes pre-seeded | ✅ Confirmed, exact |
| `test/scope_registry_test.go:41-49` — `srRegistry` construction | ✅ Confirmed |
| `test/e2e_test.go` fixture wires no `WithScopeRegistry` | ✅ Confirmed (buildE2E at 80-170, shared with `risk_test.go`) |
| "No such command or flag exists today" | ✅ Confirmed |

## One refinement to the evidence (finding #2)

The evidence proposed wiring `WithScopeRegistry` into `test/e2e_test.go`'s `buildE2E` for the R3 oracle test. I rejected that: the server oracle is already pinned in `test/scope_registry_test.go` (A-1b, `newScopeRegistryHarness`), `test/` cannot be imported from `cmd/` (and vice versa per AGENTS.md), and mutating `buildE2E` perturbs `risk_test.go`'s 7+ tests for zero gain. The agreement test instead gets a dedicated registry-wired fixture in `clientscmd` (mirror of `newCLIDeployment`, which already mounts `/token` at `/`), leaving E-4/E-5/E-6 green — same outcome, smaller blast radius.

## Deliverable: `docs/architect-analysis/cmd-sso-ctl-clientscmd-scope-matrix-conformance-requirements.md`

Contains: evidence-verification table with measured verdicts; **API change** (`sso-ctl clients validate <client-id>`, 0/1/2 exit contract, stderr-only offenders, `validate: OK` on pass); **compatibility constraints** (list/get byte-identical, predicate = `NewMemory(Matrix(), nil).Registered`, composition-layer imports only, budget check: 2 new non-test files ≤ 10); **failure modes** FM-1..FM-7 (incl. the documented false-positive on provisioned/extra-scope deployments — the soundness boundary of the built-in-matrix gate); **migration steps** (new binary only, no server/config/storage changes, trivially clean rollback); **testable acceptance mapping** — 9 unit tests (U1-U9) + 3 e2e tests (E1-E3) with Given/When/Then, plus the R3 oracle triple: CLI exit 1 naming scope ⇔ `/token` byte-identical `400 invalid_scope` ⇔ matrix member mints 200.

Scope contained as the evidence promised: 3 new files, 1 small edit (dispatch arm + usage line), no server/proto/config/OpenAPI changes.
