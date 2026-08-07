The requirements specification is complete at `docs/architect-analysis/cmd-sso-ctl-generate-verify-gate-requirements.md` (197 lines, matching the repo's established spec format).

## Summary

**Evidence verification (all direction citations re-checked against HEAD):**

| Claim | Result |
|---|---|
| `verifyGeneratedBuild` runs bare `go build` only | **Confirmed** (verify.go:35) |
| `TestGeneratedScaffoldsCompile` runs `go build ./...` only | **Confirmed** (scaffold_build_test.go:107–116, isolated module, no vet/content checks; baseline passes at HEAD) |
| `core.ErrorBody("not_implemented")` unregistered in `docs/error-codes.md` + `shared/core/consts.go` | **Confirmed** — plus a **new finding**: `method_not_allowed` (line 45) and `create_failed` (line 79) are also unregistered, same drift class |
| Handler POST example: `ctx.Bind` with no Content-Type guard | **Confirmed** |
| `TestOIDCDiscovery*` zero matches in tree | **Confirmed** (grep exit 1) |
| `server_discovery.go:251`, `consts.go:9,21-23` anchors | **Confirmed** |
| Registered-set extractability | **Confirmed** — 250 `| `code` |` doc rows, `ErrX = "code"` pairs in errors.go, 143 `Path*` consts, 501+`ErrNotSupported` precedent at governance.go:462 |

**Spec structure** — R1 vet at both gate surfaces (test extension per the pinned acceptance + generation-time parity for `verifyGeneratedBuild`, which entry 1's spec explicitly delegated to "entry 2's territory"); R2 registered-error-code assertion (string + constant forms, comments included); R3 legacy path/port bans + `Path*`-only constants (fix surface is exactly one doc comment); R4 form-urlencoded Content-Type guard in the generated POST path; R5 mutation-testable named assertions. Nine Given/When/Then acceptance cases preserve the supplied checks verbatim in testable form, with a T-9 regression case and a mutation pass in the verification plan. No scope expansion: server-side B4-4 enforcement and the live discovery sweep remain their own modules, explicitly listed as non-goals.
