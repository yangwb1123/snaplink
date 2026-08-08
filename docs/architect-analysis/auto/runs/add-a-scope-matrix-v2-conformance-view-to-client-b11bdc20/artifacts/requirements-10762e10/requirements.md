The requirements specification is complete. Final deliverable:

**`docs/architect-analysis/cmd-sso-ctl-clientscmd-scope-matrix-conformance-requirements.md`**

## Verification summary — every direction citation checked against HEAD

| Citation | Result |
|---|---|
| `interfaces/scopecontract/consts.go:22-36` — `Matrix()` | Confirmed (func at 25-33; 9 rows, 8 structural aliases + pinned literal) |
| `cmd/sso-server/build_stores.go:306` — `NewMemory(MatrixOrDefault(), ExtraScopes)` | Confirmed, exact line |
| `cmd/sso-server/scope_registry_wiring_test.go:28,79` | Confirmed (matrix pin at 28/41, provisioned-replaces-builtin at 79; extras at 57) |
| `cmd/sso-ctl/clientscmd/clients.go:25-30` — `allowedScopes` w/o conformance signal | Confirmed (struct at 74-85, `AllowedScopes` at 80; `list`/`get` only) |
| `cmd/sso-ctl/apiclient/check.go:18` — T-8d | Confirmed (line 20; `probeScope` at 300) |
| `cmd/sso-ctl/apiclient/token.go:282+` — dynamic probe | Confirmed (`runT8d` at 351-385, byte-identical `400 {"error":"invalid_scope"}` pin at 375) |
| "No such command or flag exists today" | Confirmed — direction's hedge was necessary |

## Two decisive findings beyond the direction's citations

1. **The predicate must reuse the registry, not a slice lookup.** `Memory.Registered` is exact-or-`":*"` (protocols/oauth/scoperegistry/registry.go:115-125) and always pre-registers the 7 protocol scopes (lines 48-57). A naive "member of `Matrix()`" check would false-flag every `admin:...` concrete scope and every client carrying `openid`/`profile` — while disagreeing with the server. The spec locks `scoperegistry.NewMemory(scopecontract.Matrix(), nil).Registered` (the exact `srRegistry` construction, test/scope_registry_test.go:41-48).
2. **The agreement test needs `WithScopeRegistry` wired** into the e2e fixture (e2e_test.go:70-130 wires none today); the spec's R3 triple (validate exits 1 naming the scope ⇔ `/token` returns byte-identical 400 `invalid_scope` for the same scope ⇔ matrix member mints 200) is feasible against `PathToken` mounted in that fixture, and leaves E-4/E-5/E-6 green.

## Spec decisions (within the direction's boundary)

- **`sso-ctl clients validate`** subcommand (not a `list` flag): keeps `list`'s byte-pinned output intact; carries its own 0/1/2 exit contract mirroring `check`.
- Both supplied acceptance checks preserved and made testable: the httptest-admin-fixture unit test (offender → exit 1 + named scope; matrix/protocol/wildcard-covered → exit 0) and the e2e oracle-agreement test.
- Documented non-goal: deployment-specific `extra_scopes`/provisioned matrices are out of scope (covered by `config validate` for config-declared clients and the T-8d probe at runtime); the CLI gate targets the built-in matrix — the drift source the direction identifies, which the offline config gate cannot see.
- Scope contained: 2 new files + 3 small edits (dispatch, usage, main.go usage string); no server/proto/config/OpenAPI changes; composition-layer imports only.
