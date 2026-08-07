All assertions verified. The requirements specification is complete.

## Summary

**Spec location:** `docs/architect-analysis/auto/runs/add-scope-matrix-v2-provisioning-config-vali-912ba237/artifacts/requirements-10762e10/requirements.md`

**Key finding — the direction's central premise is stale.** The analysis claims "no ScopeRegistry symbol exists anywhere in the tree," but the B4-2 work has fully landed since it was written:

- `protocols/oauth/scoperegistry/{registry.go,reject.go}` — `Registry` interface, frozen `Memory`, `NewMemory(matrix, extra)`, `ValidatePattern`, `RejectUnregistered` (plain 400 `invalid_scope`)
- `interfaces/scopecontract/consts.go` — the eight-scope matrix, now **pinned** (compile-time aliases), superseding the proposal's `[PROPOSED]` marker (proposal line 13 verified as written, now outdated)
- `config/config_oauth2.go:47-76` — `oauth.scope_registry.{enabled,extra_scopes}` + always-on `validateScopeRegistry`; wired at `cmd/sso-server/build_stores.go:306-313`; T-8(d) e2e in `test/scope_registry_test.go`

**Verified citations:** `config_client.go:15` (AllowedScopes) ✓, `server_token.go:122` (scope split + `rejectUnregisteredScopes` seam) ✓, reflection schema has no enum support ✓, `config.validate()` has no allowed_scopes semantic checks ✓, compose deploy tree uses `billing:checkout:create`/`tenant-quota:projection:write` outside the matrix ✓.

**Remaining gap (spec re-anchors to it):** no config-expressible matrix table, no configcmd gate for unknown allowed_scopes / duplicate rows, and no YAML input feeding `NewMemory`.

**Spec contents:** R1 `oauth.scope_registry.matrix` surface (absent = byte-identical, present = replaces built-in table); R2 validation in `config.validate()` (grammar + duplicates always fail-closed; allowed_scopes membership gated on `enabled: true` to preserve the B4-2 byte-compat promise — documented decision); R3-R6 configcmd exit-code flow, schema section, one-line wiring swap in `build_stores.go` (stays under the 500-line budget), config-reference row; R7 bounded compose provisioning with `extra_scopes` covering the two non-matrix dev scopes. All four acceptance checks preserved as testable Given/When/Then exit-code pins (A1-A4), plus four regression pins (P1-P4) protecting default-off and fail-closed contracts. Non-goals keep scope tight: no runtime changes, no completeness rejection, no discovery changes.
