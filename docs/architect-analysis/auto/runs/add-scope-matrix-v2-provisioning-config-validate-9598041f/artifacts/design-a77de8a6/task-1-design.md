All claims confirmed. Design delivered at:

**`docs/architect-analysis/auto/runs/add-scope-matrix-v2-provisioning-config-vali-912ba237/artifacts/design-3f9a2c51/task-1-design.md`**

## Verification verdict

Every evidence claim checked against HEAD `5644809b` — **all substantively true**, with only line-number drift (e.g. `validateScopeRegistry` is at `config_oauth2.go:15`, struct at :68-76, not :47-76; scope split at `server_token.go:124-126`). Independently confirmed:

- **B4-2 landed**: `scoperegistry.{registry,reject}.go` (frozen `Memory`, `NewMemory(matrix, extra)`, `ValidatePattern`, oracle-safe `RejectUnregistered`); `scopecontract` eight-scope matrix pinned as compile-time aliases; `build_stores.go:307` wiring; T-8(d) e2e in `test/scope_registry_test.go`
- **The gap is real**: no `matrix` config key, no `MatrixOrDefault`, no `allowed_scopes`/duplicate semantic checks in `config.validate()` (`validateConfiguredClients` checks only `id` + `login_page_uri`), schema has no enum support, compose tree uses two non-matrix scopes
- **No import-cycle or budget risk**: `config` is composition-layer; both proposed imports (`interfaces/scopecontract`, existing `protocols/oauth/scoperegistry`) are legal; `build_stores.go` is 497 lines

## Design highlights

- **API**: `ScopeRegistryConfig.Matrix []string` + `MatrixOrDefault()`; `validateScopeRegistry` extended in 4 deterministic steps (matrix grammar always → exact-duplicates always → extra grammar → membership gated on `enabled: true`, built via the exact runtime `NewMemory` call so the gate can never disagree with `/token`); one-line `build_stores.go` swap; schema picks up the section via reflection (`generateType` emits `{type: array, items: {type: string}}`, verified at `schema/generate.go:92-93`)
- **Core invariant**: runtime grants ⊆ `allowed_scopes` ∪ `{openid, device_sso}` (rule 1/3 of `GrantedScopes`), and both bypass constants are pre-seeded — so per-entry `reg.Registered()` is exactly the runtime predicate, pre-deploy
- **Compatibility**: 11 constraints (default-off byte-compat, `matrix: []` ≡ absent, fail-closed grammar/dupes, idempotent cross-list/protocol-scope rows, exit-code contract, no hot-reload)
- **12 failure modes**, including the deliberate behavior change (FM-11: configs already running `enabled: true` with dirty clients now fail boot — converting a runtime 400 storm into a deploy-time error) and the documented residual (FM-12: unrestricted clients can still request unregistered scopes at runtime — inherent to B4-2)
- **Migration**: 5 steps with the production enablement order (matrix with `enabled: false` → staging pre-flight → fix clients → fleet-wide flip → rollback by dropping the block, no data migration)
- **Acceptance mapping**: A1-A4/P1-P4 pinned to concrete test functions across `configcmd/main_test.go` (exit codes), `config/scope_registry_test.go` (unit), and `scope_registry_wiring_test.go` (matrix-replaces-builtin), plus the R7 compose-tree gate and T-8(d) regression pins

No Go files were edited; per AGENTS.md the design artifact required no gate runs.
