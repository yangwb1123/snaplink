All pins verified against HEAD. Here is the validation report.

## Verdict: all four pins are feasible; hygiene checks pass (two nuances, one tight budget, one minor citation drift)

### Pin 1 — srCC form shape (`test/scope_registry_test.go:104-124`) ✅ exact
`func srCC` at line 104, closing brace at 124 — the citation is line-exact. It POSTs `/token` with `application/x-www-form-urlencoded`, fields `grant_type=client_credentials`, `client_id`, `client_secret`, optional `scope` via `url.Values` + `form.Encode()`, and returns `(status, rawBody, parsedMap)`. That is exactly the one-space-joined-scope shape `platformTokenRequest` sends (`infrastructure/auditgovernance/platform_token.go:151-166`), and the return triple supports both the 200 scope-claim assertion and the byte-identical 400 assertion.

### Pin 2 — srClientAny nil-allowlist path ✅ (citation off by ~4 lines)
The nil-allowlist seed is **lines 60-65** (design cites 56-60, which is the tail of the matrix client + `AddSeed` open). The seam itself is real: `AllowedScopes` unset on the `sso.Client` seed with the comment "nil AllowedScopes ⇒ unrestricted — the registry is the only gate." (line 64). `sso.Client` is an alias of `core.Client` (interfaces/sso/aliases.go:106); `core.Client.GrantTypes` exists (shared/core/types.go:304) and `config.ClientConfig` has no `GrantTypes` field — the design's §1.1 nuances 1/4 hold. The R4 negative control needs no new client.

### Pin 3 — byte-identical assertion pattern (`test/scope_registry_test.go:184-218`) ✅ exact
Test at 184, `want := {"error":"invalid_scope"}` at 205, `strings.TrimSpace(got) != want` at 207, trace_id-leak check at 211. The underlying path is `RejectUnregistered` → `ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))` (protocols/oauth/scoperegistry/reject.go:31-44; `ErrInvalidScope = "invalid_scope"`, `ErrorBody` emits only `{error: code}`) — so the asserted shape is guaranteed by construction, no trace_id possible.

### Pin 4 — buildApp registry construction (`cmd/sso-server/build_stores.go:305-312`) ✅ exact
Line 305 `if cfg.OAuth.ScopeRegistry.Enabled`, 306 `NewMemory(MatrixOrDefault(), ExtraScopes)`, 308 error → boot fail-closed, 310 `WithScopeRegistry(reg)`, 312 log. Zero `validateScopeRegistry` references in `cmd/sso-server/` — the R1/R2 split is faithful. The existing 4 `TestBuildApp_ScopeRegistry*` tests (scope_registry_wiring_test.go, 100 lines) establish the pattern; `a.server.ScopeRegistry()` (accessors_handlers.go:184) and `reg.Registered(sc)` (registry.go:115) exist.

### Pin 5 — MatrixOrDefault semantics ✅
`config_oauth2.go:138`: `len(c.Matrix) > 0` → provisioned verbatim, else `scopecontract.Matrix()` (9 rows). Pinned by `TestScopeRegistryConfigMatrixOrDefault` at `config/scope_registry_test.go:183` (absent/empty/present). Both construction sites (build_stores.go:306 and the validator at config_oauth2.go:52) consult it, so R5's "read the provisioned matrix when present" is correct.

### Pin 6 — goccy/go-yaml parse of the compose file ✅ (probed)
`goccy/go-yaml v1.19.2` is a direct dep (go.mod:14) and the config loader itself uses it (config/source.go, config/internal/parse). I probed `yaml.Unmarshal` into `map[string]any` against `ops/deploy/compose/config.yaml` in a scratch module: `enabled=true`, **exactly 8 matrix rows** (admin:read, admin:write, billing:payment:order:read, billing:payment:write, metering:write, billing:entitlement:read, audit:event:write, admin:\*), 2 extras. `admin:*` decodes as a plain string; no alias/anchor traps. None of the three provisioner tokens is present today — the R5 pin is red until R3 lands, which is the intended pin behavior. `scoperegistry.ProtocolScopes()` is exported (registry.go:48), so the derivation is structural.

### Layer legality (composition → infrastructure) ✅ with nuance
`layerName` classifies `config`, `test`, `cmd` → composition (6), `infrastructure` → 4 (architecture_layer_test.go:49-72); violations only fire when `layerRank[to] > layerRank[from]`, so 6→4 is legal. Precedent exists: `test/auditoutbox_governance_test.go:39` and `test/importcmd_governance_outbox_test.go:46` already import `infrastructure/auditgovernance`. **Nuance:** the layer gate skips `_test.go` files entirely (`strings.HasSuffix(path, "_test.go") → return nil`), so test-file edges are enforced by rank convention + AGENTS.md discipline, not the machine gate. The design's claim holds either way.

### No-cmd/-import rule ✅
AGENTS.md §2: "no package imports `cmd/`"; `test/auditoutbox_governance_test.go:10` restates it. Grep of `test/` and `config/` shows zero cmd/ imports; the new files import only `infrastructure/auditgovernance`, `config` (in the package-main wiring test, composition→composition, existing precedent), `scopecontract`, `scoperegistry`. Compliant.

### File-budget headroom ⚠️ one tight spot
- `test/scope_registry_test.go`: 394 lines; R4 (~45) + R5 (~35-40) → **~475-485, margin only ~15-25 lines under 500**. Feasible but tight — if R5's parser helper grows, it should go in its own file.
- **Nuance:** the machine gate `TestMaintainability_FileSizeBudget` skips `_test.go` (maintainability_budget_test.go:66), so the 500-line cap is only the AGENTS.md-budget-table reading for test files. Both readings are satisfied at the estimated size.
- `config/scope_registry_test.go` 208 → ~245; `cmd/sso-server/scope_registry_wiring_test.go` 100 → ~145. Comfortable.

### Minor citation drift (only one)
§8 cites "srClientAny nil-allowlist path (line 56-60)"; the seed is 60-65. Seam correct, range off a few lines. All other citations are line-exact.

### Also confirmed en route
`Matrix()` = 9 rows with `audit:event:write` the only audit row and no `audit:platform:*`/`audit:policy:*`; `admin:*` cannot accidentally match the provisioner tokens; compose clients' `allowed_scopes` are all registered today (R3 is purely additive, `make config-validate` stays green — the Makefile sweeps the file at lines 156/404); `docs/config-reference.md:20` already documents the block; campaign row 2 T-8(d) at implementation-gate.md:12 and G5 at line 77.

**Bottom line:** the design's seams are real and line-accurate, the negative-control path cannot false-positive through a wildcard, the goccy parse works against the live file, and the composition→infrastructure edges plus the no-cmd rule are legal. The only actionable items: watch `test/scope_registry_test.go` growth (~15-25 lines of headroom) and fix the §8 line citation for `srClientAny` (56-60 → 60-65) if the doc is touched again.
