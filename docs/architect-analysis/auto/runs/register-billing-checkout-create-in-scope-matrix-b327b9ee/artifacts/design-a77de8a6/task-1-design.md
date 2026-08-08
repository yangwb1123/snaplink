Verification is complete. Here is the deliverable.

---

# Verification verdict

All 8 cited evidence items checked against executable code. **7 confirmed; item 8 confirmed in content with a file-disambiguation correction.** No blocking drift found.

| # | Citation | Verdict | Independent finding |
|---|---|---|---|
| 1 | `model.go:12` | ✅ content (line is 13) | `cmd/snaplink-stripe-adapter/model.go:13`: `scopeCheckoutCreate = "billing:checkout:create"` — off-by-one precision note |
| 2 | `http.go:216-218` | ✅ | `authorizeMachineCheckout` at 212; `rs.CheckScope(claims, scopeCheckoutCreate)` at **216**; 403 `insufficient_scope` challenge at 219; machine flow selected at 206-207 |
| 3 | `scopecontract/consts.go:25-36` | ✅ | `interfaces/scopecontract/consts.go:25` `func Matrix()`; exactly 8 rows; no checkout scope; 7 rows structurally alias owners, audit row is pinned literal |
| 4 | `commerce/consts.go:23-27` | ✅ | `interfaces/commerce/consts.go:23-27`: exactly 4 scopes, no checkout scope |
| 5 | `build_stores.go:306` | ✅ | Exact line: `scoperegistry.NewMemory(cfg.OAuth.ScopeRegistry.MatrixOrDefault(), cfg.OAuth.ScopeRegistry.ExtraScopes)` |
| 6 | `reject.go:29-42` | ✅ | Func at 31; 400 plain `{"error":"invalid_scope"}` via `core.ErrorBody` (no trace_id); nil/empty no-op; invoked post-allowlist on client_credentials (`internal/handler/tokengrant/token_client_credentials.go:46`, after `GrantedScopes`) and on 8 other effective-scope points |
| 7 | `config_oauth2.go:30-52` | ✅ | Func at 30; `enabled` gates the membership loop; check runs against `NewMemory(MatrixOrDefault(), ExtraScopes)` — the exact runtime registry; disabled = no check |
| 8 | `scope_registry_test.go:108-135` | ⚠️ file ambiguous, **content confirmed** | The breaking negative test is **`config/scope_registry_test.go:116-129`** "membership rejects unregistered allowed_scope": `Enabled=true`, `Matrix=scopecontract.Matrix()`, client `tenant-a` allowed `billing:checkout:create`, expects an error naming the scope. It **breaks** when the row joins `Matrix()`. Note: `protocols/oauth/scoperegistry/registry_test.go` (the same-name file in the registry package) uses `billing:typo` (line 183) and `anything`/`api:read` — **not affected**; `test/scope_registry_test.go` uses `billing:typo` (lines 188-196) — **not affected**; `cmd/sso-ctl/configcmd/main_test.go` A1 uses a hardcoded `matrixYAML` literal — **not affected** |

Supplementary claims verified: `TestScopeRegistry_MatrixScopesMintable` (test/scope_registry_test.go:162) iterates `scopecontract.Matrix()` → **auto-covers** a new row; `srCC`/`newScopeRegistryHarness` (lines 68-104) are the cross-server `/token` seam; adapter tests prove 201-with-scope / 403-without (`http_test.go:113,132-133,152,164,195`); "eight" enumerations live in 7 files (`interfaces/scopecontract/consts.go`, `consts_test.go`, `config/config_oauth2.go` ×3, `config/scope_registry_test.go`, `cmd/sso-server/scope_registry_wiring_test.go`, `test/scope_registry_test.go` ×3, `protocols/oauth/scoperegistry/registry.go` ×2) + `docs/config-reference.md:20` (exact line, inline eight-scope table).

**One breakage the evidence's spec should be expanded to name explicitly** (it is implied by R2 "pin tests" but deserves a row): `interfaces/scopecontract/consts_test.go:TestMatrixShape` (lines 43-60) asserts the exact 8-entry list and fails on length mismatch once the row is added.

---

# Design: register `billing:checkout:create` in scope-matrix-v2

## Goal and non-goals

**Goal:** make the stripe adapter's machine-checkout scope part of the built-in scope-matrix-v2 table, so an enabled registry can mint it (today it is unprovisionable: `/token` 400s, and `sso-ctl config validate` flags every checkout client).

**Non-goals (explicitly out of scope, per the no-scope-expansion constraint):** `tenant_id` enforcement changes at `/token`; relay-convergence work (the `tenant-quota:projection:write` gap is out of scope — it remains unregistered and is used as the rebase target below). No new error surface, no `/token` wire change, no server OpenAPI change.

## API changes (all additive, Go-level only)

1. **Owner constant — `interfaces/commerce/consts.go`** (the billing resource-scope owner; the adapter is a composition consumer, so the scope cannot live in `cmd/`): add to the existing scope block (line 27, after `ScopePaymentWrite`):
   ```go
   ScopeCheckoutCreate = "billing:checkout:create"
   ```
   `interfaces/commerce` imports only `net/http` + `shared/core` — negligible dependency pull.

2. **Matrix row — `interfaces/scopecontract/consts.go`**: add `ScopeCheckoutCreate = commercehttp.ScopeCheckoutCreate` (structural alias, same pattern as the other seven rows) and insert `ScopeCheckoutCreate` into `Matrix()` **after `ScopePaymentWrite`**, keeping `billing:` rows grouped:
   `admin:read, admin:write, billing:payment:order:read, billing:payment:write, billing:checkout:create, metering:write, billing:entitlement:read, audit:event:write, admin:*`. Exact literal, no wildcard — registry grammar unchanged.

3. **Adapter pin — `cmd/snaplink-stripe-adapter/model.go:13`** (the only adapter code touch, R5): replace the literal with a compile-time alias:
   ```go
   scopeCheckoutCreate = commercehttp.ScopeCheckoutCreate
   ```
   The adapter already imports `interfaces/...` packages (`middleware`, `ssoclient/rs`), so `interfaces/commerce` is a legal downward edge (composition → interfaces). This is the structural-pin doctrine (vs. a test-only pin) — a future literal drift becomes a compile error. No behavior change; the adapter's own `openapi.yaml` (lines 22, 29) and `docs/error-codes.md:1040` already document the scope.

4. **No config change.** The row lives in the built-in table (`MatrixOrDefault`); `matrix`/`extra_scopes` mechanics, `enabled` gating, and the boot-time validation (`config_oauth2.go:30`) are untouched.

## Compatibility constraints

- **Default-off byte-compat:** registry unwired (nil) → zero behavior change; all existing deploys without a `scope_registry` block are bit-identical.
- **Enabled + built-in matrix:** the mintable set widens by exactly one exact scope. Widening only (nothing removed) — existing minting unaffected; checkout clients that previously 400'd now mint. This is the intended fix.
- **Enabled + explicit `matrix`:** provisioned matrix replaces the built-in (pinned by `TestBuildApp_ScopeRegistryProvisionedMatrixReplacesBuiltin`) — behavior unchanged; such deployments must add the row to `matrix` or `extra_scopes` themselves.
- **Oracle safety:** the rejection shape (`400 invalid_scope`, plain body, no trace_id) is untouched; only *which* scopes are rejected changes. The `permissions.Matches` mint/enforce drift guard stays consistent (exact scope both directions).
- **Duplicate with `extra_scopes`:** idempotent no-op (set semantics), not a boot error — deployments already listing it in `extra_scopes` need no change.
- **Discovery side effect (intentional, not a requirement):** under an enabled registry, `scopes_supported` is registry-filtered, so the row will surface there. Consistent with "discovery mirrors what `/token` mints."
- **Enforcement unchanged:** the adapter still 403s tokens lacking the scope; the registry only affects minting.

## Failure modes

| Mode | Behavior | Mitigation |
|---|---|---|
| Enabled registry + explicit matrix missing the row | `/token` 400 `invalid_scope` for checkout clients → adapter cannot acquire a token (fails at mint, before checkout) | `sso-ctl config validate` exit 1 names client + scope pre-deploy; migration step 5 |
| Const drift (rejected by design) | Matrix has scope, adapter checks another string → permanent 403, silent billing breakage | Structural alias = compile error, not runtime drift |
| Wildcard misuse (`billing:*`) | Would widen minting beyond intent | Rejected: exact literal only; registry grammar unchanged |
| Test-shape drift | Cosmetic | `TestMatrixShape` exact-list pin |
| Rollback of explicit-matrix deploys | Remove the row from config; validate catches dirty clients | Config-only, no token invalidation (registry is mint-time; live tokens and enforcement unaffected) |

## Migration steps

1. Land this change (consts + matrix + pins + rebased tests + docs) — registry default-off, zero runtime impact.
2. Mandatory gates after edits: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; then `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.
3. Deploy the binary fleet-wide; no config change required for the default path.
4. Enabled-with-built-in-matrix deployments: nothing to do — checkout becomes mintable atomically with the binary.
5. Explicit-matrix deployments: add `billing:checkout:create` to `matrix` (or `extra_scopes`) in the same change as any `enabled: true` flip; run `sso-ctl config validate` pre-flight first.
6. Rollback: downgrade binary (built-in) or drop the config row (explicit); no credential/token invalidation needed.

## Testable acceptance mapping

| Acceptance | Mapping (named tests) |
|---|---|
| T-8(d): registry gates `/token`; new row mints | `test/scope_registry_test.go:TestScopeRegistry_MatrixScopesMintable` — iterates `Matrix()`, **auto-covers** the row (200 + exact scope claim); boot twin `cmd/sso-server/scope_registry_wiring_test.go:TestBuildApp_ScopeRegistryEnabledBuildsMatrix` — iterates `Matrix()` |
| T-8(d) negative, byte-identical | `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (`billing:typo` — unaffected, still passes) |
| T-8(a): adapter machine checkout | `cmd/snaplink-stripe-adapter/http_test.go` — 201-with-scope (113, 164), 403-wrong-scope/unbound (132-133, 152, 195) unchanged; pin is now compile-time (alias) |
| R1 matrix row + alias | `interfaces/scopecontract/consts_test.go:TestMatrixShape` — update `want` list (checkout after `billing:payment:write`); `TestMatrixPinnedToSourceConstants` — add `ScopeCheckoutCreate == commercehttp.ScopeCheckoutCreate` assertion |
| R2 registry parity | `protocols/oauth/scoperegistry/registry_test.go` — add row to `matrixLiteral` + `Registered("billing:checkout:create")==true` case in the semantics drift guard (keeps the mirror honest) |
| R3 config rebase | `config/scope_registry_test.go:116-129` — rebase the unregistered example onto `tenant-quota:projection:write` (real, still-unregistered, `shared/core` const exists); add a positive subtest: `Matrix()` + allowed `billing:checkout:create` → `validateScopeRegistry()` nil |
| R4 cross-server minting | covered by the T-8(d) rows above (`srCC`/`newScopeRegistryHarness`) |
| R5 adapter pin | compile-time; `go build` is the assertion |
| R6 docs | `docs/config-reference.md:20` — inline table to nine rows; "eight" → "nine" comment updates in the 7 enumerated files; `docs/feature-matrix.md:135` ("8 grant branches") and `docs/error-codes.md:1040` unchanged |
| Config-cmd regression | `TestRun_Validate_ScopeRegistry_*` (A1/P1/P2/A3) — fixtures use explicit `matrixYAML`, unaffected; verify in `make ci` |

**Cost check:** change touches 3 production files (one line each: `interfaces/commerce/consts.go`, `interfaces/scopecontract/consts.go`, `cmd/snaplink-stripe-adapter/model.go`) plus tests/docs. No new files → no layer classification, no fan-out impact; `interfaces/sso` 60-file ceiling untouched. No budget crossings.
