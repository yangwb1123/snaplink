Requirements specification complete. Written to `docs/architect-analysis/auto/runs/register-billing-checkout-create-in-scope-matrix-b327b9ee/artifacts/requirements-10762e10/requirements.md` (the pipeline-expected output path).

## Verification summary — all 8 cited evidence items confirmed

| Citation | Verdict |
|---|---|
| `model.go:12` `scopeCheckoutCreate` | ✅ exact line, literal `"billing:checkout:create"` |
| `http.go:216-218` `authorizeMachineCheckout` | ✅ `rs.CheckScope(claims, scopeCheckoutCreate)` → 403 `insufficient_scope`; machine flow selected at 206-207 |
| `scopecontract/consts.go:25-36` `Matrix()` | ✅ exactly 8 rows, no checkout scope |
| `commerce/consts.go:23-27` scope consts | ✅ 4 scopes, no checkout scope |
| `build_stores.go:306` registry wiring | ✅ `NewMemory(MatrixOrDefault(), ExtraScopes)` |
| `reject.go:29-42` `RejectUnregistered` | ✅ func at 31; 400 `invalid_scope`, no trace_id; invoked post-allowlist on client_credentials path |
| `config_oauth2.go:30-52` `validateScopeRegistry` | ✅ enabled→membership check on exact runtime registry |
| `scope_registry_test.go:108-135` | ✅ confirmed, with a key finding: the negative test at 116-128 uses `billing:checkout:create` as its *unregistered* example — **it breaks when the scope is registered** and must be re-based onto a still-unregistered scope (spec R3) |

Supplementary verification closed the acceptance chain: `TestScopeRegistry_MatrixScopesMintable` iterates `scopecontract.Matrix()` (auto-covers the new row), `srCC`/`newScopeRegistryHarness` are the cross-server /token seam, adapter tests already prove 201-with-scope / 403-without, and the "eight" wording enumerations were located in 6 files + `docs/config-reference.md:20`.

## Spec contents (11 sections)

- **Evidence table** with line-precise verification and the two precision notes
- **Requirements R1-R6**: matrix row (owner = `interfaces/commerce` alias pattern, inserted after `ScopePaymentWrite`), pin tests, config-validation positive/negative rebase, cross-server minting, adapter literal pin (R5 — the only adapter code touch), docs in same change
- **Acceptance** — T-8(d)/T-8(a) preserved verbatim, each mapped to concrete named tests; regression boundaries (oracle-safe body, fail-closed provisioning, allowlist-first ordering) made explicit
- **Compatibility/security analysis** — strictly additive; no new error surface, no openapi change, no discovery requirement
- **Fenced non-goals** — the other two analysis rows (`tenant_id` enforcement, relay convergence) explicitly excluded, per the no-scope-expansion instruction
