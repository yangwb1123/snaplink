Requirements specification complete. Two files written:

1. **`docs/architect-analysis/cmd-snaplink-stripe-adapter-scopecontract-alias-requirements.md`** — the full spec
2. **`docs/architect-analysis/auto/runs/alias-adapter-scope-literals-to-scopecontract-ma-032f6785/artifacts/requirements-10762e10/requirements.md`** — the run artifact summary (path matches the run's pipeline output)

## Evidence verification results (all 5 citations checked)

| Citation | Verdict |
|---|---|
| `model.go:12-14` literals vs commerce alias | Confirmed with line drift 12-14 → 16-18 (`scopePaymentOrderRead` :17, `scopePaymentWrite` :18, alias `scopeCheckoutCreate` :15) |
| `scopecontract/consts.go:23-29` Matrix() | Confirmed: `Matrix()` at :25-36, nine rows; eight constants are structural aliases of owner packages |
| `billing.go:157-190` client_credentials scope | Confirmed: `requestClientToken` :154-187, form :157-158; non-200 → `oauth_token_status` deliveryError |
| `test/scope_registry_test.go:182-291` invalid_scope pins | Confirmed: byte-identical pin :184-221 (`want` literal exactly at :205), refresh-family variant :224-295 |
| `config/` + `scoperegistry/registry_test.go` seed pins | Confirmed: grammar-always-validated subtest; `matrixLiteral` nine-row mirror at :17-25 |

## Key findings

- **Import edge is legal**: the adapter is root-module composition (rank 6), so `interfaces/scopecontract` is a downward import — already precedented by its existing `interfaces/commerce` import, and the scopecontract package doc names composition packages as importers.
- **One precision correction** (acceptance unaffected): the direction's "permanent errors" mechanism is imprecise — `billingStatusError` sets `permanent=false`, so degradation is retry-until-quarantine (worker.go:101-102), not immediate permanent classification.
- **Acceptance preserved as 6 testable Given/When/Then cases**: T2-1 alias replacement (compile-time structural pin, value-identical per `TestBillingClientUsesSeparateLeastPrivilegeTokens`), T2-2 new `TestScopeRegistry_StripeAdapterScopesRegistered` pin (four literal scopes with symbol-mapping comments — `test/` cannot import `cmd/`, following the `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault` precedent), T2-3 the existing byte-identical `{"error":"invalid_scope"}` wire pin preserved verbatim (no duplicate test — that would be scope expansion).
- **Scope guardrails**: exactly the two payment literals aliased (`scopeAdminWrite` stays a literal per the acceptance), no invalid_scope handling in the adapter (explicit non-goal), no registry/config/protocol changes, no new `Err*`/endpoints/config keys.
