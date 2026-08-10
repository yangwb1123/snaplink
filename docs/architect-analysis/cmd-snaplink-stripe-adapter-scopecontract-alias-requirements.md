# Requirements Spec: alias adapter scope literals to scopecontract.Matrix and pin registry conformance (B4-2)

- Direction: "Alias adapter scope literals to scopecontract.Matrix and pin registry conformance (B4-2)" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-stripe-adapter-f67dafca.json`, entry 1)
- Analysis module: `cmd/snaplink-stripe-adapter`; change surface: one const block in the adapter (root module) + one pin test in `test/scope_registry_test.go`. No registry, config, protocol, or wire behavior changes.
- Status: requirements (evidence-verified against HEAD `a2cbcb3b`, working tree)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/snaplink-stripe-adapter/model.go:12-14` — two raw scope literals vs the commerce alias | Line drift of 4: `scopeCheckoutCreate = commercehttp.ScopeCheckoutCreate` is at model.go:15, `scopeAdminWrite = "admin:write"` at :16, `scopePaymentOrderRead = "billing:payment:order:read"` at :17, `scopePaymentWrite = "billing:payment:write"` at :18. The two payment scopes are raw literals; the checkout scope is a structural alias of the commerce constant (`interfaces/commerce/consts.go:28`). The claim is substantively exact | Confirmed (line drift 12-14 -> 16-18) |
| `interfaces/scopecontract/consts.go:23-29` — `Matrix()`, the scope-matrix-v2 table | `Matrix()` at consts.go:25-36 returns the nine rows `admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `billing:checkout:create`, `metering:write`, `billing:entitlement:read`, `audit:event:write`, `admin:*`. Eight of nine constants are aliases of their owner packages (commerce/metering/admin) so the pin is structural; `consts_test.go TestMatrixShape` pins the exact nine strings and `TestMatrixPinnedToSourceConstants` pins the aliases | Confirmed (function at :25-36; the direction's :23-29 covers the doc comment + signature) |
| `cmd/snaplink-stripe-adapter/billing.go:157-190` — `requestClientToken` sends scope in the `client_credentials` request | `requestClientToken` at billing.go:154-187; the form `{"grant_type": "client_credentials", "scope": {scope}, "resource": {c.resource}}` at :157-158. Any non-200 (including a registry 400 `invalid_scope`) becomes `billingStatusError("oauth_token", status)` (:177-179) -> `deliveryError` category `"oauth_token_status"`; the body is discarded, so `invalid_scope` is indistinguishable from any other token-endpoint failure. Callers: `GetOrder` mints with `scopePaymentOrderRead` (:62), `Deliver` with `scopePaymentWrite` (:98) | Confirmed (function :154-187; form :157-158) |
| `test/scope_registry_test.go:182-291` — byte-identical plain `invalid_scope` pins, e.g. line 205 | `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` at :184-221: allowlist rejection, registry rejection, and mixed `profile billing:typo` all return 400 with `strings.TrimSpace(raw) == '{"error":"invalid_scope"}'` (the `want` literal is at line 205) and no `trace_id` substring. `TestScopeRegistry_RefreshChainPreservesOIDCScopes` at :224-295 pins the same shape for a pre-enablement family failing closed at refresh rotation (:291, :293) | Confirmed (line exact) |
| `config/scope_registry_test.go` — registry seed pins | `TestValidateScopeRegistry` at :15; the `"matrix grammar always enforced"` subtest at :63-82 pins fail-closed grammar/duplicate validation even at `enabled=false` | Confirmed |
| `protocols/oauth/scoperegistry/registry_test.go` — registry seed pins | `matrixLiteral` (the nine-row mirror, deliberate literal because protocols must not import interfaces) at :17-25; `TestMemoryProtocolScopesMatchCoreConstants` at :33; `TestMemoryRegisteredMatchesPermissionsSemantics` at :52. The seed is `NewMemory(matrix, extra)` and `RejectUnregistered` writes the byte-identical plain body | Confirmed |

**Supplementary facts verified (not cited by the direction, needed for the design):**

- `cmd/snaplink-stripe-adapter` is a root-module package (no `go.mod` in the directory; not in AGENTS.md's nested-module list). The architecture gate classifies `cmd/` as composition (architecture_layer_test.go `layerName`, "cmd" -> "composition", rank 6), so importing `interfaces/scopecontract` is a downward edge. The adapter already imports `interfaces/commerce` (model.go:8), and the scopecontract package doc names composition packages as intended importers ("Composition packages (cmd/sso-server, test/) and interfaces/sso import this package").
- `test/` cannot import `cmd/` (AGENTS.md: "no package imports `cmd/`"). The existing precedent is `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault` (test/scope_registry_test.go:386-393), which pins the billing default literal from the test side without importing `cmd/snaplink-billing`. The new pin must enumerate the adapter's scope strings as literals, with comments naming the adapter symbols.
- The four adapter-requested scopes and their sites: `scopePaymentOrderRead` (`billingClient.GetOrder`, billing.go:62), `scopePaymentWrite` (`billingClient.Deliver`, billing.go:98), `scopeCheckoutCreate` (checkout authorization gate, http.go:224/227), `scopeAdminWrite` (user checkout authorization gate, http.go:236/237). All four strings are exact members of `Matrix()` today (admin:write both exactly and via the `admin:*` wildcard row).
- No existing `test/` pin covers the adapter's scopes: `test/stripe_adapter_tenant_claim_test.go:35` only seeds `saScope = "billing:checkout:create"` as harness input, it is not a matrix membership pin.

**One precision correction to the problem statement (acceptance unaffected):** the direction says a registry 400 "would degrade order reads and event delivery as permanent errors". Measured: `billingStatusError` sets `permanent=false` (deliveryError zero value), so `oauth_token_status` is a retryable category; degradation is retry-until-budget then quarantine (worker.go:101-102 `permanentDeliveryError`). The directionally-correct part stands: an unregistered scope breaks GetOrder and event delivery with a failure indistinguishable from any token-endpoint outage, and no invalid_scope-aware handling exists. This direction does not add that handling (the acceptance asks only for the compile-time alias plus pins); it removes the silent-drift path that would make the runtime breakage reachable.

## 2. Goal and user outcome

The adapter's two payment scopes become compile-time aliases of the scope-matrix-v2 table, and registry conformance of all four scopes the adapter requests becomes a pinned, test-enforced contract.

Concretely:

- `scopePaymentOrderRead` and `scopePaymentWrite` stop being duplicated literals. A matrix rename or re-registration that removes or renames either scope now fails the build of `interfaces/scopecontract` (whose own constants alias the same owner constants) and of the adapter, instead of surfacing at runtime as a 400 `invalid_scope` on the adapter's `client_credentials` mints (GetOrder, Deliver).
- A new `test/` pin proves every scope the adapter requests — GetOrder's `billing:payment:order:read`, Deliver's `billing:payment:write`, checkout's `billing:checkout:create`, and the user gate's `admin:write` — is a member of `scopecontract.Matrix()`, so the adapter cannot silently consume a scope the registry does not register.
- The byte-identical `{"error":"invalid_scope"}` /token wire shape (no trace_id, no registry oracle) stays pinned by the existing `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` as the regression boundary for the runtime symptom.

Completion marker: T-2 of the direction is satisfied — the two literals are aliases, the membership pin exists and passes, and the wire-shape pin is green under the same suite.

## 3. Product boundary

- Surface: `cmd/snaplink-stripe-adapter` (root module) const block + `test/scope_registry_test.go` (root-module `package ssotest`). No server, registry, config, protocol, or deploy-tree change.
- Default: no behavior change. The aliases resolve to byte-identical strings (`billing:payment:order:read`, `billing:payment:write`); the token cache keys, wire form parameters, and challenge strings are unchanged. The registry itself remains default-off; nothing here enables it.
- Explicit non-goals (do not implement):
  - No `invalid_scope`-aware handling in `billingClient` (no new error categories, no classification of the 400 body, no retry policy change). The direction's problem statement motivates the pins with the runtime degradation; the acceptance does not ask to fix the degradation path.
  - No change to `scopeAdminWrite = "admin:write"` (model.go:16). The acceptance names exactly the two payment literals for aliasing; `admin:write` membership is covered by the T-2 pin (and by the `admin:*` wildcard row).
  - No change to `interfaces/scopecontract`, `interfaces/commerce`, `protocols/oauth/scoperegistry/*`, `config/*`, `cmd/sso-server/*`, or any other package's non-test files.
  - No new test duplicating `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody`. The direction's third acceptance item cites test/scope_registry_test.go:205 as the shape; that pin already exists and the requirement is preservation, not duplication.
  - No `docs/config-reference.md` / `docs/openapi.yaml` / `docs/error-codes.md` additions (no new config key, endpoint, or `Err*`).

## 4. Module classification

- [ ] OAuth/OIDC/protocol flow
- [ ] Store implementation
- [ ] Admin or self-service endpoint
- [ ] Authenticator
- [ ] Audit/observability
- [x] Authorization/policy (scope-contract conformance pinning)
- [ ] Infrastructure/config/deployment
- [ ] Cold module / build profile / hot lifecycle
- [x] Refactoring only (literal -> alias, zero behavior delta)

Owning physical layer: `cmd/` (composition, rank 6) for the alias; `test/` (composition) for the pin. Dependency direction review: the new import `cmd/snaplink-stripe-adapter -> interfaces/scopecontract` is a downward edge (composition -> interfaces), same direction as the existing `interfaces/commerce` import in the same const block, and matches the scopecontract package doc's stated importer list. No `layerExemptions` entry is needed (the layer test classifies by first path segment; no new top-level package is created).

## 5. Requirements

### R1 — Alias the two payment scope literals to scopecontract (compile-time structural pin)

In `cmd/snaplink-stripe-adapter/model.go`, replace the two literals:

```go
import (
	...
	scopecontract "github.com/yangwb1123/snaplink/interfaces/scopecontract"
)

const (
	...
	scopePaymentOrderRead = scopecontract.ScopePaymentOrderRead
	scopePaymentWrite     = scopecontract.ScopePaymentWrite
)
```

- Same pattern as the existing `scopeCheckoutCreate = commercehttp.ScopeCheckoutCreate` (model.go:15): the adapter binds its requested scopes to the matrix constants, which themselves alias the owner-package constants (`interfaces/scopecontract/consts.go:39-50`), so the pin is structural at compile time end to end.
- `scopeAdminWrite` (model.go:16) stays a literal per the acceptance; its membership is pinned by R2.
- `billing.go` is untouched: `clientToken`'s cache key (`tokenCacheKey{clientID, scope}`) and the `client_credentials` form parameter (billing.go:157-158) keep receiving the same string values.

### R2 — test/ membership pin: every scope the adapter requests is a matrix member

Add to `test/scope_registry_test.go` (root-module `package ssotest`) a pin test, e.g. `TestScopeRegistry_StripeAdapterScopesRegistered`, next to the existing matrix rows:

- Enumerate the four adapter-requested scope strings as a test-side literal set, each with a comment naming the adapter symbol and its call site (the test must NOT import `cmd/`, AGENTS.md; precedent: `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault`, scope_registry_test.go:386-393):
  - `"billing:payment:order:read"` — adapter `scopePaymentOrderRead`, minted by `billingClient.GetOrder` (billing.go:62),
  - `"billing:payment:write"` — adapter `scopePaymentWrite`, minted by `billingClient.Deliver` (billing.go:98),
  - `"billing:checkout:create"` — adapter `scopeCheckoutCreate`, checkout authorization gate (http.go:224),
  - `"admin:write"` — adapter `scopeAdminWrite`, user checkout authorization gate (http.go:236).
- For each literal, assert exact membership in `scopecontract.Matrix()` (string equality against the returned slice, the same style as `TestScopeRegistry_MatrixScopesMintable`'s iteration). The failure message must name the literal and the matrix, so a matrix re-registration that drops or renames a scope the adapter consumes fails loudly with the offender named.
- No minting, no harness, no registry construction needed: this is a pure contract pin between the adapter's requested-scope surface and the matrix table.

### R3 — Preserve the byte-identical invalid_scope wire-shape pin

The direction's third acceptance item ("an unregistered scope at /token returns the exact `{"error":"invalid_scope"}` body, no trace_id") is already pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (test/scope_registry_test.go:184-221; the `want` literal at :205) and by the refresh-family variant (`TestScopeRegistry_RefreshChainPreservesOIDCScopes`, :224-295). Requirement: leave both tests untouched and green; they are the regression boundary that makes a future unregistered adapter scope detectable at /token as the byte-identical plain body. R2's pin reuses the same assertion discipline (raw-body/string equality, no parsing into maps) for the membership direction.

## 6. Testable acceptance (Given/When/Then)

Preserved from the direction; each check made machine-testable.

**T-2 (R1) — compile-time structural pin:**

1. Given the adapter const block (model.go), when `go build ./cmd/snaplink-stripe-adapter/...` runs, then it compiles with `scopePaymentOrderRead` and `scopePaymentWrite` bound to `scopecontract.ScopePaymentOrderRead`/`ScopePaymentWrite` (aliases, not literals). Fail condition: a matrix rename that removes the two rows from `interfaces/scopecontract` (whose constants alias `interfaces/commerce/consts.go:26-27`) breaks compilation — the drift surfaces at build time, never at runtime.
2. Given the aliased values, when the adapter's existing unit suite runs, then `TestBillingClientUsesSeparateLeastPrivilegeTokens` (clients_test.go:66-121) still observes exactly one `/token` request per scope with `scope=billing:payment:order:read` and `scope=billing:payment:write` — proving the alias is value-identical (no wire delta).

**T-2 (R2) — membership pin:**

3. Given `TestScopeRegistry_StripeAdapterScopesRegistered`, when it runs against `scopecontract.Matrix()`, then each of `billing:payment:order:read`, `billing:payment:write`, `billing:checkout:create`, `admin:write` is an exact matrix member. Fail condition: any literal is missing from the matrix — message names the literal and the matrix contents.
4. Given the same test, when `Matrix()` is edited to drop or rename any of the four (a future re-registration), then the test fails. This is the drift the direction prevents: today, dropping `billing:payment:order:read` from the matrix would compile cleanly and only break the adapter's mints at runtime.

**T-2 (R3) — wire shape preserved:**

5. Given the existing `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody`, when an unregistered scope is presented at `/token` (allowlist rejection, registry rejection, and mixed `profile billing:typo`), then each response is 400 with body `{"error":"invalid_scope"}` (raw trim-equality against the line-205 literal) and no `trace_id` substring — byte-identical across all three branches, no registry-state oracle.
6. Given the full change, when `go test ./test/ -run 'TestScopeRegistry_StripeAdapterScopesRegistered|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody|TestScopeRegistry_MatrixScopesMintable' -v` runs, then all pass.

Acceptance mapping grade: 6/6 machine-checked under root gates (cases 1-2 compile/unit, cases 3-4 the new pin, cases 5-6 the preserved wire pins). No review-only invariants.

## 7. Engineering-gate constraints (verified)

- **No package imports `cmd/`**: the R2 pin enumerates literals with symbol-mapping comments (precedent `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault`, scope_registry_test.go:386-393). `test/` never imports `cmd/snaplink-stripe-adapter`.
- **Import direction**: `cmd/snaplink-stripe-adapter -> interfaces/scopecontract` is composition -> interfaces (downward), legal per `layerName` (architecture_layer_test.go: "cmd" -> "composition", rank 6). No new top-level package, so no `layerName()` classification and no `layerExemptions` change.
- **Budgets**: `model.go` change is two const lines plus one import (no function touched); `test/scope_registry_test.go` grows by one test function (~25 lines, well under the 500-line file budget and the 15-subdirectory fan-out). `interfaces/sso`'s 60-file ceiling is untouched (no file there). No function has complexity or nesting changes.
- **Wire/contract invariants untouched**: no routes, no `Err*`, no config keys, no audit events, no credential-endpoint headers, no SSRF surface, no oracle-safe-table change. The `/token` rejection shape is preserved (case 5 asserts it).
- **Root module only**: the adapter is a root-module package; no nested-module or `cli.py modules` impact (no module/profile change). `make ci` covers the root module including `test/`.

## 8. Files

### Modify

```text
cmd/snaplink-stripe-adapter/model.go
    - R1: add the scopecontract import; scopePaymentOrderRead and
      scopePaymentWrite become aliases of scopecontract.ScopePaymentOrderRead /
      scopecontract.ScopePaymentWrite (same pattern as scopeCheckoutCreate).
test/scope_registry_test.go
    - R2: add TestScopeRegistry_StripeAdapterScopesRegistered asserting the four
      adapter-requested scope literals (with symbol-mapping comments) are exact
      members of scopecontract.Matrix().
```

### Do not modify

```text
interfaces/scopecontract/consts.go — the nine-row matrix stays frozen; the
    adapter now binds to it instead of duplicating it.
interfaces/commerce/consts.go, protocols/oauth/scoperegistry/*, config/*,
    internal/handler/tokengrant/*, cmd/sso-server/* — no behavior change.
cmd/snaplink-stripe-adapter/billing.go, http.go, worker.go — no invalid_scope
    handling, no retry/quarantine change (explicit non-goal).
test/scope_registry_test.go TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody
    and TestScopeRegistry_RefreshChainPreservesOIDCScopes — preserved verbatim
    (R3).
docs/config-reference.md, docs/openapi.yaml, docs/error-codes.md — nothing to add.
```

## 9. Dependencies and compatibility

- New/changed SPI: none. The aliases resolve to the identical strings, so the token cache, the `client_credentials` form, the `invalidateOnUnauthorized` key space (billing.go:189-195), and the RS `CheckScope` gates (http.go:224/236) see zero value change.
- New option/store wiring: none. Storage migration: none. HTTP/proto compatibility: none. Module graph: none (root module only; `interfaces/scopecontract` is already a root-module package with no new dependencies).
- Rollout/rollback: pure refactor plus additive test. Removing the change restores the previous literals exactly; the pins are additive.
- Campaign: advances the B4-2 row for `cmd/snaplink-stripe-adapter` (T-2): the adapter's requested scopes become provably registered members of the scope-matrix-v2 table, closing the deploy-tree consumer gap named in the direction. Runtime registry enablement (the G5 flip) remains the campaign owner's deployment decision, untouched here.

## 10. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config surface).
- [ ] `docs/openapi.yaml` / `docs/error-codes.md` — not applicable (no endpoint, no `Err*`).
- [ ] `docs/feature-matrix.md` / `docs/observability.md` — not applicable (no behavior change).
- [x] Campaign bookkeeping: B4-2/T-2 advanced as described in §9.

## 11. Verification plan

```bash
go build ./... && go vet ./...                                   # root module; the alias must compile
go test -run 'TestMaintainability_|TestArchitecture_' .          # root gates (import direction, budgets)
go test ./cmd/snaplink-stripe-adapter/... -run 'TestBillingClientUsesSeparateLeastPrivilegeTokens' -v
go test ./test/ -run 'TestScopeRegistry_StripeAdapterScopesRegistered|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody|TestScopeRegistry_MatrixScopesMintable|TestScopeRegistry_AuditRelayScopeMatchesBillingDefault' -v
go test ./... -race                                              # full suite before handoff
make ci                                                          # handoff gate (includes test/ under ci)
```

Baselines verified during evidence gathering: all five direction citations confirmed against the working tree; `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (test/scope_registry_test.go:184-221) is present and is the line-205 shape reference. No pre-existing failure observed in the touched packages; no nested-module or `cli.py modules` impact.
