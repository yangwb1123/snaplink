All verification complete. Every cited site was checked against the actual files. Here is the verdict.

# Verification verdict: docs/comment enumeration complete and contract-safe — with two precision corrections

## 1. config-reference.md:20 — ✅ exact line, update needed as designed

`docs/config-reference.md:20` is the `oauth.scope_registry.{enabled,matrix,extra_scopes}` row. It enumerates the built-in eight-scope table (`admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `metering:write`, `billing:entitlement:read`, `audit:event:write`, `admin:*`) and says "the built-in eight-scope table". Post-change: nine rows with `billing:checkout:create` inserted after `billing:payment:write` (keeps `billing:` rows adjacent). The same row already documents the discovery side effect ("it never expands discovery, which is filtered through the registry instead when enabled") — so the intentional `scopes_supported` behavior needs **no new sentence**, only the table/wording update.

## 2. The 7 enumerated files — ✅ 16 comment sites, all comment-only — ⚠️ one file missing from the count

| File | Lines | Status |
|---|---|---|
| `interfaces/scopecontract/consts.go` | 2, 8, 9, 22 ("eight tenant resource scopes", "Seven of the eight constants", "The eighth", "Matrix returns the eight…") | comment-only |
| `interfaces/scopecontract/consts_test.go` | 11, 43 | comment-only |
| `config/config_oauth2.go` | 96, 114, 134 (×3 as claimed) | comment-only |
| `config/scope_registry_test.go` | 167 | comment-only |
| `cmd/sso-server/scope_registry_wiring_test.go` | 76 | comment-only |
| `test/scope_registry_test.go` | 39, 51, 161 (×3 as claimed) | comment-only |
| `protocols/oauth/scoperegistry/registry.go` | 32, 60 (×2 as claimed) | comment-only |

⚠️ **Correction:** the count is incomplete by one file — `protocols/oauth/scoperegistry/registry_test.go:14` also carries an "eight" comment ("The eight-scope matrix literal mirrors interfaces/scopecontract.Matrix"). Not a blocker: the design's R2 already touches this file (`matrixLiteral` + `Registered` case), so the comment rebase lands in the same edit — but the "7 files" enumeration should name it as the eighth for completeness.

## 3. The three sweep-surfaced comment sites — ✅ exact lines confirmed

- **`interfaces/sso/options_misc.go:488`** — "and the eight-scope tenant matrix (interfaces/scopecontract); pass nil (the" → eight→nine. Comment-only, inside `WithScopeRegistry` doc.
- **`cmd/sso-ctl/configcmd/main_test.go:123`** — "Full eight-row scope-matrix-v2 table (interfaces/scopecontract) as YAML,". **The rebase has a trap, as the sweep flagged:** the `matrixYAML` const must *stay* eight rows — A1 (`TestRun_Validate_ScopeRegistry_UnregisteredAllowedScope`, exit 1) depends on the fixture-local literal lacking checkout; adding the row or switching to `scopecontract.Matrix()` flips A1 to exit 0. The rebased comment must stop claiming it mirrors `interfaces/scopecontract` (which becomes nine) — e.g., "eight-row fixture matrix (explicit provisioning; checkout deliberately absent so A1 stays negative)". All four fixtures assert exit codes only, so no assertion changes.
- **`ops/deploy/compose/config.yaml:57`** — "full eight-row matrix plus the two compose-only dev scopes as extra_scopes,". The stack is already compliant (`extra_scopes: [billing:checkout:create, tenant-quota:projection:write]` registers checkout; explicit matrix stays eight rows), so only the comment's "full" claim vs. the future nine-row built-in goes stale. Comment-only rebase; no config behavior change.
- Sweep finding #4 (`registry_test.go:90` `matrixOnly`): verified that adding the row to `matrixLiteral` alone does **not** break the slice (it is a fixed probe list; the test checks only listed scopes). But it leaves the new row unprobed by the mint/enforce mirror — recommend adding `"billing:checkout:create"` (matches the sweep's "should"); not test-breaking if omitted.

## 4. Adapter contract consistency — ✅ no change required

- `cmd/snaplink-stripe-adapter/openapi.yaml:22` — "`billing:checkout:create` scope; its client id selects one server-owned…" (description); **:29** — "machine: billing:checkout:create" (`x-required-scopes`). Both already document the scope; the change is mint-side only. (Line 218's 403 example is the user path, `scope="admin:write"` — unrelated.)
- `docs/error-codes.md:1040` — exact line: "`billing:checkout:create` scope, or whose `client_id` has no unique tenant" in the Stripe adapter section (header 1034), documenting `insufficient_scope` 403. Consistent; enforcement is untouched by the registry change.

## 5. No server OpenAPI/config-reference/error-code change — ✅

`docs/openapi.yaml` contains **no** scope-matrix enumeration (only `admin:read`/`admin:write` in admin-endpoint descriptions; `scopes_supported` at 2912 is an untyped `{type: array, items: {type: string}}` schema). The config-reference change is exactly the one already-counted row (line 20). Error-codes has no matrix enumeration beyond the adapter section above.

## 6. feature-matrix.md:135 and DECISIONS.md:929 — ✅ correctly untouched

- `docs/feature-matrix.md:135` — "`/token` (all 8 grant branches, on effective scopes post-resolution)". "8" counts *grant branches* (authcode, refresh, exchange, device, CIBA, client_credentials, JWT/SAML2 bearer), not the scope table — accurate and unrelated; untouched is correct.
- `docs/DECISIONS.md:929` — an entry recording a security-engineer review of an unrelated DR proposal (line 928's "8 rows" is that proposal's state map). Correctly untouched.

## 7. Discovery side effect — ✅ documented and pin-safe

Documented in three places: config-reference.md:20 ("filtered through the registry instead when enabled"), `server_discovery_cache.go:162` (comment + `FilterRegistered` call), `reject.go:46` (`FilterRegistered` doc). No existing discovery test breaks:

- `TestScopeRegistry_DiscoveryAdvertisesOnlyRegistered` (A-8d) asserts only that "anything" is filtered and OIDC scopes survive; its client's allowlist (`{openid, profile, email, anything}`) contains no matrix scope, so `scopes_supported` output for that fixture is unchanged even though `srRegistry` (built from `scopecontract.Matrix()`, line 43) auto-gains the row.
- `TestDiscovery_ScopesUnionFromClientAndOpenID`, `invalidation_bus_test.go:164`, and `discovery_cache_test.go` (seed scopes "read"/"newscope") assert presence, not exact lists, and run without an enabled registry.

**Bottom line:** all 8 asks verified against the code; enumeration is complete for *assertions*, with two precision corrections — (a) the "7 files" count misses `registry_test.go:14`'s comment (covered incidentally by R2, should be named), and (b) `main_test.go:123`'s rebase must pin the trap that `matrixYAML` stays eight rows or A1 flips. No server OpenAPI/config-reference/error-code changes required; feature-matrix and DECISIONS correctly untouched; the discovery side effect is documented and breaks no pin.
