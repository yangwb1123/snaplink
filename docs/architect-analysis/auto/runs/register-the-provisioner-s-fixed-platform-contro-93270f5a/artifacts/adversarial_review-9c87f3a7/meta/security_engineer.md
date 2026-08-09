All five invariants verified against code at HEAD (`ff04f683`; design pinned `374f9890` — the only delta is the design doc itself). Every targeted suite re-run green. Findings:

## 1. Byte-identical 400 `invalid_scope`, no trace_id — HOLDS

- `RejectUnregistered` (protocols/oauth/scoperegistry/reject.go:31-44) writes `ctx.JSON(400, core.ErrorBody(core.ErrInvalidScope))`. `ErrorBody` (shared/core/error_body.go:11-13) is `{"error": code}` — trace_id only enters via `ErrorBodyWithTrace`, never called here. The seam comment (interfaces/sso/server_token.go:195) states the constraint explicitly: "never `errorBody`, whose trace_id would drift the byte-compat baseline".
- Pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (test/scope_registry_test.go:184-218): asserts `raw == {"error":"invalid_scope"}` across allowlist/registry/mixed rejections **and** asserts the `trace_id` substring is absent. Suite green. R4 reuses exactly this pattern.

## 2. Default-off byte-compat everywhere outside compose — HOLDS (structurally)

- Repo-wide grep over all deploy trees (helm, k8s, k8s-prod, k8s-distributed, kustomize, baremetal-ha, terraform, etc.): `scope_registry` exists in exactly **one** file, `ops/deploy/compose/config.yaml`. No other tree carries the block, so nil-registry no-op applies everywhere (reject.go/registry.go nil guards).
- `build_stores.go:305`: `if cfg.OAuth.ScopeRegistry.Enabled` → otherwise no option wired. Pinned by `TestScopeRegistry_DefaultPathUnwired_ByteIdentical` and `TestScopeRegistry_MixedReplicaDivergence` (200 off / 400 on) — both green.

## 3. extra_scopes → registry only; never discovery or scope expansion — HOLDS

- **Registry**: extras are a `NewMemory(MatrixOrDefault(), ExtraScopes)` construction input; the config gate builds the *same* registry for membership (config_oauth2.go:58-63), so the gate can't disagree with /token.
- **Discovery**: `FilterRegistered` (server_discovery_cache.go:170) is the only discovery interaction and it only *filters* the client-set union — nothing ever adds extras to `scopes_supported`; no code path reads `ExtraScopes` at discovery time.
- **Expansion**: the registry is reject-only (`RejectUnregistered`). Mint scopes = `oauth.GrantedScopes(requested, client)` (token_client_credentials.go:34-46); extras never enter the grant path. `TestScopeRegistry_DiscoveryAdvertisesOnlyRegistered` pins the filter behavior.

## 4. No new error surface / headers / audit events — HOLDS (trivially, by construction)

- The change is 3 additive entries in an existing documented YAML key + three test files. Zero production Go edits → no new `Err*`, routes, headers, middleware, or audit event types; no contract-doc changes needed (docs/config-reference.md:20 already documents the block incl. "no new error surface").
- The rejection path emits no audit: reject.go has zero audit references (the only audit call near the seam, server_token.go:344, is the FAPI path, not registry rejection). The 400 rides the existing /token pipeline; headers unchanged.

## 5. R4 negative control proves the seam, not a bypass — SOUND

- Same mint path (`srCC` → POST /token client_credentials), differing only in registry contents: positive = `NewMemory(Matrix(), provisionerScopes)` → 200 with all three tokens in the scope claim; negative = matrix-only `srRegistry` + `srClientAny` (nil allowlist) → 400 byte-identical.
- The negative is probative on four legs: (a) nil allowlist = unrestricted per oauthvalidate rule 2, so `GrantedScopes` cannot reject; (b) the registry check is a single unconditional, client-agnostic call site (token_client_credentials.go:46 + dispatch seam server_token.go:204); (c) the byte-identical/no-trace_id assertion excludes misattribution from tokenpolicy's trace-wrapped `errorBody` (ordering pin: seam runs before `denyTokenScopeCombo`); (d) counterfactual proof — the same client+scope class returns 200 on an unwired server (`DefaultPathUnwired_ByteIdentical`), so a bypass would 200 the negative, not 400.

## Supporting re-checks (no drift found)

- Gap live: `--validate-only` on the compose file exits 0 at current HEAD; compose has `enabled: true`, 8-row matrix, 2 extras, none of the three provisioner tokens.
- Exact error string, `Matrix()` = 9 rows, `ProtocolScopes()` = 7, GrantTypes guard at server_token.go:111, `ClientConfig` has no `GrantTypes`, T-C seed at client_tenant_binding_test.go:67, goccy/go-yaml direct dep (go.mod:14), layer legality (config/cmd/test = composition → infrastructure = layer 4), file budgets 100/208/394 lines — all match the design's citations.
- `go test ./config/ -run TestValidateScopeRegistry`, `go test ./cmd/sso-server/ -run TestBuildApp_ScopeRegistry`, `go test ./test/ -run TestScopeRegistry_` — all pass.

**Verdict**: the design preserves every requested oracle-safe and fail-closed invariant; no corrections needed. The only caveat worth noting (not a design flaw): the compose gap's mint-400 leg (FM-2) presumes the provisioner client is registrable out-of-band in that tree (etcd/control-plane); the config-declared leg (FM-1) is the one measured live. The design's R3 fix is correct for both.
