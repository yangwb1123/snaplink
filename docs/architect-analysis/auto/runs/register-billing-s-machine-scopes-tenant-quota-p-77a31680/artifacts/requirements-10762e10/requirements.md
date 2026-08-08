Requirements specification complete. Both deliverables written and byte-identical:

- **Full spec**: `docs/architect-analysis/cmd-snaplink-billing-scope-registry-requirements.md`
- **Pipeline artifact**: `docs/architect-analysis/auto/runs/register-billing-s-machine-scopes-tenant-quota-p-77a31680/artifacts/requirements-10762e10/requirements.md`

## Evidence verification — all 9 citations confirmed

| Citation | Verdict |
|---|---|
| `scopecontract.Matrix()` eight rows, no quota/retention scope | Confirmed — 8 rows exactly; package doc freezes the table at eight |
| `shared/core/consts.go:26` `ScopeTenantQuotaProjectionWrite` | Confirmed (line exact); `PathTenantQuotaProjection` at :25 |
| `quota_relay.go:128,143-144` exact scope pin | Confirmed — `finalize` default + `validate` exact-match boot error |
| `quota_relay.go:347-350` PlatformTokenSource/PlatformRetentionScope | Confirmed at :346-366/:350; retention TokenURL derives from issuer (`TrimRight(issuer,"/")+PathToken`, :226-228) |
| `platform_token.go:17-18,91` | Confirmed (line exact) — retention scope is a hard-coded two-token constant |
| `scoperegistry.NewMemory(matrix, extra)` | Confirmed — seeds 7 protocol scopes + matrix + extra; frozen; `RejectUnregistered` writes plain byte-identical `{"error":"invalid_scope"}`, no trace_id |
| `build_stores.go:305-310` registry wiring | Confirmed at :302-312 — pure function of config snapshot; enabled=false = nil registry |
| `scope_registry_test.go:162` MatrixScopesMintable | Confirmed — only `Matrix()` rows + admin:read/write via `admin:*`; harness builds `NewMemory(Matrix(), nil)` |
| `helm/sso-server/values.yaml` no scope_registry | Confirmed — no `oauth:` section at all; `configmap.yaml:9-10` renders `.Values.config` verbatim, so a new block flows straight into `/etc/sso/config.yaml` |

**Gap confirmed**: `Matrix() ∪ ProtocolScopes()` (15 entries) misses exactly the three strings billing mints — `tenant-quota:projection:write` and the retention pair (`audit:platform:cross_tenant`, `audit:policy:write`). With `enabled: true`, `token_client_credentials.go:43-47` rejects all of them → quota projection, retention projection, and billing's `/readyz` (`app.go:100,103`) break.

## Spec structure (4 requirements, 7 machine-testable acceptance cases)

- **R1** — `TestScopeRegistry_BillingScopesMintable`: 200 via `client_credentials` for all 8 supplied scopes + the space-joined retention pair (as `PlatformTokenSource` sends it) + byte-identical 400 for an unregistered scope (raw-body equality, no oracle).
- **R2** — `TestScopeRegistry_BillingScopeLiteralsRegistered`: every billing literal (`core.ScopeTenantQuotaProjectionWrite`, `defaultAuditScope` "audit:event:write", `PlatformRetentionScope` tokens, `values.yaml` audit/quota scopes) ∈ `Matrix() ∪ ProtocolScopes() ∪ extra_scopes`, with `extra_scopes` **read from the deploy tree** — absent block = loud failure, so the pin cannot go circular.
- **R3** — `ops/deploy/helm/sso-server/values.yaml` gains `config.oauth.scope_registry {enabled: false, extra_scopes: [tenant-quota:projection:write, audit:platform:cross_tenant, audit:policy:write]}` — the documented pre-G5 enablement order (`docs/config-reference.md:20`), grammar-validated ALWAYS, server byte-identical until the campaign owner's flip.
- **R4** — `TestE2EQuotaProjection_RegistryEnabled`: mint via `POST /token` `client_credentials` (through the registry seam, not the direct-issuer bypass the existing e2e uses), one `relay.RunOnce` delivery assertion on `PUT /api/v1/internal/tenant-quota/projection`; optional negative control with the pre-fix composition.

Constraints honored: no production Go changes to billing, `Matrix()` stays frozen at eight rows, no test imports `cmd/` (existing literal-pin precedent at `scope_registry_test.go:387`), no new config keys/`Err*`/endpoints, YAML via the already-present `goccy/go-yaml v1.19.2` (go.mod:14 — the analysis's `yaml.v3` claim was corrected to the actual dependency).
