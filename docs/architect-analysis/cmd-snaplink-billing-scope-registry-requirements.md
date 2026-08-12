# Requirements Spec: register billing's machine scopes in the scope-matrix-v2 registry path (pre-G5)

- Direction: "Register billing's machine scopes (tenant-quota:projection:write + retention platform scopes) in the scope-matrix-v2 registry path before G5 enablement" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-billing-a1788a26.json`, entry 1)
- Analysis module: `cmd/snaplink-billing`; change surface: root-module tests in `test/` (extend `scope_registry_test.go`, `quota_projection_e2e_test.go`) + deploy-tree registration in `ops/deploy/helm/sso-server/values.yaml`. No production Go changes to `cmd/snaplink-billing` — the billing binary already pins its scopes at boot; this direction makes the registry path honor them.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `interfaces/scopecontract/consts.go:Matrix()` — eight rows, no quota/retention scope | `Matrix()` (consts.go:18-28) returns exactly eight rows: `admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `metering:write`, `billing:entitlement:read`, `audit:event:write`, `admin:*` (`ScopeAdminWildcard = admin.Scope = "admin:*"`). No `tenant-quota:projection:write`, no `audit:platform:cross_tenant`, no `audit:policy:write`. The package doc pins the table as "the eight tenant resource scopes" — the matrix is intentionally frozen at eight rows | Confirmed |
| `shared/core/consts.go:26` — `ScopeTenantQuotaProjectionWrite` | Line 26: `ScopeTenantQuotaProjectionWrite = "tenant-quota:projection:write"`; line 25: `PathTenantQuotaProjection = "/api/v1/internal/tenant-quota/projection"` (the T-8(e) delivery path) | Confirmed (line exact) |
| `cmd/snaplink-billing/quota_relay.go:128,143-144` — exact scope pin | `finalize` at 127-128 defaults `config.Scope = core.ScopeTenantQuotaProjectionWrite`; `validate` at 143-144 rejects any other value with `"quota relay scope must be exactly tenant-quota:projection:write"`. The scope is an exact-match boot pin, not a configurable | Confirmed |
| `cmd/snaplink-billing/quota_relay.go:347-350` — PlatformTokenSource / PlatformRetentionScope | `withRetentionProjection` (quota_relay.go:346-366) builds `auditgovernance.NewPlatformTokenSource(PlatformTokenConfig{..., Scope: auditgovernance.PlatformRetentionScope, ...})` at line 350. The retention projector mints from the same IdP token URL family (retention TokenURL defaults to `TrimRight(issuer,"/")+core.PathToken`, quota_relay.go:226-228) | Confirmed (line drift 347→350, symbols exact) |
| `infrastructure/auditgovernance/platform_token.go:17-18,91` | Lines 17-18: `PlatformProvisioningScope = "audit:platform:cross_tenant audit:policy:read audit:policy:write"`, `PlatformRetentionScope = "audit:platform:cross_tenant audit:policy:write"`. Line 91: `validPlatformScope` accepts exactly these two strings — the retention scope pair is a hard-coded constant, not configurable | Confirmed (line exact) |
| `protocols/oauth/scoperegistry/registry.go:NewMemory` | `NewMemory(matrix, extra []string)` (registry.go:68) seeds `ProtocolScopes()` (openid, device_sso, profile, email, address, phone, offline_access — registry.go:48-58) + matrix + extra; frozen; `ValidatePattern` (exact or `domain:*`) runs fail-closed at construction. `Registered` (registry.go:119-131) is exact-or-`:*`-prefix; `RejectUnregistered` (reject.go:31-45) writes the byte-identical plain `{"error":"invalid_scope"}` body (no trace_id) and returns 400 | Confirmed |
| `cmd/sso-server/build_stores.go:305-310` — registry wiring | `if cfg.OAuth.ScopeRegistry.Enabled { reg, err := scoperegistry.NewMemory(cfg.OAuth.ScopeRegistry.MatrixOrDefault(), cfg.OAuth.ScopeRegistry.ExtraScopes); ... b.opts = append(b.opts, sso.WithScopeRegistry(reg)) }` (build_stores.go:302-312). Registry construction is a pure function of the config snapshot; enabled=false passes nil (byte-identical server). Enforcement seam: `interfaces/sso/server_token.go:204` and `internal/handler/tokengrant/token_client_credentials.go:43-47` (`RejectUnregistered` on effective scopes) | Confirmed |
| `test/scope_registry_test.go:162` — `TestScopeRegistry_MatrixScopesMintable` (only Matrix() rows asserted) | Test at 162-181 iterates only `scopecontract.Matrix()` plus concrete `admin:read`/`admin:write` under the `admin:*` pattern. Harness `srRegistry` (line 59-66) builds `NewMemory(scopecontract.Matrix(), nil)` — no extra scopes, no quota/retention coverage. `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (184-217) already pins the byte-identical rejection; `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault` (387-393) pins `audit:event:write` | Confirmed |
| `ops/deploy/helm/sso-server/values.yaml` — no scope_registry block | File has no `oauth:` section at all: the `config:` block (values.yaml:157-166) contains only `server`, `logging`, `audit`. `grep -rn "scope_registry" ops/deploy/helm/sso-server/` → 0 hits. The chart renders `.Values.config` verbatim into `/etc/sso/config.yaml` (templates/configmap.yaml:9-10 `toYaml .Values.config`), so a `config.oauth.scope_registry` block would flow straight into the server config | Confirmed |
| `config/config_oauth2.go` — `extra_scopes` enablement path | `ScopeRegistryConfig{Enabled bool; ExtraScopes []string yaml:"extra_scopes"; Matrix []string yaml:"matrix"}` (config_oauth2.go:123-134); `MatrixOrDefault()` (136-141); `validateScopeRegistry` (30-63) runs ALWAYS (grammar + duplicates, fail-closed even when disabled); client `allowed_scopes` membership check only when enabled. `docs/config-reference.md:20` documents the enablement order: land matrix/extra_scopes with `enabled: false` → staging `sso-ctl config validate` pre-flight → fleet-wide flip → rollback by dropping the block | Confirmed |
| Billing side-scope consumers (acceptance list) | `cmd/snaplink-billing/auth.go:45-46,159-167` — resource-server gates require `billing:payment:order:read` / `billing:payment:write`; `app.go:207-210` mounts commerce routes behind `ClientCredentialsScopeGate`; `cmd/snaplink-billing/config.go:22` `defaultAuditScope = "audit:event:write"` with exact-match boot pin (config.go:359-360); `relay.go:46-49` mints it via `NewOAuthTokenSource`. `ops/deploy/helm/snaplink-billing/values.yaml:43` `settings.audit.scope: audit:event:write`, `:54` `settings.quota.scope: tenant-quota:projection:write`; the retention block (values.yaml:58-63) has NO scope literal — retention's scope is the code constant `PlatformRetentionScope` | Confirmed |
| `/readyz` coupling | `cmd/snaplink-billing/app.go:93-106` — `applicationReadyChecks` appends `audit_relay_module` (auditModule.Ready) and `tenant_quota_projection` (quotaRelay.Ready); both `Ready` implementations gate on token acquisition, so a registry-rejected mint fails readiness | Confirmed |

**Gap confirmation (the direction's problem is real).** Today `Matrix() ∪ ProtocolScopes()` = 15 entries. Billing's machine consumers mint exactly three missing strings:

1. `tenant-quota:projection:write` — quota relay (quota_relay.go:128,143-144 boot pin; minted via `buildQuotaTokenSource` → `NewOAuthTokenSource`),
2. `audit:platform:cross_tenant` — retention projector (PlatformRetentionScope, first token),
3. `audit:policy:write` — retention projector (PlatformRetentionScope, second token).

With `oauth.scope_registry.enabled=true` and today's registration, `internal/handler/tokengrant/token_client_credentials.go:43-47` rejects every one of these effective scopes with 400 `invalid_scope` → quota projection, retention projection, and both `/readyz` checks break. `ops/deploy/helm/sso-server/values.yaml` carries no `oauth.scope_registry` block, so the documented `extra_scopes` path is unwired today. Everything else billing consumes (`audit:event:write`, `billing:payment:order:read`, `billing:payment:write`, `metering:write`, `billing:entitlement:read`, `admin:read`, `admin:write`) is already registered by the matrix (admin:read/admin:write via the `admin:*` row).

## 2. Goal and user outcome

The scope-matrix-v2 registry (B4-2) becomes safe to enable (G5) without breaking billing's three machine consumers. Concretely:

- The three missing scopes are registered through the documented `extra_scopes` path in the deploy tree before the G5 flip, with the block landed `enabled: false` per the documented enablement order (grammar/duplicates validated ALWAYS; server byte-identical until the flip).
- The registry-enabled tests pin that every scope `cmd/snaplink-billing` mints or requires at boot is mintable through the registry: the eight billing-consumed scopes return 200 via `client_credentials`, the retention platform scope pair (minted as one space-joined parameter, exactly as `PlatformTokenSource` sends it) returns 200, and an unregistered scope still returns the byte-identical plain 400 `invalid_scope` (no registry oracle).
- The quota-relay e2e proves one real `PUT /api/v1/internal/tenant-quota/projection` delivery end-to-end with the registry enabled and the mint going through `/token`.

Completion marker: T-8(d) and T-8(e) of `docs/campaigns/implementation-gate.md` (G5 row, line 77) are satisfied for billing — the campaign's "矩阵配给后端到端无 403" contract holds for billing's machine scopes, and the deploy tree's registration cannot silently drift from the billing binary's boot pins.

## 3. Product boundary

- Surface: registration + registry-side tests only. No behavior change to `cmd/snaplink-billing` (its scope pins are already exact-match and stay byte-identical), no scope-contract table change (`interfaces/scopecontract.Matrix()` stays eight rows — the matrix is frozen by B4-2; the extension path is `extra_scopes`), no `/token` behavior change (registry remains default-off).
- Defaults: the registration lands `enabled: false` — the documented pre-G5 state (`docs/config-reference.md:20` enablement order). The G5 flip itself is out of scope (a deployment decision by the campaign owner).
- Explicit non-goals (do not implement):
  - No change to the eight-row `scopecontract.Matrix()`; no change to `shared/core/consts.go`, `config/config_oauth2.go`, `protocols/oauth/scoperegistry/*`, `interfaces/sso/*` non-test files, `cmd/sso-server/*`, or any `cmd/snaplink-billing/*` non-test file.
  - No change to the registry rejection shape (byte-identical `{"error":"invalid_scope"}`, no trace_id — already pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` and preserved).
  - No new config keys, `Err*`, OpenAPI surface, audit events, or endpoints. `docs/config-reference.md` already documents the knob; nothing to add.
  - The retention scope pair is registered via `extra_scopes`, NOT added to the matrix and NOT merged into discovery (registry `extra_scopes` never feeds `scopes_supported` — existing documented semantics, `config_oauth2.go` doc comment).
  - No test imports `cmd/snaplink-billing` (AGENTS.md: no package imports `cmd/`; the existing audit-scope pin at `scope_registry_test.go:387` deliberately compares literals instead).

## 4. Module classification

- [x] Infrastructure/config/deployment (registry registration + deploy-tree wiring)
- [x] Testing (T-8(d) mint + pin tests, T-8(e) e2e)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layers: `test/` (root-module `package ssotest` — composition-side pin tests; the existing B4-2 registry suite lives there) and `ops/deploy/helm/sso-server` (deploy tree). The registry construction in tests follows the composition rule already used by `srRegistry` (test/ composes `scopecontract.Matrix()` + extra into `scoperegistry.NewMemory`, exactly as `cmd/sso-server/build_stores.go:305-310` does — protocols never imports interfaces).

## 5. Requirements

### R1 — Registry-enabled `client_credentials` mint test for every billing-consumed scope (T-8(d), first half)

Extend `test/scope_registry_test.go`:

- Add a billing registration set as a test-side constant mirroring the deploy-tree registration (R3): the three scopes missing from `Matrix() ∪ ProtocolScopes()`:
  `tenant-quota:projection:write`, `audit:platform:cross_tenant`, `audit:policy:write`.
- Add `srBillingRegistry(t)` — `scoperegistry.NewMemory(scopecontract.Matrix(), billingExtra)` (matrix untouched; extra = the R1 set).
- Add a billing harness variant of `newScopeRegistryHarness` (registry ON) that wires `srBillingRegistry` and seeds a billing relay client (`srBillingClient`) whose `AllowedScopes` are the eight billing-consumed scopes (the pre-existing per-client allowlist gate is orthogonal to the registry; both must pass for the mint to succeed, exactly as in production where the IdP client allowlist and the registry both gate).
- New test `TestScopeRegistry_BillingScopesMintable`: for every scope in the supplied list —
  `tenant-quota:projection:write`, `audit:event:write`, `billing:payment:order:read`, `billing:payment:write`, `metering:write`, `billing:entitlement:read`, `admin:read`, `admin:write` —
  a `client_credentials` mint (existing `srCC` helper) returns 200 and the token's `scope` equals the requested scope.
- Retention half (the direction title's second half): a `client_credentials` mint with `scope = "audit:platform:cross_tenant audit:policy:write"` (one space-joined parameter, byte-identical to how `PlatformTokenSource` sends `PlatformRetentionScope` — `infrastructure/auditgovernance/platform_token_test.go:65`) returns 200.
- Unregistered-scope guard: a mint with an unregistered scope (e.g. `billing:typo`) returns 400 with a body byte-identical to the plain `{"error":"invalid_scope"}` shape already pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (no trace_id, no registry-state oracle). Compare raw bodies, not parsed maps.

### R2 — Billing-scope membership pin test (T-8(d), second half)

Add to `test/scope_registry_test.go` a pin test `TestScopeRegistry_BillingScopeLiteralsRegistered` asserting every billing scope literal is in `Matrix() ∪ ProtocolScopes() ∪ extra_scopes`:

- Code-side literals (expressed as constants/strings — the test must NOT import `cmd/`):
  - `core.ScopeTenantQuotaProjectionWrite` (the constant `quota_relay.go:128,143-144` pins at boot) equals the literal `"tenant-quota:projection:write"`, and the literal is registered.
  - `scopecontract.ScopeAuditEventWrite` equals `"audit:event:write"` (billing's `config.go:22` `defaultAuditScope`; equality already pinned by `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault` — keep that test), and the literal is registered.
  - `auditgovernance.PlatformRetentionScope` — the string is space-joined; every token in it (`audit:platform:cross_tenant`, `audit:policy:write`) is registered (infrastructure import is fine from `test/`).
- Deploy-tree side: parse `ops/deploy/helm/snaplink-billing/values.yaml` and assert `settings.audit.scope` and `settings.quota.scope` literals are registered; parse `ops/deploy/helm/sso-server/values.yaml` and take `config.oauth.scope_registry.extra_scopes` as the `extra_scopes` set (the R3 registration). If the block is absent (the current unwired state), the test fails with a self-explaining message naming the missing key — the pin is the drift guard between the deploy-tree registration and the billing boot pins.
- Helper: `billingExtraScopesFromDeployTree(t)` reads the two helm files (YAML via the root module.s existing direct dependency `github.com/goccy/go-yaml v1.19.2` (`go.mod:14`, already used by `cmd/sso-ctl/configcmd/schema.go`)). The R1 harness extra set and the R2 registered-set derivation share one source of truth: `srBillingRegistry` uses the same helper so the mint test and the pin test cannot disagree.

### R3 — Register the scopes in the deploy tree (the "unwired enablement path" fix)

Modify `ops/deploy/helm/sso-server/values.yaml` — add under the existing `config:` block (values.yaml:157-166; rendered verbatim into `/etc/sso/config.yaml` by `templates/configmap.yaml:9-10`):

```yaml
  oauth:
    scope_registry:
      enabled: false
      extra_scopes:
        - tenant-quota:projection:write
        - audit:platform:cross_tenant
        - audit:policy:write
```

- `enabled: false` per the documented enablement order (`docs/config-reference.md:20`): grammar and duplicate validation run ALWAYS (fail-closed), the server stays byte-identical, and G5's flip to `true` activates a registry that already registers every billing machine scope. The flip itself is the campaign owner's deployment decision — not this direction.
- No `matrix` key: the built-in eight-scope table (`MatrixOrDefault()` with empty matrix) is the B4-2 contract; only the three missing scopes ride `extra_scopes`.

### R4 — Registry-enabled quota-relay e2e (T-8(e))

Extend `test/quota_projection_e2e_test.go` with `TestE2EQuotaProjection_RegistryEnabled` (mirror of `TestE2ECommerceEntitlementProjectsIntoSSOQuota`):

- Server: `sso.NewServer` with the token issuer, a memory tenant-quota store, a client store, AND `sso.WithScopeRegistry(srBillingRegistry)` (Matrix + billing extra, R1/R2 helper). Mount the projection handler with `sso.NewTenantQuotaProjectionHandler(server, "sso-e2e", sources)` exactly as the existing harness (audience = `"sso-e2e"`, matching `newQuotaProjectionE2EClient`'s direct mint).
- The relay client is seeded with `AllowedScopes: []string{core.ScopeTenantQuotaProjectionWrite}` and the projection audience bound (resources), so the `/token` mint yields the exact claims the handler requires (`interfaces/sso/quota_projection_test.go:95` pins: valid machine-shaped JWT, audience = projection audience, scope `tenant-quota:projection:write`; wrong audience/missing scope → 403 `insufficient_scope`).
- The `quotaprojection.Client` authorizer mints via `POST /token` `grant_type=client_credentials` with `scope=tenant-quota:projection:write` (through the registry seam) instead of the direct `Ed25519JWTIssuer` mint the existing harness uses — this is the net-new coverage: the registry-enabled mint path, not a bypass.
- Drive: publish the plan, create a subscription, run `relay.RunOnce` and assert `result.Delivered == 1` plus the store projection values (reuse `assertQuotaProjectionE2EDelivery` semantics) — one completed `PUT /api/v1/internal/tenant-quota/projection` delivery (`core.PathTenantQuotaProjection`) with the registry enabled.

## 6. Testable acceptance (Given/When/Then)

Preserved from the direction; each check made machine-testable:

**T-8(d) — mint + byte-identical rejection (R1):**

1. Given a registry-enabled server wired with `srBillingRegistry` (matrix + the three billing extras) and the `srBillingClient` seed, when `client_credentials` mints request each of `tenant-quota:projection:write`, `audit:event:write`, `billing:payment:order:read`, `billing:payment:write`, `metering:write`, `billing:entitlement:read`, `admin:read`, `admin:write`, then each returns 200 and the token's `scope` equals the requested scope. (Fail condition: any of the eight returns 400 `invalid_scope` — the exact G5 breakage this direction prevents.)
2. Given the same server, when `client_credentials` requests the retention platform scope string `audit:platform:cross_tenant audit:policy:write` (space-joined, as `PlatformTokenSource` sends it), then 200.
3. Given the same server, when `client_credentials` requests an unregistered scope (e.g. `billing:typo`), then 400 with a body byte-identical to the plain `{"error":"invalid_scope"}` rejection already pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` — raw-body equality, no registry-state oracle.

**T-8(d) — pin (R2):**

4. Given `cmd/snaplink-billing`'s boot-pinned literals (`core.ScopeTenantQuotaProjectionWrite`, billing's `defaultAuditScope` literal `"audit:event:write"`, every token of `auditgovernance.PlatformRetentionScope`) and the scope literals in `ops/deploy/helm/snaplink-billing/values.yaml` (`settings.audit.scope`, `settings.quota.scope`), when membership is checked against `Matrix() ∪ ProtocolScopes() ∪ extra_scopes` where `extra_scopes` is read from `ops/deploy/helm/sso-server/values.yaml` `config.oauth.scope_registry.extra_scopes`, then every literal is a member. (Fail conditions: a billing scope literal drifts from the registry, or the deploy-tree `extra_scopes` block is removed/absent — the unwired state the direction fixes.)
5. Given the same derived set, when the retention tokens are checked, then `audit:platform:cross_tenant` and `audit:policy:write` are both members.

**T-8(e) — registry-enabled quota-relay e2e (R4):**

6. Given a registry-enabled server (matrix + billing extras) with the tenant-quota projection handler mounted and a relay client whose allowlist and audience cover `tenant-quota:projection:write`, when the relay mints via `POST /token` `client_credentials` (scope `tenant-quota:projection:write`), publishes a plan, creates a subscription, and runs `relay.RunOnce`, then exactly one delivery completes (`Delivered == 1`, `Retried == 0`) and the projection store holds the expected revision/quota — i.e., one `PUT /api/v1/internal/tenant-quota/projection` succeeded end-to-end through the registry-enabled mint path.
7. Given the mint in case 6, when the registry did NOT register `tenant-quota:projection:write` (the pre-fix composition, `NewMemory(Matrix(), nil)` — a negative control), then the mint returns 400 `invalid_scope` and no delivery occurs. (Optional but cheap; proves the test exercises the registry seam rather than a bypass. If included, keep it as a separate subtest on its own server.)

Acceptance mapping grade: 7/7 machine-checked under root gates — `go test ./test/ -run 'TestScopeRegistry_Billing|TestE2EQuotaProjection' -v`. Cases 1-5 fail on regression under named assertions; case 6 fails if the registry seam, the mint path, or the delivery breaks; case 7 (if included) is the negative control. No review-only invariants.

## 7. Engineering-gate constraints (verified)

- **`interfaces/sso` is at its 60-file ceiling** — no new non-test file there; this direction touches no `interfaces/sso` files at all (the registry seam, `server_token.go:204` / `token_client_credentials.go:43-47`, is already tested and unchanged).
- **No package imports `cmd/`**: the pin test compares literals/constants (existing precedent `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault`, `scope_registry_test.go:387`); `test/` never imports `cmd/snaplink-billing`.
- **Budgets**: changes are test-only plus one helm values block. `test/scope_registry_test.go` grows by ~2 test functions + a small YAML helper (well under file budget); no production function touched; `TestMaintainability_|TestArchitecture_` unaffected.
- **Wire/contract invariants untouched**: no routes, no `Err*`, no config keys (the `oauth.scope_registry` block is an existing documented knob, `docs/config-reference.md:20`), no audit events, no credential-endpoint headers, no SSRF surface. Registry default-off byte-compat is preserved (`enabled: false`).
- **Oracle-safe response tables unaffected**: the byte-identical 400 `invalid_scope` shape is preserved (case 3 asserts it).
- **Helm values render path verified**: `ops/deploy/helm/sso-server/templates/configmap.yaml:9-10` renders `.Values.config` verbatim (`toYaml`) into `/etc/sso/config.yaml`, so the added block reaches the server config; `validateScopeRegistry` grammar-checks it ALWAYS (fail-closed even at `enabled: false`).
- **Root module dependency**: `github.com/goccy/go-yaml v1.19.2` is already a direct dependency (`go.mod:14`) — the YAML helper adds no module changes.

## 8. Files

### Modify

```text
test/scope_registry_test.go
    - R1: add billing registration-set constant, srBillingRegistry helper
      (NewMemory(scopecontract.Matrix(), billingExtra)), billing relay client
      seed, billing harness variant, TestScopeRegistry_BillingScopesMintable
      (cases 1-3).
    - R2: add deploy-tree YAML helper + TestScopeRegistry_BillingScopeLiteralsRegistered
      (cases 4-5), deriving extra_scopes from the sso-server helm values.
test/quota_projection_e2e_test.go
    - R4: add TestE2EQuotaProjection_RegistryEnabled (cases 6-7): registry-enabled
      server + projection handler, /token client_credentials minting authorizer,
      one RunOnce delivery assertion.
ops/deploy/helm/sso-server/values.yaml
    - R3: add config.oauth.scope_registry {enabled: false, extra_scopes:
      [tenant-quota:projection:write, audit:platform:cross_tenant,
      audit:policy:write]}.
```

### Do not modify

```text
cmd/snaplink-billing/* (non-test) — the boot pins stay; this direction registers
    the pinned scopes registry-side.
interfaces/scopecontract/consts.go — the eight-row matrix stays frozen.
shared/core/consts.go, config/config_oauth2.go, protocols/oauth/scoperegistry/*,
    interfaces/sso/*, cmd/sso-server/* — no behavior change.
ops/deploy/helm/snaplink-billing/values.yaml — billing's own values stay; the
    pin test reads them (read-only).
docs/config-reference.md, docs/openapi.yaml, docs/error-codes.md — nothing to add.
```

## 9. Dependencies and compatibility

- New/changed SPI: none (test-only + deploy-tree values).
- New option/store wiring: none (registry construction already exists; tests reuse the composition `cmd/sso-server/build_stores.go:305-310` performs in production).
- New YAML/env keys: `oauth.scope_registry` block in the sso-server helm values — an existing documented config key surface (`docs/config-reference.md:20`), previously absent from the deploy tree. `enabled: false` keeps the deployed server byte-identical.
- Storage migration: none. HTTP/proto compatibility: none. Module graph: none (root module only; `github.com/goccy/go-yaml` already present).
- Rollout/rollback: the helm block is additive and inert at `enabled: false`; removing it restores the tree exactly. Tests are additive; removing them restores the previous suite.
- Campaign: advances `docs/campaigns/implementation-gate.md` row 2 (B4-2, T-8(d)) and the G5 gate (line 77, T-8(b-e)) for billing's machine scopes: the "矩阵配给后端到端无 403" contract now holds for `tenant-quota:projection:write`, the retention platform pair, and the audit relay scope, with the deploy-tree registration pinned against the billing boot literals.

## 10. Documentation

- [ ] `docs/config-reference.md` — not applicable (knob already documented at line 20; this direction wires a deploy-tree default under it).
- [ ] `docs/openapi.yaml` / `docs/error-codes.md` — not applicable (no endpoint, no `Err*`).
- [x] Campaign bookkeeping: B4-2 row and G5 gate advanced via T-8(d)/T-8(e) coverage as described in §9.

## 11. Verification plan

```bash
go build ./... && go vet ./...                                   # root module
go test -run 'TestMaintainability_|TestArchitecture_' .          # root gates
go test ./test/ -run 'TestScopeRegistry_BillingScopesMintable|TestScopeRegistry_BillingScopeLiteralsRegistered|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody|TestScopeRegistry_MatrixScopesMintable|TestScopeRegistry_AuditRelayScopeMatchesBillingDefault' -v
go test ./test/ -run 'TestE2EQuotaProjection' -v                 # R4 (registry-enabled + existing e2e)
go test ./... -race                                             # full suite before handoff
make ci                                                          # handoff gate (includes test/ under ci)
```

Baselines verified during evidence gathering: `go build ./...` clean; the existing `test/scope_registry_test.go` suite and `test/quota_projection_e2e_test.go` pass (no pre-existing failure observed in the touched packages). No nested-module or `cli.py modules` impact (no module/profile change).
