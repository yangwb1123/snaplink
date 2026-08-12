# Requirements Spec: register the audit provisioner's fixed platform-control scopes in the scope-matrix-v2 registry path (pre-G5)

- Direction: "Register the provisioner's fixed platform-control scopes in the scope-matrix-v2 registry before enabling oauth.scope_registry" (source: `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`, entry 1)
- Analysis module: `cmd/snaplink-audit-provisioner`; change surface: root-module tests (`cmd/sso-server/scope_registry_wiring_test.go`, `config/scope_registry_test.go`, `test/scope_registry_test.go`) + deploy-tree registration in `ops/deploy/compose/config.yaml`. No production Go changes to `cmd/snaplink-audit-provisioner` or `infrastructure/auditgovernance` — the provisioner's scope is already fixed in code; this direction makes the registry path honor it.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `infrastructure/auditgovernance/platform_token.go:17-18` — `PlatformProvisioningScope`/`PlatformRetentionScope` | Lines 17-18: `PlatformProvisioningScope = "audit:platform:cross_tenant audit:policy:read audit:policy:write"`, `PlatformRetentionScope = "audit:platform:cross_tenant audit:policy:write"`. `defaultPlatformTokenConfig` (platform_token.go:66-81) defaults an empty config `Scope` to `PlatformProvisioningScope`; `validPlatformScope` (platform_token.go:90-92) accepts exactly these two strings — the scope is a hard-coded boot pin, not configurable. `platformTokenRequest` (platform_token.go:151-166) sends `grant_type=client_credentials` with `scope` as ONE space-joined form parameter plus RFC 8707 `resource` | Confirmed (line exact) |
| `interfaces/scopecontract/consts.go:23-42` — `Matrix()` registers only `audit:event:write` among audit scopes | `Matrix()` (consts.go:25-42) returns exactly nine rows: `admin:read`, `admin:write`, `billing:payment:order:read`, `billing:payment:write`, `billing:checkout:create`, `metering:write`, `billing:entitlement:read`, `audit:event:write` (`ScopeAuditEventWrite = "audit:event:write"`, consts.go:57), `admin:*`. No `audit:platform:cross_tenant`, no `audit:policy:read`, no `audit:policy:write` | Confirmed (line drift 23→25, symbols exact) |
| `protocols/oauth/scoperegistry/reject.go:31-47` — `RejectUnregistered` → 400 `invalid_scope` | `RejectUnregistered` (reject.go:31-44) writes the byte-identical plain `{"error":"invalid_scope"}` body (no `trace_id` — the oracle-safe shape) with status 400 when an EFFECTIVE scope is unregistered; a nil registry (unwired default) and an empty scope set are no-ops — the byte-compat baseline. `FilterRegistered` (reject.go:47-59) drops unregistered scopes from the discovery snapshot only | Confirmed (line exact) |
| `config/config_oauth2.go:30-66` — `validateScopeRegistry` membership check | `validateScopeRegistry` (config_oauth2.go:30-66) runs ALWAYS (matrix/extra grammar + exact-string duplicates, fail-closed even when `enabled: false`); the client `allowed_scopes` membership loop (config_oauth2.go:58-63) runs ONLY when `enabled: true`, building the exact runtime registry from `MatrixOrDefault()` + `ExtraScopes` (config_oauth2.go:52-56) and failing with `client %q allowed_scopes %q is not registered by oauth.scope_registry`. Wired into config load via `validateFeatureConfig` (config/config_load.go:220), so `cmd/sso-server --validate-only` and boot both exercise it | Confirmed (line exact) |
| `ops/deploy/compose/config.yaml:63-67` — `extra_scopes` without audit:policy | `oauth.scope_registry` block (config.yaml:62-67): `enabled: true`, explicit 8-row `matrix` (includes `audit:event:write`, excludes `billing:checkout:create`), `extra_scopes: [billing:checkout:create, tenant-quota:projection:write]` (config.yaml:67). No `audit:policy:*`, no `audit:platform:cross_tenant` anywhere in the file | Confirmed (line exact) |
| `cmd/sso-server/scope_registry_wiring_test.go` — matrix pin test | Four boot-level tests build `buildApp(&config.Config{...})` and assert via `a.server.ScopeRegistry()`: disabled-by-default (nil), enabled builds matrix + protocol scopes, extra_scopes (exact + `domain:*`), provisioned matrix replaces builtin. `buildApp` (cmd/sso-server/build_stores.go:37) does NOT run `validateScopeRegistry` (config validation lives in `config.Load`/`LoadFromSources`); the fail-closed membership gate is unit-tested in `config/scope_registry_test.go` (`TestValidateScopeRegistry`, incl. "membership rejects unregistered allowed_scope") | Confirmed |
| `ops/deploy/audit-provisioner/settings.env` — documented client | `SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID=snaplink-audit-provisioner`, `SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL=https://sso-server.snaplink-sso.svc.cluster.local:8080/token`. The k8s overlay (service/deployment/kustomization) carries no sso-server config — the client and scopes are registered on the server side by the operator | Confirmed |
| Repo-wide grep: `audit:policy:*` / `audit:platform:cross_tenant` appear nowhere else | In Go code and config files the tokens appear ONLY in `infrastructure/auditgovernance/platform_token.go:17-18`. They also appear in documentation that corroborates the fixed contract: `cmd/snaplink-audit-provisioner/README.md:13` ("Register a dedicated OAuth client with exactly this scope string … The scope is fixed in code and cannot be widened by configuration"), `docs/config-reference.md:946` ("The OAuth scope is intentionally not configurable. It is exactly …"), `docs/deployment.md:454,481`, `ops/deploy/{baremetal-ha/RUNBOOK.md:252, helm/snaplink-billing/README.md:84, billing/README.md:113, audit-provisioner/README.md:19}`. No registry matrix, no `extra_scopes` in any deploy tree, no other Go file | Confirmed for code/config (docs corroborate) |
| `cmd/snaplink-audit-provisioner/run.go:50` — module sends the fixed scope | `buildProvisioner` builds `auditgovernance.NewPlatformTokenSource(PlatformTokenConfig{TokenURL, ClientID, ClientSecret, Resource, Timeout, AllowInsecureLoopback}, nil)` with NO `Scope` field → `defaultPlatformTokenConfig` substitutes `PlatformProvisioningScope`; `validPlatformTokenConfig`/`validPlatformScope` reject any other value at boot. The binary cannot mint with any other scope string | Confirmed |
| `ops/deploy/compose/compose.yaml:227-248` — compose deploys the provisioner against sso-server | Service `snaplink-audit-provisioner` (profile `audit-provisioning`) POSTs to `${AUDIT_PROVISIONER_TOKEN_URL:-https://sso-server:8080/token}` with client id `${AUDIT_PROVISIONER_CLIENT_ID:-snaplink-audit-provisioner}` and resource `audit-governance` — the same `/token` URL as `settings.env`. The compose sso-server config (`config.yaml`, mounted at compose.yaml:57) registers NO audit-provisioner client and none of the three scopes, so an operator-registered provisioner client minting under the enabled registry gets 400 `invalid_scope` | Confirmed |
| `test/scope_registry_test.go` — existing B4-2 sweep (the T-8(d) home) | `srRegistry` = `NewMemory(scopecontract.Matrix(), nil)` (line 41-47); `srCC` (line 104-124) POSTs `/token` `client_credentials` with a `scope` form param; `TestScopeRegistry_MatrixScopesMintable` (line 161+) mints the nine matrix rows; `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` pins the byte-identical plain 400 body. `test/` already imports `infrastructure/auditgovernance` (test/auditoutbox_governance_test.go:39) — the structural pin via `PlatformProvisioningScope` is legal from `package ssotest` | Confirmed |
| `Makefile` `config-validate` target | Lines 158/406 sweep `ops/deploy/compose/config.yaml` (among six deploy configs) through `cmd/sso-server --config=… --validate-only`, which runs config load → `validateScopeRegistry`. The modified compose file must stay green under `make ci` | Confirmed |

**Gap confirmation (the direction's problem is real).** Today `Matrix() ∪ ProtocolScopes() ∪ compose extra_scopes` registers none of the three tokens in `PlatformProvisioningScope`. Consequences under the compose tree, where `oauth.scope_registry.enabled: true` (config.yaml:64):

1. Any operator who follows the module's own documented contract (`cmd/snaplink-audit-provisioner/README.md` — "Register a dedicated OAuth client with exactly this scope string") and declares that client in a server config file fails boot-closed: `validateScopeRegistry` membership (config_oauth2.go:58-63) rejects `audit:policy:read` first with `client %q allowed_scopes %q is not registered by oauth.scope_registry`.
2. A client registered out-of-band (DCR/admin API, as the k8s overlay directs) boots, but every `/token` mint carrying the space-joined `PlatformProvisioningScope` string is rejected by `RejectUnregistered` (reject.go:31-44) with 400 `invalid_scope` — the provisioner's `PlatformTokenSource` then retries forever and the reconciliation loop never applies a manifest.

The fix path is the documented `extra_scopes` extension (config_oauth2.go doc comment: extra_scopes feed the registry only, never discovery; the matrix stays frozen at nine rows by B4-2).

## 2. Goal and user outcome

The scope-matrix-v2 registry (B4-2) becomes safe to enable (G5) without breaking the audit provisioner's machine token. Concretely:

- The three platform-control tokens (`audit:platform:cross_tenant`, `audit:policy:read`, `audit:policy:write`) are registered through the `extra_scopes` path in the compose deploy tree, which already runs `enabled: true`.
- Registry-side tests pin both halves of the failure mode: a client whose `allowed_scopes` equal the provisioner's fixed string boots cleanly and mints 200 through a `client_credentials` `/token` exchange (one space-joined scope parameter, byte-identical to how `PlatformTokenSource` sends it), while the unregistered negative control still returns the byte-identical plain 400 `invalid_scope` (no registry oracle).
- A parity test derives the registered set from `ops/deploy/compose/config.yaml` and asserts it covers the module's code-pinned scope string, so the deploy tree cannot silently drift from `PlatformProvisioningScope`.

Completion marker: T-8(d) of `docs/campaigns/implementation-gate.md` (row 2, line 12: "矩阵配给后 vault/aero-id 端到端无 403") holds for the provisioner's platform-control scopes, and the G5 gate (line 77, T-8(b–e)/T-2) stays sweep-compatible: the existing `TestBuildApp_ScopeRegistry*` and `TestScopeRegistry_*` suites remain green, and `make ci` `config-validate` still passes with the modified compose config.

## 3. Product boundary

- Surface: registry registration + registry-side tests only. No behavior change to `cmd/snaplink-audit-provisioner` (its scope is fixed in `infrastructure/auditgovernance` and stays byte-identical), no scope-contract table change (`interfaces/scopecontract.Matrix()` stays nine rows — the B4-2 contract; the extension path is `extra_scopes`), no `/token` behavior change (registry remains default-off outside deploy trees that opt in; the compose tree already opted in).
- Defaults: the compose tree already runs `enabled: true`; this direction only adds the three tokens to its `extra_scopes`. No other deploy tree is touched (helm values, k8s, baremetal-ha carry no registry block and are out of scope — the direction names `ops/deploy/compose/config.yaml` only).
- Explicit non-goals (do not implement):
  - No change to the nine-row `scopecontract.Matrix()`; no change to `shared/core`, `config/config_oauth2.go`, `protocols/oauth/scoperegistry/*`, `interfaces/sso/*` non-test files, or `cmd/sso-server/*` non-test files.
  - No change to `infrastructure/auditgovernance/*` or `cmd/snaplink-audit-provisioner/*` (non-test) — the fixed scope string and the mint are already correct; the gap is registry-side.
  - No new config keys, `Err*`, OpenAPI surface, audit events, or endpoints. `docs/config-reference.md` already documents `oauth.scope_registry`; the module README already documents the scope contract.
  - The provisioner client is NOT added to `ops/deploy/compose/config.yaml`: the k8s overlay (`ops/deploy/audit-provisioner/`) documents out-of-band client registration with an operator-supplied secret, and compose registers the client the same way (secret bind-mounted at compose.yaml:248). Registering the scopes is necessary for that client to mint under the enabled registry; registering the client itself is a separate deployment concern outside this direction.
  - No change to the registry rejection shape (byte-identical `{"error":"invalid_scope"}`, no `trace_id` — already pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody`).
  - No test imports `cmd/snaplink-audit-provisioner` or any `cmd/` package (AGENTS.md: no package imports `cmd/`); pins use the `infrastructure/auditgovernance` constant directly (existing precedent: `test/auditoutbox_governance_test.go:39`).

## 4. Module classification

- [x] Infrastructure/config/deployment (registry registration in the compose deploy tree)
- [x] Testing (boot-wiring pin, config-gate pin, `/token` mint sweep, deploy-tree parity)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layers: `cmd/sso-server/scope_registry_wiring_test.go` (boot-level composition test, package main), `config/scope_registry_test.go` (config-gate unit test, package config), `test/scope_registry_test.go` (`package ssotest` — the B4-2 sweep home), and `ops/deploy/compose/config.yaml` (deploy tree). Registry construction in tests follows the existing composition rule: `scoperegistry.NewMemory(scopecontract.Matrix(), extras)` exactly as `cmd/sso-server/build_stores.go:305-312` does in production — protocols never imports interfaces.

## 5. Requirements

### R1 — Boot-wiring pin: provisioner client boots cleanly under the enabled registry (Leg A)

Extend `cmd/sso-server/scope_registry_wiring_test.go` with `TestBuildApp_ScopeRegistryRegistersProvisionerScopes`:

- Registration set: `provisionerScopes = strings.Fields(auditgovernance.PlatformProvisioningScope)` — the test imports `infrastructure/auditgovernance` (legal composition-root downward edge; the pin is structural, not a literal copy).
- Config: `cfg.OAuth.ScopeRegistry.Enabled = true`, `cfg.OAuth.ScopeRegistry.ExtraScopes = provisionerScopes`, and one client `cfg.Clients = []config.ClientConfig{{ID: "snaplink-audit-provisioner", Secret: "s", Active: true, TokenStrategy: "jwt", AllowedScopes: provisionerScopes}}` (mirrors the documented client; `ClientConfig` needs no `GrantTypes` — YAML clients mint `client_credentials` by default).
- Assertions: `buildApp` succeeds; `a.server.ScopeRegistry()` is non-nil; `reg.Registered("audit:policy:read")`, `reg.Registered("audit:policy:write")`, `reg.Registered("audit:platform:cross_tenant")` all true.
- Negative control: same config without `ExtraScopes` — `buildApp` still succeeds (buildApp does not validate) but all three `Registered` calls are false, proving the registration is what makes the client mintable.

### R2 — Config-gate pin: membership fail-closed and pass-open (Leg A, boot-closed half)

Extend `config/scope_registry_test.go` (`TestValidateScopeRegistry`) with two provisioner subtests:

- "membership rejects unregistered provisioner scope": `Enabled = true`, `Matrix = scopecontract.Matrix()` (no extras), client with `AllowedScopes = provisionerScopes` → `validateScopeRegistry` returns an error naming the client id, the first unregistered token, and `oauth.scope_registry` (mirrors the existing "membership rejects unregistered allowed_scope" subtest).
- "membership accepts provisioner scopes via extra_scopes": same client, `ExtraScopes = provisionerScopes` → `nil`.

The literal set is derived from `auditgovernance.PlatformProvisioningScope` (package `config` may import `infrastructure/auditgovernance` — downward edge; keeps the pin structural).

### R3 — Deploy-tree registration: compose `extra_scopes` gains the three tokens (T-2)

Modify `ops/deploy/compose/config.yaml:67`:

```yaml
    extra_scopes: [billing:checkout:create, tenant-quota:projection:write,
                   audit:platform:cross_tenant, audit:policy:read, audit:policy:write]
```

- The compose tree already runs `enabled: true` (config.yaml:64), so this is the registration that makes an operator-registered provisioner client mintable in the dev stack. Purely additive: the existing three seeded clients' `allowed_scopes` stay registered, so `make ci` `config-validate` (Makefile:158/406) stays green.
- No `matrix` key change: the built-in nine-scope table (`MatrixOrDefault()` with the provisioned 8-row matrix minus `billing:checkout:create` is the compose tree's own choice) stays as-is; only the three missing tokens ride `extra_scopes`.
- No change to `enabled` (stays `true` — the compose tree's documented state), no provisioner client added (see §3 non-goals).

### R4 — `/token` mint sweep: provisioner scope string mints 200 (Leg B)

Extend `test/scope_registry_test.go`:

- Add `srProvisionerScopes = strings.Fields(auditgovernance.PlatformProvisioningScope)` and a harness variant `newScopeRegistryProvisionerHarness` (registry ON) wired with `scoperegistry.NewMemory(scopecontract.Matrix(), srProvisionerScopes)` and a seeded provisioner client (`sso.Client{ID: srClientProvisioner, Secret: srSecret, Active: true, TokenStrategy: "jwt", AllowedScopes: srProvisionerScopes, GrantTypes: []string{"client_credentials"}}` — the T-C invariant from `test/client_tenant_binding_test.go`).
- New test `TestScopeRegistry_ProvisionerScopeMintable`: `srCC` POST `/token` `client_credentials` with `scope = auditgovernance.PlatformProvisioningScope` (ONE space-joined parameter, byte-identical to `platformTokenRequest` platform_token.go:146-151) returns 200 and the token's `scope` claim contains all three tokens.
- Negative control (separate subtest, own server): the same mint against the existing matrix-only `srRegistry` harness (no extras) returns 400 with a body byte-identical to the plain `{"error":"invalid_scope"}` shape pinned by `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` — raw-body equality, no registry-state oracle. Proves the test exercises the registry seam rather than a bypass.

### R5 — Deploy-tree parity pin: compose registration covers the module's fixed scope string (T-2)

Add to `test/scope_registry_test.go` `TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree`:

- Parse `ops/deploy/compose/config.yaml` with `github.com/goccy/go-yaml` (already a root-module direct dependency, go.mod:14, used by `cmd/sso-ctl/configcmd/schema.go`).
- Derive the registered set exactly as the runtime registry construction would: `matrix` from `oauth.scope_registry.matrix` (falling back to `scopecontract.Matrix()` when absent — `MatrixOrDefault` semantics) + the pre-seeded protocol set (`openid`, `device_sso`, `profile`, `email`, `address`, `phone`, `offline_access`) + `extra_scopes`.
- Assert every token of `auditgovernance.PlatformProvisioningScope` is a member; assert the file's `scope_registry.enabled` is present. Fail conditions: any provisioner token drifts out of the compose registration, or the `oauth.scope_registry` block is removed — the unwired state this direction fixes.

## 6. Testable acceptance (Given/When/Then)

Preserved from the direction; each check made machine-testable:

**Leg A — boot (wiring + config gate):**

1. Given `scope_registry.enabled: true` with `extra_scopes` = the three provisioner tokens and a client whose `allowed_scopes` equal `PlatformProvisioningScope`, when `buildApp` runs (extended `TestBuildApp_ScopeRegistryRegistersProvisionerScopes`), then boot succeeds and `reg.Registered("audit:policy:read") == true`, `reg.Registered("audit:policy:write") == true`, `reg.Registered("audit:platform:cross_tenant") == true`. (Fail condition: any token unregistered — the boot-closed breakage.)
2. Given the same client config WITHOUT the `extra_scopes` registration, when `validateScopeRegistry` runs (R2 subtest), then it returns the `is not registered by oauth.scope_registry` error naming the client and token; with the registration, `nil`. (Fail condition: the fail-closed gate regresses or the registration stops satisfying it.)

**Leg B — mint (T-8(d) sweep-compatible):**

3. Given a registry-enabled server with matrix + provisioner extras and the provisioner client seed, when `client_credentials` POSTs `/token` with `scope = "audit:platform:cross_tenant audit:policy:read audit:policy:write"` (one space-joined parameter, exactly as `PlatformTokenSource` sends it), then 200 and the token's `scope` claim contains all three tokens.
4. Given the same mint against the matrix-only registry (no extras — the pre-fix composition), then 400 with a body byte-identical to the plain `{"error":"invalid_scope"}` rejection (raw-body equality; no trace_id, no registry-state oracle).
5. Given the existing sweep, when the R1-R4 changes land, then `TestBuildApp_ScopeRegistry*` (cmd/sso-server), `TestValidateScopeRegistry` (config), and `TestScopeRegistry_*` (test/) all stay green — no existing pin weakened (T-8/T-9 sweep-compatible).

**Leg C — deploy-tree parity (T-2):**

6. Given `ops/deploy/compose/config.yaml`, when the registered set is derived as `matrix ∪ protocol ∪ extra_scopes` (R5), then every token of `auditgovernance.PlatformProvisioningScope` is a member. (Fail conditions: the compose `extra_scopes` registration is removed, or a provisioner token drifts from the module's fixed string.)
7. Given the modified compose config, when `make ci` runs (or `make config-validate`), then `cmd/sso-server --config=ops/deploy/compose/config.yaml --validate-only` passes — the file stays a valid enabled-registry snapshot.

Acceptance mapping grade: 7/7 machine-checked under root gates — `go test ./config/ -run TestValidateScopeRegistry`, `go test ./cmd/sso-server/ -run 'TestBuildApp_ScopeRegistry'`, `go test ./test/ -run 'TestScopeRegistry_Provisioner|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody' -v`, plus `make config-validate`. No review-only invariants.

## 7. Engineering-gate constraints (verified)

- **`interfaces/sso` is at its 60-file ceiling** — no new non-test file there; this direction touches no `interfaces/sso` files at all (the registry seam, `interfaces/sso/server_token.go:204` / `internal/handler/tokengrant/token_client_credentials.go:46`, is already tested and unchanged).
- **No package imports `cmd/`**: the pins import `infrastructure/auditgovernance` from `cmd/sso-server` (test file; composition-root downward edge, legal), `config` (downward edge, legal), and `test/` (existing precedent `test/auditoutbox_governance_test.go:39`). No test imports `cmd/snaplink-audit-provisioner` or any `cmd/` package.
- **Budgets**: changes are test-only plus one YAML list. `cmd/sso-server/scope_registry_wiring_test.go`, `config/scope_registry_test.go`, `test/scope_registry_test.go` each grow by ~1-2 test functions + a small helper (well under the 500-line file budget); no production function touched; `TestMaintainability_|TestArchitecture_` unaffected.
- **Wire/contract invariants untouched**: no routes, no `Err*`, no config keys (the `oauth.scope_registry` block is an existing documented knob), no audit events, no credential-endpoint headers, no SSRF surface. Registry default-off byte-compat is preserved everywhere outside the compose tree.
- **Oracle-safe response tables unaffected**: the byte-identical 400 `invalid_scope` shape is preserved (case 4 asserts it).
- **Compose config render path verified**: `ops/deploy/compose/config.yaml` is mounted into sso-server at compose.yaml:57 and swept by `make ci` `config-validate` (Makefile:158/406); the provisioner service (compose.yaml:227-248, profile `audit-provisioning`) mints against that server's `/token`.
- **Root module dependency**: `github.com/goccy/go-yaml v1.19.2` is already a direct dependency (go.mod:14) — the R5 YAML helper adds no module changes.

## 8. Files

### Modify

```text
ops/deploy/compose/config.yaml
    - R3: add audit:platform:cross_tenant, audit:policy:read, audit:policy:write
      to oauth.scope_registry.extra_scopes (config.yaml:67). enabled stays true.
cmd/sso-server/scope_registry_wiring_test.go
    - R1: TestBuildApp_ScopeRegistryRegistersProvisionerScopes (buildApp boots
      with enabled + extras + provisioner client; Registered x3; negative
      control without extras). Imports infrastructure/auditgovernance.
config/scope_registry_test.go
    - R2: two TestValidateScopeRegistry subtests (membership rejects
      unregistered provisioner scope; accepts via extra_scopes).
test/scope_registry_test.go
    - R4: srProvisionerScopes + provisioner client seed + registry-enabled
      harness variant; TestScopeRegistry_ProvisionerScopeMintable (200) and
      negative control (byte-identical 400 invalid_scope).
    - R5: TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree (compose
      config.yaml parity; goccy/go-yaml).
```

### Do not modify

```text
cmd/snaplink-audit-provisioner/* (non-test) — the fixed scope pin stays; this
    direction registers the pinned scopes registry-side.
infrastructure/auditgovernance/* — the scope constants and PlatformTokenSource
    stay byte-identical.
interfaces/scopecontract/consts.go — the nine-row matrix stays frozen.
shared/core/*, config/config_oauth2.go, protocols/oauth/scoperegistry/*,
    interfaces/sso/*, cmd/sso-server/* (non-test) — no behavior change.
ops/deploy/helm/*, ops/deploy/k8s*, ops/deploy/baremetal-ha/* — carry no
    scope_registry block; out of scope (direction names compose only).
docs/config-reference.md, docs/openapi.yaml, docs/error-codes.md — nothing to add.
```

## 9. Dependencies and compatibility

- New/changed SPI: none (test-only + deploy-tree YAML).
- New option/store wiring: none (registry construction already exists; tests reuse the composition `cmd/sso-server/build_stores.go:305-311` performs in production).
- New YAML/env keys: none — `extra_scopes` entries ride the existing documented `oauth.scope_registry` block (`docs/config-reference.md`), which the compose tree already enables.
- Storage migration: none. HTTP/proto compatibility: none. Module graph: none (root module only; `github.com/goccy/go-yaml` already present).
- Rollout/rollback: the compose `extra_scopes` addition is additive and inert until a provisioner client actually mints (no client is added by this direction); removing the three tokens restores the tree exactly. Tests are additive; removing them restores the previous suite.
- Campaign: advances `docs/campaigns/implementation-gate.md` row 2 (B4-2, T-8(d)) and the G5 gate (line 77) for the provisioner's platform-control scopes: the "矩阵配给后端到端无 403" contract now holds for `audit:platform:cross_tenant` / `audit:policy:read` / `audit:policy:write`, with the compose registration pinned against the code constant.

## 10. Documentation

- [ ] `docs/config-reference.md` — not applicable (the knob and the provisioner's fixed scope are already documented at lines 879/946).
- [ ] `docs/openapi.yaml` / `docs/error-codes.md` — not applicable (no endpoint, no `Err*`).
- [x] Campaign bookkeeping: B4-2 row and G5 gate advanced via T-8(d) coverage as described in §9.

## 11. Verification plan

```bash
go build ./... && go vet ./...                                   # root module
go test -run 'TestMaintainability_|TestArchitecture_' .          # root gates
go test ./config/ -run TestValidateScopeRegistry -v              # R2 (config gate)
go test ./cmd/sso-server/ -run 'TestBuildApp_ScopeRegistry' -v    # R1 (boot wiring; tests live in cmd/sso-server, package main)
go test ./test/ -run 'TestScopeRegistry_ProvisionerScopeMintable|TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody|TestScopeRegistry_MatrixScopesMintable' -v  # R4/R5 + sweep
make config-validate                                             # compose config stays a valid enabled-registry snapshot
go test ./... -race                                             # full suite before handoff
make ci                                                          # handoff gate (includes config-validate)
```

Baselines verified during evidence gathering: `go build ./...` clean; the existing `cmd/sso-server/scope_registry_wiring_test.go`, `config/scope_registry_test.go`, and `test/scope_registry_test.go` suites pass (no pre-existing failure observed in the touched packages). No nested-module or `cli.py modules` impact (no module/profile change).
