# Design: register the audit provisioner's fixed platform-control scopes in the scope-matrix-v2 registry path (pre-G5)

- Source direction: "Register the provisioner's fixed platform-control scopes in the scope-matrix-v2 registry before enabling oauth.scope_registry" (`docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`, entry 1)
- Requirements: `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-2-scope-registry-requirements.md` (R1–R5)
- Status: design (every evidence citation re-verified against HEAD at commit `374f9890`)

## 1. Evidence verification verdict

All seven cited claims plus nine supporting claims were re-checked against the repository. All are **confirmed**. Baselines measured during verification: `go build ./...` clean; `go test ./config/ -run TestValidateScopeRegistry`, `go test ./cmd/sso-server/ -run TestBuildApp_ScopeRegistry`, and the two `TestScopeRegistry_MatrixScopesMintable|TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` suites pass; `go run ./cmd/sso-server --config=ops/deploy/compose/config.yaml --validate-only` exits 0. **Pre-existing root-gate failures, unrelated to this direction** (see §6.7): `TestArchitecture_DirectoryDepth`, `TestArchitecture_DirectorySubdirFanout` (docs/architect-analysis/auto batch artifacts; root fanout 24 > frozen 21), `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539 lines).

| Claim | Verified reality | Verdict |
|---|---|---|
| `platform_token.go:17-18` scope constants; scope fixed in code | `PlatformProvisioningScope = "audit:platform:cross_tenant audit:policy:read audit:policy:write"`, `PlatformRetentionScope = "audit:platform:cross_tenant audit:policy:write"`; `defaultPlatformTokenConfig` (66-81) defaults empty Scope to `PlatformProvisioningScope`; `validPlatformScope` (90-92) accepts exactly these two strings; `platformTokenRequest` (151-166) sends `grant_type=client_credentials` with ONE space-joined `scope` form param + RFC 8707 `resource` | Confirmed |
| `scopecontract.Matrix()` = 9 rows, only `audit:event:write` among audit | `Matrix()` (consts.go:25-42) returns nine rows incl. `ScopeAuditEventWrite = "audit:event:write"` (consts.go:57); no `audit:platform:cross_tenant` / `audit:policy:*` | Confirmed |
| `RejectUnregistered` → 400 plain `invalid_scope`, nil-registry no-op | reject.go:31-44: `reg == nil || len(scopes) == 0` no-op; otherwise 400 + `core.ErrorBody(core.ErrInvalidScope)` (no trace_id — oracle-safe shape); `FilterRegistered` (47-59) drops unregistered scopes from discovery only | Confirmed |
| `validateScopeRegistry` membership only when enabled, exact error string | config_oauth2.go:30-66: matrix/extra grammar + duplicate checks ALWAYS (fail-closed even disabled); membership loop (58-63) only when `enabled: true`, builds registry from `MatrixOrDefault()` + `ExtraScopes`, error `client %q allowed_scopes %q is not registered by oauth.scope_registry (matrix + protocol scopes + extra_scopes)`; wired at config_load.go:220 in `validateFeatureConfig` → `--validate-only` and boot | Confirmed |
| compose `config.yaml:62-67` — `enabled: true`, extra_scopes without audit scopes | `oauth.scope_registry`: `enabled: true`, provisioned 8-row `matrix` (incl. `audit:event:write`, excl. `billing:checkout:create`), `extra_scopes: [billing:checkout:create, tenant-quota:projection:write]`; the three compose clients' `allowed_scopes` (lines 32/41/50) are all registered today — the file passes `--validate-only` (measured) | Confirmed |
| `scope_registry_wiring_test.go` + `settings.env` | Four `TestBuildApp_ScopeRegistry*` tests build `buildApp(&config.Config{...})` and assert via `a.server.ScopeRegistry()`; `ops/deploy/audit-provisioner/settings.env` documents client `snaplink-audit-provisioner` → `https://sso-server.snaplink-sso.svc.cluster.local:8080/token` | Confirmed |
| Repo-wide grep: tokens appear only in `platform_token.go` | `grep -rn --include='*.go' --include='*.yaml' --include='*.env' -e 'audit:policy:' -e 'audit:platform:cross_tenant'` matches only platform_token.go:17-18 (docs/architect-analysis excluded); no registry matrix, no extra_scopes, no other Go file | Confirmed |
| `buildApp` does not run `validateScopeRegistry` | Zero references in `cmd/sso-server/` (grep); registry construction at build_stores.go:305-312 (`NewMemory(MatrixOrDefault(), ExtraScopes)` when enabled, `WithScopeRegistry`); config validation lives in `config.Load` | Confirmed |
| compose.yaml:227-248 deploys the provisioner against sso-server | Service `snaplink-audit-provisioner` (profile `audit-provisioning`) POSTs `${AUDIT_PROVISIONER_TOKEN_URL:-https://sso-server:8080/token}`, client `snaplink-audit-provisioner`, resource `audit-governance`, secret bind-mounted — same contract as settings.env; compose sso-server config registers no provisioner client and none of the three scopes — the live gap | Confirmed |
| `test/scope_registry_test.go` sweep shape | `srRegistry` = `NewMemory(scopecontract.Matrix(), nil)` (41-47); `srSeedClients` seeds matrix-allowlist + unrestricted `srClientAny` (nil allowlist — registry is the only gate); `srCC` (104-124) POSTs `/token` `client_credentials` with `scope` form param; `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` (184-218) pins raw-body `{"error":"invalid_scope"}` + no trace_id | Confirmed |
| T-C invariant (`client_tenant_binding_test.go`) | `GrantTypes: []string{"client_credentials"}` on cc clients (line 67); `interfaces/sso/server_token.go:111` — `len(client.GrantTypes) > 0` guard ⇒ **empty GrantTypes = unrestricted (backward compat)**; `ClientConfig` (config/config_client.go) has **no** `GrantTypes` field, so YAML-seeded clients always carry nil | Confirmed |
| Protocol preseed set | `scoperegistry.ProtocolScopes()` (registry.go:42-52): openid, device_sso, profile, email, address, phone, offline_access — preseeded by `NewMemory` construction, not config | Confirmed |
| `goccy/go-yaml` direct dep | go.mod:14 `github.com/goccy/go-yaml v1.19.2` | Confirmed |
| Makefile `config-validate` sweeps the compose file | Both `config-validate` loops (Makefile ~156 and ~404) include `ops/deploy/compose/config.yaml`; `ci` depends on `config-validate-all` | Confirmed |
| Campaign rows | `docs/campaigns/implementation-gate.md` row 2 T-8(d) ("矩阵配给后 vault/aero-id 端到端无 403") and G5 gate (line 77) reference B4-2 scope registry | Confirmed |

### 1.1 Nuances the requirements spec glosses over (design decisions in §4)

1. **`ClientConfig` cannot express `GrantTypes` at all** — the field does not exist in `config/config_client.go`, and seeded clients carry nil, which `server_token.go:111` treats as unrestricted. R1's buildApp client therefore needs no grant list (and none can be set); R4's `sso.Client` seed sets `GrantTypes: []string{"client_credentials"}` explicitly, matching the T-C invariant and the module's documented contract (stricter than necessary but provably mintable).
2. **R1's negative control can only assert registration *absence*, never boot failure** — `buildApp` does not run `validateScopeRegistry` (verified: zero references in `cmd/sso-server/`). The boot-closed half is enforced by `config.Load` (config_load.go:220) and pinned by R2. The requirements' split of Leg A into R1 (wiring truth) + R2 (config-gate truth) is therefore not a workaround but the only faithful decomposition; the design keeps it.
3. **R5's parity derivation must read the compose file's provisioned 8-row matrix** — `MatrixOrDefault()` is bypassed whenever `matrix` is present (build_stores.go:306; `TestScopeRegistryConfigMatrixOrDefault` at config/scope_registry_test.go:183 pins the fallback). The protocol preseed must come from the exported `scoperegistry.ProtocolScopes()` so the pin is structural, not a literal copy.
4. **The R4 negative control needs no new client** — `srClientAny` (nil allowlist) is exactly the "registry is the only gate" path the byte-identical test already exercises; the negative mint runs it against the existing matrix-only `srRegistry` harness.
5. **Layer legality of the test imports is confirmed** — `config`, `cmd/sso-server`, and `test/` are composition (layer 6 per architecture_layer_test.go:31-34); `infrastructure` is layer 4; the edge is downward and legal, with precedent `test/auditoutbox_governance_test.go:39`.

**Gap confirmation (the direction's problem is real and live in compose).** Under the compose tree (`enabled: true`), the registered set is 8 matrix rows + 7 protocol scopes + 2 extras — none of the three provisioner tokens. An operator following the module's documented contract (README: "Register a dedicated OAuth client with exactly this scope string") either (a) declares the client in a server config file → `config.Load` fails boot-closed on `audit:policy:read` membership, or (b) registers out-of-band (as the k8s overlay directs) → every `/token` mint is rejected by `RejectUnregistered` with 400 `invalid_scope`, `PlatformTokenSource` wraps `ErrTokenUnavailable: platform token HTTP 400`, and the reconciliation loop never applies a manifest.

## 2. Design overview

One deploy-tree registration + registry-side pins. No production Go changes anywhere.

```text
provisioner (fixed, unchanged)              registry path (this change)
┌───────────────────────────────┐   ┌──────────────────────────────────────────┐
│ auditgovernance.Platform-     │   │ Matrix() (9 rows, frozen)                │
│ ProvisioningScope (code pin)  │──▶│ ∪ ProtocolScopes() (7, preseeded)        │
│ └─ /token client_credentials  │   │ ∪ compose extra_scopes  ── R3 adds the 3 │
│    one space-joined scope     │   │   provisioner tokens here                │
└───────────────────────────────┘   └──────────────┬───────────────────────────┘
                                                   │ buildApp (build_stores.go:305)
                                     ┌─────────────▼─────────────┐
                                     │ config.Load gate (R2 pin) │ boot-closed
                                     │ /token RejectUnregistered │ runtime (R4 pin)
                                     └───────────────────────────┘
```

- **Spine**: the three platform-control tokens ride the existing `oauth.scope_registry.extra_scopes` extension path in the compose deploy tree (already `enabled: true`). `extra_scopes` feed the registry only, never discovery; the nine-row matrix stays frozen (B4-2 contract).
- **Pins**: boot-wiring (R1, `cmd/sso-server`), config-gate membership (R2, `config/`), `/token` mint + byte-identical negative control (R4, `test/`), deploy-tree parity against the code constant (R5, `test/`, goccy/go-yaml). Every pin derives the token set from `auditgovernance.PlatformProvisioningScope` (structural), never a literal.
- **Zero new surface**: no endpoints, no `Err*`, no config keys, no audit events, no headers, no module/profile change, no nested-module impact.

## 3. API changes

**None to production APIs.** The public contract surface is deliberately untouched:

- No endpoint, `Err*`, OpenAPI row, audit event type, credential-endpoint header, or middleware change.
- No change to `interfaces/scopecontract.Matrix()` (nine rows stay frozen), `protocols/oauth/scoperegistry/*`, `config/config_oauth2.go`, `interfaces/sso/*` non-test, or `cmd/sso-server/*` non-test.
- No change to `infrastructure/auditgovernance/*` or `cmd/snaplink-audit-provisioner/*` (non-test) — the fixed scope string and the mint are already correct; the gap is registry-side.
- The only configuration change is additive content inside an existing, documented key: `ops/deploy/compose/config.yaml` → `oauth.scope_registry.extra_scopes` gains three entries (no schema change; `docs/config-reference.md` already documents the block).
- The one behavioral delta: in the compose tree (and only there), a registered client whose `allowed_scopes` equal `PlatformProvisioningScope` becomes mintable at `/token`; the unregistered negative still gets the byte-identical plain 400. Registry stays default-off (nil) everywhere else — byte-identical servers.
- Test surface: four test files (three gain functions, one new file `test/scope_registry_compose_parity_test.go`); no exported symbols outside test packages; no test imports any `cmd/` package (AGENTS.md rule).

## 4. Concrete changes

### 4.1 R1 — boot-wiring pin (`cmd/sso-server/scope_registry_wiring_test.go`)

New `TestBuildApp_ScopeRegistryRegistersProvisionerScopes` (package main):

- `provisionerScopes := strings.Fields(auditgovernance.PlatformProvisioningScope)` — import `infrastructure/auditgovernance` (composition-root downward edge; structural pin).
- Config: `cfg.OAuth.ScopeRegistry.Enabled = true`; `ExtraScopes = provisionerScopes`; one client `config.ClientConfig{ID: "snaplink-audit-provisioner", Secret: "s", Active: true, TokenStrategy: "jwt", AllowedScopes: provisionerScopes}` — no `GrantTypes` field exists (§1.1.1; nil = unrestricted).
- Assertions: `buildApp` succeeds; `a.server.ScopeRegistry()` non-nil; `reg.Registered` true for all three tokens.
- Negative control: same config without `ExtraScopes` → `buildApp` still succeeds (buildApp does not validate, §1.1.2) but all three `Registered` calls are false — proves the registration is the operative mechanism, and the boot-closed half is R2's job.

### 4.2 R2 — config-gate membership pin (`config/scope_registry_test.go`)

Two subtests inside `TestValidateScopeRegistry` (pattern: existing "membership rejects unregistered allowed_scope", line 113):

- "membership rejects unregistered provisioner scope": `Enabled = true`, `Matrix = scopecontract.Matrix()` (no extras), client with `AllowedScopes = strings.Fields(auditgovernance.PlatformProvisioningScope)` → error names the client id, the first unregistered token, and `oauth.scope_registry`.
- "membership accepts provisioner scopes via extra_scopes": same client, `ExtraScopes = provisionerScopes` → `nil`.

`config` may import `infrastructure/auditgovernance` (composition → infrastructure, §1.1.5); the pin stays structural.

### 4.3 R3 — compose registration (`ops/deploy/compose/config.yaml:67`)

```yaml
    extra_scopes: [billing:checkout:create, tenant-quota:projection:write,
                   audit:platform:cross_tenant, audit:policy:read, audit:policy:write]
```

- Purely additive: the three existing clients' `allowed_scopes` remain registered, so `make config-validate` stays green (measured baseline: the file validates today).
- No `matrix` key change, no `enabled` change (stays `true`), no provisioner client added (compose registers it out-of-band via secret bind-mount at compose.yaml:248, same as the k8s overlay).

### 4.4 R4 — `/token` mint sweep (`test/scope_registry_test.go`)

- `srProvisionerScopes := strings.Fields(auditgovernance.PlatformProvisioningScope)` (new var, ~4 lines incl. const `srProvisioner = "sr-provisioner"`).
- Harness changes (minimal, all in `test/scope_registry_test.go`): `srRegistry(t, extras ...string)` and `newScopeRegistryHarness(t, registryOn bool, extras ...string)` go variadic — existing call sites (`(t)`, `(t, true/false)`) are unchanged; `srSeedClients` gains one `AddSeed` for `sso.Client{ID: srProvisioner, Secret: srSecret, Active: true, TokenStrategy: "jwt", AllowedScopes: srProvisionerScopes, GrantTypes: []string{"client_credentials"}}` (T-C invariant, ~8 lines).
- `TestScopeRegistry_ProvisionerScopeMintable`: `newScopeRegistryHarness(t, true, srProvisionerScopes...)`; `srCC` POST `/token` `client_credentials` with `scope = auditgovernance.PlatformProvisioningScope` (ONE space-joined parameter, byte-identical to `platformTokenRequest`) → 200 and the token's `scope` claim contains all three tokens (~15 lines).
- `TestScopeRegistry_ProvisionerScopeRejectedWithoutExtras` (negative control, ~14 lines): same mint against `newScopeRegistryHarness(t, true)` (matrix-only registry, no extras) with `srClientAny` (nil allowlist — registry is the only gate) → 400 with raw body byte-identical to `{"error":"invalid_scope"}` (no trace_id), reusing the assertion pattern of `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody`. Proves the positive path exercises the registry seam rather than a bypass.

### 4.5 R5 — deploy-tree parity (`test/scope_registry_compose_parity_test.go`, new file)

R5 lives in its OWN file, not `test/scope_registry_test.go`: the new file owns the `goccy/go-yaml` import and the repo-relative file read (`../ops/deploy/compose/config.yaml` — `go test` runs with CWD = package dir), keeping `scope_registry_test.go` at ~445 lines (R4 alone adds ~50; see the §9 budget table). `TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree` plus a `composeScopeRegistry(t)` helper (~38 lines) that decodes the file's `oauth.scope_registry` block with struct tags (the same decoding the config loader already proves against this file):

- Parse `ops/deploy/compose/config.yaml` with `github.com/goccy/go-yaml` (go.mod:14, existing direct dep; `config/source.go` already decodes this exact block shape via tags).
- Registered set = file's `oauth.scope_registry.matrix` (provisioned 8 rows — `MatrixOrDefault` fallback semantics: fall back to `scopecontract.Matrix()` only when `matrix` absent) ∪ `scoperegistry.ProtocolScopes()` ∪ `extra_scopes`.
- Assert every token of `auditgovernance.PlatformProvisioningScope` is a member; assert `scope_registry.enabled` is present in the file.
- Fail conditions: any provisioner token drifts out of the compose registration, or the `oauth.scope_registry` block is removed (the unwired state this direction fixes).

## 5. Compatibility constraints

| Constraint | Mechanism |
|---|---|
| Nine-row matrix frozen (B4-2) | No `scopecontract.Matrix()` change; extension is `extra_scopes` only, which feeds the registry, never discovery |
| Registry default-off byte-compat | `enabled` default false → nil registry (build_stores.go:305 guard); no other deploy tree carries a registry block and none is touched (helm/k8s/baremetal-ha out of scope per the direction) |
| Wire shape pinned | 400 `{"error":"invalid_scope"}`, no trace_id, oracle-safe — unchanged, asserted byte-identical by the R4 negative control |
| Config gate precedence/order | `validateScopeRegistry` steps and error strings unchanged (deterministic order is testable and pinned); R3 adds registrations only, which cannot break membership |
| Provisioner module contract | `PlatformProvisioningScope` / `PlatformRetentionScope` byte-identical; binary cannot mint any other string (validPlatformScope boot pin) |
| Compose tree stays a valid snapshot | `make ci` `config-validate` sweeps the modified file; baseline validated (exit 0) |
| Seeded-client semantics | YAML clients carry nil GrantTypes = unrestricted (server_token.go:111) — R3 adds no client, so no grant-surface change |
| Dependency graph | No new module deps (goccy/go-yaml present); no `cmd/` imports; no `interfaces/sso` file touched (60-file ceiling); test files stay under the 500-line budget (final layout: ~445/~244/~147 + new ~85-line parity file; see §9) |

## 6. Failure modes

| # | Failure | Detection | Impact | Mitigation |
|---|---|---|---|---|
| 1 | Config-gate boot rejection (pre-change state): enabled registry + client with provisioner allowed_scopes, no extras | `config.Load` / `--validate-only` error at boot | Boot-closed: server refuses to start — the safe failure, but the current dead end for config-declared clients | R2 positive subtest proves `extra_scopes` clears the gate; R3 ships the registration |
| 2 | Runtime mint rejection (pre-change live gap in compose): out-of-band-registered client, unregistered scopes | `RejectUnregistered` → 400 `invalid_scope`; `PlatformTokenSource` wraps `ErrTokenUnavailable: platform token HTTP 400` | Provisioner retries forever; reconciliation loop never applies a manifest; drift between desired and actual audit-governance state | R3 registers the tokens; R4 positive mint proves 200; R4 negative control pins the rejection shape as the controlled baseline |
| 3 | Deploy-tree drift: extras removed or a token renamed in compose | R5 parity test fails at `go test ./test/` | Compose stack reverts to failure mode 2 silently (config still valid — no gate catches it) | R5 structural pin against `PlatformProvisioningScope`; `make ci` runs the sweep |
| 4 | Registry construction error (e.g. malformed pattern) | `NewMemory` error fails boot loudly (build_stores.go:308) | Boot fails — fail-closed by existing design | Grammar validation in `validateScopeRegistry` runs always, even disabled (config_oauth2.go:30-46) |
| 5 | Seam bypass regression: positive mint succeeds without the registry | R4 negative control (byte-identical 400) fails | Registry gate silently ineffective — G5 (T-8(b–e)) vacuous | Byte-identical raw-body assertion, no registry-state oracle |
| 6 | Compose config malformed YAML / invalid snapshot | `make config-validate` fails in `ci` | Deploy tree broken | R3 edit is minimal; `config-validate` is part of `make ci` |
| 7 | Pre-existing root-gate failures (unrelated) | `TestArchitecture_DirectoryDepth`, `TestArchitecture_DirectorySubdirFanout`, `TestMaintainability_FileSizeBudget` fail at HEAD before any change | None for this direction; already failing on main | Reported separately; this direction touches no docs/architect-analysis/auto, no root fan-out, no oversized file |

## 7. Migration steps

1. **Land R3** (compose `extra_scopes`) — deploy-tree-only, inert until a provisioner client actually mints; no client is added by this direction.
2. **Land R1/R2/R4/R5** (test pins) in the same change as R3 per AGENTS.md "update contracts in the same change" (here: the deploy-tree registration and its pins land together).
3. **Verify**: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` (report the three pre-existing failures separately); `go test ./config/ -run TestValidateScopeRegistry -v`; `go test ./cmd/sso-server/ -run TestBuildApp_ScopeRegistry -v`; `go test ./test/ -run 'TestScopeRegistry_Provisioner' -v`; `make config-validate`; `go test ./... -race`; `make ci`.
4. **Operator rollout for other trees (G5)**: in any tree where the provisioner mints against a registry-enabled server, the three tokens must be present in `extra_scopes` (or the provisioned `matrix`) **before** the provisioner client's scopes are declared/registered — the config gate is boot-closed, so the order cannot be wrong at runtime, but the flip is: register scopes first, then enable or keep `enabled: true` (compose), then register the client. The k8s overlay carries no sso-server config (operator-owned), so this direction's compose registration is the reference for the G5 flip; helm/k8s/baremetal-ha are out of scope here.
5. **Rollback**: remove the three tokens from compose `extra_scopes` — the file returns exactly to its prior state and `config-validate` still passes (registration is additive); tests are additive and removable. No store migration, no wire change, no module graph change.

## 8. Testable acceptance mapping

Preserved from the requirements; each check machine-testable under root gates. Verified seams: `srCC` form shape (test/scope_registry_test.go:104-124), `srClientAny` nil-allowlist path (lines 60-65), byte-identical assertion pattern (184-218), buildApp registry construction (build_stores.go:305-312), `MatrixOrDefault` semantics (config/scope_registry_test.go:183).

| # | Given | When | Then | Gate |
|---|---|---|---|---|
| 1 | `enabled: true` + extras = 3 provisioner tokens + client with `allowed_scopes` = `PlatformProvisioningScope` | `buildApp` runs | Boot succeeds; `Registered` true for `audit:policy:read`, `audit:policy:write`, `audit:platform:cross_tenant` | `TestBuildApp_ScopeRegistryRegistersProvisionerScopes` (`go test ./cmd/sso-server/`) |
| 2 | Same client, no extras | `validateScopeRegistry` runs | Error names the client and the FIRST unregistered token in `strings.Fields` order — `client "snaplink-audit-provisioner" allowed_scopes "audit:platform:cross_tenant" is not registered by oauth.scope_registry (matrix + protocol scopes + extra_scopes)` (verbatim, config_oauth2.go:62); with extras → `nil` | R2 subtests (`go test ./config/ -run TestValidateScopeRegistry`) |
| 3 | Registry-enabled server, matrix + provisioner extras, provisioner client seed | POST `/token` `client_credentials`, `scope = auditgovernance.PlatformProvisioningScope` (one space-joined param) | 200; token `scope` claim contains all three tokens | `TestScopeRegistry_ProvisionerScopeMintable` (`go test ./test/`) |
| 4 | Same mint against matrix-only registry, unrestricted client | POST `/token` as above | 400; raw body byte-identical to `{"error":"invalid_scope"}`, no trace_id | R4 negative control (reuses byte-identical pattern) |
| 5 | Existing sweep | R1–R5 land | `TestBuildApp_ScopeRegistry*`, `TestValidateScopeRegistry`, `TestScopeRegistry_*` all stay green — no pin weakened | listed commands + `make ci` |
| 6 | `ops/deploy/compose/config.yaml` | Derive registered set = file matrix ∪ `ProtocolScopes()` ∪ extras | Every token of `PlatformProvisioningScope` is a member; `enabled` present | `TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree` |
| 7 | Modified compose config | `make config-validate` (or `go run ./cmd/sso-server --config=ops/deploy/compose/config.yaml --validate-only`) | Exit 0, "config valid" | Makefile loop (part of `make ci`) |

Acceptance grade: 7/7 machine-checked; no review-only invariants.

## 9. Engineering gates

- **Budgets** — final layout decided after the tight-budget review (R4 ~50 + R5 ~40 on top of 394 would land at ~475-485, too close to 500): R5 moves to its own file. Machine `TestMaintainability_FileSizeBudget` skips `_test.go` (maintainability_budget_test.go:66), so the 500-line cap here is the AGENTS.md budget-table reading, which the layout holds with margin:

  | File | Today | Adds | Final | Headroom under 500 |
  |---|---|---|---|---|
  | `test/scope_registry_test.go` | 394 | R4 only: import +1, `srProvisioner`/`srProvisionerScopes` ~4, variadic harness +3, provisioner seed +8, positive mint ~15, negative control ~14 | ~445 | ~55 |
  | `test/scope_registry_compose_parity_test.go` (new) | — | R5: header ~8, imports ~8, `composeScopeRegistry` helper ~38, test ~16 | ~70-90 | ~410 |
  | `config/scope_registry_test.go` | 208 | R2: `auditgovernance` import +2, two subtests ~17 each | ~244 | ~256 |
  | `cmd/sso-server/scope_registry_wiring_test.go` | 100 | R1: `strings`/`auditgovernance` imports +2, one test ~45 | ~147 | ~353 |

  No production function touched; no new packages (no `layerName()` classification needed); new file is package `ssotest` in the existing `test/` dir (211 `_test.go` files, 0 non-test, 7 subdirs — all gates unaffected).
- **`interfaces/sso` 60-file ceiling**: untouched (seam `interfaces/sso/server_token.go:204` already tested).
- **No `cmd/` imports** in tests: pins use `infrastructure/auditgovernance` from `cmd/sso-server` (test file), `config`, and `test/` — all composition → infrastructure downward edges, precedent `test/auditoutbox_governance_test.go:39`.
- **Wire/contract invariants untouched**: no routes, `Err*`, config keys, audit events, headers, or SSRF surface; oracle-safe rejection shapes preserved.
- **Module/profile**: no `cli.py configure` impact; root `go.mod` unchanged (goccy/go-yaml already direct); no nested module touched.
- **Campaign**: advances `docs/campaigns/implementation-gate.md` row 2 (B4-2, T-8(d)) and the G5 gate (line 77) for the provisioner's platform-control scopes.
- **Files**: modify `ops/deploy/compose/config.yaml`, `cmd/sso-server/scope_registry_wiring_test.go`, `config/scope_registry_test.go`, `test/scope_registry_test.go`; create `test/scope_registry_compose_parity_test.go`; do not modify any production Go, `infrastructure/auditgovernance/*`, `interfaces/scopecontract/consts.go`, or non-compose deploy trees.
