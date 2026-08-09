Verification complete. I re-checked every requirement seam and baseline against the repository at current HEAD (`ff04f683` — one pi-batch bookkeeping commit after the design's cited `374f9890`; all evidence files unchanged), ran the relevant gates, and confirmed the pre-existing failure claims.

## Verdict: design is faithful — all R1–R5 and 7/7 acceptance rows map to concrete machine-checkable changes; Leg-A split and all five §1.1 nuances resolve (not defer) the requirements

### R1–R5 → concrete changes (all seams verified in code)

| Req | Change | Verified seam |
|---|---|---|
| R1 | `TestBuildApp_ScopeRegistryRegistersProvisionerScopes` in `cmd/sso-server/scope_registry_wiring_test.go` | File exists (100 lines); pattern `buildApp(&config.Config{})` + `a.server.ScopeRegistry()` + `reg.Registered` proven by 4 passing tests; `buildApp` confirmed **not** to validate (zero `validateScopeRegistry` refs in `cmd/sso-server/`); `seedClients` (build_app_core.go:79) consumes exactly the R1 `cfg.Clients` shape |
| R2 | Two subtests in `TestValidateScopeRegistry` (`config/scope_registry_test.go`) | "membership rejects unregistered allowed_scope" subtest at line 113 passes today; error string verbatim at config_oauth2.go:62 (`is not registered by oauth.scope_registry (matrix + protocol scopes + extra_scopes)`); `config`→`auditgovernance` import is a legal composition(6)→infrastructure(4) edge per the layer gate (`layerRank[to] <= layerRank[from]`, no exemption) |
| R3 | `ops/deploy/compose/config.yaml:67` `extra_scopes` +3 | File state matches exactly (`enabled: true`, 8-row matrix, 2 extras); Makefile `config-validate` (158) and `config-validate-all` (406) sweep the file; `ci` depends on `config-validate-all` (268) |
| R4 | `TestScopeRegistry_ProvisionerScopeMintable` + negative control in `test/scope_registry_test.go` | `srRegistry`/`srCC`/`srClientAny` (nil allowlist = "registry is the only gate") / byte-identical assertion pattern all present and passing; `sso.Client.GrantTypes` exists (shared/core/types.go:304), T-C invariant at client_tenant_binding_test.go:67; one space-joined `scope` param matches `platformTokenRequest` (platform_token.go:151-166) |
| R5 | `TestScopeRegistry_ProvisionerScopeRegisteredInComposeTree` | `goccy/go-yaml v1.19.2` direct dep (go.mod:14); `scoperegistry.ProtocolScopes()` exported (registry.go:48); `MatrixOrDefault` provisioned-when-present semantics confirmed (config_oauth2.go:138, build_stores.go:306) |

**Baselines I ran**: `go build ./... && go vet ./...` clean; `TestValidateScopeRegistry` 6/6 PASS; `TestBuildApp_ScopeRegistry` 4/4 PASS; `test/` sweep 8/8 PASS; `--validate-only` on compose config exits 0 ("config valid") — the live gap is real. File sizes 100/208/394 match the design's claim. The three pre-existing root-gate failures reproduce exactly as reported (directory depth/fanout from `docs/architect-analysis/auto`; root fanout 24>21; `ed25519_jwt_issuer.go` 539 lines).

### Leg-A split and §1.1 nuances — resolved, not deferred

- **Leg-A split** is not a workaround: I confirmed `buildApp` contains zero `validateScopeRegistry` references, so R1 (construction truth via `Registered()`) and R2 (boot-closed gate via `config.Load`, wired at config_load.go:220) are the only faithful decomposition — the two halves cannot live in one test.
- **§1.1.1** — `ClientConfig` indeed has no `GrantTypes` (verified in config_client.go; `seedClients` mapping confirms YAML clients always carry nil → unrestricted per server_token.go:111). R1 correctly omits it; R4 correctly sets it on the `sso.Client` seed.
- **§1.1.2** — R1's negative control correctly asserts registration absence only; the boot-closed half is owned by R2's negative subtest, which asserts the exact error string. No requirement is left dangling.
- **§1.1.3** — confirmed the compose file's explicit 8-row matrix bypasses `MatrixOrDefault`'s fallback, so R5's file-matrix ∪ `ProtocolScopes()` ∪ extras derivation is the *only* correct one; the design uses it.
- **§1.1.4** — `srClientAny` nil-allowlist path verified; the negative control needs no new client.
- **§1.1.5** — layer legality verified against the gate's rank check and precedent (`test/auditoutbox_governance_test.go:39` imports `auditgovernance`).

Nothing is deferred to G5: R3 is the concrete registration that makes the G5 flip safe for the provisioner; the other deploy trees are excluded by the direction itself, not by the design.

### Two nits (minor, do not affect the mapping)

1. **Command-path typo, duplicated from the requirements doc**: design §11 lists `go test . -run 'TestBuildApp_ScopeRegistry' -v`, which runs **zero** tests at root (measured: "no tests to run" — the tests live in `cmd/sso-server/`, package main). §8's acceptance table has it right (`go test ./cmd/sso-server/`). Fix the §11 command line when implementing.
2. **HEAD drift**: design cites `374f9890`; HEAD is `ff04f683` (one pi-batch stage bookkeeping commit). All cited lines were re-verified at the current HEAD and hold.

Acceptance grade: **7/7 machine-checked under root gates** — the requirements' §6 grade is accurate.
