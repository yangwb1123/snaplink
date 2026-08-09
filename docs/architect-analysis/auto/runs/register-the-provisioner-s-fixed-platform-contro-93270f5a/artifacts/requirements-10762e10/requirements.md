Verification complete. `GrantTypes` empty means unrestricted (backward compat), so the R4 seed with explicit `["client_credentials"]` is correct and matches the T-C invariant.

## Summary

Produced `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-2-scope-registry-requirements.md` (evidence-backed, following the accepted `cmd-snaplink-billing-scope-registry-requirements.md` sibling format).

**Evidence verification** — all 7 cited files confirmed at HEAD, plus 4 additional claims checked:

| Claim | Result |
|---|---|
| `platform_token.go:17-18` scope constants; scope fixed in code | Confirmed; also `defaultPlatformTokenConfig` (66-81) defaults empty Scope to `PlatformProvisioningScope`, `validPlatformScope` (90-92) accepts only the two strings, `platformTokenRequest` (151-166) sends one space-joined scope param via `client_credentials` |
| `scopecontract.Matrix()` = 9 rows, only `audit:event:write` among audit | Confirmed (consts.go:25-42, 57) |
| `RejectUnregistered` → 400 plain `invalid_scope`, nil-registry no-op | Confirmed (reject.go:31-44) |
| `validateScopeRegistry` membership only when enabled, exact error string | Confirmed (config_oauth2.go:30-66, membership 58-63; wired at config_load.go:220) |
| compose `config.yaml:62-67` — `enabled: true`, extra_scopes without audit scopes | Confirmed; **notably the compose tree already runs the registry enabled** (unlike helm), and `compose.yaml:227-248` deploys the provisioner against `https://sso-server:8080/token` — the gap is live |
| `scope_registry_wiring_test.go` + `settings.env` | Confirmed |
| Repo-wide grep | Tokens appear in no other Go code or config; only docs corroborating the fixed contract |

**Key design finding**: `buildApp` does not run `validateScopeRegistry` (config validation happens at load), so the boot-closed acceptance is split into a buildApp wiring test (`cmd/sso-server`) + a config-gate membership test (`config/scope_registry_test.go`).

**Preserved acceptance, made testable** (7/7 machine-checked Given/When/Then): Leg A — buildApp boots with the provisioner client + `reg.Registered` true for all three tokens, plus fail-closed membership gate; Leg B — `/token` `client_credentials` mint with the exact space-joined scope string returns 200 (byte-identical 400 `invalid_scope` negative control); Leg C (T-2) — `ops/deploy/compose/config.yaml` `extra_scopes` gains the three tokens, with a goccy/go-yaml parity test (already a root-module dep) pinning the deploy tree against the `auditgovernance` constant. Scope strictly bounded: no matrix change, no provisioner-code change, no compose client registration, no helm/k8s trees.
