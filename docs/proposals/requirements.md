Specification written to `docs/auto/domains-tokenpolicy-spec.md`. All claims were verified against the code before writing (grep-confirmed: `memory.Store.Replace` has zero non-test callers; `ParseYAML` is the only `yaml.Unmarshal` in the package; `Policy` has no `Validate`).

# Requirements Specification — 方向一：治理生命周期闭环

Direction scope: `domains/tokenpolicy` + its wiring seams (`config.TokenPolicyConfig`, `interfaces/sso`). Three improvements form one lifecycle: rules enter validated → mutate via writable admin API → persist in a single source of truth. Constraints honored: fail-open evaluation, oracle-safe wire responses, `admin:read`/`admin:write` gating, contract docs updated in the same change.

## 改进一：规则校验闭环——严格 YAML 解析 + `Policy.Validate` 语义校验 + 发行方默认 TTL 可见性

**问题**: Three silent-failure gaps. (1) `ParseYAML` (`domains/tokenpolicy/yaml.go`) uses non-strict `yaml.Unmarshal` — a misspelled dimension silently disables a governance rule, drifting from `conditionalaccess.LoadPolicies` (`domains/conditionalaccess/yaml.go`) which uses `DisallowUnknownField` + per-policy `Validate`. (2) `Policy` has no `Validate()` — negative `max_refresh_depth`, `require_renew_after: 2` all load; a negative depth is inert forever in `denyReason` (`evaluate.go`). (3) `tokenpolicy.go`'s `MaxTTL` comment admits "the engine cannot see that default" — and `clampTTL` (`evaluate.go`) turns a `MaxTTL` above `core.DefaultTokenTTL` (`shared/core/consts_oauth.go:134`, 1h) into a concrete TTL for `RequestedTTL==0` clients, silently **widening** default-client lifetimes.

**提议行为**: `ParseYAML` switches to `yaml.UnmarshalWithOptions(..., yaml.DisallowUnknownField())`; new pure `Policy.Validate(defaultTTL time.Duration) error` rejects negative dimensions and `RequireRenewAfter` outside (0,1], and loudly warns when `MaxTTL > defaultTTL`. Called at both config wiring and admin PUT ("启动/写入双重校验"). `ClampingIssuer` wiring passes the issuer default so `EffectiveTTL = min(MaxTTL, defaultTTL)` when `RequestedTTL==0` — the widening becomes impossible.

**验收**: table tests for typo-field rejection, negative depth, renew>1, advisory on `max_ttl: 2h` + default 1h; existing valid fixtures byte-identical; default-client issuance ≤ issuer default; existing `clamp_issuer_test.go`/`rootcov_token_policy_enforce_test.go` stay green.

## 改进二：可写管理 API——`Store` SPI 写方法 + PUT/DELETE 端点

**问题**: Read-only governance surface. `Store` (`tokenpolicy.go`) exposes only `Policies()`; the sole write path `memory.Store.Replace` (`memory/store.go`) has zero callers. Admin is GET-only (`admin.go` `HandleAdminPolicies`; `docs/openapi.yaml:6836` has only `get`). Adjusting policy = edit config + restart/redeploy every replica. Sibling `threataction` already ships the full lifecycle: `ThreatPolicyStore` List/Get/Put/Delete (`policy.go:238`), `HandleAdminPutPolicy`/`HandleAdminDeletePolicy` (`admin.go`) with the `ErrInvalidRequest`-vs-`ErrInvalidPolicy` split (`shared/core/errors.go:313`) and `admin:write` gating (`sso.go:489-498`).

**提议行为**: Extend `Store` with `Get`/`Put`/`Delete` (name-keyed, mirroring `ThreatPolicyStore`) + `ErrPolicyNotFound`; `memory.Store` becomes map-keyed COW, `Replace` retained as startup seeding. New handlers: `PUT`/`DELETE`/`GET` `/api/v1/admin/token-policies/:name` — decode failure → `400 invalid_request`, `Validate` failure → `400 invalid_policy` + description, unknown name → 404, gated `admin:write`, mounted only under `WithTokenPolicy` (unwired stays 404). OpenAPI, error-codes, config-reference updated in the same change.

**验收**: memory store round-trip/overwrite/delete-unknown tests (`-race -count=10+`); server-level tests for PUT-then-GET, DELETE, 400 splits, 401 realm=admin, unmounted-404; OpenAPI check in `make ci`.

## 改进三：持久化后端——SQLite `Store` 作为多副本单一事实源

**问题**: Only implementation is a per-replica memory snapshot (`memory/store.go`) — admin-authored rules (once 改进二 lands) vanish on restart and diverge across replicas; no single point of truth. Sibling domains already solved this: `domains/threataction/sqlite/policy_store.go` ("the memory store loses every admin-authored policy on restart; this backend persists them…shared across replicas"), `domains/tokenexchange/sqlite/chain_store.go`. `TokenPolicyConfig` (`config/config_snapshot.go:298`) has only File/Policies.

**提议行为**: New root-module package `domains/tokenpolicy/sqlite` implementing the extended `Store`: single table `token_policies (name TEXT PRIMARY KEY, policy_json TEXT)`, `platform/migrate` versioned migrations (baseline v1), `modernc.org/sqlite` (already a root dependency). `TokenPolicyConfig` gains a mutually-exclusive `sqlite` DSN; DB seeds from config only when empty (first boot), then admin writes own it. Hot-path contract unchanged: `Policies()` failure fails open; store keeps a snapshot refreshed by admin writes and invalidation-bus `token-policy` events (`server_invalidation.go` pattern), bus failure fails open.

**验收**: sqlite CRUD round-trip, restart persistence (reopen DB), idempotent migrations, `-race` clean; `test/` integration with two server instances sharing one DB file — PUT via A visible on B after invalidation flush, survives B restart; `make ci` green (SQLite stays root-module, no nested-module trigger).

**Budget check**: `domains/tokenpolicy` has 6 non-test files (limit 10); 改进一 adds `validate.go`, 改进二 adds admin handlers, 改进三 adds a new `sqlite/` subdirectory at depth 3 — all within limits.
