# Root Directory Migration Roadmap

This document outlines the migration plan to move business logic from root (`package sso`) to proper domain packages.

## Current State

- **70 violations** (35 unique files) detected by `python cli.py check-root`
- Root contains 65 non-test `.go` files
- Target: reduce to ~15 files (server composition only)

## Migration Strategy

For each file:
1. **Extract logic** to pure functions in target domain package
2. **Keep thin wrapper methods** in root that call domain functions
3. **Update Deps interface** if needed
4. **Verify** with `go build ./...` and `go test ./...`

This follows the hexagonal pattern already used in `oauth/` and `oidc/`:
```go
// In oauth/auth_code.go
func HandleAuthCode(deps Deps, ctx context.Context, ...) { ... }

// In root (wrapper)
func (s *Server) handleAuthCode(w http.ResponseWriter, r *http.Request) {
    oauth.HandleAuthCode(s, ctx, ...)
}
```

## Phase 1: OAuth Handlers (High Priority)

| File | Target | Lines | Complexity |
|------|--------|-------|------------|
| `auth_code_handler.go` | `oauth/auth_code.go` | 316 | Medium |
| `ciba_handler.go` | `oauth/ciba.go` | 85 | Low |
| `device_code_handler.go` | `oauth/device_code.go` | 484 | High |
| `token_handler.go` | `oauth/token.go` | 459 | High |
| `token_exchange_handler.go` | `oauth/token_exchange.go` | 448 | High |
| `refresh_token_grant.go` | `oauth/refresh_token.go` | 187 | Medium |

## Phase 2: OIDC Handlers (High Priority)

| File | Target | Lines | Complexity |
|------|--------|-------|------------|
| `backchannel_logout.go` | `oidc/backchannel_logout.go` | 384 | Medium |
| `logout_handler.go` | `oidc/logout.go` | 427 | Medium |
| `userinfo_handler.go` | `oidc/userinfo.go` | 293 | Medium |
| `discovery_handler.go` | `oidc/discovery.go` | - | Low |
| `discovery_cache.go` | `oidc/discovery_cache.go` | - | Low |
| `discovery_config.go` | `oidc/discovery_config.go` | - | Low |
| `oidc_configuration.go` | `oidc/configuration.go` | - | Low |

## Phase 3: Self-Service Handlers (Medium Priority)

Create new package `selfservice/` for user account operations:

| File | Target | Lines |
|------|--------|-------|
| `handle_signup.go` | `selfservice/signup.go` | - |
| `handle_email_change.go` | `selfservice/email_change.go` | - |
| `handle_password_reset.go` | `selfservice/password_reset.go` | - |
| `handle_data_export.go` | `selfservice/data_export.go` | - |
| `handle_native_sso.go` | `selfservice/native_sso.go` | - |

## Phase 4: Me Endpoints (Medium Priority)

Create new package `me/` for user self-service API:

| File | Target | Lines |
|------|--------|-------|
| `me_handler.go` | `me/handler.go` | - |
| `me_mfa.go` | `me/mfa.go` | - |
| `me_security.go` | `me/security.go` | - |
| `me_sessions.go` | `me/sessions.go` | - |

## Phase 5: Login/Auth Flow (Medium Priority)

Keep in root or create `login/` package:

| File | Target | Notes |
|------|--------|-------|
| `login_handler.go` | Keep in root | Core login orchestrator |
| `login_types.go` | Keep in root | Types used by handler.go |
| `finish_login.go` | Keep in root | Part of login flow |
| `resolve_login_request.go` | Keep in root | Part of login flow |
| `mfa_handler.go` | `mfa/handler.go` | MFA-specific logic |

## Phase 6: Security Logic (Low Priority)

Move to existing `security/` package:

| File | Target | Notes |
|------|--------|-------|
| `dpop.go` | `security/dpop.go` | DPoP validation |
| `mtls.go` | `security/mtls.go` | mTLS extraction |
| `jar_security.go` | `security/jar.go` | JAR security |
| `pairwise_client_assertion.go` | `security/pairwise.go` | Pairwise subjects |

## Phase 7: Cluster Coordination (Low Priority)

Move to existing `cluster/` package:

| File | Target | Notes |
|------|--------|-------|
| `coordinated_key_rotation.go` | `cluster/key_rotation.go` | Key rotation coordination |
| `cross_replica_revocation.go` | `cluster/revocation.go` | Cross-replica revocation |
| `invalidation_bus.go` | `cluster/invalidation.go` | Invalidation bus |

## Phase 8: Tenant Logic (Low Priority)

Move to existing `tenant/` package:

| File | Target | Notes |
|------|--------|-------|
| `tenant_metrics.go` | `tenant/metrics.go` | Tenant metrics |
| `tenant_residency.go` | `tenant/residency.go` | Data residency |
| `tenant_residency_grant_gate.go` | `tenant/residency_gate.go` | Grant gate |
| `tenant_revoke.go` | `tenant/revoke.go` | Tenant revocation |

## Phase 9: Audit & Authorization (Low Priority)

| File | Target | Notes |
|------|--------|-------|
| `audit_helpers.go` | `audit/helpers.go` | Audit helpers |
| `authz_policy_bundle.go` | `authz/policy_bundle.go` | Policy bundles |

## Phase 10: Other Business Logic (Low Priority)

| File | Target | Notes |
|------|--------|-------|
| `client_store_cache.go` | `oauth/client_cache.go` | Client caching |
| `federation_handler.go` | `federation/handler.go` | Federation |
| `federation_options.go` | `federation/options.go` | Federation options |
| `home_realm.go` | `login/home_realm.go` | Home realm discovery |
| `protected_resource_metadata.go` | `oauth/resource_metadata.go` | Resource metadata |
| `logging.go` | `spi/logging.go` | Logging helpers |

## Success Criteria

- [ ] `python cli.py check-root` passes (0 violations)
- [ ] Root contains only ~15 files (server composition)
- [ ] `go build ./...` succeeds
- [ ] `go test ./... -race` passes
- [ ] No circular imports introduced
- [ ] All existing tests still pass

## Notes

- **Do NOT move**: `sso.go`, `handler.go`, `handlers.go`, `server_extensions.go`, `mesh_authz.go`, `signing_key_aggregation.go`, `storage_health.go`, `accessors.go`, `aliases.go`, `options*.go`, `server_*.go`
- **Create new packages**: `selfservice/`, `me/`, `mfa/` (if not exists)
- **Reuse existing packages**: `oauth/`, `oidc/`, `security/`, `cluster/`, `tenant/`, `audit/`, `authz/`, `federation/`

## Migration Order

Start with **simplest files first** to establish the pattern:
1. `ciba_handler.go` (85 lines, low complexity)
2. `audit_helpers.go` (202 lines, helpers only)
3. `authz_policy_bundle.go` (88 lines, small)

Then move to larger files once the pattern is established.
