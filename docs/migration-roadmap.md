# Root Directory Migration — Completion Report

> **Status: ✅ COMPLETED** (commit `2d01b06` + subsequent architecture refactors)
>
> All business logic has been extracted from root (`package sso`) into
> proper layer-aligned domain packages. The root directory is now reserved
> exclusively for server composition files under `interfaces/sso/`.

---

## Before vs. After

| Metric | Before Migration | After Migration |
|--------|-----------------|-----------------|
| Root non-test `.go` files | 65 | **0** (all under `interfaces/sso/`) |
| `python cli.py check-root` violations | 70 | **0** ✅ |
| Server struct location | Root (`package sso`) | `interfaces/sso/sso.go` |
| Business logic | Mixed with server wiring | Isolated in domain/protocol packages |

---

## Migration Map

Every old root file was moved to its architecturally-assigned package.
The old root stored thin `server_*` wrappers that delegate to domain pure
functions — the hexagonal pattern established by `oauth/` and `oidc/`.

### Phase 1: OAuth Handlers → `protocols/oauth/` + `internal/handler/tokengrant/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `auth_code_handler.go` | `protocols/oauth/oauthwire/auth_code_handler.go` | Wire handler |
| `ciba_handler.go` | `protocols/oauth/handle_ciba.go` | CIBA grant handler |
| `device_code_handler.go` | `protocols/oauth/oauthspi/device_code.go` + `device_codes.go` | Device grant SPI |
| `token_handler.go` | `internal/handler/tokengrant/token_authcode.go` et al. | Split into per-grant files |
| `token_exchange_handler.go` | `internal/handler/tokengrant/token_exchange.go` + `_idtoken.go` + `_stages.go` | Token exchange pipeline |
| `refresh_token_grant.go` | `internal/handler/tokengrant/token_refresh.go` + `protocols/oauth/oauthspi/refresh_token.go` | Refresh rotation + SPI |
| `client_store_cache.go` | `interfaces/sso/servercache/server_client_cache.go` | Caching adapter (thin wrapper) |
| `protected_resource_metadata.go` | `protocols/oauth/oauthvalidate/rar.go` | RAR validation |

### Phase 2: OIDC Handlers → `protocols/oidc/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `backchannel_logout.go` | `interfaces/sso/server_backchannel_logout.go` + `protocols/oidc/handlers.go` | Thin wrapper + core logic |
| `logout_handler.go` | `protocols/oidc/handle_end_session.go` | End-session endpoint |
| `userinfo_handler.go` | `protocols/oidc/handle_userinfo.go` + `oidcsupport/userinfo.go` | Userinfo endpoint + signing |
| `discovery_handler.go` | `protocols/oidc/handlers.go` | Discovery route |
| `discovery_cache.go` | `protocols/oidc/oidcsupport/discovery_doc_cache.go` | Cache layer |
| `discovery_config.go` | `protocols/oidc/oidcsupport/discovery_options.go` | Options derivation |
| `oidc_configuration.go` | `protocols/oidc/metadata.go` + `types.go` | Configuration types |

### Phase 3: Self-Service → `protocols/selfservice/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `handle_signup.go` | `protocols/selfservice/signup.go` | Signup flow |
| `handle_email_change.go` | `protocols/selfservice/email_change.go` | Email change flow |
| `handle_password_reset.go` | `protocols/selfservice/password_reset.go` | Password reset flow |
| `handle_data_export.go` | `protocols/selfservice/data_export.go` | GDPR data export |
| `handle_native_sso.go` | `interfaces/sso/server_native_sso.go` + `protocols/selfservice/aliases.go` | Native SSO bridge |

### Phase 4: Me Endpoints → `protocols/selfservice/selfserviceaccount/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `me_handler.go` | `protocols/selfservice/selfserviceaccount/profile.go` | Profile management |
| `me_mfa.go` | `protocols/selfservice/selfserviceaccount/mfa.go` | MFA device management |
| `me_security.go` | `protocols/selfservice/selfserviceaccount/security.go` | Security settings |
| `me_sessions.go` | `protocols/selfservice/sessions.go` | Session management |

### Phase 5: Login/Auth Flow → `interfaces/sso/server_login*.go`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `login_handler.go` | `interfaces/sso/server_login.go` | Core login orchestrator |
| `login_types.go` | `protocols/oidc/types.go` | Login types |
| `finish_login.go` | `interfaces/sso/server_finish_login.go` | Login completion |
| `resolve_login_request.go` | `interfaces/sso/server_login_resolve.go` | Request resolution |

### Phase 6: Security Logic → `shared/security/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `dpop.go` | `interfaces/sso/server_dpop.go` + `shared/security/securityverify/` | DPoP validation |
| `mtls.go` | `shared/security/tls_client_auth.go` | mTLS extraction |
| `jar_security.go` | `shared/security/securityverify/jar_fetch.go` | JAR fetch/verify |
| `pairwise_client_assertion.go` | `shared/security/pairwise.go` | Pairwise subjects |

### Phase 7: Cluster Coordination → `platform/cluster/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `coordinated_key_rotation.go` | `interfaces/sso/server_key_rotation.go` + `platform/cluster/bus.go` | Key rotation + cluster events |
| `cross_replica_revocation.go` | `interfaces/sso/server_invalidation.go` + `platform/cluster/bus.go` | Cross-replica revocation |
| `invalidation_bus.go` | `platform/cluster/bus.go` + memory/etcd impls | Invalidation bus |

### Phase 8: Tenant Logic → `domains/tenant/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `tenant_metrics.go` | `interfaces/sso/server_tenant.go` | Tenant metrics (thin wrapper) |
| `tenant_residency.go` | `interfaces/sso/server_tenant_residency.go` + `domains/tenant/tenant.go` | Data residency |
| `tenant_residency_grant_gate.go` | `domains/tenant/client_gate.go` | Grant gate |
| `tenant_revoke.go` | `interfaces/sso/server_tenant.go` | Tenant revocation |

### Phase 9: Audit & Authorization → `platform/audit/` + `domains/permissions/`

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `audit_helpers.go` | `platform/audit/handler_helpers.go` + `handlers.go` | Audit helpers |
| `authz_policy_bundle.go` | `domains/permissions/policy_bundle.go` | Policy bundle management |

### Phase 10: Other Business Logic

| Old Root File | New Location | Notes |
|---------------|-------------|-------|
| `federation_handler.go` | `domains/federation/handler.go` | Federation endpoint |
| `federation_options.go` | `domains/federation/entity_statement_config.go` | Federation options |
| `home_realm.go` | `interfaces/sso/server_login_client.go` | Home realm discovery |
| `logging.go` | `internal/handler/logging.go` + `platform/audit/` | Logging helpers |

---

## Retained Root Files (Server Composition Only)

These files remain in `interfaces/sso/` as thin wrappers, accessors, or
composition wiring. They contain NO business logic — only delegation to
domain packages, route registration, and dependency assembly.

| File | Purpose |
|------|---------|
| `sso.go` | Server struct + HTTP route registration |
| `sso_newserver.go` | Server constructor |
| `sso_newserver_wiring.go` | Dependency injection wiring |
| `sso_wiring.go` | Protocol wire-up |
| `sso_protocol.go` | Protocol-level routing |
| `sso_selfservice.go` | Self-service route registration |
| `sso_cluster.go` | Cluster bus wiring |
| `sso_federation_mesh.go` | Federation mesh wiring |
| `sso_ratelimit.go` | Rate-limit configuration |
| `sso_cachestate.go` | Cache state management |
| `handler.go` | Login orchestrator handler |
| `handlers.go` | Delegating discovery handlers |
| `mesh_authz.go` | Mesh authorization middleware |
| `signing_key_aggregation.go` | Key aggregation loop |
| `signing_key_aggregation_loop.go` | Key aggregation loop internals |
| `accessors.go` | Field accessors for `Deps` interface |
| `accessors_handlers.go` | Handler-level accessors |
| `aliases.go` | Type re-exports |
| `options*.go` | Server configuration options |
| `origin_validation.go` | Origin validation helpers |
| `quota.go` | Quota helpers |
| `server_*.go` | Thin HTTP handler wrappers delegating to domain packages |

---

## New Architecture Pattern

Every `server_*.go` file in `interfaces/sso/` follows the hexagonal adapter
pattern — they are thin, stateless wrappers that:

1. Parse the HTTP request
2. Call a pure domain function (e.g., `oauth.HandleAuthCode(s, ctx, ...)`)
3. Serialize the response

```go
// interfaces/sso/server_oauth.go — thin wrapper
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
    // Parse request
    var req oauthwire.TokenExchangeRequest
    if err := bindOAuthParams(r, &req); err != nil {
        oauthwire.WriteError(w, err)
        return
    }
    // Delegate to domain
    resp, err := tokengrant.HandleTokenExchange(s, r.Context(), &req)
    if err != nil {
        oauthwire.WriteError(w, err)
        return
    }
    // Serialize response
    oauthwire.WriteJSON(w, resp)
}
```

Domain packages (`protocols/oauth/`, `protocols/oidc/`, `protocols/selfservice/`,
`internal/handler/tokengrant/`, etc.) contain all business logic as exported
pure functions.

---

## Verification Gates

All committed gates continue to enforce the root directory policy:

| Gate | File | Current |
|------|------|---------|
| Root business code check | `checks/root_business_code.py` | ✅ PASS (0 violations) |
| File size ≤ 500 lines | `maintainability_budget_test.go` | ✅ Enforced |
| Cyclomatic complexity ≤ 15 | `maintainability_complexity_test.go` | ✅ Enforced |
| Import boundaries (down only) | `architecture_layer_test.go` | ✅ Enforced |
| Directory depth ≤ 3 | `maxdepth_test.go` | ✅ Enforced |
| Directory fanout ≤ 15 | `directory_fanout_test.go` | ✅ Enforced |

Run `make ci` or `python cli.py harness` to verify all gates locally.

---

## What This Enables

- **Clear dependency direction**: `interfaces/sso/` → domain packages → `shared/core/`
- **Independent testability**: Domain functions testable without HTTP setup
- **Package-level budgets**: Each domain package manages its own complexity budget
- **Protocol independence**: OAuth, OIDC, SCIM, etc. are fully decoupled
- **Simpler onboarding**: New developers only need to understand the layer map

---

## Historical Context

The migration was executed as a series of structured phases between commits
`2d01b06` (initial root-to-domain extraction) and subsequent architecture
refactors. The original `check-root` script detected 70 violations across
35 unique files; every violation was resolved.
