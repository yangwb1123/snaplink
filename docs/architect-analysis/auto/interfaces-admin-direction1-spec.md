# Requirements Spec: interfaces/admin — Direction 1

> Source: `docs/auto/interfaces-admin-analysis.md`, expansion direction 1
> "管理授权模型升级：从二元 scope 到可组合的委派 RBAC（角色 × 资源 × 租户）".
> This spec covers only the three improvements below; all evidence was
> re-verified against executable code on this commit. The three form one
> coherent upgrade: a capability language (1), a tenant dimension (2), and
> delegation semantics in the two governed flows (3).

## 1. Resource-qualified capability codes with handler-declared requirements

**Name**: `admin:<resource>:<action>` capability codes, declared per handler and
enforced by the middleware.

**Problem**: The entire admin authorization language is two booleans. The
middleware can only ask "does this subject hold `admin:read` / `admin:write`",
so any holder of `admin:write` may execute everything from signing-key rotation
to tenant export. The wildcard matcher already speaks resource-level codes, and
a full resource catalog exists, but nothing consumes either.

**Evidence**:
- `interfaces/admin/middleware.go:24-30` — the constants `Scope = "admin:*"`,
  `ScopeRead = "admin:read"`, `ScopeWrite = "admin:write"` are the whole
  vocabulary; `scopeForHTTP` (`middleware.go:139-148`) and `scopeForGRPC`
  (`middleware.go:128-137`) can only ever produce `admin:read` or
  `admin:write`. `Authorizer.HasAdminScope(ctx, userID, clientID, requiredScope)`
  (`middleware.go:34-39`) has no resource parameter.
- `interfaces/admin/deps.go:22-24` — "Every admin operation is gated UPSTREAM
  by AdminMiddleware… handlers run only after that gate, so they assume admin
  authorization". Verified: 55 `func HandleAdminX` handlers (e.g.
  `HandleAdminResetUserPassword` `interfaces/admin/users.go:173`,
  `HandleAdminExportTenant` `interfaces/admin/tenants.go:237`) contain zero
  authorization layering; the gRPC side is identical
  (`KeyAdminService.RotateSigningKey` `interfaces/grpcserver/grpcadmin/admin_keys.go:74`).
- `domains/permissions/matcher.go:19-36` — `Matches` already expands
  `domain:*` → any `domain:action`; the language can express
  `admin:clients:write` today, but no caller in the repo ever requests such a
  code.
- `platform/bootstrap/builtin/builtin.go:149-166` (`stepSeedAdminRole`) and
  `interfaces/sso/server_setup.go:198` (`provisionFirstAdmin`) seed exactly one
  role (`sso-admin`, "Full admin:* scope across the control plane").
- `domains/permissions/resources.go` — `ResourceProvider.ResolveResource`
  (`resources.go:150-160`), `Resource` with per-type attributes
  (`resources.go:63-110`), and `MemoryProvider.ResolveResource`
  (`domains/permissions/memory_resources.go:100`) exist but have **zero runtime
  callers** (grep: only the implementation itself). `Permission.Resource`
  (`domains/permissions/types.go:7`) is round-tripped
  (`interfaces/ssoclient/remote/authz.go:47`) but never matched.

**Proposed behavior**:
- Add the code convention `admin:<resource>:<action>` (resource ∈
  `users|devices|connections|tenants|keys|tokens|changes|break-glass|…`,
  action ∈ `read|write|approve|…`). Legacy `admin:*` / `admin:read` /
  `admin:write` remain valid and match every resource-qualified requirement
  (backward compatibility, never a permission reduction for seeded admins).
- Extend the gate decision with a resource dimension: the middleware resolves
  the requested capability from (HTTP method, path) or (gRPC method) via a
  capability table — an extension of the existing `methodScopes` /
  `SetMethodScope` mechanism — and succeeds iff the subject's permission set
  matches `admin:<resource>:<action>` OR a legacy code. Both transports share
  the one construction object, so the tables cannot drift (same invariant as
  today's `NewMiddleware`).
- Handlers declare their required capability (per-handler, defaulting to
  read/write by method as today), closing the `deps.go` "handlers assume
  authorization" gap for the sensitive subset (password reset, key rotation,
  tenant export, device revocation, approvals).
- Wire the resource catalog as the naming authority: admin routes register
  `http_api` `Resource` entries (method+path attributes) and the middleware
  resolves them via `ResolveResource` — giving `ResourceProvider` its first
  consumer and a single source of truth for resource names.
- Keep the seeded `sso-admin` role byte-identical; the upgrade is additive.

**Acceptance check**:
- `middleware_test.go` matrix: subject holding only `admin:users:write` →
  `POST /api/v1/admin/users/:id/password` allowed, `POST /api/v1/admin/keys/rotate`
  denied with the identical 403 body a scope-less subject receives (oracle-safe);
  subject holding `admin:*` and subject holding legacy `admin:write` → both
  allowed (compat).
- Same matrix on the gRPC interceptor for `KeyAdminService.RotateSigningKey`.
- `go test ./test/ -run TestE2E` passes unchanged with the seeded `sso-admin`.
- Mandatory gates: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`; `make ci` before
  handoff.

## 2. Tenant-scoped admin authorization

**Name**: Tenant as an authorization dimension, not a quota-key hint.

**Problem**: The tenant dimension is a "best-effort hint" and a fail-open host
check. Nothing in the authorization path answers "may this subject operate on
tenant T". A tenant admin — or a tenant-scoped delegation — cannot be expressed;
tenant isolation on the admin surface depends on routing, not authorization.

**Evidence**:
- `interfaces/admin/governance.go:474-484` — `tenantHintFromClaims` reads
  `claims.Extra[core.KeyTenantID]`; its only consumer is
  `checkWriteQuota`'s quota key (`interfaces/admin/middleware.go:345`). The
  tenant ID influences billing keys, never the allow/deny decision.
- `interfaces/admin/tenants.go:273-287` — `tenantRequestMismatch` is
  host-route-based and explicitly fail-open ("only rejects when BOTH sides are
  known"); `HandleAdminExportTenant` (`tenants.go:237-242`) relies on it, so a
  tenant path parameter with no host context passes.
- `interfaces/admin/middleware.go:34-39` (`HasAdminScope` signature) and
  `withActor` / `ActorFromContext` (`middleware.go:459-478`) — the actor context
  carries only (userID, clientID); there is no tenant in the authorization
  decision anywhere.
- `domains/permissions/resources.go:63-68` — `Resource.TenantID` exists and
  `ResourceLookup` is already tenant-aware ("Empty TenantID means match
  resources whose TenantID is also empty"): the data model supports
  tenant-scoped resources; the admin gate does not use it.
- `interfaces/admin/tenants.go:33-44` — `membershipToJSON` / `validTenantRole`
  over `core.TenantMembership`/`core.TenantRole`: tenant membership and roles
  exist for the user-facing surface and are never consulted by the admin gate.

**Proposed behavior**:
- Extend the authorization decision with tenant: a tenant-aware authorizer
  (additive optional interface over `Authorizer`, nil-safe — providers that do
  not implement it keep today's behavior exactly).
- The middleware resolves the request tenant from, in order: the admin route's
  tenant path parameter, the resolved host tenant (`domains/tenant` context),
  then the bearer claim — and enforces fail-closed once a tenant is resolved: a
  tenant-scoped grant may only operate on its own tenant; a global grant
  (`admin:*` / legacy codes) is unchanged.
- Tenant scoping is expressed as data in the permissions provider (e.g.
  tenant attribute on the role/assignment), not trusted from the claim alone —
  the claim remains a hint (as today), the provider is the authority.
- `tenantRequestMismatch` stays as a routing backstop; the middleware-level
  check becomes the primary control on `HandleAdminExportTenant` and sibling
  `:id` tenant routes.
- Fail-open is preserved only where it exists today: unresolved tenant
  (single-tenant deployments) never denies.

**Acceptance check**:
- Unit test: tenant-scoped grant for `acme` → `POST
  /api/v1/admin/tenants/acme/export` allowed, `/api/v1/admin/tenants/globex/export`
  → 403 `tenant_mismatch`; global `admin:*` passes both.
- Oracle-safety: tenant-mismatch denial body is byte-identical to the
  insufficient-scope denial body (per AGENTS.md oracle table).
- Single-tenant regression: tenant-scoped grant with no resolved tenant context
  still passes (fail-open preserved).
- `permissionstest.ConformanceSuite` passes (provider contract change is
  additive only).

## 3. Role-aware delegation in governed flows: graded break-glass and a change-approval role matrix

**Name**: Delegation grading — break-glass impersonation floor becomes
capability-subset, and two-person approval checks the approver's grants against
the change's required capability.

**Problem**: Both governed delegation flows use the same binary floor. Break-glass
cannot express "L1 support may impersonate ordinary users but never a security
admin", and the two-person approval flow lets any second `admin:write` holder
approve any change type.

**Evidence**:
- `interfaces/admin/break_glass_impersonate.go:72-93` — break-glass
  impersonation minting is gated by `d.TargetHoldsAdminScope`; the
  implementation `interfaces/sso/accessors_feature_gates.go:291-316` matches
  exactly `[]string{admin.ScopeRead, admin.ScopeWrite}` against the target's
  permissions. Two consequences: a target holding a resource-qualified code
  (per improvement 1) escapes the floor entirely, and a target holding only
  `admin:users:write` is treated identically to a full `admin:*` admin — no
  grading.
- `interfaces/admin/deps.go:106-117` — the contract comment admits the binary
  ceiling: "reports whether targetUserID holds an admin scope… REFUSE minting…
  impersonating an admin" — it cannot express "impersonate normal users, never
  security admins".
- `interfaces/admin/governance.go:144-173` — `HandleAdminApproveChange` calls
  `admingovernance.ApproveAndApply(rctx, store, d.ChangeRegistry(), id, approver)`
  with the actor pulled from `ActorFromContext`; `platform/lifecycle/
  admingovernance/approval.go:64` — `ErrChangeSelfApproval` ("approver must
  differ from proposer") is the ONLY approval constraint; `ChangeRequest`
  (`approval.go:43-57`) has no role/capability field; `RequiredActionTypes`
  (`approval.go:167-186`) constrains only which `action_type` may be proposed,
  not who may approve it.
- `proto/admin/v1/permissions.proto:17-58` — `PermissionAdminService`
  (ListRoles/AssignRoles/SetMenus) is implemented
  (`interfaces/grpcserver/grpcadmin/admin_permissions.go:26-79`): the role
  model is administrable but un-consumed by either flow.

**Proposed behavior**:
- Replace the binary floor with a subset check: break-glass minting for a
  target is refused when the target's effective permission set is not a subset
  of the acting admin's (the impersonator may never gain capabilities they do
  not hold). This yields graded delegation ("L1 support holding `admin:users:*`
  may impersonate ordinary users, never someone with `admin:keys:write`") and
  closes the blind spot where a resource-qualified target grant escapes the
  current two-code check. Keep the existing fail-open for deployments without a
  permissions provider, and fail-closed on provider error (both today's
  documented behaviors).
- Change approval gains a capability matrix: the action-type registry maps
  `action_type` → required capability, `ChangeRequest` carries it (or resolves
  it at decision time), and `ApproveAndApply` refuses when the approver's
  effective grants do not satisfy it (legacy `admin:write` satisfies any
  requirement — compat). The proposer/approver-differ invariant and the
  action-type allow-list are unchanged.
- Both flows consume the same matcher as improvement 1 — one authorization
  language across the whole admin surface, including `TargetHoldsAdminScope`'s
  replacement in `interfaces/sso/accessors_feature_gates.go`.

**Acceptance check**:
- Break-glass unit test: admin holding `admin:users:read` attempts impersonation
  of a user holding `admin:keys:write` → refused (fail-closed, generic 403, no
  oracle); same admin impersonating an ordinary (non-admin) user → minted;
  full `admin:*` admin → minted for any non-privileged target as today.
- Approval unit test: admin A proposes a key-rotation change; admin B holding
  only `admin:users:write` approves → rejected with the insufficient-scope
  error; admin C holding `admin:keys:write` (or legacy `admin:write`) approves
  → applied. Self-approval still rejected (`ErrChangeSelfApproval`).
- Regression: `interfaces/admin/break_glass_test.go` and
  `interfaces/admin/governance_test.go` pass with the graded matcher as the
  only behavioral change; seeded `sso-admin` flows byte-identical.
