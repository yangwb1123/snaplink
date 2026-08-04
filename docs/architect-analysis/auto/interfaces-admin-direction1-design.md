# Design: interfaces/admin — Direction 1 (capability language, tenant dimension, delegation grading)

> Companion to `docs/auto/interfaces-admin-direction1-spec.md`. Design only —
> no code was modified. All statements below are grounded in the executable
> code at the current commit; every file/line cited was re-verified.
>
> The three decisions form one coherent upgrade and share one authorization
> language: `admin:<resource>:<action>` capability codes (D1), a tenant
> dimension on the grant decision (D2), and delegation semantics built on the
> same matcher (D3). Each `##` decision covers API surface, storage model,
> failure modes, and what could break the design. Cross-cutting gates and
> contract updates are collected at the end.

**Fixed constraints discovered while verifying (bind every decision):**

- `interfaces/admin` has exactly 10 non-test files — the fan-out ceiling
  (`AGENTS.md` §2). **No new file may be added** to that package. New pure
  logic goes to `domains/permissions` (shared kernel, imports only downward)
  or `platform/lifecycle/admingovernance`; `middleware.go` (492 lines) and
  `governance.go` (483) are within 17 lines of the 500-line file budget, so
  the middleware additions require a line reshuffle across existing files.
- `interfaces/sso` is at its 60-file ceiling — the `TargetHoldsAdminScope`
  replacement must extend `accessors_feature_gates.go`, not add a file.
- `sso.AdminMiddleware = admin.Middleware` (`interfaces/sso/aliases.go:64`);
  the single wiring point for scope overrides is
  `wireAdminMW` (`cmd/sso-server/build_app.go:291-304`), which today registers
  exactly two `admin:read`-despite-POST overrides (wasmauthz check,
  config-cluster-diff). Both transports share the one construction object, so
  the capability table cannot drift between HTTP and gRPC — same invariant as
  today's `NewMiddleware`.
- `permissions.Matches` (`domains/permissions/matcher.go:19-36`): `admin:*`
  already grants every `admin:<res>:<action>` requirement via the `domain:*`
  prefix rule. Legacy `admin:read`/`admin:write` do **not** — they are exact
  codes. Therefore D1 needs an explicit legacy-fallback expansion at the gate;
  `admin:*` needs nothing.
- `MemoryProvider.Permissions` (`domains/permissions/memory.go:270-286`) is the
  union of permission codes of the user's roles for (userID, clientID). Roles
  key on `(clientID, code)` (`AddRole`, memory.go:60-71); assignments key on
  `userID → clientID → []roleCodes` (memory.go:134-145).
- `tenantRequestMismatch` (`interfaces/admin/tenants.go:273-287`) is fail-open
  and handler-side; `docs/error-codes.md:87` documents `tenant_mismatch` as the
  wire code for tenant mismatch — this row must be reconciled with D2's
  oracle-safe denial (see D2, "What could break").
- `ApproveAndApply` (`platform/lifecycle/admingovernance/approval.go:141-160`)
  has exactly one caller (`interfaces/admin/governance.go:157`); its signature
  may change. `ApprovalStore` is memory-backed (`approval_memory.go`) — no SQL
  migration surface.

---

## Decision 1 — Resource-qualified capability codes with handler-declared requirements

**Rule.** The admin authorization language becomes `admin:<resource>:<action>`
(resource ∈ the catalog: `users|devices|connections|providers|tenants|keys|
tokens|changes|break-glass|clients|crypto-keys|webhooks|audit|netpolicy|…`,
action ∈ `read|write|approve|…`). The gate's decision for a required
capability `c` succeeds iff the subject's permission set matches any code in
`RequirementFallbacks(c)`:

```text
RequirementFallbacks(admin:<res>:read)   = { admin:<res>:read,   admin:read }
RequirementFallbacks(admin:<res>:<other>) = { admin:<res>:<other>, admin:write }
RequirementFallbacks(legacy code)        = { legacy code }
```

`admin:*` needs no entry — the wildcard matcher already covers every
`admin:<res>:<action>` (and both legacy codes), so the seeded `sso-admin`
role stays byte-identical. Write never implies read and read never implies
write, preserving today's exact semantics for the legacy codes.

### API surface

**`domains/permissions` (new pure helpers — the language's single home):**

- `const ScopeAdmin = "admin:*"`, `ScopeAdminRead = "admin:read"`,
  `ScopeAdminWrite = "admin:write"` — the canonical code constants. `admin.Scope`
  / `admin.ScopeRead` / `admin.ScopeWrite` (`interfaces/admin/middleware.go:24-30`)
  become aliases (`const Scope = permissions.ScopeAdmin`), keeping every
  existing importer (`interfaces/sso/accessors_feature_gates.go` uses
  `admin.ScopeRead`) compiling unchanged.
- `func AdminRequirementFallbacks(required string) []string` — the expansion
  above; pure, unit-testable, shared by the HTTP gate, the gRPC gate, the
  approval matrix (D3), and the break-glass subset check (D3).
- `type CapabilityTable` — a small longest-prefix (HTTP) / exact (gRPC) table
  mapping transport key → required capability, generic over the existing
  `methodScopeForPath` longest-prefix semantics (governance.go:429-455). The
  `Middleware.methodScopes` map is replaced by this type; `SetMethodScope`
  keeps its signature and now accepts legacy or qualified values.

**`interfaces/admin.Middleware` — gate changes (all in existing files):**

- Resolution chain for the required capability, per request (first match wins):
  1. Capability table (existing `SetMethodScope` values; longest-prefix for
     HTTP path prefixes, exact full method for gRPC) — statically registered
     wins, mirroring AGENTS.md's "statically registered authenticator wins
     over a dynamic connection".
  2. Resource catalog: `ResourceProvider.ResolveResource` with
     `ResourceTypeHTTPAPI` `{method, path}` (path patterns support `:param`,
     `memory_resources.go:100-124`) or `ResourceTypeGRPCAPI`
     `{service, method}`, looked up in the empty (platform) tenant bucket
     first, then the request-resolved tenant bucket (D2). `Found=true` →
     `RequiredPermissions[0]` is the requirement (`RequireMode` defaults
     `any`; `RequireAll` is out of scope for v1 and must be rejected at
     registration, not silently treated as `any`). `Found=false` is not an
     error — fall through.
  3. Method default, unchanged: GET/HEAD/OPTIONS → `admin:read`; else
     `admin:write`. gRPC: `isReadMethod` prefix → `admin:read`, else
     `admin:write`.
- The decision point `authorizeGRPC` (middleware.go:215-245) and
  `authenticateHTTP` (middleware.go:349-385) compute
  `AdminRequirementFallbacks(required)` and succeed iff any code matches.
  Optional additive authorizer interface (nil-safe, pattern of
  `MenuLister`/`ResourceProvider`):

  ```go
  type CapabilityAuthorizer interface {
      HasAdminCapabilities(ctx context.Context, userID, clientID string, required []string) (bool, error)
  }
  ```

  `providerAuthorizer` implements it with **one** `Permissions` fetch + one
  `Matches` per fallback (today it fetches per `HasAdminScope` call). When the
  authorizer does not implement it, the gate loops the existing
  `HasAdminScope` per fallback — behavior identical, slightly more calls.
- Wiring-time validation (loud, not silent): when a capability-table value is
  `admin:<res>:<action>` and the provider implements `ResourceProvider`, the
  wiring site verifies a catalog entry exists for `<res>` with a matching
  type+attributes; unknown resource names fail at startup. When the catalog is
  absent (no `ResourceProvider`), qualified values are accepted as opaque
  strings (documented).

**Sensitive-subset declaration (the `deps.go` gap closer), registered in
`wireAdminMW` next to the existing two overrides:**

| Route / method | Capability |
|---|---|
| `POST /api/v1/admin/users/:id/password` (`HandleAdminResetUserPassword`) | `admin:users:write` |
| `/snaplink.admin.v1.KeyAdminService/RotateSigningKey` | `admin:keys:write` |
| `POST /api/v1/admin/tenants/:id/export` | `admin:tenants:write` (POST is write-gated today; `admin:tenants:read` would **widen** — forbidden) |
| `POST /api/v1/admin/devices/bulk-revoke` | `admin:devices:write` |
| `POST /api/v1/admin/break-glass/:id/impersonate` | `admin:break-glass:write` |
| `POST /api/v1/admin/changes/:id/approve` | `admin:changes:approve` (transport floor; D3 adds the workflow-level matrix) |

Every other route keeps the method default — 55 handlers unchanged. gRPC
parity: the same table entries keyed by full method; the interceptor shares
the `Middleware` object so the two transports cannot drift.

### Storage model

No new persistence in D1.

- Capability codes are `Permission.Code` strings in the existing provider
  (role → permissions). `Permission.Resource` (types.go:7) stays untouched —
  it round-trips but is not part of the match.
- The resource catalog is already a storage contract: `ResourceProvider`
  (resources.go:150-160) with a real `MemoryProvider` implementation
  (tuple-keyed index, `memory_resources.go:19-24`) and the sqlite backend.
  Admin route resources (`http_api` with `method`+`path` attributes) are
  seeded: a new bootstrap step beside `stepSeedAdminRole`
  (`platform/bootstrap/builtin/builtin.go:149-166`, versioned — the Runner
  runs each step version once) for the builtin admin client, and
  `provisionFirstAdmin` (`interfaces/sso/server_setup.go:198`) registers the
  same entries for `setupAdminClientID`.
- The capability table is in-memory construction config on `Middleware`
  (like `methodScopes` today) — never persisted, re-declared at wiring.

### Failure modes

| Condition | Behavior |
|---|---|
| Provider/authorizer error (store down) | Fail closed: 500 `internal_error` / gRPC `Internal` — identical to today (middleware.go:372-376). No allow on error. |
| `ResolveResource` returns error | Fail closed: 500. `Found=false` (documented non-error) falls through to the next resolution source. |
| `ResolveResource` not implemented | Skip step 2 — exact today's behavior. |
| Denial | Byte-identical 403 `{"error":"forbidden"}` (HTTP) / `PermissionDenied "admin scope required"` (gRPC) regardless of which fallback failed — oracle-safe by construction (one literal per transport, as today). |
| Unknown resource name in table | Wiring-time validation error when catalog present; startup fails loud. No catalog → opaque string, matches today. |
| `RequireAll` resource entry | Rejected at registration for v1 (not silently treated as `any`). |

### What could break the design

- **Legacy fallback omission is the #1 regression risk.** If a qualified
  requirement forgets its legacy fallback, every existing `admin:write`-only
  deployment silently loses that route. Mitigation: `AdminRequirementFallbacks`
  is the single expansion point, unit-tested exhaustively, and the E2E
  (`go test ./test/ -run TestE2E`) plus the acceptance matrix
  (subject with `admin:*` and subject with `admin:write` → both allowed) run
  against the seeded `sso-admin`.
- **The two existing `admin:read`-despite-POST overrides** (wasmauthz,
  config-cluster-diff, build_app.go:301-304) must stay legacy values and keep
  legacy semantics — no fallback expansion applies to them. Regression test in
  `middleware_test.go`.
- **Prefix-table over-narrowing:** a qualified table entry on a shared prefix
  (e.g. `/api/v1/admin/tenants/`) would gate sibling routes. Longest-prefix
  wins already mitigates ordering; the declared sensitive set uses full
  paths, and each entry gets a test.
- **Route growth without declaration** silently defaults to read/write —
  safe by construction (today's behavior), but the "handler-declared
  requirements" promise only covers the sensitive subset. Documented, not a
  gate.
- **Budgets:** `middleware.go`/`governance.go` have ≤17 lines slack; adding
  the resolution chain (~60 lines) requires moving ~70 lines out (bearer +
  actor helpers and `methodScopeForPath` are the natural candidates) across
  the existing 10 files. No new files in `interfaces/admin` (fan-out
  ceiling), and the maintainability gates
  (`TestMaintainability_|TestArchitecture_`) enforce it mechanically.
- **`admin:write` still does not imply `admin:read`** (and vice versa) —
  unchanged from today; a test pins it so nobody "helpfully" widens it.

---

## Decision 2 — Tenant-scoped admin authorization

**Rule.** Once a tenant is resolved for a request, a tenant-scoped grant may
operate only on that tenant; a global grant (`admin:*`, legacy codes, or
untagged roles) is unchanged. The provider's grant data is the authority; the
bearer claim stays a hint. Fail-open is preserved exactly where it exists
today: an unresolved tenant (single-tenant deployments) never denies.

### API surface

**`domains/permissions` — additive optional provider extension (nil-safe,
pattern of `ResourceProvider`):**

```go
type TenantPermissionsProvider interface {
    // PermissionsForTenant returns the subject's effective permissions for a
    // tenant-scoped query: untagged (global) grants PLUS grants tagged with
    // tenantID. Unknown user → ErrUserNotFound, as today.
    PermissionsForTenant(ctx context.Context, userID, clientID, tenantID string) ([]Permission, error)
    // Tenant-scoped role administration. Additive — base AddRole/AssignRoles
    // are untouched and continue to manage untagged (global) grants only.
    AddTenantRole(ctx context.Context, clientID, tenantID string, role Role) error
    AssignTenantRoles(ctx context.Context, userID, clientID, tenantID string, roles []string) error
    ListTenantRoles(ctx context.Context, clientID, tenantID string) ([]Role, error)
    ListTenantAssignments(ctx context.Context, clientID, tenantID string) ([]Assignment, error)
}
```

`MemoryProvider` implements it; the sqlite backend must too (it runs
`permissionstest.ConformanceSuite` — a new optional suite section, skipped for
providers that don't implement the interface; the base suite is untouched).

**`interfaces/admin` — middleware decision:**

- Optional authorizer extension:

  ```go
  type TenantAwareAuthorizer interface {
      HasAdminTenantScope(ctx context.Context, userID, clientID, tenantID string, required []string) (bool, error)
  }
  ```

  `providerAuthorizer` implements it via `PermissionsForTenant` + the D1
  fallback set. The gate's decision becomes: capability (D1) **and**,
  when a tenant is resolved and the authorizer is tenant-aware, tenant scope.
  Providers implementing neither optional interface keep today's behavior
  exactly (nil-safe).
- **Tenant resolution order** (pure helper `resolveRequestTenant`):
  1. Tenant path parameter: a small registered pattern table (default:
     `/api/v1/admin/tenants/:id` — segment 1 after the prefix, covering
     export/members/invitations/settings routes; `SetTenantPathPattern` for
     other shapes). Only routes registered here are parsed.
  2. Resolved host tenant: `tenant.FromHandlerContext` when the admin
     middleware runs inside the tenant middleware, else the deployment wires
     the same host→tenant lookup explicitly via
     `Middleware.SetTenantResolver(func(r *http.Request) (string, bool))` —
     no hidden ordering dependency, no new middleware dependency on
     `domains/tenant` internals.
  3. Bearer claim (`tenantHintFromClaims`, governance.go:474-484) — hint
     only; the provider is the authority.
- **Enforcement:** allowed iff `Matches(PermissionsForTenant(...))` for any
  fallback **or** the subject holds an untagged global grant for the same
  capability (untagged grants are inside `PermissionsForTenant` by its union
  semantics, so this is one check). Denial uses the **identical body as the
  D1 scope denial** (403 `{"error":"forbidden"}` / gRPC `PermissionDenied`) —
  see the oracle reconciliation below.
- Actor context gains an optional tenant stamp: `TenantFromContext(ctx)`
  (additive; `ActorFromContext` unchanged). The gRPC interceptor stamps the
  claim tenant; HTTP stamps the resolved tenant.
- `tenantRequestMismatch` (tenants.go:273-287) stays as the handler-side
  host-routing backstop; the middleware check is the primary control on
  `HandleAdminExportTenant` and sibling `:id` tenant routes. Both are
  deny-only, so they cannot widen each other.
- gRPC: tenant resolves from the bearer claim only (no path params at the
  interceptor). grpcadmin handlers that take `tenant_id` in the message
  consult `TenantFromContext` and deny on disagreement (fail closed) — new
  handler-side logic, scoped to the tenant CRUD service.

### Storage model

- `Role` gains `TenantID string` (`json:"tenant_id,omitempty"`). The
  MemoryProvider role key becomes `(clientID, tenantID, code)`; untagged
  roles key `(clientID, "", code)` — byte-identical to today for all
  existing callers (`AddRole` with an untagged role behaves exactly as now,
  `ErrRoleExists` included).
- Assignments: untagged stay in `assignmentsByUser[userID][clientID]`;
  tenant-scoped assignments live in a new map keyed
  `userID → tenantID → clientID → []roleCodes`. The base `Permissions`,
  `Roles`, `ListAllRoles`, `ListAssignments` methods ignore tenant-tagged
  data entirely — **no existing query changes meaning**.
- `PermissionsForTenant` unions untagged roles with `Role.TenantID ==
  tenantID` roles for the user's assignment under that tenant.
- Tenancy of the grant is data in the provider, never the claim: a forged
  claim tenant only matters if the provider holds a tenant-tagged grant for
  that tenant, and a global grant holder is never restricted by a stale
  claim (the union includes the global grant).
- Seeding: the builtin/`setup` admin roles stay untagged (global). No new
  bootstrap step required; tenant-scoped roles are created through the
  optional administration methods (or the existing
  `PermissionAdminService` once it learns the tenant dimension — out of
  scope for v1, note only).

### Failure modes

| Condition | Behavior |
|---|---|
| Provider implements no optional interface | Exactly today's decision (no tenant check). |
| `PermissionsForTenant` error (store down) | Fail closed: 500 — the provider is the authorization authority. |
| No tenant resolved (no path param, no host resolver, no claim) | No tenant check — fail-open preserved (single-tenant regression is an acceptance check). |
| Tenant resolver error (host lookup outage) | Log + audit, treat as unresolved, skip the tenant check — fail-open-with-audit, matching the tenant-suspension-outage precedent in AGENTS.md. |
| Path param vs claim disagree | Path wins (request intent); claim is the last-resort source. |
| Denial | Byte-identical to insufficient-scope denial (one literal per transport). No oracle between "wrong tenant" and "wrong capability". |
| Handler-side `tenantRequestMismatch` | Unchanged — `tenant_mismatch` routing backstop. |

### What could break the design

- **The `tenant_mismatch` wire code conflicts with the spec's oracle
  requirement.** AGENTS.md's oracle table and `docs/error-codes.md:87`
  document `403 tenant_mismatch`; the spec mandates the middleware-level
  denial be byte-identical to the insufficient-scope denial. These are
  contradictory as written. Resolution (stricter contract wins): the
  middleware-level denial emits the identical `forbidden` body — a caller
  cannot probe other tenants' existence or grant topology through it; the
  pre-existing host-routing backstop keeps `tenant_mismatch` (the caller
  already knows the host they arrived on). The oracle table row and
  error-codes doc must be updated in the same change to say exactly this.
  If a reviewer disagrees, the alternative is `tenant_mismatch` at the
  middleware too — which reintroduces the cross-tenant existence oracle the
  spec is explicitly closing.
- **Route-shape dependence:** tenant scoping only bites where a tenant
  resolves. A tenant-scoped `acme` grant holder can still operate on
  `/api/v1/admin/users` (no tenant param) if the deployment doesn't resolve
  host tenants there. This is the spec's documented fail-open
  ("tenant-scoped grant with no resolved tenant context still passes") — but
  it means tenant isolation on non-tenant routes depends on the host-resolver
  wiring. Document per-route behavior; do not promise isolation the design
  doesn't deliver.
- **Ordering of middleware vs `domains/tenant`:** if the admin middleware is
  outside the tenant middleware, `FromHandlerContext` is empty and step 2
  silently degrades to the claim. The explicit `SetTenantResolver` wiring
  removes the ambiguity; wireAdminMW must set it for multi-tenant
  deployments.
- **ConformanceSuite:** the optional tenant section must pass for
  MemoryProvider and sqlite; existing providers (third-party) that never
  implement `TenantPermissionsProvider` must still pass the base suite —
  the section is skipped, never required.
- **`TenantMembership`/`TenantRole` remain unconsumed** (tenants.go:33-44) —
  the admin gate's authority is the permissions provider, not the B2B roster.
  A future bridge (TenantRoleAdmin membership ⇢ tenant-scoped admin grant)
  is deliberately out of scope; without it, tenant admins must be granted
  through the provider. Flag in release notes.
- **Budgets:** resolution helpers live in `domains/permissions` /
  `domains/tenant`; the admin-package delta stays within the D1 reshuffle
  budget (no new files).

---

## Decision 3 — Role-aware delegation in governed flows: graded break-glass and a change-approval capability matrix

**Rule.** Two changes to the governed flows, both consuming the D1 matcher:

1. **Break-glass impersonation floor becomes a strict-subset check.** Minting
   for target T by actor A is refused unless (a) every capability in T's
   effective grant set is matched by A's effective grant set, and (b) the
   relation is not symmetric (T does not also cover A). Rule (b) keeps
   today's refusal for equal-level targets (a full `admin:*` admin still
   cannot impersonate another full admin) while enabling grading below the
   actor (L1 support holding `admin:users:*` may impersonate ordinary users,
   never a `admin:keys:write` holder).
2. **Approval gains an action-type → required-capability matrix.** `ApproveAndApply`
   refuses when the approver's effective grants do not satisfy the change's
   required capability. Legacy `admin:write` satisfies any requirement
   (compat). The proposer/approver-differ invariant and the action-type
   allow-list are unchanged.

### API surface

**Break-glass (Deps + sso implementation):**

- `interfaces/admin/deps.go:106-117` — `TargetHoldsAdminScope(ctx,
  targetUserID, clientID)` is replaced by:

  ```go
  // CanImpersonate reports whether actorUserID may mint an impersonation
  // bearer for targetUserID: the target's effective grant set must be a
  // strict subset of the actor's (the impersonator never gains capabilities
  // they do not hold, and equal-level impersonation stays refused). No
  // permissions.Provider wired ⇒ (true, nil) — the floor is a no-op,
  // preserving break-glass without RBAC. Provider error ⇒ (false, err) so
  // the caller fails CLOSED.
  CanImpersonate(ctx context.Context, actorUserID, targetUserID, clientID string) (bool, error)
  ```

  Sole caller: `refuseTargetPrivileged` (break_glass_impersonate.go:77-92) —
  update to pass the actor from `ActorFromContext`. All refusal causes
  (provider error, not-subset, equivalent-set) collapse to the same generic
  403 `break_glass_target_privileged` body with details only in the log —
  oracle-safe, unchanged from today's shape.
- Implementation in `interfaces/sso/accessors_feature_gates.go` (extend the
  existing file — the 60-file ceiling forbids a new one): fetch actor and
  target grants over `[clientID, ""]` (both clients, as today at
  accessors_feature_gates.go:291-316); subset via `permissions.Matches(actor,
  targetCode)` per target code; strictness via the reverse check. Empty
  target set (ordinary user) is always a strict subset of any non-empty
  actor set — minted, as today.

**Approvals (`platform/lifecycle/admingovernance` — no upward imports):**

- `Registry` gains a requirement matrix (additive; `Register` unchanged):

  ```go
  func (r *Registry) RegisterRequirement(actionType, capability string)
  func (r *Registry) Requirement(actionType string) (capability string, ok bool)
  ```

- `ChangeRequest` gains `RequiredCapability string`
  (`json:"required_capability,omitempty"`), resolved at **propose** time from
  `d.ChangeRegistry().Requirement(actionType)` (governance.go:144-173) and
  carried on the record — frozen at proposal, visible in List/Get and the
  audit chain. The carried value is authoritative at decision time (a
  registry change between propose and approve does not silently alter a
  pending record's bar).
- `ApproveAndApply` gains a checker and refuses **before** `store.Approve`
  (a refused approval never transitions the record):

  ```go
  type CapabilityChecker func(ctx context.Context, approverID, capability string) (bool, error)

  func ApproveAndApply(ctx context.Context, store ApprovalStore, reg *Registry,
      id, approverID string, check CapabilityChecker) (ChangeRequest, error)
  ```

  Semantics: `RequiredCapability == ""` (legacy pending records, or no
  requirement registered) → no check, today's behavior. Checker returns
  false → new sentinel `ErrChangeInsufficientScope`, mapped by
  `writeChangeDecisionError` (governance.go:169-187) to 403
  `change_insufficient_scope`. Checker error → 500 (fail closed, provider
  outage — the approval is refused, never applied blind).
- The handler supplies the closure from `Deps.Permissions()` + the actor's
  clientID: `capability satisfied iff Matches(perms, c) for any c in
  AdminRequirementFallbacks(capability)` — legacy `admin:write` satisfies
  any requirement; `admin:*` via the wildcard matcher. No provider wired
  (nil) → closure returns true — today's no-RBAC behavior, documented.
- `HandleAdminApproveChange` (governance.go:144-173) passes the closure;
  `HandleAdminProposeChange` stamps `RequiredCapability`. Self-approval and
  not-pending errors are unchanged. Capability-refused approvals emit an
  audit record (reuse `EventAdminChangeApproved` with `OutcomeFailure` +
  reason — no new event type, keeping `auditreport` classification stable).

### Storage model

- `ChangeRequest.RequiredCapability` is a new field on an in-memory
  `ApprovalStore` record (`approval_memory.go`) — no schema migration, no
  SQL surface. Old in-process records (none survive restart) read as `""` →
  no requirement → approvable, so a hot binary upgrade cannot strand pending
  changes. (If a durable `ApprovalStore` appears later, the column must be
  nullable and `""` must mean "no requirement", never "deny".)
- Break-glass needs no storage change: the subset check is a runtime
  permissions-provider decision.
- The requirement matrix lives in the `Registry` (in-memory wiring config,
  like `methodScopes`).

### Failure modes

| Condition | Behavior |
|---|---|
| No permissions.Provider wired | Floor no-op (mint proceeds) and approval checker passes — today's no-RBAC behavior, preserved exactly. |
| Provider error (store down) | Fail closed both flows: break-glass refuses with the generic 403; approval refuses with 500. Today's break-glass behavior; **new** for approvals (only when a requirement is registered — deployments without requirements see no change). |
| Target not a strict subset (incl. equal-level) | Generic 403 `break_glass_target_privileged`, details only in the log — no oracle about which capability failed. |
| Approver lacks the required capability | 403 `change_insufficient_scope`; record stays PENDING (no transition). |
| Self-approval / not-pending | Unchanged (`ErrChangeSelfApproval` 400 / `ErrChangeNotPending` 409). |
| Empty `RequiredCapability` | No check — legacy pending changes remain approvable. |
| Requirement registered after proposal | Carried value wins; registry changes apply only to new proposals. |

### What could break the design

- **Equal-level impersonation is the delicate case.** Pure subset semantics
  would let a full `admin:*` admin impersonate another full admin — a
  *widening* vs today's binary refusal. The strict-subset rule (b) preserves
  today's refusal for equivalent sets; the acceptance checks (L1 refused for
  `admin:keys:write` target, minted for ordinary users, full admin minted
  for non-privileged targets) all pass under it. Pin both directions in
  `break_glass_test.go`: equal-level refused, strictly-lower minted.
- **`ErrChangeInsufficientScope` is a new wire code** — `docs/error-codes.md`
  and (if the admin API documents the changes workflow) `docs/openapi.yaml`
  must be updated in the same change (AGENTS.md §5.6). The code is distinct
  by design: the change-approval workflow already surfaces cause-specific
  codes (self_approval, not_pending) to authenticated admins; collapsing
  capability failure would be inconsistent with that row's existing shape.
- **Layering:** `admingovernance` (platform/lifecycle) must never import
  `interfaces/admin` or `interfaces/sso` — the `CapabilityChecker` closure
  injected by the handler is what keeps the import flow legal. A design that
  put the matcher call inside `ApproveAndApply` directly would violate
  `architecture_layer_test.go`.
- **`TargetHoldsAdminScope` is a Deps method** — removing it is a breaking
  change to the `interfaces/admin.Deps` interface (internal, one caller, one
  implementor — safe) but any other implementor (tests) must be updated in
  the same change; the maintainability gates catch stragglers.
- **`interfaces/sso` file ceiling:** the subset implementation must extend
  `accessors_feature_gates.go`; a new file would trip the 60-file gate.
- **Seeded `sso-admin` flows stay byte-identical** (`admin:*` covers every
  requirement, is a top of the subset lattice, and passes every approval
  matrix row) — verified by `go test ./test/ -run TestE2E` and the
  `governance_test.go`/`break_glass_test.go` regressions.
- **Wire compatibility of `ChangeRequest`:** the new JSON field is additive
  (omitempty); strict decoders of propose responses must tolerate unknown
  fields — the propose *request* body does not accept the field (server-
  computed), so no client can inject a requirement.
- **Race with the D1 gate:** the approval capability check duplicates the
  transport gate's work. It must use the same `AdminRequirementFallbacks`
  so the two cannot disagree; a test asserts the matrix rows against the
  route table.

---

## Cross-cutting: contracts, gates, and sequencing

**Contracts updated in the same change (AGENTS.md §5.6):**

- `docs/error-codes.md` — new `change_insufficient_scope` (403); amend the
  `tenant_mismatch` row to state the middleware-level tenant denial is
  byte-identical to `forbidden` (host-routing backstop remains
  `tenant_mismatch`); AGENTS.md oracle-table row updated to match.
- `docs/openapi.yaml` — `ChangeRequest.required_capability` (additive);
  admin API 403 bodies unchanged (`forbidden`).
- `docs/architecture/DIRECTORY_MAP.md` — ownership notes for
  `domains/permissions` capability helpers and the tenant extension.
- `docs/config-reference.md` — only if a config knob surfaces for the
  action-type → capability matrix (default: none; registry is programmatic).

**Mandatory gates (run after every edit, then full):**

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

**Acceptance mapping:** D1 `middleware_test.go` matrices (HTTP + gRPC) →
spec §1; D2 unit tests (acme/globex, oracle byte-identity, single-tenant
fail-open, `permissionstest.ConformanceSuite`) → spec §2; D3 break-glass and
approval unit tests → spec §3. All three run against the seeded `sso-admin`
unchanged.

**Sequencing (each step lands green):** (1) `AdminRequirementFallbacks` +
constants move + unit tests; (2) capability table + gate resolution +
sensitive-subset declarations + tests; (3) tenant data model + optional
interfaces + middleware tenant check + tests; (4) break-glass subset floor;
(5) approval matrix; (6) doc/error-code updates; (7) E2E + `make ci`.

## Open questions for review

1. **Oracle row for tenant mismatch** — resolved above (byte-identical
   `forbidden` at the middleware; `tenant_mismatch` stays only for the
   host-routing backstop). Confirm the AGENTS.md oracle-table edit is
   acceptable, or state the alternative explicitly.
2. **Strict vs plain subset** for break-glass (equal-level refusal preserved
   vs. permitted). This design picks strict to keep today's top-tier
   refusal; the spec's wording ("never gains capabilities they do not hold")
   is satisfied by both.
3. **`admin:changes:approve` as a transport-level code** — the approve
   endpoint gets a qualified requirement in addition to the workflow-level
   matrix. Alternative: leave the endpoint at legacy `admin:write` and rely
   solely on the matrix. This design declares the code for symmetry with the
   rest of the sensitive subset; either is wire-compatible.
4. **Audit on capability-refused approvals** — this design reuses
   `EventAdminChangeApproved` with `OutcomeFailure`. A dedicated
   `EventAdminChangeApprovalDenied` would need `auditreport` classification
   (bounded cardinality) — only worth it if operators need to filter
   denials distinctly.
