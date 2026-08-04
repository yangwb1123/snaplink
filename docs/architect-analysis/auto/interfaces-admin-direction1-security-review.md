# Security Review: `interfaces/admin` direction-1 design (capability language, tenant dimension, delegation grading)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/interfaces-admin-direction1-design.md` (581 lines) plus its
companion spec (`docs/auto/interfaces-admin-direction1-spec.md`, 212 lines).
Scope: Decision 1 (resource-qualified capability codes), Decision 2
(tenant-scoped authorization), Decision 3 (break-glass subset floor +
change-approval capability matrix), and the cross-cutting contract/gate plan.

This is an advisory review of a **proposal**. No code was modified; no
implementation of the three decisions exists in the tree yet. Claims below are
labeled per the evidence standard.

## Verification run for this review

No Go tests ran (design-only review; the tree is unchanged). Every design
claim I rely on was re-verified against the current revision by reading the
cited files; the checks that ran were `git log/status`, file inventories
(`ls`/`wc`), and targeted `grep`/`sed` reads:

- `interfaces/admin` has exactly 10 non-test files (break_glass.go,
  break_glass_impersonate.go, connections.go, deps.go, governance.go,
  lifecycle.go, middleware.go, tenants.go, token_portfolio.go, users.go);
  `middleware.go` = 492 lines, `governance.go` = 483 lines. **Verified**
- `interfaces/sso` has exactly 60 non-test `.go` files. **Verified**
- Scope constants `Scope/ScopeRead/ScopeWrite` at
  `interfaces/admin/middleware.go:24-30`; `sso.AdminMiddleware = admin.Middleware`
  at `interfaces/sso/aliases.go:64`; the only scope overrides are the two
  `admin:read`-despite-POST entries in `wireAdminMW`
  (`cmd/sso-server/build_app.go:291-304`). **Verified**
- `permissions.Matches` (`domains/permissions/matcher.go:17-36`): `admin:*`
  expands via `domain:*` prefix rule to every `admin:<res>:<action>`;
  legacy `admin:read`/`admin:write` are exact codes only. The design's
  claim that the legacy-fallback expansion is required is correct. **Verified**
- `MemoryProvider.Permissions` (`domains/permissions/memory.go:270`) unions
  role permission codes; roles key `(clientID, code)` (`AddRole`,
  memory.go:60); assignments key `userID → clientID → []roleCodes`
  (memory.go:134). `Roles` falls back to the empty/global client
  (memory.go:225-238). **Verified**
- `tenantRequestMismatch` (`interfaces/admin/tenants.go:280`) is fail-open,
  handler-side, used only by `HandleAdminExportTenant` (tenants.go:237).
  AGENTS.md:161 and `docs/error-codes.md:87` both document
  `403 tenant_mismatch` — the design's contract-conflict claim is real. **Verified**
- `ApproveAndApply` (`platform/lifecycle/admingovernance/approval.go:145`)
  has exactly one caller (`interfaces/admin/governance.go:144`,
  `HandleAdminApproveChange`); `ChangeRequest` has no capability field;
  `ErrChangeSelfApproval`/`ErrChangeNotPending` enforced in the store
  contract. **Verified**
- `TargetHoldsAdminScope` (`interfaces/sso/accessors_feature_gates.go:291`)
  checks exactly `[]string{admin.ScopeRead, admin.ScopeWrite}` over
  `[clientID, ""]`; sole caller is `refuseTargetPrivileged`
  (`interfaces/admin/break_glass_impersonate.go:76`), which fires on BOTH
  grant creation (`HandleCreateBreakGlass`, break_glass.go:70) and bearer
  minting (break_glass_impersonate.go:37-63). **Verified**
- `MintImpersonationToken` (`interfaces/sso/accessors_feature_gates.go:239`)
  stamps `sub=target`, `ClientID=urn:snaplink:break-glass`, **`TenantID:""`
  ("tenant rules deliberately do not apply")**, `amr=break_glass`,
  `act=actor`, TTL clamped to the grant window; readonly grants are
  structurally refused at mint. **Verified**
- `ResolveResource` (`domains/permissions/memory_resources.go:100`) matches
  TenantID AND ClientID exactly; HTTP paths support `:param` segment
  wildcards (`matchPath`, memory_resources.go:112-124). `ResourceProvider`
  has zero runtime callers today. **Verified**
- `methodScopeForPath` (`interfaces/admin/governance.go:439-455`) is a
  **literal longest-prefix** match with a path-segment boundary check — it
  cannot match `:param` patterns. **Verified**
- Admin middleware wraps the whole mux (`cmd/sso-server/build_http.go:87`),
  i.e. OUTSIDE the per-route `domains/tenant` middleware, whose resolved
  tenant lives in `core.HandlerContext` (`domains/tenant/middleware.go:125`,
  `FromHandlerContext` takes a HandlerContext, not `context.Context`). The
  design's "spec's domains/tenant context isn't reliably populated at
  middleware time" claim is correct; explicit `SetTenantResolver` is
  required for host-based resolution. **Verified**
- Compliance routes: `GET /api/v1/compliance/users/:id/export` +
  `POST .../erase` (`cmd/sso-server/compliance_routes.go:68-71`) — export
  defaults to `admin:read`. `IsProtectedPath` covers them
  (middleware.go:414-441). **Verified**
- `stepSeedAdminRole` (`platform/bootstrap/builtin/builtin.go:150`) and
  `provisionFirstAdmin` (`interfaces/sso/server_setup.go:192`) seed only the
  `admin:*` role. **Verified**

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets touched by the design

| Asset | Trust level today | Change proposed |
|---|---|---|
| Admin HTTP surface `/api/v1/admin/*` (55 handlers) | binary `admin:read`/`admin:write`/`admin:*` bearer gate | D1 resolution chain (table → catalog → method default) + D2 tenant check |
| Admin gRPC services `snaplink.admin.v1.*`, `audit.v1.*`, `netpolicy.v1.*` + discovery Register/Deregister | same binary gate via shared `Middleware` | D1 gRPC table entries; D2 claim-tenant check |
| `POST /api/v1/admin/users/:id/password`, `/keys/rotate`, `/tenants/:id/export`, `/devices/bulk-revoke`, `/break-glass/:id/impersonate`, `/changes/:id/approve` | `admin:write` (method default) | qualified codes (`admin:users:write`, `admin:keys:write`, `admin:tenants:write`, `admin:devices:write`, `admin:break-glass:write`, `admin:changes:approve`) |
| Permissions provider role/assignment data | `(clientID, code)` keys | D2 adds `(clientID, tenantID, code)` dimension + `PermissionsForTenant` |
| Resource catalog (`ResourceProvider`) | zero runtime consumers | D1 makes it the step-2 naming authority; seeded per admin client |
| Break-glass grants + impersonation bearers | binary floor (`TargetHoldsAdminScope`) | D3 strict-subset floor (`CanImpersonate`) |
| Change-approval records (`ApprovalStore`) | self-approval + pending-only constraints | D3 `RequiredCapability` carried on the record + checker |
| Audit trail (SOC 2 evidence chain) | `admin_break_glass_*`, `admin_tenant_exported`, `admin_change_*` events | new `change_insufficient_scope` wire code; capability-refused approvals reuse `EventAdminChangeApproved` + `OutcomeFailure` |

### Trust boundaries

1. **Admin bearer gate (HTTP + gRPC).** The gate is the primary boundary for
   every asset above. Today it distinguishes exactly two outcomes per
   transport (`forbidden` / `PermissionDenied "admin scope required"`).
   D1/D2 preserve the one-literal-per-transport denial — this is the
   oracle invariant the whole direction hangs on, and the review found no
   design element that breaks it (provided Finding F4's error mapping is
   pinned).
2. **Permissions provider boundary.** The provider is the authorization
   authority. D2 correctly keeps the bearer claim as a hint and the provider
   as authority ("a forged claim tenant only matters if the provider holds a
   tenant-tagged grant for that tenant"). The review's High findings F1/F2
   live on the *interface between* the provider's data model and the
   middleware's decision, not on the claim.
3. **Break-glass mint boundary.** `MintImpersonationToken` is NON-BYPASS by
   construction (sub=target, no admin scope, `act=actor`, TTL-clamped,
   readonly structurally refused, revocation cascade). D3 changes only the
   floor that precedes minting — which is exactly where the delegation
   grading risk sits (F5).
4. **Change-approval boundary.** `ApproveAndApply` is store-authoritative
   (self-approval/pending-only enforced in the store). D3 adds a capability
   check BEFORE `store.Approve`, keeping the record untransitioned on
   refusal. The layering constraint (closure injected by the handler, no
   upward import) is the right shape and is enforced mechanically by
   `architecture_layer_test.go`.
5. **Composition root.** `wireAdminMW` is the single wiring point for both
   transports (verified), so table/catalog drift between HTTP and gRPC is
   structurally impossible as long as the table lives on the shared
   `Middleware` object. D1 keeps this invariant.

### Attacker capabilities

- **Unauthenticated attacker:** can reach every admin path only to receive
  401/403/429 — no new reachable surface. The tenant resolution order
  (path → host → claim) introduces no unauthenticated input into the
  decision: path params and claims are only consulted AFTER bearer
  validation.
- **Global `admin:*` or legacy `admin:read`/`admin:write` holder:** behavior
  byte-identical today and in the design (verified: wildcard matcher covers
  every qualified requirement; legacy fallbacks cover the legacy codes).
  The D1 sensitive subset cannot lock this class down — by design (compat).
- **New: qualified-code holder (`admin:users:write` etc.):** gains the
  least-privilege granularity D1 promises; the abuse surface is the
  resolution chain's silent-degradation paths (F3) and the tenant
  dimension's scope (F1, F2).
- **New: tenant-scoped grant holder (D2):** the headline risk. Depending on
  wiring and code space, this attacker may reach cross-tenant resources
  (F1), platform capabilities (F2), or be silently unrestricted when no
  tenant resolves (F8).
- **Approver admin (D3):** can approve any change whose requirement falls in
  their fallback set; legacy `admin:write` satisfies every requirement
  (compat, documented). A requirement-registration omission silently
  removes the bar (F6).
- **Break-glass actor (D3):** may mint for any target whose grant set is a
  strict subset of theirs — a *widening* vs today's blanket refusal for any
  admin-scope target (F5).

### Entry points (modified by the design)

1. Every `IsProtectedPath` HTTP route + every `isGatedGRPCMethod` RPC —
   the D1 resolution chain replaces `scopeForHTTP`/`scopeForGRPC`.
2. `POST /api/v1/admin/tenants/:id/export` and sibling `:id` tenant routes —
   D2 middleware check on top of the existing host-routing backstop.
3. `POST /api/v1/admin/users/:id/password`, `/devices/bulk-revoke`,
   `/connections/:id/*`, `/changes/:id/approve`, `/break-glass/:id/*` —
   D2's tenant check applies here via host/claim resolution ONLY (no path
   param); resource ownership is never validated (F1).
4. `POST /api/v1/admin/break-glass` and `.../:id/impersonate` —
   D3 `CanImpersonate` replaces the binary floor at both call sites.
5. `POST /api/v1/admin/changes` and `.../:id/approve` — D3 capability
   stamping + checker.

---

## 2. Findings

### F1 — HIGH: D2 validates grant-vs-request-tenant, never resource ownership; tenant-scoped grants reach cross-tenant resources on non-tenant routes

**Evidence (Verified):** The design's tenant check answers "does subject hold
capability C for resolved tenant T" (D2 enforcement: `HasAdminTenantScope`
against `PermissionsForTenant`). Resolution order is path param → host
resolver → claim. Only `/api/v1/admin/tenants/:id` routes (and siblings)
resolve via path param — where the path tenant IS the resource, so the check
is meaningful. For every other route — `POST /api/v1/admin/users/:id/password`
(`HandleAdminResetUserPassword`, `interfaces/admin/users.go:173`),
`/devices/bulk-revoke`, `/connections/:id/*`, `/changes/:id/approve`,
`/break-glass/:id/*` — the resolved tenant comes from host or claim, and
**no proposed code ever compares the resource's tenant to the resolved
tenant**. Today the ONLY resource-ownership guard in the entire admin package
is `tenantRequestMismatch` (tenants.go:280), applied only to the export
handler. The spec's own acceptance tests cover only the export route.

**Exploit preconditions:** (1) D2 implemented; (2) deployment wires
`SetTenantResolver` (host-based, multi-tenant) or tokens carry a tenant
claim; (3) an operator grants a tenant-scoped role containing
`admin:users:write` — the natural shape of a "tenant admin" role.

**Steps:** tenant-scoped acme holder → `POST /api/v1/admin/users/<globex-user-id>/password`
arriving on the acme host (or with an acme claim) → middleware: resolved
tenant = acme, grant = acme-tagged `admin:users:write` → **pass** →
handler resets the password of a user who belongs to another tenant. The
resolved tenant never constrains the `:id` in the path. Same shape for
`/devices/bulk-revoke` (revoke any tenant's devices), `/connections/:id/*`,
and `/changes/:id/approve` (approve a platform change — see F2).

**Impact:** cross-tenant account takeover (password reset), cross-tenant
device/connection manipulation, cross-tenant change approval — under a
feature whose headline promise is "a tenant-scoped grant may operate only on
that tenant". The design's own "What could break" section concedes isolation
on non-tenant routes depends on host-resolver wiring, but even WITH correct
wiring the check is vacuous for these routes because the resource ID is never
tied to the tenant.

**Remediation:** (a) add a per-resource ownership assertion on tenant-relevant
routes: when a tenant resolved AND the authorizer's grant view is
tenant-scoped, the handler (via a small shared helper, e.g.
`requireTenantResource(ctx, resourceTenantID)` consuming `TenantFromContext`)
must verify the target user/device/connection belongs to the resolved tenant
(membership via `TenantUserStore`/owner columns), fail-closed on lookup
error; (b) at minimum, ship the F2 code-space restriction so tenant-scoped
roles cannot carry platform codes; (c) document per-route isolation
guarantees in `docs/config-reference.md` (the design already flags this).

**Regression test:** acme-scoped `admin:users:write` holder + acme host +
`POST /api/v1/admin/users/<globex-user>/password` → 403 (byte-identical
`forbidden`); same holder + acme-tenant user → 200. Repeat for
`/devices/bulk-revoke` and `/changes/:id/approve`.

---

### F2 — HIGH: tenant-tagged grants may carry platform-wide capability codes; a tenant admin can rotate the platform signing key or approve platform changes

**Evidence (Verified/Proposed):** D2's storage model keys roles
`(clientID, tenantID, code)` with **no code-space restriction**: "Tenant-scoped
role administration" is described as additive CRUD, and the design nowhere
limits which `Permission.Code` values may be tenant-tagged. The D1 sensitive
subset includes `admin:keys:write` (`RotateSigningKey`), `admin:changes:approve`,
`admin:break-glass:write` — all platform-wide capabilities. The D2 enforcement
("capability AND tenant scope") treats a tenant-tagged `admin:keys:write` as
satisfying the keys route's requirement for the resolved tenant.

**Exploit preconditions:** an operator (or a delegated admin, once
`PermissionAdminService` learns the tenant dimension) tags a role with a
platform code; the subject calls the platform operation through a request
that resolves their tenant (gRPC: claim tenant; HTTP: host resolver).

**Steps:** acme tenant role tagged `admin:keys:write` → gRPC
`/snaplink.admin.v1.KeyAdminService/RotateSigningKey` with a token carrying
the acme claim → `HasAdminTenantScope(acme, [admin:keys:write, admin:write])`
→ pass → **the platform-wide signing key rotates**, invalidating every
tenant's tokens at once (per AGENTS.md: signing-key rotation is a
cluster-wide fail-closed event). Same shape for `admin:changes:approve`
(approve a tenant-unbound change record — `ApprovalStore` is global) and
`admin:break-glass:write` (mint impersonation bearers — the minted token is
deliberately tenant-unbound, see F5/F9).

**Impact:** tenant-scoped grants become a vehicle for platform-wide
cryptographic/identity operations — a privilege boundary that does not exist
today (today these codes don't exist) but that the design creates without a
guard.

**Remediation:** reject tenant-tagged roles containing platform codes at
`AddTenantRole`/`AssignTenantRoles` time. Define the tenant-eligible code
set explicitly (resource families whose data is tenant-owned:
`users|devices|connections|tenants`) and treat `keys|changes|break-glass|
tokens|clients|crypto-keys|webhooks|audit|netpolicy` as global-only. Enforce
in `permissionstest.ConformanceSuite`'s new tenant section for both
MemoryProvider and sqlite.

**Regression test:** `AddTenantRole(clientID, "acme", Role{Code:"k-rotate",
Permissions:["admin:keys:write"]})` → error; `admin:tenants:write` tagged →
accepted.

---

### F3 — HIGH (design-coherence): the CapabilityTable as specified (literal longest-prefix) cannot match the declared `:id` sensitive routes; the sensitive subset silently degrades

**Evidence (Verified):** The design declares the sensitive subset with full
paths containing `:param` (`POST /api/v1/admin/tenants/:id/export`,
`/api/v1/admin/users/:id/password`, `/api/v1/admin/devices/bulk-revoke`,
`/api/v1/admin/break-glass/:id/impersonate`, `/api/v1/admin/changes/:id/approve`)
but specifies the table as "generic over the existing methodScopeForPath
longest-prefix semantics (governance.go:439-455)". `methodScopeForPath` is a
literal string-prefix matcher (with a segment-boundary check): the literal
`/api/v1/admin/tenants/:id/export` is NOT a prefix of the real path
`/api/v1/admin/tenants/acme/export` (the `:id` segment differs), so a
faithful "longest-prefix" implementation makes every declared `:id` entry
dead. Only the catalog (`matchPath`, memory_resources.go:112-124) supports
`:param`, and the design's step-2 catalog lookup has a second un-pinned
variable: `ResolveResource` matches TenantID AND ClientID exactly, the seed
registers entries under the builtin/setup admin client IDs, but the design
never says what ClientID the middleware passes in the `ResourceLookup` — an
actor client other than the seeded clients (a third-party OAuth client with
admin grants) finds no entry and the step silently no-ops.

**Why it is a security issue, not just a bug:** the sensitive-subset table IS
the security feature of D1. A literal-prefix implementation makes the
declared routes fall through to the catalog (seeded only for the builtin
clients) or the method default (`admin:write`). The denial outcome is still
fail-closed (a qualified-code-only holder is denied — `admin:write` is not in
their fallback set), so there is no direct widening — but the control
operators believe is active ("handler-declared requirements") silently does
not fire, and the design's own acceptance matrix ("POST
/api/v1/admin/tenants/acme/export allowed for `admin:tenants:write` holder")
fails, which means the direction as written cannot land green.

**Remediation:** (a) specify `CapabilityTable` HTTP matching as
segment-aware pattern matching (reuse `matchPath` semantics; move it to
`domains/permissions` or share the helper — the design already plans a pure
helper home); (b) pin the catalog lookup's `ClientID` (recommend: the actor's
client with the platform/empty client consulted as a second lookup, matching
the `Roles` fallback convention at memory.go:225-238); (c) make the
wiring-time validation assert that every declared sensitive entry actually
matches a live catalog entry for the builtin clients.

**Regression test:** table entry `/api/v1/admin/tenants/:id/export` matches
real path `/api/v1/admin/tenants/acme/export` (and does NOT match
`/api/v1/admin/tenants/acme/members`); a subject with only
`admin:tenants:write` passes export, a subject with only `admin:users:write`
gets the byte-identical 403; repeat for the gRPC exact-method entries.

---

### F4 — MEDIUM: `ErrUserNotFound` and authorizer-error mapping in the new decision paths are not pinned; a 500-vs-403 split would create an enumeration oracle

**Evidence (Verified/Proposed):** today `providerAuthorizer.HasAdminScope`
maps `permissions.ErrUserNotFound` → `(false, nil)` → 403, and any other
provider error → 500 (`middleware.go:372-376`). The design's new
`HasAdminCapabilities` and `HasAdminTenantScope` paths say
"Unknown user → ErrUserNotFound, as today" (for `PermissionsForTenant`) and
"Provider error → fail closed: 500", but do not pin the middleware-level
mapping of `ErrUserNotFound` in the NEW authorizers, nor the fallback-loop
error semantics. If the loop `for fallback ∈ RequirementFallbacks(...)` treats
an error as "no match, try next", a provider outage ends at 403 instead of
today's 500 — and if `ErrUserNotFound` is treated as a generic error, an
attacker who can provoke a permission lookup for a target user can
distinguish "unknown to the provider" (500) from "known, not allowed" (403).

**Impact:** oracle on user existence/enumeration at the admin boundary;
provider-outage behavior drift vs today's documented fail-closed 500.

**Remediation:** pin both in the design and in tests: (a) every new authorizer
maps `ErrUserNotFound` → deny (403), identical to today; (b) the fallback
loop short-circuits on the first error → 500 (never falls through to the next
fallback); (c) `PermissionsForTenant` unknown-user behavior must be
byte-identical in shape to `Permissions` for the same subject.

**Regression test:** unknown subject + qualified requirement → 403 identical
to known-subject-denied; provider returning an error → 500 `internal_error`
(HTTP) / `Internal` (gRPC), on the FIRST fallback attempt.

---

### F5 — MEDIUM: D3's strict-subset floor lifts today's blanket "never impersonate an admin-scope holder" for strictly-lower targets; attribution semantics change and the subset basis is blind to tenant-tagged grants

**Evidence (Verified/Proposed):** today the floor refuses ANY target holding
`admin:read`, `admin:write`, or `admin:*`
(`accessors_feature_gates.go:291-316`). D3's rules (a)+(b) allow minting
whenever the target's set is matched by the actor's and the relation is not
symmetric — so a full `admin:*` actor may now impersonate a target holding
only `admin:write` (or `admin:users:write`), which today is **refused**. The
design frames rule (b) as "preserves today's equal-level refusal" — true only
for equal sets. The minted bearer is `sub=target` with `act=actor`
(`accessors_feature_gates.go:239-276`), so every action lands in the SOC 2
evidence chain under the TARGET's identity. Additionally, the subset basis is
`Permissions` (untagged) over `[clientID, ""]`; under D2 a target whose admin
rights are tenant-tagged is invisible to the check, while the minted token is
deliberately tenant-unbound (`TenantID:""`), so the tenant dimension never
re-engages downstream.

**Impact:** (1) behavior change requiring explicit sign-off — the graded
semantics are likely intended (the spec's "never gains capabilities they do
not hold" is satisfied), but the acceptance tests pin only equal-level-refused
and ordinary-user-minted, leaving the admin:write-target-under-admin:*
case unpinned; (2) repudiation/attribution: a full admin can now perform
actions attributed to a lower-tier admin's identity; (3) the D2×D3
interaction is unaddressed — a target with tenant-tagged admin grants can be
impersonated (their tagged rights do not ride the token, but the floor's
intent — "never let support act with an admin's boundary" — is silently
defeated for that target class).

**Remediation:** (a) explicitly decide and document the graded semantics,
including the admin:write-target case; (b) define the subset basis to include
tenant-tagged grants (evaluate via the union view `PermissionsForTenant` for
the target across the resolved/claim tenants, or refuse targets holding ANY
admin code — tagged or not); (c) pin the minted token's tenant binding as an
open question (F9).

**Regression test:** equal-level refused; strictly-lower minted;
`admin:*` actor + `admin:write` target — pinned with an explicit expected
outcome and an audit-note assertion; target with tenant-tagged
`admin:keys:write` refused.

---

### F6 — MEDIUM: the approval requirement matrix silently no-ops when a requirement is not registered for an action type that has an Applier

**Evidence (Verified/Proposed):** D3 stamps `RequiredCapability` at propose
time from `Registry.Requirement(actionType)`; empty ⇒ no check
("legacy pending records stay approvable"). The Registry is wiring config
(`Register`/`RegisterRequirement` are programmatic). Nothing ties
`RegisterRequirement` to `Register` (the Applier): an operator who registers
an Applier for `key-rotation` but forgets the requirement row gets a silent
no-op — every `admin:write` holder can approve, exactly the failure D1's
wiring-time validation ("loud, not silent") prevents for the capability
table. The same "forgot the fallback" failure class the design calls its #1
regression risk has a second, quieter instance here.

**Impact:** false sense of workflow control; a governed key-rotation change
approvable by any write-admin with no operator-visible signal.

**Remediation:** (a) at `Registry.Register` time (or wiring time), if an
Applier exists for an action type with no requirement, log loudly (and/or
reject new proposals of that type until a requirement is declared); (b) stamp
an audit meta key on `EventAdminChangeProposed` recording whether a
requirement was resolved; (c) state in `docs/config-reference.md` that an
empty requirement means "any `admin:write`" for NEW proposals.

**Regression test:** action type with Applier but no requirement → proposal
carries empty `RequiredCapability` + wiring warning; after
`RegisterRequirement("key-rotation", "admin:keys:write")`, a new proposal
carries it and an `admin:users:write`-only approver gets
403 `change_insufficient_scope` with the record still PENDING.

---

### F7 — MEDIUM: compliance export stays at `admin:read` and break-glass create/approve stay at plain `admin:write` — the sensitive subset is narrower than the sensitive surface

**Evidence (Verified):** `GET /api/v1/compliance/users/:id/export`
(`cmd/sso-server/compliance_routes.go:68`) is gated `admin:read` by the
method default — a read-only admin can pull the full cross-store PII bundle
for any subject (GDPR export: users, sessions, consent, MFA enrollments,
login history). `POST .../erase` is `admin:write`. Neither appears in the D1
sensitive table. Likewise `HandleCreateBreakGlass` (break_glass.go:55) —
which establishes impersonation grants — and `.../:id/approve` stay on the
`admin:write` method default while only the mint endpoint gets
`admin:break-glass:write`.

**Impact:** not a regression (all pre-existing), but D1 is the moment to
declare these: the design's own goal is least-privilege for the sensitive
subset, and a `admin:users:write`-only support role would be denied
password-reset yet still able to export every subject's PII.

**Remediation:** add `admin:compliance:export` (and `admin:compliance:erase`)
plus `admin:break-glass:write` on create/approve to the sensitive table, or
explicitly document why the method default is intentional. All additions are
compat-safe (legacy `admin:write`/`admin:read` fallbacks cover existing
holders).

**Regression test:** `admin:read`-only subject → compliance export 403;
legacy `admin:read` holder → unchanged (fallback).

---

### F8 — LOW: no audit signal when a tenant-scoped grant is exercised with no tenant resolved (fail-open with no observability)

**Evidence (Proposed):** the design's failure table gives "No tenant resolved
→ no tenant check — fail-open preserved", and fail-open-with-audit only for
resolver ERRORS. A deployment where `SetTenantResolver` was forgotten (or
tokens carry no claim) runs every tenant-scoped grant as effectively global —
the exact misconfiguration F1/F2 depend on — with nothing in the audit trail.

**Remediation:** when the authorizer holds tenant-tagged grants for the
subject but the request resolved no tenant, emit a bounded-cardinality audit
event (one meta key, fixed values) so operators can detect silent
degradation. Cheap, matches the "fail open with audit/logging" precedent in
AGENTS.md (tenant-suspension lookup outage).

**Regression test:** tenant-scoped grant + no tenant context → request passes
AND an audit event with the fixed meta key is recorded.

---

### F9 — LOW: `SetTenantResolver` implementations must not trust forwarded host headers; impersonation bearers stay tenant-unbound

**Evidence (Verified/Proposed):** the design adds
`Middleware.SetTenantResolver(func(r *http.Request) (string, bool))` — a
host→tenant lookup. AGENTS.md's proxy-trust invariants gate XFF/forwarded
host/proto behind `security.trusted_proxies`; the stock
`domains/tenant.DefaultHostExtractor` reads `r.Host`, and the resolver
contract must document the same constraint (an untrusted edge can forge
`Host:` today only if the server accepts it — the resolver must not add a
weaker source, e.g. `X-Forwarded-Host`, without the trusted-edge gate).
Separately, `MintImpersonationToken` stamps `TenantID:""` ("tenant rules
deliberately do not apply") — so under D2, impersonation bearers resolve no
tenant by construction and their downstream use is tenant-check-free; the
design should state this explicitly as a documented residual rather than
leaving it implicit.

**Remediation:** document in the `SetTenantResolver` contract comment;
add a resolver test with a spoofed forwarded host.

---

## 3. Abuse-case table

| Abuse case | STRIDE class | Reachable? | Path | Design status |
|---|---|---|---|---|
| Cross-tenant password reset: acme-scoped grant + acme host + globex user `:id` | Elevation/Isolation | **Yes (F1)** | D2 middleware passes (grant-vs-request-tenant only); `users.go:173` has no ownership check | Unaddressed; needs resource-ownership assertion |
| Tenant admin rotates platform signing key | Elevation | **Yes (F2)** | tenant-tagged `admin:keys:write` accepted by `AddTenantRole`; gRPC claim-tenant resolves; `RotateSigningKey` (`admin_keys.go:74`) is platform-wide | Unaddressed; needs code-space restriction |
| Tenant-bucket catalog entry downgrades a route's requirement below the method default | Elevation (widening) | **Possible (F3)** | `ResolveResource` honors the request-resolved tenant bucket; platform bucket checked first but is only seeded for builtin clients; who writes the tenant bucket is unspecified | Unaddressed; needs write-authority + requirement-strength validation |
| Admin impersonates a lower-tier admin; actions attributed to the target's identity | Spoofing/Repudiation | **Yes (F5)** | strict-subset floor mints for `admin:write` target under `admin:*` actor; `sub=target, act=actor` | Behavior change; needs explicit decision + pinned test |
| Target with tenant-tagged admin grants escapes the subset floor | Spoofing | **Yes (F5)** | subset basis is untagged `Permissions` only; minted token tenant-unbound | Unaddressed; needs union-view basis |
| Unknown-user probe distinguishes 500 from 403 | Information disclosure (enumeration) | **Conditional (F4)** | depends on `ErrUserNotFound` mapping in the new authorizers | Needs pinning |
| Provider outage turns 500 into 403 (oracle + drift) | Information disclosure | **Conditional (F4)** | fallback-loop error handling unspecified | Needs pinning |
| Replay of an approved change | Replay | **No** | `ApproveAndApply` transitions pending→approved atomically in the store; a second approve hits `ErrChangeNotPending` (409) | Control verified (store-authoritative) |
| Replay of an impersonation bearer after grant expiry | Replay | **No** | TTL clamped at mint; `AttachImpersonationToken` re-checks active under lock; revoke/expiry cascade destroys tokens | Control verified |
| Forged claim tenant to widen scope | Spoofing | **No** | provider is authority; forged claim only matters if a tagged grant exists for that tenant | Control verified (design) |
| Header forgery via `SetTenantResolver` | Tampering | **Conditional** | depends on resolver honoring forwarded headers without the trusted-edge gate | F9; needs contract pinning |
| Resource exhaustion via fallback-loop amplification | DoS | **No** | at most 2-3 `Matches` per request; admin-wide rate limit + write quota precede authz (`middleware.go` chain order verified) | No new surface |
| Catalog linear scan per admin request | DoS | **No (bounded)** | `ResolveResource` is O(n) (`memory_resources.go:100`); catalog is "rarely larger than a few hundred entries" | Acceptable; sqlite backend must keep the documented dispatch-table note |
| PII export by read-only admin | Data leakage | **Yes (pre-existing)** | `GET /api/v1/compliance/users/:id/export` at `admin:read` (`compliance_routes.go:68`) | F7; D1 omission |
| `admin:tenants:read` accidentally substituted for export | Data leakage | **No** | design explicitly forbids it (`read` would widen today's POST-gated contract) | Control verified (design) |
| Client injects `required_capability` on propose | Tampering | **No** | propose body has no such field (`proposeChangeRequest`, governance.go:47-52); server-computed | Control verified |
| Self-approval or non-pending approval | Elevation | **No** | store-authoritative `ErrChangeSelfApproval`/`ErrChangeNotPending` | Control verified |

## 4. Positive controls verified

- **Oracle-safe denials preserved.** One literal per transport for scope AND
  tenant denials (`forbidden` / `PermissionDenied "admin scope required"`),
  byte-identical regardless of which fallback failed. The design's
  reconciliation of the `tenant_mismatch` conflict (AGENTS.md:161 vs
  `docs/error-codes.md:87`) is the correct resolution: byte-identical denial
  at the middleware, `tenant_mismatch` kept only for the host-routing
  backstop where the caller already knows their host. The AGENTS.md oracle-row
  and error-codes amendments belong in the same change (the design says so).
- **`admin:*` covers every qualified requirement** via the matcher prefix
  rule (verified matcher.go:17-36) — the seeded `sso-admin` role is
  byte-identical, and the E2E acceptance is meaningful.
- **Legacy fallback omission correctly identified as the #1 regression
  risk** — verified that `admin:read`/`admin:write` do NOT match qualified
  codes today, so the single expansion point `AdminRequirementFallbacks`
  with exhaustive unit tests is the right shape; the two existing
  `admin:read`-despite-POST overrides keep legacy semantics and are exempt
  from expansion.
- **Transport parity.** One `Middleware` construction object shared by HTTP
  middleware and gRPC interceptors (`build_app.go:291-304`,
  `main_servers.go:198-200`) — the table cannot drift between transports.
- **Fail-closed on provider error** in the D1 gate (500 today,
  middleware.go:372-376 — preserved), in break-glass minting
  (`refuseTargetPrivileged` returns refused on error), and proposed for the
  approval checker (500, record untransitioned). No allow-on-error anywhere
  in the design.
- **Break-glass NON-BYPASS minting** (verified end-to-end): sub=target, no
  admin scope, `act=actor`, `amr=break_glass`, TTL clamped, readonly
  structurally refused at mint, attach re-checks active under the store
  lock, revocation cascade on grant end.
- **Approval store authority** (verified): self-approval and pending-only
  transitions enforced in the store, not just pre-checked; capability
  refusal happens BEFORE `store.Approve` so the record never transitions.
- **No client-injected requirement** (verified): `required_capability` is
  server-computed at propose; the JSON field is additive/omitempty, so
  strict decoders are safe.
- **Credential-endpoint hygiene untouched** (verified): no-store headers and
  bearer challenges on the mint endpoint precede all handlers.
- **Layering respected** (verified): `CapabilityChecker` closure injected by
  the handler keeps `admingovernance` free of upward imports; the
  maintainability gates enforce it mechanically.
- **No new persistence surface**: approvals stay in-memory; the new
  `ChangeRequest` field is additive; the D2 provider change is additive over
  the base interface with a skip-able ConformanceSuite section.

## 5. Residual risks and prioritized validation plan

### Residual risks (accepted or to be documented)

1. **Stock-binary tenant resolution is wiring-dependent.** The admin
   middleware runs outside `domains/tenant`'s per-route middleware
   (verified, build_http.go:87), so host-based D2 resolution requires
   `wireAdminMW` to call `SetTenantResolver` in multi-tenant deployments;
   otherwise resolution silently degrades to claims. F8's audit signal is
   the safety net.
2. **gRPC tenant resolution is claim-only** (no path params at the
   interceptor); the proposed handler-side message-`tenant_id` agreement
   check is new logic scoped to the tenant CRUD service — F1's ownership
   problem applies there too (a tenant CRUD handler must verify the
   message's `tenant_id` against `TenantFromContext`, which the design
   already plans, but the same must hold for user/device CRUD services).
3. **Impersonation bearers are tenant-unbound by construction** (verified
   `TenantID:""` at accessors_feature_gates.go:258) — under D2 their
   downstream use is tenant-check-free; F9 asks for this to be documented
   as a deliberate residual.
4. **`TenantMembership`/`TenantRole` bridge is out of scope** — tenant
   admins must be granted through the permissions provider; the roster is
   not the authority (design documented; flag in release notes).
5. **Cross-client admin targets** (a target whose admin grant lives under a
   different client than the actor's audience) remain invisible to the
   floor — pre-existing (`TargetHoldsAdminScope` checks `[clientID, ""]`
   only), inherited by D3; the subset basis should at least be widened to
   the target's own client(s).

### Prioritized validation plan

| Step | Gate / test | Blocks |
|---|---|---|
| 1 | `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` after every edit (fan-out/file budgets — no new `interfaces/admin` file) | all |
| 2 | D1: `AdminRequirementFallbacks` exhaustive unit tests; `CapabilityTable` pattern-match tests for every declared `:id` entry (F3); fallback-error→500 short-circuit + `ErrUserNotFound`→403 tests (F4); legacy-override regression (`middleware_test.go`) | F3, F4 |
| 3 | D2: acme/globex matrix incl. the F1 negative (globex user via acme host → 403); platform-code rejection at `AddTenantRole` (F2); oracle byte-identity test; single-tenant fail-open regression; `permissionstest.ConformanceSuite` tenant section (memory + sqlite) | F1, F2, F8 |
| 4 | D3: `break_glass_test.go` equal-level refused / strictly-lower minted / admin:write-target pinned (F5); tenant-tagged-target refused; `governance_test.go` matrix incl. `ErrChangeInsufficientScope` mapping + record-stays-pending; missing-requirement wiring warning (F6) | F5, F6 |
| 5 | Contracts in the same change: `docs/error-codes.md` (`change_insufficient_scope` + amended `tenant_mismatch` row), AGENTS.md oracle row, `docs/openapi.yaml` (`required_capability`), DIRECTORY_MAP ownership notes | contract drift |
| 6 | `go test ./test/ -run TestE2E -v`; `go test ./... -race`; `make ci` | handoff |

### Open questions this review adds

1. **F1's resource-ownership assertion**: is per-resource tenant validation
   in scope for v1, or is the code-space restriction (F2) + documented
   per-route isolation the accepted v1 posture? The design's "do not promise
   isolation the design doesn't deliver" is honest but the delivery gap is
   larger than the doc states.
2. **F5's graded floor**: the admin:write-target-under-admin:* case must be
   either pinned as intended (with the audit-attribution note) or excluded.
3. **Tenant-bucket catalog write authority** (F3): who may register
   tenant-scoped `http_api` resources, and what validation prevents a
   requirement downgrade below the method default?
4. **F2's code-space restriction**: confirm the tenant-eligible resource
   family list (`users|devices|connections|tenants`) before the
   ConformanceSuite tenant section is written.
