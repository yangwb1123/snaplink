Design doc written to `docs/auto/interfaces-admin-direction1-design.md`. All evidence re-verified against code before writing; no code modified.

## What the design contains

**## Decision 1 — Resource-qualified capability codes.** A single expansion point, `AdminRequirementFallbacks`, in `domains/permissions` (canonical code constants there; `admin.Scope*` become aliases). Three-step resolution chain: capability table (existing `SetMethodScope`, longest-prefix/exact) → `ResolveResource` catalog lookup (platform tenant bucket first) → method default. One optional `CapabilityAuthorizer` interface fetches permissions once. Sensitive-subset table (password reset, key rotation, tenant export, device revoke, break-glass, approvals) declared in `wireAdminMW` beside the two existing overrides. Notably: `admin:tenants:export` maps to `admin:tenants:write`, not `read` — `read` would widen today's POST-gated contract.

**## Decision 2 — Tenant-scoped authorization.** Additive optional `TenantPermissionsProvider` (tenant-tagged roles keyed `(clientID, tenantID, code)`; base methods ignore tagged data, so no existing query changes meaning) + `TenantAwareAuthorizer`. Resolution order: path param (registered patterns) → host tenant (explicit `SetTenantResolver` wiring — the spec's "domains/tenant context" isn't reliably populated at middleware time) → claim. Fail-closed on provider error, fail-open on unresolved tenant.

**## Decision 3 — Delegation grading.** Strict-subset break-glass floor (preserves today's equal-level refusal — pure subset would *widen* it) via `CanImpersonate` replacing `TargetHoldsAdminScope`; approval matrix via `Registry.RegisterRequirement` + carried `ChangeRequest.RequiredCapability` (empty = no requirement, so legacy pending records stay approvable) + a `CapabilityChecker` closure injected by the handler — keeping `admingovernance` free of upward imports.

## Hard constraints discovered that shape the design

- `interfaces/admin` is at its **10-file fan-out ceiling** with `middleware.go` (492) and `governance.go` (483) near 500 lines — no new files allowed, so pure logic lives in `domains/permissions` and the middleware delta needs a line reshuffle.
- **Contract conflict resolved:** the spec's byte-identical tenant denial vs. AGENTS.md's documented `403 tenant_mismatch`. I picked the stricter (byte-identical `forbidden` at the middleware, `tenant_mismatch` kept only for the host-routing backstop) and flagged the required oracle-table/error-codes doc update in the same change.
- `admin:*` already covers all `admin:<res>:<action>` via the matcher's prefix rule, but legacy `admin:read`/`admin:write` do not — hence the explicit fallback set, with "forgot the fallback" identified as the #1 regression risk.

The doc closes with cross-cutting contract updates, gate commands, a 7-step sequencing plan, and 4 open review questions (oracle row, strict-vs-plain subset, approve-endpoint transport code, audit event reuse).
