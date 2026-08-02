Design doc written to `docs/auto/domains-tenant-direction3-design.md`. It follows the established design-doc format (`## Decision` headings, each with problem restated / API surface / storage model / failure modes / what could break the design), with three decisions plus a sequencing/gate-compliance section.

## What the design fixes

**Decision 1 — Durable backends**: sqlite `collab.go` (migration v5 appended to the shared `migrations` list, single `"tenant"` namespace), postgres `collab.go`, and the in-place `ConformanceSuite` in `domains/tenant/memory`. Key storage decisions: no FK to `tenants` (opaque IDs, memory-tenant deployments), `created_at` as Unix-nano integers matching the tenant tables, and JSON `null` round-trip for nil-vs-empty `Roles`/`Attributes` parity with memory.

**Decision 2 — Admin surface**: six RPCs with exact route shapes. Two notable calls I made:
- `guest_tenant_id` is **required** on both list RPCs — the SPIs have no global list, so unfiltered listing would couple the service to a `tenant.Store`; full inventory belongs to the snapshot category.
- The second key of composite removes rides as a **query parameter**, not a second path segment — tenant IDs and raw subject IDs are opaque and may contain `/`.

**Decision 3 — Snapshot + provisioning**: two new categories, per-tenant export via the existing `ListTenants` scan, restore arms with full mode semantics (Merge-skip / Overwrite-upsert / Replace-prune, with `ErrUnsupportedRestore` when no tenant store is wired, per the pairwise precedent), and shared-`*sql.DB` wiring in `wireTenant`. No new config knob — durability derives from `tenant.backend`.

## Three spec corrections surfaced during design

1. **Postgres upgrade trap (most important)**: the spec's "extend `tenantSchema`'s ensure path" is wrong — the versioned runner (`applyPending` in `infrastructure/postgres/migrate.go`) never re-applies an already-stamped v1 baseline, so existing postgres DBs would silently lack the collab tables. The design mandates a **v2 migration** in `tenantMigrations` plus an upgrade-path test.
2. **Wire-key drift**: `shared/core/consts_wire.go` has only `KeyGuestTenantID`; `home_tenant_id`/`external_subject_id` are not existing consts — two must be added.
3. **File budget**: the spec's single-file plan (`admin_domains.go` 171 → ~470) leaves ~30 lines of headroom; a realistic estimate is ~530. Split committed: RPCs in `admin_domains.go`, converters/helpers in `admin_paginate.go` (331 → ~430, both under 500).

All budget numbers were re-verified against the tree, including the pre-existing quirk that `infrastructure/postgres` (26 files) is gate-skipped via `skipDirs` despite AGENTS.md calling it a root-module package — noted, not fixed.
