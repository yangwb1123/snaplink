The requirements specification is complete and verified. I wrote it to `docs/auto/domains-tenant-direction3-spec.md`, following the established format of the existing direction-1 spec (`docs/auto/domains-tenant-direction1-spec.md`).

## Summary: 方向 3 spec — B2B cross-tenant collaboration「内存-only + 零管理面」→ 持久化后端 + 运营/审计表面

The spec contains exactly three evidence-backed improvements, each under its own `##` heading with problem → evidence (file/symbol) → proposed behavior → acceptance check:

**## Improvement 1: Durable SPI backends — sqlite + postgres implementations**
- *Problem*: The only implementations of `ExternalUserStore`/`CollaborationStore` are the single-replica in-process memory stores (`memory/collab_store.go:5–8` explicitly points at durable backends as the production path); restart destroys the entire trust graph.
- *Evidence*: `tenant_collab.go:37–39` (SPI doc promise), `tenant_collab.go:109/178` (interfaces), `options_grants.go:195–219` (only wiring), `sqlite.go:29–58` (migrations v1–v4), `postgres/tenant.go:35–57` (schema pattern).
- *Proposed*: migration v5 tables + two store types in `domains/tenant/sqlite/collab.go` and `infrastructure/postgres/collab.go`, plus a shared `ConformanceSuite` realized in-place in `domains/tenant/memory` (domains/ is at its frozen subdir ceiling, so the `permissionstest` pattern can't get its own package).

**## Improvement 2: Management + audit surface — `CollaborationAdminService`**
- *Problem*: Zero ops surface — no list/revoke for trust edges or guests, no audit trail for trust-graph mutations; every other tenant resource has full `TenantAdminService` CRUD.
- *Evidence*: `admin_tenants.go:19–75` (pattern to mirror), `tenants.proto:21–75` (RPC shape), `event_types_admin.go:60` + `auditreport/control_areas.go:34,109–120` (audit classification), `build_http.go:451` (gateway mount); budget constraint: grpcadmin is at its 10-file fan-out ceiling and `admin_tenants.go` at 461 lines, so RPCs extend `admin_domains.go`.
- *Proposed*: new `collaborations.proto` service (List/Put/Remove for edges; List/Add/Remove for guest records), 4 new `admin_*` audit events classified in `auditreport` and mapped in CEF/OCSF sinks.

**## Improvement 3: Snapshot v2 backup coverage + provisioning wiring**
- *Problem*: DR restore silently produces a server with zero trust edges/guest registrations; `cmd/sso-server` has no way to provision durable collab stores.
- *Evidence*: `snapshotter.go:162–188` (only `CategoryTenants`/`CategoryTenantDomains`), `snapshot.go:103–104,119`, `restorer.go:177–178`, `build_stores.go:142–160`, `build_app_oauth.go:67`; interfaces/snapshot is at its frozen 14-file ceiling.
- *Proposed*: `CategoryCollaborations`/`CategoryGuestRecords` categories exported per-tenant via the existing `ListTenants` scan, restore arms replaying idempotent upserts, and backend-switch wiring in `cmd/sso-server` (memory ⇒ nil, byte-identical).

The spec also pins preserved invariants (gate fail-closed oracle collapse untouched, nil-store no-op byte-identity, no new subdirectories, `admin:read`/`admin:write` scoping) and closes with Files (create/modify/do-not-modify) and a `make ci`-anchored verification plan. All line-number citations were checked against the sources.
