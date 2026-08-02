Spec written to `docs/auto/domains-tenant-direction1-spec.md`. It follows the sibling-spec convention (Chinese title, English body) and contains exactly the three evidence-backed improvements for 方向 1:

## Summary

**## Improvement 1: `tenant.Resolver` — converge duplicated resolution logic**
- **Problem**: Host→Domain→Tenant resolution is implemented three times (`Middleware`, `ResolveTenantID`, `handleBranding` fallback); the "identical result" invariant is enforced only by review.
- **Evidence**: `domains/tenant/middleware.go:73–122` (Middleware), `middleware.go:137–172` (ResolveTenantID, whose doc concedes the duplication), `interfaces/sso/options_httpstack.go:121` + `server_routes.go:425` (call sites), `interfaces/sso/server_me.go:107–116` (third copy), `middleware_test.go` (pinning tests).
- **Proposed**: single canonical `Resolve` in a new `resolver.go`; `Middleware`/`ResolveTenantID`/branding fallback all delegate.
- **Acceptance**: existing middleware tests unchanged; grep-proof that `ResolveTenantID` no longer calls the store; knob-matrix equivalence table test.

**## Improvement 2: Route-resolution TTL cache — zero store calls on hit**
- **Problem**: every request pays 2 DB round trips; Store doc blesses caching ("backends MAY cache aggressively", tenant.go:81–84) but postgres/sqlite `GetDomain` are live queries and there is no wrapper; suspension/residency have caches, routing has none.
- **Evidence**: `tenant.go:81–84`, `middleware.go:23` (100 ms timeout), `infrastructure/postgres/tenant_domains.go:15–25`, `domains/tenant/sqlite/sqlite.go:265–277`, `server_tenant_residency.go:59–95` (the TTL pattern to mirror).
- **Proposed**: resolver-owned hostname→Resolved TTL cache (60 s default, off by default for byte-identity), suspended verdicts cached, negatives not cached.
- **Acceptance**: counting-store test — N requests ⇒ 1 GetDomain + 1 GetTenant, expiry re-fetch, disabled ⇒ N pairs.

**## Improvement 3: Invalidation-bus integration — `KindTenantDomain` + admin callbacks + re-seed**
- **Problem**: no routing-class bus event, so rebinds/deletes can't converge cross-replica; domain admin mutations publish nothing; `flushInvalidationCaches` can't re-seed a lost route event.
- **Evidence**: `platform/cluster/bus.go:30–79` (no domain kind), `server_invalidation.go:338–357` (no arm), `server_discovery_cache.go:283–314` (no flush), `grpcadmin/admin_domains.go:75–144` (mutation sites), `admin_tenants.go:19–49` (callback pattern to mirror), `server_tenant_residency.go:454–463` (publish pattern).
- **Proposed**: new `KindTenantDomain` event; `InvalidateDomainCache` mirroring residency; nil-safe admin callbacks; tenant-scoped eviction via reverse index on suspension/residency arms; `Flush()` in recovery re-seed.
- **Acceptance**: memory-bus integration test (replica B re-resolves immediately after replica A's rebind), dispatch/eviction unit tests, unwired byte-identity, `make ci`.

The spec also records preserved invariants (oracle-safety, fail-open ladders, zero-value byte-identity, no new upward imports, `domains/tenant` 4→5 files under the 10-file budget) and a verification plan with the mandatory gates.
