# domains/tenant — 方向 1 需求规格：租户解析热路径「两跳查询 + 零缓存」→ 单一解析器 + TTL 缓存 + 失效总线

Scope: expansion direction 1 from `docs/auto/domains-tenant-analysis.md` —
「租户解析热路径"两跳查询 + 零缓存"——收敛重复解析逻辑并接入失效总线」.
Today every tenant-bound request pays two storage round trips
(`GetDomain` + `GetTenant`), the resolution logic is duplicated across the
middleware and the rate-limit rejection path (a third partial copy in the
branding fallback), and — unlike suspension/residency/client checks, which
all have TTL caches plus invalidation-bus events — the base Domain→Tenant
route resolution has no cache at all and no routing-class bus event, so a
domain rebind/delete cannot take effect across replicas before each node's
TTL.

This spec contains exactly three evidence-backed improvements:

1.  `tenant.Resolver` — converge the duplicated resolution logic onto one
    canonical implementation.
2.  Route-resolution TTL cache — collapse the two-hop lookup to zero store
    calls on a cache hit.
3.  Invalidation-bus integration — `KindTenantDomain` event + admin
    callbacks + recovery re-seed coverage.

## Preserved invariants (non-negotiable)

- Oracle-safe semantics and the fail-open decision ladders in
  `interfaces/sso/server_tenant_residency.go` and
  `interfaces/sso/server_login.go` (suspension) are NOT touched. The route
  cache holds the same `*tenant.Resolved` verdict the store would return;
  it is advisory routing state, not a credential decision.
- Zero-value byte-identity: no `WithTenantStore` / no resolver cache wired ⇒
  every lookup behaves exactly as today (two live hops per request).
  Existing `domains/tenant` middleware + memory/sqlite/postgres tests stay
  green unchanged.
- `ResolveTenantID`'s contract (silent "" on any failure; only for
  already-slow reject paths) is preserved for its two call sites
  (`options_httpstack.go`, `server_routes.go`).
- No new upward imports: `domains/tenant` stays free of `platform/cluster`
  and `interfaces/sso`; bus publish/apply lives only at the sso layer
  (the suspension/residency precedent).
- Budgets: `domains/tenant` root grows 4 → 5 non-test files (ceiling 10);
  the new `resolver.go` stays well under 500 lines; `middleware.go` shrinks.

## Improvement 1: `tenant.Resolver` — converge duplicated resolution logic

**Problem**: The Host → Domain → Tenant resolution semantics exist in three
places that must be kept identical by discipline alone. `Middleware` performs
the two-hop lookup with timeout, `OnError` policy, and the suspended-status
gate; `ResolveTenantID` re-implements the same logic for the rate-limit
rejection path (which runs BEFORE the middleware in the HTTP stack and cannot
read `FromHandlerContext`); the branding fallback is a third, partial copy.
The `ResolveTenantID` doc comment itself concedes the invariant: "Honors the
same Timeout/HostExtractor/IncludeSuspended knobs as Middleware so the result
is identical whichever path resolved it" — enforced only by review.

**Evidence**:

- `domains/tenant/middleware.go:73–122` — `Middleware`: two sequential
  lookups (`GetDomain` → `GetTenant`), `OnError` handling, suspended gate,
  (nil, nil) misbehaved-store guard.
- `domains/tenant/middleware.go:137–172` — `ResolveTenantID`: same lookup
  re-implemented with silent failure; doc "performs the same Host -> Domain
  -> Tenant lookup as Middleware".
- `interfaces/sso/options_httpstack.go:121` and
  `interfaces/sso/server_routes.go:425` — the two `ResolveTenantID` call
  sites (rate-limit `TenantKeyFunc` + `SetRateLimitPolicy` defaulting).
- `interfaces/sso/server_me.go:107–116` — `handleBranding` fallback: third
  direct `GetDomain` lookup with its own host-extractor defaulting.
- `domains/tenant/middleware_test.go` — white-box `memStore` tests pin the
  current behavior of both paths.

**Proposed behavior**: New `domains/tenant/resolver.go` defines
`type Resolver struct` holding the `Store`, `MiddlewareOptions`, and the
cache from Improvement 2. It owns the single canonical
`Resolve(ctx, host) (*Resolved, error)` implementation (host extraction,
timeout, error policy, suspended gate, misbehaved-store guard — moved
verbatim from `Middleware`). `Middleware` becomes a thin adapter that calls
`Resolver.Resolve` and stashes on `HandlerContextKey`; `ResolveTenantID`
becomes a one-line delegation returning `resolved.Tenant.ID`; the
`handleBranding` fallback reuses `Resolver.Resolve` (the cached `Domain`
carries `Branding`, and suspended tenants are cached per Improvement 2, so
the suspended-tenant branding case keeps working). `Middleware(store, opts)`
keeps its signature by constructing a resolver internally, so no wiring
change is needed at `interfaces/sso/server_routes.go:122`.

**Acceptance check**:

- All existing `domains/tenant/middleware_test.go` tests pass unchanged.
- `ResolveTenantID` body no longer contains a `GetDomain` / `GetTenant`
  call (grep-proof); it delegates to the resolver.
- New table test drives Middleware-stashed `Resolved` and `ResolveTenantID`
  through the same resolver across the knob matrix — `IncludeSuspended`
  true/false, `ErrDomainNotFound`, store outage, misbehaved (nil, nil)
  store, empty host — and asserts identical outcomes (same tenant ID, same
  stashed/absent verdict).

## Improvement 2: Route-resolution TTL cache — zero store calls on the hot path

**Problem**: Every tenant-bound request (login, token, userinfo, branding)
pays two DB round trips. Suspension and residency each have a TTL cache with
invalidation-bus wiring, but the most-repeated lookup — the base route
resolution — has none: the Store doc explicitly blesses caching, yet both SQL
backends run a live query per call and no caching wrapper exists anywhere.
With `DefaultLookupTimeout` at 100 ms, a slow backend multiplies latency on
the hottest paths, and domain rebinds/deletes propagate only after each
replica's (nonexistent) TTL.

**Evidence**:

- `domains/tenant/tenant.go:81–84` — Store doc: "the routing-layer hot path
  always wants both (Domain → Tenant in one round trip)" and "backends MAY
  cache aggressively".
- `domains/tenant/middleware.go:23` — `DefaultLookupTimeout = 100ms`;
  `middleware.go:73–85` — the two sequential round trips.
- `infrastructure/postgres/tenant_domains.go:15–25` — `GetDomain`: live
  `QueryRowContext`, no cache.
- `domains/tenant/sqlite/sqlite.go:265–277` — `GetDomain`: live
  `QueryRowContext`, no cache.
- `interfaces/sso/server_tenant_residency.go:59–95` — the
  `DefaultTenantResidencyCacheTTL = 60s` + `residencyCache` (entries with
  `expiresAt`, RLock reads) pattern the routing layer lacks.
- `domains/tenant/memory/memory.go` — in-process map store, no TTL wrapper.

**Proposed behavior**: The `Resolver` from Improvement 1 owns a
hostname-keyed TTL cache of `*Resolved` (domain + tenant + status verdict).
Default TTL mirrors the residency pattern
(`DefaultTenantResolutionCacheTTL = 60s`, configurable via
`MiddlewareOptions`; unset ⇒ cache off, byte-identical today). Cache hit ⇒
zero store calls. Miss ⇒ the single two-hop read, then cached. Suspended
tenants are cached too (the middleware must know the status to gate, and the
branding fallback serves suspended-tenant branding). Expired entries
re-fetch. Negative lookups (`ErrDomainNotFound`) are NOT cached: unknown-host
probing must not pin memory, and new-domain propagation relies on the
invalidation events from Improvement 3, not on a negative-entry expiry race.
Exposes `Invalidate(hostname)`, `InvalidateTenant(tenantID)` (hostnames of a
tenant via a reverse index), and `Flush()` for Improvement 3.

**Acceptance check**:

- White-box test with a counting store: N requests for the same host within
  TTL ⇒ exactly 1 `GetDomain` + 1 `GetTenant`; after expiry ⇒ exactly one
  fresh pair; cache disabled ⇒ N pairs (prior behavior).
- Cache-hit path performs zero store calls and returns a `*Resolved` with
  field-identical values to a fresh lookup.
- Suspended tenant with `IncludeSuspended=false` resolves to "no tenant"
  from the cached verdict without touching the store; `IncludeSuspended=true`
  surfaces the cached suspended tenant.
- `go test ./domains/tenant/...` and the postgres/sqlite backend suites
  green unchanged; cache lives only in `resolver.go` (no store-interface
  change, no backend change).

## Improvement 3: Invalidation-bus integration — `KindTenantDomain` + admin callbacks + recovery re-seed

**Problem**: The invalidation bus already covers suspension, residency,
client metadata, discovery, authz policies, connections, and control-plane
restore — but has no routing-class event. Domain rebind/delete and tenant
status/residency changes therefore cannot take effect across replicas
immediately (only after each node's TTL, once Improvement 2 lands).
`TenantAdminService`'s domain mutations publish nothing, unlike the tenant
mutations which already wire `invalidateSuspensionCache` /
`invalidateResidencyCache` callbacks, and the bus-recovery re-seed
(`flushInvalidationCaches`) cannot converge a lost route event.

**Evidence**:

- `platform/cluster/bus.go:30–79` — `EventKind` consts: `KindTenantSuspension`
  (33), `KindDiscoveryReload` (40), `KindTenantResidency` (56),
  `KindClientChange` (66), `KindControlPlaneRestore` (79); no domain/routing
  kind. Doc at bus.go:25–29: "add a kind here and a dispatch arm on the
  subscriber side" is the sanctioned extension path.
- `interfaces/sso/server_invalidation.go:338–357` —
  `applyControlPlaneInvalidation`: arms for suspension/residency/client/
  discovery/authz/connection/restore, no route arm.
- `interfaces/sso/server_discovery_cache.go:283–314` —
  `flushInvalidationCaches`: flushes suspension, residency, client,
  discovery, JWKS, authz bundles; no route-cache flush.
- `interfaces/grpcserver/grpcadmin/admin_domains.go:75–144` —
  `CreateDomain`/`UpdateDomain`/`DeleteDomain`: `PutDomain`/`DeleteDomain`
  mutation sites with zero invalidation.
- `interfaces/grpcserver/grpcadmin/admin_tenants.go:19–49` — the
  `TenantAdminService` callback wiring pattern (`invalidateSuspensionCache` /
  `invalidateResidencyCache`, nil-safe no-ops) to mirror for domains.
- `interfaces/sso/server_tenant_residency.go:454–463` —
  `InvalidateTenantResidencyCache`: the local-evict + publish + log-not-fail
  pattern for the new `InvalidateDomainCache`.

**Proposed behavior**:

1. `platform/cluster/bus.go`: new `KindTenantDomain EventKind = "tenant.domain"`
   (key = canonical hostname), doc mirroring `KindTenantResidency`'s
   best-effort note ("a dropped Event only degrades a replica to its
   route-cache TTL").
2. `interfaces/sso`: `(*Server).InvalidateDomainCache(hostname)` mirrors
   `InvalidateTenantResidencyCache` — local `resolver.Invalidate(hostname)` +
   bus publish, publish failure logged not propagated. Also extend the
   `KindTenantSuspension`/`KindTenantResidency` receive arms to evict the
   tenant's cached hostnames (`resolver.InvalidateTenant(evt.Key)`, reverse
   index) — a status/residency change alters the cached route verdict.
3. `interfaces/grpcserver/grpcadmin`: new nil-safe `invalidateDomainCache
   func(hostname string)` callback on `TenantAdminService`, invoked after
   `CreateDomain`/`UpdateDomain`/`DeleteDomain`; `UpdateTenant`/
   `DeleteTenant`/`SetTenantStatus` additionally call a tenant-scoped
   eviction — wired from `cmd/sso-server` to `(*sso.Server).
   InvalidateDomainCache` exactly like the suspension/residency callbacks.
4. `applyControlPlaneInvalidation` gains `case cluster.KindTenantDomain:
   resolver.Invalidate(evt.Key)`; `flushInvalidationCaches` gains
   `resolver.Flush()` so a lost event during a bus outage converges on
   recovery re-seed, matching the documented re-seed contract
   (`server_discovery_cache.go:283–291`).
5. Mixed-version safety preserved: unknown kinds still fall to the default
   branch; the new kind is only dispatched by newer publishers and only
   evicts cache entries (never a store write).

**Acceptance check**:

- `test/invalidation_bus_test.go`-style integration with the memory bus:
  replica B resolves host → tenant A; admin mutation on replica A rebinds
  host → tenant B and publishes; replica B's next `Resolve` returns B
  immediately, without waiting out the TTL.
- Unit test: `applyControlPlaneInvalidation` dispatches `KindTenantDomain` →
  resolver eviction; a `KindTenantSuspension` event for tenant T evicts
  every cached hostname of T (reverse index); `KindControlPlaneRestore` →
  `resolver.Flush()` (full cache drop).
- `TenantAdminService` with nil callbacks (unwired deployment) is
  byte-identical; no store writes on the receive path; `go test ./... -race`
  and `make ci` green.
- Oracle-safety unaffected: the route cache resolves public hostnames only
  (no credential surface); `test/` E2E suite green unchanged.

## Files

### Create

```text
domains/tenant/resolver.go — canonical Resolve + TTL cache + Invalidate/InvalidateTenant/Flush (Improvements 1–3)
domains/tenant/resolver_test.go — counting-store cache tests + knob-matrix equivalence tests
```

### Modify

```text
domains/tenant/middleware.go — Middleware/ResolveTenantID delegate to Resolver; cache knob in MiddlewareOptions
interfaces/sso/server_tenant_residency.go — InvalidateDomainCache + resolver field wiring (or new server_tenant_route.go)
interfaces/sso/server_invalidation.go — applyControlPlaneInvalidation KindTenantDomain arm + tenant-scoped eviction arms
interfaces/sso/server_discovery_cache.go — flushInvalidationCaches resolver flush
interfaces/sso/options_misc.go — WithTenantStore constructs the Resolver (cache TTL option)
interfaces/sso/server_me.go — handleBranding fallback via Resolver
interfaces/grpcserver/grpcadmin/admin_domains.go — invalidateDomainCache callback after Create/Update/DeleteDomain
interfaces/grpcserver/grpcadmin/admin_tenants.go — tenant-scoped eviction callbacks on Update/Delete/SetStatus
cmd/sso-server/… — wire the new callbacks to (*sso.Server).InvalidateDomainCache
platform/cluster/bus.go — KindTenantDomain const + doc
```

### Do not modify

```text
domains/tenant/tenant.go — Store interface (no new method; caching lives in Resolver)
infrastructure/postgres/tenant_domains.go, domains/tenant/sqlite/sqlite.go — backends stay live-query; cache is a layer above
interfaces/sso/server_tenant_residency.go — the residency decision ladder (evaluateResidency order is load-bearing)
```

## Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./domains/tenant/... -race
go test ./interfaces/sso/ -run 'TestInvalidation|TestTenant' -race
go test ./test/ -run 'TestE2E|TestInvalidationBus' -v
make ci
```
