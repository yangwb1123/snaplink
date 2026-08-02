Spec written to `docs/requirements/domains-region-policystore-spi.md` (verified every cited file:line against the codebase). Exactly three evidence-backed improvements for expansion direction #3:

## 1. Wire the dead PolicyStore SPI into the enforcement engine
- **Problem**: `region.PolicyStore` (`domains/region/region.go:70`) and `memory.Store` have zero production importers — `resolveResidencyPolicy` (`interfaces/sso/server_tenant_residency.go:214`) hardcodes `tenantStore.GetTenant` → `residencyPolicyFromTenant` (line 425). SDK embedders can't plug a policy source.
- **Behavior**: new `WithResidencyPolicyStore(region.PolicyStore)` option in a *new* file (`server_tenant_residency.go` is at the 500-line budget ceiling); two-tier resolution — non-zero store policy wins, zero/error falls through to tenant fields (fail-open, store can only add constraint, never silently remove it); nil store = byte-identical.
- **Accept**: precedence/fail-open unit tests; existing `TestResidency_*` suites unchanged.

## 2. Durable sqlite PolicyStore backend + config surface
- **Problem**: `memory.Store`'s own doc says policies are "loaded from config at boot" (`memory.go:1-4`) but no config surface exists; every sibling store (tenant, connections at `build_tenant_geo_region.go:109`) has memory|sqlite; `RegionConfig` (`config/config_geo_tenant.go:59`) has no policy-store knobs.
- **Behavior**: `domains/region/sqlite` (`New(dsn)`, `platform/migrate`, JSON `allowed_regions` column, mirroring `connections/sqlite/store.go`); `region.policy_store.{backend,sqlite.dsn,seed[]}` config; `BuildRegionPolicyStore` with boot-loud seeding; `regiontest` conformance helper run against both backends.
- **Accept**: conformance + persistence-across-reopen tests; build tests for each backend; E2E untouched.

## 3. Region-ID validation at every policy write boundary
- **Problem**: `trimRegions` (`admin_tenants.go:444-457`) "does NOT validate region identity" while `evaluateResidency` (`server_tenant_residency.go:246-261`) and `HeaderResolver.Resolve` (`resolver.go:62-77`) compare IDs by exact string equality — `"EU-WEST-1"` vs `"eu-west-1"` silently under-constrains a default-fail-open compliance control.
- **Behavior**: `region.ValidateID`/`ValidatePolicy` enforcing lowercase DNS-label form + new `ErrInvalidRegion`; enforced at admin (`InvalidArgument` via the existing `ErrInvalidTenant` mapping), `memory.Store.Set` (gains error return; all existing tests use valid IDs), `sqlite.Store.Set`, and config seed (boot-loud). No silent case normalization — loud rejection only.
- **Accept**: accept/reject unit tests, grpcadmin `InvalidArgument` test, store-unchanged-on-invalid tests, full gates (`go build`, `go vet`, `-race`, `make ci`).

All three preserve oracle-safe semantics, the `evaluateResidency` decision ladder, and nil-default behavior; contract updates (config-reference, feature-matrix, error-codes, DIRECTORY_MAP) are folded into each decision per AGENTS.md §5.
