Design doc written to `docs/design/domains-region-policystore-spi.md`. Every cited file:line in the requirements spec was re-verified against the codebase before designing.

## Key findings from verification

**One gate conflict found**: the spec mandates a *new* file `interfaces/sso/server_residency_policystore.go`, but `interfaces/sso` is at its frozen 60-file ceiling (`directory_fanout_test.go`: `dirFileCountExemptions["interfaces/sso"] = 60`, enforced as regression-if-grown — a 61st file fails `make ci`). The design resolves it the AGENTS.md-sanctioned way: the two-tier resolution moves **down** into a new `domains/region/policyresolve.go` (domain free function + thin Server wrapper), while the `WithResidencyPolicyStore` option and field land in the existing `sso_wiring.go` (439 lines, ~61 headroom). `server_tenant_residency.go` shrinks to ~460, staying under its 500-line budget.

**All other spec claims verified**: 500-line ceiling, dead SPI with zero production importers, trim-only admin boundary, exact-match enforcement, all `memory.Store.Set` callers using valid lowercase IDs, `ErrInvalidTenant`→`InvalidArgument` mapping, connections/sqlite pattern, `permissionstest` conformance pattern, `modernc.org/sqlite` already in root `go.mod`, same-layer domain imports precedented (`tokenanomaly` → `metering`).

## Design decisions per heading

- **Two-tier resolution**: precise ladder (cache → store → tenant fields), with two subtleties nailed down: (1) store-*error* fall-throughs are **not cached** (`cacheable=false`) so a transient outage can't cement an under-constrained policy for a full TTL; (2) the "store only adds constraint" guarantee holds only for zero/error answers — a *non-zero* store policy **replaces** tenant fields wholesale (no merge), documented as an operator footgun.
- **sqlite backend + config**: `region_policies(tenant_id PK, home_region, allowed_regions JSON, enforce_writes)` via `platform/migrate` namespace `"region"`; `region.policy_store.{backend,sqlite.dsn,seed[]}`; `BuildRegionPolicyStore` boot-loud on bad DSN/seed/backend; `wireRegion` gains an error return; `regiontest` conformance `Backend` interface (Set/Delete beyond the read-only `PolicyStore`).
- **Validation**: `ValidateID`/`ValidatePolicy`/`ErrInvalidRegion`, enforced at admin (via the existing `ErrInvalidTenant` shape), memory/sqlite `Set` (validate-before-store, state unchanged), and seed. One documented deviation: the spec's literal regex admits `a--b`; I chose the strict DNS-label form `^[a-z0-9]+(-[a-z0-9]+)*$` + length 1–63, which matches the spec's own prose and has an identical acceptance set.
- **What could break the design**: 10 ordered risks, topped by the file-ceiling trap, cache-poisoning across tiers, the replace-not-merge surprise, and the `Set` signature tightening.

One note: `docs/architecture/DIRECTORY_MAP.md` needs **no** structural change — its layout block enumerates only top-level packages (subpackages like `connections/sqlite` aren't listed), so `region/{sqlite,regiontest}` ownership follows the existing `domains/` row.
