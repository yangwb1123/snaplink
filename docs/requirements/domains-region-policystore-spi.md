# Requirements Spec: domains/region — Activate the PolicyStore SPI

> Expansion direction (from `docs/auto/domains-region-analysis.md` #3):
> 激活死代码 SPI：让 `PolicyStore` 成为真实扩展点，补耐用后端与区域 ID 校验。
> Exactly three evidence-backed improvements; scope is the policy-source SPI,
> its durable backend, and region-ID validation only. Direction #1
> (observability) and direction #2 (serving region in tokens/discovery) are
> separate specs.

Problem class: `region.PolicyStore` is a designed-but-dead extension point. The
interface and its only implementation (`domains/region/memory`) exist, yet no
production code imports them — the enforcement engine derives every policy from
tenant-row fields (`tenantStore.GetTenant` → `residencyPolicyFromTenant`), so
SDK embedders cannot plug a policy source, no durable backend exists for
residency policy independent of tenant rows, and the admin boundary writes
region IDs without any identity validation, so a typo such as `"EU-WEST-1"` vs
`"eu-west-1"` silently loosens or tightens a default-fail-open compliance
control. The three decisions below activate the SPI, add its durable half, and
close the validation hole — without changing oracle-safe semantics, the
fail-open decision order in `evaluateResidency`, or unwired (nil-default)
behavior.

## 1. Wire the dead PolicyStore SPI into the enforcement engine

**Name**: Two-tier policy resolution — an explicitly wired `region.PolicyStore`
becomes the authoritative, constraint-adding policy source with tenant-field
fallback.

**Problem**: The module's own extension point is never called in production.
`region.PolicyStore` (`domains/region/region.go:70`) and `memory.Store`
(`domains/region/memory/memory.go`) are imported by nothing outside the subtree
(only the compile-time check at `memory.go:69` and its own tests), while the
enforcement engine hardcodes the tenant-row path: `resolveResidencyPolicy`
(`interfaces/sso/server_tenant_residency.go:214`) does
`tenantStore.GetTenant` → `residencyPolicyFromTenant` (line 425). Consequences:
(a) an SDK embedder cannot plug a residency-policy source (config seed / admin /
external registry), the first-class extension dimension for an embeddable
product; (b) a dead SPI is worse than none — a future implementer will fork a
parallel store rather than reuse it; (c) AGENTS.md §4 ("Every storage concern is
an interface plus a real Memory* implementation and optional durable backends")
is satisfied in shape only. Budget note: `server_tenant_residency.go` is exactly
500 lines (the file ceiling), so the new code must not land there.

**Evidence**: `domains/region/region.go:70` (`PolicyStore`); `domains/region/memory/memory.go`
(sole implementation, zero production importers — `rg -n "PolicyStore" --type go`
hits only the subtree); `interfaces/sso/server_tenant_residency.go:159,214,425`
(`WithTenantResidencyCheck`, `resolveResidencyPolicy`, `residencyPolicyFromTenant`);
`interfaces/sso/sso_wiring.go:89-90` (residency server fields);
`wc -l interfaces/sso/server_tenant_residency.go` = 500.

**Proposed behavior**:

- New option `WithResidencyPolicyStore(store region.PolicyStore) Option` plus a
  `Server.residencyPolicyStore` field, in a NEW file
  `interfaces/sso/server_residency_policystore.go` (server_tenant_residency.go is
  at its line budget; the moved `resolveResidencyPolicy` + store tier live in the
  new file). Nil store = today's path, byte-identical.
- Resolution order in `resolveResidencyPolicy` (cache unchanged, sits above both
  tiers): cache hit → return; else, when a store is wired →
  `store.GetPolicy(ctx, tenantID)`. A NON-ZERO policy (`HomeRegion != ""` or
  `len(AllowedRegions) > 0` or `EnforceWrites`) wins and is cached. A zero policy
  OR a store error falls through to the existing tenant-field derivation; a
  store error is logged exactly like the tenant-store outage branch (fail-open).
- Precedence rationale: the store can only ADD constraint, never silently REMOVE
  it — a zero/absent/erroring store answer can never un-constrain a tenant the
  admin pinned via tenant fields, and existing deployments (no store wired) keep
  `evaluateResidency`'s decision ladder and fail-open semantics untouched.
- `evaluateResidency`, the cache TTL, `InvalidateTenantResidencyCache`, and the
  `KindTenantResidency` invalidation-bus path are unchanged.
- Contract updates in the same change: `docs/feature-matrix.md` multi-region row
  (add `WithResidencyPolicyStore` to the enablement column).

**Acceptance check**:

- New unit tests in `interfaces/sso`: (1) store wired via `memory.Store` with a
  constrained policy for a tenant whose tenant fields are unconstrained →
  `ResidencyDecision`/`residencyGateLogin` deny per the store policy (write and
  read gates); (2) store returns zero for a tenant with constrained tenant fields
  → tenant policy still enforced (fallback tier); (3) store stub returning an
  error → request allowed and `logger.Error` emitted (fail-open); (4) no store
  wired → the existing `TestResidency_*`/`TestRcov2Cl_ResidencyDecision` suites
  pass unchanged.
- `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' .`
- `go test ./interfaces/sso/ -run 'TestResidency|TestTenantResidency' -race`

## 2. Durable sqlite PolicyStore backend + config surface

**Name**: `domains/region/sqlite` — a durable `PolicyStore` (memory|sqlite)
with `region.policy_store` config and boot seeding, wired by the stock server.

**Problem**: The durable half of the storage concern is missing. `memory.Store`
self-describes as fine only where "residency policies are loaded from config at
boot" (`domains/region/memory/memory.go:1-4`), but no config surface loads
policies and no cluster-shared backend exists — every sibling store has one
(tenant: memory|sqlite; connections: memory|sqlite, `buildConnectionBackend` in
`cmd/sso-server/serverbuildstore/build_tenant_geo_region.go`). The stock binary
has no way to populate residency policy except admin `UpdateTenant` writing
tenant rows. `RegionConfig` (`config/config_geo_tenant.go:59`) exposes only
`serving_region`, `header_name`, `allowed_regions`, `residency_check_cache_ttl`;
`docs/config-reference.md:380` documents the same four knobs. AGENTS.md §4's
"interface + Memory* + optional durable backends" is half-built.

**Evidence**: `domains/region/memory/memory.go:1-4` (doc admits restart-loss +
config-loading assumption with no config surface); `config/config_geo_tenant.go:59-75`
(`RegionConfig`); `cmd/sso-server/serverbuildstore/build_tenant_geo_region.go:109-131`
(`buildConnectionBackend` memory|sqlite pattern); `domains/connections/sqlite/store.go`
(durable-backend pattern: `New(dsn)`, `platform/migrate` migrations, JSON columns);
`docs/config-reference.md:380` (region row).

**Proposed behavior**:

- New package `domains/region/sqlite` (directory depth 3; subdirectory count of
  `domains/region` stays ≤ 15; file < 500 lines): `New(dsn string) (*Store, error)`
  implementing `region.PolicyStore` plus `Set(ctx, tenantID, policy) error` and
  `Delete`. Schema: `region_policies(tenant_id TEXT PRIMARY KEY, home_region TEXT
  NOT NULL DEFAULT '', allowed_regions TEXT NOT NULL DEFAULT '[]',
  enforce_writes INTEGER NOT NULL DEFAULT 0)` with JSON-encoded
  `allowed_regions`, migrations via `platform/migrate` (mirrors
  `domains/connections/sqlite/store.go`). `Set` rejects invalid region IDs
  (decision 3). Absent tenant → zero policy, nil error (interface contract).
- Config `region.policy_store`: `backend` (`""` | `memory` | `sqlite`),
  `sqlite.dsn`, `seed[]` entries `{tenant_id, home_region, allowed_regions,
  enforce_writes}`. Empty backend = not wired, byte-identical.
- `cmd/sso-server/serverbuildstore/build_tenant_geo_region.go`: new
  `BuildRegionPolicyStore(cfg, logger) (region.PolicyStore, error)` — selects the
  backend, seeds declared policies after build, and fails boot LOUD on an invalid
  seed (mirrors connections seeding and `TokenStrategy`'s "boot fails loud");
  cmd passes a non-nil store to `sso.WithResidencyPolicyStore`.
- Shared conformance: `domains/region/regiontest` conformance helper (pattern:
  `permissionstest.ConformanceSuite`, AGENTS.md §4) exercised by BOTH
  `memory.Store` and `sqlite.Store` so future backends inherit the contract.
- Contract updates in the same change: `docs/config-reference.md` region row,
  `docs/feature-matrix.md`, `docs/architecture/DIRECTORY_MAP.md` ownership.

**Acceptance check**:

- `go test ./domains/region/...` — conformance suite passes on both backends;
  persistence test: `Set` → close → reopen the same DSN → `GetPolicy` returns
  the policy; absent tenant → zero policy, nil error; invalid ID on `Set` →
  `ErrInvalidRegion`, stored state unchanged.
- `cmd/sso-server/serverbuildstore` build tests: backend=sqlite with seed → seed
  lands and is readable; invalid seed region ID → boot error; backend=memory
  without dsn OK; backend empty → `(nil, nil)`.
- E2E unchanged for default config: `go test ./test/ -run TestE2E -v`.

## 3. Region-ID validation at every policy write boundary

**Name**: Canonical lowercase DNS-label region IDs enforced by
`region.ValidateID` / `region.ValidatePolicy` at the admin, memory, sqlite, and
seed boundaries.

**Problem**: Region IDs are compared by exact string equality everywhere —
`evaluateResidency` (`interfaces/sso/server_tenant_residency.go:246-261`,
`slices.Contains`), `HeaderResolver.Resolve` (`domains/region/resolver.go:62-77`)
— yet nothing validates them on write. The admin boundary explicitly refuses to:
`trimRegions` (`interfaces/grpcserver/grpcadmin/admin_tenants.go:444-457`) says
it "does NOT validate region identity", and `protoToTenant` (lines 422-431) only
trims `HomeRegion`. `"EU-WEST-1"` vs `"eu-west-1"` is therefore a silent
CONSTRAINT CHANGE, not a cosmetic one: a typo in `AllowedRegions` either
over-constrains (loud 403s) or — the dangerous direction against a
default-fail-open control — under-constrains by never matching the serving
region, with no error anywhere. The analysis doc calls this the module's most
dangerous failure mode. There is no `Validate`/`Normalize` symbol in
`domains/region` today (`rg -n "Validate|Normalize" domains/region` hits only
comments).

**Evidence**: `interfaces/grpcserver/grpcadmin/admin_tenants.go:422-431,444-457`
(`protoToTenant` trim-only, `trimRegions` non-validating);
`interfaces/sso/server_tenant_residency.go:246-261` (exact-match
`evaluateResidency`); `domains/region/resolver.go:62-77` (exact-match header
allowlist); `docs/error-codes.md:88` (`region_not_allowed` is the only
documented region surface — no write-time guard exists).

**Proposed behavior**:

- `domains/region`: `ValidateID(ID) error` — canonical form is 1–63 characters,
  lowercase `[a-z0-9]` labels joined by single `-`
  (`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`), covering `eu-west-1`, `us-east-1`,
  `ap-southeast-2`; rejects uppercase, spaces, underscores, leading/trailing
  `-`, empty (the empty ID is the unconstrained sentinel and is handled by
  callers). `ValidatePolicy(ResidencyPolicy) error` — validates `HomeRegion`
  when non-empty and every `AllowedRegions` entry. New sentinel
  `region.ErrInvalidRegion` (wrapped by stores; documented in
  `docs/error-codes.md` per AGENTS.md §5 step 6).
- Admin boundary: `protoToTenant` validates `HomeRegion` + `AllowedRegions`
  before `PutTenant` in `UpdateTenant`/`CreateTenant`
  (`interfaces/grpcserver/grpcadmin/admin_tenants.go`), surfacing gRPC
  `InvalidArgument` via the existing `ErrInvalidTenant` mapping path. NO silent
  case normalization: a governance control must be loud at write time, and all
  major clouds (AWS/GCP/Azure) use lowercase region names.
- Backend boundary: `memory.Store.Set` and `sqlite.Store.Set` reject invalid
  policies with `ErrInvalidRegion` — `memory.Store.Set` gains an error return
  (deliberate API tightening; every existing caller and test already uses valid
  lowercase IDs: `eu-west-1`, `eu-central-1`, `us-east-1`, `ap-south-1`, `us`,
  `ap`). Config seed fails boot loud through the same `Set` path (decision 2).
- Enforcement path untouched: `evaluateResidency`/`HeaderResolver` keep
  exact-match semantics — validated IDs make exact match safe.

**Acceptance check**:

- `domains/region` unit tests: `ValidateID` accepts `eu-west-1`, `us-east-1`,
  `ap-southeast-2`; rejects `EU-WEST-1`, `eu west`, `eu_west`, `-eu`, `eu-`,
  a 64-char label, and `""`; `ValidatePolicy` rejects a policy with a single bad
  `AllowedRegions` entry.
- grpcadmin unit test: `UpdateTenant` with `HomeRegion: "EU-WEST-1"` →
  `InvalidArgument`, store untouched; all existing valid-lowercase calls
  unchanged.
- memory/sqlite `Set` tests: invalid policy → error, stored state unchanged;
  existing `memory_test.go` suites green.
- Full gates: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`,
  `go test ./... -race`, `make ci`.
