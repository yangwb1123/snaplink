# Design: Activate the `region.PolicyStore` SPI

> Implements `docs/requirements/domains-region-policystore-spi.md` (expansion
> direction #3: wire the dead policy-source SPI, add its durable backend, and
> close the region-ID validation hole). Scope is exactly the three decisions in
> that spec; observability (direction #1) and serving-region-in-tokens
> (direction #2) are separate.

## Verified evidence (every cited file:line re-checked)

| Claim | Verification |
|---|---|
| `region.PolicyStore` exists, zero production importers | `domains/region/region.go` (interface), `domains/region/memory/memory.go` (sole impl); `rg PolicyStore` hits only the subtree + unrelated `ratelimit.PolicyStore` |
| Enforcement hardcodes tenant-row path | `interfaces/sso/server_tenant_residency.go`: `resolveResidencyPolicy` (line 214) → `tenantStore.GetTenant` → `residencyPolicyFromTenant` (line 425) |
| `server_tenant_residency.go` at the 500-line ceiling | `wc -l` = 500 |
| `interfaces/sso` at its 60-file ceiling | 60 non-test files; `directory_fanout_test.go` `dirFileCountExemptions["interfaces/sso"] = 60`, enforced as regression-if-grown (**this conflicts with the spec's "new file in interfaces/sso" — resolved below**) |
| `RegionConfig` has no policy-store knobs | `config/config_geo_tenant.go` (4 fields only); `docs/config-reference.md` region row documents the same 4 |
| Sibling memory\|sqlite builder pattern | `cmd/sso-server/serverbuildstore/build_tenant_geo_region.go` `buildConnectionBackend` |
| Durable-backend pattern to mirror | `domains/connections/sqlite/store.go`: `New(dsn)`, `platform/migrate.Run(ctx, db, namespace, migrations)`, JSON columns, `modernc.org/sqlite` already in root `go.mod` |
| Admin boundary refuses validation | `interfaces/grpcserver/grpcadmin/admin_tenants.go` `protoToTenant`/`trimRegions` (422–457): trim only, "does NOT validate region identity" |
| Exact-match enforcement | `evaluateResidency` (`slices.Contains`) and `HeaderResolver.Resolve` allowlist |
| `ErrInvalidTenant` → `InvalidArgument` mapping | `admin_tenants.go:220,261` (`status.Errorf(codes.InvalidArgument, ...)`) |
| All existing `memory.Store.Set` callers use valid lowercase IDs | `memory_test.go` only: `eu-west-1`, `eu-central-1`, `us-east-1`, `ap-south-1`, generated `rt*` — so `Set` gaining an error return breaks nothing |
| Conformance-suite pattern | `domains/permissions/permissionstest` (`Factory` per subtest) |
| No `Validate`/`Normalize` in `domains/region` today | `rg` hits only comments |
| Cross-domain (same-layer) imports are legal | precedent `domains/tokenanomaly` → `domains/metering`, `domains/threataction`; layer gate classifies by first path segment |

---

## Decision 1: Two-tier policy resolution — wire the SPI into the enforcement engine

### Placement (deviation from the spec's letter, same behavior)

The spec proposes a new `interfaces/sso/server_residency_policystore.go`. That
file **cannot exist**: `interfaces/sso` is at its frozen 60-file ceiling and
`TestArchitecture_DirectoryFileFanout` fails on 61. AGENTS.md §2 sanctions the
alternative: *"Extend an existing file or move behavior down to a domain
package."* The resolution logic is domain logic, so it moves **down** into
`domains/region` (the package's own doc already claims ownership: "region/
sits above tenant/", and `residencyPolicyFromTenant`'s comment says "region/
owns the typed mapping"). The Server keeps a thin cache-orchestrating wrapper.

### API surface

**New file `domains/region/policyresolve.go`** (package `region`; 5th
non-test file, well under the 10-file/dir cap):

```go
// TenantReader is the minimal fallback-tier dependency. tenant.Store
// satisfies it; embedders may supply their own.
type TenantReader interface {
    GetTenant(ctx context.Context, tenantID string) (*tenant.Tenant, error)
}

// Logger is the optional fail-open reporter (spi.Logger satisfies it).
type Logger interface{ Error(msg string, kv ...any) }

type ResolveDeps struct {
    Store   PolicyStore  // nil = tenant-fields-only (today's path, byte-identical)
    Tenants TenantReader // nil = no fallback tier -> unconstrained
    Logger  Logger       // nil = silent
}

// ResolveResidencyPolicy renders the effective policy for tenantID.
// Returns ok=false for every unconstrained / fail-open case (MUST allow).
// cacheable=false when the result was derived under a store ERROR — the
// wrapper must not cache it (see Caching semantics).
func ResolveResidencyPolicy(ctx context.Context, deps ResolveDeps, tenantID string) (policy ResidencyPolicy, ok bool, cacheable bool)
```

Resolution ladder (order is load-bearing, mirrors the spec):

1. `deps.Tenants == nil` → `(zero, false, false)` — unconstrained, no cache.
2. Store tier (only when `deps.Store != nil`):
   - `GetPolicy` **error** → log `"region residency policy store lookup failed; failing open to tenant fields"` (same shape as the existing tenant-store-outage log) → **fall through to step 3 with `cacheable=false`**.
   - non-zero policy (`HomeRegion != "" || len(AllowedRegions) > 0 || EnforceWrites`) → `(storePolicy, true, true)` — authoritative, cache it.
   - zero policy → fall through to step 3 with `cacheable=true`.
3. Tenant-fields tier: `GetTenant` error or nil tenant → existing log + `(zero, false, false)` (fail-open, unchanged). Otherwise derive via `residencyPolicyFromTenant` (moved here) → `(derived, true, cacheable)`.

**New file `domains/region/policyresolve.go` also receives the moved**
`residencyPolicyFromTenant(t *tenant.Tenant) ResidencyPolicy` (moved verbatim
from `server_tenant_residency.go`; its home is `domains/region` per its own
documented intent; requires the same-layer `domains/tenant` import —
precedented). No behavior change.

**Existing file `interfaces/sso/sso_wiring.go`** (439 lines; ~61 headroom):
- field `residencyPolicyStore region.PolicyStore` beside `tenantResidencyEnabled` (line ~89);
- `func WithResidencyPolicyStore(store region.PolicyStore) Option` — sets the field; `nil` is a no-op (byte-identical).

**Existing file `interfaces/sso/server_tenant_residency.go`** — `resolveResidencyPolicy` shrinks to a thin wrapper (net −40 lines; file drops to ~460):

```go
func (s *Server) resolveResidencyPolicy(ctx context.Context, tenantID string) (region.ResidencyPolicy, bool) {
    if s.tenantResidencyCache != nil {
        if policy, hit := s.tenantResidencyCache.get(tenantID); hit {
            return policy, true
        }
    }
    policy, ok, cacheable := region.ResolveResidencyPolicy(ctx, region.ResolveDeps{
        Store: s.residencyPolicyStore, Tenants: s.tenantStore, Logger: s.logger,
    }, tenantID)
    if ok && cacheable && s.tenantResidencyCache != nil {
        s.tenantResidencyCache.put(tenantID, policy)
    }
    return policy, ok
}
```

Unchanged: `evaluateResidency` decision ladder, `residencyCache` type + TTL,
`checkTenantResidency`, `residencyGateLogin`, `ResidencyDecision`,
`residencyDeniedForAccess`, `InvalidateTenantResidencyCache`, `KindTenantResidency`
bus path, middleware order.

### Caching semantics (the subtle case)

A **store error** falls through to tenant fields **and is NOT cached**
(`cacheable=false`): caching a tenant-derived policy immediately after a store
error would cement a potentially under-constrained policy into the cache for a
full TTL. Skipping the put makes the next request re-probe the store — recovery
is immediate when the store returns, and the per-request tenant-store cost
during the blip is exactly what today's outage path already pays. A **zero**
store answer IS cached (store healthy, no entry — nothing to recover from).
`InvalidateTenantResidencyCache` is unaffected and remains the admin-edit
invalidation path.

### Precedence guarantee — and its precise boundary

The "store can only ADD constraint, never silently REMOVE it" guarantee holds
for zero / absent / erroring store answers (they fall through and tenant fields
still enforce). A **non-zero** store policy is **authoritative and replaces the
tenant-fields policy wholesale** — there is no per-field merge. Consequence to
document in `docs/config-reference.md`: an operator wiring a store with a
partial policy (e.g. only `AllowedRegions`) for a tenant whose row pins
`HomeRegion` silently drops the row pin. This is deliberate: merging would make
the effective policy depend on two sources and destroy the "authoritative
source" property; the store is the single source of truth once wired, and
`WithResidencyPolicyStore` is an explicit operator act. Zero-policy fall-through
still guarantees the store cannot *un-constrain* an admin-pinned tenant.

### Failure modes

- Store outage → logged, tenant-fields tier still enforces, request proceeds (fail-open, matching the tenant-store-outage contract; never a 4xx).
- Store returns a stale/partial non-zero policy → authoritative by design; operator-owned.
- Store returns a policy for a tenant whose row was deleted → store policy still enforced (store outlives the row; deleting a tenant does not clear the store — documented; `Delete` exists for embedders).
- Store closed/never-opened → `GetPolicy` error → fail-open path above.
- Concurrent `Set` during enforcement: memory is RWMutex-guarded, sqlite is DB-backed — both safe; the cache may hold a pre-Set policy until TTL/invalidation (unchanged from today).

---

## Decision 2: Durable `domains/region/sqlite` backend + `region.policy_store` config

### API surface

**New package `domains/region/sqlite`** (directory depth 3; `domains/region`
subdir count 1 → 2):

```go
func New(dsn string) (*Store, error)      // open, ping, migrate; mirrors connections/sqlite
func (s *Store) GetPolicy(ctx context.Context, tenantID string) (region.ResidencyPolicy, error) // absent row -> zero, nil
func (s *Store) Set(ctx context.Context, tenantID string, p region.ResidencyPolicy) error       // ValidatePolicy first (decision 3); upsert
func (s *Store) Delete(ctx context.Context, tenantID string) error                               // idempotent
func (s *Store) Close() error
var _ region.PolicyStore = (*Store)(nil)
```

**New package `domains/region/regiontest`** — shared conformance helper
(permissionstest pattern; production packages stay free of `testing`):

```go
type Backend interface {
    region.PolicyStore
    Set(ctx context.Context, tenantID string, p region.ResidencyPolicy) error
    Delete(ctx context.Context, tenantID string) error
}
type ConformanceSuite struct{ Factory func(*testing.T) Backend } // fresh instance per subtest
func (s ConformanceSuite) Run(t *testing.T)
```

Subtests: `SetGet_Roundtrip`, `AbsentIsZeroUnconstrained`, `DeleteRevertsToUnconstrained`,
`DeleteIdempotent`, `SetRejectsInvalidRegion_StateUnchanged`, `SetCopiesAllowedRegions`,
`SetReplacesPolicy`. Both `memory.Store` and `sqlite.Store` run the suite from
their own `_test.go` files, so future backends inherit the contract.

**`config/config_geo_tenant.go`** (204 lines; ~30 added):

```go
type RegionPolicyStoreConfig struct {
    Backend string                       `yaml:"backend"` // "" | memory | sqlite; "" = not wired
    SQLite  RegionPolicyStoreSQLiteConfig `yaml:"sqlite"`
    Seed    []RegionPolicySeedConfig     `yaml:"seed"`
}
type RegionPolicyStoreSQLiteConfig struct{ DSN string `yaml:"dsn"` }
type RegionPolicySeedConfig struct {
    TenantID      string   `yaml:"tenant_id"`
    HomeRegion    string   `yaml:"home_region"`
    AllowedRegions []string `yaml:"allowed_regions"`
    EnforceWrites bool     `yaml:"enforce_writes"`
}
// RegionConfig gains: PolicyStore RegionPolicyStoreConfig `yaml:"policy_store"`
```

**`cmd/sso-server/serverbuildstore/build_tenant_geo_region.go`** (227 lines; ~60 added):

```go
func BuildRegionPolicyStore(cfg *config.Config, logger spi.Logger) (region.PolicyStore, error)
```

- `backend == ""` → `(nil, nil)` — cmd wires the option unconditionally; the
  option no-ops on nil → byte-identical default config.
- `memory` → `regionmemory.New()`; `sqlite` → DSN required (else boot error,
  mirrors connections), `regionsqlite.New(dsn)`; unknown backend → boot error.
- Seeding: every `seed[]` entry → `store.Set(ctx, tenant_id, policy)`; any
  error (including `ErrInvalidRegion` from decision 3) closes the store and
  **fails boot loud**. Logs `"region policy store: <backend>"` + seed count.

**`cmd/sso-server/build_app_selfservice.go`** — `wireRegion()` (currently no
error return; called from `wireGeoRegionRisk() error`):
- Build the store **before** the resolver-nil early return (a configured-but-
  broken `policy_store` must fail boot even when region middleware is absent —
  same boot-loud discipline as connections), return the error from `wireRegion`
  (signature gains `error`).
- After `WithTenantResidencyCheck`, append `sso.WithResidencyPolicyStore(store)`
  unconditionally (nil-safe).

### Storage model

Single table, dedicated migration namespace (mirrors connections; `migrate.Run(ctx, db, "region", migrations)`):

```sql
CREATE TABLE IF NOT EXISTS region_policies (
    tenant_id       TEXT PRIMARY KEY,
    home_region     TEXT NOT NULL DEFAULT '',
    allowed_regions TEXT NOT NULL DEFAULT '[]',  -- JSON array of strings
    enforce_writes  INTEGER NOT NULL DEFAULT 0
);
```

- v1 baseline only. `allowed_regions` JSON-encoded (`[]region.ID` ↔ `[]string`),
  decoded on read, tolerant of `'[]'`/empty.
- `Set` = `INSERT ... ON CONFLICT(tenant_id) DO UPDATE` (replace semantics, matches memory.Store).
- `GetPolicy` absent row → zero policy, nil error — the interface contract
  ("no policy" == "unconstrained"), no `sql.ErrNoRows` leak.
- No foreign key to a tenants table: `region/` sits above `tenant/`, policy
  rows may legitimately precede tenant rows and survive tenant deletion.
- Root module (like `connections/sqlite`): `modernc.org/sqlite` already in
  root `go.mod`; no nested go.mod, no `go.work`.

### Boot wiring summary

`config` → `BuildRegionPolicyStore` (select backend, migrate, seed, boot-loud
on any failure) → `wireRegion` → `sso.WithResidencyPolicyStore` → two-tier
resolution (decision 1). Default config (`backend: ""`) produces `(nil, nil)`
→ the option sets a nil field → enforcement path byte-identical; E2E untouched.

### Failure modes

- Bad DSN / unreachable file / migrate failure → `New` errors → boot fails loud (no half-built store).
- Invalid seed region ID → `Set` → `ErrInvalidRegion` → boot fails loud with the offending seed named; store closed.
- Unknown backend string → boot error (mirrors connections).
- `GetPolicy` on a closed store → error → decision-1 fail-open path (logged, tenant fields, never 4xx).
- Memory backend + seed: valid (in-process, restart re-seeds — matches memory.Store's documented contract); sqlite persists.
- Replica divergence: sqlite is cluster-shared, so a policy write on one replica is visible to all (after their residency-cache TTL or explicit invalidation); memory is single-replica by contract.

---

## Decision 3: Region-ID validation at every policy write boundary

### API surface

**New file `domains/region/validate.go`** (package `region`):

```go
var ErrInvalidRegion = errors.New("region: invalid region id")

func ValidateID(id ID) error
func ValidatePolicy(p ResidencyPolicy) error // HomeRegion when non-empty + every AllowedRegions entry
```

Canonical form: 1–63 chars, lowercase `[a-z0-9]` labels joined by single `-`
(covering `eu-west-1`, `us-east-1`, `ap-southeast-2`). The empty ID is the
unconstrained sentinel — `ValidateID("")` rejects it, but `ValidatePolicy`
skips an empty `HomeRegion` (callers own the sentinel).

**Regex decision (deviation from the spec's literal regex, same acceptance
set).** The spec's `^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$` admits `a--b`
(consecutive dashes), contradicting its own prose ("labels joined by single
`-`"). Use the strict DNS-label form `^[a-z0-9]+(-[a-z0-9]+)*$` plus an explicit
1–63 length check. Every listed acceptance case behaves identically
(`EU-WEST-1` reject, `eu west` reject, `eu_west` reject, `-eu` reject, `eu-`
reject, 64-char reject, `""` reject, the three examples accept); the strict form
additionally rejects `a--b` in line with the prose intent. Errors wrap the
offending value: `fmt.Errorf("%w: %q", ErrInvalidRegion, id)` — loud, never
silent case-normalization.

**Enforcement points (validate-then-write everywhere; no partial state):**

1. **Admin gRPC** — `interfaces/grpcserver/grpcadmin/admin_tenants.go`: new
   helper `validateTenantRegions(t *tenant.Tenant) error` (maps the tenant's
   string fields into `region.ResidencyPolicy`, calls `region.ValidatePolicy`,
   returns `errors.Join(tenant.ErrInvalidTenant, err)`). Called in
   `CreateTenant` and `UpdateTenant` immediately after `protoToTenant`, before
   `PutTenant`; the error is surfaced as `status.Errorf(codes.InvalidArgument, "%v", err)`
   — the exact shape of the existing `ErrInvalidTenant` branch (lines 220/261),
   so the "existing mapping path" wording holds and `errors.Is` against
   `tenant.ErrInvalidTenant` keeps working for any downstream checks.
   `trimRegions` stays as-is (whitespace trim is orthogonal; validation runs on
   the trimmed values). The HTTP admin surface does not write region fields
   (verified: no `HomeRegion`/`AllowedRegions` in `server_admin_handlers.go`).
2. **`memory.Store.Set`** — gains `error`; `region.ValidatePolicy` **before**
   storing (state unchanged on rejection). Deliberate API tightening; every
   in-repo caller (memory_test.go) already uses valid lowercase IDs.
3. **`sqlite.Store.Set`** — same validate-first ordering (conformance subtest
   `SetRejectsInvalidRegion_StateUnchanged` locks both).
4. **Config seed** — goes through `Set` (decision 2) → invalid seed = boot loud.

**Enforcement path untouched:** `evaluateResidency` and `HeaderResolver.Resolve`
keep exact-match semantics — validated writes are what make exact match safe.
No normalization, no migration of legacy rows (write-time guard only; a
pre-existing uppercase row keeps today's exact-match behavior, which is the
status quo and out of scope).

### Failure modes

- Typo'd region at admin write → `InvalidArgument`, store untouched, admin
  sees the offending value in the error text (governance loudness is the point).
- Typo'd region in config seed → boot fails loud, server does not start.
- Typo'd region via SDK `store.Set` → `ErrInvalidRegion`, stored state unchanged.
- Legacy uppercase rows already in tenant stores: unchanged behavior (they
  never matched enforcement anyway); no silent correction.

---

## Cross-cutting contract updates (AGENTS.md §5 step 6, same change)

| Artifact | Update |
|---|---|
| `docs/config-reference.md` | Region row: add `region.policy_store.backend` (`""` · `memory` · `sqlite`), `region.policy_store.sqlite.dsn`, `region.policy_store.seed[]`; document the replace-not-merge authority of a wired store and the boot-loud seed failure |
| `docs/feature-matrix.md` | Multi-region row (line 150): add `WithResidencyPolicyStore` + `region.policy_store` to the enablement column |
| `docs/error-codes.md` | Add `ErrInvalidRegion` entry: surfaces as gRPC `InvalidArgument` on admin tenant create/update and as a boot-loud config-seed failure (not an HTTP wire code); keep it next to the `region_not_allowed` / `residency_violation` rows |
| `docs/architecture/DIRECTORY_MAP.md` | No structural change needed — the layered-layout block enumerates top-level packages only, and subpackages (`connections/sqlite` etc.) are not listed; ownership of `domains/region/{sqlite,regiontest}` follows the existing `domains/` row |

## What could break the design

1. **The 60-file ceiling** (highest risk, already resolved): any implementer
   who follows the spec's letter and creates `interfaces/sso/server_residency_policystore.go`
   fails `TestArchitecture_DirectoryFileFanout` at `make ci`. The domain-package
   placement above is mandatory, not optional.
2. **Byte-identical nil-default regression**: with no store wired, the wrapper
   must not consult `residencyPolicyStore` at all and must produce the exact
   same cache behavior. Guard: existing `TestResidency_*` / `TestRcov2Cl_ResidencyDecision`
   suites pass unchanged, plus the new no-store-wired test.
3. **Cache poisoning across tiers**: (a) a store-error fall-through MUST NOT be
   cached (`cacheable=false`) or a transient store outage under-constrains for a
   full TTL; (b) a zero-store-answer fall-through IS cached, so a store `Set`
   arriving later is invisible until TTL — embedders calling `store.Set` must
   also call `InvalidateTenantResidencyCache` (documented in config-reference);
   there is no admin RPC for the policy store in this scope.
4. **Replace-not-merge surprise**: a wired store with a partial policy silently
   overrides tenant-row pins. Mitigated by documentation, but an operator
   migration from tenant-fields to store policies can under-constrain if they
   copy only part of a policy. Consider a follow-up (out of scope): a boot-time
   or admin-surface diff warning.
5. **`memory.Store.Set` signature change**: breaks external SDK embedders that
   call `Set` ignoring a return value — compile-time break, deliberate API
   tightening per the spec; every in-repo caller verified valid. The conformance
   suite locks the new contract.
6. **Regex drift**: the spec's literal regex vs the stricter DNS-label form —
   acceptance cases are identical; the strict form is load-bearing, so the
   regex + length check must live in one place (`validate.go`) and be covered
   by table tests including `a--b`.
7. **Layer gate**: `domains/region` gains a same-layer import of
   `domains/tenant` (precedented by `tokenanomaly`); no `layerExemptions`
   entry may be added — if the gate unexpectedly flags the edge, the fix is
   moving `residencyPolicyFromTenant` back to `interfaces/sso`, not an exemption.
8. **Budgets**: `server_tenant_residency.go` must shrink below 500 (it does,
   net −40); `sso_wiring.go` stays ~452; `config_geo_tenant.go` ~234;
   `build_tenant_geo_region.go` ~290; `domains/region` at 5 non-test files
   (cap 10); subdirs `memory`/`sqlite`/`regiontest` (cap 15); depth 3 for
   `domains/region/sqlite`.
9. **E2E / default-config drift**: empty `policy_store.backend` → `(nil, nil)`
   → option no-ops → `go test ./test/ -run TestE2E -v` unchanged. The
   `wireRegion` signature change (gains `error`) must propagate through
   `wireGeoRegionRisk` — a silent swallow would hide boot failures.
10. **Conformance overreach**: the `regiontest` suite must stay backend-agnostic
    (no sqlite-specific reopen test inside it — persistence-across-reopen lives
    in the sqlite package's own tests; concurrency stress stays in memory's).

## Implementation order and gates

1. `domains/region`: `validate.go` + tests → mandatory gates.
2. `domains/region`: `policyresolve.go` (move `residencyPolicyFromTenant`, add
   `ResolveResidencyPolicy` + tests) → gates.
3. `interfaces/sso`: field + `WithResidencyPolicyStore` in `sso_wiring.go`,
   thin wrapper in `server_tenant_residency.go`, new decision-1 tests →
   `go build ./... && go vet ./...`, `TestMaintainability_|TestArchitecture_`,
   `-race` on the residency suites.
4. `domains/region/memory`: `Set` error return; `domains/region/sqlite` +
   `domains/region/regiontest`; conformance on both → gates.
5. `config` + `serverbuildstore.BuildRegionPolicyStore` + `wireRegion` + build
   tests → gates.
6. `grpcadmin` validation + `InvalidArgument` test → gates.
7. Contract docs (config-reference, feature-matrix, error-codes) in the same
   commits as their code.
8. Full handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
   `make ci`.
