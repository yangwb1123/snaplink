# Requirements Spec: Threat-action policy storage + rate-limit persistence and multi-replica consistency

> Expansion direction 1 of `docs/auto/domains-threataction-analysis.md`:
> "策略存储与限流的持久化、多副本一致性（接线已存在但无人使用的 SQLite store）".
> Scope: `domains/threataction`, `cmd/sso-server/serverbuildplatform/build_governance.go`,
> `cmd/sso-server/anomaly.go`, `config`, `docs/config-reference.md`.
> Each decision below is one independent, evidence-backed improvement.

## 1. Backend selection: wire the dormant SQLite ThreatPolicyStore into `BuildThreatAction` behind `threat_action.backend`

**Name**: Durable policy backend selection (`memory|sqlite`) for the threat-response policy store.

**Problem**: Threat-response policies are a security control plane, yet the
composite executor is hardwired to an in-process memory store. Admin CRUD
mutations (PUT/DELETE `/api/v1/admin/threat-policies`) are silently lost on
restart, and in multi-replica deployments each replica evaluates against its
own private policy view — the same threat can hit `suspend` on replica A and
`noop` on replica B. The durable backend already exists, is fully tested, and
is dead code.

**Evidence**:
- `domains/threataction/sqlite/policy_store.go` — complete `ThreatPolicyStore`
  (`List/Get/Put/Delete` + `migrate` + `Ping`/`DB`/`Close`), package doc:
  "the multi-replica durable peer of threataction/memory.ThreatPolicyStore…
  persists them so a threat-response policy list survives a redeploy and is
  shared across replicas pointed at the same database file". Zero importers
  repo-wide (`grep -rln "threataction/sqlite" --include="*.go"` outside the
  package returns only a doc-comment mention in
  `domains/tokenexchange/sqlite/chain_store.go`); 6 passing tests in
  `policy_store_test.go` exercise only the package itself.
- `cmd/sso-server/serverbuildplatform/build_governance.go` `BuildThreatAction`
  — unconditional `store := threatactionmemory.NewThreatPolicyStore()`, no
  backend switch, no DSN.
- `config/config_snapshot.go` `ThreatActionConfig` — fields are only
  `Enabled`, `DefaultAction`, `Policies`; no `Backend`/`Sqlite` knob exists.
- Precedent to mirror: `BuildConfigAuditStore` (same file, `backend` switch
  over `memory|sqlite` with fail-loud "dsn required" error) and
  `buildTenantStoreBackend` (`cmd/sso-server/serverbuildstore/build_stores_helpers.go`,
  logs the selected backend: "tenant store: sqlite (cluster-shared)").

**Proposed behavior**:
- Add `threat_action.backend` (`memory` default | `sqlite`) and
  `threat_action.sqlite.dsn` to `ThreatActionConfig`, following the
  `ConfigAuditConfig`/`TenantConfig` shape.
- In `BuildThreatAction`, select the store: empty/`memory` → current
  `threatactionmemory.NewThreatPolicyStore()` (byte-identical default);
  `sqlite` → `threatactionsqlite.New(dsn)`, failing loud at boot when `dsn`
  is empty or the store cannot open/migrate; unknown backend → boot error
  listing supported values.
- Wire the sqlite handle's lifecycle like `anomalyRuntime` does
  (`cmd/sso-server/anomaly.go` `openAnomalyStores`/`close`): close the store
  at shutdown, register `sso.WithReadyCheck` via the existing
  `ThreatPolicyStore.Ping` (documented for exactly this purpose in
  `sqlite/policy_store.go`).
- Update `docs/config-reference.md` (`threat_action.backend`,
  `threat_action.sqlite.dsn`) and the `threat_action.enabled` row that
  currently promises an "in-memory ThreatPolicyStore".

**Acceptance check**:
- `go build ./... && go vet ./...` pass; a unit test on `BuildThreatAction`
  with `threat_action.backend=sqlite` + temp-DSN returns an executor whose
  policy store `List`s the seeded policies and whose `Put` survives
  `Close` + re-open of the same DSN; `backend=sqlite` without DSN returns a
  boot error; unknown backend returns an error; empty backend is
  byte-identical to today (existing `build_governance_test.go` cases pass
  unmodified).
- `docs/config-reference.md` documents both new keys; `make ci` passes.

## 2. Seed-once boot semantics: YAML seeds must not clobber admin-authored policies on restart

**Name**: Bootstrap seeds apply only to an empty store; runtime-admin state is authoritative.

**Problem**: The naive wiring of improvement 1 would keep the current
unconditional re-seed loop, which is correct for memory (seeds are the only
source) but wrong for a durable backend: every restart would overwrite
admin-authored runtime policies with the YAML seed values — a silent rollback
of a security control with no error, audit event, or log. The documented
contract already promises runtime edits survive; persistence must honor it.

**Evidence**:
- `cmd/sso-server/serverbuildplatform/build_governance.go` `BuildThreatAction`
  — `for _, p := range cfg.Policies { store.Put(context.Background(), p) }`
  runs unconditionally at every boot, no emptiness check, no seed-tracking.
- `config/config_snapshot.go` `ThreatActionConfig.Policies` — "seeds the
  in-memory ThreatPolicyStore at boot; further policies can be added/edited
  at runtime via the admin CRUD API" (i.e., the config comment itself asserts
  a coexistence contract the unconditional reseed breaks once the store is
  durable).
- `domains/threataction/admin.go` `HandleAdminPutPolicy`/`HandleAdminDeletePolicy`
  — runtime mutations target the same store instance the executor reads; with
  the sqlite backend these are the durable source of truth and must win over
  stale YAML on the next boot.
- `domains/threataction/memory/policy_store.go` package doc — "loses every
  admin-authored policy on restart", which is precisely the failure the
  durable backend exists to remove, not to re-introduce at seed time.

**Proposed behavior**:
- In `BuildThreatAction`, seed `cfg.Policies` only when the selected store
  is empty (`List` returns zero policies) — i.e., YAML is a bootstrap
  default for a fresh database, never an overwrite of live state. Explicitly
  reject (fail loud) a config that mixes `backend=sqlite` with the intent of
  re-applying seeds (e.g., no new knob; document the empty-store rule).
- Log the seed decision: `n` policies seeded vs `m` existing policies left
  untouched, at boot, so the operator can see whether YAML applied.
- Keep deterministic ordering: both backends already `ORDER BY name`/sort by
  name, so first-match-wins evaluation order is unaffected.
- Update the `ThreatActionConfig.Policies` comment and
  `docs/config-reference.md` to state the seed-once contract.

**Acceptance check**:
- New test: sqlite backend store; boot-seed with 2 policies; `Put` an
  edited version of one policy (simulating admin CRUD); "restart" (new
  `sqlite.New` on the same DSN, same seed config); assert the admin-edited
  value survives and the other seed policy is present — no overwrite.
- Memory backend keeps today's behavior (seeds always applied), verified by
  existing tests.
- Boot log line asserts seed/keep counts; `go build ./... && go vet ./...`
  and `make ci` pass.

## 3. Cross-replica rate limiting: shared window for the durable backend, explicit config for the split

**Name**: Rate-limit state must not be per-replica when policies are cluster-shared.

**Problem**: The rate limiter is process-local state, so a multi-replica
deployment multiplies the effective budget by the replica count: an attacker
rotating subjects/replicas gets `N × Max` actions per window instead of
`Max`, and the window resets per replica. This contradicts the direction's
"多副本一致性" and turns a documented security control
(`RateLimitPolicy`, AGENTS.md §3) into a deployment-dependent one. The sqlite
backend (improvement 1) shares policies but not limit state.

**Evidence**:
- `domains/threataction/registry.go` — `ThreatExecutors.rateLimit
  map[string]*rateLimitEntry` guarded by `te.mu`; `allow()` creates/replaces
  entries and `rateLimitSweepThreshold`/`evictExpiredLocked` bound the map —
  all strictly in-process; nothing reads or writes shared state.
- `domains/threataction/sqlite/policy_store.go` — the schema contains only
  `threat_policies`; no table or type exists for rate-limit counters, so the
  durable backend as built cannot hold shared limiter state.
- `domains/threataction/threataction.go`/`policy.go` — `RateLimitKey`,
  `RateLimitPolicy{Max, PerWindow}` define the tuple `(subject, type, action)`
  and window semantics that a shared limiter must preserve identically.
- `cmd/sso-server/anomaly.go` `wireThreatAction` doc — "one shared instance,
  one rate-limiter, one policy view for both detection sources": the
  single-instance guarantee is explicit and would be silently violated by
  N replicas with N limiters.

**Proposed behavior**:
- Add a shared limiter backend selected by the same `threat_action.backend`
  switch (memory default, byte-identical today):
  - `memory` — current map + sweep behavior, unchanged.
  - `sqlite` — a `threat_rate_limits` table keyed by
    `(subject, type, action, window_start)`, mutated with atomic
    upsert/increment under the SQLite writer lock so concurrent replicas
    sharing the DSN file serialize on one window; expiry via window_start
    comparison (reusing the same "replace if expired" logic as `allow()`).
- Keep the fail-open contract: a limiter-store error must log and allow
  (never block the action path), matching `allow()`'s current posture.
- Document in `docs/config-reference.md` the consistency semantics: sqlite
  backend ⇒ cluster-shared window; memory backend ⇒ per-replica window
  (explicitly labeled as such, with the budget-multiplication caveat).

**Acceptance check**:
- New test: two `ThreatExecutors` instances (simulating two replicas) over
  one shared DSN file and one shared sqlite store; fire `Max` matching
  threats from replica A, then one from replica B within the window — B's
  action is rate-limited (`ActionResult{OK:false, Detail:"rate-limited"}`);
  after the window elapses (short `PerWindow`), a fresh threat passes.
- Memory-backend path keeps existing `registry_test.go`/`actions_test.go`
  rate-limit expectations unmodified; limiter-store failure injection logs
  and proceeds (fail-open).
- `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`, and `make ci` pass; `docs/config-reference.md` updated.
