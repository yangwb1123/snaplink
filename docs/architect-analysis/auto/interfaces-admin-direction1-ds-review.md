# Distributed-Systems Review — interfaces/admin Direction 1 (capability language, tenant dimension, delegation grading)

Reviewer role: distributed-systems engineer (`ai-dev/prompts/README.md` baseline). Advisory only; no files modified. Focus: consistency, ordering, atomicity, idempotency, ownership, conflict resolution, dependency outage, replica crash, retry, split-brain, stale reads, clock assumptions, and recovery for the state D1–D3 introduce or touch.

**Checks actually run:** `go build ./...` and `go test -run 'TestMaintainability_|TestArchitecture_' .` pass on the current worktree. All claims below are **Verified** against the files cited unless labeled **Proposed** (design commitment) or **Partial** (verified in one backend only).

**What D1–D3 actually add to the distributed-state surface:** (a) a per-request read chain on the permissions provider (one read today → up to three reads: capability table, catalog `ResolveResource`, `PermissionsForTenant`); (b) a new bootstrap step that seeds catalog entries into the provider; (c) tenant-tagged roles/assignments (new keys, new query); (d) a `RequiredCapability` field on approval records (in-memory store); (e) a subset read (actor + target grants) at break-glass mint time. No new timestamps, leases, TTLs, or quorum requirements are introduced — D1–D3 add no clock dependency.

---

## 1. State map

| State | Owner | Store(s) | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Roles / assignments / permission codes (D1 codes are `Permission.Code` strings; D2 tenant-tagged roles are **Proposed**) | `domains/permissions` | memory · sqlite · postgres · redis (`serverbuildplatform/build_permissions_risk.go:38-69`; `infrastructure/{postgres,redis}/permissions.go` exist) | sqlite/postgres: durable; memory: per-replica, lost on restart | **No cache anywhere on the gate path** — `providerAuthorizer.HasAdminScope` reads `Permissions` per request (`interfaces/admin/middleware.go:50-60`); shared backends give read-your-writes; memory gives per-replica divergence | none — shared DB is one logical copy; memory is N copies that never converge | store outage → gate 500 / gRPC `Internal` (fail-closed, `middleware.go:372-376, 232`); `/readyz` drains the replica (`wireRedis`/`wirePostgres` ready checks, `cmd/sso-server/build_bootstrap.go:139-180, 184-228`) |
| Resource catalog (D1 step 2) | `domains/permissions` — **`MemoryProvider` only** (`memory_resources.go`; 0 `ResolveResource` hits in sqlite/redis/postgres) | memory (bootstrap-seeded, **Proposed**) | per-replica | per-replica deterministic seed (same step, same YAML, every replica runs it at its own boot) | none | re-seeded at each boot; no durability to lose |
| Capability table (D1 step 1, D3 matrix) | `wireAdminMW` construction config (`cmd/sso-server/build_app.go:291-304`); approval matrix in `admingovernance.Registry` | in-memory, per-replica | config-only | identical by construction (same binary + YAML on every replica; no drift path) | none | re-declared at boot; a rolling deploy with mixed binaries sees mixed tables only during the window a replica serves old code — same class as any config rollout |
| Approval records incl. `RequiredCapability` (D3, **Proposed**) | `platform/lifecycle/admingovernance` | `MemoryApprovalStore` (in-process `sync.RWMutex` map, `approval_memory.go`) | **none** — lost on restart, per-replica | atomic **within one process** (mutex: pending-only + self-approval transitions, `approval_memory.go:52-76`); no cross-replica visibility | none | **none** — failover loses pending records; approve on a different replica is 404 |
| Break-glass grants | `core.BreakGlassStore` — `memorystoreidentity.NewMemoryBreakGlassStore` (`cmd/sso-server/build_stores.go:298`) | memory | none | per-replica; mint re-checks grant active under the store lock (`break_glass_impersonate.go:126-137`) | token revocation is cross-replica via the cluster bus (`RevokeToken`, `accessors_feature_gates.go:316+`) | grants vanish on restart; minted impersonation bearers survive only via revocation cascade + TTL |
| Tenant resolution (D2 step 2, **Proposed**) | `domains/tenant` middleware (`server_routes.go:122`) + `SetTenantResolver` wiring | tenant store (memory/sqlite/postgres) | durable (shared backends) | read-per-request | shared store | resolver outage → **fail-open** (design D2 failure table) — see F5 |
| Bootstrap tracker / seed versioning | `platform/bootstrap` (`file.Tracker`, `Runner`) | local JSON file (`bootstrap.json`, `build_bootstrap.go:29-40`) | durable per-replica, atomic-rename writes | per-replica; cluster-wide once-only **only** when `bootstrap.lock.backend: etcd` is configured — default is `noop` (`config.yaml:192-193`, `buildBootstrapLock`) | none by default; opt-in etcd lock with fencing token + heartbeat (`bootstrap.go:143-210`) | crash mid-step → idempotent re-run; lock loss cancels the in-flight step (`ErrLockLost`) |

**Key structural facts (Verified):** the admin middleware wraps **outside** the SSO router's tenant middleware on both HTTP stacks (`wrapAdminAndBuildMux`, `build_http.go:66-90`; the gateway mux is wrapped separately and never traverses the sso router at all, `buildAdminRESTMux` `build_http.go:224-240`), so `tenant.FromHandlerContext` is **not** populated at gate time — D2's `SetTenantResolver` is load-bearing, and the design's own ordering caveat is correct. The gate's provider reads are synchronous, uncached, and fail-closed; there is no stale-allow path.

---

## 2. Findings (severity-sorted)

### F1 — High — D2's tenant dimension is a no-op on the stock *production* backend: `permissions.backend: postgres`
**Evidence (Verified):** `ops/deploy/kustomize/overlays/prod/config.yaml:68` = `permissions: { enabled: true, backend: postgres }`. `infrastructure/postgres/permissions.go` and `infrastructure/redis/permissions.go` are first-party conformance-suite providers. The design (D2 storage model) mandates `TenantPermissionsProvider` only for `MemoryProvider` and the sqlite backend; non-implementing providers are discussed as a third-party skip case.
**Triggering failure:** a tenant-scoped acme grant is created through the optional administration methods; production requests for `POST /api/v1/admin/tenants/acme/export` and `/globex/export` both pass — no tenant check, exactly today's behavior.
**User impact:** the flagship D2 isolation promise silently does not exist in the shipped production configuration; the acceptance matrix (memory) passes while deployed behavior is unchanged. It is a *default-widening gap*: the feature is accepted on memory, shipped on postgres.
**Recovery:** none needed (no wrong denials — it is a missing control, not a broken one); the risk is a false sense of isolation.
**Corrective pattern:** either (a) scope D2 explicitly to memory+sqlite and **fail loud at boot** when the tenant dimension is configured alongside `backend: postgres|redis` (mirroring `enforceHACoherence`'s posture), or (b) add the tenant dimension to postgres (additive `permissions_roles.tenant_id` migration — the versioned-migration machinery exists, `infrastructure/postgres/permissions.go:13-34`; the architect's M-2 already flags the sqlite migration) and redis in the same change. Do not ship a security dimension that production topology silently skips.
**Validation:** boot with `permissions.backend: postgres`, create a tenant-tagged grant via `AddTenantRole`, call the globex export with that grant — today: 200 (no check). Pin as a known-unsupported test or gate it.

### F2 — High — Multi-replica coherence check omits the permissions provider: memory-backend role writes silently diverge per replica
**Evidence (Verified):** `haCoherenceIssues` (`cmd/sso-server/build_stores.go:107-135`) covers oauth, sessions, jti_replay, ciba, identity, mfa, identity_link, pairwise — **not `permissions.backend`**. `wirePermissions` logs "memory (single-replica only)" but nothing fails loud in a declared multi-replica topology. `PermissionAdminService.AddRole/AssignRoles` (`interfaces/grpcserver/grpcadmin/admin_permissions.go:79-95,167-179`) write the local provider. The gate reads per request (`middleware.go:50-60`).
**Triggering failure:** LB sends `AssignRoles` to replica A (memory); the next admin request lands on replica B → 403 `forbidden`. The failure comes and goes with routing — the worst class of intermittent authorization bug.
**User impact:** D2 makes this worse, not better: `AddTenantRole`/`AssignTenantRoles` are new per-replica writes, and the D1 catalog bootstrap step also seeds per-replica. Read-your-writes is violated whenever the client's requests and the mutation land on different replicas.
**Recovery:** re-issue the mutation until it hits the same replica; reboot re-seeds YAML roles but not runtime mutations.
**Corrective pattern:** add `permissions.backend` to `haCoherenceIssues` (memory → per-pod critical) so declared multi-replica topologies fail loud, exactly like the other critical stores; document runtime role mutations as shared-backend-only. This is a 3-line change in `cmd/sso-server/build_stores.go`.
**Validation:** `topology.mode: multi` + `permissions.backend: memory` → expect boot error, currently get none.

### F3 — High — The D1 catalog-seed bootstrap step must be an idempotent upsert; nothing today guarantees cluster-wide once-only
**Evidence (Verified):** tracker is a per-replica local file (`bootstrap.json`); default `bootstrap.lock.backend: noop` = nil lock = unlocked Runner (`build_bootstrap.go:132-171`; `bootstrap.go:200-214`); prod overlay does not configure the lock. Existing steps tolerate re-runs by sentinel (`stepSeedAdminRole` treats `ErrRoleExists` as success, `builtin.go:149-165`). `MemoryProvider.RegisterResource` is "insert or update" (`memory_resources.go:17-22`), but there is **no sqlite/postgres `ResourceProvider` at all** (F1's sibling), so the durable-backend seed path is undefined today.
**Triggering failure:** N replicas boot concurrently against one shared sqlite store with a create-only catalog seed step: replica A inserts, B..N get a uniqueness conflict → **boot failure** on every first boot (the tracker is per-replica, so no replica sees another's applied version). A create-only step is a first-boot deadlock in any multi-replica rollout.
**User impact:** rollout wedges; operator must hand-clean rows. With an upsert step, the same race is harmless (last-writer-wins on identical rows).
**Recovery:** none automatic — manual row cleanup, or the step is made idempotent.
**Corrective pattern:** the seed step must be **idempotent-upsert** (mirror `stepSeedAdminRole`'s sentinel discipline and the YAML seeder's `ErrRoleExists → UpdateRole` pattern, `build_permissions_risk.go:112-133`), and the design must state the concurrency contract: per-replica tracker + noop lock means "at least once per replica, exactly-once is not guaranteed cluster-wide" — the step must tolerate concurrent execution on a shared store. Also note the YAML seeder (`seedPermissions`) runs at **provider construction, outside the bootstrap lock entirely**; concurrent boots during a rolling config change can flap role definitions via `UpdateRole` last-writer-wins (pre-existing; D1's seed step inherits the exposure).
**Validation:** two replicas, shared sqlite, concurrent first boots with an upsert seed step → both succeed; with a create-only step → one wedges.

### F4 — Medium — D3's approval workflow is single-replica by construction; `RequiredCapability` inherits the ceiling, and Approve→Apply→MarkApplied is not crash-atomic
**Evidence (Verified):** `MemoryApprovalStore` is in-process; stock wiring registers no `Applier` (book-keeping only, `build_stores.go:308`); `ApproveAndApply` = `store.Approve` → `reg.Lookup` → `fn(ctx, payload)` → `MarkApplied`/`MarkFailed` (`approval.go:141-160`). D3 adds a capability check before `store.Approve` (**Proposed**).
**Triggering failure:** propose on replica A, approve routed to replica B → 404 `ErrChangeNotFound` (no cross-replica visibility). Replica A crashes with pending records → records gone (two-person workflow state is single-point-of-failure). Crash between `Approve` and `MarkApplied` → mutation applied (or not) with the record stuck `approved` — moot today because the record dies with the process, but the ordering is the exact shape a future durable store must fix.
**User impact:** approvals are unreliable under any LB without sticky routing; compliance-grade approval trails are not persistable (already documented by the database review F4).
**Recovery:** re-propose on the surviving replica; no data migration exists.
**Corrective pattern:** state the single-replica ceiling in the D3 contract (the design already says "none survive restart" — make the multi-replica 404 behavior an explicit documented topology, and pin it with a test). For any future durable `ApprovalStore`: the `Approve` transition must remain the atomic authority (it is), and the Applier must be **idempotent** so a crash-between-approve-and-marked re-run cannot double-apply. The design's "carried `RequiredCapability` frozen at propose" is the right consistency choice (decision-time bar cannot drift with registry changes) — keep it.
**Validation:** propose on replica A, approve on B → 404 (documents the topology); double-submit approve on one replica → one success + `ErrChangeNotPending` (already atomic via mutex).

### F5 — Medium — D2's resolver-outage fail-open is a cluster-wide isolation-widening window with no bound
**Evidence (Verified / Proposed):** the design's D2 failure table: resolver error → "log + audit, treat as unresolved, skip the tenant check". The tenant resolver depends on the tenant store / routing context — a shared dependency, so the outage hits **every replica simultaneously**, and the fail-open then applies cluster-wide: a tenant-scoped acme grant acts globally (union semantics + skipped check) until the store recovers.
**Triggering failure:** tenant store partition; a tenant-scoped grant holder calls `/api/v1/admin/users/:id/password` for a globex user — allowed during the window.
**User impact:** tenant isolation silently widens for the outage duration; the audit trail records events but nothing bounds or signals the window (no degraded flag, no rate-based tripwire). This is the security review's H3 restated in availability terms: the decision is a consistency-vs-availability trade-off that needs an owner.
**Recovery:** store recovery restores the check; the widening window is unbounded by any mechanism.
**Corrective pattern:** either fail-closed when a tenant dimension is configured (resolve failure → deny), or bound the window with a per-replica degraded flag (the invalidation-bus degraded-readiness pattern, `server_extensions.go` / `flushInvalidationCaches`, is the in-repo precedent for "degraded until re-seeded"), or accept fail-open with a documented maximum window and an explicit owner sign-off (design open question — take the principal reviewer's H3 path).
**Validation:** inject resolver failure; assert fail-open + audit event; then assert the chosen bound (deny or degraded flag) engages.

### F6 — Medium — The gate's per-request read amplification triples the shared-store dependency of every admin call
**Evidence (Verified / Proposed):** today one `Permissions` read per gated request; D1 adds `ResolveResource` and D2 adds `PermissionsForTenant` on the same provider, synchronously, uncached. With sqlite cluster-shared (single writer, `busy_timeout`), a degraded shared store turns gate latency into 500s — the design's fail-closed posture is correct but makes every new read a new availability coupling. Admin surface is low-QPS, so this is bounded; it is not a defect.
**Corrective pattern:** serve the catalog step from the per-replica in-memory capability table (the design's step 1) on a miss-based fallthrough, so the shared-store catalog read fires only for entries the static table does not declare — this is the natural v1 bound and matches the resolution chain's intent. State the read budget (≤3 provider reads, no cache, no stale-allow) in the design.
**Validation:** benchmark the gate with the catalog miss path under store degradation (no new load test exists in-tree — mark as unknown).

### F7 — Low — Read-read races between the gate and break-glass mint are safe-by-direction; pin them
**Evidence (Verified):** the gate authorizes the actor (read 1); `refuseTargetPrivileged` → `CanImpersonate` re-reads actor+target grants (read 2); `AttachImpersonationToken` re-checks grant liveness under the store lock (`break_glass_impersonate.go:126-137`). A revocation between reads fails the mint (403) — safe; a concurrent grant cannot widen (the mint reads current state). The D3 subset change preserves both directions.
**Corrective pattern:** one comment + one test (revoke target role between gate and mint → 403, never a minted credential). No code change needed.

### F8 — Info — D1–D3 introduce no clock dependence; the only lease in play is the bootstrap lock
**Verified:** no new timestamps/TTLs/leases in D1–D3. `ChangeRequest.CreatedAt/DecidedAt` are local `time.Now()` values used for display/sort only. The bootstrap lock (30 s TTL, heartbeat at TTL/3, fencing token, lock-loss cancels the in-flight step — `bootstrap.go:143-210`) is the only time-based coordination D1's seed step touches, and it is opt-in. The pre-existing admin idle-timeout (`time.Since(meta.LastUsedAt)`, `middleware.go:387-405`) uses per-replica clocks against a shared token store — unchanged, out of scope, but note it: multi-replica clock skew shifts idle expiry by the skew delta (no security impact — skew only makes expiry earlier or later, never weaker than TTL on the token itself).

---

## 3. Scenario table

| Scenario | Behavior (today / as designed) | Verdict | Recovery |
|---|---|---|---|
| **Partition: permissions store unreachable** | Gate read errors → 500 `internal_error` / gRPC `Internal` (`middleware.go:372-376`); no allow-on-error. `/readyz` drain (2 s ping) removes the replica from the LB; `/livez` stays 200. | Correct fail-closed; admin surface unavailable for the partition — accepted and documented. | Store recovery → ready check clears → LB re-admits; no state to repair. |
| **Partition: tenant store unreachable (D2 resolver)** | Fail-open with audit per the design (F5). | **Needs owner decision** — cluster-wide isolation widening with no bound. | Store recovery restores the check; events remain in audit. |
| **Replica crash mid-bootstrap (D1 seed step)** | Per-replica tracker: step re-runs on next boot; must be idempotent (F3). Existing steps tolerate by sentinel. | Correct **iff** the new step is upsert; a create-only step wedges first boot. | Idempotent re-run; no manual cleanup. |
| **Replica crash mid-approval (D3)** | Pending record lost (memory store); approve-before-MarkApplied window loses the outcome. | Accepted ceiling, must be documented as single-replica (F4). | Re-propose; no migration to unwind. |
| **Retry: double-submit approve, same replica** | Mutex-serialized `Approve`: second call → `ErrChangeNotPending` (409). | Atomic, idempotent-per-record. | None needed. |
| **Retry: approve on a different replica** | 404 `ErrChangeNotFound` (per-replica memory). | Not idempotent cross-replica; document topology (F4). | Re-route to the proposing replica or re-propose. |
| **Retry: concurrent boots, shared sqlite, noop lock** | Both replicas run the seed step; sentinel/upsert makes it benign (F3). | Correct with upsert; exactly-once is never promised. | None. |
| **Clock rollback** | No D1–D3 decision depends on time. Approve `CreatedAt` sort only; bootstrap lock is lease-based with fencing token (opt-in). | No impact. | None. |
| **Stale cache** | No cache on the gate path — reads are per-request (F6). Discovery/`embed_in_login` caches are outside this path. | No stale-allow exists. | N/A. |
| **Split-brain** | No quorum-requiring state introduced. Memory-backend permissions is N diverging copies (F2) — the only "brain split" in scope; shared backends are single-logical-copy. | F2 corrective (coherence check) is the fix. | Re-seed/re-apply mutations on the shared backend. |
| **Dependency outage: invalidation bus** | Revocation/dedicated events best-effort; recovery re-subscribes + flushes caches + re-seeds deny-sets before clearing degraded readiness (AGENTS.md §3). Unchanged by D1–D3; no permission cache exists to flush. | Correct; D1–D3 add nothing to the bus. | Existing recovery path. |
| **Rolling deploy, mixed binaries** | Capability table / approval matrix are per-replica construction config; during rollout, replicas enforce their own binary's table. Legacy fallbacks make D1 additive (no holder is denied), so the mixed window is behavior-preserving. | Correct **iff** the fallback set is complete — the design's own #1 regression risk. | Full rollout converges; E2E + `admin:write` matrix is the guard. |

---

## 4. Stated guarantees, unsupported topologies, validation, residual risks

**Guarantees D1–D3 can honestly state:**
- The gate is fail-closed on provider error; there is no allow-on-error and no stale-allow (no cache in the read chain).
- On shared backends (sqlite/postgres), the gate is read-your-writes: every decision is a fresh read of the single logical copy.
- Approval transitions are atomic per process (mutex; pending-only; self-approval authoritative); a refused approval never transitions the record *on the replica that holds it*.
- Seeding steps are at-least-once per replica; cluster-wide once-only only with the opt-in etcd bootstrap lock; every step must be idempotent-upsert on shared stores.
- D1–D3 add no clock, lease, fencing, or quorum requirements; the only lease in play is the pre-existing opt-in bootstrap lock.
- No permission cache is introduced, so the invalidation-bus recovery machinery needs no extension for D1–D3 (verify this stays true if a cache is ever added — then `flushInvalidationCaches` must gain a permissions flush).

**Unsupported topologies (must be stated in the design, not discovered mid-flight):**
- `permissions.backend: memory` behind a load balancer: role mutations diverge per replica (F2). Today this is a log line, not a gate.
- D2 tenant dimension on `backend: postgres` (the stock prod overlay) and `backend: redis`: unimplemented — D2 is a no-op there (F1).
- Approval workflow across replicas or across restarts: single-replica, non-durable (F4).
- Cluster-wide exactly-once seeding without `bootstrap.lock.backend: etcd`.

**Executable validation tests to add (per AGENTS.md §5, beside the code):**
1. Two-replica concurrent first boot, shared sqlite, D1 catalog seed step → both succeed; assert catalog idempotency (F3).
2. `topology.mode: multi` + `permissions.backend: memory` → boot error after the F2 corrective; today: none.
3. Postgres backend + tenant-tagged grant → globex export 200 today; pin as known-unsupported or gate (F1).
4. Propose on replica A / approve on B → 404 (documented topology pin); same-replica double-approve → one success + 409 (F4).
5. Revoke target role between gate and mint → mint 403, never a credential (F7).
6. Tenant-resolver outage injection → fail-open + audit event; then the chosen bound (deny or degraded flag) once F5 is decided.
7. Gate read budget: assert ≤3 provider reads per request and no cache path (F6) — a unit-level instrumentation test.

**Residual risks (accepted or owner-pending):**
- F5's isolation-widening window is unbounded until the owner decision lands (fail-closed / degraded-flag / accepted-with-audit).
- Rolling config changes can briefly flap YAML-seeded role definitions on shared backends (pre-existing `UpdateRole` last-writer-wins during concurrent boots; D1's seed step inherits it).
- The approval workflow's compliance story is single-replica book-keeping until a durable store exists (database review F4 is the companion finding; the crash-atomicity shape for a future durable store is specified in F4 above).
- Admin idle-timeout under multi-replica clock skew is a pre-existing, out-of-scope skew delta (F8).

**Bottom line:** D1–D3 are distributed-systems-safe in their core decisions — no caching (hence no stale-allow), fail-closed provider reads, atomic per-process approval transitions, additive legacy fallbacks that make the mixed-binary rollout window behavior-preserving, and no new clock/lease/quorum dependence. The two High items are scope-completeness gaps, not design flaws: the tenant dimension missing from the **stock production backend** (F1) and the permissions provider missing from the multi-replica coherence gate (F2), plus one idempotency contract the new bootstrap step must honor (F3). Fixes are small, localized in `cmd/sso-server` + one backend migration, and none touch the wire contracts.
