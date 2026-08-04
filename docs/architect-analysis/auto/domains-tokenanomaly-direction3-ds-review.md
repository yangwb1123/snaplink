# Distributed-Systems Review — `domains/tokenanomaly` Direction 3 design (FamilyID chain + windowed rate_spike)

**Review target:** `docs/auto/domains-tokenanomaly-direction3-design.md` (+ spec), against current handlers, stores, cluster bus, and sweep wiring.
**Checks that actually ran:** static verification only — full-file reads of `domains/tokenanomaly/{detector,detect,tokenanomaly,admin}.go`, `domains/tokenanomaly/memory/store.go`, `domains/threataction/{actions,registry,policy,threataction}.go`, `domains/metering/{token_recorder,token_usage}.go`, `domains/metering/memory/token_store.go`, `domains/metering/sqlite/aggregator.go`, `protocols/oauth/{handle_introspect,oauthspi/refresh_token}.go`, `infrastructure/{redis/refresh_token.go,defaultimpl/memorystoreoauth/memory_refresh_token.go,defaultimpl/sqlite/refresh_tokens.go}`, `platform/cluster/bus.go`, `internal/handler/cross_replica.go`, `interfaces/sso/server_invalidation.go`, `cmd/sso-server/{build_app_security.go,serverbuildplatform/build_governance.go}`, `config/config_snapshot.go`; plus `rg`/`sed` symbol scans and `git log`/`git status`. No `.go` file changed by this review, so no Go gate ran on the proposal itself (matching the design's own claim). Worktree carries a large unrelated WIP diff; all citations below were taken from the current tree at `35dee544`.

Scope discipline: the design changes no wire contract and no grant decision; this review focuses on consistency, ordering, atomicity, idempotency, ownership, conflict resolution, crash/partition/retry behavior, clock assumptions, and the fail-open/fail-closed boundary of the detection→response chain.

## 1. State map — owner, store, durability, consistency, replication, failover

| State | Owner | Store | Durability | Consistency / ordering | Replication | Failover |
|---|---|---|---|---|---|---|
| Recorder queue (`metering.Recorder`, default 1024) | request-path handlers via `Offer` | in-process channel | none | FIFO per drainer; drop-on-full (`token_recorder.go:147-158`) | per-replica (one recorder per `sso.Server`) | n/a — ephemeral; drops are the load-shedding contract |
| Bucket store (`tokenusagememory.Store`) | recorder drain goroutine (single writer) | in-process map under `s.mu` | none | upsert per (minute, client, kind, endpoint); eviction insertion-order | per-replica — **Verified: only `domains/metering/memory/token_store.go` implements `metering.Store` for `Record`**; `metering/sqlite` is a read-only `Aggregator` over `audit_events` | n/a — cannot fail in stock build |
| Observation table (`Detector.obs` + `order`) | drain goroutine via `recordObservation` (`detector.go:254-271`) | in-process map under `d.mu` | none | per-thumbprint fold; cap 4096, insertion-order eviction | per-replica | n/a |
| **`subjectMinuteRates` (NEW)** | drain goroutine fold (design D4) | in-process map under `d.mu` | none | per-(subject,client) per-minute; cap `WithMaxTrackedSubjects` (4096), oldest-minute eviction + sweep pruning | per-replica | n/a |
| Finding store (`tokenanomalymemory.FindingStore`) | `Analyze` sweep (`processFinding`) | in-process map under `s.mu` | none | upsert by `DedupKey`; `mergeFinding` = earliest FirstSeen, latest LastSeen, severity escalates, fresher Count/Geos/Detail/FamilyID (`memory/store.go:69-87`); cap 1024 | per-replica | n/a |
| Threat policy store | admin CRUD / boot seed | in-memory (`build_governance.go:326`) | none | first-match by name; rate-limit keyed (subject, type, action) (`registry.go:187-191`) | per-replica — no bus invalidation for policy edits | n/a (pre-existing, out of design scope) |
| Refresh-token store (the revoke target) | grant handlers (Consume/Issue), revoke handlers, `RevokeFamilyExecutor` | memory (per-process) / redis / sqlite (shared) | redis/sqlite durable; memory none | `Consume` atomic single-use (redis GETDEL `refresh_token.go:229-260`; memory single mutex `memory_refresh_token.go:161-195`; sqlite per AGENTS.md `DELETE RETURNING`); `DeleteFamily`/`DeleteAllForSubject` idempotent | shared in production → a local revoke is cluster-wide **by store sharing**, not by bus | outage ⇒ revoke fails open, retried at sweep cadence while the signal persists (F2) |
| Access-token revocation deny-sets (per-issuer, in-process) | local revoke paths + `ApplyTokenRevocation` | in-process `revoked` maps | re-seeded from durable `RevocationStore` at boot and on bus recovery | additive/idempotent | cross-replica via `KindTokenRevoked` carrying `MetaRevokedToken` (`cross_replica.go:74-108`) | lost event ⇒ token honored until exp (TTL-free target, hence the reseed) |
| Cluster bus | `StartInvalidationBus` subscriber loop | etcd / memory | replay buffer (etcd), best-effort | no delivery/ordering guarantees; idempotent apply | fan-out to all replicas | self-heal: degraded → backoff (1–30 s, jittered) → resubscribe → flush caches + re-seed deny-sets → clear degraded (`server_invalidation.go:114-196`; `resubscribeAndReseed` ordering is load-bearing) |
| Audit events | `audit.Recorder` | durable sink | yes | fail-open | n/a | sink errors fail open (AGENTS.md) |

**Ownership summary.** Everything the design adds is *detector-local in-process state* (subject table, family field on observations) or *fields on already-local records* (Event/Finding/Threat). The only shared, durable state in the chain is the refresh-token store (production: redis/sqlite) and the bus; the design's revoke path writes the former and publishes to the latter. No new ownership domain, no new cross-replica state, no migration.

**Consistency model.** Detection is per-replica and sharded by request locality (F1); findings are never merged across replicas; the admin API is a per-replica view. Revocation is at-least-once and idempotent against shared state; ordering between the grant path (reuse kill) and the ITDR path (sweep revoke) is unspecified but irrelevant because both converge on idempotent `DeleteFamily`. The fail-open/fail-closed boundary is preserved exactly: grant-path reuse kill is synchronous and fail-closed; every detection/response hop is fail-open (F2).

## 2. Findings

### F1 — Medium · Family precision is gated on request locality, not just introspection traffic

- **Evidence (Verified):** the detector's observation table is fed only by this replica's recorder drain (`BuildTokenAnomaly` always wraps the in-process memory store, `build_governance.go:359-381`; the recorder is per-`Server`). Direction-1's design already documents the consequence ("a load-balanced fleet where replica A sees country X and replica B sees country Y never combines the evidence", `domains-tokenanomaly-direction1-design.md:411-418`). Direction-3's Decision 2 claim — "the observation row for a lineage learns the family the first time a refresh token of that family is introspected" — and the subject-burst signal both silently assume one detector sees the whole chain.
- **Triggering failure:** introspection of the family's leaf lands on replica B while the geo/velocity observations for that thumbprint are on replica A. A's finding stays `FamilyID == ""` and the executor takes the subject-wide `DeleteAllForSubject` fallback — the exact self-inflicted DoS the direction exists to fix, despite introspection traffic being present.
- **Impact:** the family precision improvement is doubly gated: introspection traffic (protocol F1 / security F1) **and** request locality. In an N-replica fleet each thumbprint-bearing introspect has ~1/N chance of landing on the replica holding the observation; over a window with repeated probes it converges probabilistically, never deterministically.
- **Recovery:** none automatic — the fallback fires (safe, broad). A later introspection on the obs-holding replica corrects the finding, but the revoke already fired subject-wide.
- **Corrective pattern:** the design should add one paragraph stating the per-replica sharding of observations/subject-rates/findings and that the family precision is fleet-probabilistic; a fleet-wide view is explicitly out of scope (direction-2 territory, `domains-tokenanomaly-direction2-*`). No code change required for this direction; the negative E2E (protocol F1) plus this paragraph suffice.

### F2 — Medium · Revoke delivery is at-most-once per finding lifetime with no durability; an outage that outlives the window permanently loses the revoke

- **Evidence (Verified):** `Analyze` dispatches only findings the sweep *re-detects* (`processFinding` → `dispatchThreat`, `detector.go:385-430`); geo/velocity findings stop re-emitting once `o.last` ages past `now - window` (`detect.go:24-36`), and rate_spike stops once the burst minute leaves the window. `RevokeFamilyExecutor.Execute` returns store errors (`actions.go:158-177`) which `dispatchThreat` only logs. There is no durable intent log, no replay, no finding-state-based re-dispatch, and no admin "re-run finding" surface.
- **Triggering failure:** refresh-store outage (or detector crash) longer than the finding's remaining window. The attacker keeps rotating during the outage; when the store/sweep returns, the finding is no longer emitted and the revoke never fires. Only the grant-path reuse kill (fail-closed, unchanged) or natural expiry stops the attacker.
- **Impact:** bounded but real availability gap in the *response* half; consistent with the documented fail-open boundary, but the design's failure-mode section does not state the delivery guarantee precisely.
- **Recovery:** none automatic for a missed revoke; the grant path remains the backstop.
- **Corrective pattern:** (a) document the guarantee ("best-effort, at-most-once with retry-while-signal-persists at sweep cadence; no durability"); (b) when the dispatch-gating decision (principal review M6) lands, gate on state transition (FirstSeen/LastSeen advance), never on key existence — key-existence gating would also suppress the retry after a *transient* executor failure, turning this gap from "outage-length window" into "one failed call". A unit test should pin re-dispatch after one executor failure (see §4, test 5).

### F3 — Medium (doc/claims) · The executor's `KindTokenRevoked` bus event has no receiver arm — publish-only, and the design's "receiver-side dedup" phrasing implies a receiver that does not exist

- **Evidence (Verified):** `publishRevoked` (`actions.go:184-200`) publishes `KindTokenRevoked` with `Key: FamilyID` (or SubjectID) and payload `threat_action/threat_type/subject_id` — **no `revoked_token` key**. The only receiver arm, `applyInvalidation` → `applyTokenRevocation` → `handler.ApplyTokenRevocation` (`server_invalidation.go:327-328`; `cross_replica.go:98-108`), requires `Payload[MetaRevokedToken]` and returns early on empty — so every executor event is dropped at the receiver. `KindSessionSuspended`'s arm is likewise empty (`applySessionSuspension`). The actual convergence mechanism is the **shared refresh store** (redis/sqlite), not the bus.
- **Triggering failure:** an operator or future implementer reads the design's Decision 3 / failure-mode text ("the `KindTokenRevoked` bus event keyed by FamilyID … receiver-side dedup") as a cross-replica propagation guarantee for refresh families.
- **Impact:** none in supported topologies — a local `DeleteFamily` on a shared store is already cluster-wide; in the unsupported per-replica-memory-store multi-replica topology the revoke would not propagate. The real risk is the EventKind overload: `KindTokenRevoked` now carries two incompatible payload shapes (access-token deny-set vs. threat-action family key). A future arm written for one shape silently misbehaves on the other; today's default arm drops unknown payloads gracefully, so this is a latent mixed-version trap, not a live bug.
- **Corrective pattern:** restate in the design that the executor's bus publish is a best-effort, **publish-only** signal (a peer has no family-indexed invalidation surface because refresh state is shared); keep the E2E `KindTokenRevoked` assertion as a publish-side spy assertion; if a peer effect is ever wanted, define a new EventKind with an explicit arm rather than overloading `token_revoked`.

### F4 — Low · Redis `DeleteFamily` is non-atomic; a concurrent rotation can escape the current kill — the in-window re-dispatch is the compensating retry

- **Evidence (Verified):** redis `DeleteFamily` (`refresh_token.go:464-486`) is `SMEMBERS` → per-key `DEL` → family-SET `DEL` — no Lua script, no transaction. `Issue` re-seeds the family SET (`refresh_token.go:126`), so a rotation whose `Consume`+`Issue` lands between the snapshot and the SET delete mints a leaf that survives this call. sqlite `DeleteFamily` is three sequential statements without a transaction (`refresh_tokens.go:323-347`); a crash between them leaves benign ledger rows. Memory store is fully atomic under one mutex.
- **Triggering failure:** attacker rotating the stolen family at the same instant a sweep's revoke executes (ms-scale window; the grant-path reuse kill has the same race today — this design merely adds a caller).
- **Impact:** one escaped leaf remains valid until the next kill; each rotation re-seeds the SET so the *next* sweep's re-dispatch (window/sweep_interval ≈ 15 at defaults) catches it — **provided the re-dispatch-while-signal-persists property survives the dispatch-gating decision (M6)**. If gating suppresses re-dispatch, this compensating retry disappears.
- **Recovery:** subsequent sweep re-dispatch while the finding is in-window; grant-path reuse detection as backstop.
- **Corrective pattern:** document the race and its compensation in the design; if dispatch gating lands, preserve re-dispatch on signal persistence (state-transition gate); optionally make redis `DeleteFamily` atomic (Lua) as a follow-up — out of scope for this direction.

### F5 — Low · Clock anomalies interact with the *windowed* scan and the new subject pruning differently than with today's latest-minute test

- **Evidence (Verified):** the design's failure-mode text says "a skewed replica clock shifts the window exactly as it does today". That is true for bucketing, but the windowed scan is new behavior: every minute in `[now-window, now]` is a candidate, so a **backward** step (NTP correction, `time.Now` jump) widens the effective window and can resurrect already-subsided bursts as findings — each re-firing re-dispatches (idempotent, but noisy and re-triggers the executor fan-out). A **forward** step narrows the window and can drop a burst-at-T−2 from evaluation (missed detection, accepted). The subject table's sweep-time prune (`now - window`) with a backward step can prune live rows (they refill on the next events); the cap eviction ("oldest most-recent minute") keys on *event time*, so a backward step can evict fresh rows — bounded churn; the insertion-order tie-break is clock-independent but only breaks ties.
- **Impact:** bounded, idempotent, no false revokes beyond the pre-existing false-positive surface; detection-quality only.
- **Corrective pattern:** one paragraph in the design stating: window boundaries are per-replica wall-clock; backward steps widen (resurrected bursts re-dispatch idempotently), forward steps narrow (missed detection); the subject-table eviction tie-break is insertion-order so eviction is deterministic under clock noise. No code change.

### F6 — Low · Observation/subject folds run even when the wrapped store write fails — a cross-signal divergence worth stating

- **Evidence (Verified):** `Detector.Record` (`detector.go:236-247`) forwards to `d.next.Record` and folds the observation *unconditionally*, even when the store returns an error. The design's subject fold should mirror this. During a store-write failure, geo/velocity and subject signals keep accumulating while `detectRateSpike`'s store query returns nothing (`detect.go:78-92`, fail-open) — the two signal paths disagree. In the stock build the wrapped store is the in-process memory store, which cannot fail, so this is a custom-store consideration only.
- **Corrective pattern:** state the divergence in the design (one sentence); the subject fold "can never fail `Record`" claim is then precisely true.

### F7 — Info · Sweep snapshot semantics for the new subject table

`Analyze` is not one atomic instant across sources: the bucket query runs under the store's lock (outside `d.mu`), the obs scan under `d.mu` (`detect.go:24-36`), at a slightly different instant. The design should state that the subject scan runs under `d.mu` (coherent with the obs scan; `Record` blocks briefly), not a lock-free copy. No deadlock risk exists: one mutex per component, no nesting (perf review's snapshot suggestion is compatible — copy under lock, compute outside).

### F8 — Info · Rate-limit interplay: shared per-subject bucket and unbounded default-action path

`ThreatExecutors` rate-limits on (subject, type, action) (`registry.go:187-191`). Two consequences for the family path: (a) two *different* families of one subject share one bucket — a dispatch storm for family X can rate-limit family Y's revoke (degraded response, fail-open); (b) the `default_action: revoke` path (no matching policy) has **no** rate limit, so the ~15× re-dispatch amplification (perf M1) is fully unbounded unless a rate-limited policy matches. One sentence in `docs/config-reference.md` should state both.

### F9 — Info · Sweep scheduling and split-brain are non-issues by construction

Sweeps are independent per-replica tickers with no leader/coordination; concurrent identical revokes across replicas converge on idempotent deletes — no fencing/quorum is needed because the effect is delete-only against shared state. Partitions affect only cache invalidation (TTL fallback, bus degraded flag + /readyz red). The design adds nothing bus-dependent to revocation correctness (see F3). Also: `RunTokenAnomalyDetection` (`sso.go:411-428`) has no per-sweep timeout — a hung custom store would stall the sweep loop indefinitely; stock memory store cannot hang; worth one line in the design's failure modes.

## 3. Scenario table

| Scenario | Behavior (verified) | Outcome |
|---|---|---|
| **Bus partition** | `runInvalidationBus` marks degraded, backs off (1–30 s jittered), resubscribes; `/readyz` red while degraded (`server_invalidation.go:114-196`) | Detection/revoke continue (shared store); deny-set convergence delayed to exp; on recovery: flush caches + re-seed deny-sets *before* clearing degraded |
| **Refresh-store partition** (dispatching replica) | `DeleteFamily`/`DeleteAllForSubject` error → logged by `dispatchThreat`; next sweep retries while the signal is in-window (`detector.go:407-430`) | Revoke delayed; if outage outlives the window, **permanently missed** (F2); grant-path reuse kill is the backstop |
| **Replica crash** | All in-process state lost: queue, buckets, obs, subject table, findings (memory); no replay | Applied revokes persist (shared store); detection rebuilds over the next window; undelivered threats are lost (F2) |
| **Detector restart mid-incident** | Same as crash for detector state; finding row (memory) gone | Family revoke may be lost if the burst minute aged out during downtime — documented fail-open |
| **Retry / duplicate delivery** | Sweep re-dispatch (≤ ~15×) hits idempotent `DeleteFamily`/`DeleteAllForSubject`; finding upsert by `DedupKey`; bus re-delivery additive | No double-revoke effect; no duplicate finding rows |
| **Clock rollback** | Window widens; old bursts resurrect as findings and re-dispatch (idempotent); subject prune may evict live rows (refill); eviction tie-break is insertion-order | Bounded noise, no false revokes beyond pre-existing FP surface (F5) |
| **Clock forward step** | Window narrows; burst-at-T−2 may fall out of the query window | Missed detection, accepted (F5) |
| **Stale finding row / winner alternation** | Client-scoped and subject-scoped winners upsert the same `rate_spike\x00<client>` key; `mergeFinding` keeps earliest FirstSeen, freshest SubjectID/Detail | Admin row alternates scope across sweeps (documented); one-per-client rule is load-bearing — a regression test must pin it |
| **Dependency outage (audit)** | Fail-open per AGENTS.md; executor errors logged, never block the sweep | Detection continues; audit gap only |
| **Concurrent rotation vs `DeleteFamily` (redis)** | Non-atomic multi-key delete; a leaf issued between snapshot and SET delete escapes this call; Issue re-seeds the SET | Escaped leaf killed by the next sweep's re-dispatch while the signal persists (F4) — keep the retry property |
| **Bus recovery sequencing** | subscribe-first → re-seed (cache flush + deny-set re-seed) → clear degraded (`server_extensions.go:resubscribeAndReseed`); partial re-seed keeps `/readyz` red | Refresh-family state needs no reseed (shared store); ordering is load-bearing and already implemented |

## 4. Stated guarantees, unsupported topologies, validation tests, residual risks

**Guarantees the design actually provides (all Verified):**
- **Idempotent, at-least-once revocation** targeting shared state; no fencing/quorum required (delete-only semantics); concurrent dispatches across replicas/sweeps converge.
- **Fail-open/fail-closed boundary preserved:** every detection/response hop fails open (drop-on-full queue, store-error → no findings, executor-error → logged, subject fold cannot fail `Record`); the grant-path reuse kill stays synchronous and fail-closed; no change alters a grant/introspect decision.
- **Bounded, deterministic memory:** obs cap 4096 (insertion-order eviction), subject cap 4096 × ≤ window minutes (oldest-minute eviction, insertion-order tie-break), finding cap 1024 (DedupKey upsert).
- **No new cross-replica coordination:** all new state is detector-local; revocation uses the existing shared-store + bus machinery; the bus retains best-effort, TTL-fallback semantics.
- **Ordering:** single drainer preserves Offer order per replica; no ordering guarantees across replicas or sweeps — none are needed for correctness.
- **Zero-value byte-identity** for family-less paths, including the fallback revoke.

**Unsupported topologies / declared non-goals (confirmed):**
- Multi-replica detection aggregation — observations, subject rates, and findings are per-replica and sharded by request locality (F1); fleet-wide views are direction-2 territory.
- Durable detection state or finding history (memory-only; finding persistence is direction-2).
- Durable threat-intent delivery (at-most-once per finding lifetime, F2).
- Per-replica memory refresh stores across replicas (revocation propagation depends on the store being shared).
- The bus as a delivery guarantee for the executor's `KindTokenRevoked` (publish-only, F3).
- No SLOs or baselines for sweep duration, drain lag, or dispatch latency (no sweep-duration gauge, no subject-cardinality gauge — perf M2/M8).

**Validation tests this review adds to the design's plan (all unit-level unless noted):**
1. **Crash/restart semantics:** build a detector, feed observations + subject rates, drop the instance (new `Detector`), assert no replay of undelivered threats and that applied (spy-store) revokes "persist" — pins F2's at-most-once contract as documented behavior.
2. **Retry-after-executor-failure:** spy executor fails once, succeeds on the next sweep; assert re-dispatch fires — pins the retry-while-signal-persists property that any dispatch gating (M6) must preserve.
3. **Concurrent rotation-vs-DeleteFamily (redis backend test):** rotate during `DeleteFamily`; assert the escaped leaf is killed by a subsequent `DeleteFamily` (the compensating retry) — documents F4.
4. **Clock-step tests (fixed clock):** step backward — assert a subsided burst re-fires as a finding (idempotent dispatch); step forward — assert burst-at-T−2 is not evaluated; subject-table prune under a backward step refills without unbounded growth — pins F5.
5. **Rate-limit interplay:** two families of one subject with a rate-limited policy; assert family-2's revoke can be delayed by family-1's dispatches — pins F8 semantics.
6. **E2E (existing plan, refined):** assert idempotent final state only, never dispatch counts (QA F8); the `KindTokenRevoked` assertion must be a publish-side spy assertion (F3); two-family survival assertion holds in the single-process harness (shared memory store — the locality assumption is trivially satisfied there, which is exactly why F1 needs a doc paragraph, not a test).

**Residual risks (accepted or owner-decided):**
- The dispatch-gating decision (principal M6) interacts with F2 (delivery retry) and F4 (compensating retry): a key-existence gate silently removes both. Gate on state transition.
- Family precision remains doubly gated on introspection traffic and request locality (F1); the user-wide hammer persists for rotation-first and access-token-only paths (security F1).
- `KindTokenRevoked` carries two incompatible payload shapes; a future arm must not assume `MetaRevokedToken` (F3).
- Subject-spike revoke is subject-wide by correct construction (design failure-mode 6) — with `default_action: revoke` and no matching rate-limited policy, a legitimate 20+/min login wave self-inflicts a subject-wide revoke (security F4); pair with `rate_limit` guidance in config docs.
- Sweep loop has no timeout (F9); stock memory store cannot hang, custom stores can.

**Bottom line:** the design is sound as a *single-replica* state machine and preserves every distributed invariant it touches — idempotent shared-store revocation, fail-open response, bounded per-replica memory, and no new coordination. The distributed gaps are documentation-and-decision items, not code defects: the per-replica sharding of the family signal (F1), the at-most-once delivery contract (F2), the publish-only bus event (F3), the non-atomic redis family kill with its sweep-retry compensation (F4), and the clock-window interactions of the windowed scan (F5). All five must be reflected in the design doc before implementation; only F1/F2/F3 need operator-facing documentation in `docs/config-reference.md` as well.
