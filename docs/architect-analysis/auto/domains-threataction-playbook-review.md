# Distributed-Systems Review: `domains/threataction` — Multi-Action Playbooks and Explicit Priority

Reviewer role: distributed-systems engineer. Input: `docs/auto/domains-threataction-playbook-design.md`
(and its spec). Scope: consistency, ordering, atomicity, idempotency, ownership,
conflict resolution, outage/crash/retry/partition behavior, clock assumptions,
and the fail-open/fail-closed boundary of the proposed design.

Checks that actually ran for this review: `go build ./...` (clean);
`go test ./domains/threataction/... ./domains/anomaly/... ./domains/tokenanomaly/...`
(all pass at the reviewed revision). Every claim below cites a file + symbol.

Verdict: **the design is sound and the distributed-systems deltas are bounded**.
All three improvements operate on state that is already per-replica or
idempotent; no new cross-replica coordination, quorum, or clock dependence is
introduced. Two findings need work before merge: a silent fail-toward-noop
window during rolling upgrades (F-1), and an evidence error about a "parity
test" that does not exist (F-4). One design decision (dedup-before-rate-limit,
D-1) changes observable behavior and must be called out in the changelog.

---

## 1. State map

| State | Owner | Store | Durability | Consistency | Replication | Failover |
|---|---|---|---|---|---|---|
| Threat policies (stock binary) | One `threataction.ThreatPolicyStore` **per replica**, created in `cmd/sso-server/serverbuildplatform/build_governance.go:323` (`BuildThreatAction`, memory store) and wired by `cmd/sso-server/anomaly.go:75` | `domains/threataction/memory/policy_store.go` (in-memory map, RWMutex) | **None** — admin PUTs (`HandleAdminPutPolicy`) are lost on restart; boot re-seeds from `threat_action.policies` config (`config/config_snapshot.go:472`) | Per-replica read-your-writes; **no cross-replica convergence** (no invalidation bus for policy state) | **None** | Restart re-seeds from config; admin mutations lost (pre-existing) |
| Threat policies (sqlite backend, **library only**) | Shared SQLite file; `domains/threataction/sqlite/policy_store.go` | `threat_policies` table, whole `ThreatPolicy` in `policy_json` blob | Yes (file) | Last-writer-wins whole-blob upsert (`Put`, `ON CONFLICT(name) DO UPDATE SET policy_json = excluded.policy_json`); row-atomic, no cross-row txn | Shared file, not replicated; **not wired into the stock binary** (only `domains/threataction/sqlite/policy_store.go` imports the package) | Reopen / `Ping` readiness probe (`sqlite/policy_store.go:88`, `TestThreatPolicyStore_Ping`) |
| Rate-limit windows | Per-replica `ThreatExecutors.rateLimit` map (`registry.go:29`, guarded by `te.mu`) | In-memory only | None (map cleared on restart) | Per-replica independent; **effective cap is N×Max under N replicas** (pre-existing) | None | Reset on restart → flapping detector may re-fire once per replica |
| Session suspension / refresh-token revocation (action effects) | Session manager / refresh-token store (durable, shared) | `core.SessionManager`, `oauthspi` refresh store | Yes | Idempotent primitives (`Destroy`, `DeleteFamily`/`DeleteAllForSubject` documented idempotent — `actions.go:33,63`) | Cross-replica via cluster bus: `KindSessionSuspended` / `KindTokenRevoked` best-effort publishes (`actions.go:99,193`); nil bus is a safe no-op | Re-execution after failover is safe because primitives are idempotent |
| Audit trail | `audit.Recorder` (`registry.go:241` `recordAudit`; nil-safe) | Audit sinks (durable per sink) | Per sink | Sink errors fail open (documented repo-wide) | Per sink | N/A |

Ownership summary: **the only state the design writes is per-replica (memory
policy store, in-memory rate limiter) or idempotent (action effects)**. No new
shared mutable state is introduced. The design's "both stores must change in
lockstep" constraint (design §Priority) is a library-parity constraint, not a
runtime convergence mechanism — in the stock binary there is exactly one store
per process.

---

## 2. Findings (severity order)

### F-1 — High: mixed-version window silently evaluates new-format policies as noop (read side)

- **Evidence (Verified)**: Old binaries ignore unknown JSON/YAML fields.
  `unmarshalPolicy` (`sqlite/policy_store.go:171`) is a plain
  `json.Unmarshal` — unknown keys are dropped. Config loading is
  lenient-fallback by design: `decodeStrictWithFallback`
  (`config/source.go:260`) warns and re-decodes without
  `DisallowUnknownField`. In both paths a pre-upgrade binary reads a
  new-format policy (`actions: [...]`, `priority`) with `Action == ""` and
  `Actions == nil`, which `Execute` treats as noop (`registry.go:104`,
  `validAction("")` returns true by design — `admin.go:129`).
- **Triggering failure**: rolling upgrade of a multi-replica deployment where
  any replica runs the old binary while a new-format policy exists (config
  YAML shipped with the new binary, or admin PUT to the shared sqlite store).
- **User impact**: a real threat is detected and **no security action fires**
  — silent fail-toward-noop on old replicas. The design's failure-mode 4
  covers only the write side (old server `PUT` strips new fields). The read
  side is worse: it needs no admin write at all, only a new-format config,
  and it is silent (one boot-time config warning + a noop audit event per
  threat).
- **Recovery**: complete the rollout; the new binary evaluates correctly. The
  policy data itself survives (unless an old binary `PUT`s the row — design
  failure-mode 4).
- **Corrective pattern**: rollout discipline, made verifiable. Recommend (a)
  the design's documented "do not use `actions`/`priority` until all replicas
  are upgraded" note extended to the **config-seeded path**, not just sqlite
  admin PUTs; (b) optionally a boot-time log line in `BuildThreatAction` when
  a policy resolves to noop through the legacy field while `Actions` is
  non-empty (old binary: `Actions` unknown → cannot detect; so (a) is the
  real control). This is a transient-window issue, not a persistent defect.

### F-2 — Medium: policy-state divergence across replicas is now behaviorally observable

- **Evidence (Verified)**: stock binary = per-replica memory store
  (`build_governance.go:323`); no policy invalidation bus exists (the cluster
  bus carries only `KindSessionSuspended`/`KindTokenRevoked` — `actions.go`).
  Admin `PUT` mutates one replica only (`HandleAdminPutPolicy` →
  `store.Put`); the executor re-reads `List` on every event (`registry.go`
  `matchPolicy`), so there is no cache, but also no convergence.
- **Triggering failure**: admin edits a policy (or `priority`/`actions`)
  while replicas are live; or rolling restart with a new config.
- **User impact**: before the change, divergence meant "which single action
  fires" differed per replica; after the change, **which ordered action list
  fires, and which policy owns a deduped action's rate-limit window**, differs
  per replica. The design's priority/dedup semantics make the divergence more
  consequential and more visible. Pre-existing property, not a regression.
- **Recovery**: restart the edited replica (re-seed from config) or roll the
  change via config rollout.
- **Corrective pattern**: document that threat-policy admin CRUD is
  single-replica-effective in the stock binary (sqlite backend required for
  shared state); this is the same operational class as other admin mutations,
  but the design should state it explicitly since ordering now carries
  security meaning. No code change required for this design.

### F-3 — Low: `invalid_policy` reason enumeration in `docs/error-codes.md` becomes stale

- **Evidence (Verified)**: `docs/error-codes.md:1010` enumerates the exact
  rejection reasons for `invalid_policy` (`action`, `rate_limit.max`,
  `rate_limit.per_window`, `conditions.operator`). The design adds two new
  rejection reasons (`priority < 0`, empty `actions` entries). No new `Err*`
  is added — verified: `shared/core/errors.go:322` `ErrInvalidPolicy` exists
  and admin validation returns it with reason strings (`admin.go:92`) — so
  the design's "error-codes untouched" claim is *technically* true and the
  wire contract is unchanged; only the row's illustrative enumeration drifts.
- **User impact**: operators consulting the row see an incomplete reason list.
- **Corrective pattern**: append the two new reasons to the row in the same
  change (one sentence; keeps the doc honest without a new `Err*`).

### F-4 — Info: design cites a cross-store parity test that does not exist

- **Evidence (Verified)**: design §Storage says "The existing cross-store
  parity test in `domains/threataction/sqlite/policy_store_test.go` is
  extended with mixed priorities". The file's tests are
  `TestThreatPolicyStore_CRUD`, `_RoundTripNestedFields`,
  `_FirstMatchOrdering` (sqlite-only, no memory comparison),
  `_PersistsAcrossReopen`, `_Ping`, `_MaxVersion` — no parity test exists
  anywhere (grep for `Parity`/`parity` across `domains/` test files: none).
- **Impact**: the design's parity-by-construction argument is right, but the
  belt-and-braces test it references must be **written new**, not extended.
  This is the single most important new test for the ordering guarantee (see
  §4).

### D-1 — Design consequence to confirm in changelog: dedup before rate limiting

- **Evidence (Verified)**: today `matchPolicy` returns the first match only
  (`registry.go:139`), so a lower-priority policy's action never runs — its
  `RateLimitKey` (`threataction.go:134`) is shared, so windows were never
  independent. The design's dedup-before-rate-limit is a faithful
  generalization (verified reasoning, **Proposed** semantics until tests
  land).
- **User impact**: if the highest-priority owner of an action is
  rate-limited, a lower-priority duplicate gets no second chance; operators
  cannot express independent windows for one action. Documented in the
  design; call out in the changelog since audit *event volume* changes
  (N events per multi-action threat) are observable to dashboards (design
  failure-mode 2).

### Verified-benign (no action)

- **Clock**: `allow()` compares `time.Now()` values carrying the monotonic
  component (`registry.go:187-218`) — within a process, wall-clock rollback
  cannot extend windows; forward jumps only shrink them (more actions, the
  safe direction for a suppression control). No wall-clock value is used in
  any decision. Restart clears the map. **No clock assumption in the design
  needs fencing or NTP guarantees.**
- **Concurrency**: `Execute` holds `te.mu` only inside `allow()`, never
  across handler execution; the composite is documented thread-safe
  (`threataction.go` package doc) and shared by both detectors per replica
  (`cmd/sso-server/anomaly.go:42-75`). The design's helpers must preserve
  this (no shared mutable plan state).
- **Store-outage fail-open**: `List` error → log + `defaultPolicy()` fallback
  (`registry.go:93-96`), unchanged. Note: with `default_action: suspend`
  configured, a store outage makes **every** threat suspend — pre-existing,
  preserved by the design, and consistent with the documented fail-open
  boundary (advisory detection must not crash the login path).

---

## 3. Scenario table

| Scenario | Behavior today | Behavior after design | Safe? | Notes |
|---|---|---|---|---|
| Partition (replica loses sqlite/shared store) | `List` error → log + `defaultPolicy()` → default action or noop | Identical (fallback path unchanged; `matchPolicies` consumes same `List`) | Yes — fail-open preserved | A partition mid-plan cannot occur: plan is built from one `List` call |
| Replica crash mid-plan (after suspend, before notify) | N/A (single action) | Earlier actions applied, later actions lost; audit events already recorded survive; next detection event re-triggers the full plan | Yes — per-action best effort, no cross-action atomicity | No journal/outbox; recovery is re-detection. Underlying primitives idempotent, so re-execution is safe |
| Crash between policy `List` and first action | Fallback or normal path | Identical; no partial write to any store | Yes | Policy evaluation is read-only |
| Retry / duplicate delivery (same event re-processed) | Rate limiter (per-replica) may suppress; actions idempotent | Dedup collapses intra-plan duplicates; cross-replica duplicates still possible (independent limiters) | Yes | One execution per action per event per replica; at-most-once per replica, at-least-once across replicas — safe only because actions are idempotent |
| Clock rollback (wall clock steps backward) | Monotonic comparisons in `allow()` unaffected | Unchanged | Yes | No TTL/fencing depends on wall clock here |
| Clock jump forward | Windows expire early → more actions fire | Unchanged | Yes | Safe direction (suppression weakens, actions still idempotent) |
| Stale cache | None — `List` re-read per event (no policy cache) | None | Yes | The design adds no cache; the tradeoff is a full-table scan + unmarshal per event on sqlite |
| Dependency outage (session store / refresh store down) | Handler returns error → logged, audited `OK:false`, sibling… | …siblings continue (now explicit per-action loop; today single action only) | Yes — strictly safer | Design's per-action `recover` keeps one panicking handler from dropping the rest of the plan |
| Dependency outage (audit sink down) | `recordAudit` sink errors fail open | Unchanged | Yes | Per AGENTS.md fail-open list |
| Rolling upgrade, new fields present on old replica (F-1) | — | Old replica: `Actions` unknown → `Action == ""` → **silent noop** | **No** | Needs rollout discipline (F-1); write-side stripping is design failure-mode 4 |
| Split-brain (two replicas, shared sqlite, concurrent admin PUTs) | Last-writer-wins whole-blob upsert, row-atomic | Unchanged (blob layout untouched) | Yes | Pre-existing; whole-policy overwrite means a concurrent `PUT` of stale fields can clobber newer ones (pre-existing, now includes `priority`/`actions`) |
| Readiness / failover | sqlite `Ping` ready-check exists; memory store none | Unchanged | Yes | Executor is not a readiness gate; degraded policy store degrades to default action, not 503 |

---

## 4. Stated guarantees, unsupported topologies, validation tests, residual risks

### Guarantees the design must state (and tests must pin)

1. **Per-replica, per-event determinism**: given identical policy state, the
   execution plan is total and reproducible: store order `(priority asc,
   name asc)` → policy order → list order → dedup first-occurrence-wins. No
   map-iteration or concurrency input to the plan.
2. **Per-action isolation**: one action's failure (handler error, no handler,
   rate-limit, panic) never suppresses sibling actions of the same threat,
   and each outcome is in the result slice with its own audit event.
3. **At-most-once per (replica, event, action)**: dedup + per-replica rate
   limiter. **Not** global exactly-once: cross-replica duplicates are
   possible and safe only because every leaf action's underlying primitive is
   idempotent (`Destroy`, `DeleteFamily`, `DeleteAllForSubject`,
   `MarkStepUp`) — `notify` is the exception (duplicate audit events, benign,
   rate-limited).
4. **No cross-action atomicity**: the plan is best-effort sequential; a crash
   mid-plan loses the tail. Recovery is re-detection, and re-execution is
   safe by guarantee 3's idempotency.
5. **Fail-open boundary preserved**: policy-store outage → `default_action`
   (which may be a real action — documented); handler/audit/bus failures →
   logged + audited, never propagated to the request path.
6. **Backward compatibility**: policies without new fields evaluate
   byte-identically (legacy resolution rule; `Priority: 0, Actions: nil`
   round-trip from old blobs/config).

### Unsupported topologies (state explicitly)

- **Cross-replica policy convergence**: no replication of admin mutations in
  the stock (memory-store) build; sqlite backend required for shared policy
  state, and it is not wired in the stock binary today.
- **Cross-replica rate limiting**: effective limit scales with replica count;
  restart resets windows. Not a security control — a suppression control.
- **Global dedup**: dedup scope is one `Execute` call, not the fleet.
- **Mixed-version operation**: new fields must not be used before all
  replicas run the new binary (F-1, design failure-mode 4).

### Validation tests (required; existing where noted)

- **New** cross-store parity test with mixed priorities + equal-priority name
  tiebreak (F-4 — must be written, not extended).
- Existing: `TestThreatPolicyStore_FirstMatchOrdering` (sqlite-only ordering
  baseline; extend with `priority`), `TestThreatExecutors_RateLimit`,
  `TestThreatExecutors_NoHandlerForAction`, `TestHandleAdminPutPolicy_*`,
  `TestThreatPolicyStore_PersistsAcrossReopen`, `TestThreatPolicyMaxVersion_MatchesLiveSchema`
  (schema version unchanged — the design correctly adds no migration).
- New: dedup attribution (higher-priority owner's `RateLimitPolicy` governs;
  lower-priority duplicate produces no result/audit); rate-limited owner →
  one `OK:false` result, no sibling retry (D-1); sibling isolation across
  policies (revoke fails mid-ladder → notify still runs); panic in one
  handler → that action `OK:false`, siblings run; legacy payload byte-parity
  (one result, one audit event); concurrent `Execute` under `-race` with the
  shared composite (guards helper-shared-state regression); openapi `required`
  relaxation is safe-direction (generated validators accept more, never
  fewer).

### Residual risks

- F-1 window (High) is closed only by rollout discipline; a boot-time guard is
  not possible on old binaries (they cannot see unknown fields).
- Audit volume multiplies by plan length — dashboards counting
  `threat_action_executed` will shift (design failure-mode 2; call out in
  changelog).
- `default_action` silently unreachable once a catch-all policy exists —
  documented in the design; the deferred wiring-time warning is the right
  follow-up but out of scope.
- The executor's `error` return remains for "future catastrophic paths" —
  today effectively always nil; the two production callers keep their
  dead-ish `err != nil` branches (harmless; both test doubles exercise them).

## Change-class summary

- Required before merge: F-1 documentation extension (config-seeded path),
  F-4 (write the parity test), F-3 (error-codes row), changelog note for D-1
  and audit-volume change.
- No changes to the design's architecture: no new shared state, no new
  coordination, no clock/fencing dependency, fail-open boundary preserved.
