# Performance review: `domains/userlifecycle` direction 1 (login/refresh gates + transition revocation)

Reviewer: performance engineer. Inputs: `docs/auto/domains-userlifecycle-direction1-design.md`
(revision `f0b83ce`). No `.go` edits; `go build ./...` re-run green on this revision.
All claims below were re-verified against the working tree by source inspection
before writing; labels follow the AI-prompt evidence standard.

## 1. Workload assumptions and evidence quality

The change touches three request classes plus two background/control-plane paths:

| Path | Workload assumption | Gate/decision | Evidence |
|---|---|---|---|
| Password / LDAP / federated / MFA login | High rate, latency-sensitive; dominated by bcrypt + SCIM `GetByID` + session/token minting | D1 gate at 5 sites | **Verified**: `authenticateUser` (`interfaces/sso/server_login_auth.go:57`) runs the authenticator (bcrypt family in `domains/authenticators/password_hash.go`), SCIM `rejectDeactivatedUser`, then session creation; `recordLoginFailure` (`server_helpers.go:282`) does metric + tenant-attempt + anomaly + audit on the deny path |
| Refresh grant | High rate; already ≥3 store round trips (Consume → session-liveness Get → resolve/velocity → issue+rotate) + JWT signing | D2 gate | **Verified**: `HandleRefreshGrant` (`internal/handler/tokengrant/token_refresh.go:60–118`); gate inserts after liveness (~:93), before `refreshResolveGrant` |
| Admin lifecycle transition (suspend/archive) | Cold path, operator-driven, must not exceed admin/gateway budget; D3 makes the 200 imply revocation done | D3 sync reactions | **Verified**: bus dispatches synchronously inside `RecordTransition` (`sweep.go:162`) on the admin request goroutine; `audit.Recorder` buffers nothing (`platform/audit/recorder.go:10`, `Record` at :143) |
| Auto-deprovision sweep | Background, operator-set interval (doc example 1h); walks every user | D3 sweep-driven ARCHIVED fires reactions | **Verified**: `SweepOnce` (`sweep.go:75`) calls `d.Users.List` (full roster) then per-user `Get`+`LastActive`; `RunUserAutoDeprovision` (`interfaces/sso/options_admin.go:318`) |

**Evidence quality.** Every cost-bearing claim below is source-verified. What is
**Missing**: there are no current latency/throughput SLOs for login, refresh, or
admin transitions anywhere in the repo, and no benchmarks exist for
`interfaces/sso`, `internal/handler/tokengrant`, `domains/userlifecycle`, or
`protocols/lifecyclereactions` (grep of `func Benchmark` — only
`interfaces/ratelimit`, `memorystoreoauth/sharded`, `issuer_bench`,
`sqlite/clients_scan`, `auth_pipeline`, `trust` have them). Per the prompt's
rule, no targets are invented; the plan in §4 establishes baselines at this
revision instead. Predicted deltas are order-of-magnitude estimates from code
shape, not measurements.

**Hot-path verdict up front.** The two read gates (D1/D2) add one in-process
`memory.Store.Get` (RWMutex RLock + map lookup, allocation only when the user
has a non-empty transition history — see F-3) per login leg and per refresh.
That is ~50 ns–1 µs against bcrypt (~10–100 ms) and existing refresh store
round trips (~1 ms each): **not measurable at the request level**. The material
performance surface is D3: the synchronous reaction's O(clients) refresh leg
(F-1) and the sweep's now-destructive tick (F-2).

## 2. Findings

### F-1 — Medium — D3 reaction's refresh leg is O(fleet clients) round trips on the admin request path

- **Path/symbol**: `protocols/lifecyclereactions/revoke_on_archive.go:78–99`
  (`revokeRefreshTokens`), reused as-is by the new `RevokeAccessOnSuspend`
  (design D3.1).
- **Mechanism (Verified)**: the leg calls `clients.List(ctx)` — the SPI doc
  (`shared/core/spi.go:60`) says "returns every registered client"; on SQL
  backends that is a full-table scan — then loops `DeleteAllForSubject(userID,
  c.ID)` once per client. The SPI already supports the empty-client form
  (`RefreshTokenSubjectIndex`, `protocols/oauth/oauthspi/refresh_token.go:233`):
  sqlite executes 2 statements total for `userID, ""` vs 2×M for the loop
  (`infrastructure/defaultimpl/sqlite/refresh_tokens.go:242–270`); Redis does
  one bounded SCAN of the subject-index prefix vs M single-key fetches
  (`infrastructure/redis/refresh_token.go:313–336`); memory is one map pass
  either way (`memory_refresh_token.go:300`). In-repo precedent for the
  efficient form: `interfaces/admin/users.go:399`, `interfaces/admin/deps.go:166`.
- **Impact (predicted)**: suspending one user in a fleet with 10k registered
  clients = 10k+1 serialized round trips on the admin request goroutine.
  At ~1 ms RTT that is ≥10 s — past most gateway budgets — and because the
  reaction runs on the request context (ds-review F-1, security F-3), a client
  disconnect mid-reaction cancels the revocation after the state committed,
  leaving a suspended user's credentials alive. Latency scales with fleet
  client count, not with the target user's footprint.
- **Recommendation**: call `DeleteAllForSubject(ctx, userID, "")` once and
  drop `clients.List()` from the leg (this is also protocol-expert F-2's
  correctness fix; the two reviews agree on the same code change). Keep
  best-effort `errors.Join` semantics.
- **Experiment**: micro-benchmark both forms on sqlite + memory with
  {10, 100, 1000, 10k} clients; assert the loop form's op count is O(M) and the
  empty form O(1) statements.

### F-2 — Medium — sweep-driven ARCHIVED transitions now execute destructive sync reactions inside a full-roster walk

- **Path/symbol**: `SweepOnce` (`domains/userlifecycle/sweep.go:75`) +
  `apply` → `RecordTransition` (:162) → bus → sync reactions (design D3.2).
- **Mechanism (Verified)**: the sweep already does `d.Users.List` (entire
  roster) plus a `Get` + `LastActive` per user; `MaxPerSweep` caps *transitions*,
  not iteration. D3 makes every ARCHIVED transition in the loop run the full
  reaction (F-1 refresh leg + per-session destroy leg) synchronously, so tick
  duration = roster scan + (archived users × reaction cost).
- **Impact (predicted)**: on a large roster (100k+ users) with a long-dormant
  cohort, a single tick can exceed the operator-chosen interval (doc example:
  1h), and each archived user's reaction cost currently scales with fleet
  clients (F-1). The reaction runs on the loop's own ctx (no client-cancel
  risk), but a slow tick delays dormancy detection for the whole tenant.
- **Recommendation**: land F-1 first (it dominates); then measure a real-roster
  tick (§4 plan). If tick latency matters, note the design's own escape hatch
  (§3.2 "a future switch to OnAsync must pair with bus.Close") — sweep-driven
  transitions have no 200 contract, so `OnAsync` for ARCHIVED would decouple
  them without weakening the admin guarantee, at the cost of the shutdown
  wiring the design already documents. Keep admin-path SUSPENDED synchronous.
- **Experiment**: sweep-tick duration vs roster size {10k, 100k, 500k} with
  1% ARCHIVED-eligible cohort, before/after D3.

### F-3 — Low — `memory.Store.Get` clones the unbounded per-user history on every gate read

- **Path/symbol**: `domains/userlifecycle/memory/memory.go:41–49` (`Get` →
  `cloneRecord` → `slices.Clone(rec.History)`), called by D1 (5 sites), D2
  (`LifecycleState` accessor), and the sweep (`sweep.go:104`).
- **Mechanism (Verified)**: history is append-only (`Append`, `memory.go:51`)
  with no trim, so a user with T transitions pays a T-element slice allocation
  + copy under the RLock on every login leg, every refresh, and every sweep
  iteration. Users with zero transitions (the common case) allocate nothing
  (miss path returns a value record). RLock is held during the clone.
- **Impact (predicted)**: negligible at the request level today (bcrypt and
  store round trips dominate), and T is admin-driven and small in practice;
  the linear-in-T term is the only unbounded component on the gate paths and
  the only reason the RLock is held for more than a map read. Also worth
  noting: the memory store never evicts records or history (per-process,
  grows monotonically) — fine for the documented "tests and small embedded
  deployments" target; the direction-3 SQL peer should cap history.
- **Recommendation (optional, measure first)**: add `StateOf(ctx, userID)
  (State, error)` to the `userlifecycle.Store` interface and have the gates use
  it; the gates need only the state, never the history. This touches test
  doubles, so it is a deliberate interface change, not a freebie — only
  justified if the benchmark in §4 shows the clone in the login/refresh
  profile, which I do not expect at realistic T.
- **Experiment**: `BenchmarkStoreGet` with history lengths {0, 1, 100},
  `-benchmem`; compare gate cost per login at 1k rps.

### F-4 — Info — bus-as-audit-sink adds one type compare to every audit event

- **Path/symbol**: `domains/userlifecycle/bus.go:175` (`Record`, early return
  on `ev.Type != EventAdminUserLifecycleChanged`).
- **Mechanism (Verified)**: the bus is added to the audit `MultiSink`
  (`audit.Recorder.AddSink`, `platform/audit/recorder.go:131`); every audited
  event calls it. Non-lifecycle events cost a string compare + return; lifecycle
  events copy the (2-element) handler slice under RLock. The primary sink runs
  first, unchanged.
- **Impact**: unmeasurable on any real workload. No action. The design's
  wiring-time-only `AddSink` constraint also matches the recorder's documented
  non-concurrency with `Record` — verified safe.

### F-5 — Info — gate placement costs and retry amplification on the refresh path

- **Mechanism (Verified)**: D2 inserts after `Consume` (`token_refresh.go:75`),
  so a denied suspended user's token is burned; client retries hit the reuse
  path and kill the family (`token_refresh.go:37–44` semantics). Each retry is
  consume + reuse-detect + family delete — pre-existing store work the gate
  makes reachable for suspended users.
- **Impact**: bounded by the number of suspended users actually retrying
  (admin-driven, small); per-retry cost is a few store ops, and the family kill
  is the desired outcome (design D2 pinned properties). No backpressure concern
  at realistic suspension counts; note the amplification in the runbook so an
  operator does not mistake a retry storm for a store problem. The fail-closed
  denial path itself is inert today (memory store never errors) — it becomes a
  per-request point read only with the direction-3 SQL peer, at which point a
  store outage = mass 403/400 (design Decision 5; re-baseline then, per §5).

### F-6 — Info — concurrency, caching, and cardinality posture

- **Verified**: `memory.Store` RWMutex — reads concurrent, writers are admin
  transitions + sweep only (rare); no contention risk at realistic QPS. The
  design adds **no caching** — correct: the read is already O(1) and a cache
  would reintroduce the staleness the gates exist to remove (speculative
  caching rejected). Audit meta is bounded (6-state enum); the variadic meta
  on `recordLoginFailure` allocates only on the deny path. No pools, timeouts,
  or backpressure changes; the only timeout-shaped risk is the sync reaction
  duration on the admin path (F-1), which is a latency budget, not a resource
  leak. `context.WithoutCancel` (ds-review F-1 fix) would convert bounded
  request-scoped work into unbounded background work — pair it with a deadline
  (e.g. `context.WithTimeout(context.WithoutCancel(rctx), 30s)`) if adopted.

## 3. Critical-path table

| Path | Baseline (this revision) | Target | Bottleneck (dominant term) | Profiling method |
|---|---|---|---|---|
| Password login (single leg) | No lifecycle work | +1 `Store.Get` (RLock+map; +alloc iff history non-empty) | bcrypt verify + SCIM `GetByID` (10–100 ms class) — gate adds ≤1 µs | `go test -bench` on `authenticateUser`-shaped harness; pprof CPU delta |
| MFA login (2 legs) | No lifecycle work | +2 gate reads | bcrypt + challenge session round trips | same |
| Refresh grant | Consume + liveness + resolve + velocity + rotate (≥3 store ops + JWT sign) | +1 gate read | store round trips (~1 ms RTT class) | pprof + per-op tracing in `test/` E2E |
| Admin suspend/archive (D3) | `Append` + audit write (~ms) | **+ O(M+N) reaction RTTs today; O(1)+O(N) after F-1** | `clients.List()` full scan + M×`DeleteAllForSubject` + N×`Destroy` | trace admin `POST`; count store ops; gateway-budget check |
| Sweep tick (D3) | `Users.List` full roster + per-user Get/LastActive | + per-ARCHIVED reaction cost | roster scan (pre-existing) + reaction legs | tick-duration metric (absent today — add) |

Targets: none supplied (no SLOs exist); the table's "target" column is the
predicted post-change shape, and §4 defines acceptance rules against
baselines measured at `f0b83ce`.

## 4. Prioritized benchmark/load plan

| # | Focus | Dataset | Concurrency / duration | Acceptance rule | Regression comparison |
|---|---|---|---|---|---|
| P1 | Reaction refresh leg (F-1) | 1 user × {10, 1k, 10k} clients × {0, 10, 100} tokens, sqlite + memory + redis | serial, single shot, `-benchmem` | empty-client form ≤ 2 statements (sqlite) / 1 SCAN (redis); loop form excluded | memory vs sqlite vs redis op counts, this revision |
| P2 | Reaction session leg | 1 user × {1, 50, 200} live sessions | serial | N `Destroy`s, linear; document N bound per backend | before/after D3 |
| P3 | Refresh-gate overhead | 10k users, 50% with 1-transition history, 5% suspended | 100 rps × 60 s (with `-race` variant, 30 s) | P50/P99 delta vs no-gate build < 5% or < 1 ms absolute; suspended-user deny path byte-identical | same harness at `f0b83ce` (add gate flag build) |
| P4 | Login-gate overhead | 10k users, mixed history | 50 rps × 60 s | P99 delta < 5% or < 5 ms absolute (bcrypt dominates; expect ~0) | same |
| P5 | Admin transition latency | user with 50 sessions × 1k clients | serial, 20 runs | p95 < 1 s after F-1; assert no ctx-cancel mid-flight (ds F-1 harness) | pre-F-1 build |
| P6 | Sweep tick | roster {10k, 100k, 500k}, 1% ARCHIVED-eligible | 1 tick each | tick < interval/10 (operator interval; flag if unbounded) | pre-D3 build |

Baseline discipline: every row has a no-change comparison at `f0b83ce`;
deltas recorded in the same change that lands D1–D3 (AGENTS.md §5.6
contracts-first applies to docs; perf evidence should ride the same PR).
`-count=10` for idempotency rows (double-transition, re-ARCHIVED).

## 5. Optimization risks and measurements still needed

**Risks**

1. **Do not cache lifecycle state** on any path. The read is O(1) today; a
   cache would reintroduce exactly the staleness the gates are the fix for and
   would need invalidation across the five sites and the refresh path. This is
   the design's correct non-decision.
2. **The F-1 fix must not regress oracle safety.** `DeleteAllForSubject(userID,
   "")` deletes across all clients in one call — wire shape unchanged, denial
   shapes unchanged; it also removes the `clients.List()` failure mode that
   today aborts the whole refresh leg on a listing error (protocol F-2).
3. **`context.WithoutCancel` (ds F-1) converts bounded to unbounded work** —
   if adopted, pair with a deadline; without one, a hung backend turns a
   single admin request into a permanent background goroutine. Alternatively
   keep sync + fix F-1 so the work fits the request budget.
4. **`OnAsync` for sweep ARCHIVED** is available but requires the `bus.Close`
   shutdown wiring the design explicitly deferred; do not mix async sweep with
   sync admin on the same state without the drain.
5. **Direction-3 SQL peer re-opens every estimate**: gates become point reads
   (one per login/refresh), fail-closed outage = mass denial, sweep roster scan
   moves to SQL. Re-run P3/P4/P6 at that point; today's memory-store numbers
   will not transfer.
6. **History growth is unbounded per user** in the memory store (F-3). Not a
   request-path risk; cap/trim history in the SQL peer.

**Measurements still needed**

- Login/refresh P50/P99 baselines at `f0b83ce` (no benchmark exists today —
  **Missing**, this is the prompt-mandated baseline design, not an SLO claim).
- Admin-transition latency and store-op counts per backend (sqlite/redis) for
  the reaction legs.
- Sweep tick duration metric (no metric exists for `SweepOnce` today;
  `RunUserAutoDeprovision` only logs errors — add a duration/gauge with the
  change).
- Per-user session-count distribution (bounds the N term of the session leg)
  and per-user transition-count distribution (bounds the F-3 clone term) from
  a production-like dataset — both currently **Unknown**.
- Redis SCAN bound behavior for `DeleteAllForSubject(userID, "")` at very
  large per-user token counts (verify the bounded SCAN stays bounded).

**Summary for the design.** No Critical/High findings. D1/D2 are
per-request-cost-free at memory-store scale (sub-µs vs bcrypt and existing
store round trips) and correctly avoid caching. D3's sync reaction is the only
material performance surface: fix the per-client refresh loop to the
empty-client SPI form (F-1, also protocol F-2), re-check sweep tick latency
(F-2), and establish the missing baselines (§4) in the same change. The
fail-closed denial paths are inert today and become one point read per
login/refresh with the direction-3 SQL peer — re-baseline then, and treat the
accepted mass-denial outage posture as an availability SLO decision the
operator must ratify (design Decision 5; ds F-5).
