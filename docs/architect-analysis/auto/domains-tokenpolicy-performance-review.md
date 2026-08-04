# Performance Review: token-policy lifecycle design at the issuance/introspection boundary

Reviewer role: performance engineer (latency / throughput / resource risk).
Input: `docs/auto/domains-tokenpolicy-design.md` (12 decisions + failure-mode
table + distributed-systems review) plus the current tree's measurable
surfaces: the `/token` issuance path, the login/session-mint path, the
introspection path, the admin governance surface, and the proposed sqlite
store's snapshot model.

This is an advisory review of a **proposal**. The design's decisions are not
implemented (`Store` is `Policies()`-only; no sqlite package; no
`KindTokenPolicyChange`; no `WithTokenPolicyDefaultTTL`). All hot-path claims
about current code are **Verified** against this tree; all performance
numbers are **Predicted** — there are **no benchmarks and no SLOs anywhere in
the repo** (grep of `domains/tokenpolicy` for `Benchmark*`: zero hits;
`docs/` contains no SLO statement), so this review designs the baseline
rather than inventing targets.

## 1. Workload assumptions and evidence quality

**Assumed workloads (must be confirmed before load testing):**

| Workload | Rate assumption | Basis |
|---|---|---|
| `/token` issuance (all grants), policy store wired | high QPS; the dominant hot path | `dispatchTokenGrant` → `denyTokenScopeCombo` (`server_token.go:168`) runs on every request reaching dispatch; minting funnels through `ClampingIssuer.Issue` via `issuerForClient` (`server_helpers.go:67`) |
| Login / session mint | high QPS | `createSession` (`server_logout.go:357`) → `sessionPolicyCapExceeded` (`server_oauth.go:162`) |
| Introspection | high QPS (RS polling) | `introspectAccess` → `IntrospectionRenewExceeded` (`sso_protocol.go:477`) on every access-token introspection |
| Admin policy PUT/DELETE/GET | low QPS, tail-latency-sensitive | new surface; mirrors threataction CRUD |
| Policy-set size P | **Unknown** — no telemetry | no gauge exists; `sso_token_policy_*` metrics cover decisions, not cardinality (`platform/metrics/metrics_token.go:100-120`) |

**Evidence quality:** every mechanism below is a **Verified** call-site/path
claim with **Predicted** cost estimates. The repo has no `Benchmark*` tests in
`domains/tokenpolicy`, no load-test harness against `/token` with the policy
engine wired, and no SLO. "Baseline" columns in §3 are therefore measured
baselines to be established, not targets; where the design implies a target
(fail-open hot path, writer read-your-writes), the acceptance rule is a
regression bound, not an absolute number.

## 2. Findings

### F-P1 [High, Proposed-behavior] — Snapshot rebuild must not hold the snapshot lock across DB I/O or full-set rebuilds

- **Path/symbol:** design 决策 6 ("Mutations … rebuild both under the write
  lock") and 决策 10 (sqlite `Put`/`Delete`/`Refresh` = DB write + full-table
  read + per-row JSON unmarshal + snapshot rebuild, synchronous before the
  admin response). Hot-path reader: `Store.Policies` (memory
  `memory/store.go:41-48` today; sqlite snapshot per design).
- **Mechanism (Predicted):** if the sqlite store's refresh holds the snapshot
  mutex across `SELECT policy_json … ORDER BY name` + `json.Unmarshal` of
  every row + map/slice rebuild, every in-flight issuance/introspection
  (which takes `RLock` for `Policies()`) stalls for the whole refresh. At
  P=10k rules × ~1 KB JSON ≈ 10 MB of unmarshal ≈ 10–50 ms of **fleet-wide
  issuance stall per admin write** on that replica. The memory store's
  rebuild is µs-scale (slice + map copy) and harmless today; the sqlite store
  is the first durable wiring where the refresh is expensive.
- **Impact:** availability blip on the token-issuance hot path, triggered by
  an admin write — the exact inverse of the design's fail-open contract.
- **Recommendation (required, implementation constraint):** build the new
  snapshot (DB read + unmarshal + map/slice) **outside** the snapshot lock;
  take the lock only for the pointer swap. Same for memory `Put`/`Delete`
  (trivial today, cheap to do right). Never hold the lock across DB I/O.
- **Experiment:** `BenchmarkStorePut` with concurrent `Policies()` readers
  (§4 item 3): assert reader p99 is flat while `Put`/`Refresh` run at
  P ∈ {100, 1000, 10000}. Acceptance: reader p99 shift < 10% vs. idle.

### F-P2 [Medium, Verified] — Login path pays a session-enumeration DB query even when no policy uses `max_active_sessions`

- **Path/symbol:** `sessionPolicyCapExceeded` (`server_oauth.go:162-171`)
  calls `sessionMgr.ListByUser` **unconditionally** whenever a policy store
  and a session manager are wired — on every login, via `createSession`
  (`server_logout.go:357`). Only the active-sessions dimension can fire on
  this seam (its own doc comment says so, `server_oauth.go:177-180`).
- **Mechanism (Verified):** `Policies()` + `ListByUser` (a session-store
  enumeration; a DB/redis round trip depending on the backend) run before
  `Evaluate` — the query is wasted whenever no matching policy sets
  `MaxActiveSessions > 0`. Pre-existing (not introduced by this design), but
  the design's sqlite store does not address it and the governance surface is
  exactly what makes this seam more likely to be wired.
- **Impact:** one extra session-store round trip per login, permanent, even
  for deployments whose policies only use `max_ttl`/`require_renew_after`.
- **Recommendation (cheap, in scope):** after `Policies()` returns, pre-scan
  (O(P), no I/O) for any policy with `MaxActiveSessions > 0` that could
  match; skip `ListByUser` when none. Fail-open semantics unchanged.
- **Experiment:** rootcov login test asserting zero `ListByUser` calls with a
  TTL-only policy set; load item in §4.

### F-P3 [Medium, Verified] — Double full evaluation per issuance (gate + clamp)

- **Path/symbol:** per access-token issuance with a wired store: (1)
  `enforceTokenPolicy` (`server_helpers.go:85-115`, deny dimensions, called
  from `dispatchTokenGrant` via `denyTokenScopeCombo` / refresh seam), then
  (2) `ClampingIssuer.Issue` (`clamp_issuer.go:47-57`, TTL clamp) — two
  `Policies()` fetches + two full `Evaluate` passes + two metric bumps per
  token. Introspection: one pass. Login: up to two passes + the F-P2 query.
- **Mechanism (Verified):** the passes have different inputs (the gate lacks
  `RequestedTTL`; the clamp lacks refresh depth/sessions), so they are
  genuinely different seams — but the constant factor is 2× on the same
  O(P) work.
- **Impact:** negligible at small P (each pass is sub-µs to low-µs); it is
  the multiplier that turns the F-P5 cardinality risk into ms-scale latency.
- **Recommendation:** do **not** merge the seams (would couple the grant
  layer to the issuer layer and require plumbing a decision through
  `issuerForClient`); measure P first (§4 item 1). If P is small, accept and
  document. If P grows, the clientID index (F-P5) fixes both passes.
- **Experiment:** `BenchmarkEvaluate` at realistic P; the double-pass cost is
  then 2× the per-pass number.

### F-P4 [Medium, Proposed] — Admin write path is O(P) per write and O(P²) for bulk import; tail latency absorbs DB write + full refresh + bus publish

- **Path/symbol:** design 决策 9/10 (`Put` = upsert + synchronous full-set
  refresh before the response) + 决策 8 (synchronous best-effort bus publish;
  etcd `Publish` = `Grant`+`Put`, `context.Background()`, verified
  `platform/cluster/etcd.go`).
- **Mechanism (Predicted):** each `Put`/`Delete` costs the single-statement
  DB write (serialized on the SQLite single-writer lock with `busy_timeout`
  when replicas share a file) + O(P) refresh + up to two etcd round trips.
  Importing N rules via N `PUT`s is O(N²) in refresh work.
- **Impact:** admin tail latency grows with P and bus latency. The designed
  seed path (config → first-boot seed) is the bulk-import path and avoids the
  quadratic; per-rule `PUT` remains the interactive path. Bounded and
  admin-trusted, but unbounded in the design.
- **Recommendation:** keep refresh build-outside-lock (F-P1); document that
  bulk import is done via seed at first boot, not N `PUT`s; benchmark the
  refresh at N ∈ {100, 1000, 10000} to publish a number. Do not add a batch
  `Put` to the SPI unless the benchmark shows a real need.
- **Experiment:** §4 item 3 latency table.

### F-P5 [Medium, Proposed] — Unbounded policy count = unbounded hot-path cost and snapshot memory

- **Path/symbol:** `Evaluate` (`evaluate.go:28-46`) is O(P × (selector
  scopes + block combos)); `matches`/`violatesScopeCombos`/`scopePresent`
  (`evaluate.go:127-200`) are linear in scopes with wildcard prefix scans.
  The admin surface (决策 7) has no policy-count quota; the security review
  accepts 10⁵ policies as admin-trusted.
- **Mechanism (Predicted):** at P=10⁵ and ~20 scopes, one pass ≈ 5–20 ms;
  ×2 passes per issuance + 1 per introspection, on every token request.
  Snapshot memory grows O(P × avg policy size). The sqlite snapshot loads
  the whole set at boot and on every refresh (F-P1/F-P4).
- **Impact:** a governance set this large degrades the token plane itself —
  the fail-open contract still holds (errors skip), but latency is a soft
  availability risk; no mechanism detects it today (no cardinality metric).
- **Recommendation:** (a) measure P first (§4 item 1); (b) if the benchmark
  supports it, add a per-client index (`map[clientID][]Policy` plus the
  fleet-wide `""` bucket) built **as an order-preserving partition** so the
  deny-reason precedence documented in 决策 6/9 is unchanged (index buckets
  must keep original relative order; this is the same class as the
  documented memory-vs-sqlite label drift, so it needs the same doc note);
  (c) consider a documented count cap with `400 invalid_policy`. Do not build
  the index speculatively before the measurement.
- **Experiment:** §4 item 1 acceptance rule is exactly this decision gate.

### F-P6 [Info, Verified + Proposed] — Hot-path `Policies()` must stay zero-copy, zero-alloc, zero-DB

- **Path/symbol:** memory `Policies()` returns the backing slice under
  `RLock` (`memory/store.go:41-48`) — zero alloc today. The sqlite store's
  `Policies()` must do the same with its snapshot; **it must not** copy per
  call, re-parse JSON per call, or touch the DB (threataction's sqlite
  `List` does a full query per call — that precedent must NOT be copied for
  the hot path; the design's snapshot model is the correct departure).
- **Mechanism (Predicted):** a per-call copy at issuance frequency would add
  an allocation and O(P) copy to every token mint; a per-call DB read would
  be catastrophic. The design says the right thing (决策 10); this finding
  pins it as a benchmarked invariant, and adds: `Get` should serve from the
  snapshot map (O(1), and consistent with the enforcement view) rather than
  a per-request DB query (also answers database review F-DB-3 in perf terms).
- **Impact:** none today; guard against implementation drift.
- **Experiment:** `BenchmarkPolicies` asserting 0 allocs/op and flat ns/op
  after `db.Close()` (fail-open proof, also QA's request).

### F-P7 [Info, Proposed] — One-time and recovery costs are small but should be timed

- **Mechanism (Predicted):** boot = `migrate.Run` (`BEGIN IMMEDIATE` on a
  pinned connection, `platform/migrate/migrate.go:161-200`) + seed-if-empty +
  full snapshot load: one-time O(P), serialized with sibling stores on a
  shared file. `KindControlPlaneRestore` triggers a full refresh on **every**
  replica simultaneously (thundering herd on the shared file) — trivial at
  small P, worth timing at large P. The `RenewExceeded`/`RenewAt` NaN guard
  proposed by the security review adds an O(1) float check on the
  introspection path — no measurable impact.
- **Impact:** none at expected scale.
- **Experiment:** boot-time measurement in §4 item 5; no code change.

## 3. Critical-path table

Baselines are **to be measured** (no SLOs or benchmarks exist); targets are
proposed regression bounds, not supplied SLOs.

| Path | Baseline (today, Verified) | Target (Proposed) | Bottleneck | Profiling method |
|---|---|---|---|---|
| `/token` issuance, store wired | 2× (RLock `Policies` + `Evaluate` O(P)) + 2 metric bumps | p99 within +20% of unwired at P ≤ 100 | double `Evaluate` pass (F-P3), O(P) scan (F-P5) | `pprof` CPU on `dispatchTokenGrant`/`ClampingIssuer.Issue`; `BenchmarkEvaluate` |
| Login / session mint | `Policies` + `ListByUser` (unconditional) + `Evaluate` | `ListByUser` skipped when no matching `MaxActiveSessions` rule (F-P2) | session-store round trip per login | rootcov counter on `ListByUser`; trace span timing |
| Introspection (access token) | `Policies` + `Evaluate` + `RenewExceeded` + metric | flat vs. today (design adds nothing hot) | `Evaluate` O(P) | `pprof` on `introspectAccess`; `BenchmarkEvaluate` |
| Admin `PUT`/`DELETE` (sqlite, new) | n/a | p95 < 50 ms at P ≤ 1000; **zero hot-path stall** (F-P1) | single-writer SQLite lock, O(P) refresh, etcd publish (F-P4) | `BenchmarkStorePut`; lock-hold-time trace; bench `Publish` |
| Admin `GET` by name (new) | n/a | snapshot map read, O(1) | `Get` implementation choice (F-P6) | `BenchmarkStoreGet` |
| Boot (sqlite + seed, new) | n/a | < 2 s at P ≤ 10k (proposed) | migrate `BEGIN IMMEDIATE`, seed writes, snapshot load | boot timing log; `BenchmarkNew` |

## 4. Prioritized benchmark / load plan

All items are new (no harness exists). Ordered by decision value:

1. **`BenchmarkEvaluate` — the cardinality decision gate (F-P5).**
   Dataset: P ∈ {0, 1, 10, 100, 1000, 10000}, scopes ∈ {5, 20}, combos ∈
   {0, 3}; one fleet-wide rule + per-client rules; wildcard selectors.
   Concurrency: single-goroutine (pure function). Duration: `-benchtime=1s
   -count=10`. Acceptance: report ns/op + allocs/op; the P at which one pass
   crosses 50 µs becomes the documented cap rationale (or the trigger to
   build the clientID index). Regression comparison: re-run after the
   `DefaultTTL` min-clamp change (决策 3 adds one comparison per policy —
   expect < 5% delta).
2. **`BenchmarkPolicies` — zero-alloc invariant (F-P6).** Memory store
   (today) vs. sqlite snapshot (new): `-race -count=10+`, assert 0
   allocs/op, flat ns/op, and identical results after `db.Close()`.
   Acceptance: allocs/op == 0 and ns/op within 2× of the memory store.
3. **`BenchmarkStorePut` with concurrent readers — the F-P1 gate.**
   Dataset: P ∈ {10, 100, 1000, 10000} pre-seeded rows; 1 writer doing
   sequential `Put`s; 8 reader goroutines hammering `Policies()`.
   Duration: 10 s. Acceptance: reader p99 shift < 10% vs. idle (this fails
   if the refresh holds the snapshot lock); publish the writer p95 table.
   Regression comparison: re-run after any store refactor; this is the test
   that keeps the sqlite store from becoming a hot-path stall.
4. **Login-path regression (F-P2).** Rootcov/server test: with a wired store
   + session manager and a TTL-only policy set, assert `ListByUser` is
   invoked 0 times per login; with a `MaxActiveSessions` rule, 1 time.
   Acceptance: 0/1 as specified. This is a behavior pin, run in CI, not a
   load test.
5. **End-to-end `/token` load comparison (F-P3 baseline).** Dataset: 50-rule
   set (10 clients × 5 rules + fleet-wide default); client-credentials +
   authorization-code grants; concurrency 100; duration 60 s. Acceptance:
   wired vs. unwired p99 delta ≤ +20% and no alloc/op growth (this is the
   "policy engine is cheap when wired" regression comparison). If the delta
   exceeds the bound, the F-P5 index becomes required, not optional.
6. **Two-server shared-DB admin write (F-P4).** Dataset: 1 PUT via server A;
   assert B converges after invalidation flush. Duration: single-shot, 10
   iterations. Acceptance: A's PUT p95 < 50 ms at P=100; B's convergence
   < 1 s (baseline only — no SLO exists). This doubles as the distributed
   review's integration gate.
7. **Boot-time measurement (F-P7).** `sqlite.New` against a pre-seeded
   10k-row file: report open+migrate+load latency. Acceptance: < 2 s
   (proposed baseline, not a supplied SLO).

## 5. Optimization risks and measurements still needed

**Risks of the proposed optimizations:**

- **ClientID index (F-P5):** if built as a plain `map[clientID][]Policy`
  partition, it changes the iteration order of matching policies and thus
  the deny-reason label for overlapping rules — the exact drift class 决策 6/9
  already document. Mitigation: build as an order-preserving partition
  (stable filter over the original slice, fleet-wide `""` bucket merged by
  original index) and extend the existing divergence doc note. Do not build
  until `BenchmarkEvaluate` shows P large enough to matter.
- **F-P2 pre-scan:** must not change fail-open semantics — a `Policies()`
  error still returns false (allow) before any scan. Keep the scan inside
  the existing error path.
- **Do NOT pursue:** (a) caching `Evaluate` decisions — inputs include
  client, scopes, kind, refresh depth, session count; a cache adds
  invalidation coupling and staleness for an O(P) pass; (b) merging the
  gate + clamp passes (F-P3) — couples grant layer to issuer layer, saves a
  constant factor that is only worth recovering after the cardinality
  measurement; (c) per-call defensive copies of `Policies()` output — QA
  finding F5 (slice aliasing via `Get`) must be fixed by contract/COW in the
  store, not by copying on the hot path.
- **Two-server shared-DB topology:** SQLite single-writer serializes admin
  writes with `busy_timeout` retry; concurrent admin PUTs from two replicas
  add tail latency under contention. Documented LWW; no optimistic locking —
  acceptable at admin QPS, but the load plan item 6 should include a
  two-writer variant (2 writers, 10 PUTs each) to bound the tail.

**Measurements still needed (all Missing/Unknown today):**

1. Real production P (policy count) and per-client rule distribution — no
   gauge exists; propose a `sso_token_policy_active_rules` gauge (product
   change, out of scope here) or a one-off inventory query at rollout.
2. `ListByUser` cost per login on each supported session backend (drives
   F-P2's actual savings).
3. SQLite refresh cost vs. P on the target filesystem (shared POSIX file —
   F-P1/F-P4 numbers).
4. Bus publish latency (memory vs. etcd) contribution to admin PUT tail
   (F-P4).
5. Actual scope-set cardinality per request (drives the combos scan term in
   `Evaluate`).
6. All SLOs: none exist in the repo; the SRE review's proposed login-success
   SLI is the prerequisite for turning any "target" column above into a
   binding number.

**Bottom line:** the design keeps the hot path disk-free and O(1) at the
store boundary — the correct architecture — and every Verified hot-path cost
today is a small constant (sub-µs to low-µs per pass at realistic P). The
three things that could turn this into a latency incident are all
implementation-stage: holding the snapshot lock across DB I/O during
refresh (F-P1, the #1 risk), the unconditional `ListByUser` on login
(F-P2, pre-existing but in scope), and unbounded policy cardinality
(F-P5, needs the §4.1 measurement before any fix is justified). No benchmark
or SLO exists to validate any of this today; §4 defines the baseline.
