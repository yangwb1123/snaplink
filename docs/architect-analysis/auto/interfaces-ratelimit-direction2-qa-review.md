# QA Review: `interfaces/ratelimit` direction 2 — quota visibility (design stage)

Review of `docs/auto/interfaces-ratelimit-direction2-design.md` (revision
`62b6f142` "Stage: design"; design and spec are committed, zero
implementation of the three decisions exists in the tree). Every planned
test below is therefore **Proposed**; every baseline claim was re-verified
against the current working tree and the committed gates.

Evidence labels: **Verified** = reproduced in this review; **Partial** =
the design states it but evidence is indirect; **Proposed** = planned, not
yet implemented; **Missing** = gap found.

---

## 1. Test inventory and commands actually run for this revision

| Command | Result | What it establishes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | Whole-tree compile + vet for the reviewed revision |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | File-size (500-line), complexity, fan-out, maxdepth, layer gates the design's placements must satisfy |
| `go test ./interfaces/ratelimit/... ./infrastructure/redis/ -race -count=1` | PASS | All three backends' unit suites incl. the miniredis limiter tests, middleware tests, fuzz seed corpus, race |
| `go test ./test/ -run 'TestRateLimitE2E' -v -count=1` | PASS (4/4) | The e2e net the design says must not break (Retry-After on 429, /health default bucket, /metrics never limited) |
| `go test ./test/ -count=1` | PASS (full package, 20.5s) | Whole cross-server integration package incl. `auth_signup_test.go` (the `stubSignupRateLimiter` migration surface) |
| `go test ./protocols/selfservice/... -count=1` | PASS | `selfservicecore` + signup tests incl. `signup_test.go`'s `stubRateLimiter` 429-path test |
| `go test ./cmd/sso-server/ -run 'RateLimit|ClosePolicyLimiters|ReadyCheck' -count=1` | PASS | `rate_limit_reload_test.go` (hot-swap), `readycheck_test.go` (`pingerLimiter`), `security_test.go` (policy build) |
| `go test ./interfaces/sso/ -run 'TestClientRegistrationRateLimit' -count=1` | PASS | DCR direct-caller tests (`client_registration_ratelimit_test.go` — quota.go path) |
| `go test ./interfaces/admin/ -run 'TestHTTPMiddleware_RateLimit' -count=1` | PASS | Admin gate tests (`middleware_test.go` — governance.go path) |
| `go test ./test/backendsemantics/ -count=1` | PASS | Cross-backend semantic suite — NOTE: contains **no** ratelimit coverage today |
| `go test ./interfaces/ratelimit/ -run Fuzz -fuzz FuzzMemoryLimiterAllow -fuzztime 5s` | PASS (404k execs) | Fuzz seed corpus healthy; only asserts no-panic, no Allowance invariants |
| `go test ./interfaces/ratelimit/ -run Fuzz -fuzz FuzzMemoryLimiterStalePrune -fuzztime 5s` | PASS (453k execs) | Same |
| `go test ./interfaces/ratelimit/ -run '^$' -bench 'BenchmarkMemoryLimiterAllow' -benchmem -count=1` | baseline captured | SingleKey **178.3 ns/op**, ManyKeys 100/1000/10000 **191.2/222.1/447.1**, Parallel **89.3**; all **64 B/op, 1 alloc/op** (existing alloc = FNV-32a hash, unchanged by the design) |

NOT run (deliberately, design-stage): `make ci` (includes `race ./...`,
nested modules, config validation, route-contract), `make chaos-test`
(manual fault-injection suite — no ratelimit entry exists), `make
bench-gate` (opt-in perf gate), `make load-test` (manual k6). These are
implementation handoff gates; see §6.

## 2. Design-doc claim verification (traceability)

All of the design's architectural findings re-checked against code:

| Design claim | Evidence | Status |
|---|---|---|
| `selfservicecore.RateLimiter` (deps.go:21) is byte-identical to `ratelimit.Limiter`; Go has no covariance | deps.go:21 `Allow(key string) (ok bool, retryAfter time.Duration)` — verbatim | Verified |
| `WithSelfServiceSignupRateLimiter(ratelimit.NewMemoryLimiter(...))` is documented public wiring | options_passwd.go:125-139, doc example `ratelimit.NewMemoryLimiter(3.0/60, 3)` | Verified |
| Four direct consumers: middleware x2, quota.go:154, governance.go:314, signup.go:96 | All four destructure `ok, retryAfter` from `Allow` | Verified |
| Memory deny-all returns `(false, 0)`; ~292-year InfDuration sentinel exists | ratelimit.go:140-147 (`perSecond <= 0` after `Cancel()`); test `TestMemoryLimiter_DenyAllRateZero_RetryAfterIsZero` | Verified |
| SQLite denyAll branch short-circuits without persisting, returns `(false, 0)` | sqlite_limiter.go `consumeToken` + `Allow`; `TestSQLiteLimiter_DenyWhenRateAndBurstExhausted` | Verified |
| Redis deny-all = `{limit:1, window:365d}`, value-indistinguishable from legit config | `NewLimiterFromRate` perSecond<=0 branch; `TestLimiter_DenyAllFromRate` | Verified |
| Redis `allowScript` returns `{count, pttl}`; count discarded today; pttl<0 falls back to full window | ratelimit.go:96-110 (script), Allow pttl handling | Verified |
| Memory `calls` unexported; SQLite prune is ms-clock 1/64, not call-based | `calls atomic.Uint64`; `(nowNs/int64(time.Millisecond))%64 != 0` | Verified |
| `Buckets()` locks all shards; inline prune runs under one shard lock → hook there would self-deadlock | ratelimit.go:200-210 vs Allow's `sh.mu.Lock()` + `pruneLocked` | Verified |
| `limiterFor` has no out-of-package callers; returns bare `Limiter` | Only middleware.go:127,180 call it; unexported | Verified |
| Zero schema/script changes needed | SQLite table + Redis Lua untouched by the mapping | Verified |
| `sql.Open` + `SetMaxOpenConns(1)` (SQLite COUNT must stay in the same tx) | sqlite_limiter.go:80 | Verified |
| Metrics: single `sso_rate_limit_hits_total`; unconditional registration is the repo pattern | consts.go:110; `registerRateLimitMetrics` called unconditionally in `NewWithRegistry` (metrics_ctor.go) | Verified |
| `x/time` `Tokens()` exists at v0.15.0 rate.go:94 | `go doc` + module cache | Verified |
| openapi.yaml: no rate-limit response headers today; Retry-After only on the 503 degradation path (~line 6151) | grep: zero `RateLimit` matches in openapi.yaml; 6151 is degradation 503 | Verified |
| observability.md has exactly one rate-limit row (~line 43) | table row `sso_rate_limit_hits_total` | Verified |
| e2e asserts Retry-After on 429 (won't break: normal buckets keep retry>0) | ratelimit_e2e_test.go:111 | Verified |
| `server_token.go:370` and `degradation.go:57` `Allow` are unrelated types | x/time `rate.Limiter.Allow()`; degradation `Policy.Allow(mode, ...)` | Verified |
| Bench gate covers the allow-path benchmarks | `ops/deploy/benchgate/benchmarks.yaml`: `./interfaces/ratelimit` `^BenchmarkMemoryLimiterAllow`, 10% threshold | Verified |

Discrepancies found in the design doc (see §4 findings F7/F8):

1. "ratelimit_test.go 的 `var _ Limiter` 断言保持" — **no such assertion
   exists anywhere for `MemoryLimiter`**; only `sqlite_limiter.go:255` and
   `infrastructure/redis/ratelimit.go:168` carry `var _ Limiter`
   assertions. The plan must ADD the Memory-side assertion, not keep one.
2. "sso 不 import ratelimit 的约束不变" — reversed. `interfaces/sso`
   **does** import `interfaces/ratelimit` (quota.go, options_grants.go);
   the actual constraint is that `ratelimit` must not import `sso`
   (consts.go comment). No placement impact, but the rationale text is
   wrong.
3. Migration table ("完整迁移面") is **incomplete**: two test doubles
   implementing the `selfservicecore.RateLimiter` shape are missing —
   `test/auth_signup_test.go:235` (`stubSignupRateLimiter`) and
   `protocols/selfservice/testhelpers_test.go:393` (`stubRateLimiter`,
   used by `signup_test.go:92` to force the 429 path). Both break
   compilation on commit 1 exactly like the design's own key discovery
   (risk #1). The compile gate catches them, but the table's
   completeness claim is false and commit 1 undercounts its migration
   surface.

## 3. Requirement-to-test matrix

Spec acceptance criteria × current coverage × planned coverage. Status:
**V**erified (tested today), **P**artial, **M**issing (untested today),
**Proposed** (planned by this review).

### 决策一 — SPI `Allow` returns `Allowance`

| # | Requirement | Today | Planned test / acceptance assertion |
|---|---|---|---|
| 1 | Build/vet + gates green; no stale call sites; `var _` assertions updated | V (build/vet/gates pass; redis+sqlite assertions exist) | **P**: add `var _ Limiter = (*MemoryLimiter)(nil)` (ratelimit) and `var _ selfservicecore.RateLimiter = (*MemoryLimiter)(nil)` (selfservicecore); grep proof: no `Allow(string) (bool, time.Duration)` implementors remain outside the three backends |
| 2 | Memory: `Remaining` monotonically decreasing to 0; refill shortens `ResetIn`, `Remaining` capped at `Limit == burst`; `perSecond<=0` → all-zero | P (ok/retry semantics tested; no Remaining/ResetIn assertions) | **P**: extend `ratelimit_test.go` — after each of burst calls assert `Remaining == burst-i`; after refill assert `ResetIn` shrinks; deny-all rejects carry `{false,0,0,0,0}` AND the three allowed-within-burst calls return finite `ResetIn == 0` (see F3) |
| 3 | SQLite: two instances (cross-replica) read consistent `Remaining`; reject path does not persist but returns correct value | P (`TestSQLiteLimiter_CrossInstanceSharing` asserts ok/deny only) | **P**: extend with `Remaining` equality across limA/limB; after a reject, a fresh SELECT (or third instance) still sees the pre-reject tokens |
| 4 | Redis (miniredis): `Remaining = limit - count` decreasing; window flip restores `Limit`; deny-all reject `RetryAfter == 0` | P (`TestLimiter_UnderAndOverLimit`, `WindowResetAfterTTL` assert ok/retry only; `DenyAllFromRate` doesn't assert retry) | **P**: extend with `Remaining`/`Limit`/`ResetIn` assertions; `NewLimiterFromRate(rdb, 0, …)` deny path `RetryAfter == 0` and `Limit == 0` (denyAll marker; see F6) |
| 5 | fail-open (SQL/Redis error) → `{OK:true}`, no panic, no false quota | P (Redis only: `coverage_test.go` `ratelimit_fail_OPEN`) | **M** → **P**: SQLite fail-open test (closed DB / poisoned tx) asserting `{OK:true}` + all-zero quota; middleware-level: no X-RateLimit-* headers (决策二 #4) |
| 6 | Mapping rules documented in package doc | M | **P**: doc comment update in the same commit |

### 决策二 — X-RateLimit-* headers

| # | Requirement | Today | Planned test / acceptance assertion |
|---|---|---|---|
| 1 | Allowed path writes `Limit == burst`, `Remaining` consistent, `Reset` plausible future epoch; unmatched rule writes nothing | M (no header assertions beyond Retry-After) | **P**: middleware test — allowed request: three headers present, `Remaining` matches bucket state; nil-rule path: none of the three headers |
| 2 | 429 carries Retry-After (ceil) + three headers; `Remaining` 0 ⇒ next request 429 (self-consistency) | P (Retry-After tests exist) | **P**: extend `TestMiddleware_Returns429WithRetryAfter`; add cross-backend invariant `X-RateLimit-Reset >= now + Retry-After` (holds for bucket AND window backends) |
| 3 | deny-all byte-identical across Memory/SQLite/Redis: 429 body + `X-RateLimit-Remaining: 0`, no Retry-After/Reset/Limit | M (no middleware test is backend-parameterized; all use MemoryLimiter) | **P**: table-driven middleware test parameterized by backend (external test pkg can import `infrastructure/redis` without a cycle); assert header SET and body bytes identical, `redis.NewLimiterFromRate` deny `RetryAfter == 0` |
| 4 | fail-open injection: no quota headers, request passes | M | **P**: middleware over a `downClient` Redis limiter and a closed-DB SQLite limiter — 200, zero X-RateLimit-* headers |
| 5 | `DynamicMiddleware` hot swap: new headers reflect new bucket params | P (admin `TestHTTPMiddleware_RateLimitPolicyStoreHotSwap` exists) | **P**: extend the ratelimit-level PolicyStore test to assert `X-RateLimit-Limit` changes after `Set` |

### 决策三 — observability

| # | Requirement | Today | Planned test / acceptance assertion |
|---|---|---|---|
| 1 | `requests_total{result,tenant}`: allowed increments `{result="allowed",tenant="unknown"}`; rejected `{result="rejected",tenant=<resolved>}`; nil Metrics no-op | M | **P**: extend `ratelimit_metrics_test.go` pattern (`rateLimitHitValue` helper → generic gather helper); assert both counters after one allow + one reject; TenantKeyFunc still called ONLY on reject (extend existing `calls`-counting test) |
| 2 | `remaining{policy}` updates at 1/64 sample, equals `Allowance.Remaining`; unknown tenant on reject without TenantKeyFunc | M | **P**: fresh middleware per test, 64 calls → deterministic sample (counter-based); assert gauge == Allowance.Remaining; **skip sample when `a.Limit == 0`** (fail-open guard, see F2) |
| 3 | `buckets` gauge rises/falls with key creation/timeout (Memory, short stale window) | M | **P**: `NewMemoryLimiterWithStalePrune` + `StartPruner(5ms)` + 2s deadline pattern (mirror `TestMemoryLimiter_StartPrunerSweepsAllShards`); SQLite via clock-controlled `s.now` sample point (see F4) |
| 4 | Bench: allow path no significant regression; `-race` green | V (baseline captured this review) | **P**: re-run `-bench BenchmarkMemoryLimiterAllow -benchmem` before/after on the same machine; allocs must stay 1/op, B/op 64; record in commit-3 message; `bench-gate` (10%) if baseline re-recorded |
| 5 | observability.md three new rows match implementation | M | **P**: doc rows incl. "Redis backend never updates `sso_rate_limit_buckets`" and "Memory gauge updates only when `prune_interval` is set" |
| 6 | Existing `sso_rate_limit_hits_total` unchanged (name/labels/reject semantics) | V (tested today) | **P**: existing tests keep passing unmodified; add one 429 → both counters increment (documented double-count) |

## 4. Findings (severity-sorted)

### F1 — High: migration table omits two `selfservicecore.RateLimiter` test doubles
- **Evidence**: `test/auth_signup_test.go:235` `stubSignupRateLimiter` and
  `protocols/selfservice/testhelpers_test.go:393` `stubRateLimiter`
  implement `Allow(string) (bool, time.Duration)` — the exact parallel-SPI
  shape the design identifies as its key discovery (risk #1). The design's
  "完整迁移面清单" lists only `pingerLimiter` and `closeCountingLimiter`.
- **Impact**: commit 1 undercounts its surface; the doc's completeness
  claim is false. Compile gate catches the break, so no shipped risk — a
  planning/review defect, not a runtime one.
- **Test to add**: none new — the two stubs must be migrated in commit 1.
  Acceptance assertion: after commit 1,
  `grep -rn "func (.*) Allow(" --include="*.go" .` shows exactly the three
  backends (plus unrelated `domains/tokenexchange` and degradation types).

### F2 — High: fail-open quota would pollute `sso_rate_limit_remaining`
- **Evidence**: design §决策三① samples every rule hit and records
  `Allowance.Remaining`. Fail-open returns `{OK:true, Remaining:0, Limit:0}`.
  At 1/64 the gauge would record **0** during a backend outage — the
  header rule (决策二) deliberately suppresses fail-open (three-way table)
  but the sampling rule as written does not.
- **Impact**: a storage partition would paint every policy at zero
  remaining — exactly the "client mis-limits itself on wrong data" the
  design rejects for headers, now reintroduced on the ops side. Alerting
  on the gauge would fire during outages.
- **Test to add**: `TestMiddleware_RemainingGaugeSkipsFailOpen` — wire a
  `downClient` Redis limiter (pattern exists in
  `infrastructure/redis/coverage_test.go`), make 64+ calls, assert the
  `sso_rate_limit_remaining{policy=...}` series is absent. Acceptance:
  gauge changes only when `Allowance.Limit > 0`.

### F3 — Medium: allowed-path division by zero for deny-all configs
- **Evidence**: the mapping `ResetIn = (burst - tokens)/perSecond` runs on
  **both** paths. With `perSecond <= 0` and `tokens >= 1` (allowed within
  the burst — `TestMemoryLimiter_DenyAllRateZero_RetryAfterIsZero` proves
  burst is honored), the quotient is `+Inf`; converting `Inf` to
  `time.Duration` is implementation-defined garbage. The design's guard
  ("防除零", "前移") is described only around the reject branch.
- **Impact**: `X-RateLimit-Reset` on deny-all allowed requests is a
  garbage epoch; `ResetIn` for SQLite the same. Latent, config-triggered
  (per_sec<=0 prefix rules are constructible via YAML — prefix limiters
  are built unconditionally in `memoryRateLimitPolicy`).
- **Test to add**: `TestMemoryLimiter_DenyAll_AllowedPathFinite` —
  `NewMemoryLimiter(0, 3)`: the three allowed calls must return
  `ResetIn == 0` (finite), 4th call the all-zero deny shape. Same for
  SQLite with the controlled clock (`TestSQLiteLimiter_RefillAfterIdle`
  pattern). Acceptance: `a.ResetIn` is always finite and `>= 0` across
  all backends and paths.

### F4 — Medium: SQLite bucket-gauge reporting path is unspecified
- **Evidence**: design §决策三③ says SQLite "复用 `pruneStale` 的采样点
  执行 SELECT COUNT(*)" but commit 3's change list names only
  `MemoryLimiter.SetBucketObserver`; there is no stated mechanism for a
  `SQLiteLimiter` to reach `Metrics` (the limiter knows nothing about
  metrics).
- **Impact**: commit 3 cannot be implemented as written; the SQLite gauge
  silently never updates (worse than documented).
- **Test to add**: the design must specify the same unexported-observer +
  exported nil-safe setter on `SQLiteLimiter`, fired inside the sampled
  tx, wired from `serverbuildplatform.sqliteRateLimitPolicy`. Acceptance
  test: clock-controlled `s.now` at a `(nowNs/ms)%64 == 0` boundary, N
  keys created, assert gauge == N; advance clock, same sample point,
  assert drop.

### F5 — Medium: metrics.go is at 494/500 lines — struct fields cannot move to a new file
- **Evidence**: `wc -l platform/metrics/metrics.go` = 494; the design adds
  three struct fields + doc comments (~15-20 lines) to the `Metrics`
  struct (metrics.go:403). "文件预算不够则新开 ratelimit_quota.go" cannot
  host struct fields — Go structs are single declarations.
- **Impact**: commit 3 trips `TestMaintainability_` (500-line gate) unless
  the plan also moves the `Metrics` struct (or a field block) to a new
  file, e.g. `metrics_types.go`. `metrics_ctor.go` (497) fits one
  registration line (498) but has zero slack.
- **Test to add**: none — plan-level fix. Acceptance: `go test -run
  'TestMaintainability_' .` green after commit 3.

### F6 — Medium: no cross-backend conformance test for the byte-identity claims
- **Evidence**: spec acceptance 决策二 #3 (three backends byte-identical
  deny-all) and the design's "三后端字节一致" claims have no test vehicle
  today: every middleware test uses `MemoryLimiter`;
  `test/backendsemantics/` (the repo's memory-vs-sqlite equivalence suite,
  run every PR) has zero ratelimit coverage.
- **Impact**: the core uniformity promise of the change is only ever
  asserted per-backend in isolation; a drift (e.g. a missed `denyAll`
  marker) ships green.
- **Test to add**: `middleware_backends_test.go` (package `ratelimit_test`,
  which may import `infrastructure/redis` — external test packages break
  no cycles) parameterizing: normal reject, deny-all, fail-open ×
  Memory/SQLite/Redis(miniredis). Acceptance: identical status, body
  bytes, and header SET (presence/absence, not values, for epoch headers);
  `Redis` deny-all reject `RetryAfter == 0` and no `X-RateLimit-Reset`.

### F7 — Medium: client-visible divergence for direct 429 callers is an unstated non-goal
- **Evidence**: after commit 2 only the middleware writes X-RateLimit-*;
  the three direct consumers (`quota.go` /register DCR,
  `governance.go` admin gate, `signup.go` /auth/register) keep Retry-After
  only. An operator reading the new docs ("429s carry X-RateLimit-*")
  will not see them on those three surfaces.
- **Impact**: doc/behavior mismatch on credential-shaped endpoints —
  precisely where rate-limit clients care most.
- **Fix**: record the non-goal explicitly in the design's breakage table
  and in observability.md/openapi notes ("emitted by the global
  middleware only"). Optionally note it in `docs/error-codes.md`'s
  rate-limit section.

### F8 — Low: factual errors in the design doc
- "ratelimit_test.go 的 `var _ Limiter` 断言保持": no such assertion
  exists (only sqlite_limiter.go:255, redis ratelimit.go:168). Plan
  should ADD `var _ Limiter = (*MemoryLimiter)(nil)` in addition to the
  selfservicecore-side assertion already proposed.
- "sso 不 import ratelimit 的约束不变": reversed; sso imports ratelimit.
  No impact on header-constant placement.

### F9 — Info: ABI claim inaccurate, conclusion holds
- `Allowance` is 33+ bytes (bool + pad + 2×Duration + 2×int = 40 bytes
  laid out); amd64 aggregates >32 bytes return via caller stack slot, not
  registers. Still zero heap allocation — the "no alloc change" conclusion
  stands. Verify with benchmem (must stay 1 alloc/op, 64 B/op) rather
  than ABI reasoning.

### F10 — Info: fuzz harnesses assert only no-panic
- `FuzzMemoryLimiterAllow`/`StalePrune` never assert Allowance invariants.
  Cheap oracle: `Remaining ∈ [0, Limit]`, `ResetIn >= 0`, finite, and
  deny-all shape all-zero. Extend in commit 1 — the fuzz corpus then
  guards the new mapping rules for free.

## 5. Prioritized scenario list

Priority P0 = gate/compile, P1 = correctness, P2 = boundary, P3 = race/recovery.

| Pri | Path | Scenario | Acceptance assertion |
|---|---|---|---|
| P0 | All | Commit-1 compile sweep | `go build ./...` green with zero remaining old-signature implementors (grep proof) |
| P1 | Middleware | Normal allow → headers; next request within burst | `X-RateLimit-Limit == burst`, `Remaining` decrements 1 per request, `Reset` in `[now, now+ε]` (±1s second-granularity tolerance) |
| P1 | Middleware | Drain to 0 → 429 with Retry-After ceil + three headers | `Remaining == 0` on the 429; `X-RateLimit-Reset >= now + Retry-After` (bucket and window backends) |
| P1 | All backends | deny-all config (per_sec<=0): Memory/SQLite/Redis | Byte-identical 429 body + header SET: only `X-RateLimit-Remaining: 0`; no Retry-After, no Reset, no Limit (F6) |
| P1 | All backends | deny-all allowed-within-burst (per_sec<=0, burst>0) | Finite `ResetIn == 0`, allowed requests pass until burst drained (F3) |
| P1 | Middleware | fail-open (Redis down / SQLite closed) | Request passes (200), zero X-RateLimit-* headers, gauge NOT updated to 0 (F2) |
| P1 | Direct callers | /register, admin gate, /auth/register 429s | Unchanged bytes: Retry-After ceiling + `rate_limited` body; no X-RateLimit-* (documented non-goal, F7) |
| P2 | Middleware | Unmatched rule / nil Default | Identity path: no headers, no counters, no sampling |
| P2 | Metrics | One allow + one reject | `requests_total{allowed,unknown}` and `{rejected,<tenant>}` both == 1; TenantKeyFunc called once (reject only) |
| P2 | Metrics | 64 calls → sample fires | `remaining{policy}` == last `Allowance.Remaining`; policy label = prefix string or "default"; fresh middleware per test (closure-local counter) |
| P2 | Memory/SQLite | Bucket gauge rise/fall | Key creation raises gauge; stale timeout lowers it (Memory: StartPruner + deadline pattern; SQLite: clock-controlled sample) |
| P2 | Dynamic | Hot swap policy mid-traffic | Headers and `{policy}` label reflect the new Policy from the next request; sampling counter persists |
| P3 | Concurrency | Parallel Allow + sampled gauge (mixed policies) | `-race` green; gauge values always equal some valid Allowance, never torn |
| P3 | Concurrency | `SetBucketObserver` vs pruner sweep | Wired before StartPruner per builder order; `-race` green; `Close` detaches cleanly (no panic, no leak) |
| P3 | Recovery | Redis recovers after fail-open window | Next Allow returns real quota again (no stuck state); sampling resumes with real values |
| P3 | Migration | Signup 429 with real backend limiter | Wire `WithSelfServiceSignupRateLimiter(ratelimit.NewMemoryLimiter(...))` (the documented public pattern) → 429 after burst, Retry-After ceiling preserved |

## 6. CI/manual-suite gaps, flake risks, fixtures, exit criteria

### Suite distinction (verified from Makefile + CHECKS_REGISTRY)
- **Default CI** (`make ci`): fmt, vet, `race ./...`, build, examples,
  proto-lint, ci-modules, config-validate-all, modules-check, smoke,
  route-contract, capabilities, sdk-surface, profiles-evidence. Plus the
  committed gates (`TestMaintainability_|TestArchitecture_`). Runs on
  every PR — this change's first-line gate.
- **Tagged/manual suites** relevant here:
  - `make backend-semantics` (memory-vs-sqlite equivalence) — every PR
    but **no ratelimit coverage today** (F6 candidate home).
  - `make chaos-test` (`-tags chaos -race -count=2`) — manual/pre-release;
    **no ratelimit fault-injection entry exists**. Optional addition:
    a chaos test flipping a SQLite limiter's DB to closed mid-stream and
    asserting fail-open + recovery. Not required for this change since
    unit-level injection covers the same paths.
  - `make bench-gate` — opt-in; gates `^BenchmarkMemoryLimiterAllow` at
    10% vs `baseline.txt`. Must re-record baseline on the same machine
    after commit 3 (`bench-gate-record`) and document before/after in the
    commit message.
  - `make load-test` (k6 /token) — manual; not needed for this change
    (header writing is off the auth hot path's limiter cost).
- **Gap**: no middleware-level test imports all three backends today
  (F6); no `interfaces/ratelimit` entry in `test/backendsemantics`.

### Flake risks in the proposed tests
1. **Epoch header assertions**: `Reset` is second-granularity
   (`time.Now().Unix()`); use ±1s windows, never exact equality.
2. **SQLite gauge/sample tests**: the prune/COUNT sample is ms-clock
   based — nondeterministic under real sleeps. Use the injectable
   `s.now` clock to land exactly on a `(nowNs/ms)%64 == 0` boundary.
3. **Memory pruner tests**: use the existing deadline pattern
   (`TestMemoryLimiter_StartPrunerSweepsAllShards`, 2s deadline) rather
   than fixed sleeps.
4. **Sampling tests**: the 1/64 middleware counter is closure-local —
   build a fresh middleware per test (and per policy under test) so
   tests stay `t.Parallel`-safe and deterministic at the 64th call.
5. **Redis deny-all `pttl`**: miniredis `FastForward` is the existing
   pattern; keep window-flip assertions on whole-window boundaries.

### Fixtures needed
- All already exist: `newTestClient` (miniredis), `downClient` (Redis
  outage), `newSQLiteLimiterForTest` (t.TempDir DSN), `metrics.New()` +
  registry gather (extend `rateLimitHitValue` into a generic
  `metricValue(name, labels...)` helper), `newMemoryLimiterPruned`
  (builder), controlled-clock `lim.now = func() time.Time` (SQLite).

### Exit criteria (implementation handoff)
1. Commit 1: build/vet + gates green; grep proof of zero old-signature
   implementors; F1 doubles migrated; F8 assertions added; F10 fuzz
   invariants; `TestMemoryLimiter_DenyAll_AllowedPathFinite` (F3) for
   Memory + SQLite.
2. Commit 2: F6 backend-parameterized middleware suite; F2/F3 header
   rules; openapi.yaml 429 note; `TestLimiter_DenyAllFromRate` extended
   with `RetryAfter == 0` + `Limit == 0`.
3. Commit 3: F4 SQLite observer mechanism specified and tested; F5
   struct move so `TestMaintainability_` stays green; F2 gauge guard
   test; bench before/after recorded (allocs unchanged: 1/op, 64 B/op).
4. Handoff gates: `go test ./... -race`, `go test ./test/ -run TestE2E
   -v`, `make ci` green; `make bench-gate` green on the same machine
   after re-recording the baseline; `docs/observability.md` + F7
   non-goal noted.

---

### Bottom line
The design's architecture is sound and its key discovery (the
`selfservicecore.RateLimiter` parallel SPI) is real and correctly
mitigated via `shared/spi`. It is not yet implementable as written: the
migration table is incomplete (F1), the fail-open gauge pollution (F2),
the deny-all allowed-path division-by-zero (F3), the unspecified SQLite
gauge path (F4), and the metrics.go 500-line gate violation (F5) all need
resolution before commit 1 is cut. No runtime defect exists in the
current tree; all findings are design-stage.
