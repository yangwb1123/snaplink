All design claims verified against code. Here is the performance review.

---

# Performance Review: X-RateLimit-* Headers + Quota Metrics Design (方向二)

## 1. Workload assumptions and evidence quality

**Workload model** (from code, not invention):
- Hot path = rate-limit middleware on `/auth/login`, `/token`, `/auth/register`, `/register` plus any operator-configured prefix. The Redis limiter's own doc names it "the genuinely-hot store, consulted on EVERY request" (`infrastructure/redis/ratelimit.go:15-17`). Memory is the single-replica default; SQLite is documented as "low-thousands writes/sec … comfortable for hundreds of login attempts/sec" (`sqlite_limiter.go:17-19`).
- Two regimes: mostly-**allowed** (steady-state `/token`) and mostly-**rejected** (brute-force on `/auth/login` — the headline use case in `ratelimit.go:2-4`). The design's per-request additions (atomic increment, counter Inc, header formatting) land on the **allowed** path, which is the higher-QPS regime.

**Evidence quality:**
- **Verified** — every cited signature, line, and mechanism: `Limiter` SPI (`ratelimit.go:38-43`), the four prod callers (`middleware.go:127,180`, `quota.go:154`, `governance.go:314`, `signup.go:96`), the `selfservicecore.RateLimiter` byte-identical twin (`deps.go:21`) and its public wiring (`options_passwd.go:139`), `allowScript` returning `{count, pttl}` (`redis/ratelimit.go:96-110`), `Tokens()` in x/time v0.15.0 (`rate.go:94`, matches root `go.mod`), the self-deadlock claim (`pruneLocked` runs under `sh.mu`; `Buckets()` locks all 16 shards — non-reentrant mutex, deadlock is real), `SetMaxOpenConns(1)` making a second sampled tx a self-deadlock, `shared/spi` at layer rank 0 (`architecture_layer_test.go:41`), the 4 non-test files in `interfaces/ratelimit`, and the `var _ Limiter` assertion being SQLite-only today (`sqlite_limiter.go:255`).
- **Verified** — blast-radius inventory is complete: repo-wide `Allow(` grep shows exactly the four prod callers plus correctly-excluded lookalikes (`server_token.go:370` is x/time; `degradation.go:57` and `token_exchange.go:382` are their own policies).
- **Missing** — no committed benchmark numbers exist for any backend (bench files exist, results don't). No middleware-level benchmark exists at all. No SLOs are supplied. Both the design's own regression gate and this review must therefore be **regression-relative** (benchstat vs a baseline captured pre-change), not absolute.

## 2. Findings

**M1 — Medium — The only layer that gains per-request work has no benchmark; the planned gate cannot see it.**
- Path: `interfaces/ratelimit/middleware.go` allowed path (closure at `:127` and `:180`), not the limiter layer.
- Mechanism: per allowed request the design adds one closure-level `atomic.Uint64` increment (a **single cache line shared by all 16 shards** — it serializes across goroutines where the shard locks parallelize), one `CounterVec.WithLabelValues("allowed","unknown").Inc()`, 1/64 `GaugeVec.Set`, plus `strconv.Itoa` ×3 and `time.Now().Unix()` for the headers. Predicted impact: tens of ns per request — small in absolute terms, but it is the **only** new hot-path cost, and the design's stated regression gate (`BenchmarkMemoryLimiterAllow*`, risk #6) measures a code path that contains none of it. The claim "预期不应有回归" is untestable as planned.
- Recommendation: add `BenchmarkMiddlewareAllow*` (httptest recorder + `MemoryLimiter`, variants: metrics-nil, metrics-wired, headers, parallel with a small key pool). The parallel variant is mandatory: the closure atomic is the one new shared-contention point in an otherwise 16-way parallelized design.
- Experiment: `go test ./interfaces/ratelimit -bench BenchmarkMiddleware -benchmem -count=10` pre/post change; benchstat.

**M2 — Medium — Unconditional atomic increment on the default (metrics-nil) deployment.**
- Path: design decision 3 hot-path cost table ("允许路径 = 一次原子自增 + 一次计数 Inc + 1/64 Gauge Set") — stated unconditionally.
- Mechanism: `Policy.Metrics == nil` is the default wiring (no `WithMetrics`); the existing `recordRejection` short-circuits on exactly this nil check (`middleware.go:195-197`). An unconditional `LOCK ADD` on every allowed request is wasted work when metrics are off, and it makes the "no metrics → zero cost" property false by construction.
- Recommendation: guard the increment and the 1/64 sampling behind `p.Metrics != nil` (a branch vs a locked RMW). Then the metrics-nil middleware bench variant must be statistically identical to a no-feature control — a cheap, strong regression assertion.
- Impact: low-moderate; keeps today's zero-cost contract intact on the default path.

**M3 — Medium — `Tokens()` adds a second leaf-lock acquisition per `Allow` on the Memory backend (both paths).**
- Path: `MemoryLimiter.reserve` (`ratelimit.go:117-148`) reading `lim.Tokens()` post-Reserve/Cancel; verified `Tokens()` takes `lim.mu` internally (x/time v0.15.0 rate.go:94).
- Mechanism: one extra uncontended leaf mutex + `advance()` float math inside the shard lock. No lock-order hazard (leaf lock, design's analysis correct), no allocation, but real added latency on the hottest backend. The design's reuse of one `Tokens()` call for both `Remaining` and `ResetIn` (finding F in my notes) is the right call — single extra read, two consumers.
- Recommendation: capture pre-change `BenchmarkMemoryLimiterAllow*` benchstat before commit 1 (numbers are not committed anywhere today); acceptance = benchstat no-significant-change. Also worth asserting in tests: `Remaining == 0` on the reject path is **consistent across all three backends** (floor of post-Cancel tokens <1; denied row; `max(limit-count,0)=0`) — a genuinely nice cross-backend property the design implies but doesn't pin.

**L4 — Low — SQLite 1/64-sampled COUNT extends the single-connection critical section.**
- Path: `sqlite_limiter.go` `pruneStale` sampling point; design decision 3 ③.
- Mechanism: the COUNT runs inside the existing sampled tx (correctly — the `SetMaxOpenConns(1)` self-deadlock analysis is verified). `bucket_name` is the PK prefix, so it's a range scan, and it lengthens a tx only 1-in-64 times on a backend already serialized at low-thousands of writes/sec. Negligible; no bench required — cover it in a load test if the harness can run the SQLite backend.

**L5 — Low — Redis deny-all still pays a full script RTT per request.**
- Path: `redis/ratelimit.go` `Allow` with the new `denyAll` marker (design decision 1, failure mode 3).
- Mechanism: deny-all is a static property; with the marker, `Allow` could return `{false,0,...}` without touching Redis at all. But that changes fail-open semantics (today a Redis outage **admits**, which contradicts a deny-all operator intent — a genuine design tension). The "只做加法" scope rule correctly keeps this out; flag as a proposed optimization needing an explicit fail-open decision, not a defect.

**I6 — Info — `Reset` vs `Retry-After` diverge on token-bucket backends.**
- Verified: `ResetIn` = time-to-*full* (`(burst-tokens)/perSecond`) while `Retry-After` = time-to-*next-token*; they agree only on Redis (pttl for both). Deliberate and documented in the design; clients using `Reset` for backoff would over-wait on Memory/SQLite. Pin the relationship (`Reset >= RetryAfter` on buckets, `==` on Redis) in a test so it stays documented behavior.

**I7 — Info — No Redis/SQLite benches exist; the change is zero-RTT by construction.** Script untouched, count/pttl already returned; SQLite values already in-tx. An optional bench would lock the property in; low value given the diff is in-process only.

**I8 — Info — `time.Now()` on the allowed path** (Reset epoch) is a vDSO read (~20ns); fold into the M1 middleware bench rather than separate treatment.

## 3. Critical-path table

| Path | Baseline | Target | Bottleneck | Profiling method |
|---|---|---|---|---|
| Memory `Allow`, allowed | **none committed** — capture benchstat before commit 1 | flat vs baseline (no significant change) | shard mutex → `Reserve()` + new `Tokens()` leaf lock | `BenchmarkMemoryLimiterAllowSingleKey/ManyKeys` + benchstat |
| Memory `Allow`, parallel | none committed — capture first | flat | 16 shard locks (unchanged); **new**: 1 shared closure atomic | `BenchmarkMemoryLimiterAllowParallel` + new middleware parallel variant |
| Middleware allowed path (headers+metrics) | **no bench exists** — design one | flat vs metrics-nil control variant | new: closure atomic, `WithLabelValues`, 3×`Itoa`, `time.Now` | NEW `BenchmarkMiddlewareAllow*` (httptest) |
| Redis `Allow` | no bench; network-bound (RTT) | zero (script text unchanged) | Lua script RTT | load test; assert script byte-identical |
| SQLite `Allow` | no bench; single-conn serialized | zero per-request; 1/64 tx + COUNT | `BEGIN IMMEDIATE` + fsync | load test; pprof the sampled tx |

No absolute SLOs exist in the repo; per the prompt, targets are regression-relative until a baseline is established.

## 4. Prioritized benchmark/load plan

1. **Now (pre-change):** `go test ./interfaces/ratelimit -run '^$' -bench BenchmarkMemoryLimiterAllow -benchmem -count=10` → benchstat → save under `docs/auto/` (benchmark results are evidence, not commit-message prose). Without this step, commit 3's "no regression" claim is unprovable.
2. **Commit 1 (SPI):** re-run, benchstat vs step 1. Acceptance: no significant change per benchstat. Add the `var _ selfservicecore.RateLimiter = (*MemoryLimiter)(nil)` compile assertion (design already plans it). Dataset: single-key, 100/1k/10k pre-populated keys, 16 goroutines/32-key pool (all exist already).
3. **Commit 2 (headers):** add `BenchmarkMiddlewareAllow*` with the M1 matrix. Acceptance: metrics-nil variant statistically identical to a no-feature control (guards M2 if implemented); metrics-wired variant flat vs itself. Run `-race` on the new tests.
4. **Commit 3 (metrics):** full bench re-run + `go test ./test/ -run TestE2E -v` (Retry-After contract at `ratelimit_e2e_test.go:111` unchanged) + `make ci`. Optional load test: `hey -z 30s -c 16` against a local `sso-server` on the `/auth/login` prefix, same harness before/after — **proposed** harness, not in repo; acceptance = throughput/p99 within noise (±5%), since no SLO exists.
5. **Regression comparison:** store benchstat delta tables next to the baseline file; document in commit 3 per the design.

## 5. Optimization risks and measurements still needed

- **Baseline capture is the critical dependency.** No committed numbers exist for any backend; if baselines are captured after commit 1 lands, the "no regression" gate is void. This is the top risk to the design's own verification story.
- **Middleware-layer measurement gap (M1)** is the design's biggest blind spot: the only new per-request cost lives in a layer with zero bench coverage, and the design's named gate (`BenchmarkMemoryLimiterAllow*`) cannot detect a regression there.
- **Metrics-nil default path (M2):** decide guard-vs-unconditional before commit 3; if unconditional, the metrics-nil middleware variant quantifies the waste on every default deployment.
- **SQLite:** the 1/64 COUNT is inside the single-conn critical section; acceptable by analysis, but unmeasured — a SQLite-backend load leg is the only way to confirm tail-latency impact.
- **Redis deny-all short-circuit (L5)** is a real optimization but changes fail-open semantics; requires an explicit decision outside the additive scope.
- **Correctness-of-measurement caveats worth recording:** the gauge samples on request arrival (1/64), so at low traffic it updates rarely — acceptable for a gauge, but document that it tracks *traffic-weighted* remaining, not *bucket truth*; `Reset` divergence on token buckets (I6) should be pinned by a test, not just a consts comment.
- The design's register-passing claim (6-field `Allowance` = 5 words, register ABI, no escape) is plausible on amd64; the alloc assertions in the bench (`ReportAllocs`) will confirm it — keep them.

**Bottom line:** the design is architecturally sound and its performance analysis of the storage backends (zero schema/script/round-trip changes) is correct and verified. The two gaps that need action before commit 1 are both measurement, not code: capture the pre-change benchstat baseline, and add the middleware-level benchmark matrix — the only place the design actually adds per-request work.
