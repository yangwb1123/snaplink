All review claims cross-checked against the design/spec and independently verified against the code. Here is the gatekeeper assessment.

# Gatekeeper Cross-Check: 方向二 Design vs. Six Reviews

**Timeline note:** design/spec were finalized at 10:23–10:28; all reviews landed 10:34–10:47. **The design was not revised in response to any review.** The principal review's own verdict is "Conditionally Ready" — and the conditions are exactly the items below, none of which are in the design.

## Verified in code (my own reads, agreeing with reviewers)

| Claim | Code evidence | Status |
|---|---|---|
| H1: `Close()` sets `s.db=nil`; `Allow` has no nil guard; `main_wiring.go` comment claims SQLiteLimiter isn't an `io.Closer` (it is); `closePolicyLimiters` → `closeIfCloser` will close it on SIGHUP | sqlite_limiter.go:122-131, 148; main_wiring.go:163-170 | **Confirmed — real High, absent from design** |
| H2: normal reject path unconditionally `persistBucket` + `tx.Commit()`; only `denyAll` returns early | sqlite_limiter.go:160-177 | **Confirmed — design/spec say the opposite** |
| M1: Memory deny-all allows the first `burst` requests (`wait==0 → true,0`); `perSecond<=0` guard fires only on reject | ratelimit.go:185-198 | **Confirmed — allow-branch `ResetIn = (burst−tokens)/0 = +Inf` unguarded in design** |
| M9: `stubRateLimiter` (testhelpers_test.go:393) + `stubSignupRateLimiter` (auth_signup_test.go:235) implement old signature | both files | **Confirmed — missing from migration table** |
| L3: only `var _ Limiter` assertion is SQLite's (sqlite_limiter.go:255); `sso` **does** import ratelimit (quota.go:10) | grep | **Confirmed — two design factual errors** |
| M2: config_load.go:414,457 drops `PerSec<=0` rules; stock builder builds prefix limiters unconditionally (serverbuildplatform/build_ratelimit_cluster.go:75) | both files | **Confirmed — asymmetry unreported in design** |
| M4: metrics.go 494/500, metrics_ctor.go 497/500 | wc -l | **Confirmed — commit 3 trips the gate; "新开文件" escape can't hold struct fields** |
| M7: benchgate gates only `^BenchmarkMemoryLimiterAllow` | ops/deploy/benchgate/benchmarks.yaml:40-41 | **Confirmed — the only new hot-path cost is invisible to the named gate** |
| M8: `recordRejection` short-circuits on `p.Metrics==nil` (middleware.go:195-197); design's closure atomic is unconditional | code + design 决策三② | **Confirmed** |
| M6: cors.go:44 lists only X-RateLimit-Remaining; ExposedHeaders is operator YAML | interfaces/cors/cors.go | **Confirmed — CORS absent from blast radius** |

## Findings disposition

**Resolved or dismissed with reasons (acceptable):**
- Redis deny-all short-circuit (perf L5/T9) — out of scope, would change fail-open doctrine; explicit maintainer+security decision pending — *dismissed with reason, decision still owed*.
- Cache-Control no-store on middleware 429 (L5) — pre-existing, out of scope per RFC 9111, tracked separately — *dismissed with reason*.
- `X-` prefix + epoch Reset (L7) — deliberate GitHub-convention choice, epoch risk recorded (risk #2); the prefix-deviation note itself is not yet in consts.go/openapi — *mostly dismissed, note owed*.
- selfservicecore coupling, `Buckets()` deadlock, denyAll marker, zero storage change — all Verified by six reviewers and my reads; these are the design's strengths, no action.

**Unresolved — no mention in design, or design text contradicts the finding:**

| # | Severity | Finding | Design status |
|---|---|---|---|
| H1 | High | SIGHUP + SQLite → nil-db panic | **Absent from design entirely**; principal T10 mandates in-change fix (commit 3 rewrites the same wiring; AGENTS.md forbids deferred TODOs) |
| H2 | High | Design/spec claim SQLite rejects "roll back" — code persists+commits | **Doc still wrong** (design 存储模型表, spec 验收 3); literal implementation resurrects brute-force budgets mid-attack |
| H3 | High | fail-open `{OK:true,Limit:0}` sampled into `sso_rate_limit_remaining` | **No `a.Limit>0` guard** in 决策三②; heads-doctrine and gauge rule conflict |
| M1 | Med | deny-all allow-branch division-by-zero; header table has no 4th row | Design guards only the reject branch; 四方独立 finding unresolved |
| M2 | Med | `per_sec:0` SDK-drop vs stock-deny-all | Not mentioned; needs maintainer+security decision (T3) |
| M3 | Med | unlabeled `buckets` gauge, N+1 writers | Design explicitly says 无标签 with no justification (T6 says label it) |
| M4 | Med | metrics.go 494/500 — commit 3 trips gate | "新开文件" cannot carry struct fields; unresolved |
| M5 | Med | SQLite→Metrics mechanism unspecified | Commit-3 list wires only `MemoryLimiter.SetBucketObserver`; SQLite COUNT is unimplementable as planned |
| M6 | Med | CORS: SPA can't read Limit/Reset by default | Absent from blast radius; doc fix owed |
| M7 | Med | No middleware benchmark; named gate can't see new cost | Unresolved — principal precondition #3 |
| M8 | Med | Unconditional atomic on metrics-nil default | Design keeps it unconditional (T4: guard) |
| M9 | Med | Migration table misses two `selfservicecore` stubs | Table incomplete (compile-time safety, but plan is wrong) |
| L1-L4, L6, L8 | Low | error-codes caveat, prune_interval doc row, var-`_`/import-direction errata, fuzz invariants, clock/failover notes, Reset-vs-Retry-After test pin | All unaddressed one-line doc/test items |
| Baseline | — | QA captured bench numbers (178–447 ns/op, 64 B/op, 1 alloc/op) — **not committed** | Principal precondition #1; the "no regression" gate is void if commit 1 lands without it |

## Verdict

The design's core architecture is sound and independently verified — but the gatekeeper question is whether review findings are resolved or dismissed with reasons. They are **not**: the design predates the reviews, contains two factually wrong statements (H2, L3) that would misdirect implementation, omits a verified in-tree High-severity crash (H1) that the principal ruling requires to land in the same change, and its planned verification story is structurally blind to its own hot-path cost (M7/M8, no committed baseline). Three Highs and the M1/M9 corrections are preconditions the principal review states must land **before commit 1**, and none are in the design. Conditional readiness was granted on conditions; the conditions are unmet.

VERDICT: FAIL - design/spec must be corrected and re-issued before implementation: (1) H2 doc fix (SQLite rejects persist+commit, only denyAll rolls back) + spec 验收3; (2) H1 added to change scope (Allow nil-guard, main_wiring.go comment, Close-after-Allow test, hot-reload -race; land with commit 3); (3) H3 `a.Limit>0` gauge sampling guard; (4) M1 unconditional `ResetIn=0` for perSecond<=0 + 4th header-table row + deny-all allow-path test; (5) M9 migration table += stubRateLimiter/stubSignupRateLimiter; L3 errata (add `var _ Limiter = (*MemoryLimiter)(nil)`; fix import-direction claim); (6) M4 Metrics struct move to new file (commit 3 gate); (7) M5 SQLite observer mechanism specified; (8) M7 BenchmarkMiddlewareAllow* matrix (metrics-nil/wired/headers/parallel) before commit 2; (9) M8 guard atomic+sampling behind `p.Metrics != nil`; (10) M3 `{policy}` label on buckets gauge; (11) commit benchstat baseline (QA's numbers) to docs/auto/ before commit 1; (12) record T3/T9/T7/T8 decisions and M2/M6 doc items; (13) low-item doc fixes (L1 error-codes caveat, L2 prune_interval row, L4 fuzz invariants, L6 observability notes). Re-review the amended design before implementation starts.
