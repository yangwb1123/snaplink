# Security review — interfaces/ratelimit direction 2 (quota visibility: X-RateLimit-* headers + quota metrics)

Reviewer: principal security engineer (advisory only; no production files
modified). Reviewed revision: HEAD at review time. Design under review:
`docs/auto/interfaces-ratelimit-direction2-design.md`; upstream requirement:
`docs/auto/interfaces-ratelimit-direction2-spec.md`.

Method: every claim below was verified against the code at the reviewed
revision (three backends, middleware, metrics layer, builder, hot-reload
wiring, test doubles). **No builds/tests were executed** — this is a
code-read review; the validation plan lists the executable checks that must
run before merge. Claims are labeled **Verified** / **Partial** / **Missing**.

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Where | Relevance |
|---|---|---|
| `ratelimit.Limiter` SPI | `interfaces/ratelimit/ratelimit.go:38-43` | Integrity: the contract the whole change reshapes; compiled into every consumer |
| Parallel SPI `selfservicecore.RateLimiter` | `protocols/selfservice/selfservicecore/deps.go:21` | Integrity: byte-identical signature today; the design's key breakage discovery (**Verified** — same `Allow(key string) (bool, time.Duration)`; `*MemoryLimiter` satisfies both structurally) |
| Bucket state (per-key token counts / window counters) | Memory: `bucketEntry.lim` (`ratelimit.go:96-99`); SQLite: `rate_limit_buckets` rows; Redis: `sso:ratelimit:*` keys | Confidentiality of the new `Remaining/Limit/ResetIn` values; availability (brute-force defense) |
| Policy table + live store | `ratelimit.Policy`/`PolicyStore` (`middleware.go:30-107`), SIGHUP hot-reload (`cmd/sso-server/main_wiring.go:142-169`) | Integrity: which limiter gates which path; new `{policy}` label source |
| Metrics vectors | `platform/metrics/` (`consts.go:107-110`, `conditional_access.go:43-64`) | Integrity: bounded-cardinality contract; the three new series |
| 429 wire contract | `writeTooManyRequests` (`middleware.go:216-233`), `{"error":"rate_limited"}` (`consts.go`), `docs/error-codes.md` | Oracle-safe errors; the change must keep the body byte-identical |

### Trust boundaries

1. **Edge → TrustedProxies → limiter key.** `buildMiddlewareChain`
   (`interfaces/sso/server_routes.go:360-404`) wraps `TrustedProxies`
   OUTSIDE `DynamicMiddleware`, so `KeyByClientIP` → `middleware.RealClientIP`
   keys on the validated IP (**Verified**). Without `WithTrustedProxies`,
   `KeyByClientIP` uses `r.RemoteAddr` and deliberately never reads
   `X-Forwarded-For` (`middleware.go:76-83`). The change must not and does not
   touch this boundary.
2. **Operator config → policy.** Prefix strings, per-second/burst numbers,
   prune interval: the only inputs to the new `{policy}` label and to
   `Allowance`. Never request input (**Verified** in design; consistent with
   `observability.md` bounded-cardinality doctrine).
3. **Middleware → handlers.** `writeRateLimitHeaders` runs before
   `WriteHeader` on both paths; the 429 short-circuit still precedes any
   handler execution.
4. **Request input → Allowance.** Only the key function consumes request
   state. The legacy `KeyByClientIDOrIP` (`middleware.go:59-73`) keys on
   unverified Basic usernames and is documented UNSAFE; it is unchanged by
   this design, and the new headers do not echo keys.

### Attacker capabilities

- Unauthenticated network client with arbitrary request volume and full
  control of request headers (IP forgeable only if the deployment lacks a
  trusted edge — pre-existing, unchanged).
- Ability to observe response headers on allowed and rejected requests
  (the new telemetry is addressed to the client by design).
- No write access to operator config, metrics, or the bucket stores.

### Entry points consuming the changed SPI

| Entry point | Kind | Change |
|---|---|---|
| `Middleware` / `DynamicMiddleware` Allow call sites (`middleware.go:127,180`) | request chain | decision 2/3 consumers |
| `checkClientRegistrationRateLimit` (`interfaces/sso/quota.go:154`) | `/register` DCR gate | mechanical field rename |
| `checkRateLimit` (`interfaces/admin/governance.go:314`) | admin gate | mechanical field rename |
| `rejectSignupRateLimit` (`protocols/selfservice/signup.go:91-96`) | `/auth/register` gate | mechanical field rename |
| `pingerLimiter` (`cmd/sso-server/readycheck_test.go:150`), `closeCountingLimiter` (`cmd/sso-server/rate_limit_reload_test.go:27`) | test doubles | re-signature |
| `stubRateLimiter` (`protocols/selfservice/testhelpers_test.go:388`), `stubSignupRateLimiter` (`test/auth_signup_test.go:235`) | test doubles | **Missing from the design's migration table** (finding F3) |
| fuzz/bench/single tests (`fuzz_test.go:21,39`, `infrastructure/redis/ratelimit_test.go:18,27`, `cmd/sso-server/security_test.go:157-160`) | tests | tuple destructuring |

## 2. Findings (by severity)

### F1 — Medium: the deny-all ALLOW branch has no specified shape; naive mapping yields `Inf`/`NaN` `ResetIn` and three-backend divergence exactly where the spec demands byte-identity

- **Evidence (Verified).** The design pins the deny-all *reject* shape to
  `{false, 0, 0, 0, 0}` and correctly flags the division hazard
  ("`ResetIn` 必须显式防除零"). But the deny-all *allow* branch is reachable
  in all three backends: Memory `reserve` returns `true` before the
  `perSecond <= 0` check whenever `reservation.Delay() == 0`
  (`ratelimit.go:127-137`) — a fresh `rate.NewLimiter(0, burst)` starts full,
  so the first `burst` requests pass; SQLite `consumeToken` allows while
  `tokens >= 1.0` regardless of `perSecond` (`sqlite_limiter.go:169-177`);
  Redis `NewLimiterFromRate(perSecond<=0)` produces `limit=1`, so the first
  request passes (`count=1 <= limit=1`, `infrastructure/redis/ratelimit.go:133-157`).
  Under the design's own mapping table, that branch computes
  `ResetIn = (burst - Tokens())/perSecond = +Inf` (Memory/SQLite) — and
  `time.Duration(+Inf)` is a garbage (on amd64, negative) value that would
  surface as a nonsensical `X-RateLimit-Reset` — while Redis would report
  `Limit=1, Remaining=0, Reset=now+365d`.
- **Exploit preconditions and steps.** Operator arms a kill-switch limiter
  (`perSecond <= 0`, the documented deny-everything configuration, typically
  during an active attack) on any prefix rule. Clients that hit the limiter
  during the first-burst window receive divergent headers per backend; with
  Memory/SQLite the `Reset` header can be in the past, which an aggressive
  client can read as "already reset" and retry immediately against a limiter
  that will keep denying. No throttling is bypassed (the deny decision is
  unaffected), but the spec's acceptance criterion 决策二 §3 ("三后端字节一致",
  including no `X-RateLimit-Reset` on deny-all) fails silently.
- **Impact.** Wire-contract divergence and misleading client telemetry in the
  one configuration the spec singled out for byte-identity; no authn/authz
  bypass.
- **Remediation.** Specify the deny-all allow-branch `Allowance` explicitly
  in the design and implement it as `{OK:true, Remaining:0, Limit:0,
  ResetIn:0}` in all three backends (the `OK && Limit==0` header rule then
  keeps all three byte-identical on both branches). Add an explicit
  `perSecond <= 0` guard before any `ResetIn` arithmetic in the allow path of
  `reserve`/`consumeToken`.
- **Regression test.** `NewMemoryLimiter(0, 5)` / `NewSQLiteLimiter(..., 0,
  5, ...)` / `redis.NewLimiterFromRate(rdb, 0, 5, "")`: first request → 200
  with NO `X-RateLimit-*` headers; subsequent request → 429 with only
  `X-RateLimit-Remaining: 0`; assert byte-identical headers across all three
  backends on both branches.

### F2 — Medium: `sso_rate_limit_buckets` is an unlabeled gauge with per-limiter writers; the headline "active bucket size" metric is wrong in the stock multi-rule deployment

- **Evidence (Verified).** The stock builder creates one `MemoryLimiter` per
  prefix rule plus the default, each with its own `StartPruner`
  (`cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go:70-84`).
  Per the design, each limiter's sweep observer calls
  `ObserveRateLimitBuckets(count)` — i.e., every rule's pruner writes the
  SAME unlabeled series. Last-writer-wins: with 3 prefix rules the gauge
  flips between per-rule counts and never represents the aggregate; SQLite
  (`COUNT(*) ... WHERE bucket_name = ?` per limiter) has the same conflict.
- **Exploit preconditions and steps.** Attacker sprays IPs (the exact
  scenario the metric exists to surface). Bucket count balloons across all
  rules; the gauge shows whichever rule's pruner fired last — plausibly a
  small, quiet rule — while the total is an order of magnitude larger.
- **Impact.** The attack-detection signal the spec asked for (决策三 §3) is
  misleading in the default configuration; a false-low reading can delay
  operator reaction to an IP-spray / storage-pressure event.
- **Remediation.** Label the gauge by policy/prefix (bounded — operator YAML
  strings, same provenance as the `{policy}` label already in the design) or
  aggregate over a shared registry. Keep it unlabeled only if documented as
  "last-writing-limiter wins" — not recommended.
- **Regression test.** Two prefix rules, each with a `MemoryLimiter` +
  pruner; create keys in both; assert the gauge (labeled variant) reports
  each rule's count, and that pruning one rule's keys does not change the
  other's series.

### F3 — Low: the design's test-double inventory is incomplete

- **Evidence (Verified).** The migration table lists `pingerLimiter` and
  `closeCountingLimiter` but not `stubRateLimiter`
  (`protocols/selfservice/testhelpers_test.go:388`, implements
  `selfservicecore.RateLimiter` with `Allow(string) (bool, time.Duration)`)
  nor `stubSignupRateLimiter` (`test/auth_signup_test.go:235`). Both sit on
  the selfservice side — the exact surface the design identifies as the
  subtle breakage — so the "测试双" row reads complete when it is not.
- **Impact.** None at runtime: all are test files and fail at compile time
  under commit 1, which `go build`/`go vet` will catch. Doc-level defect that
  could mislead the implementer's migration checklist.
- **Remediation.** Add both files to the migration table (or replace the
  enumeration with "every `Allow(key string)` implementor found by
  `grep -rn 'func.*Allow(key string)' --include='*.go'`").
- **Regression test.** None needed beyond commit-1 `go build ./...`.

### F4 — Low: stale `sso_rate_limit_remaining{policy}` series survive hot reload, contradicting the design's "无状态残留问题" claim

- **Evidence (Verified).** The sampling counter lives in the middleware
  closure (correct — no residue there), but the gauge's `{policy}` label
  values are prefix strings from the OLD Policy. After `PolicyStore.Set`
  changes a prefix string, the old series keeps its last value forever (a
  `GaugeVec` has no deletion path from the middleware; `closePolicyLimiters`
  at `main_wiring.go:162-169` closes old limiters but nothing clears their
  series). Bounded (operator-config-driven, rare), but stale.
- **Impact.** A dashboard may show a frozen "remaining" for a retired rule;
  alert misdirection at worst, no security effect.
- **Remediation.** Document in `observability.md` that retired policy labels
  retain their last value until process restart; optionally zero them from
  `closePolicyLimiters` (would need the label→limiter map at the wiring
  layer).
- **Regression test.** Hot-reload test: assert the new policy's series
  updates while the old series value is defined (documented behavior).

### F5 — Low (pre-existing, flagged because this change touches the function): the middleware 429 on credential paths carries no `Cache-Control: no-store`

- **Evidence (Verified).** `writeTooManyRequests` (`middleware.go:216-233`)
  sets only `Content-Type` + status. The DCR gate compensates explicitly
  (`quota.go:157-160` calls `middleware.TokenNoStoreHeaders` on its 429), but
  the global middleware's login 429 does not. AGENTS.md §3 requires
  credential-endpoint errors to be no-store. The spec explicitly says
  "429 ... `Cache-Control` 语义不变", so this is out of scope for this
  change — recorded here as a candidate follow-up. The new headers add
  marginal cache-contamination surface (a shared cache that stored a 429
  would serve another client the original requester's bucket state; RFC 9111
  makes 429 non-cacheable absent explicit freshness, so this is theoretical).
- **Remediation (separate change).** Add `Cache-Control: no-store` +
  `Pragma: no-cache` to the middleware 429 path.

### F6 — Info: two value-identical Redis deny-all constructions keep different client-visible semantics

- **Evidence (Verified).** `NewLimiterFromRate(perSecond<=0)` (deny-all
  marker → all-zero reject) vs an operator's explicit
  `NewLimiter(rdb, 1, 365*24*time.Hour, ...)` (reject keeps
  `RetryAfter=365d`). Design risk #4 documents this as intentional
  ("操作者的显式选择"), but the two are indistinguishable by value and an
  operator auditing config cannot tell which behavior they get without
  reading the constructor. Acceptable; suggest a doc note on `NewLimiter`
  that the 365-day window emits a 365-day `Retry-After`.

### F7 — Info: the design's own security properties, verified

- Allowed-path `X-RateLimit-*` values are per-bucket telemetry addressed to
  the bucket's own holder. Under IP keying, shared-NAT clients see the shared
  bucket — identical information to observing 429s; no new cross-user or
  cross-tenant disclosure surface.
- Deny-all vs normal-exhaustion are ALREADY distinguishable today via
  `Retry-After` presence (normal Memory/SQLite rejects always have
  `retry > 0`; deny-all has none), so the new header rule (deny-all writes
  only `Remaining: 0`; normal reject writes all three) adds **no new oracle**
  (**Verified** against `reserve`/`consumeToken`/`writeTooManyRequests`).
- The feature deliberately arms clients with precise remaining-quota
  telemetry (an attacker can time bursts to the refill schedule instead of
  probing with 429s). This is the spec's stated purpose (client
  self-throttling); the mitigation is the unchanged per-IP bound, not header
  secrecy. Document that `Remaining` is not a secret.

## 3. Abuse-case table

| Abuse case | Reachable? | Analysis |
|---|---|---|
| Identity spoofing | No new path | Keying unchanged: validated IP via `TrustedProxies` (chain order Verified) or `RemoteAddr`; `KeyByClientIDOrIP` remains documented-UNSAFE and unchanged. Headers never echo bucket keys or usernames. |
| Replay | No | `Allowance` is per-request state; no tokens, nonces, or sessions involved. Hot-reload swaps limiter instances, never replays decisions. |
| Cross-tenant access | No | Bucket keys are IP/subject; headers expose only the caller's own bucket. Metrics `tenant` label resolves ONLY on the reject path via the allowlist-capped resolver (`TenantKeyFunc` "Called ONLY on the reject path" constraint preserved — **Verified**; allowed-path rows carry `TenantLabelUnknown`). |
| Proxy/header forgery | No new path | `X-RateLimit-*` values are `strconv` numerics from server state — no request-input echo, no injection. `X-Forwarded-For` still unread without chain validation; `TrustedProxies` ordering preserved (`server_routes.go:385-396`). |
| Resource exhaustion | Bounded | Per-request cost: one atomic increment + one counter Inc on allow; gauge set at 1/64; SQLite `COUNT` rides the existing 1/64 prune sampling inside the SAME transaction (`SetMaxOpenConns(1)` self-deadlock avoidance — **Verified** correct). Sampling counters are not attacker-influenced beyond request volume; no unbounded labels (`result` 2-valued, `policy` operator-bounded, `tenant` allowlist-capped). |
| Sensitive-data leakage | By design | `Remaining/Limit/Reset` reveal the key's bucket state to its holder; NAT-shared buckets expose intra-NAT consumption (pre-existing via 429s). `Reset` epoch reveals server clock skew (trivial). Fail-open emits no headers, so a degraded store cannot masquerade as a real zero-quota signal (client self-throttling protection — **Verified** logic). |

## 4. Positive controls verified, residual risks, validation plan

### Positive controls verified (code-read)

1. 429 body `{"error":"rate_limited"}`, error code, and `Retry-After` ceil
   logic preserved byte-for-byte; no new error codes; `docs/error-codes.md`
   untouched (design 决策二; `writeTooManyRequests` "原样保留").
2. Middleware chain order preserved — probes outside, `TrustedProxies`
   outside rate limiting, degradation gate inside (`server_routes.go:360-404`).
3. Fail-open doctrines preserved on all three backends (SQL/Redis error,
   unexpected script shape → `{OK:true, zeros}`; SQLite tx rollback
   unchanged).
4. `selfservicecore.RateLimiter` structural coupling resolved correctly:
   `RateAllowance` hoisted to `shared/spi` (layer 0; `selfservicecore` already
   imports `spi` — **Verified** `deps.go` imports; precedent `spi.Logger` /
   `RegistrationGate`). Rejected alternatives (type duplication, signature
   change to `ratelimit.Limiter`) are correctly analyzed — both break the
   documented `WithSelfServiceSignupRateLimiter(ratelimit.NewMemoryLimiter(...))`
   wiring (`options_passwd.go:125-139`).
5. Redis deny-all marker (`denyAll` field) is required and correctly scoped —
   `{limit:1, window:365d}` is value-indistinguishable from legitimate
   config (**Verified** `NewLimiterFromRate` vs `NewLimiter`).
6. `var _ selfservicecore.RateLimiter = (*MemoryLimiter)(nil)` regression
   assertion added; existing `var _ Limiter` assertions kept.
7. Storage model: zero schema/script changes confirmed — SQLite rows already
   carry refilled `tokens`; the Redis script already returns `{count, pttl}`;
   `x/time/rate.Limiter.Tokens()` exists at v0.15.0 (`rate.go:94`,
   **Verified** in module cache).
8. Memory bucket-gauge deadlock analysis correct: `Buckets()` locks all
   shards, so the observer must not fire on the inline-prune path (under one
   shard lock); firing only in `StartPruner`'s background sweep is safe.
   Gauge gated on `prune_interval` — documented limitation, acceptable.
9. Hot-reload lifecycle: `closePolicyLimiters` (`main_wiring.go:162-169`)
   closes old limiters including their pruners, so the observer hook dies
   with its limiter (**Verified**).
10. New metrics preserve bounded cardinality (`result` ∈ {allowed,
    rejected}; `policy` from operator YAML; `tenant` via existing
    allowlist+other) — consistent with `observability.md` doctrine.

### Residual risks

- F1 must be fixed in the same commit as 决策一/二 or the deny-all
  byte-identity acceptance criterion fails silently and per-backend.
- F2's unlabeled buckets gauge is misleading under the stock multi-rule
  wiring unless relabeled.
- F4 stale series and F6 constructor asymmetry are documentation-level;
  acceptable with the noted doc updates.
- F5 (no-store on middleware 429) is pre-existing and explicitly out of the
  spec's scope; track separately.
- The `NewLimiter` direct-construction 365-day window retains the old
  `Retry-After: 31536000` behavior by design (design risk #4) — the one
  intentional wire divergence; keep the doc note.

### Prioritized validation plan (executable, in order)

1. **Commit 1 (SPI).** `go build ./... && go vet ./...` +
   `go test -run 'TestMaintainability_|TestArchitecture_' .`; then
   `grep -rn "func.*Allow(key string)" --include="*.go"` must return only the
   three backends + the four listed test doubles (F3). Confirm
   `var _ selfservicecore.RateLimiter = (*MemoryLimiter)(nil)` compiles.
2. **Commit 2 (headers).** Middleware tests across all three backends,
   asserting byte-identical responses for: normal allow (three headers,
   `Limit == burst`), normal reject (`Retry-After` + three headers),
   **deny-all allow branch (no headers — F1)**, deny-all reject
   (`Remaining: 0` only), fail-open (no headers), nil-rule short-circuit,
   and `PolicyStore.Set` hot-reload. Run `go test ./test/ -run TestE2E -v`.
3. **Commit 3 (metrics).** Metrics tests: allow/reject counters, tenant
   label only on reject, sampling gauge matches `Allowance.Remaining`,
   buckets gauge per-rule (F2), nil-`Metrics` no-ops;
   `go test ./... -race`; `make ci`.
4. **Security-specific re-review of the diff.** Confirm every
   `X-RateLimit-*` value is `strconv`-numeric (no injection), headers are set
   before `WriteHeader` on both paths, and no `Err*`/error-code additions
   landed (oracle-safe surface unchanged).
