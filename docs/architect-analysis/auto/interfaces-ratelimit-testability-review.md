# Testability Review: interfaces-ratelimit design (post-auth rate limiting)

> Review of [interfaces-ratelimit-design.md](interfaces-ratelimit-design.md) against
> the committed test infrastructure and gates: e2e rate sizing/flakiness for the
> three surfaces, race and `-count` runs, byte-identical default verification for
> admin unconfigured mode, and coverage for the two wire changes and the reload
> hook. Every claim below was verified against the current code, not the design
> prose. Verdict: the design is testable as written; the deterministic-burst e2e
> strategy works and is race-immune. Seven gaps need closing before
> implementation; none requires relaxing a gate.

## Verdict

| Axis | Verdict |
|---|---|
| e2e rate sizing/flakiness (3 surfaces) | Sound, with one formula to correct (admin tier-1 must be sized by **burst**, not rate) and one naming fix (`TestE2E_*`) |
| Race and `-count` runs | Safe by construction (`PolicyStore` atomic, shard locks); missing: concurrent hot-swap tests, `-count=10+` targets, and one design rule about never swapping the store field pointer |
| Byte-identical admin default | The claim is currently **unverifiable**: nothing pins `rate_limit_exceeded` today; a golden test must be captured from current behavior before implementation |
| Two wire changes | Green-field (no test pins either old shape — verified); new tests must pin no-store preservation on the grant 429 and the full asymmetric shape pair for admin |
| Reload hook | Four existing `config/reload` patterns to mirror; one real design omission: replaced phase-2 limiters' background pruners are never closed (goroutine leak per SIGHUP) |

## 0. Fact base (verified in code)

| Claim | Verified at |
|---|---|
| `PolicyStore` is `atomic.Pointer[Policy]`; `Set`/`Get` concurrent-safe | `interfaces/ratelimit/middleware.go:147-163` |
| `MemoryLimiter` is shard-locked; `perSecond <= 0` denies all with retry 0; deny cancels the reservation (no charge) | `interfaces/ratelimit/ratelimit.go:195-206` |
| Grant limiter 429 today: `ctx.JSON(429, errorBody(ErrUnsupportedGrantType))`, **no Retry-After**; no-store is set at the top of `handleToken` (`server_token.go:21`), so it survives any 429 written later in the same handler | `interfaces/sso/server_token.go:365-373` |
| Admin 429 today: `Retry-After` + `http.Error` → `Content-Type: text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, body `{"error":"rate_limit_exceeded"}\n` (trailing newline from `http.Error`) | `interfaces/admin/governance.go:306-330` |
| No test anywhere references `rate_limit_exceeded` or the grant-limiter 429 shape; the two `unsupported_grant_type` tests are the 400 unknown-grant branch and must not change | grep across `test/`, `interfaces/` |
| `-run TestE2E` does **not** match `TestRateLimitE2E_*` (regexp matches the literal substring); the convention is `TestE2E_*` (`test/e2e_test.go:255`) | `test/ratelimit_e2e_test.go`, `test/e2e_test.go` |
| `HandlerContext` has 4 production implementers: `core.Context`, `backgroundHandlerContext` (`sso_wiring.go:277`), `ginContext` (`adapters/gin/adapter.go:171`), `echoContext` (`adapters/echo/adapter.go:196`) — the design lists 2 | `shared/core/router.go:17-45` |
| `SetRateLimitPolicy` swaps **inside** the boot-created store (`s.rateLimitStore.Set(p)`), never the field pointer — the pattern the new setters must copy | `interfaces/sso/server_routes.go:403-430` |
| Reload hook test patterns exist for all four states: applied-once, exactly-once, unwired→Ignored, error→Ignored+state untouched | `config/reload/reload_test.go:140-245` |
| Wiring tests + pruner-close guard exist for phase-1 (`closePolicyLimiters`) | `cmd/sso-server/rate_limit_reload_test.go:1-80` |
| `make ci` runs `go test -race -count=1 ./...`, which includes `./test/` | Makefile `ci` and `race` targets |
| httptest presents one RemoteAddr per test — exactly the same-NAT-IP scenario all three e2e tests need; different-IP scenarios require direct handler invocation with crafted `r.RemoteAddr` (precedent: `test/geo_middleware_test.go:41`) | — |

## 1. e2e rate sizing and flakiness — the three surfaces

### 1.1 `/token` client bucket — deterministic, zero sizing

Key `client:<id>` means A and B never share a bucket, even from the same IP
(the httptest natural case). Configure the client bucket at `burst=1,
per_sec<=1`; A floods once → A's bucket exhausted → A 429; B's bucket
untouched → 200. No sleep, no refill wait, no sizing arithmetic. Assert:
status 429, body `{"error":"rate_limited"}`, `Retry-After` present (ceiling
guarantees `"1"` — deterministic), and `Cache-Control: no-store` /
`Pragma: no-cache` (credential endpoint, AGENTS.md §3).

The only timing-adjacent risk is the credential-gated keying table (public
PKCE client must fall back to IP): the unit table over the extracted
classification function covers it without HTTP; one behavioral case per auth
class (secret-post, Basic, private_key_jwt, mTLS, self-signed TLS, public
PKCE) at the handler level. The e2e layer already has harnesses for each
class (`jwt_client_assertion_test.go`, `mtls_bound_test.go`), so the table
can live there if `server_token_test.go` lacks the fixtures.

### 1.2 `/userinfo` subject bucket — deterministic, zero sizing

Same shape: `sub:<alice>` vs `sub:<bob>` never collide. Two valid tokens
(issue via `client_credentials` for a confidential client), flood alice's
bucket, assert alice 429 + bob 200 + no-token still 401 with the bucket
untouched (oracle pin). No timing. Assert the `rate_limited` body and
Retry-After here too.

### 1.3 Admin — the one real sizing arithmetic

This is the only surface where the design's e2e sizing needs to be exact.
The trap: tier-1 is a **shared per-IP bucket** that every request consumes
**pre-auth** — including A's flood requests *after* tier-2 has started
429ing A (tier-2 rejects post-auth, but tier-1 still charges the shared IP
bucket first). Therefore:

```
tier1_burst >= flood_count + B_requests + margin        (margin >= 2x)
```

The design says "tier-1 sized above A's flood rate" — that is the wrong
dimension. Rate only controls refill, and refill during a sub-second test
adds tokens (the safe direction). The load-bearing number is **burst**:
with `tier-1 = 1000/s, burst 1000`, `tier-2 = 1000/s, burst 2`, A floods
100 requests (429s from request 3 at tier-2), B sends 1 request → B must
still pass tier-1 (100 < 1000). Deterministic, no sleeps, and immune to
`-race` latency inflation (see 1.4).

Test structure that makes the invariant explicit, in order:

1. A floods 100 (assert A gets 429s with `rate_limited` + Retry-After).
2. B requests once → 200.
3. Assert the 429s observed in step 1 are tier-2 rejections, not tier-1:
   the wire is identical, so prove it in unit tests instead — tier-2 is
   only reachable with a valid admin token, and an invalid-token flood from
   the same IP yields byte-identical 401s (not 429s) while consuming only
   the per-IP tier-1 bucket.

Two-admins harness: `newAdminHTTPHarness(t, prov, validClaims)` takes one
claims object — extend it (or build a two-token variant) so A and B are
distinct admin subjects over the same server.

### 1.4 Flakiness doctrine (applies to all three surfaces)

1. **Assert exhausted-burst states only.** Exhausted buckets are stable
   states; refill during the test is bounded by `rate * test_duration` and
   absorbed by the margins above. Never assert "after Retry-After seconds
   the request succeeds" — that is the classic flake and must be forbidden
   in review.
2. **No `time.Sleep` in these tests.** (Even the 30 ms precedent in
   `account_lockout_test.go` is a fixed-window wait; the bucket tests need
   none.)
3. **`-race` immunity:** burst-exhaustion assertions do not depend on
   request latency, so the 2-10x `-race` slowdown cannot flip them. State
   this in the test doc comments so a future "speed up" refactor
   (e.g. shrinking burst to 1 and flooding once) does not reintroduce a
   timing dependence.
4. **Isolation:** each e2e test builds its own server and its own limiters
   (verified convention: `newTokenHarness`, `buildRateLimitHarness`,
   `newAdminHTTPHarness` are all per-test) — no shared bucket state across
   tests, so package-level parallelism is safe.

### 1.5 Naming gap: `-run TestE2E` does not match the existing convention

`go test ./test/ -run TestE2E -v` (AGENTS.md handoff command) uses an
unanchored regexp against the full test name. `TestRateLimitE2E_*` does not
contain the substring `TestE2E`, so the *existing* rate-limit e2e tests are
not covered by that command today. Name the new tests `TestE2E_RateLimit*`
(token/userinfo/admin) so the targeted handoff command picks them up; the
full suite is covered regardless via `make ci` (`-race -count=1 ./...`).

## 2. Race and `-count` runs

### 2.1 Race-safe by construction (verified, keep it that way)

- `PolicyStore` is `atomic.Pointer` — hot-swap (`store.Set` from SIGHUP)
  vs per-request `Checkpoint` (`store.Get`) is race-free by construction.
- `MemoryLimiter.Allow` is shard-locked; concurrent same-key requests are
  safe, and the deny path cancels the reservation (no charge).
- `grantRateLimiters` map is written only at boot (options) and read per
  request — the migration to `ratelimit.Limiter` must keep it that way
  (no runtime mutation, ever).
- `SetRequest`/`WithClientID`/`WithSubject` writes are request-scoped; all
  four `HandlerContext` implementers are per-request objects, so the
  write-then-check sequence is single-goroutine within a request.

### 2.2 Missing design rule: never swap the store field pointer

The design leaves the setter's mechanics unspecified. Phase-1's contract is
explicit and must be copied (`server_routes.go:403-430`): the option
creates the store at boot and stores it on the Server; the runtime setter
does `store.Set(Policy{...})` **only** — the field pointer never changes.
If `SetTokenEndpointClientRateLimit` / `SetUserInfoRateLimit` instead
construct a fresh store and assign the field, a SIGHUP-vs-request data race
appears that no existing pattern guards. State the rule in the design and
pin it with a concurrent test (2.3).

### 2.3 `-count` strategy

- New concurrency tests, all under `-race`:
  1. concurrent `Checkpoint` + `store.Set` loops on the same store
     (`interfaces/ratelimit`);
  2. concurrent `SetTokenEndpointClientRateLimit`/`SetUserInfoRateLimit` +
     live `/token`/`/userinfo` requests (`interfaces/sso`);
  3. concurrent `SetPerAdminRateLimitPolicyStore` + admin requests
     (`interfaces/admin`).
- Run them with `-count=10+` per AGENTS.md §5.5:
  `go test -race -count=10 ./interfaces/ratelimit ./interfaces/sso ./interfaces/admin -run 'RateLimit|Checkpoint|PerAdmin'`.
  Note the phase-1 hot-swap test (`rate_limit_hotreload_test.go`) is
  sequential today — the new tests should be the first *concurrent* ones
  on this path.
- E2E: the deterministic-burst strategy makes `-count=3` pre-handoff sane;
  `make ci` runs the suite with `-race -count=1` already.
- The `SetRequest` ripple is compile-time, not runtime: `go build ./...`
  after the interface change lists all four production implementers and
  every standalone fake (e.g. `userinfoHandlerDeps` in
  `protocols/oidc/handle_userinfo_test.go:33`).

## 3. Byte-identical default verification — admin unconfigured mode

### 3.1 What "byte-identical" actually means today

The unconfigured 429 is `checkRateLimit` → `Retry-After` (ceil, min 1) +
`http.Error`, which produces: status 429, `Content-Type: text/plain;
charset=utf-8`, `X-Content-Type-Options: nosniff`, body
`{"error":"rate_limit_exceeded"}\n` (trailing newline from `http.Error`).
Byte-identical verification must assert all of these, not just the body
string.

### 3.2 Gap: nothing pins this shape today — capture a golden before implementation

No test references `rate_limit_exceeded` anywhere; the existing
`TestHTTPMiddleware_RateLimitUnwiredIsUnlimited`
(`interfaces/admin/middleware_test.go:341`) only asserts the unlimited-200
path. The design's "unit test with no `SetPerAdminRateLimit`" therefore
must be a **golden test**: record the current full response
(status, headers, exact body bytes including `\n`) from today's code
*before* the change lands, then assert byte equality after. Without it,
the "byte-identical default" acceptance is unverifiable — the exact
regression it exists to prevent (someone routing the unconfigured path
through `ratelimit.TooManyRequests` unconditionally) would sail through
every other test in the suite.

### 3.3 The configured-mode asymmetry pair

The opt-in switch must be proven to flip the shape: both configured tiers
emit `application/json` `{"error":"rate_limited"}` + Retry-After (no
trailing newline) — assert the difference from the golden explicitly in the
same test file, so the asymmetry is a pinned contract, not an accident.

### 3.4 Tier-1 rekey and tier-2 ordering unit tests

- Tier-1 per-IP rekey: httptest presents one IP, so invoke the middleware
  directly with crafted requests (`httptest.NewRequest` + `r.RemoteAddr`,
  precedent `test/geo_middleware_test.go:41`); assert two source IPs get
  independent tier-1 buckets in configured mode and one shared `"admin"`
  bucket in unconfigured mode.
- Tier-2 ordering (before idle-timeout): an idle-expired admin flooding
  must see the constant 429 `rate_limited` shape, not a session/401 shape —
  this pins the oracle-safety claim (design Decision 5) as a table over
  session states (valid, expired, revoked).

## 4. Coverage for the two wire changes

### 4.1 Grant limiter: `unsupported_grant_type`-on-429 → `rate_limited` + Retry-After

Verified green-field: no test pins the current 429 shape. The two existing
`unsupported_grant_type` tests (`test/handle_token_test.go:249`,
`rootcov_flow_test.go:530`) are the 400 unknown-grant branch and must stay
green unchanged — the fix only touches the rate-limited branch. New
coverage:

- Unit + e2e: exhaust a grant bucket → 429, body `{"error":"rate_limited"}`,
  `Retry-After` present (a new header on this surface — worth an explicit
  assertion), and **`Cache-Control: no-store` / `Pragma: no-cache`
  preserved**. The no-store headers come from `tokenNoStoreHeaders` at the
  top of `handleToken` (`server_token.go:21`), so they survive the
  migration only as long as the check stays below that line — pin the
  headers so a future reordering cannot silently drop them (AGENTS.md §3
  credential-endpoint rule).
- Semantics table, untested today, add during the migration: negative rate
  → unlimited (200); `0` → deny-all (429, Retry-After absent per
  `ratelimit.go:195-206`); positive → burst then 429. This pins the
  `*rate.Limiter` → `ratelimit.Limiter` equivalence, including the
  zero-rate branch where `rate.NewLimiter(0, burst)` and
  `NewMemoryLimiter(0, burst)` must agree.
- Ordering pin: client-bucket check pre-idempotency, grant check
  post-idempotency — assert an `Idempotency-Key` replay flood still
  consumes the client bucket (design Decision 3's explicit ordering).

### 4.2 Admin body: `rate_limit_exceeded` → `rate_limited` (configured mode only)

Covered by §3.2/§3.3. The doc obligation (`docs/error-codes.md` row note)
is in the design; the tests above are what make the "scoped to the opted-in
mode" reading enforceable.

## 5. Coverage for the reload hook

### 5.1 Reloader level (`config/reload`) — mirror the four existing patterns

`reload_test.go:140-245` has the exact templates; the new
`SetPostAuthRateLimitHook` needs all four mirrors:

1. wired + config change → exactly one `Applied` entry, hook receives the
   new `RateLimitConfig`;
2. multiple leaf changes (`token_client` + `userinfo`) → hook called
   exactly once;
3. hook unwired → change reported `Ignored` — this is the design's
   "visible, not silent" claim; test it;
4. hook returns error (e.g. Redis backend unreachable at construction) →
   `Ignored` + `Current()` untouched.

### 5.2 Wiring level (`cmd/sso-server`) — mirror `rate_limit_reload_test.go` — one design omission

The phase-1 wiring test proves replaced policy limiters' background pruners
are closed on reload (`closePolicyLimiters`,
`TestClosePolicyLimiters_ClosesDefaultAndPrefixes`). **The design's
Decision 6 hook rebuilds the `token_client`/`userinfo` limiters on every
reload but never mentions closing the replaced ones** — with
`security.rate_limit.prune_interval` set, every SIGHUP leaks one goroutine
per replaced limiter, the exact leak the phase-1 test guards against. Fix
in the same change: extend the close discipline to the phase-2 stores
(either the setters close the replaced limiter, or the wiring layer calls
`closePolicyLimiters` on the previous phase-2 policies), and mirror
`TestClosePolicyLimiters_*` with a close-counting limiter through the new
setters.

### 5.3 Server level (`interfaces/sso`) — mirror `rate_limit_hotreload_test.go`

- Live swap takes effect on the very next request (both setters) — the
  `Checkpoint`-reads-`store.Get()`-per-request property.
- `SetTokenEndpointClientRateLimit`/`SetUserInfoRateLimit` return `false`
  when the option was never wired (the "can't add a gate after boot"
  contract).
- Concurrent swap-vs-request under `-race -count=10` (§2.3) to pin the
  store-pointer-never-swapped rule (§2.2).

### 5.4 Shared builder extraction

The single-limiter builder extracted from
`serverbuildplatform.BuildRateLimitPolicy` (memory/sqlite/redis dispatch)
is now on both the phase-1 and phase-2 reload paths — it needs its own
dispatch table test (backend selection + construction-error propagation),
extending `build_governance_test.go` / `build_ratelimit_cluster_test.go`.

## 6. SetRequest ripple — factual correction

The design lists two production implementers plus fakes; there are four:
`core.Context`, `backgroundHandlerContext` (`sso_wiring.go:277`), and the
gin/echo adapter contexts (`adapters/gin/adapter.go:171`,
`adapters/echo/adapter.go:196`), all of which implement the full
`HandlerContext` including `SetResponseWriter`. The additive method is a
compile error that lists them — no runtime risk — but the design's
enumeration should be corrected so the implementation checklist is
complete. Fakes embedding `core.Context` inherit `SetRequest` for free;
standalone fakes (the `userinfoHandlerDeps` fake at
`protocols/oidc/handle_userinfo_test.go:33`) fail compile and must be
extended with a recording subject + a switchable rate-limited verdict, so
the oidc-layer ordering is testable: subject stored before the checkpoint,
checkpoint-true skips the user lookup (residency gate), checkpoint-false
leaves the existing flow byte-identical.

## 7. Findings summary

| # | Finding | Severity | Fix |
|---|---|---|---|
| 1 | Byte-identical admin default is unverifiable today: nothing pins `rate_limit_exceeded`; golden must be captured from current code before implementation (§3.2) | High | Golden test: full status/headers/body bytes (incl. `\n`, text/plain, nosniff) |
| 2 | Phase-2 limiter replacement on reload never closes replaced pruners — goroutine leak per SIGHUP with `prune_interval` (§5.2) | High | Extend `closePolicyLimiters` discipline to phase-2 stores + mirror close-counting test |
| 3 | Admin e2e sizing must be tier-1 **burst ≥ flood + B + margin**, not "above flood rate" (§1.3) | Medium | Correct the design formula; concrete numbers in the e2e |
| 4 | Setter mechanics unspecified: must swap via `store.Set`, never the field pointer (§2.2) | Medium | State the phase-1 rule in the design; pin with concurrent `-race -count=10` tests |
| 5 | `WithGrantTypeRateLimit` semantics (negative/0/positive) untested today; migration equivalence (`rate.Limiter` vs `MemoryLimiter` at 0) needs a table (§4.1) | Medium | Semantics table during migration |
| 6 | New e2e tests named `TestRateLimitE2E_*` are invisible to `-run TestE2E` (§1.5) | Low | Name them `TestE2E_RateLimit*` |
| 7 | Verification mapping lacks a metrics assertion per new surface (`sso_rate_limit_hits_total`) | Low | Extend `ratelimit_metrics_test.go` + one e2e metrics check (pattern: `TestRateLimitE2E_429sCountedAs4xxInMetrics`) |
| 8 | `SetRequest` ripple undercounts implementers (gin/echo adapter contexts missing) (§6) | Low | Correct the design's enumeration |
| 9 | Concurrent hot-swap tests and `-count=10+` targets absent from the design's gate list (§2.3) | Medium | Add the three concurrent tests + the `-count=10` invocation |

## 8. Net assessment

The design's testability is above the codebase's bar: the checkpoint
mechanism reuses the already-tested `PolicyStore`/`Limiter` machinery, the
three e2e scenarios are expressible as deterministic burst-exhaustion
sequences with no wall-clock dependence (race-immune by construction), and
the two wire fixes are green-field. The four things that would actually
silently break — the admin default shape, the reload pruner leak, a field
pointer race in the setters, and a `-run TestE2E` blind spot — are all
pinned by the specific tests above, and none requires a gate change or a
threshold relaxation.
