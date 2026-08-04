# Architecture Review: interfaces-ratelimit post-auth rate limiting design

> Review of [interfaces-ratelimit-design.md](interfaces-ratelimit-design.md) against
> the current tree, the requirements spec
> ([interfaces-ratelimit-requirements.md](interfaces-ratelimit-requirements.md)),
> and the three sub-reviews
> ([keying](interfaces-ratelimit-keying-review.md),
> [testability](interfaces-ratelimit-testability-review.md),
> [distributed-systems](interfaces-ratelimit-ds-review.md)). Every claim below was
> re-verified against executable code this session (file:line anchors), including
> the driver source (`modernc.org/sqlite@v1.50.1/tx.go`, `sqlite.go`) and the
> committed gates (`maintainability_budget_test.go`, `directory_fanout_test.go`).
> No gates ran (review-only; no code changed).

## 1. Scope, assumptions, verified architecture summary

**Scope reviewed.** The design ships three post-auth rate-limit surfaces
(`/token` client bucket, `/userinfo`+mesh subject bucket, admin two-tier), two
deliberate 429 wire fixes (grant limiter `unsupported_grant_type`→`rate_limited`;
admin configured-mode `rate_limit_exceeded`→`rate_limited`), the
`HandlerContext.SetRequest` + `WithClientID`/`KeyByClientID` identity plumbing, and
config/SIGHUP wiring. All changes stay in `interfaces/` + `config/` + `cmd/` +
docs; `protocols/oidc` gains interface methods only.

**Assumptions.** (a) The requirements spec is the binding contract; the design's
deviations from its letter (credential-gated keying, deps hooks instead of a
router middleware, conditional admin body unification) are deliberate and
justified. (b) `make ci` and the committed budget gates are the handoff bar.
(c) Cross-replica behavior is in scope because the spec accepts a `Limiter` SPI
"以便接 Redis 跨副本后端".

**Verified architecture summary.**

- **Layering is preserved.** `interfaces/ratelimit` imports only
  `interfaces/middleware` (existing edge) + `platform/metrics`
  (`middleware.go:1-9`); the new `Checkpoint`/`TooManyRequests`/`KeyByClientID`
  add no imports. `protocols/oidc` never imports `interfaces/*` — the
  `UserInfoDeps` hooks mirror the verified `MaybeSignUserInfo` seam
  (`handle_userinfo.go:32`, `interfaces/sso/accessors.go:344`).
  `core.HandlerContext.SetRequest` is additive with the `SetResponseWriter`
  precedent (`shared/core/router.go`). No new packages, no upward edges, no
  `layerExemptions` growth.
- **The two wire drifts are real and singular.** `server_token.go:371` is the
  only 429+`unsupported_grant_type` site in the tree (grep-verified); admin
  emits `text/plain` `rate_limit_exceeded` + trailing newline via `http.Error`
  (`governance.go:306-330`). Both fixes are spec-mandated and contract-correct
  (RFC 6749 §5.2 semantics preserved; RFC 6585 shape adopted).
- **Checkpoint placement verified on all three surfaces**: `/token` between
  `authenticateTokenClient` and `residencyGateTokenGrant` (`server_token.go:28-35`),
  pre-idempotency; grant check post-idempotency (`dispatchTokenGrant`); `/userinfo`
  between `authenticateUserInfoBearer` and `ResidencyDeniedForAccess`
  (`handle_userinfo.go:50-57`); admin tier-2 between `authenticateHTTP` and
  `enforceIdleTimeout` (`middleware.go:325-349`). The 401/403 ladders all live
  upstream of the checkpoints — no challenge drift, no new oracle.
- **The credential gate is the exact negation of `denyPublicClientCredentials`
  (`server_token.go:387-399`)** and is the only reading of the spec consistent
  with its own UNSAFE-`KeyByClientIDOrIP` analysis. `WithSubject` has zero
  non-test callers (verified) — this is genuinely the first production write.
- **Backends**: Memory = shard-locked token bucket, monotonic (`ratelimit.go`);
  SQLite = persisted rows, wall-clock refill, silent fail-open
  (`sqlite_limiter.go:159-201`); Redis = fixed-window counter via one atomic Lua
  script, silent fail-open (`infrastructure/redis/ratelimit.go:60-76,121-146`).
- **Reload**: `wireRateLimitReload` rebuilds via `BuildRateLimitPolicy` and
  closes replaced limiters (`main_wiring.go:142-176`); `applyRateLimit` runs once
  per Reload and reports `Ignored` when unwired (`config/reload/reload.go:370-380`).
- **Budget posture**: `interfaces/sso` at 60 files (exempt ceiling),
  `interfaces/admin` at 10 non-test files (hard cap, not exempt),
  `interfaces/ratelimit` at 3 non-test files. File-length headroom is the
  constraint that matters — see Finding 3.

**Verdict.** The architecture is sound and the smallest viable shape for the
spec. The deps-hook seam for `/userinfo` is correct (the middleware alternative
would double signature verification on the scrape path and risk 401 drift); the
credential-gated keying is a required refinement, not a scope creep. Five
corrections are mandatory before implementation: Decision 7/8 storage and
failure-mode statements are Memory-centric and factually wrong for the shared
backends (Findings 1, 2, 4); the file-budget arithmetic does not fit
(Findings 3); the reload close-discipline omission (Finding 5) and the golden
capture step (Finding 6) must be planned, not discovered.

## 2. Findings table

| # | Severity | Finding | Evidence (verified this session) | Impact | Recommendation |
|---|---|---|---|---|---|
| 1 | **High** | **Decision 7's storage model is Memory-centric; "bucket-exact cross-replica limiting" is not achievable today.** SQLite is not atomic cross-process and is wall-clock coupled; Redis is fixed-window, not a token bucket. | `SQLiteLimiter.Allow` uses `BeginTx(ctx, nil)` (`sqlite_limiter.go:159`); modernc maps nil opts to plain `BEGIN` (`tx.go:22-24`) unless the DSN carries `_txlock` — the production DSN (`config.SQLite.DSN`) does not, and the code comments claiming "BEGIN IMMEDIATE" (`sqlite_limiter.go:48,135`) are false as written. Deferred BEGIN reads before taking the write lock → the cross-process decision race. `nowNs := s.now().UnixNano()` (`sqlite_limiter.go:169`) couples refill to the wall clock of whichever replica wrote last. Redis `allowScript` is INCR+EXPIRE+PTTL, one key, one slot (`infrastructure/redis/ratelimit.go:60-76`) — atomic but fixed-window (edge burst 2×). The design's Decision 7 "token-bucket entries per key, FNV-32a across 16 shards" describes only `MemoryLimiter`. `TestSQLiteLimiter_CrossInstanceSharing` (`sqlite_limiter_test.go:121`) is sequential (limA then limB, no concurrent Allow); its `_journal=WAL` DSN param is a no-op under modernc (no `_journal` handling in `sqlite.go:143-200`). | An operator who reads Decision 7 and picks `backend=sqlite` for cross-replica enforcement gets a racy bucket and cross-replica refill drift; the "atomic per shard" claim does not hold across processes. Pre-existing phase-1 behavior, but the design extends it to three new surfaces. | Rewrite Decision 7 per backend. Name the **Redis fixed-window semantics as the cross-replica contract** (it is what `backend=redis` delivers); document SQLite as "persisted, best-effort" with an explicit clock-skew bound, and either (a) document `_txlock=immediate&_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)` as required DSN params for this backend, or (b) route the sqlite backend through `infrastructure/defaultimpl/sqlite.SharedDB` + `NewSQLiteLimiterWithDB` (one pool per file, WAL+NORMAL+busy_timeout, `shareddb.go:1-60`) and add a concurrent cross-instance test (two limiters, burst=1, same key, parallel Allow — fails today). |
| 2 | **High** | **Decision 8's fail-open row is inaccurate: fail-open is silent and not instantaneous.** The design's own verification item ("verify the fail-open on error is logged") fails as written. | `SQLiteLimiter.Allow` returns `(true, 0)` on BeginTx/load/persist/commit errors with no log, metric, or audit (`sqlite_limiter.go:161,174,190-191,200-201`); Redis `Limiter.Allow` likewise on script error/shape mismatch (`infrastructure/redis/ratelimit.go:135-146`). Both use `context.Background()` with no deadline; the client config passes through `MaxRetries/DialTimeout/ReadTimeout` unset-able (`build_bootstrap.go:257-260`), so go-redis defaults (3 retries w/ backoff, 5s dial, 3s read) apply — a dead Redis turns every checkpoint into a multi-second stall before the allow. A hung filesystem blocks in the syscall with no timeout at all. | The checkpoints are new on `/token` and `/userinfo`; under store pressure (the exact moment abuse floods are likely) the limiter stops limiting and adds latency. "Limiting silently off until recovery" understates a bounded stall. | State the acceptance explicitly: fail-open is the codebase-consistent choice (auth availability wins, matching AGENTS.md doctrine), **silent** — either add a fail-open counter at the `Checkpoint`/middleware layer (which has `Policy.Metrics`) or document silence as accepted; document the bounded-stall behavior and recommend `redis.max_retries`/timeouts for the auth path in config-reference. |
| 3 | **High** | **The implementation as planned crosses committed file budgets.** The design's "additions land in existing files" list is not arithmetically possible without a split-first step. | `maxFileLines=500` with an empty, frozen exemption map (`maintainability_budget_test.go:34,40`). Files the design touches: `options_grants.go` **499**, `mesh_authz.go` **499**, `server_routes.go` **488** (12 headroom), `interfaces/admin/middleware.go` **492** (8), `interfaces/admin/governance.go` **483** (17), `config_load.go` **481** (19). Two new options with docs ≈ +50 lines on `options_grants.go`; two setters ≈ +40 on `server_routes.go`; admin tier-2 + 2 setters + rekey ≈ +55 against 25 combined headroom. `interfaces/admin` is at 10 non-test files (cap `maxGoFilesPerDir=10`, not exempt — `directory_fanout_test.go:44-58`), so no new file there either. | `TestMaintainability_FileSize`/`TestMaintainability_` fail mid-implementation; AGENTS.md §2 requires "split before feature work if the change would cross a budget". | Plan the redistribution now: move ~60 lines out of `options_grants.go` (e.g. relocate `WithDomainVerificationResolver`/`WithLocalizer` to `options_misc.go` — import-neutral), move the two setters to `accessors_*.go` (or one shared helper + two thin setters), redistribute admin code between `governance.go` and `middleware.go` (both stay under 500, file count unchanged), and land config parse/default in `config_admin.go` (333) instead of `config_load.go`. The split commits precede the feature commits. |
| 4 | **Medium** | **SQLite cross-replica wall-clock coupling needs an explicit bound or an acceptance statement.** | `elapsedSec = (nowNs - last_refill_at_ns)/1e9` with `last_refill_at_ns` persisted by whichever replica wrote last (`sqlite_limiter.go:169-185`); a forward-skewed replica over-refills and stamps a future timestamp; other replicas then hit the `elapsedSec > 0` guard and get no refill until their clock catches up. NTP-scale skew is minor (skew × perSecond per request); multi-minute skew creates real drift windows. | Design Decision 7's blanket "No clock coupling" claim is false for the sqlite backend. | Scope the claim to Memory (monotonic `rate.Limiter`) and Redis (server clock only); state an explicit skew bound for sqlite (the repo's "clocks slew, they do not step backward" doctrine) or drop sqlite from the phase-2 dispatch (Option B, §3). |
| 5 | **High** | **Reload close-discipline omission: the phase-2 hook rebuilds limiters every SIGHUP and never closes the replaced ones.** | `wireRateLimitReload` closes `prev` phase-1 limiters via `closePolicyLimiters` (`main_wiring.go:156,167-176`); the design's `SetPostAuthRateLimitHook` has no analogous step. `MemoryLimiter.StartPruner`/`Close` (`ratelimit.go:160-178`) prove the goroutine-leak mechanism. Also: `closePolicyLimiters`' doc claims "SQLiteLimiter ... doesn't implement io.Closer" (`main_wiring.go:166-173`) — **false**, `SQLiteLimiter.Close` exists (`sqlite_limiter.go:129-137`), so old sqlite limiters are already closed on reload; the comment must be fixed (behavior is safe). | With `security.rate_limit.prune_interval` set, every SIGHUP leaks one goroutine per replaced phase-2 limiter — the exact leak phase-1 guards against. | Extend the close discipline to the phase-2 stores in the same change (setters close the replaced limiter, or the wiring layer closes the previous phase-2 policies), mirror `TestClosePolicyLimiters_*` (`rate_limit_reload_test.go:33`) with a close-counting limiter, and fix the stale doc comment. For sqlite, reuse `sqlite.SharedDB` so phase-1 and phase-2 limiters do not stack independent pools on one file. |
| 6 | **High** | **The "byte-identical admin default" acceptance is unverifiable today — nothing pins the shape.** | Zero references to `rate_limit_exceeded` outside `interfaces/admin/governance.go:244` (grep-verified); `TestHTTPMiddleware_RateLimitUnwiredIsUnlimited` (`middleware_test.go:341`) only asserts the 200 path. The unconfigured 429 is `http.Error` → `text/plain; charset=utf-8`, `nosniff`, body `{"error":"rate_limit_exceeded"}\n` (trailing newline) (`governance.go:306-330`). | The regression the acceptance exists to prevent (routing the unconfigured path through `TooManyRequests` unconditionally) sails through every other test. | Capture a golden (status + all headers + exact body bytes) from today's code **before** any implementation commit; assert byte equality after; pin the configured-mode asymmetry (JSON, no trailing newline) in the same file. |
| 7 | **Medium** | **Admin tier-1 is conditional: per_admin-only config leaves tier-1 nil; the e2e sizing dimension is burst, not rate.** | `wireAdminMW` calls `SetRateLimit` only when `srv.AdminRateLimit() > 0` (`cmd/sso-server/build_app.go:305-307`); no default exists. Tier-1's per-IP bucket is consumed pre-auth by every one of A's flood requests even after tier-2 starts 429ing A, so the load-bearing number is `burst ≥ flood + B + margin`, not "above flood rate". | "Rekeying is load-bearing" holds only for the combination config; the e2e as specified can flake or pass vacuously. | State the conditionality; e2e configures both blocks; correct the verification-mapping formula to burst arithmetic; name new e2e tests `TestE2E_RateLimit*` (`-run TestE2E` does not match the existing `TestRateLimitE2E_*` — verified `test/ratelimit_e2e_test.go:96`). |
| 8 | **Medium** | **Setter mechanics unspecified: must swap via `store.Set`, never the field pointer.** | Phase-1 contract: option creates the store at boot; `SetRateLimitPolicy` does `s.rateLimitStore.Set(p)` only (`server_routes.go:403-430`). The new setters must copy this or a SIGHUP-vs-request race appears (the admin `SetRateLimitPolicyStore` field-assignment pattern is boot-time-only today and must stay so). | Data race under `-race`; hot-reload corruption. | State the rule in the design; pin with concurrent `-race -count=10` tests (`Checkpoint`+`Set`, setter+live request). |
| 9 | **Medium** | **Grant-limiter migration equivalence is untested.** | `WithGrantTypeRateLimit` semantics: `tokensPerSec >= 0` → `rate.NewLimiter`, negative → nil/unlimited (`options_grants.go:130-145`); deny at `perSecond<=0` returns retry 0 (`ratelimit.go:195-206`). `rate.NewLimiter(0, burst)` vs `NewMemoryLimiter(0, burst)` must agree on the deny-all branch. | Silent semantic drift in the fix the design explicitly ships. | Add the semantics table during migration (negative→200, 0→429 no Retry-After, positive→burst then 429). |
| 10 | **Medium (doc)** | **Mesh checkpoint protects response work only** — the design's "mirrors /userinfo cost-bounding" rationale is wrong. | `MeshAuthorize` internally runs `deriveMeshIdentity` → `resolveLocalSubject` + `permissions.Roles` (`mesh_authz.go:309-330`) before the proposed checkpoint. | A future reader "fixes" the placement by moving the checkpoint into the dep-free seam and breaks the layering or the fairness property. | Restate: the mesh checkpoint bounds per-subject response work only; fairness holds; keep the HTTP-wrapper placement (the gRPC ext_authz module reuses `MeshAuthorize` and must not inherit an sso-owned store). |
| 11 | **Low (doc)** | **`SetRequest` ripple undercounts implementers: four production, not two.** | `core.Context` (`shared/core/router.go:111-128`), `backgroundHandlerContext` (`sso_wiring.go:277-304`), `ginContext` (`adapters/gin/adapter.go:171-226`), `echoContext` (`adapters/echo/adapter.go:196-255`). The binary uses `sso.NewStdRouter` (`build_app_core.go:155`), so compile-guard catches all — but the SDK-facing adapters break too. | Surprise compile breaks in the SDK surface. | Name all four in the implementation checklist; `SetRequest` is trivial on each. |
| 12 | **Low** | **Namespace-collision invariant needs extension to all four stores + bare-keyspace reservation.** | After the tier-1 rekey, admin tier-1 keys are bare IPs — the same strings as SSO phase-1 `KeyByClientIP`. `KeyByClientIDOrIP` shares the `client:` prefix (`middleware.go:57-71`); `"admin"` vs `admin:<subject>` live in different stores today. | Sharing one limiter instance across phases merges budgets (e.g., admin flood drains the SSO login IP bucket). | Extend the "never share an instance" rule to all four stores; reserve the bare keyspace for pre-auth tiers; optional `serverbuildplatform` distinct-instance unit test. |
| 13 | **Low** | **Public-client fallback delivers zero marginal protection; shared-IP side channel inherited.** | A single valid auth code replays indefinitely against any secret-less `client_id` (code consumption happens inside the grant handler), burning the phase-2 IP bucket; phase-1 already bounds the same key. Same-NAT actors modulate each other's 429 rate. | Overstated config-reference note. | Say exactly this in config-reference; one sentence on the shared-IP channel as a conscious residual. |
| 14 | **Info** | **Backend knob is shared between phase-1 and phase-2** — `security.rate_limit.backend` dispatches all four stores; no per-surface override. | `BuildRateLimitPolicy` dispatch (`build_ratelimit_cluster.go:42-60`); design Decision 6 "backend shared with `security.rate_limit.backend`". | An operator cannot choose memory for phase-2 while redis for phase-1 (or vice versa); sqlite's per-Allow disk write lands on `/token`+`/userinfo` too. | Acceptable for this change (matches "shared dispatch"); document; revisit if an operator asks for per-surface backends. |
| 15 | **Info** | **Config-file references in Decision 6 are slightly off** — `RateLimitConfig` lives in `config/config_admin.go:46`, not `config_metrics_security.go`; `SecurityConfig` is at `config_metrics_security.go:22`. | Verified. | Cosmetic. | Fix the anchors when writing the config section. |

## 3. Decision options

**Option A — adopt the design with the mandatory correction set (recommended).**
Keep all nine decisions; land five corrections in the same doc/implementation
sweep: (1) Decision 7 rewritten per backend with Redis fixed-window named as the
cross-replica contract and sqlite's race+skew stated with a bound or DSN
requirement; (2) Decision 8 corrected to silent fail-open with bounded stall,
plus an explicit accept-or-log decision; (3) split-first budget plan (Finding 3);
(4) phase-2 reload close discipline + stale comment fix; (5) golden capture step
+ e2e burst formula. Trade-off: the change grows by ~1 engineering day of
split/redistribution work, all mechanical, all import-neutral.

**Option B — narrow the phase-2 backend dispatch to memory/redis.** Drops the
sqlite race and clock coupling from the new surfaces entirely. Trade-off:
single-node operators who already run phase-1 on sqlite lose consistency between
phases; the design's "shared dispatch" simplicity is lost; the sqlite findings
would still need documenting for phase-1. Rejected: the backend is not new code —
correcting the contract and documenting the DSN requirement is cheaper than
excluding it, and `SharedDB` reuse (Finding 1 option b) fixes the pool/WAL issues
with a few lines.

**Option C — unconditional admin body unification** (a stricter reading of the
spec's "拒绝统一 rate_limited"). Trade-off: breaks the byte-identical default
acceptance, which the same spec mandates ("未配置 per-admin 时行为与现状字节一致").
Rejected: the design's conditional scope is the only reading satisfying both
sentences; product sign-off recorded in §5.

**Rejected alternatives already covered by the design**: router-level
subject-capture middleware for `/userinfo` (double signature verification +
401-challenge drift), keying public-client buckets on `client_id` (spoofable —
the spec's own UNSAFE analysis), constant-key admin tier-1 in configured mode
(starves tier-2's promise), unconditional `rate_limit_exceeded` removal (breaks
byte-identical default).

## 4. Prioritized implementation sequence

All milestones keep the mandatory gate loop green after each commit
(`go build ./... && go vet ./...` + `go test -run 'TestMaintainability_|TestArchitecture_' .`);
`make ci` at each milestone boundary.

| # | Milestone | Content | Compatibility | Exit check (executable) |
|---|---|---|---|---|
| M0 | Pre-change capture | Golden admin 429 (status/headers/bytes incl. `\n`); baseline `make ci` green; record `rate_limit_exceeded`+grant-429 shapes | None (no code) | `go test ./... -race` green; golden file committed |
| M1 | Split-first + shared plumbing | Redistribute `options_grants.go`/`server_routes.go`/admin files per Finding 3 (pure moves, no behavior); `core.HandlerContext.SetRequest` (4 impls + fakes); `middleware.WithClientID`/`ClientIDFromContext`; `ratelimit.KeyByClientID` + `Checkpoint` + `TooManyRequests` | Byte-identical (moves only; new exports unused) | `TestMaintainability_` green on the split commits; `-run 'KeyBySubject|KeyByClientID'` unit tests; `go vet ./...` |
| M2 | `/token` client bucket + grant fix | `WithTokenEndpointClientRateLimit` + store + credential-gated keying; `checkGrantRateLimit` migration to `ratelimit.Limiter` + `TooManyRequests` (wire fix 1); grant semantics table test; docs/error-codes.md | Wire fix 1 is the only visible change (documented); default off | Unit: A 429/B 200 same IP; credential table (secret-post/Basic/private_key_jwt/mTLS/public-PKCE); no-store headers pinned on the 429 |
| M3 | `/userinfo` + mesh | `UserInfoDeps.StoreUserInfoSubject`/`UserInfoRateLimited` + sso impls (`WithSubject`+`SetRequest`, `Checkpoint`); mesh checkpoint after ALLOW; `WithUserInfoRateLimit` + store | Byte-identical when nil | Unit: `sub:<subject>` after hook; no-token still 401, bucket untouched; oidc ordering test via extended `userinfoHandlerDeps` fake |
| M4 | Admin two-tier | `SetPerAdminRateLimit`/`SetPerAdminRateLimitPolicyStore`; tier-1 rekey (per-IP) in configured mode; tier-2 `admin:<subject>` before idle-timeout; wire fix 2 (configured mode only); golden + asymmetry tests | Unconfigured byte-identical (golden-pinned); configured mode changes tier-1 wire too (documented) | Golden test passes; two-IP tier-1 unit (crafted `RemoteAddr`); idle-expired flood → constant 429 |
| M5 | Config + SIGHUP | `security.rate_limit.token_client.*` / `userinfo.*` / `admin.rate_limit.per_admin.*`; shared single-limiter builder extraction; `SetPostAuthRateLimitHook` wired in `main_wiring.go`; **close replaced phase-2 limiters**; fix `closePolicyLimiters` doc comment; sqlite via `SharedDB`+`NewSQLiteLimiterWithDB`; config-reference (incl. Decision 9 floor note, shared-instance invariant, per-backend semantics, skew bound, public-client residual) | Reload `Ignored` when unwired (visible); counters persist on shared backends — raised burst applies fleet-wide (document) | `reload_test.go` 4-pattern mirrors; close-counting test through the new setters; `-race -count=10` setter-vs-request tests; backend dispatch table test |
| M6 | e2e + metrics + gates | `TestE2E_RateLimit*` (token/userinfo deterministic burst; admin burst ≥ flood+B+margin); metrics assertion per surface (`sso_rate_limit_hits_total`); bench-gate promotion of the modeled checkpoint benchmark; feature-matrix row | Full contract state | `go test ./test/ -run TestE2E -v`; `go test ./... -race`; `make ci` |

**Risks (top).** (a) Split-first churn colliding with concurrent work in
`interfaces/sso` (at the 60-file ceiling, moves are the only lever — keep them
pure and separate commits). (b) The sqlite decision-race: if M5 routes through
`SharedDB` without the concurrent cross-instance test, the race ships silently —
the test must land with the route change. (c) The e2e admin arithmetic: burst
sizing per Finding 7, or the test flakes under `-race` latency inflation.
(d) Wire-fix clients: both fixes are documented contract repairs, but SPA
branches on `unsupported_grant_type` change behavior — call it out in
`docs/error-codes.md` in the same commit as M2/M4.

## 5. Unknowns requiring owner/product decisions

1. **Fail-open observability** (Finding 2): accept silent fail-open on the new
   post-auth checkpoints (codebase-consistent, current reality) or wire a
   fail-open counter at the `Checkpoint` layer? AGENTS.md's fail-open-with-log
   doctrine does not list the rate limiter; the design should pick one and say so.
2. **SQLite contract** (Finding 1): accept "persisted best-effort, use Redis for
   exactness" as the documented contract, or harden the backend (required DSN
   params / `SharedDB` route + concurrent test)? The latter is a phase-1-behavior
   change too — owner needed.
3. **Admin body unification scope** (Finding/C option): confirm the conditional
   reading (unified `rate_limited` only in the opted-in mode) is the accepted
   product semantics, since a stricter reading fails the byte-identical default
   acceptance.
4. **Per-surface backend override**: is sharing `security.rate_limit.backend`
   across phases acceptable, or should phase-2 blocks get an override knob
   (scope creep — flag now, defer by default)?
5. **Bench-gate promotion** (Decision 9): the modeled checkpoint benchmark joins
   `ops/deploy/benchgate/benchmarks.yaml` only with gate-owner sign-off; confirm
   the budget numbers in Decision 9 are the acceptance reference.
6. **Admin tier-2 key**: spec's optional `client:<clientID>` stacking on top of
   `admin:<subject>` is deferred — confirm deferral is acceptable (key-cardinality
   rationale in the design).

## 6. Net assessment

The design is the right architecture: one shared checkpoint mechanism reusing
the tested `PolicyStore`/`Limiter` machinery, identity carried in the request
context at the auth-success point, deps-hook seams where layering forbids direct
imports, and dedicated stores per surface. Its security analysis (credential
gate, oracle-safe placements, namespace invariants) is verified correct. What
must change before implementation is not the architecture but the design's
factual claims about the shared backends (Decision 7/8), its budget arithmetic,
and its test-plan completeness — all of which are addressable with the
corrections above and none of which requires a gate change or threshold
relaxation.
