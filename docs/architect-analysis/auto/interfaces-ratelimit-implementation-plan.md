# Implementation plan: post-auth rate limiting (方向一) — client/user/admin buckets

Source design: [interfaces-ratelimit-design.md](interfaces-ratelimit-design.md)
(Decisions 1-9). Inputs: the security keying review
([interfaces-ratelimit-keying-review.md](interfaces-ratelimit-keying-review.md)),
the distributed-engineer backend review, the performance review (Decision 9),
and the testability review
([interfaces-ratelimit-testability-review.md](interfaces-ratelimit-testability-review.md)),
plus the requirements spec ([interfaces-ratelimit-requirements.md](interfaces-ratelimit-requirements.md)).

Every file, line count, and budget figure below was re-derived from the tree
this session by source read (line counts via full-file count, matching the
`maintainability_budget_test.go` `maxFileLines = 500` gate, which fails only
at > 500). **No Go code was changed to produce this plan; no gates ran.**

## 0. Verification basis

- `interfaces/ratelimit` — `Limiter` SPI (`ratelimit.go:38-40`), `Policy`/
  `PolicyStore` (`atomic.Pointer`, `middleware.go:147-163`), `KeyBySubject`
  (`middleware.go:94-106`), `KeyByClientIDOrIP` UNSAFE (`middleware.go:57-71`),
  `writeTooManyRequests` (`middleware.go:222-233`). **Verified**
- `/token` ladder — `handleToken` (`server_token.go:17-46`):
  `authenticateTokenClient` → residency gate → `beginTokenIdempotency` →
  `dispatchTokenGrant` (grant check at :143, `checkGrantRateLimit` :365-373
  writes 429 + `ErrUnsupportedGrantType`, no Retry-After). `denyPublicClientCredentials`
  at :387-399 is the exact negation of the planned credential gate. **Verified**
- `/userinfo` — `HandleUserInfo` (`protocols/oidc/handle_userinfo.go:41-58`):
  `authenticateUserInfoBearer` → residency → `resolveUserInfoSubject`;
  `MaybeSignUserInfo` seam at :32. `handleMeshExtAuthz` at
  `interfaces/sso/server_userinfo.go:114`; `MeshAuthorize` runs
  `resolveLocalSubject`+`permissions.Roles` internally (`mesh_authz.go:309-330`). **Verified**
- Admin — `HTTPMiddleware` order (`interfaces/admin/middleware.go:325-349`):
  `checkRateLimit` (:330, constant key `adminRateLimitKey`,
  `governance.go:275-314`) → `authenticateHTTP` (:336) → `enforceIdleTimeout`
  (:342) → `checkWriteQuota` (:345). `wireAdminMW` calls `SetRateLimit` only
  when `AdminRateLimit() > 0` (`cmd/sso-server/build_app.go:305-307`). **Verified**
- Reload — `applyRateLimit` (`config/reload/reload.go:370-377`), `SetRateLimitHook`
  (:193), `wireRateLimitReload` (`cmd/sso-server/main_wiring.go:142-160`),
  `closePolicyLimiters` (:167). Comment at :162-166 claims SQLiteLimiter is a
  "silent no-op" for `closeIfCloser` — **wrong, SQLiteLimiter implements
  `io.Closer`; comment drift to fix in C4.** **Verified**
- Config — `RateLimitConfig` (`config/config_admin.go:46-63`, fields
  `backend`, `default_per_sec`, `default_burst`, `prefixes`, `sqlite`,
  `prune_interval`). **Verified**
- `HandlerContext` production implementers: **four** — `core.Context`
  (`shared/core/router.go:111-128`), `backgroundHandlerContext`
  (`interfaces/sso/sso_wiring.go:277-304`), `ginContext`
  (`interfaces/adapters/gin/adapter.go:171`), `echoContext`
  (`interfaces/adapters/echo/adapter.go:196`). The design lists two;
  corrected in P0.1. **Verified**
- Backend semantics: Redis `Limiter` is a **fixed-window counter, not a token
  bucket** (`infrastructure/redis/ratelimit.go:14-22`); SQLite `Allow` uses a
  **deferred** `BeginTx` (modernc maps nil opts to plain `BEGIN`), wall-clock
  coupled via persisted `last_refill_at_ns`; both fail open **silently**
  (no log, no metric); Redis `Allow` has no deadline (go-redis defaults: 3
  retries, 5s dial, 3s read). These change Design Decision 7/8 claims; the
  plan's storage contract is the **Redis fixed-window semantics for
  cross-replica buckets**, with SQLite documented as bucket-exact but
  race-under-concurrency and clock-coupled. **Verified by distributed review,
  spot-checked.**

### Budget arithmetic (the load-bearing constraint set)

| File | Lines | Headroom | Planned delta | Verdict |
|---|---|---|---|---|
| `interfaces/sso/options_grants.go` | 499 | 1 | −17 (move `WithClientRegistrationRateLimit` → `quota.go`, its consumer's home) + ~18 (`WithTokenEndpointClientRateLimit`) + −2 (doc trim) | ≤ 500, zero margin — re-verify per edit |
| `interfaces/sso/server_token.go` | 462 | 38 | +~24 (credential gate, context write, checkpoint; grant 429 rewrite ~0 net) | 486 OK |
| `interfaces/sso/server_routes.go` | 488 | 12 | 0 — setters do **not** land here despite the design's suggestion | untouched |
| `interfaces/sso/sso_wiring.go` | 446 | 54 | +2 store fields (`wiringState`), +~40 (both setters) | ~488 OK |
| `interfaces/sso/server_userinfo.go` | 157 | 343 | +~60 (deps impls, `WithUserInfoRateLimit`, mesh checkpoint) | OK |
| `interfaces/sso/sso_protocol.go` | 499 | 1 | 0 — move `rateLimitStore` field to `wiringState` (cohesion: all rate-limit state in one sub-struct; promoted-field access identical) | OK |
| `interfaces/sso/sso.go` | 499 | 1 | 0 (struct uses embedded state sub-structs) | OK |
| `interfaces/admin/governance.go` | 483 | 17 | −42 (quota block: `SetWriteQuota`/`adminQuotaConfig`/`checkWriteQuota`/`isAdminWriteMethod`, :396-437 → `token_portfolio.go`, 96 headroom) + ~55 (per-admin setters + tier-2 check) | ~496 OK |
| `interfaces/admin/middleware.go` | 492 | 8 | +2 (field) +4 (tier-2 call) | 498 OK, zero margin |
| `interfaces/admin` file count | 10 non-test | ceiling | 0 new files | OK |
| `cmd/sso-server/build_app.go` | 498 | 2 | +~10 (per_admin wiring) requires −10 shuffle (extract `wireAdminGovernanceMW` :327-353 or `drWiring` block to another cmd file) | see C5 |
| `config/reload/reload.go` | 395 | 105 | +~40 (hook + applyRateLimit) | OK |
| `interfaces/ratelimit` | 4 non-test files | 10 | +1 (`checkpoint.go`) | OK |

The two "zero margin" rows are deliberate: the acceptance check for every
touching task is `go test -run 'TestMaintainability_|TestArchitecture_' .`
green plus a stated line-count target, so drift is caught at the first edit,
not at handoff.

## 1. Scope, constraints, assumptions, non-goals

**Scope.** Three post-auth buckets — per-client on `/token`
(credential-gated keying), per-subject on `/userinfo` + mesh (first
production write of `WithSubject`), per-admin tier-2 on the admin API with a
per-IP tier-1 rekey in configured mode — plus the two 429 wire-contract fixes
(grant limiter `unsupported_grant_type`-on-429; admin `rate_limit_exceeded`
in opted-in mode), the shared `Checkpoint`/`TooManyRequests` kernel, the
`SetRequest`/`WithClientID` context plumbing, the SIGHUP post-auth reload
hook, config keys, and the contract docs. All changes stay in
`interfaces/` + `config/` + `cmd/sso-server/` + `protocols/oidc` (interface
methods only) + `shared/core` (one additive method) + docs + `test/` +
`ops/deploy/benchgate/`.

**Constraints.**
- `interfaces/sso` is at its 60-file ceiling: no new files there, ever.
  `interfaces/admin` is at its 10-file ceiling: no new files there either.
- File budget 500 lines, function 50 lines, complexity 15, `if` nesting 3 —
  the K4 shuffle and the governance.go quota move are pre-requisites, not
  cleanup.
- `protocols/oidc` must not import `interfaces/*`; the `UserInfoDeps` hooks
  are the only channel.
- No new `Err*` codes; no new metrics; no new storage backends; no
  `interfaces/sso` file may be created; probes/rate-limit middleware order
  preserved.
- Review corrections are part of the deliverable: P0.1 fixes the design
  doc's claims (4 implementers, mesh rationale, Decision 7/8 backend
  semantics, fail-open silence), and the golden admin test (P0.2) is
  captured **before** any admin code change or the acceptance is
  unverifiable.

**Assumptions.**
- Spec acceptance tests exercise `client_credentials` (confidential) clients;
  the public-client IP fallback therefore passes them unchanged (verified by
  security review §1).
- Decision 9 benchmark numbers (Ryzen AI MAX+ 395) are the acceptance
  reference for the promoted bench-gate benchmark; the gate itself compares
  per-machine baselines at the existing 10% threshold.
- Cross-replica contract for phase-2 buckets is the Redis fixed-window
  semantics (what `security.rate_limit.backend=redis` delivers); SQLite's
  cross-process decision race and wall-clock coupling are pre-existing
  phase-1 limitations, documented — not fixed — in this change.
- Team capacity is unknown; sizes are relative (XS/S/M), not estimates.

**Non-goals (explicit).**
- 方向二 (X-RateLimit-* visibility) and 方向三 (limiter-implementation
  convergence) — out of scope by spec.
- SQLite backend hardening (BEGIN IMMEDIATE DSN requirement, `SharedDB`
  reuse, concurrent cross-instance test) — deferred decision item, see
  Risk R11; documentation only in this change.
- Fail-open logging for Redis/SQLite limiters — accepted as silent,
  documented (R13).
- Admin `client:<clientID>` stacking — deferred by design (Decision 5).
- New metrics beyond the existing `sso_rate_limit_hits_total`.
- Changing the unconfigured admin 429 (`rate_limit_exceeded`) — the fix is
  scoped to the opted-in mode so byte-identical default holds.
- Any change to `docs/auto/*` beyond the design-doc correction P0.1 and this
  plan.

## 2. Task table

Legend — size: XS < 1 day, S 1-3 days, M 3-8 days of focused work,
relative only. Owner skill names the reviewer skill set, not a person.

| ID | Outcome | Files / packages | Depends on | Size | Owner skill | Executable acceptance check |
|---|---|---|---|---|---|---|
| P0.1 | Design doc corrected: all review deltas land in `interfaces-ratelimit-design.md` (see §4 list) | `docs/auto/interfaces-ratelimit-design.md` | — | S | Tech lead | Every item in the P0.1 checklist (§4) present in the doc; grep-verifiable claims (4 implementers named; Decision 7 storage model per-backend; mesh rationale restated; tier-1 conditional stated; burst formula in verification mapping) |
| P0.2 | Golden test pins today's unconfigured admin 429 byte-for-byte (status 429, `text/plain; charset=utf-8`, `X-Content-Type-Options: nosniff`, body `{"error":"rate_limit_exceeded"}\n` incl. trailing newline, `Retry-After` ≥ 1) — captured from HEAD before T5 | `interfaces/admin/middleware_test.go` (extend) | — | XS | QA / admin | Test asserts all four dimensions; green on HEAD; becomes the byte-identical regression for T5 |
| K1 | `Checkpoint(store, r)` + `TooManyRequests(w, retry)` (delegating to unexported `writeTooManyRequests`) + `KeyByClientID` (ctx hit → `client:<id>`, else `KeyByClientIP`; doc carries authenticated-only warning + UNSAFE sibling cross-ref) | `interfaces/ratelimit/checkpoint.go` (new), `middleware.go`, `ratelimit_test.go`, new `checkpoint_test.go` | — | S | ratelimit owner | Unit tests: Checkpoint honors `Policy.Key` default, Prefix rules, and records the rejection metric on deny only; TooManyRequests bytes == middleware 429 bytes; KeyByClientID ctx/fallback table; concurrent `Checkpoint`+`store.Set` loops green under `-race -count=10`; `go vet` clean |
| K2 | `core.HandlerContext.SetRequest(r)` additive; implemented on all **four** production implementers + all standalone fakes (`userinfoHandlerDeps` in `protocols/oidc/handle_userinfo_test.go:33` etc.); `core.Context` impl assigns `c.r`; background impl assigns `b.req`; gin/echo via embedded context | `shared/core/router.go`, `interfaces/sso/sso_wiring.go`, `interfaces/adapters/gin/adapter.go`, `interfaces/adapters/echo/adapter.go`, + fakes | — | S | core SDK owner | `go build ./...` compiles (compile error enumerates implementers); unit test: `SetRequest` replaces the request seen by `Request()`; adapters' existing suites green |
| K3 | `middleware.WithClientID` / `ClientIDFromContext(r)` — twin of `WithSubject`, same unexported-key pattern | `interfaces/middleware/context.go` (+ test) | — | XS | core SDK owner | Round-trip test; `WithSubject`/`SubjectFromContext` unchanged (existing tests untouched) |
| K4 | Budget shuffle (zero semantic change): `WithClientRegistrationRateLimit` → `quota.go` (its consumer `checkClientRegistrationRateLimit` lives at `quota.go:149`); `rateLimitStore` field `sso_protocol.go:130` → `wiringState` (`sso_wiring.go:35`); 2-line doc trim in `WithGrantTypeRateLimit` | `interfaces/sso/options_grants.go`, `quota.go`, `sso_protocol.go`, `sso_wiring.go` | — | S | sso owner | `go test -run 'TestMaintainability_|TestArchitecture_' .` green; `options_grants.go` ≤ 500 after the move; full `interfaces/sso` suite green (pure relocation) |
| T1 | `/token` client bucket: `WithTokenEndpointClientRateLimit(limiter ratelimit.Limiter)` (options_grants.go), `SetTokenEndpointClientRateLimit(limiter) bool` + both store fields in `wiringState` (sso_wiring.go), credential-gated `WithClientID` write + `Checkpoint` in `handleToken` between `authenticateTokenClient` and residency; gate = exact negation of `denyPublicClientCredentials`; setter swaps via `store.Set` only, never the field pointer | `interfaces/sso/options_grants.go`, `sso_wiring.go`, `server_token.go`, `server_token_test.go` (extend) | K1, K2, K3, K4 | M | sso owner | Unit: two confidential clients same IP — A floods → 429 `{"error":"rate_limited"}` + Retry-After, B → 200; bad-secret and no-credential requests bypass (bucket untouched); credential-gate table: secret-post, Basic, private_key_jwt, mTLS, self-signed TLS, public PKCE → IP fallback; ordering pin: checkpoint before residency and before `beginTokenIdempotency`; `SetTokenEndpointClientRateLimit` returns false when option never wired; concurrent swap-vs-request green under `-race -count=10`; `server_token.go` ≤ 500 |
| T2 | Grant-limiter SPI migration: `rateLimiterEntry.limiter` `*rate.Limiter` → `ratelimit.Limiter` (constructed via `NewMemoryLimiter`), `>=0`/negative semantics preserved; `checkGrantRateLimit` reject → `ratelimit.TooManyRequests` (429 `rate_limited` + Retry-After); `grantRateLimiters` map stays boot-only (no runtime mutation) | `interfaces/sso/options_grants.go`, `server_token.go`, `server_token_test.go` | K1, K4 | S-M | ratelimit / sso owner | Semantics table: negative → unlimited (200); 0 → deny-all 429 with Retry-After absent; positive → burst then 429; grant 429 carries `Cache-Control: no-store` / `Pragma: no-cache` (pinned — headers come from `tokenNoStoreHeaders` at `handleToken` top, check must stay below it); existing `unsupported_grant_type` 400-branch tests (`test/handle_token_test.go:249`, `rootcov_flow_test.go:530`) unchanged and green |
| T3 | `UserInfoDeps` +2 methods (`StoreUserInfoSubject`, `UserInfoRateLimited`), called in `HandleUserInfo` between `authenticateUserInfoBearer` success and the residency gate; extended fake (recording subject + switchable verdict) so ordering is testable | `protocols/oidc/handle_userinfo.go`, `handle_userinfo_test.go` | K2 | S | protocol owner | Fake tests: subject stored before checkpoint; checkpoint-true skips residency + lookup; checkpoint-false leaves flow byte-identical; `protocols/oidc` imports unchanged (architecture gate) |
| T4 | sso impls: `StoreUserInfoSubject` (`WithSubject` + `SetRequest`), `UserInfoRateLimited` (`Checkpoint` + `TooManyRequests`, nil-store → false), `WithUserInfoRateLimit` + `SetUserInfoRateLimit` (same shape as T1), store Policy `Key: KeyBySubject`; mesh variant in `handleMeshExtAuthz` after `MeshAuthorize` success (subject from `res.Subject`, same store, 429 on deny); rationale comment restated: mesh checkpoint bounds **response work only** — validation + roles lookup already ran inside `MeshAuthorize`; do not move it into the dep-free seam | `interfaces/sso/server_userinfo.go`, `sso_wiring.go`, `server_userinfo_test.go` | K1, K2, T3 | M | sso owner | Integration: user A (valid token) floods → 429, user B → 200, no-token → 401 with bucket untouched (oracle pin); mesh: denied token never consumes a bucket, allowed request consumes subject bucket; `WithSubject` → `KeyBySubject` = `sub:<subject>` round-trip; setter false-when-unwired + `store.Set`-only swap; concurrent swap test `-race -count=10` |
| T5 | Admin two tiers as one opt-in unit: `SetPerAdminRateLimit(tokensPerSec, burst)` + `SetPerAdminRateLimitPolicyStore(store)`; tier-1 rekey to `middleware.RealClientIP(r)` in `checkRateLimit` (request threaded in; constant `"admin"` key when unconfigured); tier-2 `admin:<claims.Subject>` direct `Allow` right after `authenticateHTTP` success, before `enforceIdleTimeout`; both tiers reject via `ratelimit.TooManyRequests`; quota block (`SetWriteQuota`/`adminQuotaConfig`/`checkWriteQuota`/`isAdminWriteMethod`) relocated to `token_portfolio.go` first | `interfaces/admin/governance.go`, `middleware.go`, `token_portfolio.go`, `governance_test.go`, `middleware_test.go` | K1, P0.2 | M | admin owner | Golden test (P0.2) byte-identical with no `SetPerAdminRateLimit*` call; configured-mode asymmetry pair pinned (both tiers `application/json` `rate_limited`, no trailing newline); tier-1 per-IP independent buckets via crafted `r.RemoteAddr` (precedent `test/geo_middleware_test.go:41`); tier-2 ordering table over session states (valid / idle-expired / revoked) → constant 429 shape; two admin tokens independent buckets; invalid-token spray → byte-identical 401s, consumes only tier-1; `governance.go` ≤ 500 and `middleware.go` ≤ 500 |
| C1 | Config keys: `security.rate_limit.token_client.{per_sec,burst}`, `security.rate_limit.userinfo.{per_sec,burst}` (backend shared with `security.rate_limit.backend`), `admin.rate_limit.per_admin.{per_sec,burst}`; `(0,0)` = absent = off; shared-builder semantics: `(0,0)` must map to nil limiter (off), never `NewMemoryLimiter(0, 1)` which denies all | `config/config_admin.go` (RateLimitConfig extension), `config/config_metrics_security.go` (Security block), `config/config_load.go`, config tests | — | S | wiring owner | Config tests: absent → zero/off; parse round-trip; `(0,0)` → off mapping unit test (builder level); validation rejects negative burst |
| C2 | Shared single-limiter builder extracted from `serverbuildplatform.BuildRateLimitPolicy` (memory/sqlite/redis dispatch incl. `(0,0)`→nil and prune wiring), used by both boot and reload paths | `cmd/sso-server/serverbuildplatform/build_ratelimit_cluster.go`, `build_ratelimit_cluster_test.go` | C1 | S | wiring owner | Dispatch table test: backend selection per `cfg.Backend`; construction-error propagation; boot-path policy byte-identical (existing build tests green) |
| C3 | `SetPostAuthRateLimitHook(fn func(config.RateLimitConfig) error)` + `applyRateLimit` extension (rebuild token_client + userinfo limiters, call once per Reload); admin per_admin stays boot-config with runtime `PolicyStore` swap (not in the reload set) | `config/reload/reload.go`, `reload_test.go` | C1, T1, T4 | S | wiring owner | Four mirrors of `reload_test.go:140-245`: wired+change → exactly one Applied; multiple leaf changes (`token_client`+`userinfo`) → exactly one hook call; unwired → Ignored; hook error → Ignored + `Current()` untouched |
| C4 | `main_wiring.go`: wire the new hook via the shared builder; **close replaced phase-2 limiters** on every SIGHUP (extend the `closePolicyLimiters` discipline to the two phase-2 stores — pruner goroutine and `*sql.DB` leak per reload otherwise); fix the comment drift at `main_wiring.go:162-166` (SQLiteLimiter IS an `io.Closer`) | `cmd/sso-server/main_wiring.go`, `rate_limit_reload_test.go` (extend) | C2, C3 | S-M | wiring owner | Wiring tests mirror `TestClosePolicyLimiters_*` with a close-counting limiter through the new setters; sqlite backend reload does not accumulate `*sql.DB` handles (close-count assertion); SIGHUP applies on next request; unwired → Ignored |
| C5 | `build_app.go`: wire `admin.rate_limit.per_admin.*` → `SetPerAdminRateLimit*` when configured; per_admin-only config leaves tier-1 nil/unlimited (documented conditional); shuffle to make room (−10 lines: extract `wireAdminGovernanceMW` :327-353 or `drWiring` chunk to a cmd file with headroom) | `cmd/sso-server/build_app.go` (+1 cmd file for the shuffle), build tests | C1, T5 | S | wiring owner | Build test: per_admin block configured → both setters called; per_admin-only → tier-1 nil asserted; `build_app.go` ≤ 500 after shuffle |
| E1 | e2e trio, named `TestE2E_RateLimit*` so `go test ./test/ -run TestE2E -v` matches: token client (two confidential clients, same httptest IP, burst=1, flood once → 429/200, no-store pinned), userinfo (two valid tokens, alice 429 / bob 200 / no-token 401), admin (two admin subjects, shared NAT IP, **both** rate_limit blocks configured, tier-1 `burst ≥ flood + B + 2x margin`, A's flood → 429s then B → 200; invalid-token flood from same IP → byte-identical 401s) | `test/` (`package ssotest`), new `ratelimit_e2e_test.go` (extend existing harnesses: two-token admin variant of `newAdminHTTPHarness`) | T1, T4, T5, C4, C5 | M | test engineer | `go test ./test/ -run TestE2E -v` runs the new tests; deterministic-burst doctrine in doc comments (exhausted-state assertions only, no `time.Sleep`, `-race`-immune by construction); `-count=3` green |
| E2 | Rejection-metric assertions per new surface (`sso_rate_limit_hits_total` via `Checkpoint`'s `recordRejection`) | `interfaces/ratelimit/ratelimit_metrics_test.go` (extend), one e2e metrics check (pattern `TestRateLimitE2E_429sCountedAs4xxInMetrics`) | T1, T4, T5 | S | test engineer | Metrics counter increments on each surface's 429 and not on allowed traffic; tenant label path via `TenantKeyFunc` exercised on deny only |
| E3 | Modeled checkpoint benchmark (store.Get + Policy.Key + Allow) promoted **explicitly** into the bench gate (doctrine: new benchmarks never silently join); numbers within Decision 9 budgets (p99 ≤ 5 µs memory / ≤ 100 µs sqlite / ≤ 2 ms redis; deny add-on ≤ 1 ms) | `interfaces/ratelimit/ratelimit_bench_test.go`, `ops/deploy/benchgate/benchmarks.yaml` | K1 | S | performance owner | Bench gate runs green at 10% threshold vs. baseline; measured medians within budget table |
| E4 | Contract docs in the same change (AGENTS.md §5.6): config-reference (new keys, tier-1 rekey + body-unification note, dedicated-instance invariant naming **all four stores** + bare-keyspace reservation, per-backend latency floors, sqlite DSN/cross-process semantics + clock note, Redis outage latency note, hot-reload table entry, public-client residual, setup-account sub collision, 429-precedence sentence, `(0,0)`=off), error-codes (`rate_limited` phase-2 sources; the two fixes), feature-matrix (post-auth limiting flags) | `docs/config-reference.md`, `docs/error-codes.md`, `docs/feature-matrix.md` | all | S-M | tech lead | `make ci` config/route checks green; every new config key greppable in config-reference next to its latency-floor note; error-codes `rate_limited` row lists the four phase-2 sources + both fixes |

## 3. Dependency graph and critical path

```
P0.1 ─┐
P0.2 ─┼── G0 (parallel, immediately)
K4   ─┘
        │
G1 (parallel):  K1 ──┐   K2 ──┐   K3 ──┐   C1 ──┐
        │            │        │        │        │
G2 (parallel):  T1 = K1+K2+K3+K4   T2 = K1+K4   T3 = K2   T5 = K1+P0.2
        │
G3 (parallel):  T4 = K1+K2+T3   C2 = C1   C5 = C1+T5
        │
G4:  C3 = C1+T1+T4 → C4 = C2+C3   |   E2 = T1+T4+T5   E3 = K1
        │
G5:  E1 = T1+T4+T5+C4+C5   (E4 = all, after E1)
        │
G6:  full gates: go build/vet, maintainability+architecture, ./... -race,
     test/ -run TestE2E -v, make ci, benchgate
```

**Critical path:** `K1 → T1 → C3 → C4 → E1 → E4 → gates` and the
converging `P0.2 → T5 → C5 → E1` chain. **Safe parallel work:** G0 and G1
are fully parallel (K4 is a pure relocation but must precede T1/T2's edits to
`options_grants.go`); E3 and E2 can start as soon as their deps land; P0.1
and P0.2 have no deps and can start immediately. **Integration points:**
`wiringState` (sso_wiring.go) is the single convergence point for T1+T4's
stores and setters — whoever lands second must rebase on the first; the
`SetPostAuthRateLimitHook` signature is the contract between C3 and C4.
**Ownership:** ratelimit kernel (K1, T2), core SDK (K2, K3, T1, T3, T4),
admin (T5), wiring (C1-C5), test (P0.2, E1, E2), performance (E3), tech
lead (P0.1, E4). **External dependencies:** none beyond the tree; the two
`interfaces/adapters` files are SDK-facing but the binary uses
`NewStdRouter` — compile-guard-caught, no runtime risk.
**Unknowns:** exact post-shuffle line counts of `options_grants.go` and the
admin files (acceptance checks re-measure per edit); bench-gate baseline
behavior on the implementer's machine.

## 4. Risk register

| # | Risk | Severity | Mitigation | Trigger | Fallback |
|---|---|---|---|---|---|
| R1 | Budget ceilings: `options_grants.go`/`middleware.go` at zero margin; `build_app.go` over by ~10 | High | K4 shuffle + governance quota move + C5 shuffle land **before** feature edits; every task's acceptance re-measures ≤ 500 | `TestMaintainability_` fails after an edit | Relocate more code (e.g. `WithGrantTypeRateLimit` block → `quota.go`; `methodScopeForPath` → `users.go`); shrink doc comments |
| R2 | Public-client bucket spoof if the credential gate is wrong (e.g. missing mTLS/assertion branches) | High | Gate = exact negation of `denyPublicClientCredentials`; 6-class table test (T1); security-review sign-off on the table | Any auth class absent from the table | Stricter: key public clients by IP unconditionally (drop `client:` for secret-less clients entirely) |
| R3 | Setter swaps the store field pointer → SIGHUP-vs-request data race | High | Setters copy `SetRateLimitPolicy`'s pattern (`store.Set` only, `server_routes.go:403-430`); concurrent `-race -count=10` tests (T1/T4) | Any setter assigning the field | Boot-only option + restart semantics (revert to hot-swap) |
| R4 | SIGHUP leaks: replaced phase-2 limiters' pruners / `*sql.DB` never closed | High | C4 extends `closePolicyLimiters` discipline to both phase-2 stores; close-counting wiring test | Wiring test fails; `TestClosePolicyLimiters_*` mirror absent | Setters close the previous limiter themselves |
| R5 | `(0,0)` config maps to deny-all (`NewMemoryLimiter(0, burst≥1)`) instead of off | High | C1/C2: builder maps `(0,0)` → nil limiter; unit test pins it | Config test shows deny-all on absent block | Explicit "off" sentinel at config decode; validation rejects `(0,0)`-as-on ambiguity |
| R6 | Admin e2e sizing in the wrong dimension (rate instead of burst) → flaky or misleading | Medium | Burst formula `tier-1 burst ≥ flood + B + 2x margin`; both blocks configured; exhausted-state assertions only; no sleeps (E1) | Intermittent e2e failure | Raise margin; drop the B-request step to a separate test |
| R7 | Golden admin test not captured before T5 → byte-identical acceptance unverifiable | High | P0.2 is a hard dependency of T5 (graph enforces it) | T5 lands without P0.2 in the diff | Revert to HEAD, capture, re-apply (awkward; the graph ordering prevents it) |
| R8 | Post-auth reload hook unwired → SIGHUP config silently no-op | Medium | C3+C4 land together; unwired → `Ignored` test (visible, not silent) | Reload test reports Ignored unexpectedly | Wire check in `main_wiring.go` smoke test |
| R9 | The two deliberate 429 wire changes break existing client branches | Medium | Both are spec-mandated fixes; documented in error-codes in the same change; admin change scoped to opted-in mode (byte-identical default holds) | External integration test failure | Last resort: config flag restoring legacy bodies (violates spec; requires approval) |
| R10 | Mesh checkpoint placement "fixed" later into the dep-free seam (double-validation temptation) | Medium | T4 restates rationale in code comment; design doc corrected (P0.1) | Review drift on mesh code | Keep placement; doc note forbids the move |
| R11 | SQLite cross-process semantics: deferred-BEGIN decision race, wall-clock coupling, silent fail-open, busy_timeout coupling — now on more surfaces | Medium | Documented as the storage contract (P0.1, E4): DSN guidance (`_txlock=immediate`, `_pragma=busy_timeout(5000),journal_mode(WAL)`), explicit skew bound, "fail open silently, unchanged from phase-1". Deferred backlog: concurrent cross-instance test + `sqlite.SharedDB` reuse + required-DSN validation | Operator deploys sqlite backend multi-replica | Documented limitation stands; fix is a separate decision |
| R12 | Redis outage on the auth path: fail-open but slow (3 retries, 5s dial, 3s read, no deadline) — every checkpoint stalls multi-seconds exactly when a flood saturates Redis | Medium | E4 documents bounded-stall behavior + recommends `redis.max_retries`/timeouts for the auth path; acceptance: fail-open is the deliberate codebase-consistent choice (auth availability wins) | Operator sees multi-second stalls on `/token` | Tune go-redis timeouts; keep fail-open |
| R13 | Silent fail-open (no log/metric) overstates the "fail-open-with-log doctrine" claim | Low | P0.1 corrects the wording; E4 documents silence as accepted | Review check on Decision 8 | One-line log in backend error paths (separate small change) |
| R14 | Tier-1 conditionality misread: per_admin-only config leaves tier-1 nil/unlimited | Low | P0.1 states it; C5 asserts it; E1 configures both blocks | Build test misreads | None (outcome is safe) |
| R15 | New e2e tests invisible to `go test ./test/ -run TestE2E -v` (regexp match on literal `TestE2E`) | Low | Names are `TestE2E_RateLimit*` (E1 acceptance) | Handoff command misses them | Rename at review |

**Deferred backlog (verified, not in this change's critical path):** SQLite
BEGIN IMMEDIATE / `SharedDB` reuse / concurrent cross-instance test (R11);
fail-open observability counters or backend logging (R13); admin tier-1
global-cap hardening (security review §3 restated tradeoff).

## 5. Milestones and final gate

**M1 — Kernel, context, baseline (P0.1, P0.2, K1-K4).** Deliverable:
`Checkpoint`/`TooManyRequests`/`KeyByClientID`, `SetRequest` on four
implementers, `WithClientID`, admin golden test, budget shuffle.
Verified by: per-package unit suites under `-race`; `TestMaintainability_`
+ `TestArchitecture_` green; `interfaces/sso` all ≤ 500.

**M2 — Three surfaces (T1-T5).** Deliverable: `/token` client bucket
(credential-gated), grant 429 fix, `/userinfo` + mesh subject bucket,
admin two tiers. Verified by: per-package suites `-race -count=10`;
credential-gate 6-class table; session-state 429 table; golden
byte-identical + asymmetry pair; `protocols/oidc` layering gate green.

**M3 — Config, reload, wiring (C1-C5).** Deliverable: config keys, shared
builder, post-auth reload hook, close discipline, admin boot wiring.
Verified by: config tests, 4 reload mirrors, close-counting wiring tests,
build-app conditional tests.

**M4 — e2e, observability, bench, docs (E1-E4).** Deliverable: three
deterministic-burst e2e tests, per-surface metrics assertions, promoted
checkpoint benchmark, contract docs.

**Final gate / rollout checklist.**
1. `go build ./... && go vet ./...` and
   `go test -run 'TestMaintainability_|TestArchitecture_' .` after every
   edit (AGENTS.md §2).
2. Handoff: `go test ./... -race`; `go test ./test/ -run TestE2E -v` (new
   tests named `TestE2E_RateLimit*` — the command's regexp matches);
   `make ci` (nested modules, examples, config, module validation);
   bench gate via `ops/deploy/benchgate` with the promoted benchmark.
3. Contract docs committed in the same change as the code they describe:
   config-reference (new keys + latency floors + sqlite/Redis notes +
   four-store instance invariant + `(0,0)`=off), error-codes (phase-2
   sources + the two 429 fixes), feature-matrix (post-auth flags).
4. Rollout: all new config keys are additive; unconfigured defaults are
   byte-identical (pinned by P0.2 and the T1/T2/T4 bypass tests). The two
   wire changes are deliberate, documented contract fixes; the admin body
   change only appears in opted-in mode. SIGHUP reload is per-process:
   rolling deployments see a mixed window (phase-1 doctrine, unchanged);
   with sqlite/redis backends, bucket state persists across reloads and a
   raised burst applies fleet-wide on the next request to any replica —
   documented in config-reference. `security.rate_limit.backend=redis`
   delivers the cross-replica contract (fixed-window); sqlite is
   documented as bucket-exact but cross-process-racy and wall-clock
   coupled (R11).
5. Rollback: remove the new config keys and restart — the boot options
   were never wired, so the code paths are byte-identical to pre-feature
   builds (the `Set*RateLimit` setters return false when unwired; SIGHUP
   alone restores numbers but cannot turn a boot-wired gate off without a
   restart, matching `SetRateLimitPolicy`'s "can't add a gate after boot"
   contract).
6. Report any pre-existing gate failure separately (AGENTS.md §5.7);
   no gate threshold is relaxed anywhere in this change.
