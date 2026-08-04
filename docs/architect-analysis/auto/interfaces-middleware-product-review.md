# Product Review: interfaces/middleware typed named-slot pipeline (`middleware.Chain`)

Sources: `docs/auto/interfaces-middleware-design.md` (the design), the spec at
`docs/architect-analysis/auto/interfaces-middleware-spec.md`, and four
independent reviews (protocol, security, QA, architecture) of the design at
commit `cde984d6`. All claims below were re-verified against the tree at
`cde984d6`; checks that actually ran: `go build ./... && go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .` (all green), plus
targeted reads/greps of every cited file. This is an advisory release
proposal; no code was modified.

## 1. Problem, users, desired outcome, evidence, assumptions, non-goals

### Problem

The request admission pipeline is the product's security boundary, but its
ordering is enforced by prose, not structure:

- The canonical chain (probe mux → Recover → Tracing → Metrics →
  TrustedProxies → RateLimit → Degradation → AcceptVersion → BodyLimit →
  Compression → CORS → SecurityHeaders → RequestLog → Router) is assembled by
  **seven hand-written functions spread over three files** —
  `buildMiddlewareChain` + `wrapInnerMiddlewares` + `buildProbeMux`
  (`interfaces/sso/server_routes.go:354-485`), `wrapPanicRecovery` +
  `wrapCompression` + `wrapAPIVersioning` (`interfaces/sso/sso_wiring.go:389-421`),
  `degradationGate` (`interfaces/sso/server_health.go:347-360`). **Verified.**
- Each ordering invariant is a comment contract ("trustedProxies MUST wrap
  before rate limiting", `server_routes.go:364`; "DR gate sits just inside
  rate limiting ... just outside body-limit", `:368-372`). A future
  middleware placed in the wrong slot silently breaks oracle safety or opens
  a rate-limit escape and is caught only in review.
- The package mixes two middleware signatures (`func(http.Handler) http.Handler`
  for `Recover`; `core.MiddlewareFunc` for `Auth`/`CORS`/`Logger`/`Tracing`/
  `RequestID` — `interfaces/middleware/middleware.go:27,52,71,95,119,160`),
  and every composition site pays a hand-written bridging tax.
  **Verified.**
- The legacy `Auth`/`CORS` surfaces are dead outside aliases and tests
  (treewide grep by the reviews: zero production consumers); they persist as
  a competing composition model. **Verified.**

### Users

| User | Relationship to the change |
|---|---|
| **Maintainers of `interfaces/sso` wiring** | Primary beneficiaries: the seven-function assembly collapses to one `buildChain` construction site; slot order becomes compile-time-enforced; `server_routes.go` line pressure (488/500) is relieved by ~70 lines |
| **Security/observability engineers** | The four ordering invariants (trusted-proxies-before-rate-limit, rate-limit-outside-degradation, probes-outside-chain, idempotency-after-auth) become committed regression tests that fail CI instead of review |
| **SDK consumers (Go)** | Public API surface: `sso.AuthMiddleware` and `sso.CORS` are removed (breaking); `middleware.Logger`/`Tracing` change signature shape; `middleware.Chain`/`FromCore` are new. In-tree consumers: zero for the removed/renamed surfaces (**Verified**); external consumers unknown |
| **Operators of the stock `sso-server` binary** | Zero observable behavior change under the recommended decision (D1=Option A). `cmd/sso-server` and `cmd/sso-minimal` are untouched — they compose through `sso.Server` (**Verified**). The feature-gate SIGHUP hot-reload path must keep its byte-identity oracle |

### Desired outcome

A typed `middleware.Chain` (12 named slots, one unexported field per slot, one
`With*` builder per slot, `Wrap` applying them in a fixed sequence — a wrong
order unrepresentable at compile time), one chain construction site in
`interfaces/sso`, one chain signature with a single `FromCore` boundary
adapter, and four committed ordering-invariant tests with negative controls —
**with zero observable behavior change** (decision D1, Option A).

### Evidence base

- All budget claims verified: `interfaces/middleware` at the 10-file ceiling
  (no new root file possible), `interfaces/sso` at the 60-file ceiling
  (edits only), `server_routes.go` 488 lines, `sso_wiring.go` 446,
  `server_health.go` 443, `aliases.go` 500. **Verified.**
- All 11 slot-filling constructors are `func(http.Handler) http.Handler`-
  shaped, so a type *alias* (not a defined type) makes them assignable with
  zero conversions. **Verified.**
- `middleware.Idempotency` has zero production call sites; its migration is
  therefore contract-only (test (d) pins a documented contract, not an
  enforced composition). **Verified.**
- `feature_gate_hotreload_test.go` (481 lines) wires `WithTracingMiddleware`
  in 9 tests and asserts byte-identity between gated-off and never-mounted
  paths, including the **absence** of `X-Request-Id`/`traceparent`/
  `X-Trace-Id` (17 `X-Request-Id` mentions); `shared/core/router.go:244-253`
  documents that this is deliberate: gated-off routes are treated as NOT
  MATCHED so no global middleware stamps headers a genuinely-unmatched
  request never gets. **Verified.** This is the single material conflict
  between the design and the tree (finding F1, all four reviews, High).
- Test-churn inventory beyond the design's risk register:
  `interfaces/middleware/middleware_extra_test.go` has **16 direct
  `core.NewContext` call sites** (Auth ×4, CORS ×5, Logger ×1, Tracing ×5,
  RequestID ×1) — the largest rewrite surface, unnamed in the design
  (finding F3, Medium); `interfaces/sso/health_test.go:121` calls
  `middleware.Tracing()(ctx)` directly (**Verified**);
  `test/middleware_test.go` (294 lines) drives the fake-context harness,
  which after migration has zero remaining users and should be deleted.
- `docs/observability.md:97-99` stack diagram is already drifted (metrics
  position wrong) and `interfaces/cors/cors.go:5` leaves a stale `sso.CORS`
  reference — same-change doc updates required by AGENTS.md §5.6.
  **Verified.**

### Assumptions

1. The canonical chain order is the contract and is **not** being changed
   (spec §0). The design's entire value proposition rests on this.
2. In-tree grep evidence proves zero in-tree consumers of `middleware.Auth`/
   `CORS`/`Idempotency`; it cannot prove zero external SDK consumers. The
   SDK break must be approved with that residual uncertainty (D2).
3. `make ci` at handoff is the release gate; review-suite runs at design time
   are advisory.
4. No OIDF certification, adoption, latency, or delivery targets are claimed
   or assumed anywhere in this proposal.

### Non-goals

- **No behavior change to chain order, probe bypass, or rate-limit
  semantics.** Per-`Handler()` chain rebuild and the `rateLimitStore` reset
  are explicitly preserved, not "fixed" (the design says so; this proposal
  agrees — a refactor that changes nothing observable).
- **No change to `shared/core/router.go`** (route-level `MiddlewareFunc` API
  stays), `interfaces/ratelimit`, `platform/tracing`, `platform/audit`, or
  the `idempotency_capture_missing` canary.
- No new config, endpoint, `Err*`, or store surface; no persistence.
- Direction 2 (request-state registry/capture-stack unification) and
  direction 3 (observability unification) are out of scope.
- No `interfaces/web` work — Snaplink is API-only; the change touches no
  frontend assets.
- Not a nested-module or external-frontend change: SDK (`interfaces/...`)
  plus stock-binary wiring (`interfaces/sso`), with `cmd/` binaries untouched.

## 2. Prioritized scope

### Must (release-blocking)

| # | Item | Rationale |
|---|---|---|
| M0 | **Decision gate D1**: settle request-ID placement. **Recommended: Option A** — `TracingMiddleware` stays `core.MiddlewareFunc` on `Router.Use`; the chain's Tracing slot hosts OTel only. All four reviews converge on this as the smallest viable resolution: today's OTel span already covers request-ID execution, so the design's own motivation is satisfied with zero semantic loss, and `feature_gate_hotreload_test.go` plus `router.go`'s documented intent stay intact | Under the design as written, 7 committed feature-gate tests fail (baseline sanity check `Fatalf`s first); the design mischaracterizes the break as an auditable "fix". Option B (accept the delta) permanently loses byte-identity over headers on 404s and inverts a security invariant hardened after adversarial review |
| M1 | New `interfaces/middleware/chain` subpackage (one non-test file): 12 unexported slot fields, 12 nil-tolerant `With*` builders, `WithProbes` (map copied), `Wrap` (fixed-sequence `if` chain), `SlotOrder()`, `FromCore`; `middleware.go` re-exports `type Chain = chain.Chain`, `type Middleware = chain.Middleware`, `var FromCore`. Plus `TestChain_CanonicalSlotOrder` and invariant tests (a)(b)(c) + probe-bypass test. Chain not yet wired into `Server` | Purely additive, zero production-path risk; delivers the core security value (compile-time order + committed tests) first |
| M2 | Collapse the seven assembly functions into one `buildChain` in `server_routes.go`; keep `s.rateLimitStore` assignment adjacent to `WithRateLimit` (hot-reload) and `degradationGate` as the single call site; per M0, request-ID stays on `Router.Use`; delete `buildMiddlewareChain`/`wrapInnerMiddlewares`/`wrap*`/`buildProbeMux` | Behavior-identical under Option A; `feature_gate_hotreload_test.go`, `rate_limit_hotreload_test.go`, `degradation_test.go`, and probe tests stay green **unchanged** — the regression indicator that the collapse is faithful |
| M3 | Migrate `Logger` and `Idempotency` to handler shape; implement `FromCore` with **correct propagation** (`next.ServeHTTP(ctx.ResponseWriter(), ctx.Request())` — the design leaves this unspecified, which would silently bypass `CaptureWriter` for writer-swapping middlewares, finding F2); delete `middleware.Auth`/`CORS` and `aliases.go:43-44` `sso.AuthMiddleware`/`sso.CORS`; rewrite the 16 direct-context sites in `middleware_extra_test.go`, `health_test.go:121`, `test/middleware_test.go`; delete the now-unused fake-context harness | The signature migration and SDK break are the only user-visible portion; must include the full blast-radius inventory the design under-scoped |
| M4 | Full gates: `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` | Handoff gate per AGENTS.md |
| M5 | Same-change contract updates (AGENTS.md §5.6): feature-matrix removal note for `sso.CORS`/`sso.AuthMiddleware` (currently absent — **Verified**), release notes, corrected `observability.md` stack diagram, `interfaces/cors/cors.go:5` stale-reference cleanup, fix the design doc's stale cross-references and duplicated copies (D5) | Docs drift is pre-existing (observability.md is already wrong) but ships in the same change per policy |

### Should (included if the Must scope lands cleanly)

| # | Item | Rationale |
|---|---|---|
| S1 | Test (d) negative control with an explicit **inline auth stub** (fixed-token bearer check), since the design's "swapped composition (auth inside Idempotency)" references `middleware.Auth` — which the same change deletes (architect finding 3) | The acceptance test as written is unimplementable; a specified stub prevents scope creep |
| S2 | `FromCore` unit tests: writer identity (handler-visible writer is the `CaptureWriter`), abort short-circuit, abort-after-write double-write hazard documented | F2's regression pin; the boundary adapter is the one new composition surface |
| S3 | `Chain` contract unit tests: zero-value `Wrap` returns router unchanged, nil-slot tolerance, `WithProbes` copy semantics, empty probe map builds no mux | Low cost; pins the documented failure modes |
| S4 | Correct the design's growth-path claims: future slots extend `chain/` files (depth-3 limit forbids `chain/xyz` subpackages); document `Wrap`'s cyclo ≈ 13-14 headroom and the fixed-literal-array alternative | The design's own "future subpackage" path is blocked by the depth gate — the doc must not mislead |
| S5 | Pin the intentional header delta **only if** D1 resolves to Option B (rejection-path and 404 correlation headers) with an explicit test; under Option A this disappears entirely | QA finding MED-2: release notes without a pinning test revert silently |

### Could (defer without harm)

| # | Item | Rationale |
|---|---|---|
| C1 | Re-export `SlotName`/`Slot*` constants from `middleware.go` | Minor API symmetry (architect finding 8); consumers can import `chain` directly |
| C2 | `server_health.go` line-estimate correction in the design budget table (~440-465 realistic, not ~425) | Accounting hygiene; the gate catches a real miss |

### Won't (explicitly excluded)

| # | Item | Rationale |
|---|---|---|
| W1 | **Option B** (uniform request-ID stamping on 404s/gated-off paths) absent an explicit owner override of D1 | Breaks 7 committed regression tests, inverts `router.go`'s documented intent, and delivers only a cosmetic correlation-header nicety |
| W2 | "Fixing" the per-`Handler()` `rateLimitStore` reset or caching the chain | Behavior change beyond the refactor's mandate; explicitly preserved |
| W3 | Making probes rate-limited or moving them inside the chain | Pre-existing, documented tradeoff (AGENTS.md: "Probes remain outside rate limiting") |
| W4 | Any frontend, nested-module, or `cmd/` change | Out of scope; `cmd/` binaries are untouched by construction |

## 3. User stories

All stories are SDK- or stock-binary-owned; there is no frontend ownership.

### US-1 (maintainer): wrong slot order is unrepresentable
**Given** a maintainer wires a new middleware into the chain,
**When** they try to place it in the wrong canonical slot,
**Then** the compiler rejects the code (one unexported field per slot, no
slice to shuffle), and `TestChain_CanonicalSlotOrder` pins the 12-slot list
so adding/removing a slot is an explicit, reviewed change.
*Ownership:* `interfaces/middleware/chain` (SDK).

### US-2 (maintainer): one construction site
**Given** the seven hand-written assembly functions across
`server_routes.go`/`sso_wiring.go`/`server_health.go`,
**When** the collapse lands,
**Then** `grep -n "wrapPanicRecovery\|wrapCompression\|wrapAPIVersioning\|buildProbeMux" interfaces/sso` returns only the `buildChain` site (or absence), and `interfaces/sso` adds no file (60-file ceiling).
*Ownership:* `interfaces/sso` (SDK/stock wiring).

### US-3 (operator): forged-XFF flood is bucketed under the validated IP
**Given** an attacker forges `X-Forwarded-For` per request to rotate the rate-limit key,
**When** TrustedProxies and RateLimit are installed in canonical order,
**Then** the limiter keys on the validated real client IP (untrusted peer →
`RemoteAddr` fallback), and invariant test (a)'s negative control (swapped
order keys on the fallback) fails CI, not review.
*Ownership:* `interfaces/middleware` invariant test (SDK).

### US-4 (operator): flood protection survives shedding; body-limit short-circuits
**Given** a replica is in degradation mode (503 gate),
**When** a flood arrives,
**Then** the rate limiter refuses with 429 before the gate sheds (rate-limit
outside degradation), and a huge-body request to the shedding gate is refused
503 before the body limit reads the body — pinned by invariant test (b).
*Ownership:* `interfaces/middleware` invariant test (SDK).

### US-5 (operator): probes stay byte-identical under load
**Given** a fully populated chain with a shedding gate and an over-limit rate
policy,
**When** `/livez`, `/readyz`, `/metrics` are requested,
**Then** responses are byte-identical to the no-chain case, no bucket is
consumed, and no trusted-proxy dependency applies — pinned by invariant test
(c) and the probe-bypass test.
*Ownership:* `interfaces/middleware` invariant test (SDK).

### US-6 (operator): feature-gate hot-reload keeps its oracle
**Given** the admin/branding/oidc/ciba/caep/federation/self-service gates are
toggled off via SIGHUP on a live server,
**When** a gated-off path is requested,
**Then** the response is byte-identical to a never-mounted path — including
the absence of correlation headers — and `feature_gate_hotreload_test.go`
(9 tests, 17 `X-Request-Id` assertions) passes **unchanged** (D1 = Option A).
*Acceptance:* the file's diff is empty at M2.
*Ownership:* `interfaces/sso` (stock binary behavior; tests in SDK repo).

### US-7 (SDK consumer): idempotency replay never crosses auth
**Given** an authenticated `/token` request commits a cached success under an
`Idempotency-Key`,
**When** an unauthenticated request carries the same key,
**Then** it never receives the replayed success, and the deliberately swapped
composition (auth inside Idempotency, via an inline auth stub per S1) replays
the cached 200 — the failing negative control of test (d).
*Ownership:* `interfaces/sso` composition-site test (SDK).

### US-8 (SDK consumer): writer-swapping middleware survives `FromCore`
**Given** a consumer composes `middleware.Idempotency` (or any writer-swapping
middleware) through `FromCore`,
**When** the composed handler serves a request,
**Then** the handler-visible writer is the `CaptureWriter` — the adapter must
forward `ctx.ResponseWriter()`/`ctx.Request()`, not the caller's originals —
and a replay short-circuits without calling `next` (F2 pin, S2).
*Ownership:* `interfaces/middleware` (SDK).

### US-9 (SDK consumer): upgrade break is explicit and documented
**Given** a consumer upgrading the SDK,
**When** their code references `sso.AuthMiddleware` or `sso.CORS`,
**Then** compilation fails at build time (not runtime), the feature matrix
and release notes carry the removal note, and `interfaces/cors` remains the
CORS path.
*Ownership:* `interfaces/sso` aliases + docs (SDK release).

## 4. Edge-case and dependency table

| Edge case | Current behavior (Verified) | After change | User impact | Fallback |
|---|---|---|---|---|
| Gated-off route vs never-mounted path | Byte-identical, no correlation headers (`router.go:244-253`; `feature_gate_hotreload_test.go`) | Unchanged under D1=A (request-ID stays route-level) | None | If D1=B: 7 tests rewritten, oracle weakened — rejected recommendation |
| Rejection paths (429/503/413) | No `X-Request-Id`/`traceparent` (Tracing ran inside router) | Unchanged under D1=A | None | Under D1=B: headers added; must be pinned (S5) |
| Unmatched 404s | No correlation headers | Unchanged under D1=A | None | Under D1=B: random IDs on every 404 |
| Panic in a slot | Recover outermost → 500 JSON, no panic-body headers (but `Tracing` stamped headers at entry before the panic — QA LOW-4: "header-less" wording is wrong in both states) | Same | None | Pin the actual behavior in a test (LOW-4 fix) |
| `FromCore` with writer-swapping middleware | N/A (adapter is new) | Specified propagation (F2) | Silent capture bypass + `idempotency_capture_missing` audit noise if wrong | Unit tests (S2); fail-open canary preserved |
| `FromCore` abort-after-write | Mirrors `StdRouter` loop today (double-write) | Same, documented | None (router semantics) | Doc note |
| `Idempotency` commit position | Commit happens in handler after `next`; position invariant documented (`idempotency.go:142-153`) | Handler shape moves commit after `next` returns (F3: protocol migration, not signature-only) | None (zero production call sites) | Before/after contract table + capture-missing audit assertion |
| `rateLimitStore` per `Handler()` call | Recreated per call; `SetRateLimitPolicy` hot-reload works | Preserved byte-identically | None | `rate_limit_hotreload_test.go` regression pin |
| Probe mux | ServeMux with path-cleaning; probes outside all slots | Copied map; identical mux construction; server always registers livez/readyz | None | Probe-bypass test; empty-map path returns chained handler |
| `WithProbes` with invalid patterns (`{$}`, `{`, `}`) | Go 1.22 ServeMux panics at registration | Same (SDK caller footgun) | SDK misuse panics at `Wrap` time | Document; sso-server passes only path constants |
| Zero-value chain / nil slots | N/A | `Wrap` returns router unchanged; nil = not installed | None | S3 unit tests |
| Concurrent chain mutation | N/A | Not safe; wire-then-wrap contract | None | Documented; server wires synchronously in `Handler()` |
| SDK upgrade (AuthMiddleware/CORS removal) | Aliases exist; zero in-tree consumers | Compile-time break | External consumers must adjust (unknown count) | Release notes + feature matrix (M5); D2 approval |
| `interfaces/sso` file budget | 60/60 | Edits only | None | Architecture gate |
| `server_routes.go` line budget | 488/500 | ~420-465 after collapse | None | Budget gate; M2 must keep ≤ 500 |

**Dependencies:** M1 has no dependencies (additive). M2 depends on M0/D1
(placement decision). M3 depends on M2 and on D2 (SDK-break approval) and D4
(test-(d) stub). M5 depends on D5 (canonical doc copy). Nothing depends on
external frontend or nested modules.

## 5. Success indicators, MVP boundary, rollout, unresolved decisions

### Measurable success indicators

1. `TestChain_CanonicalSlotOrder` and invariant tests (a)-(d) committed and
   green; each negative control (deliberate slot swap) verified failing
   during implementation, documented in the test comment.
2. `feature_gate_hotreload_test.go` diff is **empty** at M2 (D1=A) — the
   single strongest indicator that the refactor changed nothing observable.
3. Grep acceptance: no `wrap*`/`buildProbeMux` symbols remain in
   `interfaces/sso`; `grep -rn "core.MiddlewareFunc" interfaces/middleware`
   hits only `FromCore` plus the route-level Tracing exception amended in the
   spec (D6).
4. Budgets hold: `interfaces/middleware` ≤ 10 non-test files, `chain/` ≤ 1
   file ≤ 500 lines, `interfaces/sso` stays 60 files, `server_routes.go` ≤
   500, `Wrap` cyclo ≤ 15.
5. `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .`; `go test ./interfaces/
   middleware/... ./interfaces/sso/... -race`; `go test ./test/ -run
   TestE2E -v`; `make ci` — all green.
6. Docs updated in the same change: feature-matrix removal note (currently
   absent), release notes, corrected `observability.md` stack diagram,
   `interfaces/cors/cors.go:5` stale reference.
7. No new `Err*`, endpoint, or config surface; `docs/error-codes.md`/
   `openapi.yaml`/`config-reference.md` unchanged beyond the removal note.

### MVP boundary

**MVP = M0 + M1 + M2** (typed chain, one construction site, invariant tests
(a)-(c) + probe-bypass, D1=Option A): purely additive + behavior-identical
collapse, no SDK break, no test rewrites. This delivers the security value
(compile-time order enforcement, committed invariants) and the maintainability
value (one construction site, line-pressure relief) with zero user-visible
change and can ship even if D2 stalls.

**Full release = MVP + M3 + M4 + M5** (signature unification, `FromCore`,
dead-surface removal, SDK break, full test migration). M3 is separable
because the spec's §1 and §3 goals do not depend on §2's signature collapse;
the dual-signature tax is the part that carries the SDK break.

### Rollout / rollback

- **Rollout:** single commit/release. No config, no migration, no data, no
  operator runbook change (D1=A ⇒ byte-identical behavior). `cmd/` binaries
  untouched.
- **Rollback:** revert the commit. M1+M2 are behavior-identical; M3's only
  external risk is the compile-time SDK break (US-9), which surfaces at build
  time, not runtime.
- **Observability of correctness:** the empty-diff `feature_gate_hotreload
  _test.go` and the unchanged probe/rate-limit/degradation suites are the
  regression tripwires at every milestone.

### Unresolved product decisions

| # | Decision | Options | Recommendation |
|---|---|---|---|
| D1 | Request-ID placement (the F1 conflict) | A: keep route-level on `Router.Use`, chain Tracing slot hosts OTel only; B: accept the 404/rejection header delta, rewrite 9 gate tests | **A** — all four reviews converge; zero behavior change; preserves the adversarial-review-hardened oracle |
| D2 | SDK break approval: remove `sso.AuthMiddleware`/`sso.CORS` in the current release cadence | Approve; defer to next release (delays M3) | Approve — zero in-tree consumers; compile-time break is low-risk; note external-consumer count is Unknown |
| D3 | `Idempotency` commit-position change (handler-shape migration) | Accept documented semantics change; or keep `Idempotency` as `core.MiddlewareFunc` and exclude from the signature grep | Accept with the before/after contract table (F3); zero production call sites |
| D4 | Test-(d) negative-control mechanism | Inline handler-shaped auth stub; `FromCore`-adapted stub | Inline stub (S1) — the design's reference to `middleware.Auth` is deleted by the same change |
| D5 | Canonical doc location | `docs/auto/` vs `docs/architect-analysis/auto/` (currently identical copies with stale cross-references) | Pick one (suggest `docs/architect-analysis/auto/`, where the spec lives) and fix citations |
| D6 | Spec §2 amendment: the single-signature grep acceptance conflicts with D1=A (route-level Tracing stays `core.MiddlewareFunc` by router design) | Amend the grep to exempt route-level Tracing; or re-scope to "chain slots accept only `middleware.Middleware`" | Amend — `shared/core/router.go` is out of scope by the spec's own §0 |
| D7 | `FromCore` propagation semantics (F2) | Specify `next.ServeHTTP(ctx.ResponseWriter(), ctx.Request())`; leave unspecified | Specify (M3) — the current text silently breaks writer-swapping middleware |

### Bottom line

The design is exceptionally well-evidenced — every budget, signature, and
ordering claim verifies against the tree, and four independent reviews
converge on the same single material flaw: the Tracing-slot relocation breaks
a deliberate, security-motivated byte-identity invariant with 7 committed
regression tests. Resolve D1 as Option A (the smallest viable change that
preserves every security and observability invariant), correct the test-churn
inventory and `FromCore` propagation in M3, and the plan is a
zero-observable-behavior refactor that converts the product's security
boundary from prose into structure.
