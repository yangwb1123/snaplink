# Requirements Specification: interfaces/middleware — Typed named-slot middleware pipeline

Source: expansion direction 1 of `docs/auto/interfaces-middleware-analysis.md`
("将中间件链形式化为带命名槽位的类型化管道（构建期强制排序不变量）").
Scope is the `interfaces/middleware` module and its chain consumers
(`interfaces/sso`). Exactly three evidence-backed improvements; each carries
name, problem, evidence, proposed behavior, acceptance check.

## 0. Scope and hard constraints

- Canonical chain order today (outermost → innermost, reconstructed from
  `interfaces/sso/server_routes.go:360-470`, `sso_wiring.go:389-421`,
  `server_health.go:347-351`): **probe mux → Recover → Tracing → Metrics →
  TrustedProxies → RateLimit → Degradation → AcceptVersion → BodyLimit →
  Compression → CORS → SecurityHeaders → RequestLog → Router**. This order is
  the contract this spec formalizes; it is not being changed.
- Budgets that bind the design: `interfaces/middleware` holds exactly 10
  non-test Go files (`directory_fanout_test.go:34` `maxGoFilesPerDir = 10`)
  — no new root file is allowed; chain code extends `middleware.go` (166 →
  ~420 lines, under the 500-line file budget), or splits into a new
  `interfaces/middleware/chain` subpackage (subdir budget 15, per-dir file
  budget 10) if it crosses 450 lines. `interfaces/sso` is at its 60-file
  ceiling (`directory_fanout_test.go:59`) — the wiring collapse must be edits
  to existing files only; consolidation actually relieves the `server_routes.go`
  line-budget pressure that forced `wrapAPIVersioning` to be relocated
  (`server_routes.go:461-462`).
- Non-goals (out of scope for this direction): the request-state registry and
  capture-stack unification (direction 2), observability unification
  (direction 3), and any change to the `idempotency_capture_missing` canary.
- No imports change direction: `interfaces/middleware` gains no import above
  the `interfaces` layer; `Chain` accepts already-constructed middlewares, so
  it needs only `net/http` and `shared/core`.

## 1. Named-slot typed pipeline: `middleware.Chain`

### Name
Formalize the middleware chain as a typed pipeline with fixed named slots —
`middleware.Chain` in `interfaces/middleware` — so slot order is enforced by
construction, not by prose.

### Problem
The chain is the security boundary of the product, but every ordering
invariant is a comment contract hand-assembled across three files in
`interfaces/sso` plus a separate probe mux. A future middleware (conditional
access, geo, tenant) placed in the wrong slot silently breaks Oracle safety or
opens a rate-limit escape, and is caught only in code review. The composition
logic itself is duplicated prose: ordering rationale is restated at every
`wrap*` call site instead of living in one place.

### Evidence
- `interfaces/sso/server_routes.go:360-399` `buildMiddlewareChain` — the
  invariant "trustedProxies MUST wrap before rate limiting so the limiter keys
  on the validated real client IP" is a comment (`:364`); the DR-gate position
  ("just inside rate limiting … just outside body-limit") is a comment
  (`:368-372`).
- `interfaces/sso/server_routes.go:432-470` `wrapInnerMiddlewares` — the
  innermost cluster order (RequestLog → SecurityHeaders → CORS → Compression →
  BodyLimit → AcceptVersion) exists only as a doc comment; the function body
  is a sequence of conditional wraps whose order a reader must diff by eye.
- `interfaces/sso/sso_wiring.go:389-421` `wrapPanicRecovery`,
  `wrapCompression`, `wrapAPIVersioning` — chain assembly spread over a second
  file "beside the fields they read", explicitly because `server_routes.go` is
  at its line budget (`:419-421`).
- `interfaces/sso/server_health.go:347-351` `degradationGate` — wired from
  exactly one call site in `buildMiddlewareChain`; nothing structural ties it
  to its required slot.
- `interfaces/sso/server_routes.go:475-485` `buildProbeMux` — the invariant
  "probes bypass the middleware stack and rate limiting" (AGENTS.md §2) is a
  separate hand-written mux whose position relative to the chain is not
  represented in any type.

### Proposed behavior
Add to `interfaces/middleware` (extending `middleware.go`, or the
`interfaces/middleware/chain` subpackage if the file crosses 450 lines):

- `type Middleware func(http.Handler) http.Handler` — the single chain
  signature (see §2).
- `type Chain struct{ … }` with one unexported slot field per canonical
  position and one builder method per slot (`WithRecover`,
  `WithTracing`, `WithMetrics`, `WithTrustedProxies`, `WithRateLimit`,
  `WithDegradationGate`, `WithAcceptVersion`, `WithBodyLimit`,
  `WithCompression`, `WithCORS`, `WithSecurityHeaders`, `WithRequestLog`).
  Slots are fields and `Wrap` applies them in a fixed sequence — a wrong
  order is unrepresentable at compile time; there is no slice to shuffle.
- `WithProbes(map[string]http.Handler)` — probe endpoints (`/livez`,
  `/readyz`, `/metrics`) are a structural pre-chain slot: `Wrap` routes them
  outside every other slot, making "probes outside rate limiting" a property
  of the type, not of a separately maintained mux.
- `Wrap(router http.Handler) http.Handler` — applies slots outermost →
  innermost in the canonical order and returns the finished handler.
- `SlotOrder() []SlotName` — returns the canonical slot list for tests
  (see §3).

Replace the hand-assembled assembly in `interfaces/sso` (edits to existing
files only): `buildMiddlewareChain` + `wrapInnerMiddlewares` +
`wrapPanicRecovery` + `wrapCompression` + `wrapAPIVersioning` +
`degradationGate` + `buildProbeMux` collapse into one `Chain` construction in
`server_routes.go`; the server keeps injecting its stateful middlewares
(`ratelimit.DynamicMiddleware`, `s.metrics`, `trustedProxies.Middleware`,
`handler.SecurityHeaders`, `cors.Middleware`) into the corresponding slots.
`cmd/sso-server` and `cmd/sso-minimal` keep composing through `sso.Server`; no
SDK-facing option changes.

### Acceptance check
- New committed test `TestChain_CanonicalSlotOrder` in
  `interfaces/middleware`: `Chain{}.SlotOrder()` equals exactly
  `Recover → Tracing → Metrics → TrustedProxies → RateLimit → Degradation →
  AcceptVersion → BodyLimit → Compression → CORS → SecurityHeaders →
  RequestLog → Router` with probes outside the chain.
- `grep -n "wrapPanicRecovery\|wrapCompression\|wrapAPIVersioning\|degradationGate\|buildProbeMux" interfaces/sso` returns only the chain construction site (or the deleted symbols' absence) — no hand-written adapter remains.
- Probe behavior byte-identical: existing probe tests pass unchanged; `/livez`,
  `/readyz`, `/metrics` are not rate-limited and carry no chain middleware
  side effects.
- `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` pass; no
  `interfaces/sso` file added; `interfaces/middleware` non-test file count
  stays ≤ 10.

## 2. Single-signature pipeline with one boundary adapter

### Name
Standardize the chain on `middleware.Middleware = func(http.Handler) http.Handler`;
eliminate the `core.MiddlewareFunc`/`http.Handler` dual-signature adapter tax
and the legacy surfaces that exist only because of it.

### Problem
The package mixes two middleware signatures, and every composition site pays
a hand-written bridging tax. Worse, the `core.MiddlewareFunc`-shaped members
are the ones the server does not use: `Auth` is dead outside aliases and
tests, and `CORS` was superseded by `interfaces/cors` — yet both remain,
offering a competing composition model and forcing readers to learn which
signature belongs where.

### Evidence
- `interfaces/middleware/middleware.go` — `Recover` is
  `func(http.Handler) http.Handler` (`:27`) while `Auth` (`:52`), `CORS`
  (`:71`), `Logger` (`:95`), `Tracing` (`:119`), `RequestID` (`:160`) are
  `core.MiddlewareFunc`: two signatures in one file.
- The handler shape is already the chain-native one for the rest of the
  module: `RequestLogger` (`request_log.go:45`) and `TrustedProxies.Middleware`
  (`trusted_proxy.go`) use it; the sso server can only compose them by
  hand-written wraps (`sso_wiring.go:389-421`).
- `interfaces/sso/aliases.go:43-44` — `AuthMiddleware = middleware.Auth` and
  `CORS = middleware.CORS` are back-compat re-exports; `middleware.Auth` has
  zero non-test server consumers (verified by grep across `cmd/`,
  `interfaces/sso`).
- `interfaces/cors/cors.go:5` — "The legacy `sso.CORS` … can't be wrapped
  around the entire handler tree": the chain direction structurally requires
  handler-shaped middleware, which the legacy `MiddlewareFunc` cannot provide.

### Proposed behavior
- `Chain` slots accept only `middleware.Middleware` (§1).
- Migrate `Logger`, `Tracing`, and `Idempotency` (the `core.MiddlewareFunc`
  middlewares the server actually uses) to `middleware.Middleware`. Their
  behavior is unchanged; call sites move from `Router.Use`/group wiring to
  the corresponding chain slots. `RequestID` remains a back-compat alias of
  `Tracing`.
- Exactly one boundary adapter lives in `interfaces/middleware`:
  `func FromCore(fn core.MiddlewareFunc) Middleware`, for the residual
  route-level composition that still targets `Router.Use`/`Group`. `core`
  itself is untouched — `MiddlewareFunc` stays for route-level use; this
  change is about the chain, not the router API.
- Remove the legacy `Auth` and `CORS` middlewares and their
  `sso.AuthMiddleware`/`sso.CORS` aliases (breaking-change note in the
  feature matrix / release notes); update `test/middleware_test.go` consumers.
  `interfaces/cors` remains the CORS path.

### Acceptance check
- `grep -rn "core.MiddlewareFunc" interfaces/middleware` returns hits only
  for the `FromCore` adapter signature; every chain slot is typed
  `middleware.Middleware`.
- `go build ./...` passes for `cmd/sso-server`, `cmd/sso-minimal`, and all
  SDK consumers; `test/` suite passes with updated middleware tests.
- No `wrap*` bridging function remains in `interfaces/sso` (grep check from
  §1 also covers this).
- `middleware.Auth`/`middleware.CORS` and `sso.AuthMiddleware`/`sso.CORS` are
  gone; `interfaces/cors` tests unchanged and green.

## 3. Ordering invariants as executable test assets

### Name
Bind every security-critical ordering invariant to the chain as a committed
test, so a future mis-slotting fails CI instead of code review.

### Problem
Even with a typed chain, the *rationale* per slot pair stays prose, and one
invariant (idempotency after auth) lives at the route level where the chain
cannot see it. Today the only defense is review of comments; there is no test
that a wrong order — or a new middleware dropped into the wrong slot — fails.

### Evidence
- `interfaces/sso/server_routes.go:364` — "trustedProxies MUST wrap before
  rate limiting so the limiter keys on the validated real client IP" is
  comment-only; `interfaces/ratelimit/middleware.go:50-116`
  (`KeyByClientIDOrIP` doc) explains the flip side: rate limiting runs
  pre-auth and an unvalidated IP (or attacker-chosen username) is an escape.
- `interfaces/sso/server_routes.go:368-372` — DR gate position ("just inside
  rate limiting … just outside body-limit") is comment-only.
- `interfaces/middleware/idempotency.go:142-153` — "ORACLE-SAFE POSITION
  INVARIANT: a middleware-level replay is only sound when this middleware
  runs AT OR AFTER client authentication" is comment-only, and it binds a
  composition site (`interfaces/sso`'s route wiring) the chain cannot see.
- `interfaces/sso/server_routes.go:475-485` `buildProbeMux` + AGENTS.md §2 —
  "Probes remain outside rate limiting" is enforced by a hand-written mux,
  not by a test.

### Proposed behavior
Commit four tests that exercise the invariants end-to-end through the `Chain`
(and the route-level composition site), each constructed so a slot swap makes
it fail:

- (a) **Forged-XFF/rate-limit test** (`interfaces/middleware`): with
  `WithTrustedProxies` filled before `WithRateLimit`, a request carrying a
  forged `X-Forwarded-For` is bucketed under the validated real client IP
  (the value `peertrust` resolved), not the header value. Swapping the slots
  in the test's chain construction must change the bucket key — proving the
  invariant is test-enforced.
- (b) **Degradation-position test**: when the degradation gate sheds (503),
  the request still passes through rate limiting (flood protection applies to
  a shedding replica) and metrics counts the 503; a large-body request to a
  shedding gate is refused before the body limit reads the body
  (short-circuit outside body-limit).
- (c) **Probe-bypass test**: `/livez`, `/readyz`, `/metrics` responses are
  byte-identical with and without a fully populated chain (no rate-limit
  bucket consumed, no trusted-proxy dependency), including under a shedding
  degradation gate and over the rate limit.
- (d) **Idempotency-position test** (at the `interfaces/sso` composition
  site): an unauthenticated request carrying an `Idempotency-Key` never
  receives a replayed cached success — the post-auth replay contract of
  `idempotency.go:142-153` becomes a regression test. No new audit event:
  the `idempotency_capture_missing` canary is untouched (direction 2's
  concern).

The §1 `TestChain_CanonicalSlotOrder` complements these: adding or removing a
slot is an explicit, reviewed change to the canonical list rather than a
silent edit.

### Acceptance check
- All four tests committed and green:
  `go test ./interfaces/middleware/... ./interfaces/sso/... -run 'Chain|Idempotency|Probe|RateLimit|Degradation'`.
- Negative control verified during implementation: each test fails when its
  slot order is deliberately swapped (documented in the test comment), then
  passes with the canonical order.
- `make ci` green (full gate, including nested modules and examples).
- No new `Err*`, endpoint, or config surface is introduced by this expansion;
  no `docs/error-codes.md` / `docs/openapi.yaml` / `docs/config-reference.md`
  changes required beyond the removal note for `sso.CORS`/
  `sso.AuthMiddleware` (§2).

## Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./interfaces/middleware/... ./interfaces/sso/... -race
make ci
```

Files touched (implementation): `interfaces/middleware/middleware.go`
(`Chain`, `Middleware`, `FromCore`, migrated `Logger`/`Tracing`/`Idempotency`;
or new `interfaces/middleware/chain/` subpackage if the file crosses 450
lines), `interfaces/middleware/*_test.go` (§1/§3 tests),
`interfaces/sso/server_routes.go`, `interfaces/sso/sso_wiring.go`,
`interfaces/sso/server_health.go` (collapse to one chain construction; edits
only — 60-file ceiling), `interfaces/sso/aliases.go` (remove
`AuthMiddleware`/`CORS`), `test/middleware_test.go` (consumers of removed
surfaces). Do not modify: `shared/core/router.go` (route-level
`MiddlewareFunc` API stays), `interfaces/ratelimit`, `platform/tracing`,
`platform/audit` (direction-3 scope), the `idempotency_capture_missing`
canary (direction-2 scope).
