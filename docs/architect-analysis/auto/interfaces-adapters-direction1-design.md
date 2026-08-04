# Design: interfaces/adapters — Direction 1 (short-circuit + response capture)

Design for `docs/auto/interfaces-adapters-direction1-spec.md`. Implements the
three evidence-backed improvements in order 1 → 2 → 3, each independently
shippable under the mandatory gates. This document decides the API surface,
the storage model, the failure modes, and the things that could break the
design.

## Ground truth verified beyond the spec

The spec's evidence was re-verified against current code. Three additional
facts materially constrain the design and are treated as binding:

- **gin's `Context.Writer` is `gin.ResponseWriter`, not `http.ResponseWriter`.**
  `go doc github.com/gin-gonic/gin.ResponseWriter` shows an interface
  requiring `http.ResponseWriter`, `http.Hijacker`, `http.Flusher`,
  `http.CloseNotifier`, plus `Status()`, `Size()`, `WriteString()`,
  `Written()`, `WriteHeaderNow()`, and `Pusher()`. The spec's proposed
  `ginContext.SetResponseWriter: c.Writer = w` does **not compile** for a
  bare capture wrapper. Decision 4 introduces a facade.
- **`interfaces/sso/server_token.go` is exactly 500 lines** — at the Go file
  budget ceiling. Improvements 2 and 3 must be net-negative or flat in that
  file (they are: the assertion replacement removes 2 lines; the inline
  capture removal removes ~40). No design may add a line to it.
- **The commit path's type assertion breaks under adapters even after
  improvement 2.** `CommitIdempotentResponse` locates the capture via
  `ctx.ResponseWriter().(*idempotentResponseWriter)`. Under gin/echo the
  swapped writer sits behind an adapter facade (Decision 4), so the assertion
  still fails. Capture retrieval must move to the request context (Decision 5).
- `middleware.Idempotency`, `HandleIdempotentRequest`, and
  `CommitIdempotentResponse` have **zero production callers** (grep: only the
  middleware package itself and tests). Retiring the handler-cooperation
  convention is therefore free of production fallout; `sso.AuthMiddleware`
  and `sso.CORS` are the only aliased consumers of the terminal-writing
  middlewares, and no production route uses `Auth` today except through the
  alias (blast radius: alias + tests).
- Production `HandlerContext` implementors are exactly four: `*core.Context`,
  `ginContext`, `echoContext`, and `backgroundHandlerContext` in
  `interfaces/sso/sso_wiring.go` (the last needs no-op implementations). Two
  test fakes (`test/middleware_test.go:fakeContext`,
  `protocols/caep/stream_handler_test.go:testHandlerContext`) also
  implement it standalone; all other test contexts embed `*core.Context` and
  inherit the new methods for free. Interface growth is a compile-time
  forcing function: the compiler enumerates every missed implementor.

## Decision 1 — API surface: four new methods on `HandlerContext`

`HandlerContext` grows from 11 to 15 methods in `shared/core/router.go`:

```go
Abort()              // mark the chain stopped; terminal response already written
Aborted() bool       // chain was stopped by a middleware
Written() bool       // response committed at least once
SetResponseWriter(w http.ResponseWriter)  // replace the writer underlying ctx.JSON/raw writes
```

Semantics (documented on the interface, not just in implementations):

- `Abort` is **opt-in and sticky**: no middleware calls it unless it has
  written (or decided) a terminal response. Existing middleware that never
  calls it changes nothing — this is what keeps `TestGatedRouter_*` and all
  adapter tests byte-identical.
- `Written()` is "committed at least once", not "finished": a 401 written by
  `Auth` followed by an aborted chain reports `Written() == true`.
- `SetResponseWriter` replaces the writer that `JSON`/`Redirect` and
  `ResponseWriter()` expose; the previous writer (or a wrapper of it) is
  retained by the caller. Request-scoped; never shared across requests.
- `sso.HandlerFunc`/`sso.MiddlewareFunc` are type aliases of the core types
  (`aliases.go:111,114`), so the SDK surface grows without new symbols and
  without touching the `interfaces/sso` file ceiling (no new files there).

Migration surface is fixed and compiler-enforced: `*core.Context`,
`ginContext`, `echoContext`, `backgroundHandlerContext` (no-op
`Abort`/`Aborted`/`Written`/`SetResponseWriter` — background work has no
response), plus the two test fakes. `test/middleware_test.go`'s `fakeContext`
gets `Aborted() bool` returning true after a `JSON` write, matching the new
`Auth`/`CORS` behavior assertions.

## Decision 2 — Chain-stop: where `Aborted` lives and the loop change

The abort flag is **request-scoped state on the context struct**, not on the
framework:

- `*core.Context`: new `aborted bool` field; `Abort()` sets it.
- `ginContext`/`echoContext`: new `aborted bool` field on the adapter struct.
  The adapters allocate a fresh `ssoCtx` per request inside `wrapHandler`, so
  the flag is naturally request-scoped. gin's own `c.Abort()`/`IsAborted()`
  are deliberately **not** used: the adapter drives the chain itself and gin's
  index-based abort only matters to gin's own `Next()` machinery, which never
  runs here.

Chain loops, in all three backends:

```go
for _, mw := range route.middlewares {   // or g.middlewares / e.middlewares
    mw(ctx)
    if ctx.Aborted() {
        break
    }
}
if !ctx.Aborted() {
    handler(ctx)
}
```

This is the only behavioral change to `StdRouter.ServeHTTP` (one `if` per
middleware iteration, `break` before the handler) and to both `wrapHandler`
functions — no complexity-budget risk (each stays ≤ 3 `if` levels). `Auth`
and `CORS` gain `ctx.Abort()` after their terminal write; `Recover`,
`Logger`, `Tracing`, `RequestID`, `Compress`, `TokenNoStoreHeaders`,
`Degradation`, and the admin/tenant/geo middleware are untouched (none write
a terminal response today — verified by reading each).

`GatedRouter` is orthogonal: its route-level gate and handler-wrapping
fallback neither call nor consume abort. The abort break happens inside
`ServeHTTP`/`wrapHandler` regardless of gating.

## Decision 3 — Storage model for `Written()`: a permanent tracking wrapper in `core.Context`

A bare `written bool` flag on `*Context` is unsound because writes happen
through whatever writer is current (raw `ctx.ResponseWriter()` writes, swapped
capture writers) — `ctx.JSON` is not the only write path (CORS writes 204
directly). The decision:

- `NewContext` installs `c.w = &trackingResponseWriter{inner: w}` (a new
  small type in `shared/core/router.go`; ~25 lines). The tracking wrapper
  flips a `written` flag on its first `Write`/`WriteHeader` and delegates
  everything else. `ResponseWriter()` returns the tracking wrapper.
- `SetResponseWriter(w)` keeps **replacement semantics** (`c.w = w`) but
  re-wraps: `c.w = &trackingResponseWriter{inner: w}`. The chain after an
  idempotency swap is `tracking₂ → capture → tracking₁ → original`; every
  write path passes through the outermost tracking wrapper, so `Written()`
  (read as `c.w.(*trackingResponseWriter).written`) stays truthful across
  arbitrary swaps with no cycle and no assertion. The double wrapper is
  harmless: one interface call and one flag flip per write.
- `ginContext.Written()` → `c.Writer.Written()`. gin's writer records status
  on first `WriteHeader`; through the Decision-4 facade this reports the
  wire state, which is exactly "committed at least once".
- `echoContext.Written()` → `c.Response().Committed`. echo's `Response` sets
  `Committed` inside its own `Write`/`WriteHeader`, which forward to
  `Response.Writer` — so after a swap the flag still reflects writes through
  the capture.

Storage model summary (per-request, no shared state):

| State | Backend | Location |
|---|---|---|
| Aborted | core / gin / echo | struct field on the per-request context |
| Written | core | `trackingResponseWriter.written` (always outermost) |
| Written | gin | gin `ResponseWriter.status != 0` via facade |
| Written | echo | `Response.Committed` |
| Capture wrapper | any | request context value (Decision 5); /token keeps a local var |

## Decision 4 — `SetResponseWriter` on the interface; gin needs a `gin.ResponseWriter` facade

`SetResponseWriter(w http.ResponseWriter)` joins the interface. Backend
wiring:

- **core**: replacement semantics as in Decision 3 (re-wrap with tracking).
- **echo**: `c.Response().Writer = w` — the field is a plain
  `http.ResponseWriter` (verified: `go doc` shows `Writer http.ResponseWriter`
  as a public field), so assignment compiles directly. echo's `Response`
  methods keep setting `Committed`/`Status` because they are implemented on
  `Response` itself, not on `Writer`.
- **gin**: `c.Writer = w` does **not** compile for an arbitrary
  `http.ResponseWriter` (field type is `gin.ResponseWriter`). Decision:
  `ginContext.SetResponseWriter` wraps:

  ```go
  type ginCaptureWriter struct {
      gin.ResponseWriter            // embedded ORIGINAL writer: satisfies the interface, delegates
      capture http.ResponseWriter   // the swapped-in capture wrapper
  }
  func (w *ginCaptureWriter) Header() http.Header     { return w.capture.Header() }
  func (w *ginCaptureWriter) Write(b []byte) (int, error) { return w.capture.Write(b) }
  func (w *ginCaptureWriter) WriteHeader(code int)    { w.capture.WriteHeader(code) }
  // WriteHeaderNow, Status, Size, Written, WriteString, Pusher, Flush, Hijack,
  // CloseNotify: inherited from the embedded original gin writer.
  ```

  Routing `Header`/`Write`/`WriteHeader` through `capture` is what makes the
  capture see the body and status; the gin-only methods (including
  `Written()`) delegate to the original writer, whose own `wroteHeader` guard
  prevents double-write warnings when gin internally calls `WriteHeaderNow`
  after an explicit `WriteHeader`. The middleware package stays gin-free —
  the facade lives in `interfaces/adapters/gin`, preserving the import
  direction (`adapters → interfaces/sso → middleware → core`).

  One documented edge: `WriteHeaderNow`-only paths (no prior `WriteHeader`)
  record the status on the original writer, not in the capture. All Snaplink
  terminal responses go through `ctx.JSON`, which calls `WriteHeader` first,
  so the capture always sees a status; the acceptance tests pin this.

The ordering guarantee the spec requires (middleware swap visible to the
handler) holds in all three backends: the swap happens before the handler
runs, and every `ctx.JSON` writes through `c.w` / `c.Writer` /
`c.Response()`.

## Decision 5 — Capture retrieval via request context, not type assertion

Spec gap (see Ground truth): `CommitIdempotentResponse`'s
`ctx.ResponseWriter().(*idempotentResponseWriter)` assertion fails under
adapters because the facade (Decision 4) sits between the context and the
capture — and it is already silently wrong under the adapters today.
Decision:

- The `Idempotency` middleware stores the installed capture wrapper in the
  request context alongside key+cache (extend the existing
  `WithIdempotencyKey` value to carry `[3]any{key, cache, capture}`), using
  the existing `*r = *r.WithContext(...)` mutation pattern at
  `idempotency.go:72`.
- `CommitIdempotentResponse` retrieves the capture from the context. The
  `.(*idempotentResponseWriter)` assertion disappears entirely.
- The `/token` path (`beginTokenIdempotency`/`finishTokenIdempotency`) does
  not need this: it already threads `idemRW` as a local return value. Its
  only change from improvement 2 is `ctx.SetResponseWriter(idemRW)` replacing
  the `if c, ok := ctx.(*core.Context)` block (net −2 lines).
- After improvement 2, `grep -rn '\.(\*core\.Context)' interfaces/` returns
  zero — this is a gate assertion in the acceptance suite, not just a hope.

## Decision 6 — Idempotency hit path: middleware-level `Abort`, post-auth position, one implementation

- `middleware.Idempotency` gains the hit short-circuit: on cache hit it
  writes the cached body (`Content-Type` + 200) and calls `ctx.Abort()`; the
  chain stops on all three backends. The `HandleIdempotentRequest`-at-handler-
  entrance convention is **deleted** (zero callers), along with its
  self-documented limitation comment.
- **Oracle-safe ordering is a position invariant, not a code property**: a
  middleware-level hit replay is only sound when the middleware runs *after*
  client authentication. The generic `Idempotency` middleware documents this
  invariant on its doc comment ("install only at or after authentication").
  The `/token` hit check stays exactly where `beginTokenIdempotency` runs
  today — after `authenticateTokenClient`, residency gate, sender-constraint
  capture, FAPI rules, and `rejectDisallowedGrantType` (server_token.go:66-85)
  — so a wrong-secret replay can never receive a cached 200. The
  consolidation is limited to the capture/replay **helpers**:
  `beginTokenIdempotency`'s capture block becomes the shared helper, and
  `finishTokenIdempotency` becomes the shared commit — the /token fingerprint
  key (`tokenIdempotencyCacheKey`: clientID + request + DPoP JKT + mTLS X5T)
  and the `idempotentMu` single-flight are retained verbatim (they are the
  atomic-consume behavior AGENTS.md §3 requires).
- The generic middleware keeps its simpler raw-key semantics; it is the
  opt-in convenience path for non-token endpoints, while /token keeps the
  fingerprint-scoped store. Two key shapes, one capture mechanism.
- `commit` caches only 2xx and non-empty bodies (existing rules), so error
  responses are never replayed as successes.

## Decision 7 — Loud commit: audited capture loss

`CommitIdempotentResponse` currently returns nothing and silently no-ops when
a key is present but no capture is installed. Decision: fail open **with
audit** (per AGENTS.md "fail open with audit/logging" for non-decision
helpers):

- `Idempotency` accepts an optional audit recorder:
  `Idempotency(cache core.IdempotentCache, audit *audit.Recorder)` — nil
  keeps today's behavior (byte-identical for unwired builds; the middleware
  package already imports `platform/audit` for `Tracing`). A variadic
  parameter keeps the single existing caller (none in production) and the
  tests source-compatible.
- On commit-without-capture, emit one audit event per request that carried an
  `Idempotency-Key` and reached commit without a capture wrapper. The event
  carries a **fingerprint of the key** (sha-256 prefix), never the raw key —
  bounded cardinality and no secret material in audit, matching the audit
  event-cardinality rules. Event type is classified in `auditreport` in the
  same change (AGENTS.md: "New event types must be classified in
  `auditreport`").
- The /token commit path (`finishTokenIdempotency`) emits the same event from
  the sso layer, where the `WithAuditRecorder` recorder is already reachable
  (no recorder reachable from `middleware` for the sso path — the middleware
  only sees the cache).
- No decision changes: capture loss never fails the request, never changes
  the response. It only makes the degradation observable and testable.

## Decision 8 — Delivery order, budgets, and gate compliance

Order 1 → 2 → 3 (spec dependency), each landed with
`go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .`; each step leaves
the tree green:

- **Step 1**: interface + 5 implementors + 2 test fakes + chain-stop loops +
  `Auth`/`CORS` abort. No new files. `shared/core/router.go` grows
  ~70 lines (interface, tracking writer, Abort/Aborted/Written/SetResponseWriter
  impls) → ≈450, under the 500 budget.
- **Step 2**: `SetResponseWriter` on the interface (already present from step
  1 — step 2 is the wiring: gin facade, echo assignment, assertion removal in
  `idempotency.go:74` and `server_token.go:125`).
- **Step 3**: context-carried capture, hit short-circuit, convention removal,
  loud commit, `/token` consolidation. `server_token.go` is net-negative
  (stays ≤ 500). `interfaces/middleware/idempotency.go` grows ~50 lines
  (≈170, under 500). No new files in `interfaces/sso` (60-file ceiling
  untouched); no `layerExemptions`; no budget exemptions.

Full-suite handoff per change: `go test ./... -race`, `go test ./test/ -run
TestE2E -v`, `make ci`.

## Failure modes

| Failure | Behavior | Classification |
|---|---|---|
| Middleware aborts but a custom (non-StdRouter/gin/echo) `Router` ignores the flag | handler still runs → double write; the interface cannot force chain-stop on third-party routers | Fail closed by documentation: adapters + StdRouter are the supported embedding surface; acceptance tests cover exactly these three |
| `SetResponseWriter` swap fails to compile under gin (missing facade) | build error at the call site | Fail closed at compile time — this is the feature working as intended |
| Capture wrapper missing at commit (regression, future backend) | audited `idempotency_capture_missing` event; response unchanged; replay protection degrades observably | Fail open + audit (Decision 7) |
| Cache-hit replay for a request that would fail auth (middleware misordered) | cached 200 replayed — oracle violation | Fail closed by position invariant (Decision 6): /token check stays post-auth; generic middleware documents the invariant; oracle-safety regression test on all three backends |
| Concurrent retries | unchanged: `idempotentMu` single-flight + atomic consume; cache contract (`core.IdempotentCache`) untouched | Fail closed (existing, preserved) |
| Cache store outage | `cache.Get`/`Set` errors ignored as today (non-decision path); request proceeds | Fail open (existing, preserved) |
| gin `WriteHeaderNow` path bypasses capture status | status not recorded in capture for that path; all Snaplink terminal writes go through `WriteHeader` first | Acceptable, documented, pinned by acceptance tests |
| echo `Response.Committed` not set (writer swapped before any write, then raw `Writer.Write` used) | `Written()` false negative; no Snaplink path writes through `Response.Writer` directly | Acceptable; `ctx.JSON`/`ResponseWriter()` go through `Response` |
| `Written()` false negative after capture swap in core (replacement loses tracking) | impossible by construction: tracking wrapper is always re-installed outermost (Decision 3) | Fail closed by construction |
| Handler side effects after a 401 (today: handler runs after `Auth` writes 401) | handlers stop executing after rejection — audit events or counters inside such handlers stop firing | Deliberate behavior change; no production route depends on it (verified: `Auth` has no production route usage beyond the alias); covered by the byte-identical 401 acceptance test |

## What could break the design

1. **gin's `ResponseWriter` interface is the load-bearing risk.** The facade
   (Decision 4) must satisfy `http.Hijacker`, `http.Flusher`,
   `http.CloseNotifier`, `WriteString`, `Status`, `Size`, `Written`,
   `WriteHeaderNow`, `Pusher` — any gin upgrade that adds a method breaks
   compilation at the facade, which is the desired loud failure, but the
   embedded-original delegation must be reviewed at each gin bump
   (gin is pinned in go.mod; the pin is the mitigation).
2. **`server_token.go` is at exactly 500 lines.** Any reviewer-requested
   addition to that file during this work violates the budget. The design is
   net-negative there; if step 3's consolidation needs more room, the shared
   capture helper must move to `interfaces/middleware/idempotency.go` (the
   sso `idempotentResponseWriter` becomes the middleware one) rather than
   growing the file.
3. **Interface growth is a public-SDK break for external embedders.** Any
   downstream that implements `HandlerContext` standalone (the SDK contract)
   breaks at compile time. This is the compiler's forcing function, but it
   is a semver-visible change: the four methods must land in one release with
   a changelog note, and the doc comments must state the contract
   ("implementors must honor `Aborted()` in their chain loops").
4. **Behavioral drift in `Auth`/`CORS`.** Aborting changes observable
   behavior for any route that today tolerates the handler running after a
   401/204 (double writes are currently swallowed by net/http's
   superfluous-write guard on StdRouter; echo's second write errors). The
   byte-identical acceptance tests on three backends are the guard; the
   existing adapter tests (`TestGatedRouter_*`, in-package middleware tests)
   must pass unchanged, which the opt-in design guarantees only if no
   existing middleware other than `Auth`/`CORS` starts aborting.
5. **The `*r = *r.WithContext(...)` mutation pattern** (idempotency.go:72)
   is shared with the new capture-in-context storage. It is request-scoped
   and safe, but any future code holding the pre-mutation `*http.Request`
   would miss the capture. The acceptance tests (replayed byte-identical
   body, grant executed once) pin the mechanism end-to-end.
6. **Adapter middleware snapshot semantics**: `wrapHandler` closes over the
   `g.middlewares` slice of the router that registered the route. Abort
   behavior is unaffected (snapshotting predates this work), but new tests
   must register routes on the same router instance that carries the
   middleware, or the chain-stop test silently tests nothing.
7. **Audit cardinality**: the loud-commit event is per-key-present-request;
   an attacker hammering `Idempotency-Key` headers could inflate audit
   volume. The key fingerprint bounds the cardinality (no raw keys), but the
   event rate is unbounded by construction — acceptable for a misconfig-
   detection event, and the `auditreport` classification must mark it as such.
8. **Step 2 alone ships a half-feature**: capture works under adapters, but
   the commit assertion (Decision 5) still fails there until step 3 lands.
   Mitigation: steps 1–3 are reviewed and merged as one series; step 2's
   acceptance test (byte-identical replay through gin/echo) cannot pass
   until step 3's context-carried retrieval exists — the spec's step-2
   acceptance is therefore formally re-sequenced: step 2 proves wiring
   (no `.(*core.Context)` in `interfaces/`, capture installed), step 3 proves
   the end-to-end replay on all three backends.
9. **echo's `Committed` after swap**: echo's `Response.Write` sets
   `Committed` itself and forwards to `Writer`; the swap is transparent.
   But `Response.Hijack`/`Flush` forward to the *original* writer only if
   the swap is bypassed — the facade-free echo assignment means
   `Flush()`/`Hijack()` on `Response` still reach the original `Writer`
   field they were constructed with, not the capture. No Snaplink path
   flushes or hijacks the token response; documented, not mitigated.
10. **`Recover` is an `http.Handler` wrapper, not a `MiddlewareFunc`** — it
    sits outside the abort chain (it wraps the whole router). A panicking
    handler after an aborted chain is impossible (handler doesn't run), so
    no interaction; but a panic inside a *middleware after an abort* would
    still be caught by `Recover`'s outer wrapper. No change needed; noted
    so nobody "fixes" the layering.

## Acceptance mapping

| Spec acceptance | Where it is proven |
|---|---|
| Byte-identical 401 / 204, handler not executed, no superfluous writes (StdRouter/gin/echo) | New three-backend table test in `test/` (`package ssotest`), step 1 |
| `grep '\.(\*core\.Context)' interfaces/` → zero | Step 2 + 3; enforced as a shell check in the change, not just a manual grep |
| Byte-identical replayed `/token`, grant executed once, wrong-secret replay → 400 `invalid_client` | Three-backend token idempotency tests, step 3 (extending existing `TestToken*Idempotency*` and `TestRcov_TokenIdempotency*`) |
| Side-effect counter increments exactly once (generic middleware hit path) | Three-backend middleware test, step 3 |
| Audit event on capture loss | Unit test with a recorder + `auditreport` classification, step 3 |
| Existing adapter/gated/middleware tests unchanged | Step 1 gate run; abort is opt-in except `Auth`/`CORS` |
