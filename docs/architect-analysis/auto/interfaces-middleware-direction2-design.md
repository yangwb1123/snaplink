# Design: interfaces/middleware — Direction 2 (typed request-state registry + composable capture stack)

Design for `docs/auto/interfaces-middleware-direction2-spec.md`. Fixes the
three decisions down to API surface, storage model, failure modes, and the
failure modes of the design itself. Delivery order 1 → 3 → 2, each
independently shippable under the mandatory gates.

## Ground truth verified beyond the spec

Every evidence line in the spec was re-verified against the tree. Four
additional facts materially constrain the design and are treated as binding:

- **The spec's literal API is illegal Go — generic interface methods do not
  exist.** `HandlerContext.Get[T any](RequestKey[T]) (T, bool)` as an
  interface method fails to compile: `interface method must have no type
  parameters` (verified against `go 1.26.1`). Concrete methods are equally
  banned (`method must have no type parameters`). The typed surface must be
  expressed with generic *free functions* plus one non-generic interface
  accessor (Decision 1). This is a spec correction, not a scope reduction:
  the compile-time cross-type guarantee the spec demands is preserved —
  `Get[T]` infers `T` from the `RequestKey[T]` argument, so a key of type
  `RequestKey[*tenant.Resolved]` cannot be passed to `Get[oauth.Client]`.
- **The four "production string keys" are actually seven string-bag keys.**
  The spec's acceptance grep (`ctx.Set("` / `ctx.Get("`) misses const-keyed
  bags: `platform/geo/middleware.go:18` (`HandlerContextKey = "geo:info"`)
  and `domains/region/middleware.go` (its own `HandlerContextKey`) are the
  same collision class with the same runtime type-assertion risk. The design
  migrates all seven bag keys, not just the four literals.
- **`CommitIdempotentResponse` and `IdempotencyKeyFromContext` have zero
  production callers.** The generic `middleware.Idempotency` is embedder
  surface; the in-repo /token path commits via `CommitCapturedBody` directly
  (`server_token.go:58-64,99-105`). The commit shape is preserved for SDK
  compat, but the in-repo risk surface for "capture missing" is exactly two
  call sites, both rewritten in one change.
- **Capture position decides replay byte semantics.** `wrapInnerMiddlewares`
  (`server_routes.go:431-455`) places RequestLogger *outside* compression and
  body-limit, which are themselves outside the router. Today the idempotency
  `CaptureWriter` (inside the router, via `SetResponseWriter`) captures
  **uncompressed** bytes, while `requestLogResponseWriter` (outside
  compression) captures **compressed** bytes. A single shared stack must sit
  at the router boundary — exactly where today's `CaptureWriter` sits — or
  the idempotency cache would store compressed bytes and replay them verbatim
  as `application/json` (a wire-visible break). This forces one documented
  behavior delta: debug request-log bodies become uncompressed (Decision 2).

All budget claims were re-verified: `shared/core` has exactly 23 non-test
files (request_state.go must be carved from `router.go`); `interfaces/sso`
has exactly 60 (all SSO-side edits are modifications of existing files);
`interfaces/sso/aliases.go:110` aliases `sso.HandlerContext = core.HandlerContext`,
so the interface change propagates without touching `interfaces/sso` types.

---

## Decision 1: Typed request-state registry (`RequestKey[T]` + `RequestState`)

### API surface

All in `shared/core/request_state.go` (the new file carved from `router.go`,
§Storage model). Core imports no Snaplink package; keys are *handles
instantiated by owning packages*.

```go
// RequestKey is a typed slot handle. The type parameter is the compile-time
// guard: Get/Set[T] only accept RequestKey[T], so a key declared for
// *tenant.Resolved cannot be read as oauth.Client — that fails to compile.
// The name string is the runtime slot identity (see storage model).
type RequestKey[T any] struct{ name string }

func NewRequestKey[T any](name string) RequestKey[T]
func (k RequestKey[T]) String() string // diagnostics / collision panic text

// RequestState is the per-request (per-invocation) state object.
type RequestState struct{ /* unexported */ }

// RequestStateOf returns the request's state, lazily creating and attaching
// it to ctx on first call. The second return is ctx-with-state-attached:
// callers that derive contexts (WithValue/WithCancel) MUST pass it down so
// later RequestStateOf calls on the derived chain find the same state.
func RequestStateOf(ctx context.Context) (*RequestState, context.Context)

// Typed access. T is inferred from the key; cross-type use fails to compile.
func Get[T any](s *RequestState, key RequestKey[T]) (T, bool)
func Set[T any](s *RequestState, key RequestKey[T], value T)

// HandlerContext gains exactly one non-generic accessor:
State() *RequestState
// (string Get/Set are removed in this same change; SetResponseWriter is
// removed in Decision 2. All four implementations — core.Context, ginContext,
// echoContext, backgroundHandlerContext — implement State() identically:
// RequestStateOf(c.Request().Context()).)
```

Why not keep the spec's `Get[T]/Set[T]` on the interface: illegal Go
(verified). Why not a generic interface instead: an interface can only embed
*instantiated* generic interfaces, pinning one `T` — useless for a registry
with heterogeneous slots. Free functions preserve every property the spec
asks for: compile-time cross-type rejection, one shared implementation, and
zero per-package context-key boilerplate.

Owning packages keep their *existing exported helper signatures* — they
become one-line registry reads/writes, so callers never change:

| Package | New key (exported var) | Helper(s) kept, reimplemented |
|---|---|---|
| `interfaces/middleware` | `SubjectKey RequestKey[string]` | `WithSubject`, `SubjectFromContext` |
| `interfaces/middleware` | `IdempotencyStateKey RequestKey[idempotencyState]` (unexported type) | `WithIdempotencyKey`, `IdempotencyKeyFromContext`, `CommitIdempotentResponse` |
| `shared/security/peertrust` | `RequestInfoKey RequestKey[RequestInfo]` | `WithRequestInfo`, `RequestInfoFrom`, `ForwardedHeadersTrusted` |
| `shared/core` | `TraceIDKey`, `CSPNonceKey RequestKey[string]` | `WithTraceID`, `TraceIDFromContext`, `WithCSPNonce`, `CSPNonceFromContext` |
| `shared/core` | `BreakGlassActorKey RequestKey[BreakGlassActor]` | `ContextWithBreakGlassActor`, `BreakGlassActorFromContext` |
| `platform/geo` | `GeoInfoKey RequestKey[*GeoInfo]` | `WithContext`, `FromContext`, `FromHandlerContext` |
| `domains/tenant` | `ResolvedKey RequestKey[*Resolved]` | `FromHandlerContext` |
| `domains/region` | `RegionKey RequestKey[region.ID]` | `FromHandlerContext` |
| `interfaces/ssoclient/rs` | `ClaimsKey RequestKey[*Claims]` | `NewContext`, `ClaimsFromContext` |
| `interfaces/sso` | `DeviceCtxKey`, `AuthHookSkipMFAKey` (in an existing file, e.g. `aliases.go`) | — (call sites rewritten) |
| `protocols/selfservice` | `ExtensionsKey RequestKey[any]` | — (read site rewritten) |

The spec's acceptance `rg 'type \w+Key struct{}'` stays literally true: the
migrated keys are deleted (`subjectKey`, `idempotencyKey`, `requestInfoKey`,
`traceIDContextKey`, `cspNonceContextKey`, geo `ctxKey`,
`breakGlassActorKey`, `claimsCtxKey` — 8 of the 11), the registry's own
context anchor introduces **no** new `struct{}` type (see storage model), and
the three remaining private keys are explicitly out of scope:
`interfaces/admin/middleware.go:477` `actorContextKey` (single-package,
allowed to stay by the spec's own carve-out) and the two exported
`shared/spi` keys (`CaptchaTokenContextKey`, `codeSendTenantContextKey` —
exported typed keys, not private `struct{}` keys, not string keys).

### Storage model

```go
type RequestState struct {
    mu    sync.RWMutex
    slots map[string]typedSlot // keyed by RequestKey.name
    stack *CaptureStack        // Decision 2; created lazily
}
type typedSlot struct {
    typ reflect.Type
    val any
}
```

- **Slot identity is the key name; type safety is the type parameter plus a
  Set-time guard.** `Set[T]` records `reflect.TypeOf(value)`; a Set that
  finds an existing slot under the same name with a *different* type panics
  with both types and the name in the message. Rationale: a name collision
  between two typed keys is a programmer error (key names are package-prefixed
  by convention: `"tenant.resolved"`, `"peertrust.request_info"`,
  `"sso.device_ctx"`), and the alternative failure modes are worse — silent
  overwrite (one middleware's data vanishes, consumers fall through to
  "absent" paths) or silent divergence (two slots, behavior depends on
  registration order). Fail-fast panic is the AGENTS.md-consistent choice
  (fail closed on ambiguity), it is caught by the conformance suite in CI,
  and the panic message names the exact key.
- **Context anchor without a new `struct{}` type:** `var requestStateAnchor
  = new(int)` is used as the `context.WithValue` key. Pointer identity is
  unique per binary, it is comparable, and it keeps the spec's
  `rg 'type \w+Key struct{}'` freeze literally true (no new key type, ever).
- **Attachment is one-way and lazy.** `RequestStateOf` attaches on first
  call via `context.WithValue(ctx, requestStateAnchor, st)` and returns the
  derived context. The state is a *mutable object reached through any
  descendant context* — `ctx.Value` walks the chain, so
  `TrustedProxies`'s `r.WithContext(...)`, the idempotency state, and the
  router's `NewContext` all observe one state per request. The single
  invariant: **every context derived from the request context shares the
  state; a middleware that rebases the context onto a fresh root (not
  derived from `r.Context()`) gets a second, divergent state** — the same
  hazard class `WithValue` keys have today, now pinned by a test
  (Decision 3 acceptance).
- **The per-adapter value bags die.** `Context.values sync.Map`
  (`router.go:99`), `ginContext.values` (`adapter.go:211`), `echoContext.values`
  (`adapter.go:241`), and `backgroundHandlerContext.kv map[string]any`
  (`sso_wiring.go:291`) are all deleted; every implementation routes through
  the registry. Four copies of the same mechanism become zero.
- **The `*r = *r.WithContext(...)` mutation dies.** The idempotency
  middleware currently mutates the request in place to make state visible to
  downstream readers (`idempotency.go:105-106`). The registry is reached by
  pointer through the (unchanged) request context, so the mutation is
  deleted; `ctx.Request()` identity is stable for the whole chain.
- **File budget:** `request_state.go` receives the carve-out
  (`Context`, `NewContext`, `trackingResponseWriter`, `Written`,
  `SetResponseWriter` until Decision 2, `Set/Get` until this change's final
  commit) plus the new registry/stack code — ~350 lines, under 500.
  `router.go` shrinks from 456 to ~330. Non-test file count stays 23.
  `trace_context.go` stays (helpers shrink to registry one-liners).

### Migration and deletion plan (one change, no shim period)

The string shims are *not* shipped as a permanent compatibility layer: the
spec mandates deleting them once production hits reach zero, and a dead
shim is exactly the "deferred-refactor" artifact AGENTS.md forbids. So this
change: (1) adds `RequestKey`/`RequestState`/`Get`/`Set`/`State()`; (2)
migrates all seven bag keys and the eight cross-package struct keys in the
same commit (helper signatures preserved, so each migration is a
mechanical reimplementation); (3) removes `Set(string, any)` /
`Get(string) any` from `HandlerContext` and all implementations; (4) updates
the conformance suite's string-bag usage to a suite-local typed key
(`routertest` already imports `core`, so a `routertest.ValueKey
= core.NewRequestKey[string]("routertest.value")` slot works). During the
single transitional commit, the shim and typed keys share the name
namespace by construction (same `slots` map), so mixed reads/writes cannot
split a slot.

### Failure modes

| Failure | Behavior | Why acceptable |
|---|---|---|
| Cross-type name collision | `Set` panics (loud, named) | Programmer error; caught in CI; panic-recovery wrapper turns it into a 500 — no oracle leak (attacker cannot trigger it) |
| Wrong-type read (defense in depth) | `Get` returns `ok=false` | Callers already treat absent as "no data" (documented per key) |
| Context rebased onto a fresh root | Second, divergent `RequestState` | Pre-existing hazard class; pinned by a `-race` test; document: derive from `r.Context()` |
| `RequestStateOf` on a hot path with no state | One tiny alloc on first call, `Value` walk after | Reject path and probes only; bounded |
| Migrated helper called with a nil ctx / nil state | `Get` on nil state → panic? | Guard: `RequestStateOf(nil)` — do not call; helpers keep their existing nil-tolerance contracts (`FromHandlerContext(nil)` → `(nil,false)`) — reimplemented to preserve it |

---

## Decision 2: Composable response-capture stack (`CaptureStack`)

### API surface

```go
// In shared/core/request_state.go. The stack is owned by core; layers are
// fed by the stack, so capture is structurally impossible to miss.

type CaptureStack struct{ /* unexported */ }

// Wrap installs the stack into the response write path. The FIRST caller's
// writer becomes the stack's inner writer and the stack itself is returned
// (subsequent calls are idempotent no-ops returning the stack). Only the
// router boundary calls Wrap (see write path).
func (s *CaptureStack) Wrap(w http.ResponseWriter) http.ResponseWriter

// Add registers a capture layer and returns its handle. Nil-safe: a stack
// never installed into a write path (backgroundHandlerContext) still
// returns a handle whose Status() is 0 and Body() is empty — commits
// naturally no-op (0 is not 2xx). unlock, when non-nil, is released by
// Unlock (the /token single-flight mutex).
func (s *CaptureStack) Add(unlock func()) *CaptureHandle

// CaptureHandle is the install-time layer handle. Commit paths read ONLY
// this handle — never a type assertion on ctx.ResponseWriter(), which is
// exactly what "silently broke capture under the adapters before".
type CaptureHandle struct{ /* unexported */ }

func (h *CaptureHandle) Status() int  // first WriteHeader; 200 if only Write ran
func (h *CaptureHandle) Body() []byte
func (h *CaptureHandle) Unlock()      // idempotent? NO — caller contract: exactly once

// HandlerContext gains:
Capture() *CaptureStack
```

Deletions, all in one commit (spec mandate, no intermediate state):
`HandlerContext.SetResponseWriter`, `core.Context.SetResponseWriter`,
`ginContext.SetResponseWriter` + `ginCaptureWriter` (whole facade),
`echoContext.SetResponseWriter`, `backgroundHandlerContext.SetResponseWriter`
(the silent no-op), `middleware.InstallCapture`, `middleware.CaptureWriter`,
`requestLogResponseWriter`, `recordCaptureMissing`, and the audit event
`EventIdempotencyCaptureMissing` (touches `auditspi/event_types_system.go:68`,
`event_types.go:318`, `platform/audit/aliases_spi.go:127`,
`auditreport/drift_test.go:59`, and `docs/observability.md` in the same
change — contract-drift rule).

### Storage model and write path

- **One stack per request, owned by `RequestState`** (`st.stack`, created
  lazily on first `Capture()` call).
- **Install position: the router boundary, and only there.** `NewContext`
  (std) and the adapters' `ServeHTTP` (gin/echo) call
  `state.CaptureStack().Wrap(w)` before any handler runs. This is exactly
  where today's `CaptureWriter` sits (inside the router, below
  body-limit/compression), so the idempotency layer sees **uncompressed**
  bytes and the replay cache stays byte-compatible with today's cached
  responses. Chain after install:
  - std: `trackingResponseWriter` → `CaptureStack` → body-limit → compression → … → wire
  - gin: gin's own writer → `CaptureStack` → wire (stack is under the engine, so the `WriteHeaderNow`-only edge the old facade documented *disappears by construction* — the stack sees every status write gin emits)
  - echo: `echo.Response` → `Response.Writer` (the stack) → wire
- **`http.Handler`-level capture consumers Add layers only, never install.**
  `RequestLogger` becomes: `st, nctx := core.RequestStateOf(r.Context());
  handle := st.Capture().Add(nil); r = r.WithContext(nctx);
  next.ServeHTTP(w, r); …log handle.Status()/Body()`. The stack is already
  in the path by then (the router installs it). Layers are positionless:
  every layer on one request sees the identical byte stream (the
  acceptance's "two captures see identical status+body" holds by
  construction on std, gin, and echo).
- **Layer visibility window is Add-time.** Writes before `Add` are not
  recorded (identical to today: a middleware that writes 401 + Aborts before
  the idempotency middleware runs is not captured). Writes after Add are
  recorded regardless of what else happens to the writer — no swap, no
  re-wrap, no facade.
- **`Written()` stays truthful.** std: `trackingResponseWriter` remains the
  outermost wrapper (it wraps the stack at `NewContext`), so the flag
  reflects every write. gin: `c.Writer.Written()` (gin's own flag — the
  facade is gone, `c.Writer` is gin's original writer). echo:
  `Response().Committed`. No type assertions anywhere.
- **`http.ResponseController` keeps working.** `CaptureStack.Unwrap()`
  returns the inner writer, so `Flusher`/`Hijacker`/`Pusher`/`ReaderFrom`
  resolution walks through the stack (SSE streaming is pinned by the
  existing e2e suite).
- **Concurrency:** one goroutine per request in all in-repo flows; `Add`
  happens in middleware, writes in the handler. The write path is
  lock-free: `inner` and the layers slice are published via
  `atomic.Pointer` so a defensive `-race` run with concurrent `Add`+`Write`
  stays clean. One atomic load + one forwarding call per write.
- **Status semantics hardened:** first `WriteHeader` wins (today's
  `CaptureWriter` overwrote). For every current call path the first write
  is the only write, so this is a strict hardening of the documented
  gin `WriteHeaderNow` edge.
- **Background path:** `backgroundHandlerContext.Capture()` returns the
  registry stack (never installed, `Add` returns a live handle), `JSON` is
  a no-op so the handle stays empty, commits no-op. No panic, no audit
  noise — pinned by the Coordinator path test.
- **Commit surface:** `middleware.CommitCapturedBody(ctx, key, cache, body,
  status)` keeps its signature. `CommitIdempotentResponse(ctx, status)`
  reads `IdempotencyStateKey` from the registry and commits from the
  handle; the `st.capture == nil` branch and `recordCaptureMissing` are
  deleted — the state and the handle are created together by the same
  middleware, so "key present but no capture" is no longer expressible.
  The /token path (`server_token.go`) swaps `InstallCapture(ctx,
  s.idempotentMu.Unlock)` for `ctx.Capture().Add(s.idempotentMu.Unlock)`
  and `*middleware.CaptureWriter` for `*core.CaptureHandle`; the
  hit-path `ReplayCachedResponse` is unchanged.

### Failure modes

| Failure | Behavior | Why acceptable |
|---|---|---|
| Layer added after response bytes flowed | Layer sees a suffix (or nothing) | Same as today; structural rule: Add in middleware, writes in handler; error statuses are never cached (2xx-only commit) |
| Stack never installed but layers added | Handle stays empty; commit no-ops (status 0) | Background path only; in-repo HandlerContexts exist only under a router/adapters `ServeHTTP`, which always installs |
| Double `Unlock` | Mutex panic ("unlock of unlocked mutex") | Caller contract, unchanged from today; commit is a single `defer` |
| A middleware replaces the wire writer wholesale (not wrapping) | Its writes bypass the stack | Pre-existing hazard; no in-repo middleware does this (all wrap); the install-at-router-boundary rule makes the bypass impossible for anything inside the router |
| Compression/CORS reordering inside `wrapInnerMiddlewares` | Layer bytes change (compressed ↔ raw) | Only if someone moves the router relative to compression; the capture position is defined as "the router's writer", and the router's position is pinned by the conformance + e2e suites |
| `Unwrap` forgotten on a future wrapper | SSE/Flush silently degrades | Pinned by e2e; `Unwrap` is part of the stack's contract |

---

## Decision 3: Unified request-state surface (`RequestStateOf` on `r.Context()`)

### API surface

No new public types beyond Decision 1. The registry becomes the single
truth for both middleware signatures:

- **http.Handler-level writers** (`TrustedProxies.Middleware`,
  `rs.HTTPMiddleware`, `RequestLogger`): `st, nctx := core.RequestStateOf(r.Context()); core.Set(st, key, value); next.ServeHTTP(w, r.WithContext(nctx))`.
- **HandlerContext-level readers**: `core.Get(core.StateOf(ctx), key)`,
  or the package helper (`tenant.FromHandlerContext`).
- **`peertrust` keeps its type and its exported signatures.** `requestInfoKey`
  is deleted; `WithRequestInfo`/`RequestInfoFrom` become registry one-liners.
  `RealClientIP`/`ForwardedHeadersTrusted` keep their exact fallback
  semantics (absent state → `RemoteAddr` / first-hop trust) — byte-identical
  when the middleware is not installed.
- **`RequestLogger`** becomes a registry layer (Decision 2) — same
  signature `func(http.Handler) http.Handler`, no `requestLogResponseWriter`.
  Documented behavior delta: with `debugRequestLogBodies` + compression both
  enabled, logged response bodies are now uncompressed (capture position is
  the router boundary). Debug-only surface; strictly more useful output.
- **`geo.WithContext`/`WithRequestInfo` nil-shortcut preserved:** nil info
  returns `ctx` unchanged; non-nil derives (one `WithValue`), which is the
  only contract change and is invisible to callers.

### Tenant resolution memoization

- One internal implementation: `lookupResolved(ctx, store, opts, host)
  (*Resolved, bool)` in `domains/tenant` — the Host → Domain → Tenant
  sequence, knobs (`Timeout`/`HostExtractor`/`IncludeSuspended`) read once.
  `tenant.Middleware` calls it and stores the result:
  `core.Set(core.StateOf(hctx), ResolvedKey, &Resolved{...})`.
- `ResolveTenantID` is *reduced to a one-line adapter* (the spec's
  parenthetical), keeping its name and signature so the two call sites
  (`options_httpstack.go:121`, `server_routes.go:425`) and any embedder do
  not change:

  ```go
  func ResolveTenantID(ctx context.Context, store Store, opts MiddlewareOptions, r *http.Request) string {
      if st, _ := core.RequestStateOf(ctx); st != nil {
          if res, ok := core.Get(st, ResolvedKey); ok && res != nil && res.Tenant != nil {
              return res.Tenant.ID
          }
      }
      if res, ok := lookupResolved(ctx, store, opts, hostOf(r, opts)); ok && res.Tenant != nil {
          return res.Tenant.ID
      }
      return ""
  }
  ```

  The registry-first check is O(1); on the rate-limit rejection path (which
  runs before tenant middleware, so the slot is normally empty) the cost is
  one store query — identical to today. When any earlier resolver filled
  the slot (tenant middleware on a later check, an http.Handler-level
  resolver, a second rate-limit evaluation of the same request), the reject
  path performs **zero** store calls — the mock-Store count assertion in
  the acceptance. The "second full copy of the lookup with copied knobs"
  is gone; the knobs exist once, in `MiddlewareOptions`.
- `rg 'type requestInfoKey struct\{\}|ResolveTenantID'` — `ResolveTenantID`
  survives as the allowed retained export (the spec's parenthetical); the
  duplicate implementation does not.

### Failure modes

| Failure | Behavior | Why acceptable |
|---|---|---|
| Slot filled by a different store/options than the caller's | Slot wins | Server wiring is single-configuration (`s.tenantMiddlewareOpts`); standalone callers pass the same opts they configure the middleware with |
| Slot holds a suspended-tenant result under `IncludeSuspended=false` | Not stored (middleware skips), reject path falls back to lookup — same result | Semantics unchanged; one lookup, not two |
| Rate-limit rejection on a never-resolved request | One fallback query | Same as today; not a hot path (rejections only) |
| Registry lookup on the reject path when state absent | Empty registry alloc | Reject path only; negligible |
| `peertrust`/`geo`/`rs` helpers called from a non-request context (gRPC, background) | Registry attaches to that context; data is per-invocation | Same visibility as today's `WithValue` keys — strictly more uniform |

---

## Delivery order and regression gates

1. **Improvement 1 (registry + all migrations).** One commit: `RequestKey`/
   `RequestState`/`Get`/`Set`/`State()`, carve `request_state.go`, migrate
   all seven bag keys and eight struct keys (helpers keep signatures),
   remove string `Get`/`Set`, delete the `*r = *r.WithContext` mutation,
   conformance suite switches to a typed suite key. Acceptance: the spec's
   greps at zero; `shared/core: 23`; compile-fail test for cross-type use;
   collision-panic test.
2. **Improvement 3 (unified surface).** Tenant single-lookup +
   memoized reject path (`ResolveTenantID` → one-line adapter),
   `peertrust`/`rs`/`RequestLogger` registry rewrites (largely already done
   in 1; this step proves the cross-signature property with tests):
   http.Handler writes → HandlerContext reads and vice versa, mock-Store
   zero-query assertion, `RequestStateOf` single-state-per-request test.
3. **Improvement 2 (capture stack).** `CaptureStack`/`CaptureHandle`/
   `Capture()`, router-boundary install in all three backends,
   `RequestLogger` as layer, delete `SetResponseWriter`/`InstallCapture`/
   `CaptureWriter`/`requestLogResponseWriter`/`recordCaptureMissing`/
   `EventIdempotencyCaptureMissing` + all adapters + `backgroundHandlerContext`
   in the same commit; routertest scenarios (two layers, identical bytes;
   `Written()` truthful post-capture; background commit no-panic);
   `docs/observability.md` event table + `docs/architecture/DIRECTORY_MAP.md`
   `shared/core` description in the same change.

Each step: `go build ./... && go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .`, then
`go test ./... -race` and `make ci` before merge. The audit-event removal
updates `auditreport/drift_test.go` in the same commit or `make ci` fails —
that is a feature, not a hazard.

---

## What could break the design

1. **The spec's literal `Get[T]` interface methods are illegal Go** — the
   design already adapts (free functions + `State()` accessor). The compile
   -time guarantee survives; anyone re-reading the spec against the code
   must not "fix" the API back toward interface methods.
2. **Capture position vs. compression.** If the stack is ever installed at
   an http.Handler layer instead of the router boundary, the idempotency
   cache silently stores compressed bytes and replays them as JSON — a
   wire-visible break with no audit canary left to catch it. The
   install-at-router-boundary rule is the single most load-bearing line of
   this design; the routertest capture scenarios and the e2e idempotency
   replay tests are its tripwires.
3. **SDK/embedder breakage.** `HandlerContext` loses `Get(string)`/
   `Set(string)`/`SetResponseWriter` and gains `State()`/`Capture()`;
   `middleware.InstallCapture`, `middleware.CaptureWriter`,
   `tenant.HandlerContextKey`, `geo.HandlerContextKey`, and
   `audit.EventIdempotencyCaptureMissing` are deleted. Any out-of-tree
   HandlerContext implementation, capture user, or audit-alias user breaks.
   Mitigation: this is exactly what the spec mandates; the changes are
   coordinated in single commits (no intermediate broken state); the SDK
   release notes must call out the interface change.
4. **Two divergent `RequestState`s per request.** A middleware that rebases
   the request context onto a fresh root (not derived from `r.Context()`)
   splits the registry. Today's `WithValue` keys have the same hazard;
   nothing in-repo does it. Pinned by a `-race` cross-signature test.
5. **Name collision between typed keys.** Mitigated by the Set-time panic
   and the package-prefix naming convention; a repo-wide test enumerating
   key names is cheap and should be added in improvement 1 (one table in
   the conformance suite).
6. **Hot-path cost.** Every request now pays one extra interface call +
   one atomic load per write (stack forwarding), even when no layer is
   added. The alternative (lazy install on first Add) reintroduces the
   writer-swap fragility the design exists to kill. Accepted; the write
   path is lock-free and allocation-free.
7. **`Unlock` lifecycle.** The /token single-flight mutex release moves
   from `CaptureWriter` to `CaptureHandle`; a double release panics. The
   single `defer` in `finishTokenIdempotency` is preserved verbatim.
8. **Debug-log behavior delta** (request-log bodies uncompressed) could
   surprise an operator grepping gzip bytes out of debug logs. Documented
   in the change; it only exists with `debugRequestLogBodies` +
   compression + idempotency capture on one request.
9. **File ceilings.** The carve is the only way to keep `shared/core` at
   23; if the carve leaves `router.go` or `request_state.go` over 500
   lines the design must split further into an existing file — it fits with
   ~150 lines of margin each. `interfaces/sso` gets zero new files (key
   vars live in existing files).
10. **`auditreport` drift test and observability docs** must move in the
    same commit as the event deletion, or `make ci` goes red — a
    same-change contract, not a later cleanup.
11. **`RequestLogger` without the router** (embedder using it standalone):
    the stack is never installed, so the layer stays empty and status logs
    as 0. Today the wrapper captured regardless. In-repo the router always
    runs under it; document that capture requires the sso router (or any
    chain whose innermost handler installs the stack).

## Spec corrections (flagged, not silent)

1. `HandlerContext.Get[T]/Set[T]` interface methods → generic free functions
   `core.Get[T]/Set[T]` + non-generic `State()` accessor (Go language
   limitation, proven by compile test).
2. "Four production string keys" → seven (const-keyed `geo:info` and
   region's bag key migrate too; the literal-string grep alone would leave
   the same collision class in place).
3. `ResolveTenantID` is retained as a one-line registry-first adapter (the
   spec's own parenthetical) rather than deleted — both call sites and the
   embedder surface stay unchanged while the duplicate implementation dies.
4. `requestLogResponseWriter` deletion changes debug-log body content from
   compressed to uncompressed when both debug logging and compression are
   enabled — a deliberate consequence of the single-stack requirement.
