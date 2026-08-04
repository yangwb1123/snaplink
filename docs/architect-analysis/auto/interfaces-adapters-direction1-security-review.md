# Security Review: `interfaces/adapters` direction-1 design (abort + response capture)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/interfaces-adapters-direction1-design.md` (8 decisions, failure-mode
table, 10 risks, acceptance mapping) implementing
`docs/auto/interfaces-adapters-direction1-spec.md`.

This is an advisory review of a **proposal**. Nothing in the design is implemented in
the tree today. Reachability note up front, because it drives every severity: the
surfaces this design touches have **zero production usage** — the adapters have no
production callers (`NewGinRouter`/`NewEchoRouter` appear only in their own packages
and tests), `middleware.Idempotency`/`HandleIdempotentRequest`/
`CommitIdempotentResponse` have no callers at all (not even tests), the stock server
never wires an idempotency cache (`WithIdempotentStore` has no caller in `cmd/` or
`internal/`), and `Auth`/`CORS` have no production route usage (only the
`aliases.go:43-44` vars). Findings are therefore **design-level obligations for the
SDK surface being built**, not live exploits in the stock binary.

## Verification run for this review

Claims below are labeled per the evidence standard. I re-verified every design claim
I rely on against the current tree (no code changed):

- `shared/core/router.go` is 378 lines; `StdRouter.ServeHTTP` runs all middlewares
  then the handler unconditionally (`router.go:236-238`); `HandlerContext` has 11
  methods; `SetResponseWriter` exists only on `*core.Context` (`router.go:48-49`).
  **Verified**
- `interfaces/sso/server_token.go` is exactly 500 lines; the two concrete-type
  assertions are at `idempotency.go:74` and `server_token.go:125`; the `*r =
  *r.WithContext(...)` mutation is at `idempotency.go:72`. **Verified**
- `/token` gate order: `tokenNoStoreHeaders` → `requireDeps` → `bindOAuthParams` →
  `authenticateTokenClient` → residency gate → `captureSenderConstraint` →
  `enforceFAPITokenRules` → `rejectDisallowedGrantType` → `beginTokenIdempotency` →
  `dispatchTokenGrant` → `finishTokenIdempotency` (`server_token.go:36-87`). The
  idempotency hit check is strictly post-authentication. **Verified**
- `tokenIdempotencyCacheKey` (`server_resource.go:45-55`) fingerprints
  clientID + rawKey + request (secrets zeroed) + DPoP JKT + mTLS X5T through
  SHA-256; keys are bounded and secret-free. **Verified**
- The generic `middleware.Idempotency` cache key is the **raw client-chosen header**
  (`idempotency.go:66`), stored un-scoped (`idempotency.go:65-70`); no production or
  test caller exists anywhere (grep across `interfaces/`, `test/` — zero hits; the
  design's "only the middleware package itself and tests" overstates: there are no
  test callers either). **Verified**
- gin v1.12.0: `Context.Writer` is `gin.ResponseWriter` (interface incl.
  `http.Hijacker`, `http.Flusher`, `http.CloseNotifier`, `Status`, `Size`,
  `WriteString`, `Written`, `WriteHeaderNow`, `Pusher`); `c.Render` calls
  `c.Status(code)` → `c.Writer.WriteHeader(code)` **before** the render body write
  (`context.go:1073-1075, 1152-1166`); `render.JSON` writes via `w.Write`
  (`render/json.go:73,84`); `render.String` writes via `WriteString`. **Verified**
- echo v4.15.2: `Response.Writer` is a public `http.ResponseWriter` field
  (`response.go:18`); `WriteHeader`/`Write` set `Committed` themselves
  (`response.go:58-94`); `Flush`/`Hijack` read `r.Writer` **at call time**
  (`response.go:91-101`); `Unwrap()` returns `r.Writer`. **Verified**
- `platform/sse/handler.go:63-82`: `handleFilteredStream` takes a
  `core.HandlerContext`, calls `http.NewResponseController(ctx.ResponseWriter())`
  and requires `rc.Flush()` to succeed. Mounted via `interfaces/sso/
  server_admin_handlers.go:461` (admin event stream) and
  `protocols/selfservice/selfservicenotification/handlers.go`
  (`HandleFilteredStream`, user notification streams). **Verified**
- `middleware.Auth` writes 401 via `ctx.JSON` and returns (`middleware.go:44-59`);
  `CORS` writes 204 on OPTIONS via the raw writer (`middleware.go:70-73`). Both have
  zero production route usage (only `aliases.go:43-44`; `test/middleware_test.go`
  uses `sso.AuthMiddleware` against a fake context with a real
  `httptest.ResponseRecorder`). **Verified**
- Writer semantics after an early 401 today: net/http ignores a second `WriteHeader`
  but still writes subsequent body bytes to the wire; gin's `responseWriter.Write`
  writes regardless of prior status (v1.12.0 `response_writer.go:84-97`); echo's
  `Response.Write` skips the re-`WriteHeader` but still writes the body
  (`response.go:58-94`). So today the handler's 200 body bytes are appended to the
  401 body on **all three backends** — the 401 body is route-dependent (an
  oracle/fingerprint leak) and the existing `TestAuthMiddleware_*` tests cannot see
  it because `fakeContext.JSON` never touches a real writer. **Verified**
- `Compress`/`Recover`/`Degradation`/`AdminMiddleware.HTTPMiddleware` are
  `http.Handler` wrappers outside the `HandlerContext` chain (`compress.go:28-43`,
  `middleware.go:16-42`, `degradation.go:45`, `cmd/sso-server/build_http.go:86-87`);
  chain middlewares `Logger`/`Tracing`/`TokenNoStoreHeaders` write headers only.
  **Verified**
- Budgets: `server_token.go` = 500 lines (at ceiling), `router.go` = 378 (+~70 →
  ~448), `idempotency.go` = 122 (+~50 → ~172), `interfaces/sso` non-test files =
  60 (at ceiling). **Verified**

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets touched by the design

| Asset | Trust level | Notes |
|---|---|---|
| Cached `/token` responses (access + refresh tokens) in `IdempotentCache` | client-authenticated write path; read path = anyone holding key + matching fingerprint | Confidentiality asset; oracle-safety governed by AGENTS.md §3 |
| Generic-middleware cache entries (any 2xx body on a wired route) | write/read path = **raw key only**, no principal scoping | Confidentiality asset; cross-principal bleed risk (F1) |
| Response-writer chain (`trackingResponseWriter`, capture wrappers, gin facade) | trusted server-side; the facade is the only adapter seam | Availability asset: SSE streaming depends on the core writer (F3) |
| `HandlerContext` API (11→15 methods) | SDK public contract | Compile-time break for external implementors; abort honoring is doc-only |
| SSE event streams (admin events, user notifications) | admin:read / authenticated subject | Availability + integrity of realtime notifications (F3) |
| New audit event `idempotency_capture_missing` | audit sink (fingerprinted key only) | Cardinality bound (F7) |
| Chain-stop semantics in three routers | embedder-composed ordering | Ordering becomes security-relevant (F2, F6) |

### Trust boundaries

1. **Client → /token authentication boundary.** `authenticateTokenClient` runs
   before the idempotency hit check; a wrong-secret replay can never reach the
   cache (verified order, tested by `TestRcov_TokenIdempotencyRequiresSameAuthenticatedOperation`).
   The design preserves this position; the generic middleware has no equivalent
   enforcement (F2).
2. **Middleware-chain composition boundary (embedder-controlled).** `Abort()` makes
   the *order* of security middleware security-relevant for the first time: a cache
   hit aborts the chain and skips everything after it. The stock server is immune
   (no aborting middleware installed); SDK embedders are not.
3. **Cache-store boundary.** `IdempotentCache` implementations are trusted;
   `Get`/`Set` errors are ignored (fail open, pre-existing and preserved).
4. **Response-writer boundary.** Capture/tracking wrappers are trusted server-side
   code; they must not change the observable writer capability of `ctx.ResponseWriter()`
   for consumers like `http.ResponseController` (F3).
5. **Audit-sink boundary.** New event carries only a SHA-256 key fingerprint, never
   the raw key (Decision 7) — matches audit cardinality/secret rules.

### Attacker capabilities

- **Unauthenticated network attacker:** can send arbitrary `Idempotency-Key`
  headers on `/token` (blocked at auth — never reaches the cache) and on any
  generic-middleware-wired route (can populate and replay the raw-key cache if the
  middleware is misordered ahead of auth — F2); can hammer the audit event (F7);
  can probe the post-change 401 behavior differences (improvement over today).
- **Authenticated client (valid credentials):** can serialize all idempotent `/token`
  requests via the global `idempotentMu` (pre-existing, retained verbatim by
  Decision 6); can collide with another principal's generic-cache entry (F1);
  receives its own cached token responses by design (intended replay semantics).
- **SDK embedder:** composes the chain (F2/F6), chooses whether to install aborting
  middleware, and must implement the 4 new `HandlerContext` methods — a wrong
  `Aborted()` silently restores today's degraded behavior.
- **Compromised cache store or gin upgrade:** out of scope / mitigated by pin + tests
  (F5).

### Entry points (behavioral surfaces; no new HTTP endpoints)

1. `POST /token` with `Idempotency-Key` (SDK-wired only — `WithIdempotentStore` has
   no production caller).
2. Any route wired with `middleware.Idempotency` (generic path; zero callers today).
3. The three chain loops (`StdRouter.ServeHTTP`, `ginadapter.wrapHandler`,
   `echoadapter.wrapHandler`) with the new abort break.
4. `SetResponseWriter` on all three backends (gin facade, echo field assignment,
   core re-wrap).
5. The new `idempotency_capture_missing` audit event.

No new authentication, authorization, proxy-trust, SSRF, injection, or credential
surface is introduced. The trusted-proxy/XFF/tenant/geo middleware is untouched.

## 2. Findings (sorted by severity)

### F1 — High (design): generic `middleware.Idempotency` cache is keyed on the raw client-chosen key with no principal/tenant scoping — cross-user and cross-tenant response bleed on the opt-in generic path

**Evidence (Verified):** `middleware.Idempotency` stores `{rawKey, cache}` and the
cache key is the raw header (`idempotency.go:65-70`); `HandleIdempotentRequest`
reads with that raw key (`idempotency.go:94-107`). The `/token` path shows the
correct pattern — `tokenIdempotencyCacheKey` scopes by clientID + request fingerprint
(`server_resource.go:45-55`). Decision 6 explicitly keeps the generic path's "simpler
raw-key semantics".

**Preconditions:** an embedder wires `middleware.Idempotency(cache)` on a
user-scoped or tenant-scoped route (the design's documented opt-in path for
"non-token endpoints"); two principals use the same key. Colliding keys are realistic
for deterministic key schemes (batch job op-ids, request-hash keys, shared client
libraries), not just UUID collisions.

**Steps:** principal A (attacker) sends a request with `Idempotency-Key: K` that
returns a 2xx → body cached under K. Principal B (victim) sends the same operation
with key K → middleware replays A's cached body to B. On a tenant-scoped route, this
crosses the tenant isolation boundary without any authz bypass.

**Impact:** cross-principal disclosure of any 2xx body the endpoint produces (user
profile data, admin create-* responses containing secrets, token-shaped data), and
cache poisoning of the victim's operation result. This is the exact
oracle-safety/cross-tenant class AGENTS.md §3 guards; the design ships a documented
opt-in path that violates it while the sibling `/token` path demonstrates the fix.

**Remediation (required before merge):** scope the generic key by authenticated
identity and tenant when present, mirroring `/token`: derive
`key = SHA-256(route|subject|tenant|rawKey)` where subject/tenant are read from the
request context (auth middleware already populates these in the stock server); on
unauthenticated routes the key must include a marker so a pre-auth entry can never
match a post-auth key. At minimum, add a required `KeyScope func(ctx) string` option
and make the un-scoped form a compile-time opt-in with an explicit doc warning.

**Regression test:** two principals (distinct auth subjects/tenants) on the same
route with the same raw key must receive their own responses, never each other's;
replayed body must match the *current* principal's first response byte-for-byte.

### F2 — High (design): the generic middleware's oracle-safe ordering is a doc comment, not an enforced property; a misordered chain turns the cache into an authentication bypass

**Evidence (Verified):** Decision 6 states "Oracle-safe ordering is a position
invariant, not a code property" and the only guard is the middleware's doc comment
("install only at or after authentication"). The acceptance suite tests only the
correct ordering (the `/token` oracle test is post-auth by construction). Under the
design, a cache hit writes the cached 200 and calls `ctx.Abort()`, so every
middleware after `Idempotency` — including `Auth` — is skipped on all three backends
(chain loops at `router.go:236-238`, `gin/adapter.go:59-65`, `echo/adapter.go:61-66`).

**Preconditions:** an embedder installs `Use(middleware.Idempotency(cache))` before
`Auth` (a natural transport-level placement, next to `Tracing`); a 200 exists in the
cache for key K; the attacker replays a captured request (or guesses K).

**Steps:** victim's authenticated request with key K populates the cache. Attacker
replays the same request with **no credentials** → middleware cache hit → writes
cached 200 → aborts → `Auth` never runs → attacker receives the victim's response
without authentication. The same class applies to `/token` if an embedder installs
the generic middleware ahead of the router's own auth (the generic cache would be
consulted pre-auth, before `beginTokenIdempotency`'s post-auth check — a second
capture/hit path with a different key space).

**Impact:** credential-less replay of authenticated responses; the design's own
failure table classifies this "fail closed by position invariant", but the
"invariant" is unenforced prose, and the table has no row for a *misordered generic
middleware* (only for "middleware misordered" in the /token context).

**Remediation (required before merge):** make the property structural, not textual.
The F1 key-scoping fix does most of the work (a pre-auth request cannot compute the
post-auth key, so the hit path can never fire before authentication). Additionally:
(a) document and test that the generic middleware must not be installed on `/token`
(its key space collides with the sso inline mechanism and creates a second,
pre-auth-visible cache); (b) add the misordered-chain regression test below.

**Regression test:** chain `[Idempotency, Auth]` (deliberately wrong order), populate
the cache with an authenticated 200, then replay with no credentials → must **not**
return the cached 200 (assert the 401/auth rejection or, with key-scoping, a cache
miss that reaches `Auth`).

### F3 — High (design): Decision 3's `trackingResponseWriter` breaks SSE streaming and any `http.ResponseController`/optional-interface consumer unless it forwards `Unwrap` and the optional writer interfaces

**Evidence (Verified):** `http.ResponseWriter` (the embedded type in the proposed
wrapper) promotes only `Header`/`Write`/`WriteHeader`; an embedding struct has no
`Flush`/`Hijack`/`Pusher`/`io.ReaderFrom`/`Unwrap`. `platform/sse/handler.go:63-82`
does `rc := http.NewResponseController(ctx.ResponseWriter())` and treats
`rc.Flush() != nil` as fatal for the stream (returns without streaming). The admin
event stream (`server_admin_handlers.go:461`) and user notification streams
(`protocols/selfservice/selfservicenotification/handlers.go`) run through
`core.HandlerContext`. Decision 3 installs the tracking wrapper unconditionally at
`NewContext` (every `StdRouter` request, `router.go:239`), and its "delegates
everything else" claim is only true for the three base methods. Without `Unwrap()`,
`http.NewResponseController` cannot reach the inner writer; without `Flush`, `Flush`
returns `http.ErrNotSupported`.

**Preconditions:** the design lands as written (25-line wrapper, no optional
interfaces); any SSE stream (admin events or user notifications) is requested.

**Steps:** client subscribes to the admin/user event stream → `handleFilteredStream`
→ `rc.Flush()` fails → handler returns → the stream closes immediately (or delivers
replay only, no live events, no heartbeat). Silent: the failure surfaces as a dropped
stream, not an error response or log.

**Impact:** availability + silent degradation of the realtime security-adjacent
surfaces (CAEP-style admin events, user notifications) on the default StdRouter — the
one backend with production usage. This is the highest-impact implementation hazard
in the design; it is invisible to the design's own acceptance tests (none exercise
SSE through the tracking wrapper).

**Remediation (required before step 1 lands):** `trackingResponseWriter` must
implement `Unwrap() http.ResponseWriter` (ResponseController transparency) and
forward `Flush`, `Hijack`, `Pusher`, and `io.ReaderFrom` to the inner writer when the
inner supports them — the standard conditional-forwarding pattern, ~15 lines.

**Regression test:** (a) unit test: `http.NewResponseController(ctx.ResponseWriter())`
on a `*core.Context` built over a `httptest.ResponseRecorder`-style flusher returns
`Flush() == nil`; (b) integration: admin SSE stream and a user notification stream
through `StdRouter` deliver replay + live events + heartbeat (extend the existing
`test/` SSE coverage to run through the router).

### F4 — Medium: replay regenerates headers, not just the body — a replayed credential-bearing response can lose `no-store`/`Pragma` when the generic middleware is used

**Evidence (Verified):** only the body is cached (`idempotency.go:96-101` writes
`Content-Type` + 200 + cached bytes; `CommitIdempotentResponse` caches
`iw.body.Bytes()` only). The `/token` path is safe by position: `tokenNoStoreHeaders`
runs at the top of `handleToken` (`server_token.go:36-40`), before the swap, so the
replay writes through the same header map that already carries
`Cache-Control: no-store; Pragma: no-cache`. The generic path has no such guarantee:
a replay carries whatever headers middlewares that ran **before** `Idempotency` on
the *second* request set; anything the original response carried from middlewares
**after** it (e.g. `TokenNoStoreHeaders` installed late, or `ClearSiteData`,
`X-Content-Type-Options` policies) is absent.

**Preconditions:** an embedder uses the generic middleware on a credential-bearing
or sensitive endpoint with `TokenNoStoreHeaders` (or equivalent) installed after the
idempotency middleware.

**Impact:** AGENTS.md §3's "credential endpoints use no-store" wire contract silently
weakens on the replayed leg — an intermediary can cache the replayed credentials.
Content-type drift also occurs if the original 2xx was non-JSON (replay hardcodes
`application/json`).

**Remediation:** cache and replay the response headers alongside the body (at least
`Content-Type`, `Cache-Control`, `Pragma`), or require/document the ordering
(`TokenNoStoreHeaders` must precede `Idempotency`) and enforce it with a test.

**Regression test:** wire `[TokenNoStoreHeaders, Idempotency]` and
`[Idempotency, TokenNoStoreHeaders]` on a dummy 2xx route; assert the replayed
response carries `Cache-Control: no-store` and `Pragma: no-cache` in both orders
(fix the code so both pass, or make the second order a hard test failure with a loud
doc note).

### F5 — Medium: the gin facade will **not** fail loudly on gin upgrades, and `WriteString` bypasses the capture today — the design's risk 1 is factually wrong

**Evidence (Verified):** the facade embeds `gin.ResponseWriter`, so **any new method
gin adds to the interface is inherited automatically** — the design's claim "any gin
upgrade that adds a method breaks compilation at the facade" is incorrect; there is
no loud failure. The real risk is the opposite: a gin render path that writes through
a method the facade does not route to the capture. That already exists today:
`render.String` writes via `WriteString` (gin v1.12.0), which the facade inherits
from the embedded original and therefore bypasses the capture. The current
`c.JSON` path is safe (`Status` → `WriteHeader` → `Write`, verified in gin source),
and Snaplink's `HandlerContext` cannot render strings, so nothing in-tree hits the
gap — but an embedder mixing gin-native handlers on the same engine/context, or a
future gin render change, would silently lose capture and therefore silently lose
idempotent replay (the exact failure class this design exists to eliminate).

**Remediation:** (a) correct risk 1 in the design; (b) route `WriteString` through
the capture in the facade (one method); (c) pin the facade's routing with a
compile-time-shape test plus an interface-conformance test that asserts
`Header`/`Write`/`WriteHeader`/`WriteString` reach the capture; (d) keep the gin pin
(already in `go.mod`) and add a gin-bump checklist note.

**Regression test:** install the facade over a recording gin writer, drive
`c.String(...)`, `c.JSON(...)`, and `c.Data(...)`, and assert the capture saw the
status and body bytes for all three.

### F6 — Medium: chain-stop silently drops downstream middleware — observability and audit enrichment vanish on rejected requests for embedder chains with `Auth`/`CORS` before enrichment middleware

**Evidence (Verified):** the abort break stops the loop, so any middleware registered
after the aborting one never runs. The design's failure table covers handler-side
side effects ("deliberate behavior change") but not middleware-side: an embedder
chain `[Auth, Tracing]` (or `[Auth, Logger, tenant, geo]`) now serves 401s without
`X-Request-Id`/traceparent and without audit enrichment for rejected requests.
The stock server is unaffected (its rejections are handler-side; `Auth`/`CORS` are
not installed; the admin 401 path is an outer `http.Handler` wrapper,
`build_http.go:86-87`).

**Impact:** for SDK consumers, rejected-request observability (trace correlation,
tenant/geo audit enrichment) silently degrades; incident response for auth-failure
attacks loses the audit trail that AGENTS.md requires ("details only in audit" for
oracle-safe surfaces).

**Remediation:** document on `Auth`/`CORS` that abort is terminal for the rest of the
chain and they must be installed after all enrichment middleware (Tracing/Logger/
tenant/geo/region); pin with tests.

**Regression test:** chains `[Tracing, Auth]` and `[Auth, Tracing]` on a protected
route; assert the 401 carries `X-Request-Id`/traceparent in the first order and
document the second order's behavior in the test name/comment.

### F7 — Low: the loud-commit audit event is unbounded-rate by construction on the generic path, and per-request emission needs rate discipline

**Evidence (Verified):** Decision 7 + risk 7 acknowledge the rate is unbounded for
anyone reaching a keyed request. On the generic path the event fires pre-auth (the
middleware runs before any auth gate when misordered), so an unauthenticated
attacker can inflate audit volume on a miswired route; on `/token` it is
post-auth-bounded. The key fingerprint bounds cardinality of *content* but not
*rate*.

**Remediation:** rate-limit or sample the event (a small token bucket in the
middleware), classify it in `auditreport` as a diagnostic (not a security event) as
the design already commits to, and add meta via `audit.SetMeta` only.

**Regression test:** N=1000 keyed requests through the generic middleware with a
recorder; assert emitted event count is bounded (e.g. ≤ rate limit) and no raw key
appears in any event payload.

### F8 — Info: design-doc drifts worth correcting before merge

1. **Risk 1** ("gin adds a method → compile error"): wrong — see F5. The
   embedded-interface facade inherits silently.
2. **Failure-table row** ("double writes are currently swallowed by net/http's
   superfluous-write guard on StdRouter"): the guard swallows the second
   `WriteHeader`, but the handler's body `Write` still reaches the wire on all three
   backends (verified net/http + gin v1.12.0 + echo v4.15.2). Today's 401 body is
   401 + handler JSON appended — **route-dependent**, an oracle/fingerprint leak the
   abort change removes. The "byte-identical" acceptance must therefore compare the
   **new** clean 401 across backends, not today's behavior; no existing test asserts
   the corrupted state (fakeContext never writes a real body), so landing is safe.
   This strengthens the design's rationale; state it precisely.
3. **Risk 9** (echo `Flush`/`Hijack` bypassing the swap): inaccurate — echo's
   `Response.Flush`/`Hijack` read `r.Writer` at call time (`response.go:91-101`), so
   after the swap they reach the capture (and through it the original). The stated
   gap does not exist.
4. **Risk 6** ("snapshot semantics"): `wrapHandler` reads `g.middlewares` at request
   time (no snapshot; the analysis doc flags the concurrent `Use()`/`ServeHTTP`
   race as pre-existing). The practical test guidance stands.
5. **Caller claim**: "only the middleware package itself and tests" — there are no
   test callers of `middleware.Idempotency`/`HandleIdempotentRequest`/
   `CommitIdempotentResponse` (grep across `interfaces/`, `test/`: zero hits).
   Retirement is even freer than stated.

## 3. Abuse-case table

| # | Abuse case | Class | Reachable? | Outcome under design | Control |
|---|---|---|---|---|---|
| A1 | Replay cached 200 to a wrong-secret `/token` request | Replay / oracle | Attemptable by any attacker | `401`/`400` before the hit check; cached 200 never served | **Positive control** (post-auth position, `server_token.go` order; test `TestRcov_TokenIdempotencyRequiresSameAuthenticatedOperation`) |
| A2 | Unauthenticated replay of a cached 200 via generic middleware installed before `Auth` | Identity spoofing / replay | Yes, when embedder misorders (F2) | Cached 200 + abort → auth skipped | F2 fix (principal-scoped key + misorder test) |
| A3 | Same raw key used by two principals on a generic-wired route | Cross-tenant access / sensitive-data leakage | Yes, on key collision (F1) | Second principal receives first principal's cached body | F1 fix (subject/tenant-scoped key) |
| A4 | Replay of a credential-bearing response whose `no-store` headers were produced after the idempotency middleware | Sensitive-data leakage via intermediary caches | Yes, on embedder ordering (F4) | Replay lacks `Cache-Control: no-store`/`Pragma: no-cache` | F4 fix (cache+replay headers; ordering test) |
| A5 | Probe for route fingerprints via 401 body differences after `Auth` | Oracle | Today: **live** on all three backends (handler body appended to 401) | Removed: chain stops, 401 body is clean and route-independent | **Positive control** of the abort change; three-backend byte-identical 401 test |
| A6 | Proxy/header forgery through the adapters | Proxy trust | No new surface | Untouched: trusted-proxy/XFF/tenant/geo middleware unchanged; adapters add no header trust | Verified unchanged |
| A7 | Audit-volume inflation via `Idempotency-Key` hammering | Resource exhaustion | On miswired generic path; post-auth on `/token` | Unbounded per-request event on the generic path | F7 fix (rate-limit/sample; `auditreport` diagnostic class) |
| A8 | Serialize/deny idempotent `/token` requests via the global `idempotentMu` | Resource exhaustion | Yes, with valid client credentials (any idempotent client) | Pre-existing, retained verbatim by Decision 6 | Residual risk (per-server global mutex; document; consider per-key striping later) |
| A9 | SSE stream silently dies because the tracking wrapper lacks `Flush`/`Unwrap` | Availability | Yes, on StdRouter once Decision 3 lands (F3) | Stream closes on first flush; no live events | F3 fix + SSE-through-router regression test |
| A10 | New-principal request for key K gets a stale cached 200 from a previous principal | Identity spoofing / replay | Via F1 collision or pre-auth misorder | Cached body served | F1/F2 key-scoping |
| A11 | gin upgrade changes the writer contract; capture silently bypassed via a new/`WriteString` method | Replay (silent degradation) | Future (F5) | Capture misses body/status; replay protection degrades without error | F5 fix (WriteString routing, conformance test, pin) |
| A12 | Cached 200 replayed with wrong `Content-Type` for non-JSON endpoints | Integrity (minor) | Generic path only (F4) | Replay hardcodes `application/json` | Folded into F4 header replay |

## 4. Positive controls verified

- **/token oracle-safety position is real and preserved.** The hit check sits after
  `authenticateTokenClient`, the residency gate, sender-constraint capture, FAPI
  rules, and grant-type rejection (`server_token.go:36-87`); the wrong-secret replay
  test exists and the design's three-backend oracle test extends it. **Verified**
- **/token key fingerprint excludes secrets and is bounded.** clientID + request +
  DPoP JKT + mTLS X5T through SHA-256 (`server_resource.go:45-55`); a changed DPoP
  key is a new operation (correct issuance semantics, not a replay). **Verified**
- **Atomic consume / single-flight retained.** `idempotentMu` + cache-set-only-on-200-
  with-non-empty-body survive the consolidation verbatim (Decision 6). **Verified**
- **`no-store` survives the /token replay leg** because `tokenNoStoreHeaders` runs
  pre-swap in the handler and the replay writes through the same header map.
  **Verified**
- **Abort is opt-in with a bounded blast radius.** Only `Auth`/`CORS` migrate; zero
  production usage of either (grep); `TestGatedRouter_*` and adapter tests are
  untouched by construction. **Verified**
- **Compression composes correctly.** The gzip wrapper is an `http.Handler` outside
  the chain; the capture sits below it and records raw bytes; replays are
  re-compressed per request with honest `Content-Encoding`. **Verified** (read of
  `compress.go:28-133`)
- **gin's JSON render path reaches the capture.** `c.Render` → `c.Status` →
  `WriteHeader` → `render.JSON` → `Write` (gin v1.12.0 source). The `WriteHeaderNow`
  edge is confined to bodyless statuses (204/304), which Snaplink never renders via
  `ctx.JSON`. **Verified**
- **echo's `Committed` stays truthful across the swap** (`Response.Write`/
  `WriteHeader` set it themselves). **Verified**
- **Budget compliance of the plan.** `server_token.go` net-negative; `router.go`
  ~448/500; `idempotency.go` ~172/500; sso file ceiling untouched; no new files.
  **Verified**
- **The change removes a live oracle leak.** Today's post-`Auth` 401 bodies carry the
  handler's 200 body appended on all three backends (route fingerprinting); the
  abort change removes it (F8.2). **Verified** (writer semantics read from net/http,
  gin v1.12.0, echo v4.15.2)

## 5. Residual risks (accepted or out of scope)

1. **Third-party custom `Router`s ignore `Abort`** — interface cannot force
   chain-stop; documented; the three supported backends are tested. Accepted.
2. **External `HandlerContext` implementors** may implement `Abort`/`Written`
   incorrectly (always-false) — silent reversion to today's behavior; doc-contract
   only. SDK-semver-visible break is the forcing function. Accepted.
3. **Step 2 ships a half-feature** (commit assertion still fails under adapters until
   step 3) — mitigated by merge-as-one-series and the re-sequenced acceptance.
   Accepted.
4. **Global `idempotentMu` serialization** of all idempotent `/token` requests
   (pre-existing, retained verbatim). Accepted; document as a capacity note.
5. **Generic middleware commit-side cooperation remains** — a handler that never
   calls `CommitIdempotentResponse` silently disables caching (no event fires: the
   loud-commit covers capture loss, not missing commit). Zero callers today; the
   `/token` path cannot hit it (commit is unconditional). Document loudly.
6. **Abort-flag integrity across third-party wrappers**: a middleware that calls
   `Abort()` without writing produces a truncated chain (no response). Doc contract:
   "Abort is opt-in and sticky: call only after writing a terminal response".
7. **SSE through the tracking wrapper** — resolved only by the F3 fix; treat as a
   hard dependency of step 1.

## 6. Prioritized validation plan

| Priority | Item | Gate |
|---|---|---|
| P0 | F3: `trackingResponseWriter` `Unwrap` + optional-interface forwarding; SSE-through-router regression (admin stream + user notification stream) | Blocks step 1 |
| P0 | F1 + F2: principal/tenant-scoped generic key; misordered-chain and two-principal collision regression tests; doc prohibition of generic middleware on `/token` | Blocks step 3 |
| P1 | F4: header capture/replay (or enforced ordering) + two-order regression test | Step 3 |
| P1 | F5: facade `WriteString` routing + interface-conformance test; correct risk 1 | Step 2 |
| P1 | F6: `Auth`/`CORS` doc contract + chain-order observability tests | Step 1 |
| P2 | F7: audit event rate limit + `auditreport` classification + no-raw-key assertion | Step 3 |
| P2 | F8 doc corrections (401 corruption baseline, echo Flush/Hijack, caller counts) | Any step |
| P3 | Design's own acceptance suite per the mapping table: three-backend 401/204 table, three-backend `/token` replay + wrong-secret oracle, side-effect counter, audit-on-capture-loss, `grep '\.(\*core\.Context)' interfaces/` → zero | Steps 1–3 |
| P3 | Mandatory gates per step: `go build ./... && go vet ./...`, `go test -run 'TestMaintainability_|TestArchitecture_' .`; handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` | Every step |

Bottom line: the design's security core (post-auth `/token` replay, fingerprint keys,
single-flight, no-store preservation, opt-in abort) is sound and verified against
code. Three design-level gaps must be closed before merge — the un-scoped generic
cache key (F1), the unenforced ordering invariant (F2), and the
tracking-wrapper/SSE break (F3) — plus the header-replay gap (F4) and the facade
claims correction (F5). None of these is exploitable in the stock server today, which
is exactly why this is the right moment to fix them.
