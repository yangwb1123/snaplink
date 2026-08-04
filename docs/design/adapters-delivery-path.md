# Design: interfaces/adapters — 方向三正式交付路径（adapters delivery path）

Design for [`docs/requirements/adapters-delivery-path.md`](../requirements/adapters-delivery-path.md).
All file/line references below were re-verified against the working tree
before writing. Scope: exactly the three improvements (testkit router
injection + backend matrix e2e; embed-gin/embed-echo examples; adapters
contract doc + feature-matrix row + `adapters_check.py` CI gate). **Runtime
behavior change: zero** — this design adds test-only code, example code, and
documentation; the compiled production graph of the SDK is untouched.

**One requirement-vs-contract conflict was found and reconciled in this
design (Decision 2, finding F1):** the spec's acceptance "404/`token` 错误响应
字节与 StdRouter 后端逐字节相同" cannot hold literally for JSON error bodies —
the three backends render JSON through three different serializers (verified
below). Byte-identity is a documented guarantee only for the *unmatched-route*
surface; the matrix enforces byte-identity there and a precisely-scoped
semantic contract (status + JSON value + Content-Type prefix) for JSON error
bodies. `docs/adapters.md` states the guarantee scope so the declared contract
and the executable tests agree.

---

## Decision 1: `testkit.WithRouter(r sso.Router) Option` — testkit API surface

**What.** Add one option to `test/testkit/testkit.go`:

```go
// config gains one field
type config struct {
    issuerName   string
    clientID     string
    clientSecret string
    scopes       []string
    users        map[string]string // username -> password
    usersAreDefault bool
    router       sso.Router        // nil => sso default (NewStdRouter)
}

func WithRouter(r sso.Router) Option {
    return func(c *config) { c.router = r }
}
```

`NewServer` (testkit.go:105-127) appends `sso.WithRouter(cfg.router)` to the
option list **only when `cfg.router != nil`**. Rationale:

- Nil semantics stay identical to today: `mountMiddleware()`
  (interfaces/sso/server_routes.go:109-110) replaces a nil router with
  `NewStdRouter()` — so an unset option produces byte-identical behavior for
  the existing 16+ `WithRouter(sso.NewStdRouter())` call sites, which are pure
  additions and never edited.
- An explicit `WithRouter(nil)` is documented as "use the default StdRouter",
  matching the server's own nil discipline (same as every other `With*`
  option in this codebase).
- `sso.WithRouter` already exists (interfaces/sso/options.go:23) — **zero
  changes to `interfaces/sso`**, which is at its 60-file ceiling and must not
  grow.

**Ownership.** The injected router is caller-owned (like `WithUserProvider`
stores); the harness never closes it and adapters have no `Close`. The
`httptest.Server` wraps `srv.Handler()` as today — the probe mux +
middleware chain wrap whatever router was injected, which is exactly the
production embedding shape.

**Verification within the matrix itself (silent-fallback tripwire).** Because
a forgotten `WithRouter` silently degrades to StdRouter (the spec's core
grievance), the matrix registers a probe route on the injected router *before*
`NewServer` and asserts it is served. If testkit ever drops the pass-through,
the probe 404s and the matrix fails — the fallback can no longer be silent.
See Decision 2.

## Decision 2: `test/router_backend_matrix_test.go` — matrix structure and byte-comparison methodology

**What.** New file in `test/` (package `ssotest`, beside `e2e_test.go`), in the
`test/backendsemantics/backends_test.go` shape: a backend table, fresh harness
per subtest, one scenario set applied to every backend.

**Backend table and harness.**

```go
var routerBackends = []struct {
    name string
    new  func() sso.Router
}{
    {"std",  func() sso.Router { return sso.NewStdRouter() }},
    {"gin",  func() sso.Router { return ginadapter.NewGinRouter() }},
    {"echo", func() sso.Router { return echoadapter.NewEchoRouter() }},
}
// per subtest:
//   rt := b.new()
//   rt.GET(probePath, ...)              // fallback tripwire, see Decision 1
//   h := testkit.NewServer(testkit.WithRouter(rt))
//   defer h.Close()
```

Public constructors only, default wiring — the exact configuration
`sso.WithRouter` embeddings get, mirroring the routertest suite's own Factory
rule. Fresh harness per subtest means fresh in-memory stores (testkit seeds a
client + user per call); nothing is shared across subtests or backends. The
spec's "矩阵测试挂在 TestE2E 同级，纳入 `make test-e2e`" is satisfied by file
placement alone: `test-e2e` runs `go test -race -count=1 ./test/...`
(Makefile:259-260) and the new file is in that package.

**Scenario set** (one subtest per scenario × per backend, or one test with a
backend loop — either shape, the per-backend isolation is the invariant):

1. **Authorization code + PKCE full flow**: password login at `/auth/login`,
   authorize via `/auth/callback`, exchange at `/token` with `code_verifier`;
   assert `200` + valid tokens + `userinfo` round-trip. Reuse the request
   shapes from `test/auth_code_test.go` (`requestCode`/`exchangeCode`).
2. **Refresh rotation**: `grant_type=refresh_token` returns a new refresh
   token; reusing the old one returns `400 invalid_grant` (family kill) —
   asserted as status + error code equality across backends.
3. **DPoP-bound token**: the DPoP auth-code shape from
   `test/dpop_authcode_test.go` (bound code + proof-of-possession at
   exchange; wrong-key rejected) driven against each backend's harness.
4. **Unmatched-route byte identity**: unknown path, wrong method on a known
   path, HEAD on a GET-only route, trailing-slash variant — bytes compared
   against the std backend baseline (below).

**Byte-comparison methodology (finding F1, the design's key scoping).**
Verified serializer behavior:

| Backend | JSON writer | Body | Content-Type |
|---|---|---|---|
| std (`core.Context.JSON`, shared/core/router.go:137-143) | `json.NewEncoder().Encode` | trailing `\n` | `application/json` |
| gin (`render.JSON`, gin v1.12.0) | `json.Marshal` | **no** trailing `\n` | `application/json; charset=utf-8` |
| echo (`context.JSON`, echo v4.15.2) | `json.NewEncoder().Encode` | trailing `\n` | `application/json; charset=UTF-8` |

`routertest`'s `fiveMethodDispatch` already documents this deliberately:
"Cross-backend byte equality of the JSON body is NOT asserted". Therefore the
matrix enforces:

- **Byte-identical (status + body + full header map): the unmatched-route
  surface only** — unknown path / wrong method / HEAD / OPTIONS /
  trailing-slash → `http.NotFound` exact bytes. Baseline is captured **at
  runtime from the std backend harness** (recorder-level comparison via
  `httptest.NewRecorder` + `srv.Handler().ServeHTTP`, excluding wire framing
  like `Date`, exactly like `routertest.referenceNotFound`) — never hardcoded;
  if stdlib bytes drift, all backends track together.
- **Semantic equality for JSON error bodies** (e.g., `400 invalid_grant` at
  `/token`): same status, same parsed JSON value, same `Content-Type`
  prefix, same header *set* minus the serializer-implied charset difference.
  These responses flow through `ctx.JSON` (verified: `server_token.go`,
  `server_device.go` emit `errorBody(ctx, ErrInvalidGrant)` via `ctx.JSON`),
  so raw byte equality is not achievable without changing the adapters'
  JSON rendering — which would contradict routertest's committed decision
  and buy nothing (clients parse JSON). The spec's literal acceptance is
  thus satisfied on the surface where byte-identity is a real guarantee,
  and precisely documented for the rest; `docs/adapters.md` states this
  scope (Decision 4). If product ever requires wire-identical JSON, that is
  a separate adapter-normalization decision — see "What could break the
  design" item 3.

**Concurrency subtest (the `-race` acceptance).** `TestRouterBackendMatrix_ConcurrentUse`:
per backend, register a few routes, then run N goroutines — half issuing
requests through `rt.ServeHTTP`, half calling `rt.Use(...)` — under `-race`.
This is the tripwire the adapters' own comments demand ("a regression
tripwire for reverting to request-time reads"). It is race-free **by
construction**: adapter `Use` only appends to an adapter-local slice under
mutex (gin/adapter.go:129-133, echo/adapter.go:153-157) and never mutates the
engine, while request paths snapshot at registration — no engine route
registration happens concurrently with serving. The subtest deliberately
does **not** register routes concurrently (that would race inside gin/echo
themselves, which is an embedder error, not an adapter contract).

**Budgets.** New file target ≈ 350-400 lines — under the 500-line gate.
Crucially, **no new scenarios are added to
`interfaces/adapters/routertest/conformance.go`** (474 lines today, within
~26 lines of the 500 gate): new coverage lives in the matrix file, and the
spec's regression demo ("从 routertest 移除一个场景") is caught by the check
(Decision 6), not by growing the suite.

## Decision 3: `docs/examples/embed-gin` and `docs/examples/embed-echo` — framework embedding examples

**What.** Two new `package main` directories under `docs/examples/` (each its
own dir = automatically compiled by `make examples` →
`go build ./docs/examples/...`, Makefile:145-146). Both demonstrate the real
embedding shape: the embedder owns the engine, the adapter wraps it, the SSO
server mounts on it, and embedder business routes coexist on the same engine.

```go
// embed-gin/main.go (shape)
engine := gin.Default()                                  // embedder-owned engine
adapter := ginadapter.NewGinRouter(engine)               // public constructor, default wiring
engine.GET("/hello", func(c *gin.Context) {              // embedder business route
    c.String(http.StatusOK, "hello from the embedder")
})
srv := sso.NewServer(
    sso.WithRouter(adapter),                             // SSO mounts onto the SAME engine
    // ... minimal protocol wiring: issuer, user provider, client store,
    // session manager, password authenticator, jwt token issuers
)
log.Fatal(http.ListenAndServe(addr, srv.Handler()))      // Handler() = probe mux + SSO middleware + adapter
```

echo mirrors it with `echo.New()` + `echoadapter.NewEchoRouter(e)` +
`e.GET("/hello", ...)`.

**Interpretation note on the spec's "复用 `docs/examples/appcore` 的配置组装".**
`appcore` (docs/examples/appcore/handler.go) is the *client-side* business
handler shared by embedded-app/remote-app — it assembles no server
configuration. The embed-* examples are *server-side* embeddings, so the
relevant precedent is the wiring style of `basic/main.go`'s
`buildServerOptions` (programmatic `With*` assembly, no config file). Each
example therefore stays self-contained with ~10 `With*` options (mirroring
testkit's minimum viable protocol set, plus a redirect-URI-carrying client so
the auth-code smoke flow works). Copy-paste value beats shared-helper
abstraction for examples; duplication between the two examples is deliberate
and commented.

**Required comments (spec item 2), present in both examples:**

1. **404 normalization default**: unmatched requests are normalized to
   `http.NotFound`'s exact bytes (`engine.NoRoute`/`HandleMethodNotAllowed`/
   `RedirectTrailingSlash` pinned off at construction for gin;
   `RouteNotFound("/*")` catch-all + delegating `HTTPErrorHandler` for echo),
   so `sso.WithRouter(adapter)` is wire-interchangeable with `NewStdRouter()`.
2. **`RegisterGated` semantics**: route-level gate evaluated *before* any SSO
   middleware; a gated-off route is byte-identical to a never-registered one
   (no header leaks); group-derived routers preserve the gate. Note gin's
   `c.Abort()` is mandatory inside the gate and echo uses the swallowed
   `errGateOff` sentinel.
3. **Embedder overrides after construction**: assigning `engine.NoRoute` /
   `engine.HandleMethodNotAllowed` after construction (gin) or replacing
   `HTTPErrorHandler` (echo) later-assignment-wins — the embedder then owns
   the unmatched-response bytes and the byte-identity guarantee is gone.
   Also documented: embedder engine-level middleware applies to SSO routes
   too, while adapter-level `Use` snapshots at registration.

**Smoke tests (spec acceptance "手动冒烟（或示例自带测试）").** Each example
dir gets a `_test.go` in `package main` (`TestSmoke_AuthorizationCodeAndEmbedderRoute`)
that exercises the example's **own** `newServer()` constructor — the same
function `main` calls, so the smoke covers the shipped wiring, not a parallel
copy:

- `GET /hello` → 200 (embedder route coexists);
- full authorization-code flow: login → callback → token exchange → userinfo;
- unknown path → body byte-equal to the `http.NotFound` reference.

These run under `go test ./...` (root `make ci` race target) and
`go test ./docs/examples/...`; no new Makefile wiring needed. gin's debug
mode prints are avoided by `gin.SetMode(gin.TestMode)` in the test only
(production `main` keeps default mode).

**Public-API discipline.** Examples call only `NewGinRouter(engine)` /
`NewEchoRouter(engine)` (public constructors, engine-injection variants —
never `NewGinRouterWithOptions`/`NewEchoRouterWithOptions`, never
`WithFrameworkNotFound`). The check in Decision 6 statically enforces both
(grep for the constructors, grep for absence of `WithFrameworkNotFound`),
making the spec's "代码审查确认" mechanical rather than manual.

## Decision 4: `docs/adapters.md` — the delivery contract

**What.** New top-level doc `docs/adapters.md`, the single declared contract
for Router backends (the `permissions.Provider` +
`permissionstest.ConformanceSuite` analog that AGENTS.md §4 mandates for
permissions but that currently exists for no Router backend). Contents —
exactly the spec's five items, plus the enforcement section:

1. **Supported backends**: `std` (`NewStdRouter`), `gin`
   (`NewGinRouter`/`NewGinRouterWithOptions`), `echo`
   (`NewEchoRouter`/`NewEchoRouterWithOptions`). "Supported" is defined as
   *passing the routertest conformance suite and the matrix e2e* — a claim a
   backend cannot make without green evidence.
2. **Unmatched-response normalization**: unknown path, wrong method, HEAD on
   a GET-only route, OPTIONS, trailing-slash variant → byte-identical to
   `http.NotFound` (status + body + full header map). **Scope statement
   (finding F1)**: byte-identity covers the unmatched surface; JSON success
   and error bodies are semantically (not byte-) identical across backends —
   with the serializer table from Decision 2.
3. **`WithFrameworkNotFound` opt-out semantics**: "gives up the byte-identity
   guarantee"; the conformance suite must never be wired against this
   configuration; embedder post-construction overrides have the same effect.
4. **`GatedRegistrar`/`RegisterGated` behavior**: route-level gate before
   middleware, gated-off ≡ never-registered (byte-identical, no header
   leak), wrong method never reaches the gate, `Group` preserves the gate,
   `core.NewGatedRouter` is the coordination point.
5. **Capture primitives**: `SetResponseWriter`/`Aborted`/`Written` facade
   semantics — request-scoped, tracking-writer chain, gin's
   `ginCaptureWriter` facade, echo's public `Response.Writer` field, and the
   documented `WriteHeaderNow`-only edge.
6. **Enforcement** (ties the contract to executable truth): the scenario
   inventory of the routertest suite (named list — the check in Decision 6
   pins it), the matrix e2e file, and the two embed examples as the
   reference usage. Concurrency contract: `Use` snapshots at registration;
   concurrent `Use`+`ServeHTTP` is race-free by construction.

Also per spec item 3: append one sentence to
`docs/architecture/DIRECTORY_MAP.md:17` stating delivery semantics —
"adapters: Router backends std/gin/echo, byte-normalized unmatched
responses; contract in docs/adapters.md, reference usage in
docs/examples/embed-*".

## Decision 5: feature-matrix capability row — `embedding.framework-routers`

**What.** The generated block of `docs/feature-matrix.md` (lines 45-63) is
machine-produced from `ops/build/capabilities.json` ("edit the registry and
run `python cli.py capabilities generate`"); hand-editing inside the
BEGIN/END markers is drift that `capabilities check` flags. Therefore the
row is added to the registry:

```json
{
  "id": "embedding.framework-routers",
  "name": "Framework router embedding (gin/echo)",
  "summary": "Mount the SSO server onto an embedder-owned gin.Engine or echo.Echo via WithRouter; byte-normalized unmatched responses.",
  "availability": ["sdk"],
  "default_state": "enabled",
  "feature_gate": null,
  "required_stores": [],
  "module_capabilities": [],
  "config_keys": [],
  "surfaces": ["Router SPI"],
  "sources": ["interfaces/adapters"]
}
```

then `python cli.py capabilities generate` and verify
`python cli.py capabilities check` + `sdk-surface check` pass. Precedent for
an SPI-only surface exists: `storage.production` declares `"storage SPI"`
with empty module capabilities. The spec's "链接该契约文档与两个示例" is
satisfied by (a) the `summary` naming `docs/adapters.md` content, and (b) a
short hand-written note *outside* the generated markers (next to the profile
tables) linking `docs/adapters.md` and `docs/examples/embed-*` — the file
already hosts hand-written sections outside the generated block, so this does
not disturb regeneration.

## Decision 6: `checks/adapters_check.py` + registration — the anti-regression gate

**What.** New check module modeled on `checks/route_contract.py` (subprocess
Go execution is precedented there), exposing `run() -> int` (0 = pass).
Checks, in order:

| # | Check | Method |
|---|---|---|
| a | routertest suite exists and its scenario inventory matches the declared contract | static: parse the scenario-name table literal in `interfaces/adapters/routertest/conformance.go`; compare to the pinned list in the check (also listed in `docs/adapters.md` §6) |
| b | suite is wired into gin AND echo via public constructors, default wiring | static: `routertest.ConformanceSuite{` + `NewGinRouter(` / `NewEchoRouter(` in `gin/conformance_test.go` / `echo/conformance_test.go` |
| c | matrix e2e exists and names all three backends | static: `test/router_backend_matrix_test.go` contains `TestRouterBackendMatrix` and `NewGinRouter` / `NewEchoRouter` / `NewStdRouter` |
| d | embed examples compile | behavioral: `go build ./docs/examples/embed-gin/ ./docs/examples/embed-echo/` |
| e | examples use public constructors, never `WithFrameworkNotFound` | static grep in `docs/examples/embed-*/*.go` |
| f | `docs/adapters.md` exists and lists all three backends + the five contract sections | static: required section headings + backend tokens |
| g | suite and matrix actually run | behavioral: `go test ./interfaces/adapters/gin/ ./interfaces/adapters/echo/ -run Conformance -count=1` and `go test ./test/ -run TestRouterBackendMatrix -count=1` (the second recompiles the ssotest package; ~10-30s, acceptable for a CI gate — `make ci` already pays that compile via `race`) |

Pinned-list friction is **intentional**: removing a routertest scenario fails
(a) — the spec's regression demo; adding a legitimate scenario requires
updating docs/adapters.md §6 + the check together, which is the desired
contract-change ceremony. Fail-closed: any parse failure of the scenario
table (e.g., refactor) fails the check rather than silently passing.

**Registration (all four surfaces):**

1. `cli.py`: `cmd_check_adapters()` + `COMMANDS["adapters"] = cmd_check_adapters`
   (cli.py:323) + the `__doc__` command index line — makes
   `python cli.py adapters` independently runnable (spec acceptance).
2. `Makefile`: `.PHONY` + `adapters-check: $(CLI) adapters` target, added to
   the `ci` prerequisites list (Makefile:244). The spec's "make ci 全绿且输出
   包含 adapters 检查条目" is satisfied by the target echoing its name.
3. `docs/agent-os/CHECKS_REGISTRY.md`: row in the Python-modules table
   (Purpose: adapters contract enforcement; Command: `adapters`,
   `make adapters-check`), a command-group mention, and a scope/limitation
   note (static scans are existence-level; behavior is covered by the
   invoked Go tests).
4. `checks/test_adapters.py`: unit tests for the check's static parsers
   (pattern: `checks/test_route_contract.py`), discovered by
   `python cli.py check-test`.

**Regression-demo mapping (spec acceptance 3):** deleting `RegisterGated`
from `gin/adapter.go` breaks `make ci` via `race` (conformance GateOff
scenarios fail) *and* via `adapters-check` (b's behavioral run). Removing a
routertest scenario breaks only `adapters-check` (a) — which is exactly why
the check exists: `go test ./...` alone cannot see a deleted scenario.

## Storage model and state ownership

This feature introduces **no runtime or durable storage**. Its "storage
model" is the ownership of test/CI state and the declared-vs-executable
artifact inventory:

- **Test-state ownership**: every matrix subtest and every conformance
  subtest builds a fresh harness with fresh in-memory stores (testkit's
  `NewServer` seeds per call; routertest's `Factory` returns a fresh router
  per subtest). Nothing is shared across subtests, backends, or files; no
  network ports (httptest ephemeral). This mirrors
  `backendsemantics`'s "fresh backend per subtest" discipline and makes
  `-race` results deterministic.
- **Byte baselines are derived, not stored**: the 404 reference is produced
  at runtime from the std backend (routertest's `referenceNotFound` pattern,
  itself derived from `http.NotFound`). No hardcoded byte strings exist
  anywhere; if stdlib drifts, all backends track together and the suite still
  passes (correct — the reference moved).
- **Declared-truth store**: `ops/build/capabilities.json` is the single
  source of truth for the generated feature-matrix block; hand-editing the
  generated table is drift. `docs/adapters.md` is the single source of truth
  for the adapter contract, including the scenario inventory; the check
  (Decision 6) is the enforcement that declared and executable truth never
  diverge.
- **Artifact inventory** (what "the contract" durably consists of): the
  routertest suite (executable), the matrix e2e (executable, full-protocol),
  the embed examples + their smoke tests (executable usage), docs/adapters.md
  (declared), the capability row (declared), adapters_check.py + its unit
  test (enforcement). Each has exactly one owner; none is generated from
  another except the feature-matrix row from capabilities.json.

## Failure modes

| # | Failure | Detection | Mitigation |
|---|---|---|---|
| 1 | `WithRouter` pass-through silently dropped from testkit → matrix runs StdRouter three times (false green) | probe route registered on injected router 404s → matrix fails | Decision 1 tripwire; check (c) also statically requires the testkit option call |
| 2 | gin/echo bump changes unmatched-response behavior (gin NoRoute defaults, echo router semantics) | routertest byte-identity scenarios + matrix scenario 4 fail | suite is the tripwire; adapters pin behavior at construction; no code change needed, only verification |
| 3 | Echo `RouteNotFound` registration-after-first-request panic (pooled-context `maxParam`) | conformance suite panics on a shared-engine misuse; fresh-router-per-subtest isolates | documented in adapter comment; examples never register routes after serving starts |
| 4 | Embedder overrides `engine.NoRoute`/`HTTPErrorHandler` after construction | **not CI-detectable** — embedder-side | documented in examples + docs/adapters.md §3; examples demonstrate the correct pattern |
| 5 | Race regression (adapter reads middleware list at request time) | matrix concurrent `Use()` subtest under `-race` (make ci `race` + `test-e2e`) | subtest is the mandated tripwire; construction is race-free |
| 6 | routertest scenario removed or renamed | check (a) pinned-inventory mismatch → CI red | the spec's regression demo; intentional ceremony to change the contract |
| 7 | Check static scans break on refactor (suite split into multiple files, test renames) | parse failure → check fails loudly (fail-closed) | fail-closed by design; `checks/test_adapters.py` pins parser behavior |
| 8 | Capability row hand-edited in the generated matrix block | `capabilities check` drift detection | Decision 5: registry-only edits + regenerate |
| 9 | `capabilities check` rejects an SPI-only row (no endpoints) | `capabilities check` fails at implementation time | follow the `storage.production` precedent exactly; fallback = hand-written row outside the generated block (weaker: no drift protection) — rejected unless the registry blocks SPI rows |
| 10 | gin `Default()` Logger/Recovery middleware alters responses | — | Recovery writes a framework 500 only if it catches a panic; sso's `wrapPanicRecovery` always wraps outside the router (buildMiddlewareChain), so sso's recovery fires first; documented note in examples |
| 11 | JSON serializer drift across backends (charset/newline changes) | matrix semantic-compare still passes (status/JSON value/prefix) | by design — byte-identity scope is the unmatched surface only; docs/adapters.md states it |

## What could break the design

1. **Requirement-vs-contract conflict (F1) is the top risk.** If a reviewer
   insists on literal byte-identical JSON error bodies, the alternative is
   normalizing JSON rendering inside the adapters (shared encoder, pinned
   charset) — a real production-code change that contradicts routertest's
   committed fiveMethodDispatch decision and adds per-request overhead for
   zero client value (clients parse JSON). This design deliberately scopes
   the guarantee instead. The scope statement must be written into
   docs/adapters.md in the same change as the matrix, or the acceptance
   criterion and the tests will disagree forever.
2. **Framework upgrades**: verified pins are gin v1.12.0 / echo v4.15.2
   (root go.mod, already dependencies — no new dependency). Minor bumps are
   covered by the suite; an echo v5 (new router internals) would require a
   new adapter + contract entry, and the check's pinned suite would flag any
   dropped scenario during the port.
3. **Budget collisions**: `routertest/conformance.go` is 474 lines — within
   26 lines of the 500 gate. This design adds **no** scenarios there; if the
   suite must ever grow, the file must be split first (AGENTS.md budget rule
   — stop and split, never exempt). The matrix file must stay under 500
   lines; if the scenario set grows, split into
   `router_backend_matrix_*_test.go` files.
4. **Check cost/robustness**: check (g)'s `go test ./test/ -run
   TestRouterBackendMatrix` recompiles the 200+ file ssotest package
   (~10-30s). If CI budget complains, the behavioral matrix run can move to
   the `test-e2e` target (which already runs it) and check (g) keeps only the
   static presence assertions — but the spec's "可独立运行" acceptance argues
   for keeping the behavioral run in `python cli.py adapters`.
5. **capability_registry validation strictness** (failure mode 9): the
   registry may require `sources` paths to exist (they do:
   `interfaces/adapters`) or may link surfaces to OpenAPI operations
   (precedent says SPI surfaces are allowed). Verify `capabilities check`
   and `sdk-surface check` green immediately after `capabilities generate`;
   do not defer this to the end of the change.
6. **ssotest package growth**: one new file (~400 lines) in `test/` is
   within budget; the package is already 200+ files, so no fan-out concern
   (test files are exempt from the interfaces/sso ceiling; `test/` has no
   ceiling issue at +1).
7. **`docs-check`/`docs-validate`**: docs-check only validates a fixed file
   list (error-codes.md, openapi.yaml, SECURITY.md cross-refs) — the new
   docs/adapters.md cannot break it. `route-contract` scans `interfaces/sso`
   route registrations only; the examples' `/hello` routes are outside its
   scan and cannot break it. The regenerated feature-matrix table must keep
   the markdown table well-formed or `docs-validate`/`capabilities check`
   fails — run the generator, never hand-edit.
8. **Examples as tests**: smoke tests in `package main` example dirs run
   under root `go test ./...` (make ci `race`). gin's TestMode must be set in
   the test only; the production `main` keeps default mode so the shipped
   behavior stays the one the docs describe.
9. **Adapters' documented edges**: gin's `WriteHeaderNow`-only path records
   status on the original writer (not the capture) — if a future sso handler
   uses only `WriteHeaderNow`, capture-based assertions in the matrix would
   see a missing status. Today every terminal response goes through
   `ctx.JSON` (WriteHeader first), so the edge is dormant; the matrix's
   semantic-compare would surface it if it ever activates.
10. **Priority sequencing**: if only one improvement ships, it must be
    Improvement 1 (per the spec — it alone turns the adapters from dead code
    into test-constrained capability). The design is fully additive: each
    improvement is independently shippable, Improvement 3's behavioral
    checks reference Improvement 1's matrix and Improvement 2's examples, so
    3 must land last.

## Sequencing, gates, and acceptance mapping

**Order:** I1 (testkit option + matrix) → I2 (examples + smoke) → I3
(contract doc + capability row + check + registrations). After each step:
`go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` (mandatory per
AGENTS.md). Before handoff: `go test ./... -race`,
`go test ./test/ -run TestRouterBackendMatrix -v`, `make ci`.

**Acceptance mapping:**

| Acceptance criterion | Design element |
|---|---|
| Matrix green on 3 backends; 404 bytes identical, token errors per scoped contract | Decision 2 (scenario 4 = byte-identity; scenarios 1-3 = semantic) |
| `-race` clean incl. concurrent `Use()` | Decision 2 concurrency subtest |
| `make ci` green; testkit `WithRouter` used by an adapter call site | Decisions 1+6; matrix is the call site |
| `make examples` compiles; smoke runs auth-code + `/hello` 200 | Decision 3 + smoke tests |
| Examples use public constructors, no `WithFrameworkNotFound` | Decision 3 discipline + check (e) |
| `make ci` output includes adapters check; `python cli.py adapters` standalone | Decision 6 registration (1)-(2) |
| docs/adapters.md covers 5 contract items; feature-matrix row exists | Decisions 4+5 |
| Deleting `RegisterGated` or a routertest scenario breaks `make ci` | Decision 6 (a)+(b) via `race` + `adapters-check` |
