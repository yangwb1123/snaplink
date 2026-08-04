# QA Review: interfaces/apidocs — runtime-faithful projection, contract rendering, bidirectional lockstep

Reviewed artifact: `docs/auto/interfaces-apidocs-design.md` (design stage, commit
`9b3b4966 [pi-batch] Stage: design`). No decision of the design is implemented
yet; this review evaluates the design's test plan, its testability, and its
acceptance traceability against the current tree. Advisory only.

## 1. Test inventory and commands actually run for this revision

All commands ran against the working tree at commit `9b3b4966`.

| Command | Result | Evidence |
|---|---|---|
| `python cli.py check-routes` | **PASS** — 241 runtime routes, 322 documented operations | baseline for Decisions 1/3 |
| `go build ./... && go vet ./...` | **PASS** | mandatory gate |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | **PASS** | mandatory gate |
| `go test ./...` | **PASS** (all packages, no failures) | full unit sweep |
| `go test ./interfaces/apidocs/... ./interfaces/sso/ -count=1` | **PASS** (apidocs 0.003s, sso 11.6s) | affected surface |
| `python cli.py sdk-surface check` | **PASS** — 13 groups, 316 operations, 2 languages | Decision-3 schema surface |
| `python cli.py capabilities check` | **PASS** — 28 capabilities | gate dependency |
| diff harness (below) using `checks/route_contract.py` internals | computed `documented − registered` = **81 operations** | the concrete 81 |
| `python -m pytest` | **FAIL (environment)** — `No module named pytest` | `cli.py check-test` cannot run here; not part of `make ci` (Makefile:244) |
| `go test ./... -race`, `make ci`, E2E | **NOT RUN** this revision | implementation-stage gates |

Diff harness (reproduces the design's Decision-3 triage input): reused
`discover_route_calls` / `resolve_route_expressions` / `runtime_routes` /
`openapi_operations` from `checks/route_contract.py`. Output: 81 documented
operations with no static registration, **none** of them v2alpha/setup/WASM/
CAEP/federation — the design's correction of the analysis is **Verified**. The
81 are: admin CRUD families served by the gRPC gateway (`/api/v1/admin/
{clients,domains,permissions,releases,snapshots,tenants,users,keys,operations,
tokens/*,dr/status}` — `cmd/sso-server/build_http.go:97-196,418`), SCIM v2
(`cmd/sso-server/scim_routes.go:39,64` — mounted via `srv.Handle`), WebAuthn
(`cmd/sso-server/serverwebauthn/webauthn.go:26`), `GET /branding`,
`GET /mesh/ext-authz`, and `/api/v1/compliance/*` (also `srv.Handle`,
`build_http.go:60`).

### Existing test inventory of the affected surface

- `interfaces/apidocs/apidocs_test.go` (113 lines, 3 tests): parse+serve+headers
  (`no-store`, HTML content-type, inlined spec), malformed-YAML fail-safe,
  duplicate-top-level-key last-wins. No projection, no rendering tests.
- `checks/test_route_contract.py` (6 tests): receiver filtering, admin-prefix
  application, operationId uniqueness, one-way missing-route errors, plus a
  repository-level test (`test_repository_runtime_routes_are_documented`).
- **No** sso-layer test exercises `WithAPIDocsUI` (grep: no test references
  `apiDocsUIHandler`/`mountAPIDocsUI`).
- **No** unit tests for `ops/scripts/sdk_surface.py` (no `test_sdk_surface.py`
  in `checks/`; verified by listing).
- **No** E2E (`test/`) coverage of the docs viewer.

## 2. Requirement-to-test matrix

Spec acceptance checks from `interfaces-apidocs-spec.md`, traced to the design
provision and the test that must prove it. Status **Proposed** = the design
names the test but it does not exist yet; **Missing** = no test is named.

| # | Spec acceptance | Design provision | Test status / evidence |
|---|---|---|---|
| A1 | Projected spec contains no 404-ing op; ops reappear when option set; deterministic | recorder `Mounted` + parity test vs `check-routes` | **Proposed, Partial** — parity mechanism unspecified (F1); no option-toggle test at sso layer (F3); gate-off 404 conflict unscoped (F2) |
| A2 | `servers` = resolved issuer; `info.version` = buildinfo | `ResolveIssuer: s.resolveIssuer`, `buildinfo.Resolve("")` | **Proposed, Partial** — apidocs unit tests named for issuer/version injection; dev-build `(devel)` semantics unpinned (F5) |
| A3 | Projection failure degrades to unprojected spec | nil/empty fields + `project` error path | **Proposed** — malformed-input fallback test named in spec |
| A4 | `/token` op shows auth family + `invalid_grant`/`invalid_client`; plain admin GET shows bearerAuth only | security rendering + backtick extraction filtered by `stableErrorCodes` | **Proposed, Partial** — "scheme name + representative code" test named; vocabulary-filter negative tests not enumerated (F9) |
| A5 | Catalog reachable; untied codes listed | embedded `error-codes.md` section | **Proposed** — catalog section; nil-`ErrorCodes` degradation not pinned (F9) |
| A6 | Renderer tests on fixture spec | `apidocs_test.go` additions | **Proposed** — fixture spec with `security`/`securitySchemes`/ErrorResponse named |
| A7 | Reverse check fails on untriaged documented op; passes after triage | `unmountedOperations` exceptions + bootstrap | **Proposed, Partial** — set-diff logic trivially unit-testable, but the fail/pass fixture mechanism across the Go/Python boundary is unspecified (F1); exceptions must cover gRPC-gateway + SCIM + WebAuthn + compliance families (Verified 81) |
| A8 | Embed check fails on file/embed drift | `check-embed` hash comparison | **Proposed, Partial** — check itself has no named tests (F8) |
| A9 | `make sdk-changelog` classifies add/rename/remove; rename/remove flags breaking | `cmd/sdkdiff` + sdk-surface policy quote | **Missing** — no test plan for sdkdiff (F11); no Makefile target exists today (Verified) |
| A10 | All existing gates pass | gates listed, nothing relaxed | **Verified for baseline** (Section 1); re-run at implementation |

## 3. Findings

No **Critical** or **High** findings: at design stage no verified exploit or
hard-gate violation exists, and every ground-truth claim of the design was
confirmed against code. The findings below are design-completeness gaps in the
test plan that will surface as untestable or silently-weak tests during
implementation.

### F1 — Medium: parity-test oracle is unspecified across the Go/Python boundary

The design asserts a "unit test that asserts `mountedEndpoints()` covers every
route `check-routes` reports as statically registered". But `check-routes`
emits only a PASS/FAIL line with counts — its route set is internal to
`checks/route_contract.py` (`runtime_routes()`, `contract_errors()`). A Go test
cannot consume it without either (a) shelling out to Python and parsing a new
machine-readable output, or (b) duplicating the checker's route list as a Go
constant — which would drift and prove nothing. The repo already has the
correct pattern: the checker compiles a `go run` helper to resolve route
constants (`route_contract.py:110-136`); the parity check should invert it — a
Python check that `go run`s a helper printing `mountedEndpoints()` from a
fully-optioned server and compares against the static set.

**Exact test to add**: `checks/test_route_contract.py::test_mounted_endpoints_parity`
(or a `check-routes --parity` mode): build a stock `Server` with every option
on, `Mount()`, print `mountedEndpoints()` via `go run` helper; assert set-equal
to the checker's `runtime_routes()` plus the two probe routes.
**Acceptance assertion**: parity holds on the current tree; a deliberately
mis-recorded `Group` prefix (fixture wrapper whose `Group` forgets the prefix)
makes the check fail.

### F2 — Medium: "no 404-ing op" acceptance conflicts with GatedRouter hot gating

`mountAdminSurface` always registers the `/api/v1/admin/*` group wrapped in
`core.NewGatedRouter` (`server_routes_admin.go:48-49`): gate off ⇒ every admin
route answers 404 **while remaining registered** (hot-reloadable, by design).
The recorder therefore projects admin ops that 404 whenever
`SetAdminAPIGateEnabled(false)` is active — the spec acceptance "Projection
contains no path/operation that returns 404 in this build" is unsatisfiable in
that state, and the design's failure-modes section does not address it.

**Recommendation**: scope the acceptance explicitly to *boot-time option state*
(never-mounted ops) and document gate-state as out of scope; registration-based
projection is the right call (a live-gate consult would make the projected set
flap between requests, breaking "deterministic per build config").
**Exact test to add**: `interfaces/sso` test — build server, mount docs UI,
disable admin gate at runtime, assert projected op set is unchanged (pins the
scoping decision).
**Acceptance assertion**: projected spec before and after
`SetAdminAPIGateEnabled(false)` is byte-identical.

### F3 — Medium: no named sso-layer option-toggle test

The headline acceptance (federation off ⇒ no `/fetch`-family op; on ⇒
reappears) has no named test at the composition layer. The design names only
apidocs unit tests (pure `project` function) plus the parity test; neither
proves option-state filtering through the real `WithAPIDocsUI` wiring.

**Exact test to add**: `interfaces/sso/export_test.go`-adjacent in-package test
`TestAPIDocsProjectionFollowsOptions`: build two servers differing in one
option (e.g. federation / v2alpha), call the spec handler, assert
presence/absence of the gated operation's `(method, path)` in the served JSON.
**Acceptance assertion**: with the option unset the served `paths` contains no
key for the gated op; with it set the op is present; both pass
`-race -count=1`.

### F4 — Medium: recorder `Group` accounting lacks direct unit tests

The design's own "what could break" section identifies Group prefix accounting
as the single place a route can be mis-recorded, then relies solely on the
parity test — which is itself unspecified (F1). The recorder needs direct unit
tests; parity is a safety net, not the primary defense.

**Exact tests to add**: `interfaces/sso` recorder unit tests — (1) nested
`Group("a").Group("b")` prefix concatenation; (2) admin-prefix application
(`/api/v1` + `/admin/...`); (3) custom-verb and colon paths
(`releases:current`, `/releases/:id:pin` — two of the Verified 81, both with
literal `:` beyond `{param}` normalization); (4) `{param}` (documented) vs
`:param` (recorded) equivalence via the checker's normalization rule; (5)
HEAD/OPTIONS keys left untouched; (6) `Use`/`ServeHTTP` verbatim delegation.
**Acceptance assertion**: each recorded tuple matches
`route_contract._normalize_openapi_path` applied to the documented op.

### F5 — Low: `buildinfo.Resolve("")` makes the "empty ⇒ keep spec" fallback dead in dev builds

`platform/buildinfo/buildinfo.go:31-45`: with no ldflags and no module version,
`Resolve("")` returns `"(devel)"` — never empty. In a plain `go build`, the
projected `info.version` therefore becomes `(devel)` in place of the documented
`0.1.0` (a visible behavior change in dev), and the design's fallback triggers
only in synthetic cases. This is a defensible choice but must be pinned, not
left implicit.
**Exact test to add**: apidocs unit test with `Version: "  "`-style empty and
with `"(devel)"` values; assert the chosen semantics (either `(devel)` is
projected verbatim, or the sso wiring maps it to empty ⇒ spec value).
**Acceptance assertion**: the dev-build projection behavior is deterministic
and documented in the test.

### F6 — Medium: Decision 3 assumes existing sdk-surface registry tests that do not exist

The design says "update schema + registry tests in the same change, or `make
ci` fails for an unrelated reason". **Verified**: there are no unit tests for
`ops/scripts/sdk_surface.py` (no `test_sdk_surface.py` in `checks/`), and
`validate_schema()` hard-requires `schema_version const 1` plus a top-level
`additionalProperties: false` schema. Adding `unmountedOperations` touches
schema, registry, `validate_schema`, and needs **new** tests — and every
exception operationId must also exist in `docs/openapi.yaml` or
`sdk-surface-check` fails (the checker already enforces
`op_id in openapi_ids`), which is a good invariant to keep.
**Exact tests to add**: `checks/test_sdk_surface.py` — (1) schema with
`unmountedOperations` validates; (2) exception operationId not in OpenAPI ⇒
FAIL; (3) exception lacking `{operationId, method, path, reason}` shape ⇒
FAIL (schema `required`).
**Acceptance assertion**: `cli.py sdk-surface check` passes with the 81-entry
inventory; a synthetic bad entry fails it.

### F7 — Low: recorder concurrency claim has no named test

The design claims `-race` cleanliness for concurrent `Server.Handle` + per-
request projection but names no test.
**Exact test to add**: `TestMountedRoutesConcurrentSnapshot` — N goroutines
registering via `Handle` while M goroutines call `mountedEndpoints()`; assert
each snapshot is a consistent RLock-atomic view (a route is present or absent,
never torn) and `go test -race ./interfaces/sso/ -run TestMountedRoutes -count=10`.

### F8 — Low: embed-consistency check itself has no test plan

`check-embed`'s real coverage is embed-target drift (wrong file, rename, CRLF
munging); the design documents its dirty-tree blind spot honestly, but the
check needs fixture-based unit tests.
**Exact tests to add**: `checks/test_embed_consistency.py` — fixture tree whose
embedded bytes differ from the committed file ⇒ FAIL; identical bytes ⇒ PASS;
missing embed target ⇒ FAIL with a clear message.
**Acceptance assertion**: `cli.py check-embed` exits non-zero on a touched copy
and zero on the current tree.

### F9 — Low: Decision-2 renderer tests under-enumerated

The design names only "scheme name + representative code" for the fixture
assertion. The high-risk behaviors are the degradation paths.
**Exact tests to add** (fixture spec in `apidocs_test.go`): (1) prose token
`client_id` in a response description never renders as a code
(`stableErrorCodes` filter); (2) unknown `security` scheme name renders as
`(undocumented scheme)` without failing; (3) nil/empty `Config.ErrorCodes` ⇒
catalog section absent, per-op fallback text `see error-codes catalog`
present; (4) the embedded `error-codes.md` bytes round-trip through
`template.JS` escaping (no `</script>` breakout — assert the raw markdown
renders and the page still contains the nonce attribute); (5) `ErrorResponse`
reachable only through a `$ref` chain (response → schema → allOf → `$ref`)
still yields codes.
**Acceptance assertion**: every assertion is on rendered HTML `textContent`,
never on `innerHTML` markup.

### F10 — Info: no E2E coverage of the viewer

The spec's "saved copy renders fully offline" and the no-store/bearer-gate
properties have no `test/` (`ssotest`) coverage, and `WithAPIDocsUI` is
currently exercised by zero tests at any layer.
**Exact test to add**: `test/e2e` case — `WithAPIDocsUI` + admin bearer ⇒
`GET /api/v1/admin/docs` and `/openapi.json` return 200 with `no-store`, valid
JSON, and a **sampled** set of projected paths (admin, oauth, option-gated
family) each answering non-404 with admin auth.
**Acceptance assertion**: sampled projected paths never 404; an unmounted
family's op is absent from the JSON.

### F11 — Info: sdkdiff has no test plan

The design wires `cmd/sdkdiff` as an advisory CI step but names no tests for
its only interesting logic: the canonical schema fingerprint.
**Exact tests to add**: (1) fingerprint ignores description/example/order
changes (cosmetic edit ⇒ not flagged); (2) type/properties/required change ⇒
flagged "review"; (3) operationId rename ⇒ "breaking per
ops/build/sdk-surface.json"; (4) missing git ref ⇒ clear error, exit 1.
Use two fixture YAML files, not git refs, for determinism.
**Acceptance assertion**: `make sdk-changelog OLD=<a> NEW=<b>` on two synthetic
snapshots emits exactly the expected classifications.

### F12 — Info: per-request determinism untested

Go's `encoding/json` sorts map keys, so byte-identical repeated projections
are achievable and worth pinning (it is the design's stated determinism claim
and the memoization future-optimization's correctness baseline).
**Exact test to add**: call the spec handler twice with identical server state;
assert byte-equal bodies.

## 4. Prioritized scenario list

Ordered by risk. "Proposed test" columns reference the findings above.

| # | Scenario | Path | Assertion |
|---|---|---|---|
| 1 | Option-gated op filtered out / reappears (federation, v2alpha, WASM) | Happy | F3 test; served JSON lacks/contains the gated op |
| 2 | Group-prefix accounting incl. nested groups + custom verbs | Boundary | F4 tests; recorded == normalized documented |
| 3 | Gate-off 404 routes stay projected, byte-identical | Boundary | F2 test |
| 4 | `project` error / nil `Mounted` / nil `ResolveIssuer` ⇒ unprojected spec, never 500 | Error | A3 test |
| 5 | Concurrent `Handle` + per-request projection | Race | F7 test, `-race -count=10` |
| 6 | Recorder wrap with embedder `WithRouter` custom Router (pre-registered routes, non-recording Group) | Boundary | parity test (F1) catches sub-router misses; document pre-registered routes as out of scope |
| 7 | `/token` auth family + `invalid_grant`/`invalid_client`; admin GET bearerAuth-only | Happy | A4/A6 fixture tests |
| 8 | Prose tokens never render as codes; unknown scheme degrades; nil catalog hides section | Error | F9 tests |
| 9 | `$ref`-chained ErrorResponse + cycle bound | Boundary | F9(5); reuse `renderSchema` depth bound |
| 10 | Reverse check: documented+unregistered+unexcepted ⇒ FAIL; excepted ⇒ PASS | Error | F1/A7; fixture tree + 81-entry triage |
| 11 | Embed drift (edited yaml vs stale embed; CRLF; renamed asset) | Error | F8 tests |
| 12 | sdkdiff cosmetic vs breaking classification; missing ref exit 1 | Error | F11 tests |
| 13 | Repeated projection byte-identical | Boundary | F12 test |
| 14 | Dev-build `(devel)` version semantics | Boundary | F5 test |
| 15 | Recovery: check-embed/go-run helper failure ⇒ clear non-zero, ci unaffected (advisory sdkdiff never gates) | Recovery | F8/F11; assert `make ci` failure mode is the failing check itself |

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

### Gaps

- **Python checker tests cannot run in this environment** (pytest missing —
  environment, not repo; `make ci` does not depend on `check-test`, verified
  Makefile:244). Add pytest to the dev environment before implementing
  Decision 3's Python-side tests.
- **No test covers `WithAPIDocsUI` at any layer today** (Verified) — the
  design must add the F3 sso-layer test, not only apidocs unit tests.
- **`check-routes` has no machine-readable route-set output** — required for
  the F1 parity oracle and for triage bootstrapping; extend it in the same
  change as Decision 1.
- **`make sdk-changelog` target does not exist** (Verified); sdkdiff has no
  test plan (F11).
- **`go test ./... -race` and `make ci` were not run this revision** —
  implementation-stage gates; baseline commands in Section 1 all pass.

### Flake risks

- The `go run` helper pattern (route_constant resolution today, parity and
  embed-hash helpers tomorrow) costs ~1–3 s and compiles from the working tree:
  keep helpers single-file, deterministic output, and covered by the existing
  tempdir pattern in `checks/test_route_contract.py`.
- Parity across the Go/Python boundary is the highest flake surface: prefer
  one `go run` helper that prints `mountedEndpoints()` (JSON, sorted) and
  compare set-wise, never order-wise.
- CRLF munging of `error-codes.md`/`openapi.yaml` on Windows would false-flag
  the embed check — hash the bytes with a documented expectation (or normalize
  line endings in the helper, and say so).

### Fixtures needed

1. Fixture OpenAPI spec with `security`, `securitySchemes` (bearer/DPoP/mTLS),
   `servers`, `examples`, `$ref`-chained `ErrorResponse`, and prose tokens in
   descriptions (F9, A6).
2. Two-fixture spec pair for sdkdiff (cosmetic vs breaking delta) (F11).
3. Temp-tree fixture for the reverse check (documented op, registered op,
   excepted op) (A7/F1).
4. Option-on/option-off server builder fixture in `interfaces/sso` (F3).
5. The triage artifact itself: the 81-entry `unmountedOperations` inventory
   with reasons — the concrete list is reproducible via the Section-1 harness
   and groups into gateway-served (admin CRUD), Handle-mounted (SCIM,
   WebAuthn, compliance, dr/status), and unmounted surfaces (`/branding`,
   `/mesh/ext-authz`); a human must review it (design states this correctly).

### Exit criteria for implementation

1. All Section-1 baseline commands pass on the implemented tree, plus
   `go test ./... -race` and `make ci`.
2. F1 parity check green on current tree and red on a seeded mis-accounting
   fixture.
3. F3 option-toggle test green; F2 scoping decision documented in the design
   and pinned by a test.
4. `cli.py sdk-surface check` green with the triaged 81-entry inventory;
   `check-embed` green and covered by fixture tests.
5. `make sdk-changelog` demoed on two commits with correct
   add/rename/remove/breaking classification (advisory, never a gate).
6. No gate relaxed, no exemption added, `server_routes.go` ≤ 500 lines and
   `interfaces/sso` still 60 files (all additions in
   `server_routes_admin.go`/`server_resource.go` per the design).
