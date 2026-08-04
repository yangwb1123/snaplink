# QA Review: interfaces/apidocs Direction 1 — deployment-aware OpenAPI projection

Reviewed artifact: `docs/auto/interfaces-apidocs-direction1-design.md`
(design stage; doc-only; no Go gates touched by the design itself). Advisory
only — no files modified, no releases approved.

Scope of this review: verify the design's evidence claims against the current
tree, trace the spec's acceptance checks (`interfaces-apidocs-direction1-spec.md`)
to concrete tests the design names, and identify untested failure paths,
regression risks, and test-design holes — including two material flaws the
design does not see: a silent downgrade of route-level gating semantics and an
acceptance criterion that the proposed mechanism cannot satisfy.

## 1. Test inventory and commands actually run for this revision

All commands ran against the working tree at this revision (no code changed by
this review).

| Command | Result | Evidence |
|---|---|---|
| `python cli.py check-routes` | **PASS** — 241 runtime routes, 322 documented operations | the design's 81-op gap = 322−241, measured |
| `go build ./... && go vet ./...` | **PASS** | mandatory gate |
| `go test -run 'TestMaintainability_\|TestArchitecture_' .` | **PASS** (0.128s) | mandatory gate |
| `go test ./interfaces/apidocs/ ./shared/core/ -run 'TestNew_\|TestGatedRouter'` | **PASS** (0.003s / 0.002s) | affected package + gating pins |
| `go test ./interfaces/sso/ -run 'TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404'` | **PASS** (0.005s) | the byte-identical-404 pin H1 threatens |
| `go test ./test/ -run TestE2E -count=1` | **PASS** (0.013s) | E2E gate, sampled |
| `ls interfaces/sso/*.go \| grep -v _test \| wc -l` | **60** | 60-file ceiling claim, measured |
| `wc -l` on placement files | 443 / 332 / 488 / 469 / 446 / 84 | design's placement table, measured |
| static greps / `sed` reads (router.go, route_contract.py, apidocs.go, sso.go, server_routes.go, server_health.go, server_setup.go, buildinfo.go, server_discovery.go, openapi.yaml, Makefile, engineering.yaml) | see findings | every evidence claim re-derived from source |

Not run this revision (implementation-stage gates): `go test ./... -race`,
`make ci`, full `go test ./test/ -v`. The design correctly lists these as
pre-handoff gates.

### Existing test inventory of the affected surface

- `interfaces/apidocs/apidocs_test.go` — 3 tests: parse+serve UI+spec
  (incl. `no-store`, `v1.2.3` in UI body), malformed-YAML fail-safe,
  duplicate-top-level-key last-wins. No projection tests exist yet.
- `shared/core/router_test.go:444` `TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404`
  and `:487` `TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak` —
  package-local pins of route-matching-level gating; they exercise
  `*StdRouter` directly and **cannot** see a regression introduced by an
  `interfaces/sso` wrapper.
- `interfaces/sso/feature_gate_hotreload_test.go:83`
  `TestSetAdminAPIGateEnabled_LiveToggleIsByteIdenticalTo404` — the full-server
  pin of the same property. It builds a **minimal** server (no
  `WithRequestID`, no tenant/geo stores), so even if `WithAPIDocsUI` were
  added to it, the handler-wrapping fallback would still produce a
  byte-identical 404 (no global middleware to leak a header). See H1.
- **Zero** tests exercise `WithAPIDocsUI` at any layer (grep of `test/`,
  `interfaces/sso/*_test.go`, `examples/`, `cmd/`). `cmd/sso-server` does not
  wire the option today. The served-docs surface is currently completely
  unpinned, so nothing existing protects the new served-doc contract.

## 2. Requirement-to-test matrix

Status: **Named** = the design names the test; **Partial** = named but
insufficient or mechanistically unable to pass; **Missing** = no test named.

| # | Spec acceptance (direction1-spec) | Design provision | Status / evidence |
|---|---|---|---|
| D1-a | Unit: mounted kept, unmounted dropped, `{id}`↔`:id` normalization, whole-path drop, `Mounted==nil` fallback | `project_test.go` (filtering, `{id}`↔`:id`, whole-path drop, nil/empty fallbacks) | **Named** — `apidocs.go` is 84 lines; `project` + `normalizePath` fit. One gap: normalization tests must include paths whose recorded form is produced by `buildPath`-style cleaning (see M4). |
| D1-b | Integration: `WithAPIDocsUI` w/o `WithAPIVersionPreview`/`WithSetupWizardEnabled` ⇒ no `/api/v2alpha/version`, `/api/v1/setup`, `/api/v1/setup/status`; with options ⇒ reappear | `test/` integration (option-pair servers) | **Partial — broken for setup**: v2alpha is registration-gated (`server_health.go:291-296`, `if !s.apiV2AlphaPreview { return }`) so the recorder can drop it; setup routes are registered **unconditionally** (`server_routes.go:150-151`) and gated **inside the handlers** (`server_setup.go:64,74`, JSON 404 documented at `docs/openapi.yaml:196-224`). A registration recorder can never remove them. See H2. |
| D1-c | Parity: `mountedEndpoints()` covers every `check-routes` route (241 + probes); recorder cannot silently miss a registration | `--dump-routes` flag + `testdata/mounted_routes.txt` + `mounted_routes_parity_test.go` (⊇) + `make ci` drift guard | **Named** — mechanism sound (additive flag; `run()` unchanged; fixture exempt via `engineering.yaml` `exempt_dirs: testdata`; `make ci` includes `route-contract`, Makefile:244). Two gaps: the "fully-optioned" server is an unenumerated ~155-conditional option matrix (M5); the fixture is a **lower bound**, not "the exact set" as the failure-modes section claims (L9). |
| D1-d | `check-routes` still PASS unchanged; maintainability/architecture clean; `apidocs -race` clean | gate sequence 1→2→3 | **Named** — verified: `--dump-routes` does not alter `run()`; `make ci` and the manual gate list match AGENTS.md. |
| D2-a | Unit: fake resolver rewrites `servers`; nil resolver ⇒ documented list | `project_test.go` (`servers` rewrite, nil/empty fallbacks) | **Named** |
| D2-b | Integration: `Host: sso.internal.example`, no `WithIssuer` ⇒ `servers[0].url == "http://sso.internal.example"`; `WithIssuer` ⇒ issuer | `test/` integration | **Named** — verified mechanism: `resolveIssuer` (`server_discovery.go:251-256`) → `requestBaseURL` → `middleware.BaseURL` (`server_federation.go:40`); fail-safe on `""`/`DefaultIssuer` is defensive (the closure never returns the sentinel). |
| D2-c | Viewer HTML contains rewritten `servers` in inlined spec | UI test asserting inlined `servers` | **Named** — the design extends the UI assertion; note `handleUI` must inline the per-request projected JSON (currently inlines `specJSON` captured at `New`, template.go:28-40) — the design states this. |
| D2-d | Trusted-edge inherited, not reimplemented; no apidocs tests | explicit "adds no tests" | **Named** — correct scope boundary. |
| D3-a | Unit: `Version:"1.4.2"` rewrites `info.version`; empty keeps spec value | `project_test.go` (version rewrite, `(devel)` fallback) | **Named** — note `buildinfo.Resolve("")` never returns empty on a plain build (returns `(devel)`), so the "empty ⇒ keep" fallback is dead in dev and only `(devel)`-suppression fires (prior review F5; design pins the `(devel)` case explicitly). |
| D3-b | Integration: served `info.version == buildinfo.Resolve("")`'s ver, not `0.1.0` | integration, asserted against the package | **Named** — asserted against `buildinfo.Resolve("")` directly, so version bumps cannot rot it. Good. |
| D3-c | Viewer title/version shows injected version (extend `v1.2.3` assertion) | `specTitleVersion` picks up projected version at `New` | **Named** — verified `template.go:60` renders `v{{.Version}}`. |
| Parity guard | fixture cannot silently drift from checker | regeneration + diff in `make ci` | **Named** — fits `route-contract`/`docs-validate` (Makefile:178,181,244). |
| Gate-state scope | (spec silent; prior review F2) | design's "what could break" lists GatedRouter groups as always-registered but never decides their served-doc fate | **Missing** — see H3. |
| Race | concurrent `Server.Handle` + snapshot | "RWMutex makes the snapshot linearizable; `-race` clean by construction" | **Partial** — claim without a named concurrent test; prior review F7 carried over. See M7. |
| E2E | viewer bearer-gated, no-store, offline-save | none named | **Missing** — prior review F10 carried over. See CI gaps. |
| Determinism | "Deterministic per option set" (D1 acceptance) | sorted snapshot | **Partial** — no byte-identical double-serve assertion; prior review F12. See CI gaps. |

## 3. Findings

### H1 — High: the recorder wrapper silently downgrades route-matching-level gating to handler-level gating for every GatedRouter group

**Evidence (Verified).** `mountAdminSurface` (`server_routes_admin.go:48-49`),
`mountFederationEndpoints` (`server_federation.go:196-197`), `mountClusterEndpoints`
(`server_health.go:70`, CAEP), `mountUnauthenticatedSelfServiceRoutes`
(`server_me.go:320`), `mountSelfServiceCredentials` (`server_me.go:357`),
`mountBrandingEndpoint` (`server_me.go:434`), `mountCIBAEndpoint`
(`server_routes.go:239`), `mountUserInfo` (`server_userinfo.go:33`), and
`mountAdminTokenExchangeChainRoutes` (`accessors_threat.go:201`) — 9 sites —
wrap the router in `core.NewGatedRouter`. `GatedRouter.register` dispatches to
`GatedRegistrar.RegisterGated` **only if the inner router implements
`GatedRegistrar`** (`router.go:423-430`); otherwise it falls back to
handler-wrapping (`GateHandler`). The design's recorder "embeds `core.Router`"
(the interface, `router.go:43-52`), whose method set excludes `RegisterGated`
— so a `recordingRouter` is **not** a `GatedRegistrar`, and every one of the 9
gated groups silently falls back to handler-wrapping the moment
`WithAPIDocsUI` is applied (the wrap in `mountMiddleware` makes `s.router` a
recordingRouter before every gated group registers).

**Impact.** `GatedRouter`'s documented guarantee — gated-off routes are
"byte-identical to a route that was never registered", with global
`Use()`-registered middlewares skipped before the gate is even consulted
(`router.go:354-376`) — is lost for the admin, federation, CAEP, self-service,
branding, CIBA, and OIDC groups. With the gate off, requests now run the
global middleware chain registered by `mountMiddleware` (`server_routes.go:108-141`:
Tracing when `WithRequestID`, Tenant, Geo, Region) before answering 404:
`X-Request-Id`/trace headers and tenant/geo/region audit side effects on
gated-off requests — an oracle distinguishing "gated off" from "never
mounted", plus audit noise on every gated-off admin probe. This directly
violates the design's headline claim "No wire/security-contract change".
The existing pins cannot catch it: `shared/core/router_test.go:444,487` are
package-local; `feature_gate_hotreload_test.go:83` builds a minimal server
with **no** global middlewares, where even the degraded path is byte-identical
(no middleware to leak a header).

**Recommendation (required before implementation).** The recorder must
preserve `GatedRegistrar`: embed `*core.StdRouter` concretely (or implement
`RegisterGated(method, path, handler, live)` recording `(method, path)` and
delegating with `live` forwarded). Add this to the design's failure-modes and
budget tables (see L10).

**Exact test to add.** `interfaces/sso` in-package:
`TestAPIDocsRecorder_PreservesRouteLevelGating` — build a server with
`WithAPIDocsUI()`, `WithRequestID()`, `WithFeatureGates(...{AdminAPI: true})`;
record a baseline 404 for a never-mounted path; `SetAdminAPIGateEnabled(false)`;
GET `/api/v1/admin/endpoints`; assert status, body, and **headers**
(notably absence of `X-Request-Id`) byte-identical to baseline; re-enable and
assert reachability. Second test: `TestRecordingRouter_ImplementsGatedRegistrar`
— `core.NewGatedRouter(recorder, live).GET(...)`; assert `live=false` request
skips a `Use()`-registered middleware on the wrapped router.

**Acceptance assertion.** With the gate off, the gated-off response is
byte-identical (headers included) to the never-mounted baseline under
`go test ./interfaces/sso/ -race -run TestAPIDocsRecorder -count=10`.

### H2 — High: Decision-1's setup-wizard acceptance is unsatisfiable with a registration recorder

**Evidence (Verified).** `mountCoreOAuthOIDC` registers
`GET /api/v1/setup/status` and `POST /api/v1/setup` **unconditionally**
(`server_routes.go:150-151`); the wizard gate lives in the handlers
(`server_setup.go:44,64,74`: `if !s.setupWizardOn() { 404 JSON }`), and the
JSON 404 is itself the documented wire contract
(`docs/openapi.yaml:196-224`: "Only active when `setup_wizard.enabled`; 404
`not_found` otherwise"). The recorder records what Mount registers — both
setup ops are always recorded — so the spec acceptance "server with
`WithAPIDocsUI` but without `WithSetupWizardEnabled` ⇒ no `/api/v1/setup`,
`/api/v1/setup/status` operations" **cannot pass** through the proposed
mechanism. The spec's premise ("operations for unmounted-in-this-deployment
features", evidence citing openapi.yaml:196/224) is factually wrong for
setup: these routes are never unmounted; they are handler-gated. The design
inherits the premise unexamined ("every optional mount is a nil-field or bool
guard in `Mount()`" is not true for setup).

**Impact.** The served doc will keep advertising two operations that return
404 whenever the wizard option is off — the exact phantom the feature exists
to eliminate — and the integration test, as specified, will fail on arrival
or be silently weakened (e.g. by dropping the setup assertion).

**Recommendation (required).** Keep setup registration untouched (moving the
gate to Mount would change the documented 404 JSON body to a router-native
404 — a wire-contract change AGENTS.md forbids). Instead, the `Mounted`
closure in `buildAPIDocsProjection` must subtract the handler-gated-disabled
ops, driven by the **same server state the handlers read**
(`s.setupWizardOn()`), so handler gate and projection cannot drift. State
this in the design's storage-model section.

**Exact test to add.** Integration (as the spec intends): server with
`WithAPIDocsUI`, no `WithSetupWizardEnabled` ⇒ served `/openapi.json`
contains no `/api/v1/setup` or `/api/v1/setup/status`; with the option ⇒ both
reappear. Plus a coupling test: flipping `WithSetupWizardEnabled` changes
handler 404s **and** the projection together (assert both in one test so a
future refactor cannot split them).

**Acceptance assertion.** Without the option, `paths` in the served document
contains neither setup key and `GET /api/v1/setup/status` answers 404; with
the option, both keys are present and the endpoint answers 200-shaped.

### H3 — Medium: GatedRouter gate-state ops remain advertised while gated off — scope is never decided

**Evidence (Verified).** All 9 GatedRouter groups register their routes
regardless of gate state by design (gate is a live toggle; `router.go:376-400`).
The recorder therefore records branding, CAEP, CIBA, OIDC userinfo,
federation, and self-service ops whether or not their gate is live; the served
doc advertises them while they 404. The design's "what could break" section
does not decide this (the prior review's F2 asked for exactly this scoping;
the new design is silent).

**Impact.** For hot-reloadable gates (`SetAdminAPIGateEnabled` etc.), the
served doc can advertise 404-ing operations in a live deployment — a partial
return of the phantom the feature removes, and a "deployment inventory" claim
that is only true for boot-time option state.

**Recommendation.** Scope explicitly in the design: projection is
*registration-faithful, gate-state-static* (a live-gate consult would make the
document flap between requests, breaking "deterministic per option set").
Document that gate-off ops remain listed while a gate is toggled off; the
admin gate is self-consistent (docs endpoints are inside the gated group, so
the whole viewer is unreachable when it is off).

**Exact test to add.** `TestAPIDocsProjection_UnchangedByLiveGateToggle` —
server with docs UI + admin gate on; capture served JSON; toggle admin gate
off and on; assert the served document is byte-identical across the toggle.

**Acceptance assertion.** Projected spec before and after
`SetAdminAPIGateEnabled(false)` is byte-identical (pins the scoping decision
so it cannot drift into either extreme).

### M4 — Medium: recorder path normalization must mirror `buildPath`, not raw concatenation

**Evidence (Verified).** `StdRouter.RegisterGated` stores
`r.prefix + r.buildPath(path)` (`router.go:229-236`); `buildPath` collapses
`""` and `"/"` to `""` and strips a leading slash. The design records
`r.prefix + path` and `child prefix = parent prefix + group prefix` —
diverging when a group prefix or path argument is `""`/`"/"` or carries a
trailing slash (e.g. `Group("/api/v1/")` → registered `/api/v1/...` but
recorded `/api/v1//...`). The mismatch silently drops those routes from the
served doc (route lives, operation absent) — the phantom-in-reverse the
feature exists to prevent.

**Impact.** Correctness of the served inventory for any mount that passes
empty or slash-normalizable path fragments; today's tree may not hit the case,
but the wrapper is a new contract that must be exact (the design claims byte
equality with the checker's rule).

**Recommendation.** Specify: the recorder records `parentPrefix +
buildPath(path)` for registrars and `parentPrefix + buildPath(groupPrefix)`
for `Group` — i.e. it reuses the identical normalization the inner router
applies, so recorded and registered strings are equal by construction.

**Exact tests to add.** Recorder unit tests: (1) `Group("/api/v1/")` child
registers `/clients` ⇒ recorded `/api/v1/clients`; (2) `Group("/api/v1").GET("/", h)` ⇒
recorded `/api/v1` (not `/api/v1/`); (3) `GET("", h)` at root ⇒ recorded `/`;
(4) three-level nesting with mixed trailing slashes.

**Acceptance assertion.** For every registration, the recorded `(METHOD,
path)` equals the string `StdRouter` actually serves (can be asserted by
mirroring `buildPath` in the test).

### M5 — Medium: the parity test's "fully-optioned" server is an unenumerated option matrix

**Evidence (Verified).** Mount helpers contain ~155 `if s.*` guards (counted
per file: server_routes.go 23, server_routes_admin.go 33, server_me.go 15,
accessors_threat.go 15, server_health.go 13, sso_selfservice.go 13,
server_admin_handlers.go 10, ...); each positive condition must be wired in
the parity server (clientStore, rebacStore, federationEntity + subordinate
flag, auditor + auditAPI, cryptoInventory, credentialScheduler,
protectedResourceMetadata, ...). The design names no option list.

**Impact.** The ⊇ check fails loudly when an option is missing (good — that
is the tripwire), but implementation cost and ongoing maintenance are real:
every new option-gated mount forces a parity-test edit, and the constructor
must be built and reviewed like production wiring. Silent weakening is not
possible (fail-loud), so this is a cost finding, not a correctness one.

**Recommendation.** The design must enumerate the option set (or point at the
existing "fully-optioned" test constructor if one exists — none was found in
`interfaces/sso`), and add a rule: a new option-gated mount extends the parity
server's option list in the same change.

**Exact test to add.** None beyond the parity test; add the enumeration to the
parity test's doc comment as a checklist.

**Acceptance assertion.** `mountedEndpoints() ⊇ fixture` passes with the
enumerated option set; removing one option from the constructor makes the test
fail with a diff listing exactly the missing routes.

### M6 — Medium: the late-option degrade does not guarantee "never a half-filtered document"

**Evidence.** The design says: if `WithAPIDocsUI` is applied after `Mount()`,
"snapshot is empty, projection falls back verbatim ... never a wrong filtered
doc". But the wrap-after-Mount path records **future** registrations only; if
the embedder then calls `Server.Handle` (`server_routes.go:64`, which requires
Mount first), the snapshot is non-empty, and the projection filters
documented ops down to the post-wrap set — dropping ops for live pre-wrap
routes. Half-filtered, exactly what the design claims impossible.

**Impact.** Edge case (options are normally applied in `New`'s loop,
`sso.go:82`), but the design's stated fail-safe contract is wrong, and the
wrongness is silent.

**Recommendation.** When the option detects it is being applied to an
already-mounted server, pass `Mounted: nil` (verbatim) instead of wrapping.
This makes the degrade airtight and matches the documented claim.

**Exact test to add.** `TestWithAPIDocsUI_AppliedAfterMount_DisablesFiltering`
— call `opt(srv)` after `Mount()` (option functions are public), then `Handle`
a documented path; assert the served document is the unprojected spec
(verbatim), not partially filtered.

**Acceptance assertion.** Post-Mount option application yields a served
document byte-identical to the no-option projection.

### M7 — Medium: no named concurrent registration/snapshot race test

**Evidence.** The design claims "-race clean by construction" and lists
"post-Mount `Handle`" among recorder tests, but no test runs concurrent
`Handle` + `snapshot()` under `-race` (prior review F7 carried over).

**Exact test to add.** `TestRecordingRouter_ConcurrentHandleAndSnapshot` —
N goroutines registering via `Server.Handle`, M goroutines calling
`mountedEndpoints()`; assert every snapshot is a consistent RLock-atomic view
(a route fully present or fully absent, sorted); run
`go test ./interfaces/sso/ -race -run TestRecordingRouter -count=10`.

**Acceptance assertion.** No data race; each snapshot is internally
consistent and sorted.

### L8 — Low: D3's "the two can never disagree" is overstated for `-X main.version`

**Evidence (Verified).** The startup banner prints `buildinfo.Write(...,
version)` where `version` is `main.version`, a **separate** ldflags target
(`cmd/sso-server/main.go:65-67,131`); the option resolves
`buildinfo.Resolve("")`, which reads `platform/buildinfo.Version`
(`buildinfo.go:25-26,31-46`). The standard pipeline sets
`-X .../buildinfo.Version` (only usage found: `checks/test_modules.py:180`),
in which case they agree; a pipeline injecting only `main.version` makes the
banner and `info.version` disagree, contradicting "exactly one version truth
per binary".

**Recommendation.** Keep D3 as designed (both read buildinfo by default);
note the `main.version`-only scenario in the failure-modes section and pin the
agreement for the standard case: the D3-b integration assertion already
compares against `buildinfo.Resolve("")` — add one line asserting it equals
the value `buildinfo.Write` would render for the same profile.

### L9 — Low: "the parity test pins the exact set" overclaims — the fixture is a lower bound

**Evidence (Verified).** The checker's `ROUTE_RECEIVERS` is
`{s.router, api, gr, ssf, selfServiceGR}` (`route_contract.py:21`); routes
registered through inline GatedRouter chains — e.g.
`core.NewGatedRouter(s.router, s.brandingGateOn).GET(...)`
(`server_me.go:434`) and `...s.cibaGateOn).POST(...)` (`server_routes.go:239`)
— are captured with receiver `s.cibaGateOn`/`s.brandingGateOn`, which is not
in the set, so they are **absent** from the checker's 241. The recorder sees
them (they flow through the wrapper). The fixture can therefore never be the
exact set; ⊇ is the right assertion, and extra recorder entries are harmless
(the projection keeps only documented∩mounted).

**Recommendation.** Reword the failure-modes claim to "lower bound pinned by
the fixture; over-recording is possible and harmless by construction".

### L10 — Low: budget math omits the H1 fix

**Evidence.** `server_health.go` is 443 lines (57 headroom); the design
allocates "recorder type + `snapshot()` (~55)". The H1 fix (a `RegisterGated`
override with `live` forwarding, plus doc comments) adds ~8-12 lines,
consuming most of the headroom; the fallback homes (`sso_wiring.go` +54) are
documented, so this is a warning, not a blocker.

**Recommendation.** Update the placement table to include the `RegisterGated`
override and state the first-move fallback explicitly in the same table.

### Info — citation drift and minor inaccuracies (no action required, all verified substance intact)

- `shared/core/router.go:288` for `Group` — actual definition `router.go:236-243`;
  the semantic claim (prefix accumulation, shared route table) is correct.
- `checks/route_contract.py:162-163` for the `{param}` rule — `TEMPLATE_PARAM`
  is defined at line 23; 162-163 is its usage in `_normalize_openapi_path`.
  Rule identical; `OUT_OF_ROUTER_ROUTES` at 42-46 verified.
- Spec's "241 + probes" — the 241 already includes `{GET,/livez}`,`{GET,/readyz}`
  (`runtime_routes` seeds `OUT_OF_ROUTER_ROUTES`); the design's probe-consts
  addition is still required (both probes are documented, openapi.yaml:3219,3238,
  so they would otherwise be dropped from the served doc).
- "including `cmd/sso-server`" as a wiring embedding — `cmd/sso-server` does
  not apply `WithAPIDocsUI` today (grep-verified); the ordering claim holds
  for any embedder that does.
- D2's `DefaultIssuer` sentinel check is dead-defensive: `resolveIssuer`
  never returns the sentinel (it falls through to `requestBaseURL`). Harmless;
  keep as belt-and-braces.

## 4. Prioritized scenario list

Ordered by risk; each scenario maps to at least one finding or acceptance check.

1. **Gating semantics with the docs option on** (H1): admin gate off ⇒
   gated-off response byte-identical to never-mounted **including headers**,
   with `WithRequestID` + tenant wired; gate re-enable restores reachability.
2. **Setup option state** (H2): no `WithSetupWizardEnabled` ⇒ setup ops absent
   from served doc and handler 404s; with option ⇒ present and 200; the two
   assertions in one test (coupling).
3. **v2alpha option state** (D1-b): no `WithAPIVersionPreview` ⇒
   `/api/v2alpha/version` absent; with ⇒ present.
4. **Gate-state staticness** (H3): live admin-gate toggle leaves the served
   document byte-identical.
5. **Parity** (D1-c, M5): full-optioned `mountedEndpoints() ⊇` fixture;
   deliberate recorder miss (broken `Group` prefix) fails the test.
6. **Path normalization** (M4): empty/slash-normalized paths and group
   prefixes record exactly what `StdRouter` serves.
7. **Issuer rewrite** (D2): Host-derived base; `WithIssuer` override;
   nil resolver; untrusted `X-Forwarded-Proto` does not win (inherited
   middleware behavior, no new tests).
8. **Version rewrite** (D3): injected version; `(devel)` and empty fallbacks;
   viewer title carries injected version; equality with `buildinfo.Resolve("")`.
9. **Fail-safe projection** (D1-a/D2/D3): nil/empty `Projection` fields ⇒
   byte-identical to today's verbatim output; malformed `servers`/`info` keys
   skipped without panic; `Mounted` empty list ⇒ verbatim.
10. **Late option application** (M6): after-`Mount` option ⇒ verbatim, never
    partial.
11. **Concurrency** (M7): concurrent `Handle` + `snapshot()` under `-race`;
    dedupe under concurrency; sorted output.
12. **Post-Mount dynamic mounts** (D1): `Server.Handle` after startup ⇒ new op
    appears in the served doc on the next request.
13. **E2E viewer** (F10 carry): admin bearer ⇒ `/docs` and `/openapi.json`
    200 with `no-store`, valid JSON, sampled projected ops never 404, unmounted
    family absent; offline-save still renders.
14. **Determinism** (F12 carry): two identical requests ⇒ byte-equal bodies
    (sorted snapshot + stable JSON).

## 5. CI/manual-suite gaps, flake risks, fixtures, exit criteria

### CI gaps

- **No E2E coverage of the viewer** (prior F10, still missing from the
  design's test list): add a `test/` (`ssotest`) case exercising
  `WithAPIDocsUI` with admin bearer — 200 + `no-store` on both routes, valid
  JSON, sampled projected ops answer non-404, one unmounted family absent.
- **No determinism pin** (prior F12): extend the integration test to serve
  twice and assert byte-equal bodies.
- **No race test named** (M7): `-race -count=10` on the recorder
  concurrency test must be in the gate list, not just `go test ./... -race`.
- **Parity drift guard placement**: the design says `make ci`; the natural
  home is the `route-contract` target (Makefile:181,244) or `docs-validate`
  (Makefile:178). Specify which, so the guard is not silently dropped.
- **Checker coupling is now a de-facto interface**: the fixture encodes
  `ROUTE_RECEIVERS`, `ADMIN_PREFIX`, `PRIVATE_PATHS`, and
  `OUT_OF_ROUTER_ROUTES`; any checker change must regenerate the fixture in
  the same change (design says this — make it a checklist item in the checker's
  own doc comment).

### Flake risks

- Low: the parity test is deterministic (static source analysis + a
  construction-time server, no timing); the fixture diff in `make ci` is
  deterministic. No timing-sensitive assertions were found in the proposed
  tests. The main flake vector would be a parity test that starts the server
  and races `Mount()` with requests — the design correctly does not propose
  that (Mount completes before `Handler()` returns).
- One trap: the parity test's "fully-optioned" server must be built with
  `WithFeatureGates(...{AdminAPI: ...})` and any gate-affecting options only
  insofar as they affect **registration**; GatedRouter registers regardless,
  so gate state must not leak into the assertion (⊇ is registration-set only).

### Fixtures needed

- `interfaces/sso/testdata/mounted_routes.txt` — generated by
  `checks/route_contract.py --dump-routes` (241 entries incl. probes);
  exempt from Go gates (`engineering.yaml` `exempt_dirs: testdata`); exempt
  from the 60-file ceiling (not a `.go` file). Regeneration command must be
  documented in the fixture header comment.
- No other fixtures required; `project_test.go` can use inline spec YAML in
  the existing `testSpec` style (`apidocs_test.go:12-21`).

### Exit criteria

1. H1 and H2 resolved in the design (or explicitly re-scoped with the
   maintainer) **before** implementation; the design's "no wire/security
   change" claim is false as written.
2. All matrix rows green: D1-a/b/c/d, D2-a/b/c/d, D3-a/b/c, parity guard,
   gate-state scoping test, race test.
3. Gates as specified in the design: `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `python cli.py check-routes` PASS with the **unchanged** 241/322 line;
   `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`
   including the fixture drift guard.
4. Placement budgets re-verified after implementation (files at 443/332/488
   lines have 57/168/12 lines of headroom; the recorder + `RegisterGated`
   override must fit in `server_health.go`, with the documented fallback
   homes exercised only if the file overruns).
5. The served-doc semantics shift (spec-reference → deployment-inventory) is
   called out in the `WithAPIDocsUI` doc comment, as the design proposes.
