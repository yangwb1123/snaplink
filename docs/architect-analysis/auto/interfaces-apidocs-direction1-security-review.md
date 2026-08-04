# Security Review — interfaces/apidocs, Direction 1: Deployment-aware OpenAPI projection

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/interfaces-apidocs-direction1-design.md` + spec
`docs/auto/interfaces-apidocs-direction1-spec.md`. This review is advisory
analysis only; it changes no code.

Scope of the reviewed change: a per-request projection of the served OpenAPI
document (`GET /api/v1/admin/docs` UI + `GET /api/v1/admin/docs/openapi.json`)
that (D1) filters documented operations to the routes this build's router
actually registered, (D2) rewrites `servers` to the resolved issuer, (D3)
rewrites `info.version` to `buildinfo.Resolve("")`. All three run inside the
two existing admin-gated handlers; the static `docs/openapi.yaml` is never
mutated.

Evidence standard per `ai-dev/prompts/README.md`: claims below are labeled
**Verified** (I ran/read it for this review), **Partial**, **Missing**,
**Proposed**, or **Unknown**. Checks that ran for this review revision:
`python3 cli.py check-routes` (PASS, 241/322), source reads of
`shared/core/router.go`, `interfaces/sso/{server_routes.go,
server_routes_admin.go, server_discovery.go, server_federation.go,
sso_selfservice.go, sso.go, sso_wiring.go, accessors_feature_gates.go,
server_health.go, server_setup.go}`, `interfaces/apidocs/{apidocs.go,
template.go, apidocs_test.go}`, `interfaces/middleware/request_url.go`,
`platform/buildinfo/buildinfo.go`, `checks/route_contract.py`,
`architecture_layer_test.go`, `maintainability_budget_test.go`,
`engineering.yaml`, `cmd/sso-server/{build_app.go, build_http.go}`,
`docs/openapi.yaml`. I did not run the full `make ci` suite.

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Notes |
|---|---|
| Served OpenAPI doc (UI + JSON), admin-gated | Read-only; embeds the full endpoint + schema inventory of the build (Verified: `mountAPIDocsUI` hangs off the admin group, `server_routes.go:260-270`; `AdminMiddleware.HTTPMiddleware` wraps the whole handler stack in `cmd/sso-server/build_http.go:86-89`, `isAdminProtectedPath` per-path, GET = `admin:read`) |
| `docs.OpenAPISpec` embedded bytes | Source of truth, never mutated by the design (Verified: `project` builds a fresh tree; `apidocs.go` parses with `yaml.AllowDuplicateMapKey`) |
| Recorder state (`map[METHOD+path]` + RWMutex) | New in-memory state per server process; write path = every router registration, read path = per-request snapshot |
| Viewer HTML page | Inlines the projected spec as JSON inside `<script>`; offline-save property; `X-Frame-Options: DENY`, no-store (Verified: `template.go:28-42`) |
| Deployment identity strings | Resolved issuer (request-derived or `WithIssuer`), build version (`buildinfo.Resolve("")`) — both admin-visible only |

### Trust boundaries

1. **Untrusted internet → edge proxy → server.** `middleware.BaseURL`
   honors `X-Forwarded-Proto`/`X-Forwarded-Host` only when
   `ForwardedHeadersTrusted` (Verified: `request_url.go:22-53`). The design
   reuses this extractor via `resolveIssuer` → `requestBaseURL`
   (Verified: `server_discovery.go:251-256`, `server_federation.go:40`);
   no new trust surface.
2. **Admin bearer holder → admin-gated handlers.** The only consumers of
   the projected doc. Gate unchanged (Verified: `build_http.go:86-89`).
3. **Embedder code → `Server.Handle` / options.** Registration-time
   writes into the recorder; option ordering (`New` applies options before
   `Mount`, Verified: `sso.go` opts loop) is the design's precondition.
4. **Operator config → `WithIssuer` / feature gates / trusted-proxies.**
   These shape the issuer string and live-gate reachability; they are
   trusted inputs.

### Attacker capabilities (assumed, adversarial)

- Unauthenticated remote attacker on the public surface (no admin token).
- Admin-scope holder (`admin:read`) with hostile intent (the minimum
  capability to see the doc at all).
- Network position able to set the direct `Host` header only in
  deployments running the documented-unsafe "legacy first-hop trust"
  configuration (`ForwardedHeadersTrusted` false at an untrusted edge) —
  pre-existing exposure, same Host already lands in `iss` today.
- NOT assumed: trusted-proxy compromise, operator config compromise,
  ability to rewrite an admin's browser Host.

### Entry points

- `GET /api/v1/admin/docs` (UI) and `GET /api/v1/admin/docs/openapi.json`
  (JSON): both AdminMiddleware-gated, no-store (Verified: `apidocs.go:79-84`,
  `template.go:31-38`). These are the only handlers the projection touches.
- `Server.Handle(method, path, handler)`: post-Mount registrations that the
  recorder must observe (Verified: routes through `s.router` wrappers,
  `server_routes.go:60-88`).
- `python cli.py check-routes` and the new `--dump-routes` flag: build-time
  contract surface; the parity fixture is generated from it.

---

## 2. Findings

Sorted by severity. No Critical or High findings: the access-control,
trust, and oracle boundaries of the design are sound (Section 4). The two
Medium findings are implementation-invariant guards on genuinely new data
flows; the rest are accuracy/test gaps.

### F2 — Medium — New request-derived data flow into the viewer HTML; the XSS-inert invariant must be carried and pinned by test

- **Evidence (Verified):** Today the page inlines a static `specJSON`
  produced once by `json.Marshal` at `New` time (`apidocs.go:46-48`) — HTML
  escaping is ON by default — and assigned as `template.JS(specJSON)`
  (`template.go:22-24, 39`), which html/template does NOT re-escape. No
  request-derived data reaches the page today. The design (pipeline steps
  2-3) adds a per-request `servers` rewrite with the value of
  `resolveIssuer(ctx)`, which is request-derived when `WithIssuer` is unset:
  `scheme://Host` from `middleware.BaseURL` (`request_url.go:22-53`) — the
  direct `Host` header when `ForwardedHeadersTrusted` is false.
- **Exploit preconditions:** (a) the implementation marshals the projected
  doc for the UI path with HTML escaping disabled (`SetEscapeHTML(false)` or
  a raw-`[]byte` shortcut), and (b) an attacker controls a value reaching an
  admin's browser — via a forged `Host` header in the documented-unsafe
  untrusted-edge deployment, or a trusted-but-compromised edge's
  `X-Forwarded-Host` (a compromise that already defeats the whole trust
  model, so this is defense-in-depth, not a new hole).
- **Exploit steps (conditional):** attacker sends
  `Host: id.example/</script><script>…</script>` on a request the admin's
  tooling or saved-page flow renders; the inlined `SPEC` blob breaks out of
  the `<script>` element if step (a) holds.
- **Impact:** script execution in an admin-gated page — theft of
  admin-scope material if the operator stores bearer tokens in
  page-accessible storage, or admin-browser compromise. Not reachable with
  the escaping preserved.
- **Remediation (required invariant):** the UI path must marshal the
  projected doc with `json.Marshal` default escaping (equivalently:
  Encoder without `SetEscapeHTML(false)`), exactly as today; state this in
  the `project`/`New` doc, and add a unit test that feeds a hostile
  resolver value (`https://x/</script><script>alert(1)</script>`) and
  asserts the UI body contains no raw `</script>` sequence from the value.
- **Regression test:** `interfaces/apidocs/project_test.go` — UI-handler
  test with `Projection{ResolveIssuer: func(...) string { return hostile }}`
  asserting the rendered HTML is inert (no `</script>` from input, no
  `alert(1)` in the raw body outside the escaped form).
- Note: the version string is separately safe — `specTitleVersion` output
  flows through html/template text contexts (`template.go:60-61, 66`),
  which escape `<`, `>`, `&`. Only the inlined JSON blob carries the new
  request-derived value.

### F1 — Medium — The projected doc records registration, not reachability: live-gated routes that answer 404 are still advertised

- **Evidence (Verified):** Several surfaces are registered UNCONDITIONALLY
  at Mount and gated LIVE by `core.GatedRouter`, flippable at runtime via
  `Set*GateEnabled` (config/reload SIGHUP): the whole `/api/v1/admin/*`
  group (`server_routes_admin.go:41-49`), OIDC `/userinfo` +
  `/end_session` (`accessors_feature_gates.go:43-53`), CIBA
  (`server_routes.go:231-239`), CAEP receiver (`server_health.go:70`),
  federation group (`server_federation.go:197`), self-service group
  (`server_me.go:320-357`), branding (`server_me.go:434`). The recorder
  wraps `s.router` and sees every registration through `GatedRouter`'s
  non-`GatedRegistrar` fallback (Verified: `router.go:344-356` — the
  fallback calls `g.inner.GET(...)`, which the recorder observes; the
  design's recorder must NOT implement `GatedRegistrar` without also
  recording in `RegisterGated`, or this silently flips). The design's own
  problem statement ("operations return 404 while the viewer advertises
  them", spec Decision 1) therefore remains true for the entire
  hot-reloadable gate axis: e.g. `SetSelfServiceGateEnabled(false)` makes
  every `/me/*` route answer 404 while the admin-gated doc still lists
  them as mounted.
- **Exploit preconditions:** production deployment that toggles a feature
  gate off via config reload while the admin docs remain up (admin gate
  off ⇒ docs unreachable, so the admin axis is self-consistent; the
  self-service/federation/CAEP/CIBA/branding/OIDC axes are not).
- **Impact:** advisory accuracy gap — an operator or tooling consumer
  treats the doc as deployment inventory and acts on 404-ing operations.
  No access-control impact: the doc is admin-gated and the routes fail
  closed to 404. The checker has the same registration semantics, so the
  parity fixture will not surface this.
- **Remediation (choose and pin one):** (a) define "mounted" as
  "registered" (checker-consistent), state it explicitly in
  `WithAPIDocsUI`'s doc, and add an integration test pinning that
  `SetSelfServiceGateEnabled(false)` leaves the ops documented; or (b)
  consult the live gate flags (`*GateOn()`) at snapshot time so the doc
  reflects reachability — feasible because the projection is per-request,
  but it changes the parity fixture semantics (the fixture is
  registration-based) and adds a per-request cost. Recommend (a) for this
  change; (b) is a follow-up.
- **Regression test:** `test/` integration — build with `WithAPIDocsUI`,
  flip `SetSelfServiceGateEnabled(false)`, assert the served doc still
  contains `/me` operations (pinning semantics (a)).

### F3 — Low — Deployment version and edition label become visible to every admin:read holder

- **Evidence (Verified):** `info.version` is a static `0.1.0`
  (`docs/openapi.yaml:34`); D3 replaces it with `buildinfo.Resolve("")`,
  which for profile builds yields the decorated public identity
  (`FormatEditionVersion`, `buildinfo.go:47-60`, e.g. `snaplink-1.4.2.full`).
  The viewer `<title>`/header carries it too. The docs routes are
  admin-gated (Verified: Section 1).
- **Impact:** an admin-scope holder can fingerprint the exact build for
  CVE targeting — but that holder already sees the complete endpoint +
  schema inventory, and the binary version is deterministic from behavior;
  the startup banner prints the same value. No unauthenticated
  disclosure, no new boundary crossed.
- **Remediation:** none required; optionally note in the `WithAPIDocsUI`
  doc that the served doc discloses the exact binary version. The design
  correctly takes only `ver` and never `revision`/`dirty` (Verified:
  `Resolve` returns them separately; the design's `ver, _, _` drops them)
  — keep that.

### F4 — Low — Parity test coverage depends on replicating every mount precondition; a missed precondition silently weakens the assertion

- **Evidence (Verified):** the fixture is the checker's static union (241 +
  probes), which includes routes gated on stores/options at Mount:
  `rebacStore`/`rebacEngine`, `tenantStore`, `usageAggregator`,
  `netAPI`+`netStore`, `auditAPI`+`auditor`, crypto inventory, credential
  scheduler, CAEP receiver, federation sub-features, CIBA store, etc.
  (`server_routes_admin.go:60-110`, `mountCoreOAuthOIDC`,
  `server_health.go`, `server_federation.go`). The parity test asserts
  `mountedEndpoints() ⊇ fixture`, so the "fully-optioned" server must wire
  every precondition AND turn every live gate on; any missed one makes the
  ⊇ direction pass vacuously for that block and a recorder bug there
  invisible.
- **Impact:** test coverage gap only; no production risk.
- **Remediation:** enumerate the precondition list in the parity test's doc
  (mirroring `mountAdminSurface`'s own list), and make the fixture
  regeneration diff part of `make ci` (the design already proposes the
  drift guard — keep it mandatory, not best-effort).
- **Regression test:** the parity test itself; additionally a
  fail-loud assertion that the fixture's count equals the checker's
  reported 241 + 2 probes.

### F5 — Low — Recorder invariants that must be pinned by test (else silent doc drift)

- **Evidence (Verified):** (a) `GatedRouter.register` uses
  `RegisterGated` when inner implements `GatedRegistrar` (`router.go:344-
  348`); the recording router must NOT implement that capability without
  recording, or every gated registration (the entire admin group!) bypasses
  the recorder. Today `*recordingRouter` embedding `core.Router` does not
  implement it — the fallback records — but nothing but a test pins this.
  (b) `StdRouter.Group` normalizes prefixes via `buildPath` (empty and
  `/` collapse, `router.go:283-293, 320-329`); the recorder's prefix rule
  must mirror it byte-for-byte or nested-group registrations drift from the
  checker's `ADMIN_PREFIX` arithmetic. (c) `buildProbeMux` serves
  `/livez`/`/readyz` outside the router (Verified: `server_routes.go:357`);
  the probe consts appended to the snapshot must stay in sync with
  `OUT_OF_ROUTER_ROUTES` (`route_contract.py:42-46`).
- **Impact:** each violation produces the phantom-in-reverse (real route
  dropped from the doc) or a doc that disagrees with the checker; the
  design's own failure-mode list flags (a) but not the GatedRegistrar
  non-implementation pin.
- **Remediation:** unit tests: (a) `core.NewGatedRouter(recorder,
  …).GET(...)` ⇒ endpoint present in snapshot; (b) two- and three-level
  groups incl. `Group("")` and `Group("/")`; (c) probe consts present.

### F6 — Low — Unsupported late-option ordering degrades to the full verbatim doc with no observable signal

- **Evidence (Verified):** options are applied only in `New`
  (`sso.go` opts loop), which precedes `Mount()` in every supported
  embedding including `cmd/sso-server`; the late-wrap defensive path is
  therefore unreachable through the public API today (Proposed: no path
  exists to apply an option post-`New`). If it ever triggers, the design's
  nil/empty semantics serve the FULL 322-op doc — the exact
  phantom-advertising bug the feature exists to fix — with only a doc
  comment as the degrade note.
- **Impact:** none today; a silent regression trap if option application
  ever moves.
- **Remediation:** emit a one-line `s.logger` warning in the late-wrap
  path (server already carries `spi.Logger`), or return `nil` from
  `Mounted` so the projection is skipped with a distinguishable state.

---

## 3. Abuse-case table

| Abuse case | Reachable? | Path / evidence | Outcome | Mitigation |
|---|---|---|---|---|
| Identity spoofing | No | No authentication logic touched; both routes stay behind AdminMiddleware `admin:read` (Verified: `build_http.go:86-89`) | — | n/a |
| Token/session replay | No | Projection introduces no token handling; no-store on both handlers preserved (Verified: `apidocs.go:81`, `template.go:34`) | — | n/a |
| Saved-page replay staleness | Yes (benign) | Offline-saved doc is a point-in-time snapshot; per-request projection means issuer/mounted-set drift after host changes or re-Mount | Advisory doc goes stale; no auth impact | Note in `WithAPIDocsUI` doc (design already flags Postman re-import) |
| Cross-tenant access | No | Doc is server-global; TenantMiddleware enriches but does not gate; admin scope is server-level; no tenant input in projection | — | n/a |
| Proxy/header forgery → poisoned `servers` | Conditional (pre-existing) | `middleware.BaseURL` honors XFF only from trusted peers (`request_url.go:22-53`); untrusted-edge legacy config reflects direct Host into `servers` — same Host already lands in `iss` today (Verified: `server_discovery.go:251-256`) | Doc shows wrong base; no privilege change | Existing trusted-proxies guidance (AGENTS.md); design adds no trust surface |
| Proxy/header forgery → HTML injection | Conditional | F2: new request-derived string into inlined `<script>`; inert while `json.Marshal` HTML escaping is preserved | XSS in admin-gated page | F2 required invariant + test |
| Resource exhaustion | No (bounded) | Per-request projection O(322 ops) + sorted snapshot O(241 log 241); recorder map bounded by static registrations + embedder `Handle` calls; admin-gated + rate-limited (Verified: `build_http.go` admin rate limit wiring) | — | n/a |
| Sensitive-data leakage (unauth) | No | Filtering only removes operations; both handlers admin-gated; no cache (no-store) | — | n/a |
| Sensitive-data leakage (admin) | Yes (intended) | Real version + edition label (F3), resolved issuer, exact mounted inventory | Deployment fingerprint for admin-scope holders | F3 note; design correctly drops VCS revision/dirty |
| Doc-vs-reality mismatch (phantom ops) | Partial | D1 fixes mount-time option gaps (Verified: `mountAPIVersionPreview`/`setupWizardOn`/nil-field guards); live-gated surfaces still advertise 404-ing ops (F1) | Misleading inventory | F1 semantics pin |
| Doc-vs-reality mismatch (missing ops) | Guarded | Recorder blind spots: `RegisterGated`, prefix normalization, probe consts (F5); parity test ⊇ fixture | Silent doc drift | F5 tests + F4 fixture discipline |
| Error-oracle / enumeration | No | No error paths changed; projection cannot 500 (defensive non-map skips; design failure-mode section) | — | n/a |

---

## 4. Positive controls verified

1. **Admin gate unchanged and load-bearing.** Both routes hang off the
   `/api/v1/admin/` group (Verified: `mountAdminSurface` →
   `mountAPIDocsUI(api)`, `server_routes_admin.go:48-61`,
   `server_routes.go:260-270`); AdminMiddleware wraps the whole handler
   stack in the stock binary (`build_http.go:86-89`), GET = `admin:read`.
   The projection runs inside these handlers and can only remove
   operations and rewrite two strings.
2. **No-store discipline preserved.** `handleSpec` (`apidocs.go:79-84`)
   and `handleUI` (`template.go:31-38`) both set `Cache-Control:
   no-store`; the design's per-request host-dependent document is never
   cached by intermediaries. `X-Frame-Options: DENY` preserved.
3. **No new trust surface.** Issuer resolution reuses the canonical
   `middleware.BaseURL` extractor (`request_url.go:22-53`); `interfaces/
   apidocs` contains zero URL/trust logic (Proposed — enforced by keeping
   `ResolveIssuer` a closure). Trusted-edge behavior is inherited, not
   reimplemented.
4. **Oracle-safe errors and fail-open/fail-closed lists untouched.**
   No error path, credential endpoint, or revocation/refresh logic is
   touched by any of the three decisions (Verified: diff scope is
   renderer + recorder + one option).
5. **Fail-safe projection semantics.** nil/empty projection inputs degrade
   to today's verbatim output; `project` skips non-map nodes; parse
   failure still unmounts the feature (`apidocs.go:36-44`).
6. **No mutation of the source of truth.** `project` builds a fresh root
   and shares only never-mutated subtrees; `docs/openapi.yaml` stays
   byte-identical; `cmd/gensdk` reads the embedded spec directly
   (Verified: `cmd/gensdk/main.go:63`), unaffected.
7. **Checker contract unchanged.** `python3 cli.py check-routes` still
   prints PASS (241 runtime routes, 322 documented operations) for this
   revision; `--dump-routes` is additive (Verified: `route_contract.py`
   has no such flag today; the design's parity fixture inherits the
   checker's `{param}` → `:param` equality, which today's one-directional
   check already proves consistent in the documented→mounted direction).
8. **Concurrency.** RWMutex-guarded recorder; snapshot is linearizable;
   per-request read under RLock; no lock held across serving. Map writes
   bounded by registrations.
9. **Architecture/budget claims verified.** `interfaces/sso` top level:
   exactly 60 non-test `.go` files (+2 in `servercache/`, not counted by
   the ceiling); line counts match the placement table (server_health.go
   443, server_routes.go 488, server_routes_admin.go 332,
   sso_selfservice.go 469, sso_wiring.go 446); `platform` (1) below
   `interfaces` (5) in `architecture_layer_test.go:41-42`, so the
   `buildinfo` import is legal with no exemption.

## Residual risks

1. F2 escaping invariant lives in implementation, not in the design
   signature — must be carried into `project`'s doc and pinned by test.
2. F1 registration-vs-reachability semantics must be chosen and pinned;
   otherwise the feature's own problem statement stays half-true.
3. Checker coupling: any `route_contract.py` change (new receiver, new
   method, new path syntax) requires fixture regeneration in the same
   change; the drift guard makes this fail-loud (design-flagged).
4. Non-semver edition labels (`snaplink-1.4.2.full`) in `info.version`
   for strict semver consumers — design-flagged; accepted consequence.
5. Served-doc semantics shift from "spec reference" to "deployment
   inventory" — design-flagged; must be stated in the `WithAPIDocsUI` doc
   comment, including the ~81-op structural gap.
6. `Unknown`: whether `make ci`'s docs gate already has a regeneration
   hook the parity drift guard can ride; implementation must confirm.

## Prioritized validation plan

1. (With implementation, unit) `project_test.go`: hostile issuer value
   through the UI handler ⇒ inert HTML (F2); `servers` rewrite, nil
   resolver fallback, `{id}` ↔ `:id`, whole-path drop, `(devel)` fallback.
2. (Unit) Recorder: nested/empty group prefixes, dedupe, sorted snapshot,
   GatedRouter-registered routes present, probes present (F5).
3. (Build-time) `--dump-routes` + fixture + parity test; then
   `python3 cli.py check-routes` must print the unchanged PASS line.
4. (Integration, `test/` package) `Host: sso.internal.example` without
   `WithIssuer` ⇒ `servers[0].url == "http://sso.internal.example"`;
   `WithIssuer("https://id.example")` ⇒ that value; v2alpha/setup ops
   appear/disappear with the options; gate-off pin for F1.
5. (Gates) `go build ./... && go vet ./...`;
   `go test -run 'TestMaintainability_|TestArchitecture_' .`;
   `go test ./interfaces/apidocs/ -race`; `go test ./... -race`;
   `go test ./test/ -run TestE2E -v`; `make ci` with the fixture drift
   guard active.
