# Design — interfaces/apidocs, Direction 1: Deployment-aware (runtime-faithful) OpenAPI projection

Input: `docs/auto/interfaces-apidocs-direction1-spec.md`. This design covers
the three decisions of that spec — mounted-route filtering (Decision 1),
issuer-faithful `servers` (Decision 2), buildinfo-faithful `info.version`
(Decision 3) — through one shared projection seam. For each decision:
API surface, storage model, failure modes, and what could break the design.

Design constraints carried from the spec (AGENTS.md §2, §4):

- `interfaces/apidocs` never imports `interfaces/sso`; it stays a pure
  renderer fed by closures/values from the composition side.
- `interfaces/sso` is at its 60-file ceiling (measured: exactly 60 non-test
  `.go` files): zero new files there; placement below is budget-checked
  against the measured 500-line/file gate.
- No new module dependencies. Projection reuses the embedded
  `docs.OpenAPISpec`, the checker's `{param}` → `:param` rule
  (`checks/route_contract.py:162-163`), `s.resolveIssuer`
  (`server_discovery.go:251`), and `platform/buildinfo.Resolve`
  (`buildinfo.go:31`). Layer ranks (architecture_layer_test.go:41:
  platform=1, interfaces=5) make `interfaces/sso → platform/buildinfo` a
  downward import — no `layerExemptions` entry needed.
- Fail-safe: nil/empty projection inputs degrade to today's verbatim
  behavior, never to an error page or a 500.
- No wire/security-contract change: both routes stay AdminMiddleware-gated
  (`admin:read`), `Cache-Control: no-store` preserved, saved-page-offline
  preserved (the projected spec is what gets inlined), `docs/openapi.yaml`
  never mutated and remains the sole source of truth.

The shared seam, defined once here and consumed by all three decisions:

```go
// interfaces/apidocs
type Endpoint struct {
    Method string // canonical uppercase: GET/POST/PUT/PATCH/DELETE
    Path   string // as registered, e.g. "/api/v1/oauth/token"
}

type Projection struct {
    // Mounted, when non-nil, filters documented operations to the set it
    // returns. nil or empty means no filtering (today's verbatim behavior).
    Mounted func() []Endpoint
    // ResolveIssuer, when non-nil, rewrites servers to the single value it
    // returns. nil, "", or the core.DefaultIssuer sentinel keeps the
    // documented servers list.
    ResolveIssuer func(core.HandlerContext) string
    // Version, when non-empty and not "(devel)", rewrites info.version.
    Version string
}

func New(specYAML []byte, projection Projection) (ui, spec core.HandlerFunc, err error)
```

`New`'s signature grows by one parameter (its only production caller is
`WithAPIDocsUI`, server_routes.go:316; the package is not part of the public
SDK surface, so no compatibility obligation). The zero value of `Projection`
is the fail-safe: all three behaviors fall back to today's output.

Per-request pipeline inside both handlers (spec unchanged at
`apidocs.go:79-84`):

1. `snapshot := projection.Mounted()` if non-nil (nil ⇒ skip filtering).
2. `issuer := projection.ResolveIssuer(ctx)` if non-nil (nil ⇒ skip rewrite).
3. `doc' = project(doc, snapshot, issuer, projection.Version)` — pure,
   builds a fresh tree; `ctx.JSON(200, doc')`; UI inlines `doc'` instead of
   the parse-time `specJSON`.

---

## Decision 1 — Mounted-route projection: serve only what this build registers

### API surface

`interfaces/apidocs` (all in `apidocs.go`, 84 → ~170 lines, far under the
file gate):

- `Endpoint` and `Projection.Mounted` as defined above.
- Pure, unexported `project(doc any, mounted []Endpoint, issuer string,
  version string) any`, plus the filtering helper `normalizePath` that
  applies exactly the checker's rule: `TEMPLATE_PARAM` equivalent
  (`\{([^}]+)\}` → `:$1`, route_contract.py:162-163) to documented path
  keys before set-membership. Mounted paths are already in `:param` form,
  so membership is byte equality after normalization — the same equality
  the checker's `missing_route_errors` already enforces one-directionally
  today, which is why it passes; the inverse direction inherits that
  exactness for free.
- Filtering semantics per the spec: keep a path-item's GET/POST/PUT/PATCH/
  DELETE operation iff its normalized `(METHOD, path)` is in the mounted
  set; leave all non-HTTP-method keys (`head`, `options`, `parameters`,
  `x-*`, `$ref`, `summary`) untouched; drop a whole path when zero of the
  five method keys remain. Non-map path items are skipped defensively.

`interfaces/sso` (zero new files; placement and measured headroom below):

- `type recordingRouter` — a `core.Router` wrapper. Overrides the five
  method registrars to record `(strings.ToUpper(method), r.prefix+path)`
  before delegating; overrides `Group` to return a child `recordingRouter`
  whose prefix is `r.prefix + groupPrefix`, mirroring `StdRouter.Group`'s
  own prefix accumulation (`shared/core/router.go:288-293`); `Use` and
  `ServeHTTP` delegate (embedding `core.Router` provides them). All
  registrations in `Mount()` flow through wrappers because `Mount` hands
  only wrapper-derived routers (`api`, `gr`, `ssf`, `selfServiceGR`) to the
  mount helpers, and `s.router` itself is the wrapper.
- Server field `apiDocsRecorder *recordingRouter`, beside
  `apiDocsUIHandler`/`apiDocsSpecHandler` in the `sso_selfservice.go:258`
  field block.
- Wiring in `mountMiddleware` (server_routes.go:108): immediately after
  `s.router = NewStdRouter()`, `if s.apiDocsRecorder != nil {
  s.router = s.apiDocsRecorder.wrap(s.router) }`. `Mount()` calls
  `mountMiddleware` first, so every later registration is observed.
  `WithAPIDocsUI` is an option applied in `New` (sso.go:82-83), which is
  always before `Mount()` in every supported embedding (including
  `cmd/sso-server`); the recorder therefore exists before the wrap point.
  Defensive: if the option is applied after `Mount()` (unsupported
  ordering), `WithAPIDocsUI` wraps the existing router immediately —
  nothing is recorded retroactively, snapshot is empty, projection falls
  back verbatim (documented degrade, never a wrong filtered doc).
- `snapshot()`: read-locked, sorted `[]apidocs.Endpoint`, plus the
  out-of-router probe consts `{GET, /livez}`, `{GET, /readyz}` appended
  (mirror of `OUT_OF_ROUTER_ROUTES`, route_contract.py:42-46), since
  `buildProbeMux` registers them outside the SSO router.
- Accessor `func (s *Server) mountedEndpoints() []apidocs.Endpoint`
  (unexported; beside the recorder field), consumed by `WithAPIDocsUI`'s
  `Mounted` closure and by the in-package parity test.
- `WithAPIDocsUI` gains one call: `apidocs.New(docs.OpenAPISpec,
  buildAPIDocsProjection(s))`; the helper lives where the headroom is (see
  placement).

Placement budget (measured `wc -l`, gate = 500/file, no new files allowed):

| File | Lines | Headroom | Holds |
|---|---|---|---|
| `server_health.go` | 443 | 57 | `recordingRouter` type + `snapshot()` (~55) |
| `sso_selfservice.go` | 469 | 31 | field `apiDocsRecorder` + `mountedEndpoints()` (~6) |
| `server_routes_admin.go` | 332 | 168 | `buildAPIDocsProjection` helper (~14) |
| `server_routes.go` | 488 | 12 | `mountMiddleware` wrap (~3) + `WithAPIDocsUI` one-liner (~2) |

`server_health.go` is the spec's "server_health.go area wiring" and has
just enough room for the recorder type; `server_routes_admin.go` absorbs
the projection helper (admin-surface wiring; keeps the 12-line-headroom
`server_routes.go` to a two-line diff). If any file overruns during
implementation, the helper is the first thing to move (any file with
headroom); the recorder type itself must stay whole.

### Storage model

- One in-memory set per server process: `map[string]struct{}` keyed by
  `METHOD + " " + path`, guarded by `sync.RWMutex`, owned by
  `recordingRouter` and shared with all its group children (children write
  the same map through the same lock — a child's `Group` creates a new
  `recordingRouter` but reuses the parent's `routes`/`mu`, exactly as
  `StdRouter.Group` shares the underlying route table).
- Writes: every route registration during `Mount()` and every post-Mount
  `Server.Handle` call. Reads: one `snapshot()` per request, sorted, under
  the read lock. No cache of the projected document — projection is O(paths)
  (~322 operations, trivial) and per-request projection is what makes
  dynamic mounts and per-request issuer rewrites correct without cache
  invalidation.
- Lifetime: server lifetime; no persistence; no cross-replica concern (the
  projected doc is advisory documentation, not state).
- The embedded `docs.OpenAPISpec` is never mutated: `project` builds a new
  root map, a new `paths` map, and shares untouched operation subtrees by
  reference (JSON marshaling never mutates, so sharing is safe).

### Failure modes

- Recorder misses a registration (group-prefix accounting bug, a mount
  helper registering on an unwrapped router, a future receiver name):
  the operation is dropped from the served doc while the route lives —
  the exact phantom-in-reverse the feature exists to prevent. Guarded by
  the parity test below; the wrap point (single, inside `mountMiddleware`)
  and the group-prefix rule (mirror of `StdRouter.Group`) are the two
  places to audit.
- `Group` prefix double-accumulation: `StdRouter.Group` already prepends
  its own prefix; the wrapper records `parentPrefix + path` from the path
  argument it is handed, never re-reading the inner router's state, so the
  only rule is "child prefix = parent prefix + group prefix". Unit tests
  cover two- and three-level nesting (`/api/v1` → `/admin` → relative).
- Option applied after `Mount()`: empty snapshot ⇒ verbatim fallback
  (spec-mandated nil/empty semantics), logged as a degrade in the option
  doc comment; never a half-filtered document.
- Duplicate documented path keys (the `AllowDuplicateMapKey` case,
  apidocs.go:38-45): parse already last-wins; `project` sees one entry.
- A path item that is not a map, or operations that are not maps: skipped,
  never panics; `project` cannot 500 (the handler's only error source
  remains `json.Marshal`, which exists today and is unreachable for a
  validated spec).
- Race with concurrent `Server.Handle` during a request snapshot: RWMutex
  makes the snapshot linearizable; `-race` clean by construction.
- `Mounted` returning a snapshot containing paths never registered (a
  future bug in the recorder): cannot happen — the recorder is the only
  writer — and the parity test pins the exact set.

### What could break this design

- **The structural 81-operation gap is now visible**: the checker reports
  241 runtime routes vs 322 documented operations even with every option
  mounted — ~81 documented operations are registered by no mount in any
  build. After this change they disappear from the served spec in every
  deployment. That is the spec's intent (the admin gate exists for
  precision), but it changes the served document from "spec reference" to
  "deployment inventory": anyone treating the served JSON as the complete
  forward-looking API reference loses those operations. `docs/openapi.yaml`
  remains the full reference, and `cmd/gensdk` reads the embedded spec, so
  no tooling breaks — but this must be called out in the `WithAPIDocsUI`
  doc comment.
- **Checker drift**: if `checks/route_contract.py` gains a new receiver in
  `ROUTE_RECEIVERS` or a new method, its route set changes; the parity
  fixture must regenerate or the parity test fails loudly (fail-loud is the
  guard, not a break).
- **Router backend swap**: `core.Router` advertises the `GatedRegistrar`
  adapter capability; if `NewStdRouter` is ever replaced by a gin/echo
  adapter with different `Group` semantics, the wrapper's prefix rule must
  be re-verified. Parity test is the tripwire.
- **New path-param syntax** (e.g. `*wildcard`): the checker's
  `TEMPLATE_PARAM` and the wrapper's recording both need to evolve
  together; both `check-routes` and the parity test fail loudly on drift.
- **`RegisterGated` registrations**: `RegisterGated` is on `*StdRouter`,
  not on the `core.Router` interface; if a future mount registers through
  it directly on the unwrapped router, the recorder is blind. Rule: keep
  route registration on the `Router` interface. (The checker ignores
  `RegisterGated` too, so today's 241 are unaffected.)
- **`Server.Handle` embedder paths** are recorded but never documented, so
  they never appear — unchanged behavior (the checker already excludes
  dynamic paths via `DYNAMIC_EXPRESSIONS`).

Parity test design (acceptance: "recorder cannot silently miss a
registration"): additive `--dump-routes` flag on `checks/route_contract.py`
(no change to the PASS/FAIL path or the one-directional contract) that
prints the `runtime_routes` set; a generator writes
`interfaces/sso/testdata/mounted_routes.txt` (testdata is exempt from the
Go gates and is not a `.go` file, so the 60-file ceiling is untouched).
`interfaces/sso/mounted_routes_parity_test.go` (test files do not count
toward the ceiling) builds a fully-optioned server, `Mount()`s it, and
asserts `mountedEndpoints()` ⊇ the fixture. A drift guard regenerates the
fixture and diffs it during `make ci` (docs gate), so checker and recorder
cannot diverge silently.

---

## Decision 2 — Issuer-faithful `servers`: replace placeholder hosts with the deployment's resolved issuer

### API surface

- `Projection.ResolveIssuer func(core.HandlerContext) string` (above).
  `interfaces/apidocs` contains zero URL/trust logic: it only places the
  string the closure returns, and its only validity checks are the fail-safe
  ones below.
- `project` rewrites the `servers` key of the fresh root map to a single
  entry `[]any{map[string]any{"url": issuer}}`, replacing the documented
  two-entry list (`docs/openapi.yaml:52-60`) per the spec ("one canonical
  base, not two guesses"). `description` keys of the documented entries are
  dropped — the deployment truth replaces the dev/prod guesses.
- `WithAPIDocsUI` wires the closure to `s.resolveIssuer`
  (server_discovery.go:251-256) inside `buildAPIDocsProjection` — the
  identical function stamping RFC 9207 `iss` in authorization responses, so
  the documented base can never drift from the issued issuer. `requestBaseURL`
  (server_federation.go:40) → `middleware.BaseURL` (request_url.go:22)
  supplies the trusted-edge behavior; it is inherited, not reimplemented.
- Fail-safe checks, in `interfaces/apidocs` (which already imports
  `shared/core`): resolver nil, or result `""`, or result equal to
  `core.DefaultIssuer` ⇒ keep the documented `servers` list verbatim. If
  the documented spec has no `servers` key at all, leave it absent (do not
  invent a block — verbatim wins).

### Storage model

- Stateless. The closure is the entire state: a bound method value captured
  at option-application time, evaluated per request against the current
  request (so trusted-proxy headers, TLS, and `Host` are read live).
  No caching: the rewrite is a single map write per request.
- The value's contract is inherited from `resolveIssuer`: configured
  `WithIssuer` (when not the `DefaultIssuer` sentinel) wins; otherwise the
  trusted-peer-aware request base. Both paths are already canonicalized
  (no trailing slash — the same invariant RFC 9207 relies on), so `project`
  performs no string surgery.

### Failure modes

- Resolver nil / empty / sentinel ⇒ documented list (fail-safe, above).
- `servers` present but not a list (hand-edited spec) ⇒ skip rewrite, leave
  verbatim — never panic.
- Untrusted `X-Forwarded-Proto`/`X-Forwarded-Host` spoofing: unchanged
  threat model. `ForwardedHeadersTrusted` (request_url.go:33) already gates
  forwarded headers; a peer outside the trusted CIDRs gets the direct
  `Host`/TLS-derived base. `interfaces/apidocs` adds no trust surface and no
  tests (the middleware's own tests cover the extractor — spec-mandated).
- Admin gate and no-store: the rewrite happens inside the handlers, after
  AdminMiddleware; `Cache-Control: no-store` set in `handleSpec`
  (apidocs.go:79) is untouched, so a host-dependent document is never
  cached anywhere.
- Resolver panics: out of scope by contract — the closure is a bound
  method of the same server; no new error path exists.

### What could break this design

- **`servers` semantics for consumers**: the rewrite collapses two
  documented entries (Local dev + Production) into one. A Postman/Insomnia
  collection imported from a local dev box now carries the local host —
  correct for that deployment, but the "Production deployment" hint is gone
  from the served doc. That is the spec's intent (deployment truth over
  guesses); the full two-entry list remains in `docs/openapi.yaml` and in
  offline copies of the static file.
- **Issuer-vs-base divergence in unusual topologies**: if an operator
  configures `WithIssuer` to a value that differs from the externally
  reachable admin host (e.g. issuer `https://id.example` while the docs
  portal is reached as `https://console.example`), the served doc points at
  the issuer, not the console. This is deliberate (RFC 9207 consistency is
  the stronger invariant: the documented base always equals the issued
  `iss`), but the integration acceptance must assert exactly this behavior
  so the choice is pinned by test, not by accident.
- **First-import caching**: Postman/Insomnia cache an imported collection;
  after a host change, users must re-import. Operational note for the
  `WithAPIDocsUI` doc, not a break.
- **Trailing-slash issuers from future config validation changes**: if a
  future `WithIssuer` value with a trailing slash were accepted, the
  documented `servers[0].url` would carry it (today `resolveIssuer` never
  emits one). Mitigation is upstream in issuer validation, not here — this
  design deliberately adds no URL normalization in apidocs.

---

## Decision 3 — Buildinfo-faithful `info.version`: replace static `0.1.0` with the binary's real version

### API surface

- `Projection.Version string` (above).
- `WithAPIDocsUI` resolves it once, at option-application time, via
  `buildinfo.Resolve("")` (buildinfo.go:31-35) — `ver, _, _ :=
  buildinfo.Resolve("")` — inside `buildAPIDocsProjection`. This mirrors
  `cmd/sso-server/main.go:26,131`, which already resolves and prints the
  same value at startup; the docs portal can no longer disagree with the
  startup banner. The import lands in `interfaces/sso` (downward,
  platform=1 < interfaces=5, no exemption; `interfaces/apidocs` stays free
  of platform imports — it only places the string).
- `project` rewrites `info.version` to `Projection.Version` when it is
  non-empty and not `"(devel)"` (spec's fail-safe: an unresolved local
  build keeps the documented `0.1.0` rather than advertising `(devel)` —
  a non-semver label that OpenAPI consumers would misparse). Edition
  profiles' decorated labels (`snaplink-… .full` etc. from
  `FormatEditionVersion`, buildinfo.go:47-60) ARE injected: they are real
  public identities, and `info.version` is a free-form string per OpenAPI.
- Viewer propagation needs no template change: `New` computes
  `specTitleVersion` (apidocs.go:60) from the projected document, so the
  `<title>`/header (template.go:60) automatically carries the injected
  version. Implementation note: title/version are static per process
  (Version is resolved once; `servers` does not affect them), so they can
  be computed once at `New` time from the version-projected doc rather than
  per request; only the inlined spec JSON is projected per request.

### Storage model

- One immutable string per process, resolved once at option application.
  No per-request work, no locking, no persistence. The value is identical
  to the one `cmd/sso-server` prints at startup, so there is exactly one
  version truth per binary.

### Failure modes

- Empty or `"(devel)"` ⇒ documented `0.1.0` (fail-safe, above). Note the
  accepted consequence: a dirty local checkout still shows `0.1.0` — the
  spec deliberately prefers a stable placeholder over `(devel)` in a
  machine-readable field.
- `info` absent / not a map / `version` not a string (hand-edited spec) ⇒
  skip the rewrite; `specTitleVersion` already tolerates malformed `info`
  (apidocs.go:63-75) — the fail-safe philosophy is unchanged.
- `buildinfo.Resolve` cannot fail (it reads embedded build info, never
  errors); no new error path.

### What could break this design

- **Stale ldflags in release pipelines**: a release built with a
  forgotten/injected `-X` value advertises that value — wrong but
  deterministic, and identical to what the startup banner prints, so the
  two can never disagree. Fixing the label is a release-pipeline concern,
  out of scope here.
- **Semver-dependent consumers**: if a downstream tool parses
  `info.version` strictly (e.g. `semver.Parse`), edition-profile labels
  like `snaplink-1.4.2.full` are non-semver. Today those consumers already
  see `0.1.0` (valid semver), so this is a real behavior change for profile
  builds only. Mitigation option if it bites: emit the base version without
  the edition decoration; decided against in this design because the
  decorated label is the binary's true public identity and `info.version`
  is specified as a free-form string — flag for review if a consumer
  objects.
- **Fixture/test coupling**: the integration acceptance asserts
  `info.version == buildinfo.Resolve("")`'s ver for the test binary
  (asserted against the package directly, not a literal), so the test
  survives version bumps by construction.

---

## Cross-cutting: sequencing, gates, and whole-design risks

Sequencing (spec-mandated): 1 → 2 → 3, one change, all through `project`.
The three decisions share the same per-request pipeline and the same new
test files:

- `interfaces/apidocs/apidocs_test.go` extensions + new `project_test.go`
  (filtering, `{id}` ↔ `:id` parity with the checker's rule, whole-path
  drop, nil/empty fallbacks, `servers` rewrite, `info.version` rewrite,
  `(devel)` fallback; extend the existing `v1.2.3` UI assertion to
  projected input — apidocs_test.go:44-46).
- `interfaces/sso` recorder tests (nested group prefixes, dedupe, sorted
  snapshot, probe consts, post-Mount `Handle`, late-option degrade) +
  `mounted_routes_parity_test.go`.
- `test/` (package `ssotest`) integration: server with `WithAPIDocsUI`
  without/with `WithAPIVersionPreview` + `WithSetupWizardEnabled`;
  `Host: sso.internal.example` + no `WithIssuer` ⇒
  `servers[0].url == "http://sso.internal.example"`; `WithIssuer` ⇒ the
  issuer; viewer HTML contains the rewritten `servers` and injected version
  in the inlined spec.

Gates after every `.go` edit: `go build ./... && go vet ./...`;
`go test -run 'TestMaintainability_|TestArchitecture_' .`; before handoff
also `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
`make ci` (with the parity-fixture drift guard), and
`python cli.py check-routes` — the 241/322 PASS line must be unchanged
(Decision 1 changes what is *served*, never what the checker *reports*).

Whole-design risks not owned by any single decision:

- **Served-doc semantics shift**: the served `/openapi.json` stops being a
  superset of the mounted surface (filtering) and starts being
  deployment-dependent (host, version). Every consumer of the served
  document — Postman imports, collection naming, `cmd/gensdk` cross-checks —
  now sees deployment truth. `cmd/gensdk` is unaffected (it reads the
  embedded spec), but any consumer that diffs the served doc against
  `docs/openapi.yaml` will see intentional differences; the `WithAPIDocsUI`
  doc comment must state the new contract explicitly.
- **Budget pressure is concentrated in `interfaces/sso`**: the 60-file
  ceiling and the 500-line gate interact (split-first would create a file
  the ceiling forbids). The placement table above is the mitigation; the
  helper's fallback home (`server_routes_admin.go`) keeps the recorder
  whole. If the recorder type itself cannot fit in `server_health.go`,
  the fallback is `sso_wiring.go` (+54 headroom) with the helper elsewhere
  — the type must never be split across files.
- **Checker coupling**: the parity fixture makes the checker a de-facto
  interface of the recorder. That is intentional (fail-loud beats silent
  drift), but any future checker redesign must regenerate the fixture in
  the same change.
- **No wire/security regression surface**: the projection runs inside
  already-gated handlers and can only ever *remove* operations, *replace*
  two harmless URL strings, and *replace* one version string. There is no
  path by which it widens the exposed surface, changes a response code, or
  alters a non-docs route; the `make ci` suite pins that.
