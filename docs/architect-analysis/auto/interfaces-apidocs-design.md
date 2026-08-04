# Design: interfaces/apidocs — runtime-faithful projection, contract rendering, bidirectional lockstep

Design for `docs/auto/interfaces-apidocs-spec.md`. Implements the three
evidence-backed decisions in order 1 → 2 → 3, each independently shippable
under the mandatory gates. This document decides the API surface, the
state/storage model, the failure modes, and the things that could break the
design.

## Ground truth verified beyond the spec

The spec's evidence was re-verified against current code. Nine additional
facts materially constrain the design and are treated as binding:

- **`kin-openapi` is NOT a `go.mod` dependency.** The only reference in the
  repo is `Makefile:179`'s `go run github.com/getkin/kin-openapi/cmd/validate@latest`
  (an unpinned ad-hoc tool invocation). Decision 3's "reuse the existing
  kin-openapi dependency" therefore cannot mean "import it": adding it to
  `go.mod` would be a new module dependency, which AGENTS.md forbids for this
  work. The diff tool reuses `cmd/gensdk`'s parser instead (`goccy/go-yaml`,
  already in `go.mod`). This is a deliberate refinement of the spec's wording.
- **`interfaces/sso` does not consume `platform/buildinfo` today** (spec
  claims it does; the import exists only in `cmd/*`). The projection therefore
  adds a new `interfaces/sso → platform/buildinfo` import — legal (platform
  ranks below interfaces in `architecture_layer_test.go`'s `layerName`;
  `accessors.go` already imports `platform/audit`, `platform/geo`, ...) but a
  net-new edge to verify with the architecture gate.
- **`interfaces/apidocs` has exactly one production caller** (`interfaces/sso`);
  `cmd/gensdk` and `architecture_layer_test.go` only mention it in comments.
  `apidocs.New`'s signature change is internal — no embedder-facing break.
- **`interfaces/sso` is at its frozen 60-file ceiling** (60 non-test files
  confirmed) and `server_routes.go` is at 488/500 lines. No new file may be
  added and no meaningful code may be added to `server_routes.go`. All
  sso-side additions must land in files with headroom
  (`server_routes_admin.go` 332, `server_resource.go` 431) and `Mount` may
  gain at most ~2 lines.
- **A mount-time recorder is feasible and exact.** `core.Router` is an
  8-method interface (`shared/core/router.go:43-52`); a recording wrapper is
  ~55 lines and adapter-agnostic (wraps `s.router` regardless of gin/echo/std
  backend). `Mount()` (`server_routes.go:91`) calls `mountMiddleware()` first
  — which creates `s.router` if nil — then every mount function, with
  `mountAPIVersionPreview()` last. Wrapping `s.router` once at the end of
  `mountMiddleware` captures every subsequent registration, including
  `api.Group(...)` sub-registrations, if `Group` returns a prefix-aware
  sub-wrapper. `WithRouter(r Router)` (`options.go:24`) may replace the router
  at option time, but options all run before `Mount`, so the wrap sees the
  final router. `Server.Handle` (`server_routes.go:64`) routes through
  `s.router` after `Mount`, so embedder-dynamic routes are recorded too —
  no `Handle` change needed.
- **`/livez` and `/readyz` are documented** (`docs/openapi.yaml:3219,3238`)
  but mounted on the probe mux OUTSIDE `s.router` (`checks/route_contract.py`
  `OUT_OF_ROUTER_ROUTES`). The recorder will not see them; the mounted-set
  accessor must add them explicitly, mirroring the checker's constant.
- **The 81-operation gap is NOT what the analysis lists.** v2alpha
  (`mountAPIVersionPreview`, `server_health.go:291`), setup
  (`server_routes.go:150-151`), WASM authz, crypto inventory, CAEP and
  federation are all *statically registered* (they are inside the 241; the
  checker counts source text, not option state). The 81 documented operations
  with no static registration are a different, unenumerated set — Decision 3's
  one-time triage must produce the concrete list rather than trusting the
  analysis's family names.
- **The runtime projection and the static gate solve two different gaps.**
  Documented-but-never-registered operations (the 81) are stripped by any
  recorder-based projection automatically (they are never recorded), so the
  runtime needs no exception list at all; the exception list is needed only by
  the *Python gate*, which makes `ops/build/sdk-surface.json` (readable by
  Python, per the spec) the right home for it.
- **`/token`-family responses already name error codes in backticks**
  (`docs/openapi.yaml:1039-1040`: `` `invalid_grant`, `invalid_target`,
  `invalid_dpop_proof`, `use_dpop_nonce` ``), and `securitySchemes` today has
  `bearerAuth` (http/bearer/JWT, `docs/openapi.yaml:11843`). But
  `error-codes.md` is a 1030-line prose catalog (## endpoint-family sections),
  NOT a machine-readable code list, and there are zero `x-error-codes`
  annotations in the spec. Decision 2 therefore needs a bounded vocabulary
  filter to avoid rendering prose tokens like `client_id` as error codes.

## Decision 1 — Deployment-aware OpenAPI projection

### API surface

`interfaces/apidocs` (all new/changed code in the existing package; 3 files
today, 10-file directory ceiling):

```go
// Endpoint is one mounted (method, path) pair.
type Endpoint struct{ Method, Path string }

// Projection carries deployment truth computed by the composition side.
// Every field may be nil/empty: nil Mounted or ResolveIssuer means "serve
// the unprojected spec" for that dimension — projection failure degrades
// to the spec verbatim, never to an error page.
type Projection struct {
    // Mounted returns the routes registered in THIS build, evaluated per
    // request (option state and dynamic toggles like caepLive may change
    // between requests). nil or empty => no path filtering.
    Mounted func() []Endpoint
    // Version overrides info.version (buildinfo). Empty => keep spec value.
    Version string
    // ResolveIssuer returns the issuer for the current request — the same
    // value authorization responses stamp (RFC 9207). nil => keep
    // documented servers. Must be provided by sso (requestBaseURL's
    // trusted-proxy handling must not be reimplemented here).
    ResolveIssuer func(core.HandlerContext) string
}

// New replaces the current New(specYAML []byte). cfg.Projection == nil
// reproduces today's verbatim behavior exactly.
func New(cfg Config) (ui, spec core.HandlerFunc, err error)
// Config{ SpecYAML []byte; ErrorCodes []byte /* Decision 2 */; Projection *Projection }
```

Pure internal function `project(doc any, proj *Projection, issuer string) (any, error)`:
normalizes spec `{param}` and route `:param` to one form (the same rule
`checks/route_contract.py` uses), keeps only operations whose `(METHOD, path)`
is in `proj.Mounted()`, rewrites `servers` to `[{url: issuer}]` and
`info.version` to `proj.Version`. Paths with non-5-method keys (HEAD/OPTIONS)
are left untouched. No mutation of `docs.OpenAPISpec` or the parsed doc — the
projection builds a fresh shallow-copied tree.

`interfaces/sso` (no new files, `server_routes.go` stays under 500):

- `recordingRouter` (~55 lines, `server_routes_admin.go`): implements
  `core.Router`; records `(method, base+path)` into `s.mountedRoutes`
  (RWMutex-guarded map) for every `GET/POST/PUT/PATCH/DELETE` call; `Group`
  returns a prefix-aware sub-wrapper; `Use`/`ServeHTTP` delegate verbatim.
- `mountMiddleware` gains exactly one line (`server_routes.go:109` area):
  `if s.apiDocsUIHandler != nil { s.router = newRecordingRouter(s.router, s) }`.
- `mountedEndpoints()` accessor (~15 lines, `server_resource.go` next to the
  endpoint inventory): RLock-snapshot of `s.mountedRoutes` plus the probe
  consts `{GET /livez, GET /readyz}`.
- `WithAPIDocsUI` moves to `server_resource.go` (frees ~10 lines in
  `server_routes.go`; option signature stays niladic — no embedder break) and
  builds `Config{SpecYAML: docs.OpenAPISpec, Projection: &Projection{
  Mounted: s.mountedEndpoints, Version: ver, ResolveIssuer: s.resolveIssuer}}`
  where `ver, _, _ = buildinfo.Resolve("")`.
- `mountAPIDocsUI` and both route paths are unchanged; the two handlers now
  project per request. Headers, `no-store`, admin gating, offline inlining
  unchanged.

### Storage model

No persistent storage. Runtime state is: the parsed spec (already in memory),
the RWMutex-guarded recorded route set on `*Server` (written once during
`Mount` + on later `Server.Handle` calls, read per request), and the
ldflags-injected version via `buildinfo`. The projection result is computed
per request and not cached (a 322-operation filter + one `json.Marshal` is
sub-millisecond-to-few-ms; admin-gated low QPS — memoization by
`(issuer, mounted-hash)` is a noted future optimization, not built now).

### Failure modes

- Recorder race: `Server.Handle` may run after serving starts → every access
  to the recorded set goes through the RWMutex; the per-request snapshot under
  `RLock` is race-free (`-race` clean).
- Wrong-order assumption: if a future `Mount` change registers routes before
  `mountMiddleware`, those routes are silently missing from the projection.
  Guard: the Decision-3 reverse check plus a unit test that asserts
  `mountedEndpoints()` covers every route `check-routes` reports as
  statically registered (parity test with the Python checker's set).
- `Mounted` returns nil/empty: treated as "no filtering" (unprojected spec) —
  fail-safe per the spec's acceptance, and impossible in practice since core
  routes always mount.
- `ResolveIssuer` nil or issuer unset: fall back to the documented `servers`
  (or the per-request base URL when sso's resolver is wired, matching
  discovery).
- Projection panics/malformed input: `project` returns the error; the handler
  serves the unprojected spec with the existing no-store headers — never a 500
  page (same fail-safe philosophy as the parse-error path in `New`).

### What could break the design

- The recorder's `Group` prefix accounting is the one place a route can be
  mis-recorded; the parity unit test above catches it.
- `s.router` identity: no code type-asserts `s.router` to a concrete backend
  today (verified via grep); if an embedder's custom `Router` implementation
  returns a non-recording sub-router from `Group`, only its sub-routes are
  missed — same parity test catches it.
- The spec-vs-code drift in the requirements (`buildinfo` claim) means the new
  `interfaces/sso → platform/buildinfo` import is unexercised code today;
  `go vet` + the architecture gate are the backstop, and the import must be
  classified (platform ranks below interfaces — no `layerExemptions` needed).
- Budgets: `server_routes.go` must end at ≤ ~490 lines (the option body moves
  out); `server_routes_admin.go` 332 → ~420; `server_resource.go` 431 → ~476.
  All within the 500-line file budget with no exemption.

## Decision 2 — Render security and error contracts

### API surface

Pure viewer change. Server-side additions are limited to two data inputs:

- `docs` package: new `//go:embed error-codes.md` →
  `var OpenAPIErrors []byte` (mirrors `openapi_embed.go`; the package stays
  rank-0 shared). `apidocs.New` receives it via `Config.ErrorCodes`.
- `interfaces/apidocs/errorcodes.go` (new file, dir ceiling 10): a bounded
  `stableErrorCodes` map — the product's stable code taxonomy (oracle-safe
  table from AGENTS.md §3.1 plus the catalog in `docs/error-codes.md`),
  commented "keep in sync with docs/error-codes.md". This map is the
  vocabulary filter: a description token only renders as an error code if it
  is a known code, so prose tokens like `client_id` can never appear as codes
  (the spec's "degrade to 'see error-codes catalog', never invent content").
- `template.go` JS additions (vanilla JS, same inline nonce-gated script, all
  rendering via `textContent`/`el()` — no `innerHTML`):
  - Per operation, an "Authentication" line: resolve `op.security` (falling
    back to `SPEC.security` / `components.security` default) against
    `SPEC.components.securitySchemes`; render each scheme's name, type,
    scheme/bearerFormat, and short description; render OR-of-ANDs as
    "any of: [...]".
  - Per operation, an "Errors" block: for each non-2xx response whose content
    schema resolves to `ErrorResponse`, extract backticked tokens from the
    response description, filter through `stableErrorCodes`, and list them;
    when the filter yields nothing, render the `ErrorResponse.error`
    example/enum if present, else the literal "see error-codes catalog".
  - Top-level "Security schemes" section (all schemes, once) and "Base URLs"
    list from `SPEC.servers`.
  - `examples`/`example` on request bodies and responses rendered as
    `<pre>`-formatted JSON.
  - A collapsible "Error code catalog" section rendering the embedded
    `error-codes.md` as pre-formatted text (no md parser — bounded, always
    current, offline-safe).
- No Go renderer change in `template.go`'s server-side half beyond `pageData`
  gaining the catalog bytes as `template.JS`.

### Storage model

Static embedded bytes only: `docs.OpenAPISpec` (existing) and
`docs.OpenAPIErrors` (new). No runtime state, no new endpoints, no headers
changed. The catalog travels inside the served HTML (offline-save property
preserved).

### Failure modes

- `ErrorCodes` nil/empty: catalog section hidden, per-op extraction falls back
  to example/enum then the "see catalog" text — no error page.
- Spec `security` blocks referencing unknown scheme names: rendered as the
  raw name with "(undocumented scheme)" rather than failing the render.
- Self-referential `securitySchemes`/`examples` cycles: the existing
  `renderSchema` depth bound is reused; examples are JSON-stringified (no
  recursion).
- CSP: the script stays inline + nonce-gated; no new `src`/`href`/`style`
  attributes beyond existing patterns; tests assert the nonce attribute still
  renders.
- Budget: `template.go` 319 → ~450 lines. If the renderer work crosses 500,
  split the JS into a second `{{define "renderer"}}` template (html/template
  composition) — the spec's sanctioned fallback; the dir ceiling (10 files)
  has ample room.

### What could break the design

- `stableErrorCodes` drift from `docs/error-codes.md`: bounded blast radius
  (viewer-only), visible in the viewer, and the catalog section (embedded md)
  remains authoritative — a code missing from the map is simply not listed per
  op, which is the specified degradation.
- The backtick-token extraction depends on response descriptions naming codes;
  the `/token` family does today, and the acceptance test pins that behavior.
  If a future spec edit rewrites descriptions without codes, per-op lists
  degrade gracefully to the catalog link — by design.
- Adding `x-error-codes` annotations was considered and rejected: 258
  `ErrorResponse` references make a complete annotation pass impractical, and
  a partial pass would imply a completeness guarantee the viewer cannot keep.

## Decision 3 — Bidirectional lockstep and operationId-level API changelog

### API surface

- **Reverse route-contract** (in `checks/route_contract.py`, extending the
  existing `run()`): compute `documented - registered - exceptions`; fail with
  a per-operation listing when non-empty. Exceptions keyed by `operationId`
  (the checker already enforces operationId uniqueness), each entry carrying
  `{operationId, method, path, reason}` in a new
  `unmountedOperations` section of `ops/build/sdk-surface.json` (+ schema
  update in `ops/build/sdk-surface.schema.json` so `sdk-surface-check` keeps
  validating). The one-time bootstrap triage enumerates the concrete 81
  (NOT the analysis's family list — see ground truth) and is the auditable
  inventory the acceptance requires. A stale exception (op now mounted AND
  still listed) prints an advisory warning, not a failure.
- **Embed-consistency** (new `checks/embed_consistency.py` + `check-embed`
  command in `cli.py`): a `go run` helper (the same pattern
  `route_contract.py` uses to resolve route constants) prints
  `sha256(docs.OpenAPISpec)` and `sha256(docs.OpenAPIErrors)`; the check
  compares against the committed `docs/openapi.yaml` / `docs/error-codes.md`.
  Makefile `route-contract` target becomes
  `$(CLI) check-routes && $(CLI) check-embed` — both run under `make ci`
  (route-contract is a ci prereq) and under `make docs-validate` via its
  existing dependency.
- **operationId-level diff** (new `cmd/sdkdiff`, root module, composition
  layer — same classification as `cmd/gensdk`): parses two spec snapshots with
  `goccy/go-yaml` (gensdk's parser; NOT kin-openapi — see ground truth),
  builds `operationId → (method, path, canonical schema fingerprint)` for
  each, and emits a markdown changelog draft classifying: added (non-breaking),
  renamed/removed (breaking, quoted against `ops/build/sdk-surface.json`
  policy text), schema-shape changed (review; fingerprint = canonicalized
  schema subtree — type/properties/required/items/oneOf/allOf/enum/
  additionalProperties/$ref names, descriptions and examples stripped so
  cosmetic edits do not flag). Wired as `make sdk-changelog OLD=<ref> NEW=<ref>`
  using `git show <ref>:docs/openapi.yaml` into temp files (no committed
  snapshot copies of a 15k-line file; git-ref precedent exists in the
  Makefile's `proto-breaking`). CI runs it as an advisory step only — not a
  gate.

### Storage model

- `ops/build/sdk-surface.json` (persistent, schema-validated) becomes the
  exception inventory; the runtime never reads it (Decision 1's recorder makes
  static runtime lists unnecessary — this is what lets the spec's "exception
  list in sdk-surface.json" work cleanly).
- No spec snapshots are stored; git refs are materialized to temp files per
  invocation.
- The changelog draft is generated output (stdout or `docs/CHANGELOG-api.md`
  via the Makefile target), not a build input.

### Failure modes

- Reverse-check noise in feature PRs that document-then-mount across commits:
  mitigated by requiring exceptions to be added/removed in the same change
  that documents/unmounts the operations (stated in the check's failure
  message).
- Embed check is structurally unable to detect a *dirty working tree* at
  build time (a fresh `go build` embeds the dirty bytes, so binary == tree ==
  PASS). Its real coverage is embed-target drift (wrong file, rename, CRLF
  munging) and it doubles as a local pre-commit aid. The design states this
  limit explicitly rather than over-claiming.
- `go run` helper cost (~1-3 s per `make ci` run) — acceptable; the helper is
  compiled from the same tree the checker already compiles for route
  constants.
- `sdkdiff` on shallow clones without the requested refs: clear error message,
  exit 1, target is advisory so it cannot wedge `make ci`.
- goccy leniency vs kin-openapi strictness divergence: acceptable for an
  advisory changelog; the canonical fingerprint absorbs ordering noise.

### What could break the design

- The spec's "reuse kin-openapi" is unsatisfiable without a new go.mod
  dependency; the design reuses gensdk's parser instead and MUST document
  that choice in the sdkdiff package doc (spec drift, flagged).
- `sdk-surface.json` schema change touches `sdk-surface-check` and the
  capability registry — both must accept the new `unmountedOperations` field,
  or `make ci` fails for an unrelated reason (update schema + registry tests
  in the same change).
- The 81-operation triage is judgment work (each entry needs a reason); a
  bootstrap script can generate the initial list from the current diff, but a
  human must review it — this is the largest single implementation cost and
  the only step that cannot be automated.
- Reverse check counts option-gated registrations as "mounted" (static
  analysis): a documented op that is registered but gated off in every
  realistic build still passes the reverse check — by design (the runtime
  projection handles option state; the gate handles existence). Blurring
  these two would re-open the 241/322 ambiguity the spec calls out.

## Cross-cutting risks, budgets, and gate compliance

- **Budgets**: `interfaces/apidocs` 3 → ~5 files (projection.go, errorcodes.go)
  of a 10-file ceiling; `template.go` ≤ 500 (split-define fallback ready);
  `interfaces/sso` stays at 60 files with all additions in
  `server_routes_admin.go` / `server_resource.go` and `server_routes.go`
  ending at ~490; `cmd/` 6 → 7 directories (15 ceiling). No layer exemption,
  no file/function exemption, no gate relaxation.
- **Security/wire invariants**: no endpoint, header, error code, or
  authentication behavior changes; no-store semantics and bearer challenges
  untouched; the viewer renders only — Decision 2 adds no server contract
  surface.
- **Dependency discipline**: no new Go module dependency anywhere (goccy/go-yaml
  and the stdlib suffice); the only new embedded asset is
  `docs/error-codes.md` in the rank-0 `docs` package.
- **Sequencing**: Decision 1 (trust) → Decision 2 (viewer gain, same batch) →
  Decision 3 (CI infrastructure, next round). Decision 3's reverse check is
  the safety net that makes Decision 1's parity test and the exception
  triage auditable; neither blocks the other.

## Acceptance mapping

| Spec acceptance | Design provision |
|---|---|
| Projection contains no 404-ing op; reappears when option set; deterministic | recorder-based per-request `Mounted` + parity test vs `check-routes` |
| `servers` = resolved issuer; `info.version` = buildinfo | `ResolveIssuer: s.resolveIssuer`, `buildinfo.Resolve("")` |
| Projection failure degrades to unprojected spec | nil/empty `Projection` fields and `project` error path |
| `/token` op shows auth family + `invalid_grant`/`invalid_client`; plain admin GET shows bearerAuth only | security/securitySchemes rendering + backtick extraction filtered by `stableErrorCodes` |
| Catalog reachable; untied codes listed | embedded `error-codes.md` catalog section |
| Renderer tests on fixture spec | `apidocs_test.go` additions asserting scheme name + representative code in HTML |
| Reverse check fails on untriaged documented op; passes after triage | `unmountedOperations` exceptions + bootstrap of the concrete 81 |
| Embed check fails on file/embed drift | `check-embed` hash comparison (both embedded assets) |
| `make sdk-changelog` classifies add/rename/remove; rename/remove flags breaking | `cmd/sdkdiff` + sdk-surface policy quote |
| All existing gates pass | `go build/vet`, `TestMaintainability_|TestArchitecture_`, `make docs-validate`, `make ci` (route-contract extended, nothing relaxed) |
