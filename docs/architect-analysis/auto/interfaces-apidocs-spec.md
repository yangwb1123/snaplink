# Requirements Spec: interfaces/apidocs

> Source: [interfaces-apidocs-analysis.md](interfaces-apidocs-analysis.md), expansion direction
> "全局扫描结论". Scope: the opt-in embedded developer-documentation portal
> (`sso.WithAPIDocsUI`) — currently a static, deployment-blind projection of
> `docs/openapi.yaml`. Three improvements, all non-blocking, none relaxing an
> existing gate. Owned layer: `interfaces` (composition side of the hexagonal
> boundary: `interfaces/sso` wires, `interfaces/apidocs` renders).

## Decision 1: Deployment-aware OpenAPI projection (runtime-faithful spec)

### Name

Runtime-faithful projection: filter documented operations by mounted options and
inject the real base URL and server version.

### Problem

`WithAPIDocsUI` is documented as exposing "the full live endpoint + schema
inventory" — operationally sensitive, admin-gated — but it serves a static file
with no relationship to the running deployment. `handleSpec` serializes the
embedded spec verbatim; `mountAPIDocsUI` applies no filter. The consequence is a
documentation surface that contradicts the server it documents:

- The runtime has **241 routes but the spec declares 322 operations**
  (`python cli.py check-routes` → `PASS: route/OpenAPI contract (241 runtime
  routes, 322 documented operations)`). Roughly 81 operations (v2alpha previews,
  `/api/v1/setup`, WASM authz, crypto inventory, CAEP, federation) are not
  mounted in this deployment and return 404, yet the viewer and
  `/openapi.json` advertise them.
- `servers:` hardcodes `http://localhost:8080` / `https://{host}` with default
  `sso.example.com` (`docs/openapi.yaml` lines 52–60); `info.version` is the
  static `0.1.0` (line 32). The server has real values: ldflags-injected
  version via `platform/buildinfo.ResolveProfile` and the resolved issuer via
  `s.resolveIssuer(ctx)`.

Developers importing `/openapi.json` into Postman/Insomnia hit the wrong host or
call endpoints that 404 in this deployment; the admin gate exists precisely
because this inventory is meant to be precise.

### Evidence

- `interfaces/apidocs/apidocs.go` — `New` parses `specYAML` once; `handleSpec`
  returns `ctx.JSON(http.StatusOK, doc)` verbatim; no filter or override input
  exists on the constructor signature.
- `interfaces/sso/server_routes.go` — `mountAPIDocsUI` (lines 268–276): only
  `if s.apiDocsUIHandler == nil { return }` then registers both routes; no
  option-state filtering. `WithAPIDocsUI` (lines 302–319) comment: "the full
  live endpoint + schema inventory ... IS operationally sensitive".
- `python cli.py check-routes` output: "241 runtime routes, 322 documented
  operations" — the asymmetry is known and unactioned.
- `docs/openapi.yaml` lines 52–60 (`servers:` placeholders) and line 32
  (`info:` with static version).
- `platform/buildinfo/buildinfo.go` — `ResolveProfile` (lines 36–45) produces
  the real version/revision/dirty flags; `interfaces/sso` already consumes it.

### Proposed behavior

- Extend `apidocs.New` (or add a `Project` step) with a deployment-input struct
  carrying: (a) a route-level allowlist derived by `interfaces/sso` from the
  mounted option state (which handler families were registered), (b) the
  resolved issuer/base URL(s) from `s.resolveIssuer(ctx)`, (c) the version from
  `buildinfo.ResolveProfile`.
- The projection strips paths whose operations are not mounted in this build
  and rewrites `servers` / `info.version` before the document is inlined into
  the HTML and served at `/openapi.json`. Static spec remains the source of
  truth; the projection is a thin, pure function (no mutation of
  `docs.OpenAPISpec`).
- Dependency direction stays clean: `interfaces/sso` (composition) computes the
  projection inputs and passes them down; `interfaces/apidocs` never imports
  `interfaces/sso` (avoids the lateral/cyclic import).
- `Cache-Control: no-store` semantics preserved; the viewer keeps working fully
  offline on a saved copy (projected spec is still inlined).

### Acceptance check

- With `WithAPIDocsUI` mounted and a feature option (e.g. federation) not
  configured, `GET /api/v1/admin/docs/openapi.json` contains no path/operation
  that returns 404 in this build; with the option configured, the operations
  reappear. Projection is deterministic per build config.
- `servers` in the served JSON equals the resolved issuer (or its explicit
  override) of the running server; `info.version` equals
  `buildinfo.ResolveProfile(...)` output, not `0.1.0`.
- New unit tests in `interfaces/apidocs` cover: allowlisted/unmounted path
  filtering, issuer injection, version injection, and malformed-input fallback
  (projection failure degrades to the unprojected spec, never to an error
  page).
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`;
  `python cli.py check-routes` still passes unchanged.

## Decision 2: Render security and error contracts in the viewer

### Name

Viewer renders per-operation authentication requirements and per-endpoint
error-code catalog.

### Problem

`template.go`'s renderer displays method/path/parameters/request body/response
schemas only. It never renders `security`, `securitySchemes`, `servers`, or
`examples` — the fields an integrator needs most against an OAuth/OIDC server.
Authentication differs sharply per endpoint in this product (`bearerAuth` JWT
besides HTTP Basic precedence on `/token`-family endpoints, DPoP, mTLS,
`private_key_jwt`), and the product's most distinctive contract is its
oracle-safe error taxonomy (`invalid_grant`, `unsupported_provider`,
`mfa_invalid` — AGENTS.md oracle-safe table, `docs/error-codes.md`). The spec
carries all of it (`securitySchemes`, per-operation `security:` blocks, the
`ErrorResponse` schema whose `error` field is "Stable error code (catalog in
consts.go)"), but the viewer renders `ErrorResponse` as an ordinary object, so a
developer cannot see which codes an endpoint may return or which credential
family it requires. `cmd/gensdk` encodes this surface programmatically; the
human-readable viewer hides the two decision-critical field classes.

### Evidence

- `interfaces/apidocs/template.go` — `operationBody`, `paramsTable`,
  `renderSchema`: grep finds no branch for `op.security`,
  `components.securitySchemes`, `servers`, or `examples` (the only reads are
  `op.parameters`, `op.requestBody`, `op.responses`, `op.tags`,
  `op.operationId`, `op.summary`, `op.description`).
- `docs/openapi.yaml` — `components.securitySchemes.bearerAuth` (line 11843 ff.);
  per-operation `security: [{bearerAuth: []}]` blocks (276 `security:` lines,
  e.g. line 1253); `ErrorResponse` schema (line 14277 ff., `error` example
  `invalid_credentials`, "Stable error code (catalog in consts.go)").
- `docs/error-codes.md` and AGENTS.md section 3.1 — the oracle-safe error
  catalog this viewer should surface.
- `docs/deferred-backlog.md` — "Admin API-doc viewer: Implemented ...
  not an application UI" row; portal-side substance of the "multi-language SDK
  generation + developer portal" backlog item.

### Proposed behavior

- In `template.go`, per operation: render an "Authentication" line derived from
  `op.security` (and, when absent, the `components.security` default) that
  names the scheme(s) from `securitySchemes` with their type/bearerFormat and a
  short description; render scheme details once in a top-level
  "Security schemes" section.
- Render an "Errors" block per operation: for each non-2xx response that
  references `ErrorResponse` (or its schema), list the stable error codes that
  response can carry — sourced from the spec's `example`/`enum`/description of
  `error`, or from the documented per-endpoint error list in
  `docs/error-codes.md` cross-referenced by operationId; unknown/absent codes
  degrade to "see error-codes catalog" rather than inventing content.
- `servers` rendered as a visible "Base URLs" list; `examples` (when present)
  rendered as pre-formatted blocks. Pure viewer change — no server contract,
  no route, no header change; CSP nonce and offline-save properties preserved.
- Keep the renderer dependency-free (vanilla JS in the existing inline script;
  no new Go dependencies).

### Acceptance check

- A saved copy of `GET /api/v1/admin/docs` shows, for the `/token` family
  operation, both the bearer/DPoP/mTLS auth requirement and the
  `invalid_grant`/`invalid_client` error codes; for a plain admin GET, only
  `bearerAuth` plus its documented errors.
- `docs/error-codes.md` catalog entries are reachable from the viewer (linked
  or listed) for at least the oracle-safe codes; codes not tied to an endpoint
  are listed in a catalog section, not dropped.
- New tests in `interfaces/apidocs/apidocs_test.go` assert the rendered HTML
  contains the auth-scheme name and a representative error code for a fixture
  spec with `security`, `securitySchemes`, and an `ErrorResponse`-typed error
  response.
- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`;
  `make docs-validate` unchanged.

## Decision 3: Bidirectional lockstep and operationId-level API changelog

### Name

Reverse route-contract check + operationId-level semantic diff for a generated
changelog.

### Problem

Three artifacts must stay in sync — `docs/openapi.yaml` (source), `cmd/gensdk`
outputs (`docs/sdks/{typescript,python}`), and the runtime route table — but the
protection is one-directional and partial:

- `make docs-validate` only checks spec syntax (kin-openapi `validate`);
  `route-contract` (`checks/route_contract.py`) only fails "when a runtime
  route is absent from OpenAPI". Nothing fails when a documented operation is
  not mounted at runtime — so the 241-vs-322 asymmetry passes silently.
- `docs/openapi_embed.go` embeds `openapi.yaml` at build time via `go:embed`;
  no check compares the embedded bytes with the committed file, so a stale
  embed swallows drift.
- `ops/build/sdk-surface.json` policy states "renaming or removing an
  operationId ... is a breaking change requiring a minor-version bump and a
  CHANGELOG entry", but no automated diff produces that entry — it is manual.
  `docs/deferred-backlog.md` records the SDKs as "Not yet published as
  versioned packages"; a versioned release needs an auditable change history
  first.

### Evidence

- `Makefile` lines 178–181 — `docs-validate: route-contract capabilities-check`
  with only `kin-openapi validate` and `$(CLI) check-routes`.
- `checks/route_contract.py` — docstring "Fail when a runtime route is absent
  from OpenAPI" and the one-way comparison logic; the 241/322 asymmetry
  (confirmed by `python cli.py check-routes` output) never trips it.
- `docs/openapi_embed.go` — `//go:embed openapi.yaml` with no freshness check
  against the working-tree file.
- `ops/build/sdk-surface.json` — `compatibility.policy`: "renaming or removing
  an operationId (the spec's operationId, used verbatim as the method name) is
  a breaking change requiring a minor-version bump and a CHANGELOG entry".
- `docs/deferred-backlog.md` — "TypeScript/Python SDKs ... Not yet published as
  versioned packages".
- `cmd/gensdk/main.go` — consumes `docs.OpenAPISpec` with the same parser and
  operationId naming the diff would key on.

### Proposed behavior

- Add a reverse route-contract check: every documented operation (path+method)
  must resolve to a statically registered route (or an explicit opt-in
  exception list in `ops/build/sdk-surface.json` for embedder-dynamic and
  intentionally-unmounted surfaces such as v2alpha previews). The check fails
  `make ci` when a documented operation is neither mounted nor listed —
  turning today's silent 322-vs-241 gap into a visible, triaged inventory.
- Add an embed-consistency check: `docs/openapi_embed.go`'s embedded bytes must
  match the committed `docs/openapi.yaml` (hash comparison in a gate, e.g.
  inside `docs-validate`), closing the build-time-embed drift hole.
- Add an operationId-level semantic diff tool (reusing the existing
  kin-openapi dependency and `cmd/gensdk`'s parsing): comparing two spec
  snapshots, it emits a CHANGELOG draft classifying additions (non-breaking),
  renames/removals (breaking, per the sdk-surface policy), and schema-shape
  changes per operationId; wired as `make sdk-changelog` and a CI advisory
  step. No new Go module dependency; no security-boundary touch.

### Acceptance check

- The new reverse check fails when a documented operation is neither mounted
  nor in the exception list (demonstrated by a fixture diff), and passes after
  triage — for the current tree, the 81 un-mounted operations must be accounted
  for explicitly, making the inventory auditable.
- The embed-consistency check fails if `docs/openapi.yaml` is edited without
  regenerating the embed (or vice versa), and passes in CI.
- `make sdk-changelog` against two committed spec snapshots produces a
  changelog draft with at least the add/rename/remove classifications; the
  rename/remove path flags "breaking per ops/build/sdk-surface.json".
- All existing gates pass: `make ci` (including `route-contract`,
  `sdk-surface-check`), `go test ./... -race` unchanged in scope.

## Priority and sequencing

1. Decision 1 (runtime fidelity) — trust issue affecting every consumer
   (tooling import, gensdk cross-check); lands first.
2. Decision 2 (security/error rendering) — pure viewer gain, lowest cost; can
   ship in the same batch as Decision 1.
3. Decision 3 (lockstep + changelog) — CI infrastructure; next round.

No decision relaxes a gate, adds a layer exemption, or crosses the module's
file/line budgets (currently 3 files, 516 lines total; apidocs.go 84,
template.go 319, apidocs_test.go 113 — the renderer work in Decision 2 is the
only near-budget file and must stay under 500 lines, splitting the template if
needed).
