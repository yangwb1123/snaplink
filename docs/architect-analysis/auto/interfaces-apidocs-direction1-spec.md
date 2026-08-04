# Requirements Specification — interfaces/apidocs, Direction 1: Deployment-aware (runtime-faithful) OpenAPI projection

Source: `docs/auto/interfaces-apidocs-analysis.md` §1. Scope: make the opt-in
embedded developer-documentation portal (`sso.WithAPIDocsUI`) describe the
deployment that actually serves it — filter documented operations by mounted
option state, and inject the real base URL and real server version. The three
decisions below are the three sub-problems of that one direction; they share a
single projection seam and are delivered together, but each is independently
testable.

Design constraints honored throughout (AGENTS.md §2, §4):

- `interfaces/apidocs` never imports `interfaces/sso` (lateral import).
  The composition side (`interfaces/sso`) computes projection inputs and passes
  them down as closures/values; `interfaces/apidocs` stays a pure renderer.
- `interfaces/sso` is at its 60-file ceiling: zero new files there — all
  changes extend existing files (`server_routes.go`, `server_health.go` area
  wiring, an accessor beside the endpoint inventory).
- No new module dependencies. The projection reuses what exists: the embedded
  `docs.OpenAPISpec`, `checks/route_contract.py`'s normalization rule,
  `s.resolveIssuer`, `platform/buildinfo.Resolve`.
- Fail-safe projection: nil/empty projection inputs degrade to today's
  verbatim behavior (unprojected spec), never to an error page — the same
  philosophy as `New`'s parse-error path (`interfaces/apidocs/apidocs.go`).
- No wire/security contract changes: both routes stay
  AdminMiddleware-gated (`admin:read`), `Cache-Control: no-store` preserved,
  the saved-page-offline property preserved (the projected spec is still
  inlined into the HTML), `docs/openapi.yaml` stays the sole source of truth
  and is never mutated.

---

## Decision 1: Filter documented operations by mounted option state

### Name

Mounted-route projection: serve only the operations this build actually
registers.

### Problem

`WithAPIDocsUI` is documented as exposing "the full live endpoint + schema
inventory" — operationally sensitive, admin-gated — but the served document is
a static file with no relationship to the running build. Optional feature
families (v2alpha preview, setup wizard, WASM authz debug, crypto inventory,
CAEP receiver, federation) are documented in `docs/openapi.yaml` whether or
not their option was wired; in a build where the option is off, those
operations return 404 while the viewer and `/openapi.json` advertise them.
`python cli.py check-routes` prints the asymmetry as a PASS, so nothing
guards it: **241 runtime routes vs 322 documented operations** (~81 phantom
operations). The admin gate exists precisely because this inventory is meant
to be precise; a machine-readable consumer (Postman import, `cmd/gensdk`
cross-check) cannot distinguish "documented but unmounted" from "exists".
The server already knows its own mounted state — every optional mount is a
nil-field or bool guard in `Mount()` — so the filter is a thin projection over
existing knowledge, not new machinery.

### Evidence

- `interfaces/apidocs/apidocs.go:43` — `New(specYAML []byte)` parses once and
  has no filter/allowlist input on its signature; `handleSpec`
  (`apidocs.go:79-84`) does `ctx.JSON(http.StatusOK, doc)` — verbatim output.
- `interfaces/sso/server_routes.go:268` — `mountAPIDocsUI`: the only guard is
  `if s.apiDocsUIHandler == nil { return }`; no option-state filtering.
  `WithAPIDocsUI` (`server_routes.go:316`) builds the handlers from
  `docs.OpenAPISpec` with no reference to what else is mounted; its doc
  comment claims "the full live endpoint + schema inventory".
- `checks/route_contract.py:212-230` — `contract_errors`/`run` only check
  "runtime routes ⊆ documented operations" (`missing_route_errors`); the
  inverse direction is never checked, so `(241 runtime routes, 322 documented
  operations)` is a PASS line.
- Option-gated mount precedents the projection must mirror:
  `interfaces/sso/server_health.go:291` `mountAPIVersionPreview`
  (`if !s.apiV2AlphaPreview { return }`); `interfaces/sso/server_setup.go:44,64,74`
  `setupWizardOn()`; nil-field guards in `interfaces/sso/sso_selfservice.go`
  (cryptoInventory, credentialScheduler, apiDocs handlers).
- `docs/openapi.yaml:162` (`/api/v2alpha/version`), `:196`/`:224`
  (`/api/v1/setup/status`, `/api/v1/setup`), `:5178` (`/api/v1/admin/crypto/keys`)
  — operations for unmounted-in-this-deployment features.

### Proposed behavior

- `interfaces/sso` records every `(METHOD, path)` its router registers during
  `Mount()` (and later `Server.Handle` calls) — e.g. a recording router
  wrapper installed when `WithAPIDocsUI` is wired, plus the probe consts
  `{GET /livez, GET /readyz}` — and exposes `mountedEndpoints()` under
  RWMutex (per-request snapshot; dynamic mounts after startup are covered).
- `WithAPIDocsUI` passes `Mounted func() []Endpoint` down to `apidocs.New`.
- `interfaces/apidocs` gains a pure `project(doc, projection, issuer)` step:
  normalize each documented path's `{param}` to `:param` (the exact rule
  `checks/route_contract.py` `_normalize_openapi_path` uses), keep only
  operations whose `(METHOD, path)` is in the mounted set, drop whole paths
  left with zero kept operations, leave non-HTTP-method keys (HEAD/OPTIONS/
  `x-*`) untouched, and build a fresh shallow-copied tree — no mutation of
  `docs.OpenAPISpec`.
- Both handlers serve the projected document per request; `Mounted` returning
  nil/empty means "no filtering" (today's verbatim behavior). no-store
  headers, admin gating, and offline inlining unchanged.

### Acceptance check

- Unit tests in `interfaces/apidocs`: mounted operations kept, unmounted
  dropped, `{id}` ↔ `:id` normalization matches the Python checker's rule,
  whole-path removal, `Mounted == nil` fallback serves the unprojected spec.
- Integration: server with `WithAPIDocsUI` but without
  `WithAPIVersionPreview`/`WithSetupWizardEnabled` ⇒
  `GET /api/v1/admin/docs/openapi.json` contains no `/api/v2alpha/version`,
  `/api/v1/setup`, or `/api/v1/setup/status` operations; with the options on,
  they reappear. Deterministic per option set.
- Parity test: `mountedEndpoints()` covers every route `python cli.py
  check-routes` reports statically (241 + probes) — the recorder cannot
  silently miss a registration.
- `python cli.py check-routes` still prints PASS unchanged;
  `go test -run 'TestMaintainability_|TestArchitecture_' .` clean;
  `go test ./interfaces/apidocs/ -race` clean.

---

## Decision 2: Inject the real base URL into `servers`

### Name

Issuer-faithful `servers`: replace placeholder URLs with the deployment's
resolved issuer/base.

### Problem

The spec's `servers:` block hardcodes `http://localhost:8080` and
`https://{host}` with default variable `sso.example.com`
(`docs/openapi.yaml:52-60`). Anyone importing `/openapi.json` into
Postman/Insomnia targets the wrong host out of the box — the single most
common first failure for a tooling consumer. The server already resolves its
own public base for every request: `resolveIssuer` returns the configured
issuer, else the trusted-proxy-aware request base URL. The admin-gated docs
endpoints are served on the deployment's real host, so the request itself
carries the answer; what is missing is a rewrite of `servers` before the
document is serialized. `interfaces/apidocs` must not reimplement
trusted-proxy logic — the canonical extractor already exists and must be
reused via a closure from `interfaces/sso`.

### Evidence

- `docs/openapi.yaml:52-60` — `servers:` with
  `http://localhost:8080` ("Local dev") and `https://{host}` with
  `default: sso.example.com` ("Production deployment") — placeholders, not
  deployment truth.
- `interfaces/sso/server_discovery.go:251` — `resolveIssuer`:
  `if s.issuer != "" && s.issuer != DefaultIssuer { return s.issuer }`,
  else `requestBaseURL(ctx.Request())`; the same pattern at
  `server_discovery_config.go:264`. This is the value stamped into every
  RFC 9207 `iss` — the canonical "who am I" of this deployment.
- `interfaces/sso/server_federation.go:40` — `requestBaseURL` delegates to
  `middleware.BaseURL` (`interfaces/middleware/request_url.go:22`), the
  canonical trusted-edge extractor (first-hop `X-Forwarded-Proto`/`-Host`,
  gated by `ForwardedHeadersTrusted`).
- `interfaces/apidocs/apidocs.go:79-84` — `handleSpec` serializes the parsed
  doc with no `servers` handling anywhere in the package.

### Proposed behavior

- Projection input carries `ResolveIssuer func(core.HandlerContext) string`
  wired by `WithAPIDocsUI` to `s.resolveIssuer` — the identical function
  authorization responses use, so the documented base can never drift from
  the issued `iss`.
- The spec handler rewrites `servers` per request to a single
  `{url: <resolved issuer>}` entry (RFC 9068/discovery consistency: one
  canonical base, not two guesses). If the resolver is nil or yields empty/
  `DefaultIssuer`-sentinel, keep the documented `servers` list — fail-safe.
- `interfaces/apidocs` contains zero URL/trust logic; it only places the
  value the closure returns. The HTML viewer inherits the rewrite because the
  projected JSON is what gets inlined.

### Acceptance check

- Unit: `project` with a fake resolver rewrites `servers` to the resolver's
  value; nil resolver ⇒ documented list preserved.
- Integration: request to `/api/v1/admin/docs/openapi.json` with
  `Host: sso.internal.example`, no `WithIssuer` ⇒
  `servers[0].url == "http://sso.internal.example"`; with
  `WithIssuer("https://id.example")` ⇒ `"https://id.example"`.
- Trusted-edge behavior is inherited, not reimplemented: an
  `X-Forwarded-Proto: https` header only wins when the existing
  trusted-proxies middleware says the peer is trusted (existing
  `interfaces/middleware` tests cover the extractor; apidocs adds none).
- Viewer HTML contains the rewritten `servers` in its inlined SPEC (assert in
  the UI test).

---

## Decision 3: Inject the real server version into `info.version`

### Name

Buildinfo-faithful version: replace static `0.1.0` with the binary's real
version.

### Problem

`info.version` is a static `0.1.0` (`docs/openapi.yaml:34`) that never
changes, while the server binary carries a real version resolved at startup:
ldflags-injected `Version` (release/profile builds), else the module version,
else `(devel)`, plus VCS revision and dirty flag
(`platform/buildinfo`). `cmd/sso-server` already resolves and prints this
value; the docs portal is the one place that still shows a constant.
Tooling consumers use `info.version` for collection naming and SDK version
pinning (`cmd/gensdk` reads the same embedded spec), so a frozen `0.1.0`
silently mislabels every deployment — a release build of v1.4.2 and a dirty
`(devel)` checkout advertise the identical API version. The viewer also
renders this static value in its `<title>`/header via `specTitleVersion`,
so the lie is user-visible, not just machine-visible.

### Evidence

- `docs/openapi.yaml:32-34` — `info: {title: snaplink/sso HTTP API,
  version: 0.1.0}` — static, never bumped per build.
- `platform/buildinfo/buildinfo.go:26` — `var Version = ""` with doc
  "replaced by release or profile builds through -ldflags"; `Resolve`
  (`buildinfo.go:31`) → `ResolveProfile` (`buildinfo.go:37`) picks
  ldflags → module version → `(devel)` and surfaces revision/dirty.
- `cmd/sso-server/main.go:26,131` — sso-server already imports
  `platform/buildinfo` and writes `buildinfo.Write(os.Stdout, "sso-server",
  version)` at startup; the value exists before the docs routes are mounted.
- `interfaces/apidocs/apidocs.go:60` — `specTitleVersion` copies the static
  `info.version` into the viewer's `<title>`/header, propagating the frozen
  value into the human-facing page.

### Proposed behavior

- Projection input carries `Version string`, resolved once at
  `WithAPIDocsUI` application time by `interfaces/sso` via
  `buildinfo.Resolve("")` (architecture-clean: platform ranks below
  interfaces, no exemption needed; `interfaces/apidocs` stays import-free of
  platform too — it only places the string).
- The projection rewrites `info.version` to that value before serialization;
  the viewer's existing `specTitleVersion` then picks up the real version for
  the `<title>`/header with no template change.
- Fail-safe: empty or `(devel)`-style unresolved values keep the documented
  `0.1.0` (or fall back verbatim) — a cosmetic field never fails a request.

### Acceptance check

- Unit: `project` with `Version: "1.4.2"` rewrites `info.version`; empty
  Version keeps the spec value.
- Integration: `info.version` in the served `/openapi.json` equals
  `buildinfo.Resolve("")`'s ver for the test binary (assert against the
  package directly), not `0.1.0`.
- Viewer test: UI body contains the injected version (extend the existing
  `v1.2.3` assertion in `interfaces/apidocs/apidocs_test.go` to projected
  input).

---

## Sequencing

Decision 1 is the trust-critical half (wrong endpoints 404); Decisions 2 and 3
are the integration-friction halves (wrong host, wrong version label). All
three land through the same `project` seam and are tested in the same new
`interfaces/apidocs` test files; deliver as one change, in the order 1 → 2 →
3, with the mandatory gates (`go build ./... && go vet ./...`,
`go test -run 'TestMaintainability_|TestArchitecture_' .`, `python cli.py
check-routes`, `go test ./... -race`) run after each `.go` edit. None of the
three relaxes an existing gate or touches a security/wire contract; the
static `docs/openapi.yaml` remains the single source of truth and stays
byte-identical.
