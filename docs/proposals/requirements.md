Spec written to `docs/auto/interfaces-apidocs-direction1-spec.md` (13.6 KB, doc-only change — no Go gates affected). It decomposes direction 1 (runtime-faithful OpenAPI projection) into exactly 3 evidence-backed decisions, each with Name / Problem / Evidence / Proposed behavior / Acceptance check:

**## Decision 1: Filter documented operations by mounted option state**
- **Problem**: `WithAPIDocsUI` claims to expose "the full live endpoint + schema inventory" but serves the static spec verbatim — 241 runtime routes vs 322 documented operations, printed as PASS by the route-contract checker; ~81 phantom operations (v2alpha preview, setup wizard, WASM authz, crypto inventory, CAEP, federation) 404 when their option isn't wired.
- **Evidence**: `interfaces/apidocs/apidocs.go:43` (`New` has no filter input) + `:79-84` (`handleSpec` verbatim `ctx.JSON`); `interfaces/sso/server_routes.go:268` (`mountAPIDocsUI` guards only on nil handler) + `:316` (`WithAPIDocsUI` builds from `docs.OpenAPISpec` with no option state); `checks/route_contract.py:212-230` (one-directional check); option-gated mount precedents `server_health.go:291`, `server_setup.go:44`.
- **Proposed behavior**: recording router on the sso side exposing `mountedEndpoints()` under RWMutex; pure `project()` in apidocs normalizing `{param}`→`:param` per the checker's own rule and keeping only mounted `(METHOD, path)`; nil/empty → verbatim fallback.
- **Acceptance check**: unit filtering tests, integration with/without `WithAPIVersionPreview`/`WithSetupWizardEnabled`, a parity test that `mountedEndpoints()` covers all 241 statically-reported routes, `check-routes` still PASS.

**## Decision 2: Inject the real base URL into `servers`**
- **Problem**: `docs/openapi.yaml:52-60` hardcodes `http://localhost:8080` / `https://{host}` (`sso.example.com`) — every Postman/Insomnia import targets the wrong host.
- **Evidence**: `interfaces/sso/server_discovery.go:251` (`resolveIssuer` — configured issuer else trusted-proxy-aware `requestBaseURL`), `interfaces/middleware/request_url.go:22` (`BaseURL`, canonical trusted-edge extractor), apidocs has zero `servers` handling.
- **Proposed behavior**: `ResolveIssuer` closure wired to `s.resolveIssuer` (same function stamping RFC 9207 `iss`); per-request rewrite of `servers` to one `{url}` entry; nil/empty resolver keeps documented list; no trust logic reimplemented in apidocs.

**## Decision 3: Inject the real server version into `info.version`**
- **Problem**: static `0.1.0` (`docs/openapi.yaml:34`) never matches the binary — release v1.4.2 and a dirty `(devel)` checkout advertise identically, and `specTitleVersion` (`apidocs.go:60`) propagates it into the viewer title.
- **Evidence**: `platform/buildinfo/buildinfo.go:26,31,37` (ldflags → module version → `(devel)` + revision/dirty); `cmd/sso-server/main.go:26,131` already resolves it at startup.
- **Proposed behavior**: `Version` from `buildinfo.Resolve("")` resolved by the composition side (platform ranks below interfaces — no exemption); rewritten into `info.version`; existing `specTitleVersion` picks it up with no template change; empty/`(devel)` falls back to documented value.

Cross-cutting constraints pinned: apidocs never imports `interfaces/sso`, zero new files in the 60-file-ceiling sso package, no new dependencies, fail-safe projection never 500s, and no-store/admin-gating/offline-inline invariants preserved.
