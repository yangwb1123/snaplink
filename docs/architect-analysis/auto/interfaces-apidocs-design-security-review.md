# Security Review: interfaces/apidocs — runtime-faithful projection, contract rendering, bidirectional lockstep

Review of `docs/auto/interfaces-apidocs-design.md` (Decisions 1-3) against the
executable code, `AGENTS.md` invariants, and the shared role rules in
`ai-dev/prompts/README.md`. Advisory only; no files were modified.

Checks that actually ran for this review (revision = working tree):

- `python cli.py check-routes` → `PASS: route/OpenAPI contract (241 runtime
  routes, 322 documented operations)` — the 81-op gap the design targets is
  real and current.
- Source tracing: `shared/core/router.go` (Router/GatedRouter/GatedRegistrar),
  `interfaces/sso/server_routes*.go`, `server_resource.go`,
  `server_discovery.go`, `server_health.go`, `server_me.go`,
  `server_userinfo.go`, `server_federation.go`, `sso_selfservice.go`,
  `accessors_threat.go`, `interfaces/apidocs/{apidocs,template}.go`,
  `interfaces/middleware/{request_url,trusted_proxy}.go`,
  `interfaces/admin/middleware.go`, `cmd/sso-server/build_*.go`,
  `checks/route_contract.py`, `Makefile`, `ops/build/sdk-surface*.json`,
  `docs/error-codes.md`.
- Greps for `apidocs.New` callers, `platform/buildinfo` consumers, `Use(` /
  `Group(` sites, `GatedRegistrar` assertions, and `</script>`/`<` in
  `error-codes.md`.

No `go build`/`go vet`/`go test` ran: this review changes no code. Claims are
labeled **Verified** (traced in this tree), **Partial** (traced but with
assumptions), or **Proposed** (design text, not yet implemented).

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets touched by this change

| Asset | Who can reach it today | Change |
|---|---|---|
| `GET /api/v1/admin/docs` (HTML viewer) | AdminMiddleware-gated (`admin:read`), stock binary; opt-in | Projection per request; new rendering (Decision 2) |
| `GET /api/v1/admin/docs/openapi.json` | Same gate | Projection per request |
| `docs.OpenAPISpec` / new `docs.OpenAPIErrors` embeds | Build-time; served inside the page | New embed + `check-embed` gate |
| `ops/build/sdk-surface.json` + schema | Repo/CI only; never read at runtime | New `unmountedOperations` exceptions section |
| `cmd/sdkdiff` output | Developer tool (advisory) | New |

**Verified** admin gating: `interfaces/admin/middleware.go:438-458`
`IsProtectedPath` returns true for the `/api/v1/admin/` prefix, and
`cmd/sso-server/build_http.go:86-87` wraps the whole HTTP stack with
`adminMW.HTTPMiddleware(base)` in the stock binary, so both docs routes are
`admin:read`-gated there. The SDK-level `/api/v1` group itself carries no
AdminMiddleware (`interfaces/sso/server_routes_admin.go:49`); embedders that
skip admin wiring already expose the option ungated — pre-existing, unchanged.

### Trust boundaries

1. **Admin client → server**: bearer token + `admin:read` (or `admin:*`
   wildcard, `interfaces/admin/middleware.go:32-33,50`). The projected spec
   content and the viewer HTML live inside this boundary.
2. **Network/edge → server**: `X-Forwarded-Host` / `X-Forwarded-Proto` are
   honored only when `ForwardedHeadersTrusted` is true
   (`interfaces/middleware/request_url.go:30-46`, `trusted_proxy.go:173-178`).
   The projected `servers` URL derives from this path (via
   `s.resolveIssuer`), so the trusted-proxy gate is the boundary.
3. **Repo → served HTML**: `docs/error-codes.md` and `docs/openapi.yaml`
   become executable-in-page content (inline script). Repo-controlled, CI-
   pinned, but human-edited prose.
4. **Embedder → router**: `WithRouter` (`options.go:23-25`) and `Server.Handle`
   (`server_routes.go:64`) inject a router and routes the recorder wraps.
   Embedders are trusted, but the recorder must preserve router capabilities.
5. **Dev tooling**: `make sdk-changelog` materializes git refs into shell
   commands; `check-embed`/`route_contract.py` compile and run local Go
   helpers (`checks/route_contract.py:128-139` precedent).

### Attacker capabilities considered

- A: unauthenticated network attacker (probes, header forgery against an
  untrusted edge).
- B: authenticated non-admin user (valid bearer, no admin scope).
- C: admin with `admin:read` (legitimate viewer of the projected docs).
- D: committer of `docs/error-codes.md` / `docs/openapi.yaml` (accidental or
  malicious edit that passes CI).
- E: embedder misusing `WithRouter`/`Handle` (capability-preservation
  failures).

## 2. Findings

### Finding 1 — High: the recording router silently breaks `GatedRegistrar`; seven gated surfaces degrade to handler-wrapping, creating a route-existence oracle

**Evidence (Verified).** `shared/core/router.go:365-432` defines
`GatedRegistrar` and `GatedRouter.register`:

```go
if gr, ok := g.inner.(GatedRegistrar); ok {
    gr.RegisterGated(method, path, h, g.live)
    return
}
// fallback: handler-wrapping with GateHandler
```

Today every gated mount constructs `GatedRouter` around a `*StdRouter` (which
implements `GatedRegistrar`), so gating happens at route-matching level:
`StdRoute.live` is checked in `ServeHTTP` **before** the route's middlewares
run (`shared/core/router.go:298-306`). The design's Decision 1 wraps
`s.router` in `recordingRouter` at the end of `mountMiddleware`
(`interfaces/sso/server_routes.go:105-134`). The recorder implements only the
8-method `core.Router` interface; it does not implement `GatedRegistrar`.
Every later `core.NewGatedRouter(s.router, ...)` therefore takes the fallback
path. Affected surfaces (all Verified, all constructed after the wrap):

- admin API group — `server_routes_admin.go:49`, `accessors_threat.go:201`
- self-service — `sso_selfservice.go:344`, `server_me.go:320,357`
- OIDC — `server_userinfo.go:33`
- federation — `server_federation.go:197`
- branding — `server_me.go:434`
- CIBA — `server_routes.go:239`
- CAEP — `server_health.go:70`

**Preconditions.** `WithAPIDocsUI` enabled (the entire recorder is behind this
opt-in option) and any gated surface off (the default for most) with
`requestIDMW`/tracing enabled. The design's own grep claim — "no code type-
asserts `s.router` to a concrete backend today" — is technically true but
misses the transitive effect: `GatedRouter` asserts on **its inner**, which
after the wrap is the recorder. `interfaces/sso/origin_validation.go:28-32`
re-exports `GatedRegistrar` as SDK surface, so the capability is contractual,
not incidental.

**Exploit steps.** With the admin gate off (default) and `WithAPIDocsUI` +
request-id middleware on:

1. `GET /api/v1/admin/audit-events` (registered, gated off) → matched, route
   middlewares run (tracing stamps `X-Request-Id`/`Traceparent`), then
   `GateHandler` 404s.
2. `GET /api/v1/definitely-not-a-route` → bare `http.NotFound`, no middleware
   fingerprints.

An unauthenticated attacker (capability A) distinguishes the two by response
headers. `mountAdminSurface`'s own doc promises the opposite:
`server_routes_admin.go:41-43` — "still indistinguishable from a path that was
never defined to an outside probe", and `shared/core/router.go:383-385`
explains why the route-matching level is REQUIRED for exactly this reason.

**Impact.** Wire-visible behavioral regression on every gated surface the
moment the opt-in docs feature is enabled; violates the documented
byte-identical-to-never-mounted invariant in `core/router.go` and AGENTS.md's
gating discipline; route-enumeration oracle for unauthenticated attackers;
adapter routers under `WithRouter` lose their conformance-proven gating
semantics (`interfaces/adapters/routertest/conformance.go:361-460` exercises
exactly this contract).

**Remediation.** `recordingRouter` (root **and** its `Group` sub-wrapper) must
implement `core.GatedRegistrar`:

- record `(method, path, live)` where `live` is the predicate, and
- delegate to `inner.RegisterGated` when the inner router implements
  `GatedRegistrar` (preserving route-matching gating), else replicate
  `GatedRouter.register`'s fallback exactly.

This also provides the live predicate Finding 2 needs. The "~55 lines" budget
needs to grow by the `RegisterGated` method; the parity test below covers it.

**Regression test.** In `interfaces/sso` (or `interfaces/adapters/routertest`
conformance): build a server with `WithAPIDocsUI`, admin gate **off**, request-
id middleware **on**; assert `GET /api/v1/admin/...` (gated-off registered
route) and `GET /unmatched-path` produce byte-identical status/headers/body
(no `X-Request-Id` on either). Run with `-race -count=10`.

### Finding 2 — Medium: the projection is gate-blind; gated-off-but-registered operations are advertised as live, failing the spec's own acceptance

**Evidence (Verified + Proposed).** The design records "every
GET/POST/PUT/PATCH/DELETE call" with no live predicate
(`recordingRouter`, Decision 1). But `mountCIBAEndpoint` registers
`POST /backchannel-authentication` unconditionally and gates reachability
live (`server_routes.go:234-240`), as do the admin group
(`server_routes_admin.go:41-49`), CAEP (`server_health.go:70`), federation,
self-service, OIDC, and branding. The recorder snapshots registrations, not
reachability. The design claims `Mounted` is "evaluated per request (option
state and dynamic toggles like caepLive may change between requests)" — but
with a static record the per-request evaluation cannot see gate state.

**Preconditions.** Any gated surface off (defaults: CAEP receiver, federation
entity, CIBA without store) + `WithAPIDocsUI`.

**Exploit steps.** Admin (capability C) opens the projected spec on a default
build: CAEP `/ssf/*`, federation, CIBA operations are listed yet 404. This is
the precise class of drift the spec's acceptance "Projection contains no
404-ing op; reappears when option set" was written to eliminate — just at the
gate granularity instead of the option granularity. Security impact is
bounded (viewer is admin-gated), but the acceptance criterion fails and the
runtime endpoint inventory (`server_resource.go` `endpointCandidates` +
`on(s)`) already solves this correctly for the admin `/endpoints` route —
the projection should match its discipline.

**Remediation.** With Finding 1's `RegisterGated` recording the `live`
predicate, `mountedEndpoints()` filters the snapshot by `live()` per request:
gate off → op stripped; gate flipped on → op reappears. No static exception
list needed at runtime (consistent with Decision 3's split).

**Regression test.** Parity test: with CIBA/CAEP/federation gates off, the
projected spec contains no `/backchannel-authentication`, `/ssf/*`,
federation ops; flip the live gate on (`SetCIBAGateEnabled`-style) and the ops
reappear without re-Mount.

### Finding 3 — Medium: error-codes catalog inlined as raw `template.JS` is a latent script-context breakout on an admin-gated origin

**Evidence (Verified + Proposed).** `template.go` inlines the spec as
`var SPEC = {{.SpecJSON}};` where `SpecJSON` is `template.JS(json.Marshal(...))`
— JSON encoding HTML-escapes `<`, `>`, `&`, so `</script>` inside spec strings
becomes `\u003c/script\u003e`. `html/template` treats `template.JS` as trusted
and does not re-escape. The design (Decision 2) says `pageData` gains "the
catalog bytes as `template.JS`" — if those raw bytes are placed in the script
element, any `</script>` in the markdown terminates the element and the
remainder executes. `docs/error-codes.md` is human-edited prose that already
contains `<` nine times (`DPoP: <proof>` line 284, `Link: <url>` line 759,
`Retry-After: <seconds>` line 921/939). No `</script>` exists today
(**Verified**), and `check-embed` pins the file, so the trigger requires a
committed edit — but the file documents HTML-bearing protocols (form_post,
Link headers) where a `</script>` in a sample is a plausible accident.

**Impact.** If triggered, script execution on `/api/v1/admin/docs` — same
origin as the admin console when deployed behind the documented OpenResty
proxy (`ops/deploy/openresty`) — i.e. an admin-session takeover primitive
(capability D → capability C). Latent, not live; the existing SpecJSON pattern
already shows the correct discipline.

**Remediation.** `pageData.Catalog: template.JS(json.Marshal(string(catalogBytes)))`
and inline `var CATALOG = {{.Catalog}};` — byte-for-byte the SpecJSON pattern.
Never raw `template.JS` over prose bytes.

**Regression test.** `apidocs_test.go`: fixture catalog containing
`</script><script>window.pwned=1</script>` renders inert (assert
`window.pwned` absent from the served page and the bytes appear escaped);
reuse the existing nonce-attribute assertion.

### Finding 4 — Info: `make sdk-changelog OLD=<ref> NEW=<ref>` interpolates refs into a shell command

**Evidence (Proposed).** The design wires `make sdk-changelog` using
`git show <ref>:docs/openapi.yaml`; the `proto-breaking` precedent
(`Makefile:174-176`) interpolates no user input. An unquoted ref in the
target is developer-local command injection. Low impact (developer's own
shell) but trivially avoidable.

**Remediation.** Quote in the Makefile target: `git show '$(OLD)'` /
`git show '$(NEW)'`, and validate refs contain no whitespace. Also validate
each `unmountedOperations` exception entry against the documented set
(operationId + method + path must match a real documented op) so a typo'd
exception silently protects nothing and a stale one is flagged — the design
already prints stale-exception advisories; make the no-match case a failure.

**Regression test.** `make sdk-changelog OLD='foo;touch /tmp/pwn'` produces a
clean error and no side effects; a fixture exception with a wrong
method/path fails the reverse check.

## 3. Abuse-case table

| Abuse case | Entry point | Preconditions | Outcome today / with design | Verdict |
|---|---|---|---|---|
| Identity spoofing via forged `X-Forwarded-Host` poisoning the projected `servers` | `GET /api/v1/admin/docs/openapi.json` | Attacker can inject headers into an admin's request (untrusted edge, `trusted_proxies` unset) | Issuer resolves through `middleware.BaseURL`, which honors `ForwardedHeadersTrusted` (`request_url.go:30`); same value stamped in RFC 9207 `iss`. With trusted proxies configured, forged headers are ignored; unset = documented legacy first-hop trust, pre-existing, shared with discovery | **Positive control** (design reuses `s.resolveIssuer`; does not reimplement proxy handling) — residual risk unchanged from today |
| Route-existence oracle on gated-off admin/self-service/oidc/caep surfaces | Any gated-off path | `WithAPIDocsUI` + gate off + request-id/tracing on | **Finding 1**: middleware fingerprints distinguish gated-off from never-registered; today byte-identical | **Required fix** |
| Docs advertise 404-ing endpoints (stale-contract abuse) | Viewer/spec, admin-gated | Gate off (CIBA/CAEP/federation defaults) | **Finding 2**: projection includes gated-off ops; fails spec acceptance | **Required fix** |
| Script breakout / XSS on admin-gated origin | `GET /api/v1/admin/docs` | Committed `</script>` in `error-codes.md` | **Finding 3**: raw `template.JS` inlines it; same-origin with admin console under documented proxy | **Required fix** (cheap) |
| Replay of a saved docs page | Offline copy | Admin saves page | Page is self-contained, no-store, nonce is baked into the saved copy (nonce is per-response CSP value, not a credential); viewer is read-only, no state-changing fetch | No new replay surface; nonce reuse on a saved copy is inert (nonce gates script execution; a saved page executes with the nonce it shipped with — same as today) |
| Cross-tenant access via projected spec | N/A | — | Projection filters routes and rewrites `servers`/`version` only; no tenant-scoped data enters the doc; viewer never reads request tenant context | No cross-tenant path introduced |
| Resource exhaustion via per-request projection | `GET /api/v1/admin/docs{,/openapi.json}` | Valid `admin:read` (or ungated embedder) | Per-request filter + `json.Marshal` of a 322-op doc, sub-ms-to-few-ms, admin-gated and inside the rate-limit stack (`server_routes.go` Handler doc; `buildMiddlewareChain` order) | Acceptable; note ungated-embedder deployments are pre-existing exposure |
| Sensitive-data leakage in rendered contracts | Viewer | `admin:read` | Decision 2 renders `securitySchemes`/error codes; `stableErrorCodes` bounded vocabulary prevents prose tokens (`client_id`) rendering as codes; catalog is embedded prose, no new server data; `no-store` + `X-Frame-Options: DENY` preserved (`template.go` handleUI) | **Positive control** |
| Gate bypass via `sdk-surface.json` exceptions | CI gate | Committer | Exceptions are keyed `{operationId, method, path, reason}`, schema-validated, advisory-only for stale entries; they cannot change runtime behavior (runtime never reads the file) | No privilege boundary touched |
| Embed drift poisoning served docs | Build | Stale `go:embed` | `check-embed` compares `sha256(docs.OpenAPISpec/OpenAPIErrors)` against committed files under `make ci`; cannot detect dirty trees (design discloses) | **Positive control** with disclosed limit |

## 4. Positive controls verified, residual risks, prioritized validation plan

### Positive controls verified (traced, not assumed)

- **Issuer trust**: projected `servers` uses `s.resolveIssuer` →
  `requestBaseURL` → `middleware.BaseURL`, gated by
  `ForwardedHeadersTrusted` (`interfaces/middleware/request_url.go:30-46`);
  the design explicitly forbids reimplementing proxy handling in `apidocs`.
- **Admin gating unchanged**: `/api/v1/admin/*` → `IsProtectedPath` →
  `admin:read` in the stock binary (`interfaces/admin/middleware.go:438-458`;
  `cmd/sso-server/build_http.go:86-87`); `no-store` headers and
  `X-Frame-Options: DENY` preserved in both handlers.
- **CSP discipline**: inline script stays nonce-gated; all new rendering via
  `textContent`/`el()`; no `innerHTML`; renderer recursion reuses the bounded
  `renderSchema` depth cap.
- **Oracle-safe rendering**: `stableErrorCodes` vocabulary filter means spec
  prose can never render as a code; unknown codes degrade to the catalog
  reference, never invented content.
- **Fail-safe projection**: nil `Projection` fields and `project` errors
  degrade to the unprojected spec; parse errors in `New` leave the feature
  unmounted (`apidocs.go` `New` error path, `server_routes.go` `WithAPIDocsUI`).
- **No new dependency/wire surface**: goccy parser already in `go.mod`
  (**Verified**, `go.mod:13`, `cmd/gensdk/main.go:40`); kin-openapi exists
  only as an unpinned `go run @latest` in `Makefile:179` (**Verified**); no
  endpoint, error code, or auth behavior changes; runtime never reads
  `sdk-surface.json`.
- **Design ground truths independently confirmed**: `apidocs.New` has exactly
  one production caller (`server_routes.go:318`); `interfaces/sso` is at 60
  non-test files; `interfaces/` imports no `platform/buildinfo` today;
  `check-routes` currently reports 241/322; `error-codes.md` is prose with no
  machine-readable list; `sdk-surface.json` is `additionalProperties: false`
  (schema update required in the same change as `unmountedOperations`).
- **Recorder race safety**: RWMutex snapshot under `RLock` per request is
  race-free; `Server.Handle` after serving starts is covered.

### Residual risks

1. Legacy first-hop trust when `security.trusted_proxies` is unset: the
   projected `servers` (and `iss` everywhere) follows attacker headers.
   Pre-existing, documented; operators on untrusted edges must configure
   trusted proxies. The design neither worsens nor fixes this.
2. `check-embed` structurally cannot detect a dirty working tree (disclosed
   in the design; binary == tree == PASS).
3. Reverse check counts option-gated registrations as mounted (by design —
   the runtime projection owns option state; the gate owns existence).
4. `stableErrorCodes` drift from `docs/error-codes.md`: bounded, viewer-only,
   catalog embed remains authoritative.
5. `sdkdiff` is advisory; goccy leniency vs kin-openapi strictness accepted
   for a changelog draft (must be stated in the package doc per the design).
6. Per-request projection cost: bounded, admin-gated, rate-limited; memoization
   by `(issuer, mounted-hash)` remains a future option.

### Prioritized validation plan

| # | Step | Gate/command | Blocks |
|---|---|---|---|
| 1 | Recorder implements `GatedRegistrar` + byte-identity test (gated-off vs unmatched, tracing on) | `go test ./interfaces/sso/ -run Gated -race -count=10` | Findings 1-2 |
| 2 | Projection gate-awareness test (CIBA/CAEP/federation off → ops absent; live toggle → reappear) | `go test ./interfaces/apidocs/ -run Projection` | Finding 2 |
| 3 | Catalog `json.Marshal` + hostile fixture (`</script>`) + nonce assertions | `go test ./interfaces/apidocs/` | Finding 3 |
| 4 | Quoted `make sdk-changelog` refs + exception-entry validation | `make sdk-changelog` fixture | Finding 4 |
| 5 | Parity: `mountedEndpoints()` == `check-routes` static set; reverse check after 81-op triage | `python cli.py check-routes` (extended), `python cli.py check-embed`, `make ci` | Decisions 1+3 |
| 6 | Full regression | `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`; `go test ./... -race`; `go test ./test/ -run TestE2E -v` | All |

### Bottom line

The design's security posture is sound on the boundaries it explicitly
preserves (issuer trust, admin gating, no-store, CSP, oracle-safe rendering,
fail-safe projection, no new dependencies). It has one High-severity
architectural defect — the recorder breaking `GatedRegistrar` and with it the
byte-identical gating invariant on seven live-gated surfaces — one
Medium acceptance failure (gate-blind projection), one Medium latent XSS
pattern (raw `template.JS` catalog bytes), and one Info tooling nit. All four
are fixable within the design's stated budgets (the `RegisterGated` method
and the `json.Marshal` wrapper are small, local additions); none requires a
gate relaxation or a layer exemption. Findings 1 and 2 should be resolved in
the same change as Decision 1 — they are properties of the recorder, not of
the later decisions.
