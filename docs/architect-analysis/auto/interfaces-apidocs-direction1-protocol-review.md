# Protocol Review — interfaces/apidocs Direction 1 design (deployment-aware OpenAPI projection)

Input under review: `docs/auto/interfaces-apidocs-direction1-design.md` (doc-only;
no Go gates touched). Input spec: `docs/auto/interfaces-apidocs-direction1-spec.md`.
Baseline: `ai-dev/prompts/README.md` evidence standard; `AGENTS.md` §2/§3 as the
regression boundaries.

## Review method and what actually ran

- `python cli.py check-routes` — ran: `PASS: route/OpenAPI contract (241 runtime
  routes, 322 documented operations)` — reproduces the design's headline gap.
- Source inspection of every cited location (all Verified unless marked):
  `shared/core/router.go`, `architecture_layer_test.go`, `interfaces/sso/*`
  (wiring, mounts, gates, discovery, federation), `interfaces/apidocs/apidocs.go`
  and `template.go`, `platform/buildinfo/buildinfo.go`, `cmd/sso-server/main.go`,
  `checks/route_contract.py`, `docs/openapi.yaml`, `docs/openapi_embed.go`,
  `cmd/gensdk/main.go`, `shared/core/router_test.go`, testkit.
- File/line budgets and the 60-file ceiling: measured via `ls`/`wc -l`.
- No Go gates were run: the review changes no code (`go build`, `make ci` etc.
  are not applicable to a doc-only review of a not-yet-implemented design).

The design's evidence base is accurate. One required correction (F1) and two
test/fixture gaps (F2, F3) before implementation; the rest are acknowledged
semantics shifts or Info-level notes.

## 1. Protocol/profile scope and authoritative references

The change touches no OAuth/OIDC/CAEP/SAML/SCIM/WebAuthn wire surface: it only
projects an admin-gated, cached-nowhere document. The standards actually in
scope are:

| Reference | Relevance |
|---|---|
| OpenAPI Specification 3.0.3, §4.8.4/4.8.5/4.8.6 (paths, path item, operation), §4.8.11 (`info.version`, REQUIRED free-form string), §4.8.15 (server object: `url` REQUIRED) | The served document must remain a valid OpenAPI doc after filtering/servers/version projection |
| RFC 9207 §2 (OAuth 2.0 Authorization Server Issuer Identification) | `resolveIssuer` reuse: the documented base must equal the `iss` stamped in authorization responses for the same request |
| RFC 8414 §2 / OIDC Discovery 1.0 (issuer canonicalization: no query/fragment, no trailing slash) | Inherited, not reimplemented — apidocs adds zero URL logic |
| RFC 9111 §5.2 (no-store on sensitive responses) | Both doc handlers must stay uncacheable since the payload becomes request-dependent |
| AGENTS.md §3 (oracle-safe responses, byte-identical gating) and `GatedRouter`'s route-matching-level gate contract | The recording wrapper must not change gated-off route behavior (F1) |

The OpenAPI document is a self-describing API contract, not an IETF protocol;
the review treats OpenAPI 3.0.3 structural validity and the OAuth-family
identity invariants it inherits as the conformance surface.

## 2. Compliance matrix

Legend: requirement level MUST/SHOULD/MAY per the governing reference;
status is against the design as written.

| # | Section / requirement | Implementation evidence (design → source) | Status | Deviation / note | Test |
|---|---|---|---|---|---|
| M1 | OpenAPI 3.0.3 §4.8.11: `info.version` REQUIRED string, free-form | D3 rewrites via `buildinfo.Resolve("")` (buildinfo.go:31, ResolveProfile :37, FormatEditionVersion :47-60); `(devel)`/empty keep documented `0.1.0` (openapi.yaml:34) | **Verified — compliant** | Edition profiles inject non-semver labels (`snaplink-1.4.2.full`); spec-legal, semver-parser risk (F6) | `project_test.go` version rewrite + `(devel)` fallback; integration asserts `== buildinfo.Resolve("")` ver |
| M2 | OpenAPI 3.0.3 §4.8.15: single `servers[].url` REQUIRED | D2 rewrites to `[{"url": issuer}]`; nil/empty/`DefaultIssuer` keep documented list (openapi.yaml:52-60) | **Verified — compliant** | Two documented entries (Local dev + Production) collapse to one; deliberate, documented (F4) | unit fake-resolver; integration `Host: sso.internal.example` and `WithIssuer` cases |
| M3 | RFC 9207 §2: `iss` ≡ discovery/issued identifier | `ResolveIssuer` closure wired to `s.resolveIssuer` (server_discovery.go:251-256, RFC 9207 doc comment) — same function stamps authorization `iss`; `requestBaseURL` (server_federation.go:40) → `middleware.BaseURL` (request_url.go:22), `ForwardedHeadersTrusted` (request_url.go:33) gates XFF | **Verified — compliant** | Issuer-vs-console-host topologies: doc points at issuer, not portal host — pinned by integration test, correct per RFC 9207 consistency | integration servers-rewrite cases |
| M4 | RFC 8414 §2: issuer canonicalization | apidocs performs no string surgery; canonicalization inherited from `resolveIssuer` (verified: `BaseURL` emits `scheme://host` with no trailing slash) | **Verified — compliant** | `WithIssuer` is an unvalidated setter (options.go:348-350); a future config with trailing slash would surface verbatim — accepted, upstream fix | n/a (no apidocs tests per spec, correct) |
| M5 | RFC 9111 §5.2: no-store on both doc responses | `handleUI` (template.go:33) and `handleSpec` (apidocs.go:81) both set `Cache-Control: no-store` today; projection runs inside both handlers | **Verified — compliant** | Host-dependent payload stays uncacheable; no change needed | existing apidocs_test.go:41-42 |
| M6 | AGENTS.md: admin gate `admin:read` preserved | Both routes stay behind `mountAdminSurface`'s `/api/v1/admin` group (server_routes_admin.go:49, `s.adminAPIGateOn`) | **Verified — compliant** | Projection can only remove/replace inside already-gated handlers | existing admin tests |
| M7 | `GatedRouter` route-matching-level gate (router.go:371-373: "REQUIRED, not a style choice") + AGENTS.md byte-identical gated-off 404 | **Design gap**: `recordingRouter` overrides only the five method registrars and embeds `core.Router`; it does not implement `GatedRegistrar`. Every gated group (`api`, `gr`, `ssf`, `selfServiceGR`) registers via `GatedRouter.register` → `RegisterGated` (router.go:427-429) | **Non-compliant as designed** — F1 | Gating silently downgrades to handler-wrapping when the option is on; gates are runtime-flippable (`adminAPILive.Store` from feature gates accessors_feature_gates.go:36 and SIGHUP reload accessors.go:50) | must add: recorder `RegisterGated` + gating-semantics test (F1/F2) |
| M8 | `checks/route_contract.py` one-directional contract unchanged | `contract_errors` (route_contract.py:212-230) only checks `routes − documented`; run reproduced PASS 241/322 | **Verified — compliant** | Design only changes what is served, never the PASS line; additive `--dump-routes` flag does not alter the PASS/FAIL path | `python cli.py check-routes` after implementation |
| M9 | AGENTS.md budgets: 60-file ceiling, 500-line gate, layer imports | measured: `interfaces/sso` = 60 non-test files; placement table exact (server_health.go 443/+57, server_routes_admin.go 332/+168, server_routes.go 488/+12, sso_selfservice.go 469/+31); layer ranks platform=1 < interfaces=5 (architecture_layer_test.go:41-42) | **Verified — compliant** | F1 adds one method to `recordingRouter` (~4 lines) — fits the 55-line budget | maintainability gates |
| M10 | `StdRouter.Group` semantics mirrored | Group at router.go:236-243: child prefix = `r.prefix + r.buildPath(prefix)`, shared route table (`routes: r.routes`); design mirrors both | **Verified — compliant** | Citation points at `buildPath` (router.go:288-293) rather than `Group` itself — cosmetic | recorder group-nesting unit tests |
| M11 | Fail-safe projection (nil/empty ⇒ verbatim) | Design's zero-value `Projection` semantics; consistent with `New`'s parse-error path (apidocs.go:42-59) | **Verified — compliant** | late option application degrades to verbatim, logged | unit fallback tests |
| M12 | OpenAPI structural validity of the filtered doc | Filtering keeps non-method keys, drops whole empty path items, skips non-maps; no `head`/`options`/`trace` ops exist in openapi.yaml today (grep: zero) | **Verified — compliant** | `head`/`options` exempt from filtering while being HTTP methods — latent inconsistency (F5) | `project_test.go`; add re-parse validity test (T4) |

## 3. Findings

### F1 — High, MUST fix: `recordingRouter` does not implement `GatedRegistrar`; installing it downgrades every gated group to handler-level gating

Location: design §Decision 1 "API surface" (recorder type); `shared/core/router.go:365-366, 413-440`; `interfaces/sso/server_routes_admin.go:49`, `server_federation.go:197`, `server_health.go:70`, `server_me.go:320,357`, `accessors_threat.go:201`.

Observed facts (all Verified):

- All four gated groups derive from `s.router` (`api = NewGatedRouter(s.router.Group(PathAPIPrefix), ...)`, `gr`/`ssf`/`selfServiceGR` = `NewGatedRouter(s.router, ...)`).
- `GatedRouter.register` dispatches to `RegisterGated` whenever the inner router implements `GatedRegistrar` (router.go:427-429) — `*StdRouter` does.
- The design's recorder overrides only the five method registrars and `Group`, embedding `core.Router`; `RegisterGated` is not in the `Router` interface (router.go:43-52), so the wrapper does **not** implement `GatedRegistrar` (whether it embeds the interface or the concrete `*StdRouter`).
- Consequence, traced through the code: `GatedRouter` takes its handler-wrapping fallback (`g.inner.GET(path, GateHandler(live, h))`, router.go:430-440) — routes are still *recorded* (the override fires), but gating moves from `StdRoute.live` (checked in `ServeHTTP` **before** route middlewares run, router.go:268-273) to a handler wrap. Gated-off admin/federation/CAEP/self-service requests then match, run the global middleware chain installed by `mountMiddleware` (Tracing stamps X-Request-Id/Traceparent; tenant/geo/region run), and only then 404.
- The gates are live toggles, not constants: `adminAPILive.Store(gateOn(s.featureGates.AdminAPI))` (accessors_feature_gates.go:36) and the SIGHUP reload hook (accessors.go:50).
- `shared/core/router_test.go:487-500` documents exactly this as an oracle: "a response byte-for-byte different from a genuinely-never-registered path's 404, and thus an oracle revealing 'this route exists but is currently gated off'".

Impact: with `WithAPIDocsUI` enabled, the byte-identical gated-off-404 invariant (AGENTS.md §3 regression boundary; `GatedRouter` doc: "REQUIRED, not a style choice") is silently lost for the admin surface — the surface this very feature serves. An alternative embedding (`*StdRouter`) preserves gating but silently misses recording every gated-group route, inverting the feature (live routes dropped from the served doc). Either failure is invisible to the parity test (F2).

Corrective behavior: `recordingRouter` must implement `GatedRegistrar` — override `RegisterGated(method, path, handler, live)` to record `(strings.ToUpper(method), r.prefix + r.buildPath(path))` and delegate to the inner router's `RegisterGated` with the same `live` func (recorder prefix chain mirrors the inner's, so recorded keys equal registered paths). This keeps route-matching-level gating and makes the parity test exercise the actual dispatch point. ~4 lines inside the existing 55-line budget.

Validation step: with the recorder installed around a `StdRouter`, replicate `TestGatedRouter_LiveToggleControlsReachabilityByteIdenticalTo404` and `TestGatedRouter_GateOffSkipsGlobalMiddleware_NoHeaderLeak` (router_test.go:444, 487) — gated-off 404s must stay byte-identical to never-registered, including headers, with a `Use()`-registered middleware ahead of the gated group.

### F2 — Medium, SHOULD fix: the parity test cannot detect the F1 regression

Location: design §Decision 1 "Parity test design"; spec acceptance "Parity test".

Observed fact: the `mountedEndpoints() ⊇ fixture` assertion is pure set membership over `(METHOD, path)`. Both gating paths (route-matching-level vs handler-wrapping) produce identical route sets — F1 changes behavior, not membership. The fixture guard therefore gives false confidence on the security-relevant dimension, and the design's failure-mode list ("recorder cannot silently miss a registration") does not cover "recorder changes gating semantics".

Corrective behavior: add a dedicated gating-semantics test in `interfaces/sso` (wrapper + gated group + live toggle, asserting byte-identical 404 and no global-middleware fingerprint), as specified in F1's validation step; keep the parity test for membership.

Validation step: `go test ./interfaces/sso/ -run TestRecorderGate -race -count=10` plus the existing `shared/core` gating tests with the wrapper in the loop.

### F3 — Medium: the "fully-optioned server" parity fixture is underspecified and non-trivial to assemble

Location: design §Decision 1 "Parity test design" ("builds a fully-optioned server").

Observed facts: the checker's 241-route set is static — it counts every `(METHOD, path)` call on the five receivers regardless of runtime guards (route_contract.py:21, 62-75). The parity server must therefore satisfy **every** mount guard simultaneously: `permissions` (authz policy bundle), `storageHealthSources`, `federationHealth`, `protectedResourceMetadata`, `federationEntity` + `HasSubordinates` + signer, `meshExtAuthz`, `caepStreamStore`, `tokenExchangeChainStore`, trusted-device store + `sessionMgr`, `tenantStore` (branding), `wasmAuthzEngine` (needs a wasm module; `wasmauthz.New(ctx, module)`, engine.go:93), `cryptoInventory`, `apiDocsUIHandler`, `setupWizardEnabled`, `apiV2AlphaPreview`. Feasible — memory implementations exist (caep.NewMemoryStreamStore receiver.go:327, cryptoinventory.NewMemoryInventory memory.go:37, tokenexchange/memory, federation.MemoryHistoricalKeyStore handler.go:273, wasmauthz testdata) — but the option list is not enumerated in the design, and any store lacking a test implementation silently shrinks the fixture (⊇ still passes on a smaller set), weakening the guard by accident.

Corrective behavior: enumerate the exact option set in the design, generated from the same source the fixture is generated from; note the mutual-compatibility check (no two options may conflict in one server) as a fixture-generation assertion.

Validation step: generator runs with every option; assert the generated fixture equals the checker's `runtime_routes ∪ OUT_OF_ROUTER_ROUTES` before diffing.

### F4 — Medium (acknowledged in design): served-doc semantics shift; the structural 81-operation gap becomes visible in every deployment

Location: design "What could break this design" (first bullet); verified: check-routes reproduces 241/322 (81 gap); option-gated mounts exist (server_health.go:291, server_setup.go:44/64/74, server_me.go nil-field guards).

Impact: the served `/openapi.json` changes from "spec reference" (superset of the mounted surface) to "deployment inventory" (subset, host- and version-dependent). Optional-feature operations (v2alpha preview, setup wizard, WASM authz, crypto inventory, CAEP, federation) disappear from every deployment's served doc; consumers diffing against `docs/openapi.yaml` see intentional divergence. `cmd/gensdk` reads the embedded spec (main.go:63) and is unaffected — verified. The design already mandates the `WithAPIDocsUI` doc comment state the new contract; treat that comment as MUST (it is the only mitigation for external consumers).

### F5 — Low: `head`/`options`/`trace` path-item keys are exempt from filtering although they are HTTP methods

Location: design §Decision 1 "Filtering semantics".

Observed fact: zero `head:`/`options:`/`trace:` operations exist in `docs/openapi.yaml` today (grep verified), so there is no current phantom. But the exemption is asymmetric with the feature's own goal: a future documented `head:` operation would be advertised while unmounted (the five router registrars cannot register it; the checker's `METHODS` set also excludes it). Recommendation: state the asymmetry in the filtering helper's comment (one line); no behavior change needed.

### F6 — Info: edition-profile version labels are non-semver in `info.version`

Location: design §Decision 3 "What could break this design"; `FormatEditionVersion` (buildinfo.go:47-60) decorates `snaplink-<base>.<profile>`. OpenAPI 3.0.3 §4.8.11 specifies `info.version` as a free-form REQUIRED string, so the label is spec-valid; strict `semver.Parse` consumers see a change from today's `0.1.0`. Design's decision (decorated label is the binary's public identity) is reasonable; keep, and note in the option doc comment.

### F7 — Info: verification notes (no defect)

- The additive `--dump-routes` flag recommendation is sound: `run()` (route_contract.py:229-244) prints only the PASS line; an additive flag cannot perturb the PASS/FAIL path. The `make ci` drift guard is the enforcement point for fixture staleness (a stale fixture passes `go test`; only the guard catches it) — acceptable, stated.
- The recorder's path equality claim ("the inverse direction inherits the checker's exactness for free") is sound: since `check-routes` passes, every runtime `:param` path has a documented `{param}` counterpart with the identical parameter name under the same normalization (`_normalize_openapi_path`, route_contract.py:162-163), so byte equality after normalization is exact for the mounted set.
- The docs routes themselves are documented (`docs/openapi.yaml:5037,5071`) and recorded (registered on the `api` group), so the portal documents itself consistently; the `/livez`/`/readyz` probe consts mirror `OUT_OF_ROUTER_ROUTES` (route_contract.py:42-46) — verified.
- Layer/import analysis is correct: `interfaces/sso → platform/buildinfo` is downward (1 < 5, architecture_layer_test.go:41-42), no exemption; `interfaces/apidocs` stays free of platform imports (its only current import of Snaplink code is `shared/core` — verified in apidocs.go).

## 4. Priority conformance tests, declared unsupported, certification

Priority tests (in order):

1. **T1 (F1 gate)** — recorder installed around `StdRouter`; gated group toggled off; 404 byte-identical to never-registered including headers with an ahead-registered `Use()` middleware (mirror router_test.go:444/487). MUST pass before the feature ships.
2. **T2 (F1 recording)** — `RegisterGated`-dispatched registrations recorded with correct prefix at two/three group nesting levels; `live` func preserved (behavioral: toggle flips reachability).
3. **T3 (parity)** — fully-optioned server; `mountedEndpoints() ⊇` checker fixture ∪ probes; fixture regenerated and diffed in `make ci`.
4. **T4 (OpenAPI validity)** — after `project`, re-parse the JSON and assert required structure (paths map, `info.version` string, `servers[0].url` string); assert `info`/`servers`-absent specs stay absent (verbatim).
5. **T5 (RFC 9207 consistency)** — integration: `servers[0].url` equals the `iss` of an authorization response for the same request configuration; `X-Forwarded-Proto: https` only wins with a trusted peer (middleware tests cover the extractor; assert the end-to-end case once).
6. **T6 (version)** — integration: `info.version == buildinfo.Resolve("")` ver for the test binary; viewer `<title>`/header carries it (extend apidocs_test.go:44-46).

Declared unsupported (per design, accepted): no filtering of embedder dynamic `Server.Handle` paths (never documented, unchanged); no URL normalization or trust logic inside `interfaces/apidocs`; no caching of the projected document; late option application degrades to verbatim; `head`/`options`/`trace` operations exempt from filtering (none exist today); non-semver edition labels intentionally injected.

Certification evidence: none claimed, and none should be — the design claims no OIDF/OpenID certification anywhere; this change does not alter any wire protocol, and no published current certification result exists in the repository. Any future certification claim must reference a published current result per the review baseline.

## Bottom line

The design is evidence-accurate (every citation checked, budgets and the 241/322 gap reproduced) and protocol-sound on the surfaces it touches (OpenAPI 3.0.3 validity, RFC 9207 issuer consistency, no-store, admin gate). It must not be implemented as written until F1 is corrected (recorder implements `GatedRegistrar`), F2's gating-semantics test is added, and F3's fixture option inventory is enumerated. F4-F7 are acknowledged semantics shifts or notes, not blockers.
