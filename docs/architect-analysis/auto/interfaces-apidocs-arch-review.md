# Architecture Review: interfaces/apidocs — runtime-faithful projection, contract rendering, bidirectional lockstep

Review of `docs/auto/interfaces-apidocs-design.md` (against
`interfaces-apidocs-spec.md` and `interfaces-apidocs-analysis.md`). Advisory
only; no files modified. Review revision: current working tree, gates run:

- `go build ./... && go vet ./...` — PASS
- `go test -run 'TestMaintainability_|TestArchitecture_' .` — PASS
- `python cli.py check-routes` — PASS (241 runtime routes, 322 documented operations)

## 1. Scope, assumptions, verified architecture summary

**Scope.** The review covers the three decisions: (1) deployment-aware OpenAPI
projection via a mount-time `core.Router` recorder, (2) viewer rendering of
security/error contracts, (3) reverse route-contract check, embed-consistency
check, and an operationId-level diff tool. Non-goals per the spec: no gate
relaxation, no new Go module dependency, no wire/security-surface change.

**Assumptions.** The design's "nine binding facts" were re-verified
independently. All nine hold, with two important *conclusions drawn from them*
that do not (findings H1, M1, M2). The current tree is the authority; the spec
and analysis are proposals.

**Verified architecture summary (evidence cited at first use):**

- `interfaces/apidocs` is 3 files (84+319+113 = 516 lines), one production
  caller (`interfaces/sso/server_routes.go`; `cmd/gensdk` and
  `docs/openapi_embed.go` mention it only in comments). `New(specYAML []byte)`
  parses once with goccy/go-yaml (`AllowDuplicateMapKey`) and serves the doc
  verbatim via `handleSpec`; `handleUI` inlines the marshaled JSON.
- `interfaces/sso` is at the frozen 60-file ceiling; `server_routes.go` 488/500;
  `server_routes_admin.go` 332; `server_resource.go` 431. `Mount()`
  (`server_routes.go:91`) runs `mountMiddleware()` first and
  `mountAPIVersionPreview()` last; `mountAdminSurface()` (`server_routes_admin.go:48`)
  builds `api := s.router.Group(PathAPIPrefix, ...)` and hands it to
  `mountAPIDocsUI(api)` and `mountWASMAuthzAdminAPI(api)`. `WithRouter`
  (`options.go:23`) replaces `s.router` at option time, before `Mount()`.
  `Server.Handle` (`server_routes.go:64`) requires `Mount()` first and routes
  through `s.router`. No production code type-asserts `s.router`.
- `core.Router` is exactly the 8-method interface the design quotes
  (`shared/core/router.go:43-52`); `core.NewGatedRouter` wraps any `Router`
  (`shared/core/router.go:402-466`) and is used for the CAEP/SSF, admin-API,
  self-service, OIDC, and branding groups; `GateHandler` answers with
  `http.NotFound` when the live toggle is off (`router.go:331-339`).
  `GatedRouter.register` type-asserts `inner.(GatedRegistrar)` (`router.go:428`)
  — relevant to finding M3.
- The check-routes asymmetry is real: `documented − statically-registered` is
  exactly **81 operations** (recomputed with `route_contract.py`'s own
  functions). The design's correction of the analysis is right: v2alpha
  (`mountAPIVersionPreview`, `server_health.go:284`), setup
  (`server_routes.go:150-151`), CAEP, federation are all statically registered
  and are inside the 241.
- The composition mounts additional surfaces **outside** the static scan:
  the admin gRPC-gateway owns 53 of the 81 gap operations on a separate
  `http.ServeMux` (`cmd/sso-server/build_http.go:97-215, 243-251` —
  `adminGatewayExactPaths`, `newAdminOuterMux`); 26 more are mounted on
  `s.router` via `Server.Handle` (SCIM 19, `cmd/sso-server/scim_routes.go:76-105`;
  WebAuthn 4, `serverwebauthn/webauthn.go`; compliance 2; `dr/status` 1).
  `WithAPIDocsUI` is not invoked anywhere in `cmd/sso-server` today (no config
  knob) — the option is embedder-facing and currently dormant in the stock
  binary.
- Decision 2 inputs verified: `securitySchemes` at `docs/openapi.yaml:11843`,
  276 `security:` lines, 258 `ErrorResponse` references, zero
  `x-error-codes` annotations, backticked error codes in the `/token`
  description (`openapi.yaml:1039-1040`), `error-codes.md` is a 1030-line prose
  catalog, `servers:` placeholders and static `info.version: 0.1.0` confirmed.
- Decision 3 inputs verified: `route-contract` is a `make ci` prereq and a
  `docs-validate` prereq; `sdk-surface-check` exists; `sdk_surface.py` validates
  structurally only (no full jsonschema run — see L1); `cmd/` has 6 directories
  (15 ceiling); `proto-breaking` is the git-show precedent; `buildinfo.Resolve`
  exists at `platform/buildinfo/buildinfo.go:31` and the new
  `interfaces/sso → platform/buildinfo` edge is legal (platform ranks below
  interfaces; no exemption needed).

**Overall assessment.** The design is well-scoped, budget-disciplined, and its
mechanics (recorder placement, fail-safe degradation, bounded vocabulary
filter, hash-based embed check) are sound and verified feasible. Its central
premise about the 81-operation gap, however, is factually wrong in both
directions (H1), and two acceptance-level claims (M1, M2) do not survive
contact with the tree. All three are fixable with small, local changes; none
invalidates the architecture.

## 2. Findings

| # | Severity | Evidence | Impact | Recommendation |
|---|---|---|---|---|
| H1 | High | The 81 gap decomposes as **53 admin gRPC-gateway ops** (live on `newAdminOuterMux`'s `http.ServeMux`, `cmd/sso-server/build_http.go:97-215,243-251` — clients/domains/keys/permissions/releases/snapshots/tenants/tokens/users/operations families) + **26 Handle-mounted ops** (SCIM 19, WebAuthn 4, compliance 2, dr/status 1) + 2 option-gated s.router ops (`/branding` via `GatedRouter`, `/mesh/ext-authz`). Recomputed: `documented − static` = exactly these 81. | The design's ground-truth claim "documented-but-never-registered operations (the 81) are stripped by any recorder-based projection automatically (they are never recorded)" is false in both directions: 26 of them ARE recorded (correctly — they are live on `s.router` via `Handle`), and the 53 gateway ops are never recorded but ARE live in the stock deployment. A stock server that enables `WithAPIDocsUI` would serve a projected spec missing 53 live endpoints — the mirror-image of the bug being fixed ("docs hide live endpoints"), violating the option's documented contract "the full live endpoint + schema inventory". The acceptance "no 404-ing op" passes vacuously. | Make the projection composable at the composition boundary: keep the recorder as the SDK-surface truth, and let `cmd/sso-server` merge `s.mountedEndpoints()` with `adminGatewayExactPaths()` (+ probes) when wiring the option. Concretely: `Projection.Mounted` should accept a merge of the SDK accessor and a composition-supplied `[]core.Endpoint`-compatible slice, or the stock composition should construct the projection rather than the niladic option doing it alone. At minimum, state explicitly that the projection is SDK-router-scoped and that the gateway family is out of scope until a merge mechanism exists. |
| M1 | Medium | `ssf := core.NewGatedRouter(s.router, s.caepGateOn)` (`server_health.go:70`); same pattern for admin-API (`accessors_threat.go:201`), self-service (`sso_selfservice.go:344`), OIDC (`server_userinfo.go:33`), branding (`server_me.go:432`). Gated routes are registered unconditionally; `GateHandler` returns `http.NotFound` when the toggle is off (`router.go:331-339`). | The recorder records gated families regardless of live state, so the projected spec advertises CAEP/SSF operations that 404 when `feature_gates.caep` is off — a direct violation of the spec acceptance "Projection contains no 404-ing op in this build". The design's `Projection.Mounted` comment promises "evaluated per request (option state and dynamic toggles like caepLive may change between requests)", but the mechanism (a static registration-time snapshot) cannot honor that. | Make `mountedEndpoints()` gate-aware: it already lives on `*Server` next to `caepGateOn`/`adminAPIGateOn`/`selfServiceGateOn`/`oidcGateOn`/`brandingGateOn`; filter the recorded set through the same gates (~10 lines, the finite set of live gates). Alternatively re-scope the acceptance to "registered in this build" and document the residual 404 class — but the design's own comment already promises the stronger semantics, so implement the filter. |
| M2 | Medium | Parity test as stated: "asserts `mountedEndpoints()` covers every route `check-routes` reports as statically registered". Default-option server records a strict subset of the static set (federation, CAEP, WASM, netpolicy, threat policies, backup, v2alpha... register only when options are set). Conversely, the recorder includes Handle-mounted routes (SCIM/WebAuthn/compliance/dr-status) that are NOT in the static set (the checker excludes `DYNAMIC_EXPRESSIONS`). | The parity test is unsatisfiable as written: it fails on a default server and cannot pass without (a) an all-options fixture and (b) a composition-side Handle-route inventory. The design's "~15-line accessor + parity unit test" understates the test cost and would either be weakened in practice or fail CI. | Split into three assertions: (1) recorded ⊆ static ∪ Handle-tables (no phantom routes — recorder against the checker's set plus the composition's `scimRouteTable`/WebAuthn/compliance tables); (2) an all-options fixture asserting recorded ⊇ static; (3) Handle-mounted parity derived from the composition route tables. This also gives Decision 3's exception bootstrap its input for free. |
| M3 | Low-Med | `GatedRouter.register` type-asserts `g.inner.(GatedRegistrar)` (`router.go:428`) and falls back to handler-wrapping when absent. The recording wrapper, implementing only the 8-method `Router` interface, does not satisfy `GatedRegistrar`. | Every gated mount (CAEP/SSF, admin API, self-service, OIDC, branding) silently downgrades from route-level gating to handler-wrap gating when the recorder is installed. The package doc says both are "correct, reachability-wise", so no behavior break — but the mechanism changes whenever `WithAPIDocsUI` is on, and any future code depending on `RegisterGated` semantics behaves differently with the option set. | Have `recordingRouter` implement `GatedRegistrar` by delegation to the wrapped router (~5 lines), preserving the optimization and semantics exactly. |
| L1 | Low | `ops/scripts/sdk_surface.py` validates structurally (schema header, `schema_version`, languages, groups) — it never runs a full jsonschema pass and never rejects unknown top-level keys. | The design's claim that the schema "must accept the new `unmountedOperations` field, or `make ci` fails for an unrelated reason" is overstated: adding the field without a schema update would not fail `sdk-surface-check` today. The design's error is in the safe direction. | Still update `sdk-surface.schema.json` (strict editors and future validation) and its tests, but drop the "ci would fail" framing. Decide whether `schema_version: 1` should bump or the new section is additive within v1. |
| L2 | Low | `cmd/sdkdiff` fingerprints strip descriptions/examples; Decision 2's per-op error lists are extracted from response descriptions. | A description edit that changes the viewer's error-code listing is invisible to the changelog fingerprint, and a fingerprint change from a real description edit is flagged only as "review" (not breaking) — consistent, but the two tools have different sensitivity to the same field. | Note this asymmetry in `cmd/sdkdiff`'s package doc and keep the fingerprint semantics (cosmetic edits must not false-flag breaking changes — the chosen trade-off is right). |
| I1 | Info | `WithAPIDocsUI` is not wired anywhere in `cmd/` today. | The design's acceptance language assumes a stock deployment with the option enabled ("GET /api/v1/admin/docs/openapi.json ... in this build"), but the actual current consumers are embedders, for which Decision 1 (recorder-only) is complete and correct. H1's blast radius is therefore conditional on future stock enablement — but the design's own ground-truth claim is what makes it a design error now. | Decide and document whether the stock composition is a supported deployment for the docs UI (see U1). |
| I2 | Info | `docs` is rank-0 shared; the new `//go:embed error-codes.md` mirrors `openapi_embed.go`; `template.go` 319 → ~450 with the split-define fallback and the apidocs 2→4 non-test files of a 10 ceiling all stay within budgets. | No layering or budget concern. `server_routes.go` 488 → ~475 (move `WithAPIDocsUI`, +1 wrap line) is consistent. | None. |
| I3 | Info | `buildinfo.Resolve("")` returns `(ver, revision, dirty)`; the design injects only `ver`. | The projected `info.version` omits revision/dirty, while `info` elsewhere carries full build identity. Cosmetic; the spec asks only for version. | Optional: append `-dirty` or revision suffix to `info.version` for parity with `/status`; not required. |

## 3. Decision options and trade-offs

**D1 — Projection source for the stock composition (H1).**
- (a) SDK-scoped only, documented: recorder truth = SDK router surface; gateway family declared out of scope. Cheapest; keeps `WithAPIDocsUI` niladic; but the stock deployment (if enabled) documents 53 live endpoints as absent — the exact fidelity defect the feature exists to remove.
- (b) Composition-merged: `cmd/sso-server` supplies `adminGatewayExactPaths()` (+ probes) into the projection via an additive accessor; SDK gains one small exported or option-carried hook. ~5-10 lines total; keeps the SDK free of composition knowledge; honors the hexagonal boundary (deployment truth belongs to the composition).
- (c) Mount the docs routes on the gateway mux and project from `newAdminOuterMux`'s table. Rejected: couples the opt-in SDK option to the stock gateway and changes route ownership.
- **Preferred: (b)** — with (a)'s scope note as documentation regardless. Decision 3's exception inventory should then be auto-derived from the same two sources (SDK recorder parity + composition tables).

**D2 — Live-gate fidelity (M1).**
- (a) Gate-aware `mountedEndpoints()` (filter through the five live gates): honors the spec acceptance "no 404-ing op" for toggle-gated families; ~10 lines; needs the gates to remain reachable from the accessor (they are).
- (b) Registered-only semantics, acceptance re-scoped: honest and deterministic per build config, but fails the spec's letter for CAEP/SSF when gated off and contradicts the design's own per-request comment.
- **Preferred: (a)**, with (b)'s wording kept only as the degradation note ("gates consulted per request; a gate flipped off after the page is saved is not reflected in a saved copy").

**D3 — Reverse-check exception sourcing (Decision 3).**
- (a) Hand-triage of the 81: the design's "largest single implementation cost". Verified unnecessary: 79 of the 81 are derivable from `scimRouteTable`, the WebAuthn/compliance/Handle call sites, and `adminGatewayExactPaths`; only the two option-gated s.router ops (`/branding`, `/mesh/ext-authz`) need a reason annotation.
- (b) Bootstrap generator reading those tables + human review of the residual: same auditable inventory, most of it machine-proven, and it feeds M2's parity assertions.
- **Preferred: (b).** The design's triage framing ("intentionally-unmounted surfaces such as v2alpha previews") is wrong — v2alpha is statically registered; the inventory's dominant reasons are "gateway-mux" and "Handle-mounted", which are verifiable, not judgment.

**D4 — sdkdiff parser (build vs buy).**
- (a) Add kin-openapi to go.mod: satisfies the spec's wording; violates AGENTS.md's no-new-dependency constraint for this work.
- (b) Reuse `goccy/go-yaml` (gensdk's parser): no new dependency; lenient vs strict parsing divergence is acceptable for an advisory changelog; must be documented in the package doc (the design already commits to this).
- **Preferred: (b)** — the design's refinement of the spec is correct and should stand.

**D5 — Exception inventory home.**
- (a) `ops/build/sdk-surface.json` (schema-extended): Python-readable, schema-validated, keeps the runtime free of static lists (the recorder makes them unnecessary) — the design's choice. Verified the checker is lenient (L1), so the schema update is hygiene, not a gate requirement.
- (b) Separate `ops/build/unmounted-operations.json`: more isolation, but a second registry to keep in sync for no benefit.
- **Preferred: (a).**

## 4. Prioritized implementation sequence

**Milestone 0 — Inventory and scope (½ day, no code).** Generate the 81 with
provenance (gateway / Handle / option-gated) using `route_contract.py`'s
functions plus the composition tables; record the split in the design; owner
decision on U1 (stock enablement) and U2 (live-gate semantics).

**Milestone 1 — Decision 1 (recorder + projection).** `recordingRouter`
(implementing `GatedRegistrar` by delegation, M3), the one wrap line in
`mountMiddleware`, gate-aware `mountedEndpoints()` (M1), move `WithAPIDocsUI`
to `server_resource.go`, `apidocs.New(cfg Config)` + pure `project`, and the
three-way parity tests (M2). Composition merge for the gateway family (H1)
lands here if U1 is "supported".
- Compatibility: `New` signature is internal (one production caller); the
  niladic option is unchanged; no route/header/wire change; `server_routes.go`
  ends ≤ ~475; sso stays at 60 files.
- Executable acceptance: `go build ./... && go vet ./...`;
  `go test -run 'TestMaintainability_|TestArchitecture_' .`;
  `go test ./interfaces/apidocs/ ./interfaces/sso/ -race`; unit tests for
  filtering/issuer/version/malformed-fallback; parity tests above;
  `python cli.py check-routes` unchanged; manual: option-off deployment serves
  byte-identical spec.

**Milestone 2 — Decision 2 (viewer contracts).** `docs.OpenAPIErrors` embed,
`errorcodes.go` bounded vocabulary, template renderer (Authentication line,
Errors block, Security schemes, Base URLs, examples, catalog section), fixture
tests asserting scheme name + representative code.
- Compatibility: viewer-only; CSP nonce and offline-save preserved;
  `template.go` ≤ 500 (split-define fallback ready); `ErrorCodes` nil degrades.
- Executable acceptance: new `apidocs_test.go` assertions; saved-page check
  for the `/token` family; `make docs-validate` unchanged; `go test ./... -race`.

**Milestone 3 — Decision 3 (lockstep + changelog).** Reverse check in
`checks/route_contract.py` with `unmountedOperations` exceptions (auto-bootstrapped
per D3, D5), `check-embed` + `check-embed` cli command (sha256 of both embedded
assets), `cmd/sdkdiff` + `make sdk-changelog` (goccy parser, canonical
fingerprint), Makefile `route-contract` extended; `sdk-surface.schema.json`
updated with tests (L1).
- Compatibility: `route-contract` failure only when new drift appears (the 81
  bootstrap must land in the same change); `sdk-changelog` advisory only, not a
  `ci` prereq; no go.mod change.
- Executable acceptance: fixture diff demonstrating reverse-check failure then
  pass after triage; embed check fails on file/embed drift; `make sdk-changelog`
  classifies add/rename/remove with the breaking quote; full `make ci`.

**Risks.** The reverse check will flag every future documented-but-unmounted op
— good, but it also makes docs-first PRs fail until the exception lands in the
same change (mitigation stated in the design); the 81 bootstrap must be
committed atomically with the reverse check to avoid a red `make ci`; the
all-options parity fixture is the largest single test cost (one max-config
`Server` construction, mirroring existing composition tests).

## 5. Unknowns needing owner/product decisions

- **U1 — Stock enablement:** Is the stock `cmd/sso-server` a supported
  deployment for `WithAPIDocsUI`? If yes, the gateway family (53 ops) must be
  merged into the projection (H1); if no, the projection's SDK-scope must be
  documented as the contract and the spec's acceptance wording adjusted.
- **U2 — Live-gate semantics:** Should the "no 404-ing op" acceptance cover
  request-time feature toggles (`feature_gates.caep` and friends), or is
  "registered in this build" the contract? The design's comment promises the
  former; the mechanism needs the gate-aware accessor (M1) to deliver it.
- **U3 — Registry versioning:** Is `unmountedOperations` additive within
  `schema_version: 1`, or does `sdk-surface.json` need a version bump? (The
  checker pins the const to 1.)
- **U4 — Issuer injection scope:** `ResolveIssuer` resolves per request, so a
  saved offline copy bakes in the saving request's issuer (and tenant). For a
  multi-tenant deployment, is a single resolved issuer acceptable for the
  documented `servers`, or should the projection list all configured issuers?
- **U5 — Changelog destination:** `make sdk-changelog` output to stdout only,
  or committed `docs/CHANGELOG-api.md`? If committed, who owns regeneration
  discipline before releases?
