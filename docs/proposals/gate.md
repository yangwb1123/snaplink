# Gatekeeper cross-check — review findings vs design (`docs/auto/interfaces-apidocs-design.md` @ `9b3b4966`)

The design file is **unchanged since the reviews** (`git diff 9b3b4966 -- docs/auto/interfaces-apidocs-design.md` is empty). I re-verified the disputed mechanisms against code: `GatedRouter.register` type-asserts `g.inner.(GatedRegistrar)` at `shared/core/router.go:428` (handler-wrap fallback when the assertion fails), and `adminGatewayExactPaths()` exists in `cmd/sso-server/build_http.go` on the separate admin gRPC-gateway `ServeMux`.

## Resolved or dismissed with reasons

| Finding | Status | Evidence in design |
|---|---|---|
| T3 — goccy over kin-openapi | **Resolved** | Ground truth #1 + Decision 3: no-new-go.mod-dependency, flagged as spec drift |
| T4 — `sdk-surface.json` as exception home | **Resolved** | Decision 3 storage model; runtime never reads it |
| T5 — 81-op triage automation | **Partially** | Design has a bootstrap script but insists triage "cannot be automated" (arch: 79/81 derivable); compatible in direction |
| check-embed `go run` helper pattern (QA F1's inverted pattern) | **Resolved** | Decision 3 uses it for embed hashing |
| Fail-safe degradation, no-store, admin gating, probe consts | **Resolved** | Ground truth #6, Decision 1 failure modes |
| P1–P4, P6 protocol defects | **Dismissed with reason** | Pre-existing, separate workstream (principal §2 exclusions) |

## Unresolved — no fix, no dismissal reason in the design

**High (block Decision 1):**
- **H1** — Design's core premise is affirmatively wrong: it asserts the 81 are "documented-but-never-registered" and "the runtime needs no exception list at all". Verified: 53 admin ops are **live on the gateway mux** (invisible to any `s.router` recorder → projected spec omits 53 live endpoints in the stock composition); 26 are live via `Server.Handle` (the recorder *will* capture them). Zero mentions of `adminGatewayExactPaths`, composition merge, or an SDK-scope note.
- **H2** — The recorder silently degrades `GatedRegistrar` on all nine gated surfaces (wire-visible `X-Request-Id` fingerprint on gated-off routes). The design's only mitigation — "no code type-asserts `s.router`" — misses the transitive assertion at `router.go:428`. Zero mentions of `GatedRegistrar`/`RegisterGated`.

**Medium:**
- **M1** — Design promises per-request dynamic-toggle evaluation ("evaluated per request … caepLive may change") but `mountedEndpoints()` is a plain RLock snapshot + probe consts; no live-gate consult. The acceptance "no 404-ing op" fails at gate granularity (CAEP/SSF/federation/CIBA).
- **M2** — Parity test as stated ("`mountedEndpoints()` covers every route `check-routes` reports") is unsatisfiable; no machine-readable `check-routes` output, no three-way split, no Handle-table parity.
- **M3** — No named sso-layer option-toggle test (federation on/off ⇒ op presence in served JSON).
- **M4** — Recorder `Group` prefix accounting has no direct unit tests (nested groups, `:id:pin`, `releases:current`, `{param}`↔`:param`); relies solely on the broken parity test.
- **M6** — Design *commits to* the flagged XSS pattern: "pageData gaining the catalog bytes as `template.JS`" — raw bytes, breaking the existing `template.JS(json.Marshal(...))` discipline (`template.go:18,39`); `error-codes.md` already contains `<`.
- **M5** — Partial only: says "update schema + registry tests" but no named tests, no `operationId ∈ OpenAPI` exception invariant, no schema_version decision (U3).

**Low / in-scope:**
- **P5** (blocks Decision 2 sign-off) — `bearerAuth` "Ed25519-signed JWT" drift not folded into Decision 2.
- **L1** — `buildinfo.Resolve("")` → `(devel)` makes the "empty ⇒ keep spec version" fallback dead; semantics unpinned.
- **L2/L3/L5/L6/L9** — no named tests: recorder concurrency, check-embed fixtures, sdkdiff fingerprint, byte-determinism, `make sdk-changelog` quoting/no-match-exception-fails.

**Owner decisions U1–U5** (stock-deployment scope, request-time toggle semantics, schema versioning, issuer scope, changelog destination): **none recorded** — the design records zero of the five.

## DevOps cross-check

Design-specific deployment impact is zero (no config/state/routes) — consistent. F4 (`sdk-surface-check` runs nowhere in GitHub Actions) is directly relevant to Decision 3's schema extension and is unaddressed; F1/F1b/F2/F3/F5 are pre-existing pipeline/workspace issues outside this design's scope.

## Verdict

The principal review's verdict was "conditionally ready" with three explicit preconditions blocking Decision 1 (H2 fix, U1/U2 decisions, parity re-spec) — and the design has not been amended to meet any of them. Two Highs, five of six Mediums, P5, and U1–U5 are neither resolved nor dismissed with reasons; H1 is contradicted by the code, H2 is missed by the design's stated mitigation, and M6 is adopted verbatim as the insecure pattern. The design must be amended (H1 scope/merge, H2 `GatedRegistrar` delegation + live-predicate recording, M1 gate-aware accessor, M2 three-way parity with machine-readable `check-routes`, M6 `json.Marshal`, P5, U1–U5 recorded) and re-reviewed before implementation.

VERDICT: FAIL - H1 (81-op premise wrong; projection omits 53 live gateway-mux endpoints, no composition merge/scope decision), H2 (recorder breaks GatedRegistrar on nine gated surfaces - wire-visible gating fingerprint), M1 (gate-blind projection advertises 404-ing ops; per-request toggle promise undeliverable), M2 (parity test unsatisfiable as stated, no machine-readable oracle), M3/M4 (named option-toggle and Group-recorder tests absent), M6 (raw template.JS XSS pattern adopted), P5 (bearerAuth drift not folded into Decision 2), U1-U5 owner decisions unrecorded - all block implementation of Decisions 1-3; design must be amended and re-reviewed first.
