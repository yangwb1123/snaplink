# Principal Review: interfaces/apidocs — runtime-faithful projection, contract rendering, bidirectional lockstep

Synthesizes the supplied reviews (architecture, security, QA, identity
protocol) against the design (`docs/auto/interfaces-apidocs-design.md`) and the
tree at commit `9b3b4966`. Advisory only; nothing here binds maintainers or the
release owner. Where reviews conflicted, I re-verified the mechanism against
executable code and state the resolution with its evidence.

## 0. Evidence base and independent verification

Reviews supplied: architecture, security, QA (design-stage testability), and
identity-protocol reviews. All nine of the design's ground-truth facts were
re-verified by the reviewers and hold. I independently re-checked the disputed
points; results:

- **The 81-op gap and its decomposition (Verified by me, recomputed with
  `route_contract.py`'s own functions):** 54 `/api/v1/admin/*` (53 live on the
  admin gRPC-gateway `http.ServeMux`, `cmd/sso-server/build_http.go:97-256`;
  1, `dr/status`, via `Server.Handle`, `build_http.go:60`), 19 SCIM v2, 4
  WebAuthn, 2 `/api/v1/compliance/*` (all via `Server.Handle`), 1 `/branding`,
  1 `/mesh/ext-authz`. Sum = 81. The design's claim that the 81 are
  "documented-but-never-registered" and "stripped automatically by the
  recorder" is **false in both directions** (architecture H1).
- **GatedRegistrar break (Verified by me):** `GatedRouter.register`
  type-asserts `g.inner.(GatedRegistrar)` (`shared/core/router.go:428`); the
  core router's own doc says route-matching-level gating is "REQUIRED, not a
  style choice" because global middleware (Tracing stamps `X-Request-Id`)
  fingerprints gated-off responses before a handler-level check. `Mount()`
  (`server_routes.go:91`) runs `mountMiddleware()` first, so the design's wrap
  precedes all nine `NewGatedRouter` call sites (admin, self-service ×3, OIDC,
  federation, branding, CIBA, CAEP).
- **`buildinfo.Resolve("")` (Verified):** returns `(devel)` in dev builds —
  the design's "empty ⇒ keep spec version" fallback is dead in practice (QA
  F5).
- **`sdk_surface.py` leniency (Verified):** `validate_schema()` is structural
  (header + `schema_version const 1`); no full jsonschema pass; the design's
  "`make ci` fails" claim is overstated (architecture L1), and no registry unit
  tests exist (QA F6).
- **`WithAPIDocsUI` is not wired in `cmd/` (Verified):** only comments and the
  option exist; the blast radius of the two High findings is conditional on
  future stock enablement (architecture I1).
- **`template.JS` discipline (Verified):** today `SpecJSON` is
  `template.JS(json.Marshal(...))` (`template.go:18,39,119`); `error-codes.md`
  contains 9 `<` and 0 `</script>` today. The design's raw-bytes-as-`template.JS`
  plan breaks the existing discipline (security F3).

Baseline gates run by reviewers: `go build ./... && go vet ./...` PASS,
`TestMaintainability_|TestArchitecture_` PASS, `go test ./...` PASS,
`check-routes` PASS (241/322), `sdk-surface check` + `capabilities check`
PASS. Not run at design stage: `-race`, `make ci`, E2E, `check-test` (pytest
missing in the environment — environment gap, not a repo defect; `check-test`
is not a `make ci` prereq, Makefile:244).

## 1. Advisory recommendation

**Conditionally ready (design stage).** The design's mechanics — recorder
placement, fail-safe degradation, bounded vocabulary filter, hash-based embed
check, goccy-over-kin-openapi — are verified feasible and budget-disciplined.
But the design contains one central factual error about its own core premise
(H1), one security-relevant mechanism break (H2), and a cluster of testability
gaps. None is a release blocker (no implementation exists), and all are
fixable with small, local changes.

**Conditions before Decision 1 implementation starts:**
1. H2 fix incorporated into the recorder design (implement `GatedRegistrar` by
   delegation + record the `live` predicate) with the byte-identity regression
   test — same change as the recorder, not later.
2. Owner decisions U1 (is the stock binary a supported deployment for the docs
   UI?) and U2 (does "no 404-ing op" cover request-time feature toggles?)
   resolved and recorded in the design. Recommendation below.
3. Parity-test plan re-specified as the three-way split (H1/M2), with
   `check-routes` gaining machine-readable route output in the same change.

## 2. Consolidated findings

Deduped across the four reviews. Severity per the shared rules; the design
stage means "High" = would-be material failure of the implemented design, not
a live exploit.

### Critical

None. No verified exploit, data-loss path, or hard-gate violation exists at
design stage; all baseline gates pass.

### High

**H1 — The 81-op premise is wrong in both directions; the projection misses 54
live endpoints and wrongly claims to strip 26 (architecture H1; verified
independently).** The 81 are not "documented-but-never-registered": 54 are
live on the admin gRPC-gateway mux (invisible to any `s.router` recorder), 26
are live on `s.router` via `Server.Handle` (SCIM 19, WebAuthn 4, compliance 2,
`dr/status` 1 — these WILL be recorded), 2 are option-gated s.router ops.
A stock server enabling `WithAPIDocsUI` would serve a projected spec missing
54 live endpoints — the mirror-image of the bug being fixed — while the
design's "stripped automatically" framing is vacuous for the 26.
*Impact:* violates the option's documented "full live endpoint + schema
inventory" contract for the stock composition. *Blast radius today:* latent —
`WithAPIDocsUI` is not wired in `cmd/` (I1); embedder-facing only until U1 is
decided. *Fix:* composable projection at the composition boundary — merge
`s.mountedEndpoints()` with `adminGatewayExactPaths()` (+ probes) when the
stock composition wires the option, or explicitly scope the projection to the
SDK router surface and document it. *Validation:* stock-composition fixture —
projected spec contains all 54 gateway paths and no 404-ing op.

**H2 — The recording router silently degrades `GatedRegistrar` on nine gated
surfaces, breaking the byte-identical gating invariant (security F1; verified
mechanically; architecture M3 concurs on the fix, not the severity).**
`GatedRouter.register` type-asserts its inner (`router.go:428`); the
8-method recorder fails the assertion, so every gated mount (admin, self-
service, OIDC, federation, branding, CIBA, CAEP) falls back to
handler-wrapping. `shared/core/router.go` documents route-level gating as
"REQUIRED, not a style choice": with Tracing/request-id middleware on, a
gated-off path then runs global middleware before the 404 and stamps
`X-Request-Id`, making "gated off" distinguishable from "never registered" —
an unauthenticated route-existence oracle, violating the documented
byte-identical invariant that `mountAdminSurface`'s own doc promises.
*Severity conflict:* architecture rates this Low-Med ("no behavior break,
both correct reachability-wise"); security rates High. The core router's own
doc contradicts the arch reviewer's framing — the byte-identical property is
a security invariant ("REQUIRED", not an optimization), and the
`X-Request-Id` fingerprint is wire-visible. **Resolution: High**, with the
arch reviewer's `RegisterGated`-by-delegation fix adopted (both reviewers
recommend the same ~5-line fix; it also yields the live predicate H3/M1
needs). *Precondition:* `WithAPIDocsUI` on + any gate off + tracing on.
*Validation:* `go test ./interfaces/sso/ -run Gated -race -count=10` —
gated-off registered path and unmatched path produce byte-identical
status/headers/body.

### Medium

**M1 — Gate-blind projection advertises 404-ing ops (security F2 + arch M1 +
QA F2; direct conflict resolved below).** Gated families are registered
unconditionally and live-gated (`caepGateOn` etc.); a static recorder
advertises CAEP/SSF/federation/CIBA/admin ops that 404 when the gate is off —
failing the spec's own "no 404-ing op" acceptance at gate granularity. The
design's comment promises "evaluated per request (… dynamic toggles …)" but
its mechanism cannot deliver it. *Conflict:* QA F2 recommends scoping the
acceptance to boot-time option state (registration-based projection is right;
a live-gate consult "makes the projected set flap between requests"); security
and arch recommend filtering the snapshot through the five live gates (~10
lines). *Resolution:* both are satisfiable — with H2's fix the recorder
already has the `live` predicates; `mountedEndpoints()` consults them per
request. Determinism is defined **per fixed gate state** (QA's concern), and
the flapping objection dissolves because the projection is a per-request
artifact; a saved offline copy is a documented snapshot-at-save (gate flipped
after save not reflected — degradation note). Pin both with tests: gate off ⇒
op absent; live toggle ⇒ op reappears without re-Mount; fixed state ⇒
byte-identical repeated projections (QA F12). *Owner:* U2 (product/spec).

**M2 — The parity test is unsatisfiable as stated (arch M2 + QA F1).** A
default-option server records a strict subset of the static set (federation,
CAEP, WASM, v2alpha… register only with options), and the recorder includes
Handle-mounted routes absent from the static set (the checker excludes
composition `Handle` calls). The design's "~15-line accessor + parity unit
test" understates the test cost. *Fix:* three-way split — (1) recorded ⊆
static ∪ Handle-tables (no phantom routes), (2) all-options fixture asserting
recorded ⊇ static, (3) Handle-table parity; and give `check-routes` a
machine-readable route-set output (the parity oracle). QA F1's inverted
`go run` helper pattern is the right mechanism.

**M3 — No named sso-layer option-toggle test (QA F3).** The headline
acceptance (federation off ⇒ op absent; on ⇒ reappears) has no named test
through the real `WithAPIDocsUI` wiring — only apidocs pure-function tests.
*Fix:* in-package `interfaces/sso` test building two option-differing servers,
asserting presence/absence in the served JSON; `-race -count=1`.

**M4 — Recorder `Group` prefix accounting lacks direct unit tests (QA F4).**
The design's own highest-risk item relies solely on the (currently
unspecified) parity test. *Fix:* direct tests for nested groups,
`/api/v1` + `/admin/...` composition, colon paths (`releases:current`,
`:id:pin`), `{param}`↔`:param` normalization per the checker's rule, HEAD/
OPTIONS untouched, `Use`/`ServeHTTP` delegation.

**M5 — sdk-surface registry change: no existing tests, overstated gate claim
(QA F6 + arch L1).** Verified: no `test_sdk_surface.py` exists;
`validate_schema()` is structural; the checker enforces exception
`operationId ∈ openapi_ids` (keep that invariant). The design's "or `make ci`
fails" framing is wrong (L1), but new tests are still required (F6): schema
with `unmountedOperations` validates; exception opId not in OpenAPI ⇒ FAIL;
malformed exception shape ⇒ FAIL. Owner: U3 (additive within `schema_version
1` vs bump — the checker pins the const to 1).

**M6 — Latent script-context breakout: raw catalog bytes as `template.JS`
(security F3; QA F9(4) independently demands the same test).** The existing
`SpecJSON` discipline is `template.JS(json.Marshal(...))`; the design's
"catalog bytes as `template.JS`" breaks it. `error-codes.md` is human-edited
prose with 9 `<` today (no `</script>` yet) and documents HTML-bearing
protocols where a `</script>` in a sample is plausible. Trigger requires a
committed edit that passes CI; if it fires, script execution on
`/api/v1/admin/docs` — same origin as the admin console under the documented
proxy — is an admin-session takeover primitive (attacker D → C). *Fix:* one
`json.Marshal` wrapper, byte-for-byte the SpecJSON pattern. *Validation:*
hostile fixture catalog (`</script><script>window.pwned=1</script>`) renders
inert; nonce attribute assertion reused.

### Low

**L1 — `buildinfo.Resolve("")` returns `(devel)` in dev builds (QA F5;
Verified).** The "empty ⇒ keep spec version" fallback never fires in plain
`go build`; projected `info.version` becomes `(devel)` instead of `0.1.0` in
dev. Defensible, but pin the semantics with a test.

**L2 — Recorder concurrency has no named test (QA F7).** Add
`TestMountedRoutesConcurrentSnapshot` (N `Handle` writers + M snapshot
readers, `-race -count=10`).

**L3 — `check-embed` has no test plan (QA F8).** Fixture tests: embedded bytes
≠ committed file ⇒ FAIL; equal ⇒ PASS; missing target ⇒ clear error.
Document the CRLF handling explicitly.

**L4 — Decision-2 degradation paths under-enumerated (QA F9 minus the escaping
item deduped into M6).** Named tests for: prose tokens never rendering as
codes (`stableErrorCodes` filter), unknown scheme ⇒ "(undocumented scheme)",
nil `ErrorCodes` ⇒ catalog section absent + fallback text, `$ref`-chained
`ErrorResponse` still yields codes, cycle bound. Assertions on `textContent`
only.

**L5 — sdkdiff has no test plan (QA F11).** Fixture-YAML tests for fingerprint
ignoring cosmetic edits, flagging shape changes, operationId rename ⇒ breaking
quote, missing ref ⇒ exit 1.

**L6 — Per-request byte-determinism untested (QA F12).** Go sorts map keys;
pin byte-identical repeated projections (also the memoization baseline).

**L7 — Fingerprint vs renderer sensitivity asymmetry (arch L2).** sdkdiff
strips descriptions; Decision 2 renders them. Consistent by design — document
in the sdkdiff package doc.

**L8 — Projected `info.version` omits revision/dirty (arch I3).** Cosmetic;
optional `-dirty` suffix.

**L9 — `make sdk-changelog` ref interpolation (security F4).** Quote
`OLD=`/`NEW=` in the Makefile target; validate no whitespace. Make a
no-match exception entry (operationId/method/path not in the documented set) a
failure, not an advisory — a typo'd exception silently protects nothing.

### Pre-existing protocol findings (out of this design's scope — separate workstream)

The protocol review surfaced defects in the current server, none introduced or
fixable by this design:

**P1 — `prompt=none` silent renewal bypasses the consent gate (protocol F1,
Medium; Verified).** With a ConsentStore wired, interactive paths return
`consent_required` for uncovered scopes, but silent renewal never consults the
ConsentStore; a revoked consent grant does not stop renewals. Fix is in
`protocols/oidc/handle_silent_renewal.go` + a ConsentStore-wired unit test.
Needs maintainer triage as an independent item.

**P2 — `/end_session` can 302 without terminating anything (protocol F2,
Medium; Verified).** With only `client_id` present, the handler destroys no
session, revokes no token, and still 302s to an allowlisted URI — logout
illusion. Requires an `id_token_hint` (or resolved live session) before
redirecting, or 204. Independent item.

**P3 — Discovery omits wired grants (protocol F3, Low; Verified).**
`grant_types_supported` never includes jwt-bearer/SAML2 bearer even when
wired, while the `unsupported_grant_type` body over-advertises them. Bounded;
independent item.

**P4 — Stale DPoP algorithm comment (protocol F4, Low).** Comment only.

**P5 — `bearerAuth` description says "Ed25519-signed JWT" (`docs/openapi.yaml:
11843-11850`) while the server signs per wired signers (EdDSA/ES256/RS256/
PS256) (protocol F5, Low; Verified).** This one is **in-scope for this
design**: Decision 2 renders that exact description into the admin viewer,
propagating the drift. Fix the description (point at `/.well-known/jwks.json`)
in the same change as Decision 2.

**P6 — Documented BFF deviations (protocol F6, Info).** JSON-only
`/auth/login`, implicit-like `response_type=token` in default mode, discovery
mounted with OIDC gate off. Documented; no action for this design beyond
stating the pre-bind `state`-echo limitation in the OpenAPI description.

## 3. Trade-off ledger

| # | Conflict | Options | Recommendation | Consequence if not chosen | Accountable owner |
|---|---|---|---|---|---|
| T1 | Projection source for the stock composition (H1; arch D1) | (a) SDK-scoped, documented; (b) composition-merged (`adminGatewayExactPaths()` merged into `Projection.Mounted`); (c) gateway mux owns docs routes | **(b)** with (a)'s scope note as documentation regardless | (a) leaves the stock deployment, if enabled, documenting 54 live endpoints as absent — the exact fidelity defect the feature exists to remove; (c) couples an SDK opt-in to the stock gateway | Maintainers / architecture (U1) |
| T2 | "No 404-ing op" semantics: boot-time option state vs per-request live gates (QA F2 vs security F2/arch M1) | (a) boot-time scoping, pinned byte-identity; (b) per-request gate consult | **(b)**, with determinism defined per fixed gate state and saved-copy snapshot caveat documented | (a) fails the design's own comment and the spec's letter for CAEP/SSF/federation when gated off | Product / spec owner (U2) |
| T3 | sdkdiff parser: kin-openapi vs goccy (arch D4) | (a) add kin-openapi to go.mod; (b) reuse goccy | **(b)** — no-new-dependency wins over spec wording (AGENTS.md §4); all four reviewers agree | (a) violates the dependency constraint for this work | Maintainers (agreed; no conflict) |
| T4 | Exception inventory home (arch D5) | (a) `ops/build/sdk-surface.json` schema-extended; (b) separate file | **(a)** — Python-readable, schema-validated, runtime never reads it; L1 means the schema update is hygiene, not a gate requirement | (b) adds a second registry to sync for no benefit | Maintainers (agreed; no conflict) |
| T5 | 81-op triage: judgment work vs machine-derivable | design: "largest single implementation cost, cannot be automated"; arch: 79/81 derivable from `scimRouteTable` + `adminGatewayExactPaths` + Handle call sites | **Bootstrap generator + human review of the 2 option-gated ops**; commit atomically with the reverse check | Hand-triage burns reviewer time on provable facts; un-bootstrapped reverse check wedges `make ci` | Architecture / implementation lead |
| T6 | Registry schema versioning (U3) | additive within `schema_version 1` vs bump | Additive, if the checker's `const 1` stays; decide explicitly | Unstated choice leaves a silent contract change in a pinned registry | Maintainers |
| T7 | Changelog destination (U5) | stdout only vs committed `docs/CHANGELOG-api.md` | Owner decision; if committed, name the regeneration discipline before releases | Committed-but-stale changelog is worse than none | Release owner |
| T8 | Issuer injection scope (U4) | per-request single issuer vs all configured issuers | Per-request (matches `resolveIssuer`/RFC 9207); document the multi-tenant saved-copy limitation | Multi-issuer projection adds tenant-state to a doc that today has none | Product / architecture |

## 4. Preconditions, acceptance checks, rollback, monitoring

### Preconditions before implementation

1. H2 incorporated in the recorder design (implement `GatedRegistrar` by
   delegation; record `(method, path, live)`); byte-identity regression test
   planned. — *Blocks Decision 1.*
2. T1 (U1) resolved: composition-merged projection or documented SDK scope. —
   *Blocks Decision 1 in the stock-enablement case.*
3. T2 (U2) resolved and pinned in the design; the gate-aware accessor planned
   (~10 lines). — *Blocks Decision 1.*
4. Parity test re-specified per M2 with machine-readable `check-routes`
   output. — *Blocks Decision 1's acceptance.*
5. pytest installed for the Python checker tests (environment gap). —
   *Blocks Decision 3 test work only.*
6. T5 bootstrap generator planned; the 81-entry inventory committed atomically
   with the reverse check. — *Blocks Decision 3.*
7. P5 (bearerAuth description) folded into the Decision 2 change. — *Blocks
   Decision 2 sign-off.*

### Executable acceptance checks (at implementation)

- `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .`
- Security validation plan steps 1–6: `-run Gated -race -count=10` byte-identity;
  projection gate-awareness toggle test; hostile-catalog fixture + nonce
  assertion; quoted `make sdk-changelog` fixture; parity + reverse check +
  embed check; full regression (`go test ./... -race`, `make ci`, E2E).
- QA exit criteria 1–6, including: F1 parity green on tree / red on seeded
  mis-accounting; F3 option-toggle test; sdk-surface check green with the
  81-entry inventory; `make sdk-changelog` demoed on two commits; budgets held
  (`server_routes.go` ≤ 500, `interfaces/sso` at 60 files, no exemptions, no
  gate relaxation).
- Design-stage gates that could not run here (no implementation): `-race`,
  `make ci`, E2E — must run at implementation.

### Rollback triggers

- Byte-identity regression test fails (gated-off ≡ never-registered
  fingerprint) — revert the recorder change, not the gate.
- Reverse check red on new drift with no exception landed in the same change —
  the check is the tripwire; do not silence it.
- Projected spec missing gateway paths in a stock fixture (H1) — do not ship
  Decision 1 for the stock composition until merged or scoped.

### Monitoring

- `route-contract` (extended: reverse check + embed check) under `make ci`;
  `sdkdiff` advisory only, never a gate.
- Projection is per-request and admin-gated; no new metrics required beyond
  existing endpoint inventory (`/api/v1/admin/endpoints` discipline matches
  the projection's).

### Explicit exclusions (not this design)

- P1/P2/P3 protocol defects (separate workstreams; maintainer triage).
- SAML nested module, OIDF/FAPI certification, external-RP interop matrix
  (no committed evidence exists; do not claim certification).
- E2E of the viewer (`test/`), `-race`, `make ci` at design stage.
- Dynamic re-Mount of routes after serving starts (out of scope; `Handle`
  after start is supported via the RWMutex snapshot).

### Residual risks (accepted, documented)

1. Legacy first-hop trust with `security.trusted_proxies` unset: projected
   `servers` follows attacker headers — pre-existing, shared with discovery;
   the design reuses `s.resolveIssuer` and does not reimplement proxy handling
   (verified positive control).
2. `check-embed` cannot detect a dirty working tree (binary == tree == PASS;
   disclosed in the design).
3. Reverse check counts option-gated registrations as mounted — by design;
   the runtime projection owns option state, the gate owns existence.
4. `stableErrorCodes` drift from `docs/error-codes.md`: bounded, viewer-only,
   catalog embed authoritative.
5. goccy leniency vs kin-openapi strictness for an advisory changelog; must be
   stated in the sdkdiff package doc.
6. Saved offline copies snapshot the saving request's gate state, issuer, and
   version — documented degradation, not a defect.

## 5. Missing reviews/evidence and next actions to decide

**Missing evidence (unknowns that do not block the design but block release
claims):** implementation does not exist, so `-race`, `make ci`, E2E, and
`check-test` results are unknown for any implemented tree; no OIDF/FAPI
certification evidence exists (verified); SAML nested module behavior
unreviewed at tree level.

**Decisions required (owners named in the ledger):**
1. U1 — stock `cmd/sso-server` a supported deployment for `WithAPIDocsUI`?
   (maintainers/architecture; gates T1/H1).
2. U2 — "no 404-ing op" covers request-time feature toggles? (product/spec;
   gates T2/M1).
3. U3 — `unmountedOperations` additive within `schema_version 1`? (maintainers;
   T6/M5).
4. U4 — single per-request issuer vs all configured issuers in projected
   `servers`? (product/architecture; T8).
5. U5 — changelog destination and regeneration discipline (release owner; T7).

**Narrow next actions:**
1. Record U1–U5 decisions in the design and amend Decision 1 with the H2 fix,
   the T1 merge (or scope note), and the M1 gate-aware accessor.
2. Replace the parity-test paragraph with the M2 three-way split and add the
   `check-routes` machine-readable output to Decision 3's change set.
3. Fold P5 into the Decision 2 change set.
4. Re-run this review against the amended design before implementation;
   then run the full gate suite (`go test ./... -race`, `make ci`,
   `go test ./test/ -run TestE2E -v`) on the implemented tree.
5. Open separate work items for P1/P2/P3 protocol findings with their
   executable validation tests.
