# Protocol Review: interfaces/middleware chain design

Reviewer: identity-protocol expert (per `ai-dev/prompts/protocol_expert.md` +
`ai-dev/prompts/README.md`). Reviewed revision: `cde984d6` ([pi-batch]
Stage: design) with the uncommitted batch worktree. Checks actually run:
`go build ./...` (pass), `go vet ./...` (pass),
`go test -run 'TestMaintainability_|TestArchitecture_' .` (pass). The full
suite and `make ci` were NOT run — the design is not implemented, and this
review is advisory only (it modifies no files except this report).

Input: `docs/auto/interfaces-middleware-design.md` — a typed named-slot
`middleware.Chain` refactor of the `interfaces/sso` HTTP middleware stack.
The design touches no request binding, client authentication, redirect,
token/claim, discovery-content, or replay-store code; its protocol surface
is (a) middleware ORDER around the OAuth/OIDC/CAEP/SAML/SCIM endpoints,
(b) correlation headers on rejection paths, (c) the idempotency-after-auth
invariant, and (d) an SDK surface removal (`sso.AuthMiddleware`, `sso.CORS`).

## 1. Protocol/profile scope and authoritative references

| Scope | References | Relevance to this design |
|---|---|---|
| OAuth 2.0 core | RFC 6749 §3.2 (client auth), §5.1 (no-store on credential responses), §5.2 (error responses) | Chain order must not strip/adjust the handler-set `Cache-Control: no-store`; error bodies must stay byte-stable. |
| OAuth 2.0 Security BCP | RFC 9700 §3.1 (brute-force protection), §4.1 (URI validation) | Rate-limit position and keying (validated client IP, never forgeable input). |
| OAuth 2.0 Threat Model | RFC 6819 §4.4.1 (online guessing), §4.6.1 (DoS) | Rate-limit outside degradation; probes exempt; body limit before handler. |
| Forwarded headers | RFC 7239 §7.1 (X-Forwarded-For); peertrust walk | TrustedProxies-before-RateLimit ordering invariant. |
| OIDC Core / Discovery | OIDC Core 1.0 §3.1.2.6, Discovery 1.0 §4 | Discovery route/content untouched; only its position in the chain (unchanged) matters. |
| W3C Trace Context | W3C Trace Context Level 1 (`traceparent` format) | The relocated Tracing slot's format handling is unchanged. |
| HTTP semantics | RFC 9110 §10.2.2 (Retry-After), RFC 8594 (Sunset/Deprecation), RFC 9111 (caching) | 429/503/413 shapes and Retry-After preserved; Deprecation-outside-AcceptVersion pair preserved. |
| Idempotency extension | `draft-ietf-httpapi-idempotency-key-header` (reference only; not a published RFC) | Post-auth replay invariant; not a protocol MUST. |
| Feature-gate oracle safety | AGENTS.md §3 table ("identical 401/404 surfaces"); admin gate byte-identity | The design's Tracing relocation changes what headers gated-off routes carry. |
| OIDF certification | none claimed | No published OIDF result exists for this project; none asserted. |

Profile notes: the stock binary (`cmd/sso-server`) keys rate limits by
validated client IP (`KeyByClientIP`); the legacy Basic-username keying
(`KeyByClientIDOrIP`) is SDK back-compat only and is documented as unsafe
(`interfaces/ratelimit/middleware.go:58-75`) — the design's slot order
protects the keying the binary actually uses.

## 2. Compliance matrix

Verified against executable code; every row cites the evidence symbol.

| # | Section / requirement | Level | Implementation evidence | Status | Deviation / note | Test |
|---|---|---|---|---|---|---|
| 1 | RFC 6749 §5.1 — credential responses carry `Cache-Control: no-store` + `Pragma: no-cache` | MUST | `tokenNoStoreHeaders` set at the TOP of `handleToken` (`interfaces/sso/server_token.go:21`), before `beginTokenIdempotency`; `middleware.TokenNoStoreHeaders` (`interfaces/middleware/no_store.go:22-39`). SecurityHeaders slot stays innermost-of-chain, so no chain reorder can overwrite no-store. | **Verified — preserved** | Replayed idempotency 200s also carry no-store because the header is set before the replay short-circuit. | existing token tests; design leaves capture path untouched |
| 2 | RFC 6749 §5.2 — error responses carry `error` param; fixed bodies | MUST | 429 body `{"error":"rate_limited"}` (`interfaces/ratelimit/consts.go:22`), 503 `{"error":"service_degraded","mode":...}` (`interfaces/middleware/degradation.go:69-81`), 413 `payload_too_large` (`docs/error-codes.md:921-939`). All fixed, all written by middlewares whose code the design does not modify. | **Verified — preserved** | Only ADDED correlation headers on these paths (see finding F1/F4). | `test/ratelimit_e2e_test.go`; `interfaces/sso/degradation_test.go` |
| 3 | RFC 9700 §3.1 / RFC 6819 §4.4.1 — brute-force protection keys on unforgeable input | MUST (BCP) | `KeyByClientIP` → `middleware.RealClientIP` (`interfaces/ratelimit/middleware.go:77-92`); value comes from TrustedProxies context, fallback `RemoteAddr` (`interfaces/middleware/trusted_proxy.go:156-165`). Design keeps TrustedProxies outside RateLimit. | **Verified — preserved** | Swapped order keys on RemoteAddr: unforgeable but collapses all proxy-behind traffic into one bucket (availability, not credential, risk) — see finding F3. | design invariant test (a); `ratelimit_test.go:198` |
| 4 | RFC 7239 §7.1 — XFF processed right-to-left from trusted peer | SHOULD | `TrustedProxies.resolve`/`walkChain` (`interfaces/middleware/trusted_proxy.go:64-135`), hops budget. Slot position unchanged. | **Verified — preserved** | — | `interfaces/middleware/forwarded_trust_test.go` |
| 5 | RFC 9700 / ops invariant — probes outside rate limiting | MUST (AGENTS.md) | `buildProbeMux` outside chain (`interfaces/sso/server_routes.go:475-485`); design mirrors byte-for-byte in `WithProbes`/`Wrap`; `/livez`+`/readyz` always registered. | **Verified — preserved** | Empty probe map → no mux (production always registers both). | `test/ops_test.go`; `test/ratelimit_e2e_test.go` (metrics never 429) |
| 6 | OIDC Discovery — metadata content and caching | MUST (Discovery 1.0 §4) | `mountDiscovery` (`interfaces/sso/server_discovery.go:26`) inside router; design does not move it. | **Verified — preserved** | — | `rootcov2_discovery_test.go` |
| 7 | RFC 8594 / ADR-0008 — Sunset/Deprecation ordering | SHOULD | `wrapAPIVersioning` (`interfaces/sso/sso_wiring.go:407-420`): Deprecation wraps OUTSIDE AcceptVersion; design composes the pair into the single AcceptVersion slot. | **Verified — preserved** | Design's printed slot list ("AcceptVersion") hides the pair; composition site must keep Deprecation outermost (it does). | `api_versioning_test.go` |
| 8 | Feature-gate oracle — gated-off route byte-identical to never-mounted path | MUST (AGENTS.md §3) | `core.GatedRouter` route-matching-level gate (`shared/core/router.go:257-264`); `feature_gate_hotreload_test.go` pins byte-identity with Tracing wired. | **Partially preserved — tests break** | Invariant survives (both classes of path get identical chain treatment) but the tests encode the OLD mechanism (header absence). 8 absence assertions + 6 value-exact comparisons fail. | **F1, HIGH** |
| 9 | Replay controls — idempotent `/token` replay only after client authentication | MUST (oracle-safety) | `beginTokenIdempotency` after `authenticateTokenClient` + grant-type rejection (`interfaces/sso/server_token.go:50-99`); key = fingerprint(clientID, params, DPoP JKT, mTLS x5t); single-flight mutex. Generic `middleware.Idempotency` has zero production call sites (grep-verified). | **Verified — preserved** | Design test (d) pins a documented-but-unenforced contract; correct framing. | design invariant test (d) |
| 10 | W3C Trace Context — traceparent format + span chaining | SHOULD | `middleware.Tracing` (`interfaces/middleware/middleware.go:80-135`) preserves incoming trace, `audit.NewTracer` formats v00. Relocation does not alter format logic. | **Verified — preserved (coverage widened)** | Request-ID stamping moves from inside the router to slot 2; see F1/F4. | `test/middleware_test.go` Tracing tests (migrate to httptest) |
| 11 | RFC 6749 §3.2 / §2.3.1 — HTTP Basic precedence over body credentials | MUST | `authenticateTokenClient`/`bindOAuthParams` — handler-level, untouched by design. | **Verified — preserved** | — | `rootcov2_handlers_test.go` etc. |
| 12 | Error responses on credential endpoints incl. 401 challenges | MUST | `tokenNoStoreHeaders` applies regardless of status (`interfaces/middleware/no_store.go:31-38`). Chain unchanged. | **Verified — preserved** | — | existing handler tests |
| 13 | Chain slot order = documented order (metrics counts 429s; rate-limit outside degradation; degradation outside body-limit) | MUST (AGENTS.md documented order) | Current order verified from `buildMiddlewareChain` + `wrapInnerMiddlewares` (`server_routes.go:362-421`): Recover → OTel → Metrics → TrustedProxies → RateLimit → Degradation → Deprecation → AcceptVersion → BodyLimit → Compression → CORS → SecurityHeaders → RequestLog → Router. Design's 12-slot list matches. | **Verified — preserved** | `docs/observability.md:97-99` stack diagram is ALREADY drifted (says `tracing → ratelimit → bodyLimit → metrics → CORS`) and the design does not plan its rewrite. | **F2, MEDIUM** |
| 14 | SDK surface removal (`sso.AuthMiddleware`, `sso.CORS`) | profile decision | Zero production call sites besides `aliases.go:43-44` (grep-verified; only a doc comment in `interfaces/cors/cors.go:5`). | **Verified** | Stale doc reference in `interfaces/cors/cors.go:5` must be updated in the same change (AGENTS.md §5.6). | grep; feature matrix update planned |

## 3. Findings

### F1 — HIGH, requirement: AGENTS.md §3 oracle-safety (regression-boundary), design completeness
**Location:** `docs/auto/interfaces-middleware-design.md` "What could break the design" (risk register) vs
`interfaces/sso/feature_gate_hotreload_test.go`.
**Evidence (Verified):** the design's Tracing slot (request-ID + W3C) moves from `router.Use`
(`server_routes.go:113`) to chain slot 2, outside the router. `feature_gate_hotreload_test.go`
contains 8 header-absence assertions (`leaked X-Request-Id` at lines 175-176, 183-184, 212-213,
256-257, 294-295, 347-348, 396-397, 470-471) across 6 gate tests
(admin_api, branding, oidc, ciba, caep, federation, self_service), all wired with
`WithTracingMiddleware()`. After the change, both the never-mounted baseline
(`/definitely-not-a-real-route`) and every gated-off path carry
`X-Request-Id`/`traceparent`/`X-Trace-Id`; the baseline sanity check itself fails, and the
`fghrAssertIdentical` value comparisons fail because `X-Request-Id` is random per request
(`crypto/rand`, `middleware.go:146-155`). The design's risk register names only
`health_test.go:121` and `test/middleware_test.go`; its verification commands
(`-run 'Chain|Idempotency|Probe|RateLimit|Degradation'`) would not run these tests, so the
design would fail `make ci` silently late.
**Interoperability/security impact:** None to the protocol invariant — gated-off and
never-mounted paths still receive byte-identical treatment (both get the same header set), so
the oracle survives; the breakage is test-mechanism only. However, the design's own behavior
delta list (429/503/413) is incomplete: 404s on never-mounted paths and CORS preflight 204s
are also newly header-carrying.
**Corrective behavior (required):** (1) Add this test file to the risk register and to the
verification command list. (2) Specify the rewrite: drop the header-absence assertions;
normalize random correlation headers (X-Request-Id, traceparent, X-Trace-Id) in
`fghrAssertIdentical` (compare header SET with the three stripped, or assert both present);
the byte-identity of the remaining headers/status/body stays. (3) State the semantic flip in
release notes: every response — including 404s — now carries correlation headers; this is the
same delta family as the design's 429/503/413 note.
**Validation:** `go test ./interfaces/sso/ -run 'TestSet.*GateEnabled.*(Tracing|ByteIdentical)' -count=1`
must pass after the rewrite; the design's invariant test (c) already covers probe bypass.

### F2 — MEDIUM, requirement: AGENTS.md §5.6 contract-updates-in-same-change; documentation accuracy
**Location:** `docs/observability.md:97-99`; `interfaces/cors/cors.go:5`.
**Evidence (Verified):** observability.md's middleware-stack diagram
(`tracing → ratelimit → bodyLimit → metrics → CORS → router`) does not match the current code
(metrics is OUTSIDE ratelimit; trusted-proxies/degradation/versioning/security-headers/
request-log slots are unlisted) and will drift further once the chain lands. The design plans
feature-matrix + release notes but never mentions observability.md. `interfaces/cors/cors.go:5`
doc-comments the legacy `sso.CORS` that the design deletes — a stale cross-reference after the
change.
**Impact:** operators debugging "why did my 429 have no trace_id" or trust-chain questions get
a wrong map; the doc claims Tracing outside ratelimit (true after, false today for request-ID —
today Tracing is inside the router).
**Corrective behavior (required, cheap):** rewrite the stack diagram in the same change to the
canonical 12-slot order + probe mux; drop or reword the `sso.CORS` reference.
**Validation:** `grep -rn "sso.CORS" docs/ interfaces/` returns no stale references; the diagram
matches `chain.SlotOrder()`.

### F3 — LOW, requirement: BCP accuracy of the design's own test rationale
**Location:** design invariant test (a) rationale; `interfaces/ratelimit/middleware.go:58-91`.
**Evidence (Verified):** with TrustedProxies unwired or mis-ordered, `RealClientIP` falls back
to `RemoteAddr` — the direct TCP peer. That value is unforgeable, so a slot swap is NOT a
credential-bypass path; the actual harm is availability/correctness: every client behind a
trusted proxy collapses into one bucket (global throttle), and per-IP throttling of
credential-stuffing (RFC 9700 §3.1) is lost. The invariant test is right; its framing should
say "availability + correct bucketing", not imply forgery.
**Corrective behavior (optional):** tighten the test's doc comment; no code change.
**Validation:** none needed beyond the design's test (a).

### F4 — LOW, requirement: observability consistency (docs/observability.md:105-108)
**Location:** `interfaces/ratelimit/consts.go:22`, `interfaces/middleware/degradation.go:78-82`,
`internal/handler` body-limit 413.
**Evidence (Verified):** after the delta, 429/503/413 responses carry `X-Request-Id`/
`traceparent`/`X-Trace-Id` but their JSON bodies are fixed strings with no `trace_id`, while
observability.md says error responses surface `trace_id` in the JSON body. Not an RFC violation
(RFC 6749 §5.2 requires only `error`); a consistency gap.
**Corrective behavior (optional):** after the chain lands, consider threading the (now
available) trace ID into the three fixed rejection bodies; if declined, document the
exception in observability.md.
**Validation:** a test asserting `X-Request-Id` presence on 429/503/413 pins the delta (see
§4, item 6).

### F5 — INFO: `FromCore` adaptation detail
**Location:** design `FromCore` spec; `shared/core/router.go:103, 262-277`.
**Evidence (Verified):** `NewContext(w, r)` shares the request pointer with the chain's
handler, and `core.MiddlewareFunc`s mutate the request in place (`*r = *r.WithContext(...)`),
so passing either `r` or `ctx.Request()` to `next` is equivalent — no bug. Note for the
implementer: `FromCore` has no production consumer in the design (tenant/geo/region stay on
`Router.Use`); keep it exercised by a unit test to prevent rot.

### F6 — INFO: no certification claims
The design and this repo claim no OIDF certification; `test/oidc-conformance/results/` holds a
local conformance-run log only. Nothing in this design affects certification evidence one way
or the other (no endpoint/claim/discovery change).

## 4. Priority conformance tests, unsupported features, certification evidence

**Priority tests for the change (in order):**
1. Rewrite the 6 Tracing-wired gate tests in `interfaces/sso/feature_gate_hotreload_test.go`
   (F1) — this is the only hard gate-blocker found.
2. Design's four ordering-invariant tests (a)-(d) + `TestChain_CanonicalSlotOrder`,
   including the negative controls (deliberate slot swap fails).
3. Migrate `interfaces/sso/health_test.go:121` and the Tracing/Logger tests in
   `test/middleware_test.go` to `httptest.NewRecorder()` + `ServeHTTP`.
4. Keep green: `rate_limit_hotreload_test.go` (SetRateLimitPolicy swap),
   `test/ops_test.go` + `test/ratelimit_e2e_test.go` (probe bypass),
   `test/cors_e2e_test.go` (preflight inside metrics/ratelimit).
5. `grep` acceptance from the design: no `wrap*`/`buildProbeMux` survivors outside
   `buildChain`; `interfaces/middleware` non-test count stays ≤ 10; `core.MiddlewareFunc`
   only in `FromCore`.
6. NEW test to pin the intended delta: 429/503/413 (and unmatched-path 404) responses carry
   `X-Request-Id`/`traceparent` after the change, while panic 500s (Recover outermost) do not.

**Declared unsupported / out of scope (design + this review agree):** no change to request
binding, client authentication, redirects, token/claim projection, discovery content, replay
stores, or degradation policy; no new endpoint/config/Err*; no caching of the chain on
`Server` (per-call `Handler()` reconstruction, including `rateLimitStore` recreation, is
preserved byte-identically).

**Certification evidence:** none claimed; none available (no published OIDF result). The
OIDC/CAEP surfaces are unaffected by this refactor, so no certification delta arises.
