# Security review — interfaces/cors direction 2 (config-surface completeness)

Reviewer: principal security engineer (advisory only; no files modified).
Reviewed revision: HEAD at review time. Design under review:
`docs/architect-analysis/auto/interfaces-cors-direction2-design.md` (D1 path
overrides, D2 contract docs, D3 header-append semantics).

Scope: the three config-surface decisions only. The design claims "no security
semantics change"; this review tests that claim against the middleware, the
login-origin gate, the wiring chain, and the new operator-reachable surface.

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Where | Integrity/confidentiality relevance |
|---|---|---|
| CORS policy state | `config.CORSConfig` → `cors.Policy` (`interfaces/cors/cors.go:42-66`) → precomputed `corsConfig` | Integrity: determines which origins may read responses via browser JS |
| Per-path override map | `cors.Policy.PathOverrides` (`cors.go:58-65`) + D1 `CORSConfig.PathOverrides` | Integrity: new operator-reachable per-path policy split |
| Preflight/actual response headers | `writeCommonHeaders`/`writePreflight` (`cors.go:126-160`) | Confidentiality of response readability; Vary/Origin cache keys |
| Boot log | `cmd/sso-server/build_app_security.go` wiring log | Audit of applied policy |
| Config load validation | `LoadFromSources` chain (`config/config_load.go:56-63`) | New fail-loud boundary for D1 |
| Login origin gate | `sso.isOriginAllowed` (`interfaces/sso/origin_validation.go:103-121`) + `rejectDisallowedLoginOrigin` (`server_login.go:166-181`) | Defense-in-depth CSRF gate on `/auth/login`; reads **top-level** `AllowedOrigins` only |

### Trust boundaries

1. **Operator config (trusted) → validated config**: `LoadFromSources` — the
   only new validation boundary D1 adds. All new abuse cases in this review are
   operator-misconfiguration reachable, not attacker-reachable.
2. **Untrusted request → middleware**: `Origin` header, `Access-Control-
   Request-*` headers, and `r.URL.Path` are fully attacker-controlled inputs to
   `resolveCORSConfig`/`originAllowed` (Verified, `cors.go:165-200`).
3. **Middleware → handlers**: CORS never blocks request execution; it only
   gates header emission. Handlers remain the real authorization boundary.

### Attacker capabilities

- **Network attacker (unauthenticated)**: can send arbitrary paths, `Origin`,
  `Access-Control-Request-Method/Headers` to every mounted route (probes
  excepted).
- **Malicious web origin**: can drive a victim's browser to issue cross-origin
  requests; can read responses only when ACAO permits; can attach browser-
  ambient credentials only when allowed.
- **Misconfigured operator** (the new surface's primary risk): can now express
  per-path policies that were previously global-only.

### Entry points

- Every HTTP path through `cors.Middleware` — mounted at the single production
  site `interfaces/sso/server_routes.go:452`, inside ratelimit/trusted-proxies/
  metrics/tracing, outside security-headers and the router (Verified,
  `server_routes.go:359-398`). Probes (`/livez`, `/readyz`, `/metrics`) are
  outside the chain (Verified, `server_routes.go:474+`, `buildProbeMux`).
- Boot-time config load (`config.LoadFromSources`, `cmd/sso-server` gate at
  `build_app_security.go:170`, `config/config_load.go:315`).

## 2. Findings

### F1 — Medium — `enabled: false` override entries remain active (silent misconfiguration trap)

- **Evidence**: D1 maps `CORSConfig.PathOverrides map[string]CORSConfig` and
  `toPolicy()` does not carry `Enabled` into `cors.Policy` (Verified: current
  `toPolicy` at `config/config_load.go:472-480` maps six fields; `cors.Policy`
  has no Enabled field, `cors.go:42-66`). The design (D1 failure-mode table)
  states `enabled:false` entries "仍生效" and only documents the trap.
- **Preconditions**: operator adds a permissive override (e.g. `*` on
  `/.well-known/jwks.json`), then tries to disable it by setting
  `enabled: false` — the natural mirror of the top-level semantics where
  `enabled:false` disables CORS (`config_load.go:315`, `build_app_security.go:170`).
- **Steps**: `security.cors.path_overrides: {"/x": {enabled: false,
  allowed_origins: ["*"], allow_credentials: true}}` → loads cleanly → the
  permissive policy stays live on `/x`.
- **Impact**: operator believes a path is locked down when it is not. The
  direction's own principle ("反对静默丢弃") is violated by an ignored field
  that reads like a kill switch. Exploitability is one mis-saved YAML away;
  worst realistic case is a credentialed echo-origin policy left live on a
  path the operator intended to be CORS-free.
- **Remediation (required before merge)**: validate at `LoadFromSources` —
  reject any override entry with `enabled: false` (fail loud), and state in
  the D2 doc row that entries are active by presence; `enabled` is not a
  per-entry switch. This is 5 lines in `validate()` and consistent with D1's
  `/`-prefix fail-loud rule.
- **Regression test**: config test — YAML with an `enabled:false` override
  entry must fail load; YAML with only `enabled:true`/omitted entries must
  load and map.

### F2 — Medium — equal-length prefix nondeterminism becomes operator-reachable (cross-replica policy divergence)

- **Evidence**: `buildOverrideConfigs` (`cors.go:180-196`) sorts by length
  descending with a strict `>` swap — equal-length prefixes keep map-iteration
  order, which Go randomizes per process. Verified by reading; `cors_test.go`
  has **zero** coverage of `buildOverrideConfigs`/`resolveCORSConfig` today
  (grep for `Override` in `interfaces/cors/cors_test.go` returns nothing). The
  design correctly labels this pre-existing and operator-unreachable until D1.
- **Preconditions**: D1 ships as designed; operator configures two equal-length
  conflicting prefixes (e.g. `/admin/a` permissive, `/admin/b` strict — both
  length 8).
- **Steps**: same YAML on two replicas → different winners per replica →
  identical request path gets different CORS headers depending on which
  replica answers.
- **Impact**: a security-relevant control (per-path origin allowlist) becomes
  nondeterministic across replicas and restarts; flaky preflight behavior and
  cache divergence. This is exactly the "config means the same thing
  everywhere" invariant multi-replica deployments depend on.
- **Remediation (required, not optional — the design's "若不动，必须文档写明"
  fallback is insufficient once the surface is operator-reachable)**: add the
  secondary sort key (prefix string descending) in `buildOverrideConfigs`
  (~4 lines) and pin it with a middleware test. The design already recommends
  this; elevate to in-scope.
- **Regression test**: unit test feeding a map with equal-length prefixes
  (`map[string]cors.Policy{"/admin/a": …, "/admin/b": …}`) — assert the same
  winner over repeated constructions and a deterministic sorted order; plus a
  longest-prefix-wins test (`/token/x` override beats `/token`).

### F3 — Low — prefix matching traps: `/token` bleeds into `/token/…`, `/tokenizer`-style paths; a trailing-slash key misses the exact path; `//token`-style paths dodge the override (cleared)

- **Evidence**: `resolveCORSConfig` (`cors.go:198-203`) matches raw prefix on
  `r.URL.Path`; `/token` matches `/tokenizer`; key `/token/` does **not**
  match the exact path `/token`. All Verified.
- **Impact**: operator-intended per-path tightening silently not applied to
  the intended path (or applied more broadly than intended). Note the
  "dodge" variant is **cleared**: `NewStdRouter` wraps `http.NewServeMux()`
  (Verified, `shared/core/router.go:187-192`), which 301-normalizes `//token`
  before handler dispatch; the follow-up request carries the override policy,
  and the 301 itself is unreadable to cross-origin JS. No handler-reachable
  path escapes the override.
- **Remediation**: doc pins only (D2 row): recommend whole-path keys; state
  that matching is case-sensitive, prefix-based, and raw (decoded) `URL.Path`.
  No code change — matching semantics are out of scope by design and
  changing them would break the "no middleware semantics change" contract.

### F4 — Low — preflight 204 oracle on override paths leaks policy surface

- **Evidence**: preflights to an overridden path short-circuit with 204 +
  override headers before routing (`cors.go:151-158`); a non-overridden path
  returns the router's 404/405 without override headers.
- **Preconditions**: none (unauthenticated).
- **Steps**: attacker sends `OPTIONS <candidate-prefix>` +
  `Access-Control-Request-Method: POST` + arbitrary `Origin`; observes 204 +
  ACAO (override present and permissive) vs router 404/405.
- **Impact**: config-surface disclosure (which prefixes are overridden, with
  what origin posture). No credentials or user data; preflights are
  rate-limited (CORS sits inside `ratelimit.DynamicMiddleware`, Verified
  `server_routes.go:359-398`). Bounded, accepted residual risk; no code
  change. Optionally note in docs that override prefixes are externally
  observable.

### F5 — Low — D3 changes `cors.Policy.AllowedHeaders` semantics for direct SDK callers (replacement → merge)

- **Evidence**: `buildConfig` (`cors.go:78-103`) is shared by the config path
  and `sso.WithCORS(cors.Policy{…})`; in-tree production callers are exactly
  two (Verified: `config/config_load.go:316`, `cmd/sso-server/build_app_security.go:171`,
  plus the mount at `server_routes.go:452` — no other `cors.Policy{`/`cors.Middleware(`
  construction sites in the root module). `cors_test.go:140` encodes the old
  replacement contract (`"X-Custom, Authorization"`) and will fail after D3 —
  the design correctly requires the same-commit update.
- **Impact**: external SDK users who set `AllowedHeaders` to *restrict*
  preflight advertisement silently start advertising defaults ∪ configured.
  Security impact is minimal — the preflight echo is an advertisement, not a
  server-side allowlist; the server never rejects requests carrying non-
  advertised headers — but it is a wire-visible behavior change on a public
  API. The design flags it as intentional and provides the
  `AllowedHeadersExclusive` escape hatch; keep that, and keep the
  case-insensitive, order-preserving, first-occurrence dedup (deterministic
  seen-set + slice — a map-iteration join would reintroduce F2's flakiness
  class).
- **Regression tests**: merge case (defaults first, `authorization` lowercase
  input deduped, empty/whitespace entries skipped), exclusive case
  (`"X-Custom, Authorization"` preserved), and update `cors_test.go:140`.

### F6 — Info — `/auth/login` origin gate ignores path overrides (document, do not "fix")

- **Evidence**: `rejectDisallowedLoginOrigin` (`server_login.go:166-181`) and
  `isOriginAllowed` (`origin_validation.go:103-121`) read only
  `s.corsPolicy.AllowedOrigins` — the top-level list — never
  `PathOverrides`. Only `/auth/login` invokes the gate (`server_login.go:30`).
- **Implication**: an override cannot widen or narrow the login CSRF gate —
  good (defense-in-depth preserved; D1 cannot weaken it). But an operator who
  tightens `/auth/login` via an override to block a hostile origin will find
  the login handler still accepts it (CORS never blocks execution; only
  response readability). The D2 doc row must state: *path overrides are
  middleware-layer only; the `/auth/login` origin gate follows the top-level
  `allowed_origins`*.

### F7 — Info — grep-ruling hygiene for the X-RateLimit-Remaining acceptance

- **Evidence**: the string exists in `cors.go:44`, `cors_test.go:193,202`
  (Verified) and in historical analysis/results/proposal docs (Verified,
  `docs/requirements/*`, `docs/results/PEER_REVIEW_*`, `docs/architect-analysis/*`,
  `docs/proposals/requirements.md`). The design's ruling — enforceable scope =
  `*.go` (minus `dist/`) + the five contract docs — is sound; the historical
  docs record the drift and must not be rewritten. Note that the spec and the
  design doc themselves contain the string (they document the drift), so the
  scoped grep must explicitly exclude `docs/architect-analysis/` (incl. the
  `docs/auto` symlink) — which the ruling already does; state it verbatim in
  the commit message. Also verified `interfaces/ratelimit` emits only
  `Retry-After` (`interfaces/ratelimit/consts.go:8`), so the replacement
  examples `X-Request-Id`/`Retry-After` (`shared/core/consts_wire.go:21,31`)
  are real. (Design's `consts_wire.go:24` for `Retry-After` is off by a few
  lines; symbol and value are correct.)

## 3. Abuse-case table

| Abuse case | Reachable? | Path | Outcome / notes |
|---|---|---|---|
| Identity spoofing via forged `Origin` | No (unchanged) | Attacker sends `Origin: https://victim-app.example` | Only affects header emission; CORS is not an authentication boundary; no identity claim is derived from `Origin`. `/auth/login` gate is defense-in-depth and unchanged |
| Replay of preflight / response | No (new) | Replay `OPTIONS`+`ACRM` | Stateless 204 echo; `Max-Age` caching is browser-side; no token or session involvement |
| Cross-tenant access via override | No | Permissive override on `/api/v1/admin/…` or `/me/…` | All data endpoints are bearer-gated (`admin:read`/`admin:write`, user tokens); CORS headers cannot bypass authorization. Tenant isolation untouched (D1 touches no authn/authz code) |
| Proxy/header forgery (XFF, `X-Forwarded-*`, mesh `X-Auth-*`) | No | — | CORS consumes none of these; `trustedProxies` order in `buildMiddlewareChain` unchanged (Verified, `server_routes.go:359-398`) |
| Override-dodge via path tricks (`//token`, `/.//token`, encoded separators) | **Cleared** | `resolveCORSConfig` on raw `URL.Path` | `http.ServeMux` 301-normalizes before dispatch; final handler response always carries the override policy; the 301 hop is unreadable to cross-origin JS (see F3) |
| Resource exhaustion (preflight flood on override paths) | Bounded | `OPTIONS`+`ACRM` to any override prefix | 204s are inside ratelimit (per-IP, `KeyByClientIP`); `buildOverrideConfigs` is O(n) once at construction; per-request override scan is O(#overrides), operator-bounded; probes outside the chain unaffected |
| Sensitive-data leakage via permissive override | Low, operator-gated | `*` + `allow_credentials:true` echo-origin on any path | Server has no browser-ambient credentials on API endpoints — the only cookie is the OIDC session-management cookie, `Secure` + `SameSite=None` but **Path-scoped to `/check_session_iframe`** (Verified, `server_userinfo.go:60-74`), a static page; all data endpoints need bearer tokens the attacker page does not hold. Residual risk = misconfiguration, addressed by F1/F2/F3 remediation |
| Login CSRF via override on `/auth/login` | Not new | Override cannot widen the login origin gate (top-level list only) | Positive control; document per F6 |
| Silent disable of a permissive override | **Yes (new)** | `enabled:false` entry stays live | F1 — Medium, fix in `validate()` |
| Nondeterministic policy across replicas | **Yes (new)** | Equal-length prefix tie | F2 — Medium, fix in `buildOverrideConfigs` |
| Config-surface probing | **Yes (new, bounded)** | Preflight oracle | F4 — Low, accepted |

## 4. Positive controls verified, residual risks, validation plan

### Positive controls (all Verified against source at review time)

1. **Single production mount point**: `cors.Middleware` at
   `server_routes.go:452` only; policy precomputed once at construction; zero
   per-request merge cost (D3 claim confirmed).
2. **Two-site gate relaxation is complete and convergent**: `config_load.go:315`
   and `build_app_security.go:170` are the only two `WithCORS` call sites in
   the root module; both will call the same `toPolicy()` post-D1, so the
   pointer-overwrite order (`ServerOptions()` at `build_app_core.go:154`,
   then `wireMTLSLockoutProxiesCORS()` at `build_stores.go:259`; options
   applied in order at `sso.go:82`) becomes immaterial. Last-wins overwrite
   of the same value = no drift.
3. **Login-origin gate independent of overrides** (`origin_validation.go:103`,
   `server_login.go:166`): D1 cannot widen the `/auth/login` CSRF gate; only
   top-level `allowed_origins` governs it. The design's "no security semantics
   change" claim holds for the middleware, and the handler gate is strictly
   stronger than the middleware.
4. **Middleware chain order preserved**: CORS inside ratelimit/degradation/
   body-limit (preflight flood protection, refusals before body read), probes
   outside; `Vary: Origin` on CORS responses; `no-store`/bearer-challenge
   invariants untouched (no credential-endpoint changes in scope).
5. **No new attack surface in storage/crypto/authn**: D1/D2/D3 introduce no
   new `Err*`, endpoints, packages, secrets, or key material;
   `docs/error-codes.md` and `docs/openapi.yaml` correctly untouched.
6. **`cors → shared/core` import is acyclic**: `go list` on `shared/core`
   shows stdlib-only imports (Verified); `NewStdRouter` already lives in
   `shared/core`, so the layer test will not need exemptions.
7. **Budgets**: `wireMTLSLockoutProxiesCORS` is exactly 50 lines today
   (Verified) — the inline-literal → `toPolicy()` replacement is net-negative
   lines; `config/` file count frozen (26 non-test files, Verified);
   `interfaces/sso` at 60 files (Verified) with zero production changes
   planned. All sustainable.
8. **Gates green at HEAD**: `go build ./...`, `go vet ./...`,
   `go test -run 'TestMaintainability_|TestArchitecture_' .` all pass at the
   reviewed revision — no pre-existing failures to report.

### Residual risks (accepted, documented)

- Operator misconfiguration is the dominant risk class; F1/F2/F3 mitigation
  must land in the same change as D1 (not follow-on).
- Override prefixes are externally observable (F4) — bounded, rate-limited.
- External SDK users outside this repository may be affected by D3's merge
  semantics — intentional and documented; the escape hatch covers them.
- Per-replica policy state is boot-time only; no runtime drift detection (a
  misapplied config is detected at next restart's load validation). Out of
  scope per the direction's non-goals (hot reload).

### Prioritized validation plan

1. **Per `.go` edit** (mandatory): `go build ./... && go vet ./...` +
   `go test -run 'TestMaintainability_|TestArchitecture_' .`
2. **F1 regression**: config load rejects `enabled:false` override entries
   (and nested `path_overrides`, non-`/` keys — all fail loud at
   `LoadFromSources`).
3. **F2 regression**: equal-length tie-break determinism test + longest-prefix
   test in `interfaces/cors` (new coverage where none exists today).
4. **D3 regression**: merge + exclusive + case-insensitive dedup tests;
   update `cors_test.go:140` in the same commit; `security_test.go` add a
   `DPoP` round-trip (existing fixture's assertions don't check
   `AllowedHeaders`, Verified — unaffected).
5. **Wiring regression**: config unit test asserting the captured
   `WithCORS` policy carries `PathOverrides`; `test/` (`package ssotest`)
   integration test exercising the stock-binary path: `OPTIONS
   /.well-known/jwks.json` with a non-default `Origin` must receive the
   override's ACAO, with `*`+credentials avoided in the same fixture (echo-
   origin branch would break a `*` assertion — the design's own noted trap).
6. **Acceptance**: scoped grep (code minus `dist/` + five contract docs) for
   `X-RateLimit-Remaining` zero hits, ruling stated in the commit message;
   `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`.

No Critical or High findings. Two Medium findings (F1, F2) should be fixed in
the same change as D1; the remaining findings are documentation/acceptance
requirements already partly anticipated by the design.
