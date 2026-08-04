# Requirements Specification: interfaces/cors — 方向二：配置面完整性

> Source analysis: [docs/auto/interfaces-cors-analysis.md](interfaces-cors-analysis.md).
> Scope: exactly three evidence-backed improvements on the configuration surface
> of the `interfaces/cors` module. All three are "config surface completeness"
> work: no middleware semantics, origin-matching, or security behavior changes.
> Every change must pass the mandatory gates (`go build ./... && go vet ./...`,
> `go test -run 'TestMaintainability_|TestArchitecture_' .`, then `make ci`).

## 决定 1：`security.cors.path_overrides` YAML 映射 —— 让 `PathOverrides` 对运维可达

**Name**: YAML reachability of `cors.Policy.PathOverrides`.

**Problem**: `PathOverrides` is the cors package's most operationally valuable
feature — per-path CORS posture (permissive `/.well-known/*` vs strict
`/token`) — but it is silently truncated at the config layer. The YAML block
(`security.cors`) has no field for it, and both wiring paths that translate
config into a `cors.Policy` omit it, so a YAML operator can never express the
feature. Worse, the stock binary has **two** independent policy-mapping sites;
fixing only `toPolicy()` would still leave `path_overrides` undelivered because
the second site (which wins, see below) inlines its own field mapping.

**Evidence**:
- `interfaces/cors/cors.go:58-66` — `Policy.PathOverrides` documented with the
  selling-point example: "permissive `/.well-known/jwks.json` vs a strict
  `/token`"; longest-prefix-first, first-match-wins semantics.
- `config/config_admin.go:103-111` — `CORSConfig` has only
  `enabled/allowed_origins/allowed_methods/allowed_headers/exposed_headers/
  allow_credentials/max_age`; no `path_overrides` field. (`grep -rn PathOverrides
  --include="*.go"` outside `interfaces/cors/` returns zero hits.)
- `config/config_load.go:472-485` — `CORSConfig.toPolicy()` maps exactly six
  fields; `PathOverrides` absent.
- `cmd/sso-server/build_app_security.go:170-179` (`wireMTLSLockoutProxiesCORS`)
  — a **second**, inline `cors.Policy{...}` construction duplicating the same
  six-field mapping. `interfaces/sso/origin_validation.go:21-23` shows
  `WithCORS` stores a pointer (`s.corsPolicy = &policy`), so the later append
  wins — this inline site is the effective one for the stock binary, and it
  would silently drop any `PathOverrides` even after `toPolicy()` is fixed.

**Proposed behavior**:
1. Add `PathOverrides map[string]CORSConfig `yaml:"path_overrides"`` to
   `config.CORSConfig` (`config/config_admin.go`; `config/` is at its frozen
   file ceiling — extend the existing file, no new file). Reuse `CORSConfig`
   as the override value type; document that the entry's `enabled` flag is
   ignored (an override entry is active by virtue of existing with a non-empty
   `allowed_origins`; an entry with empty `allowed_origins` deliberately
   yields "no CORS headers on this path", which the browser treats as blocked).
2. Extract the per-policy mapping into a helper and map in
   `toPolicy()` (`config/config_load.go`): each key is a URL path prefix,
   each value becomes a `cors.Policy` via the same helper. Validate that every
   key starts with `/`; a non-`/` prefix is a config error (fail loud at load),
   not silent truncation.
3. Replace the inline mapping in `cmd/sso-server/build_app_security.go:170-179`
   with `cfg.Security.CORS.toPolicy()` so the stock binary and the SDK wiring
   share one mapping source; extend the boot log to include the override count.
4. Widen the wiring gate at both `config/config_load.go:315` and
   `cmd/sso-server/build_app_security.go:170` from
   `Enabled && len(AllowedOrigins) > 0` to
   `Enabled && (len(AllowedOrigins) > 0 || len(PathOverrides) > 0)` — otherwise
   a `path_overrides`-only configuration never installs the middleware
   (mirrors `interfaces/cors/cors.go:173`, where the middleware is identity
   only when *both* lists are empty).

**Acceptance check**:
- New config test in `config/security_test.go` (existing pattern at
  lines 61-68): a YAML with `security.cors.path_overrides:
  "/.well-known/jwks.json": {allowed_origins: ["*"]}` parses, and
  `ServerOptions()`/captured `WithCORS` policy contains the override with the
  wildcard origin; a key not starting with `/` fails `LoadFromSources`.
- `cmd/sso-server/build_app_security.go` contains no literal `cors.Policy{`
  construction (grep returns zero hits in `cmd/`).
- Integration test in `test/` (`package ssotest`): with a
  `path_overrides`-configured server, a preflight `OPTIONS /.well-known/
  jwks.json` from a disallowed-by-default origin returns
  `Access-Control-Allow-Origin: *`, while the same origin's preflight to
  `/token` gets no CORS headers.
- `go build ./... && go vet ./...`, maintainability/architecture gates, and
  `make ci` pass.

## 决定 2：`security.cors` 入契约文档 —— 消除配置键的文档缺口与 ExposedHeaders 示例漂移

**Name**: `security.cors` contract documentation in `docs/config-reference.md`.

**Problem**: `security.cors` is a real, wired config knob (parsed by
`config.Security.CORS` and translated into `sso.WithCORS` by the boot path),
but the Configuration Reference's Security table omits it entirely. That
violates the repository's own change contract (AGENTS.md §5: "config knob →
docs/config-reference.md") and leaves operators to guess defaults, gating
semantics, and restart requirements from code. Separately, the cors package's
own doc example for `ExposedHeaders` names a header that does not exist
(`X-RateLimit-Remaining`), and the test fixture propagates the same fiction —
contract drift that a doc row would otherwise freeze.

**Evidence**:
- `docs/config-reference.md:63-70` — Security table rows:
  `mtls`, `trusted_proxies`, `security_headers`, `spiffe`, `rar_limits`,
  `scope_limit`, `max_token_bytes`, `client_registration_rate_limit`;
  case-insensitive grep for `cors` returns zero hits in the file.
- `config/config_metrics_security.go:28` — `CORS CORSConfig `yaml:"cors"``
  under the `security` block; `config/config_load.go:315-316` — the boot path
  maps it to `sso.WithCORS(c.Security.CORS.toPolicy())`.
- `interfaces/cors/cors.go:44` — doc comment: "Useful when SPAs need to read
  X-Request-ID, **X-RateLimit-Remaining**, etc."; `interfaces/ratelimit/
  ratelimit.go:15,139,191,200` — the whole package emits only `Retry-After`
  (also `shared/core/consts_wire.go:24` `HeaderRetryAfter`); grep for
  `X-RateLimit-Remaining` outside `interfaces/cors/` returns zero hits.
- `interfaces/cors/cors_test.go:193,202` — the fixture asserts the
  non-existent `X-RateLimit-Remaining` in `Access-Control-Expose-Headers`.

**Proposed behavior**:
1. Add a `security.cors.*` row to the Security table in
   `docs/config-reference.md` covering every leaf of `CORSConfig`:
   `enabled`, `allowed_origins`, `allowed_methods`, `allowed_headers`,
   `exposed_headers`, `allow_credentials`, `max_age`, and `path_overrides`
   (when decided 1 lands). State the semantics precisely: empty
   `allowed_origins` disables CORS even with `enabled: true`; the
   `Allow-Credentials` + `*` interplay (echo-origin, per
   `interfaces/cors/cors.go:112-124`); and that changes require a restart
   (no SIGHUP hot reload — consistent with the Hot Reload table at
   `docs/config-reference.md:444` covering only `logging.level`,
   `security.rate_limit.*`, `feature_gates.*`).
2. Fix the ExposedHeaders doc drift: replace `X-RateLimit-Remaining` with
   headers the server actually emits — `X-Request-Id`
   (`shared/core/consts_wire.go:21`) and `Retry-After`
   (`interfaces/ratelimit/ratelimit.go`). Update the same example in
   `interfaces/cors/cors.go:44` and the fixture at
   `interfaces/cors/cors_test.go:193` so code, tests, and docs agree.
3. After the fix, `X-RateLimit-Remaining` must have zero occurrences
   repository-wide.

**Acceptance check**:
- `grep -in 'cors' docs/config-reference.md` shows the `security.cors.*` row
  with every `CORSConfig` leaf named and the enabled/origins/restart
  semantics stated.
- `grep -rn 'X-RateLimit-Remaining' --include='*.go' --include='*.md' .`
  returns zero hits.
- `go build ./... && go vet ./...`, maintainability/architecture gates, and
  `make ci` (including docs/config validation) pass.

## 决定 3：允许头列表"追加到默认值"语义 + 头常量单一来源 —— 消除凭据类头的静默丢失陷阱

**Name**: Append-to-defaults semantics for `AllowedHeaders`; single source for
CORS header constants.

**Problem**: `buildConfig` treats an *empty* `AllowedHeaders` as "use the
defaults" but a *non-empty* list as a full replacement. Because `DPoP` is a
first-class header in this codebase (the auth-code flow reads it), the natural
operator intent — `allowed_headers: [DPoP]` to *add* DPoP for an SPA — silently
drops `Authorization` and `Content-Type` from the preflight
`Access-Control-Allow-Headers` response. The browser then refuses to send the
Authorization header on the actual request, surfacing as a hard-to-debug 401
on a credential-class header. Separately, the CORS header-name constants are
declared twice: `interfaces/cors/consts.go` re-declares what
`shared/core/consts_wire.go:25-27` already owns, on a mistaken cycle fear —
`shared/core` imports no Snaplink package (AGENTS.md §4), so `cors` can import
it directly, and the duplicated names are a drift source for the exact header
contract this improvement is tightening.

**Evidence**:
- `interfaces/cors/consts.go:27-32` — `DefaultAllowedHeaders = []string{
  "Authorization", "Content-Type"}`.
- `interfaces/cors/cors.go:78-90` — `buildConfig`: `if len(p.AllowedHeaders)
  == 0 { p.AllowedHeaders = DefaultAllowedHeaders }` — empty falls back, any
  non-empty list replaces wholesale. Policy doc at `cors.go:24-25` states "Empty
  fields fall back to the sensible defaults", which is exactly the trap.
- `interfaces/sso/server_oauth.go:19-20` — `captureAuthCodeDPoPBinding` reads
  `HeaderDPoP` (also `config/config_admin.go:110` `allowed_headers` passthrough
  inherits the same semantics).
- `shared/core/consts_wire.go:25-27` — `HeaderAccessControlOrigin`,
  `HeaderAccessControlMethods`, `HeaderAccessControlHeaders` already defined;
  `interfaces/cors/consts.go:6-17` re-declares them with a comment claiming a
  cycle ("would cycle: sso → cors via WithCORS") that does not apply to
  `shared/core` (below `interfaces` in the layer order; `sso` already imports
  it, see `interfaces/sso/origin_validation.go:22`).

**Proposed behavior**:
1. Change `buildConfig` (`interfaces/cors/cors.go`) merge semantics: when
   `AllowedHeaders` is non-empty, the preflight `Access-Control-Allow-Headers`
   value becomes defaults ∪ configured, deduplicated in deterministic order
   (defaults first, then configured additions). `allowed_headers: [DPoP]` thus
   yields `Authorization, Content-Type, DPoP`. Add an explicit escape hatch
   `AllowedHeadersExclusive bool` (YAML `allowed_headers_exclusive: true`)
   that restores full-replacement for operators who deliberately narrow the
   list; empty `AllowedHeaders` still means "defaults only" (unchanged). Apply
   the same rule consistently to `PathOverrides` sub-policies (they go through
   the same `buildConfig`).
2. Update the `Policy` doc comment (`cors.go:24-25`) to state the append
   semantics and the `allowed_headers_exclusive` escape hatch; add the leaf to
   `config.CORSConfig` + `toPolicy()` mapping and the `docs/config-reference.md`
   row from decision 2.
3. Delete the duplicated declarations in `interfaces/cors/consts.go:6-17` and
   import `shared/core`, keeping only cors-specific names in `consts.go`
   (`HeaderOrigin`, `HeaderVary`, `HeaderAccessControlAllowCreds`,
   `HeaderAccessControlExposeHeaders`, `HeaderAccessControlMaxAge`,
   `HeaderAccessControlRequestMethod`, `OriginWildcard`, `TrueLiteral`).
   `shared/core` is below `interfaces` in the layer order and imports no
   Snaplink package, so no cycle is introduced.

**Acceptance check**:
- Unit test in `interfaces/cors/cors_test.go`: `Policy{AllowedHeaders:
  []string{"DPoP"}}` produces a preflight `Access-Control-Allow-Headers` of
  `Authorization, Content-Type, DPoP`; `AllowedHeadersExclusive: true` with
  `["DPoP"]` produces exactly `DPoP`; empty list still produces the defaults.
- Config test: `security.cors.allowed_headers: [DPoP]` round-trips through
  `toPolicy()` into the merged header string (via the wired middleware or the
  captured `WithCORS` policy).
- `grep -n 'HeaderAccessControl' interfaces/cors/consts.go` shows the three
  shared names gone; `go list -deps ./interfaces/cors` contains
  `shared/core`; `go vet` reports no import cycle.
- `go build ./... && go vet ./...`, maintainability/architecture gates
  (file/function budgets unaffected: `cors.go` grows by <30 lines, far under
  500; `config/` gains no new files), and `make ci` pass.

## 影响面与约束

- No security/wire-contract behavior change: origin matching, preflight
  204 semantics, credential handling, and the `Authorization`-first fallback
  are untouched; decisions 1 and 3 only change *which* policy/header values
  the config surface can express.
- No new `Err*` codes, no new endpoints, no new packages: nothing to add to
  `docs/error-codes.md` or `docs/openapi.yaml`; only `docs/config-reference.md`
  (decision 2 + row for decisions 1/3).
- Budgets: `config/` is at its frozen file ceiling — all config edits stay in
  `config_admin.go`/`config_load.go`; `interfaces/sso` is at its 60-file
  ceiling — no new files there (the `test/` integration test is `package
  ssotest`, which does not count toward the sso file ceiling).
- Deliberate non-goals (per the source analysis, direction 一/三 territory):
  CORS hot reload, unified origin-decision single source for the login gate,
  and CORS observability metrics/audit. If any of those is later pursued, the
  config surface fixed here is its prerequisite.
