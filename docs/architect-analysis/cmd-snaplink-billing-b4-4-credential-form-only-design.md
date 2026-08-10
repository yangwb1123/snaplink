# Design: B4-4 — Form-urlencoded-only credential endpoints with billing-consumer regression pinning

- Direction: B4-4 endpoint hardening, entry 3 of
  `docs/architect-analysis/auto/analyses/cmd-snaplink-billing-a1788a26.json`
  ("Enforce application/x-www-form-urlencoded on credential endpoints with
  billing-consumer regression pinning (B4-4, T-8(b)(c)(e)/T-9)")
- Requirements: `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md`
- Status: design, built on the accepted sibling design
  `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md`
  (same campaign item, sibling analysis module; its mechanism, default, and
  test resolutions are prior art this design adopts wholesale) and the
  sso-ctl sibling (`cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-*`).
- The billing module is a **consumer** of the credential surface (it mints via
  the audit/quota/retention relays and contains no credential-server code).
  Its contribution is regression pinning only: in-module wire assertions plus a
  strict-mode end-to-end pin driving the real `auditgovernance` token sources.

> **SUPERSEDED — DO NOT RE-EXECUTE (amended by the design-stage audit).**
> Written pre-landing at HEAD `30938444`; the strict-wire surface landed
> **before** this design as **opt-in default-off** (`sso.go:76` seeds
> `credentialFormOnly = false`; unset/`false` = byte-identical legacy) with the
> **415** plain `{"error":"invalid_request"}` envelope (not 400) on **four**
> endpoints (`/token`, `/token/introspect`, `/token/revoke`, `/par`;
> CIBA/device/MFA remain dual-mode, out of scope), wired via
> `server.require_form_content_type` / `sso.WithCredentialFormOnly`; the compose
> flip is already shipped (`ops/deploy/compose/config.yaml:21`). §3.3 "Breaking
> by design (default true)" never shipped, and §3.5 steps 4-5 were **never
> executed** — `TestFormEncoded_JSONStillWorks` remains the positive JSON→200
> case on the default harness, and no in-repo JSON post was swept (four
> endpoints are strict, not eight). Status codes in §3.1-§3.6 read 415 on the
> four strict endpoints. The live remainder is the R7 billing-consumer pin:
> §3.5 step 6 and §3.7 (as amended below); §4's command list uses the amended
> test name. The authoritative artifact is
> `docs/architect-analysis/auto/runs/enforce-content-type-form-urlencoded-on-credenti-b63aeb29/artifacts/design-a77de8a6/task-1-design.md`.

## 1. Verification verdict (untrusted claims → measured reality)

The requirements spec's evidence table was re-verified independently against
the working tree (HEAD `30938444`). Every citation in the table is confirmed,
with the disclosed 1-line drifts; the spec's own prose contains three small
citation/instruction drifts (section 2). All verification was read-only.

| Claim | Measured reality | Verdict |
|---|---|---|
| `oauthwire/bind.go:16-41` — JSON + missing-CT-to-JSON default | `BindParams` at :28; doc :15-21 (:18-19 "JSON is accepted as a non-standard convenience", :26-27 "Empty body + no Content-Type is treated as JSON"); switch :37, form case :38, JSON default :43-45; CT normalization (param strip + lowercase) :31-35 | Confirmed exact |
| `oauth_token_source.go:201-210` — form-encoded mint, CT set | `tokenRequest` at :200 (disclosed 1-line drift); form body :201-204, `SetBasicAuth` :207, `Content-Type: application/x-www-form-urlencoded` :209, `Accept: application/json` :210; `fetchToken` refuses non-200, requires JSON response, non-empty `access_token`, Bearer `token_type`, `expires_in > 0` | Confirmed exact |
| `token_client_credentials.go:21` — cc no refresh_token | Comment :20-23 ("no refresh token"); success body :67-73 = `access_token`/`token_type`/`expires_in`/`scope`/`token_strategy`, no `refresh_token` | Confirmed exact |
| `server_token_clientauth.go:193,239` — token client auth | `authenticateTokenClient` :193, `verifyTokenClientAuth` :239; `/token` uses it (`server_token.go:35`); introspect twin `authenticateIntrospectClient` (`handle_introspect.go:202`, invoked :134) with the identical `401 invalid_client` collapse | Confirmed exact |
| `shared/security` `CompareClientSecret` | `client_secret.go:19`: bcrypt for `$2`-prefixed, else `ConstantTimeStringEq` (`constant_time.go:5`); single compare seam used by `/token` auth + RFC 7592 registration-token gate; `client_secret_test.go:10,29,46` behavioral, timing-independent | Confirmed exact — no work |
| `server_token.go` `tokenNoStoreHeaders` | :22, before `bindOAuthParams` :30; `middleware.TokenNoStoreHeaders` (`no_store.go:22`) stamps `Cache-Control: no-store` + `Pragma: no-cache` on success AND error; stamped at all 8 credential sites (`handle_introspect.go:112`, `handle_revoke.go:68`, `handle_par.go:55`, `handle_ciba.go:76`, `server_device.go:42`, `server_mfa.go:195`) | Confirmed exact — no work |
| Billing consumer paths | `relay.go:45` `NewOAuthTokenSource` (spec said :46 — the call spans :45-52; 1-line drift), `quota_relay.go:347` `NewPlatformTokenSource`, `quota_relay.go:427` `NewOAuthTokenSource` (exact); `platform_token.go:151` `platformTokenRequest` form + CT :162; ready checks `app.go:100` `audit_relay_module`, `app.go:103` `tenant_quota_projection` (both exercise token availability via `auditModule.Ready` / `quotaRelay.Ready`) | Confirmed exact |
| **Pin missing** | `rg BindParamsFormOnly|require_form_content_type|WithCredentialFormOnly` → zero hits. `quota_relay_test.go:94` `assertRetentionTokenRequest` and `:149` `assertQuotaTokenRequest` assert the minted form body but never the request `Content-Type` header. `rg NewOAuthTokenSource|NewPlatformTokenSource` in `test/` → **zero hits**: no test ever drives a billing-shaped mint against a real `/token` handler | Confirmed exact |
| 8 credential bind sites | `server_token.go:30`, `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`, `handle_ciba.go:87`, `server_device.go:53,242`, `server_mfa.go:255` (the latter three via the `bindOAuthParams` alias `server_jar.go:304` → `oauth.BindParams` `aliases.go:97`); none checks Content-Type; `/token/revoke-all` bearer-only, outside | Confirmed exact |
| OpenAPI declares JSON on credential paths | All eight paths declare both `application/json` and `application/x-www-form-urlencoded` request bodies | Confirmed exact |
| In-repo JSON callers exist | `test/oauth_bind_test.go:272` `TestFormEncoded_JSONStillWorks` (JSON → expects 200); `auth_code_test.go:124,484`; `claims_param_test.go:352`; `handle_device_test.go:130,312,342` (+ :66/:187/:200 `/device/code`, :111 header, :361 `/device/verify`); `mfa_test.go:175` (+ :200); `credential_health_test.go:397`; `handle_introspect_test.go` `postIntrospect` :82-100 / `postRevoke` :229-240 + `TestIntrospect_AcceptsBasicAuth` :196; `introspection_jwt_test.go:70`; `handle_token_test.go:59,87,284`; `refresh_token_test.go:118,342,375,496`; `refresh_rotation_claims_test.go:57`; `rar_test.go:265,429,480,527` | Confirmed; spec R5.1 inventory is a sample (full sweep ~25 files, sibling spec) |
| MFA bind failure shape | `parseMFACompleteRequest` (`server_mfa.go:255`) collapses bind error + missing fields to verbatim `400 mfa_invalid` via `s.authzErrorBody` | Confirmed exact |
| Config seams | `ServerConfig` at `config/config_server.go:16`; `ServerOptions()` at `config/config_load.go:301`; `applyDefaults()` at `config_load.go:69`; `build_app_core.go:154` consumes `cfg.ServerOptions()`; `sso.Option` pattern + `WithMaxTokenBytes` :103, `WithOAuth21StrictMode` :194 precedents; `NewServer` seeds defaults before options (`sso.go:58` area, `issuer = DefaultIssuer` precedent) | Confirmed exact |
| Budgets | `interfaces/sso` non-test files = exactly 60 (ceiling); `cmd/snaplink-billing` non-test files = exactly 10 (fan-out ceiling); `quota_relay.go` = 485 lines; `quota_relay_test.go` = 306 lines | Confirmed exact |
| Sibling prior art | `cmd-snaplink-audit-provisioner-b4-4-credential-form-only-design.md` exists and pins: default **true** seeded in `NewServer`, `RequireFormContentType() bool` on the four protocol Deps interfaces, `oauth.BindCredentialParams` dispatch, `s.bindCredentialParams`, `*bool` config key appended-only-when-set, `errFormOnly` sentinel + wire-invisible Info log, keep-legacy-pin/fuzz resolutions | Confirmed |

## 2. Material corrections to the evidence

The requirements spec is sound; these are the drifts this design resolves:

1. **Spec R7.2 line citation drift**: "`NewOAuthTokenSource` (`oauth_token_source.go:143`)" — the constructor is at `oauth_token_source.go:77-79`. Symbol and behavior confirmed; the e2e test must be written against the real constructor signature (`NewOAuthTokenSource(config OAuthTokenConfig, client *http.Client, options ...OAuthTokenOption)`).
2. **Spec R5.1 inventory is partial, not exhaustive** (it defers to the sibling's "~25 files / ~45 JSON posts"). The full sweep for `make ci` must also cover: `test/handle_token_test.go:59,87,284`, `test/refresh_token_test.go:118,342,375,496`, `test/refresh_rotation_claims_test.go:57`, `test/rar_test.go:265,429,480,527`, `test/introspection_jwt_test.go:70`, `test/handle_device_test.go:66,111,187,200,361`, `test/mfa_test.go:200`. `/auth/login` and `/register` JSON posts stay (out of scope).
3. **Spec R5.2/R5.3 wording is superseded by the accepted sibling resolution (D2)**: `TestBindParamsJSONDefault` (`bind_extra_test.go:148`) and the legacy `FuzzBindParams` (`bind_fuzz_test.go:34`) test `oauthwire.BindParams` **directly**; that function stays dual-mode for non-credential consumers, so both stay green unmodified. Strict rejection lives in new `bind_strict_test.go` tests + a new `FuzzBindParamsFormOnly`. The "invert" requirement applies only to the *server-level* `TestFormEncoded_JSONStillWorks` (`oauth_bind_test.go:272`), whose harness goes through `sso.NewServer` (default true).
4. **Spec §7 lists `cmd/sso-server/build_app_core.go:154` as a Modify** — the sibling pins **no change there**: `ServerOptions()` appends the option only when the config key is set (matching `FeatureGatesConfig.anySet()` precedent), and `NewServer` seeds strict default `true`. `build_app_core.go` already consumes `cfg.ServerOptions()`.
5. **Spec R6 "plain bool default true" is refined to `*bool`**: `ServerConfig.RequireFormContentType *bool` (`yaml:"require_form_content_type"`). `nil` (unset) → option not appended → strict default; `false` → legacy escape hatch with a startup `slog.Warn` in `validate()`; `true` → explicit strict. This keeps untouched configs byte-identical and the escape hatch loud.
6. **The four protocol Deps interfaces gain a member** — `RequireFormContentType() bool` on `IntrospectDeps`/`PARDeps`/`RevokeDeps`/`CIBADeps`. `*sso.Server` implements it; the protocol-test fakes (`handle_par_test.go`, `handle_revoke_test.go`, `handle_introspect_test.go`, `introspect_cache_test.go`, `introspect_geo_test.go`, `handle_ciba_test.go`) gain the accessor returning `true`. The requirements spec omitted this compile-time surface; without it the flag cannot reach the four `protocols/oauth` handlers.

## 3. Design

### 3.1 API changes

| Symbol | Location | Notes |
|---|---|---|
| `oauthwire.BindParamsFormOnly(ctx core.HandlerContext, v any) error` | new `protocols/oauth/oauthwire/bind_strict.go` | Form CT → shared `bindForm` (`ParseForm` + `formIntoStruct`); any other/missing CT → unexported sentinel `errFormOnly` **before reading the body**. Shares `normalizedMediaType` and `bindForm` with `BindParams` — one definition of form semantics |
| `oauthwire.errFormOnly` (unexported) | `bind_strict.go` | Distinguishes media-type rejection from a malformed form body only inside the package; the four strict handlers collapse both to the same 415 via `errors.Is`, the dual-mode sites keep 400, so no new oracle. The sentinel path additionally emits a wire-invisible Info-level `slog` line (class `json`/`missing`/`other`, bounded cardinality; never body, never raw header, never an audit event, never response-visible) — the operator's gauge for legacy traffic during the migration window |
| `oauth.BindParamsFormOnly` | `protocols/oauth/aliases.go` (var block beside `BindParams` :97) | Preserves the `oauth.*` import surface |
| `oauth.BindCredentialParams(ctx core.HandlerContext, v any, formOnly bool) error` | `protocols/oauth` (small new file beside `aliases.go`, or appended to it) | Single flag-aware dispatch used by the four protocol-layer sites: `formOnly` → `BindParamsFormOnly` else `BindParams`. One definition of the flag gate per layer |
| `bindOAuthParamsFormOnly` + `(s *Server) bindCredentialParams(ctx, v) error` | `interfaces/sso/server_jar.go` (beside `bindOAuthParams` :304) | The four `interfaces/sso` sites call `s.bindCredentialParams` (flag from the Server field); the non-credential `bindOAuthParams` stays for `server_admin_handlers.go:293` and `options_admin.go:414` |
| `sso.WithCredentialFormOnly(v bool) Option` | `interfaces/sso/options.go` (beside `WithMaxTokenBytes` :103 / `WithOAuth21StrictMode` :194) | Sets `Server.credentialFormOnly`. Emits a startup `slog.Warn` at option construction when `false` (documented legacy escape hatch, deprecated; removal bound to the next schema-version bump) |
| `Server.credentialFormOnly bool` + `RequireFormContentType() bool` accessor | `interfaces/sso/sso.go` (embedded state struct) + `accessors.go` (beside `OAuth21Strict()` :369) | Seeds **true** in `NewServer` (`sso.go:58` area, `issuer = DefaultIssuer` precedent) before options apply → strict is the zero-config posture for SDK embedders and `cmd/sso-server` alike. Accessor satisfies the four protocol Deps interfaces |
| `RequireFormContentType() bool` on `IntrospectDeps`, `PARDeps`, `RevokeDeps`, `CIBADeps` | `handle_introspect.go:27+`, `handle_par.go:18+`, `handle_revoke.go:16+`, `handle_ciba.go:31+` | One accessor per interface, matching the established pattern (`IntrospectionCache()`, `IntrospectionCacheTTL()`, …). `*sso.Server` implements it; `RoutesDeps` (union, `grant_handler.go:22+`) inherits it automatically |
| `ServerConfig.RequireFormContentType *bool` (`yaml:"require_form_content_type"`) | `config/config_server.go:16` `ServerConfig` | `nil` → option NOT appended → strict default; `false` → `sso.WithCredentialFormOnly(false)`; `true` → explicit strict. Append-only-when-set matches `FeatureGatesConfig.anySet()` precedent |
| `config.validate()` deprecation warn | `config/config_load.go` (hosted_login convention :152-156) | When the key is explicitly `false`: `slog.Warn` that the JSON/missing-CT credential fallback survives only through the migration window |
| New `Err*` | none | Handlers collapse every bind error to the pre-existing bodies — `415 invalid_request` on the four strict sites (mapped via `errors.Is(ErrFormOnly)`), `400 invalid_request` on the dual-mode sites, `400 mfa_invalid` on `/auth/mfa` (AGENTS.md oracle table) |

**Config wiring** (`config/config_load.go:301` `ServerOptions()` gains one block):

```go
if c.Server.RequireFormContentType != nil {
    opts = append(opts, sso.WithCredentialFormOnly(*c.Server.RequireFormContentType))
}
```

**Site switches (8, flag-aware; no handler logic otherwise changes):**

| Endpoint | Site | Change |
|---|---|---|
| POST `/token` | `server_token.go:30` | `bindOAuthParams` → `s.bindCredentialParams` |
| POST `/device/code` | `server_device.go:53` | same |
| POST `/device/verify` | `server_device.go:242` | same |
| POST `/auth/mfa` | `server_mfa.go:255` | same (bind error still collapses to `400 mfa_invalid`) |
| POST `/token/introspect` | `handle_introspect.go:120` | `BindParams` → `BindCredentialParams(ctx, &req, d.RequireFormContentType())` |
| POST `/token/revoke` | `handle_revoke.go:75` | same |
| POST `/par` | `handle_par.go:66` | same |
| POST `/backchannel-authentication` | `handle_ciba.go:87` | same |

Ordering is unchanged everywhere: `tokenNoStoreHeaders` is stamped before parsing at every site; body parse precedes client auth on `/token` and `/token/introspect` (R4/T-9; auth-before-parse rejected — it would make body-credential auth unreachable and break the AGENTS.md "HTTP Basic wins over body credentials" invariant).

### 3.2 Binder semantics (pinned)

- `normalizedMediaType` (extracted from `bind.go:31-35`, byte-identical behavior): strip `;`-parameters, lowercase, trim. `application/x-www-form-urlencoded; charset=UTF-8` binds; `application/json; charset=utf-8` rejects.
- Form path: `ParseForm` + `formIntoStruct` exactly as today (multi-value and space-separated `scope`/`resource`, `json`-tag key mapping, `RawMessage`/`claims` branch untouched). Valid form CT with an empty body binds empty → per-endpoint validation downstream (`/token` → `400 invalid_request` for missing `grant_type`).
- **Validated wire semantics (Go 1.26.5, empirically confirmed against real net/http over raw TCP + httptest; evidence in the content-type semantics review):** `Header.Get` returns only the **first** `Content-Type` value — duplicate header lines stay separate slice values, comma-joined values are never split, and the first value decides (form-first binds, json-first rejects); an empty-value line (`Content-Type:`) is present-but-empty and rejects exactly like a missing header; the server transport trims leading/trailing OWS from header values and canonicalizes the field name but preserves value case (normalize's TrimSpace/lowercase is load-bearing at unit level, belt-and-suspenders at e2e); `r.ParseForm()` fills `r.Form` with query+body but `r.PostForm` with **body only**, so URL query parameters never bind (the legacy JSON path never consults the query at all); malformed percent-encoding (`%zz`, trailing `%`, truncated `%2`, `%2G`) surfaces as a `ParseForm` `invalid URL escape` error with no partial bind, `+` decodes to space, `%00` decodes to a NUL byte without error; a malformed URL query (`?x=%zz`) fails `ParseForm` even with a valid form body — identical to today's form branch; chunked transfer-encoding is transparent (the server de-chunks before `r.Body`; `ParseForm` binds chunked form bodies with or without charset param); Go's own `parsePostForm` accepts charset params via `mime.ParseMediaType` and errors on malformed media parameters (`; charset="unterminated` → `mime: invalid media parameter`). Every outcome above collapses to the same 400 — no new oracle.
- Missing CT, `application/json`, and any unexpected media type → `errFormOnly` before the body is read. The old "empty body + no Content-Type is treated as JSON" default (`bind.go:26-27`) is gone from the credential surface only; `BindParams`' default branch is untouched for the 44 non-credential call sites (commerce ×9 — `payment_ingest.go:99` REQUIRES JSON —, admin ×7, selfservice ×8, adminuser ×2, per the sibling inventory).
- `BindCredentialParams(ctx, v, false)` is byte-identical to `BindParams` — the legacy escape hatch is a flag value, not a second code path.

### 3.3 Compatibility constraints

> **SUPERSEDED — do not re-execute this section.** "Breaking by design
> (default true)" never shipped. The landed contract is opt-in default-off
> (`sso.go:76`), **four** endpoints (`/token`, `/token/introspect`, `/token/revoke`,
> `/par`), and the rejection status is **415** (plain `{"error":"invalid_request"}`),
> not 400. The escape-hatch paragraphs below invert the landed reality (the
> option turns strictness ON; unset/`false` = byte-identical legacy).

- **Breaking by design (default true)**: the eight credential endpoints stop accepting JSON/missing/unexpected Content-Type (400) under the strict default at both the `sso.NewServer` level (SDK embedders) and the `sso-server` binary level (`server.require_form_content_type` unset → strict). This is the G5 gate behavior T-8(b)(c)(e) requires.
- **Escape hatch (deprecated)**: `sso.WithCredentialFormOnly(false)` / `server.require_form_content_type: false` restores today's byte-identical dual-mode on the eight sites, with a loud startup `slog.Warn` on both paths. Removal is bound to the next schema-version bump.
- **Non-credential surface untouched**: `oauthwire.BindParams` dual-mode dispatch, `interfaces/commerce/*`, `interfaces/admin/*`, `protocols/selfservice/*`, `/auth/login` (JSON-only via `rejectNonJSONLogin`), `/register` (JSON-only per RFC 7591 §3.1 via `ctx.Bind`), admin-API bind sites (`server_admin_handlers.go:293`, `options_admin.go:414`), `/token/revoke-all` (bearer-only). `TestBindParamsJSONDefault` and the legacy `FuzzBindParams` stay green unmodified (they pin the preserved non-credential contract).
- **Oracle safety**: no new `Err*`, no new distinguishable output; `errFormOnly` is wire-invisible. `/auth/mfa` keeps the `mfa_invalid` collapse (details only in `mfa_failure` audit).
- **Middleware/order**: no-store stamping before parse at all 8 sites; probes outside rate limiting; middleware order unchanged.
- **Billing**: zero production-code change to `cmd/snaplink-billing` — its three mints already send form + exact CT (`oauth_token_source.go:200-210`, `platform_token.go:151-162`). Budgets hold: no new non-test files in `cmd/snaplink-billing` (10-file ceiling) or `interfaces/sso` (60-file ceiling); `oauthwire` gains one file under all limits; `quota_relay_test.go` grows only by assertion lines (306 → stays under 500; a second `_test.go` file is permitted — test files don't count toward the fan-out).
- **Generated SDKs**: `cmd/gensdk` TS/Python credential ops currently emit JSON bodies (`gen_ts_runtime.go:158-159`, `gen_py.go:103`). The gensdk form-emission work (R5.4/D-3, sibling module) must land **before or with** this change, and committed generated SDKs must be regenerated — otherwise generated clients break against the strict default.
- **Cross-module**: B4-2 scope registry is independent (scope vs content-type acceptance; disjoint behaviors on `/token`).

### 3.4 Failure modes

| Mode | Behavior | Mitigation |
|---|---|---|
| Billing mint breaks under strict (the direction's core risk) | A 415 from `/token` → `ErrTokenUnavailable` → relay Ready fails → `/readyz` 503 (`app.go:100,103`, `health.go:54`). Today this would be silent until production | R7.1 header asserts + R7.2 e2e pin (3.7) prove the exact wired mint paths return 200 with zero billing code change |
| External JSON/missing-CT OAuth clients | 400 `invalid_request` on all eight endpoints | Breaking-change entry in CHANGELOG + OpenAPI form-only; deprecated config fallback for the migration window; wire-invisible Info log lets operators count legacy traffic |
| SDK embedders upgrading `interfaces/sso` | Strict by default → their JSON posts 400 | Deliberate (G5); escape hatch documented + startup warn; CHANGELOG notes the default |
| Generated SDK (gensdk TS/Python) clients | JSON credential bodies → 400 | Ordering constraint: form-emission lands before/with the flip (R5.4) |
| Protocol-test fakes | Compile break from the new Deps accessor | Six fakes gain `RequireFormContentType() bool` returning `true` in the same change (compile-enforced) |
| Fuzz regressions | `FuzzBindParamsFormOnly` could panic or bind on non-form CT | Fuzz target asserts: never panic, never successful bind for non-form CT; strict fuzz runs in CI |
| Precedence regression | Unauthenticated **form** introspect must still 401; JSON introspect 415s at the bind gate (T-8(b), status superseded to 415) | T-9 tests migrated + new case 14 pin; ordering unchanged |
| Config drift | Untouched configs must stay byte-identical | `*bool` + append-only-when-set; `applyDefaults()` untouched |
| Oracle leak | `errFormOnly` detail escaping into responses or audit | Collapsed to existing bodies; log is Info-level, wire-invisible, bounded classes, no credentials/body/raw header |
| Migration sweep miss | Any in-repo JSON post left → `make ci` red | Complete inventory (section 2, item 2); `make ci` as the handoff gate |

### 3.5 Migration steps

> **SUPERSEDED — do not re-execute steps 4-5.** Steps 1-3 and 6-9 are already
> landed (binder core, flag plumbing, four-endpoint site switches, config/docs,
> gensdk form emission). Steps 4-5 were **never executed** and must not be:
> `TestFormEncoded_JSONStillWorks` stays the positive JSON→200 case on the
> default harness (strictness is opt-in), and no in-repo JSON post was swept
> (four endpoints are strict, not eight; the rejection status is 415, not 400).
> The only live step is 6 (billing pins), per the amended §3.7.

Ordered; each step keeps `go build ./... && go vet ./...` and the maintainability/architecture gates green.

1. **Binder core** — extract `normalizedMediaType` + `bindForm` from `bind.go` (behavior-identical refactor); add `bind_strict.go` (`BindParamsFormOnly`, `errFormOnly`, Info log) + `bind_strict_test.go` (acceptance 20) + `FuzzBindParamsFormOnly` (acceptance 21). Legacy `BindParams` + its tests/fuzz untouched.
2. **Flag plumbing** — `Server.credentialFormOnly` field + `RequireFormContentType()` accessor + `WithCredentialFormOnly` + `NewServer` seed `true`; `RequireFormContentType() bool` on the four Deps interfaces; update the six protocol-test fakes (return `true`).
3. **Site switches** — the eight sites (3.1 table) via `oauth.BindCredentialParams` / `s.bindCredentialParams`.
4. **Invert the server-level fallback test** — `TestFormEncoded_JSONStillWorks` (`oauth_bind_test.go:272`) becomes the negative case (JSON → 400 `invalid_request` on the default-strict harness).
5. **Full test sweep** — migrate every in-repo JSON post to the eight endpoints to form bodies (same fields, `url.Values` encoding), including the files in section 2 item 2; assertions and status codes byte-for-byte unchanged; `/auth/login`/`/register` posts untouched. `TestIntrospect_RejectsMissingCreds`/`RejectsWrongSecret`/`AcceptsBasicAuth` migrate and keep their 401/200 semantics (T-9).
6. **Billing pins** — R7.1: extend `assertQuotaTokenRequest` (`quota_relay_test.go:149`) and `assertRetentionTokenRequest` (:94) to assert the exact request `Content-Type: application/x-www-form-urlencoded` header (no parameters) plus the existing form-body asserts. R7.2: new `test/billing_form_e2e_test.go` (3.7).
7. **Config + docs** — `ServerConfig.RequireFormContentType *bool`, `ServerOptions()` block, `validate()` deprecation warn; `docs/config-reference.md` (new key, default strict, legacy deprecated), `docs/openapi.yaml` (drop `application/json` requestBody variants on the eight credential paths; keep `/register` + admin JSON), `docs/error-codes.md` note on `invalid_request` (credential endpoints form-only), CHANGELOG breaking entry.
8. **gensdk** — form emission for credential ops + regenerate committed SDKs, ordered before/with step 3 (R5.4).
9. **Gates** — section 4 verification plan; `make ci` full.

Rollback: set `server.require_form_content_type: false` (or drop the option) — one-line, no redeploy of code, behavior byte-identical to today.

### 3.6 Testable acceptance mapping

Requirements acceptance cases → concrete tests:

| Case | Acceptance (requirements §Testable acceptance) | Test |
|---|---|---|
| 1-2 | JSON on `/token`, `/token/introspect`, `/token/revoke`, `/par` → **415** `invalid_request`, no side effects (no token/PAR/revocation); `/device/code`, `/device/verify` stay dual-mode (out of scope) | Landed `test/credential_content_type_test.go`: strict harness (option passed explicitly — **mandatory**, the default is off); side-effect-free via store counts / `mintCountingIssuer` zero-mint asserts |
| 3 | JSON on `/auth/mfa` → 400 `mfa_invalid`, byte-identical envelope, detail only in `mfa_failure` audit | Same file; assert body equals the pre-existing `mfa_invalid` body |
| 4 | `application/json; charset=utf-8` on `/token` → **415** (+ variants: `Application/JSON`, `application/json;charset=utf-8` — §3.6a E4b) | Same file |
| 5-6 | Missing CT (JSON-shaped and empty body) on the four strict endpoints → canonical **415** (+ present-but-empty `Content-Type:` line and param-only `; charset=UTF-8` — §3.6a E5b) | Same file |
| 7 | `multipart/form-data`, `text/plain`, `application/octet-stream` × `/token`, `/token/introspect`, `/token/revoke`, `/par` → **415** (12 combos; unit rows add the `boundary=` param shape — §3.6a U4) | Same file (table-driven) |
| 8 | `application/x-www-form-urlencoded; charset=UTF-8` binds (+ case/OWS variants `Application/X-WWW-Form-Urlencoded`, trailing-space value — §3.6a E8b/U11) | Same file + `bind_strict_test.go` unit case |
| 9 | Strict server + real `auditgovernance` token sources, billing wiring → 200 + non-empty Bearer; raw-JSON control arm → exact 415 + `exact415Body`, zero billing code change | New `test/billing_form_e2e_test.go` (3.7) |
| 10 | Billing readiness observable stays green | Same file: the mint success is exactly the dependency `audit_relay_module`/`tenant_quota_projection` check (`app.go:100,103`); wiring of the ready checks themselves is covered by existing billing tests |
| 11 | `TestFormEncoded_*` family, `scope_registry_test.go`, `ciba_*` unmodified → green | Unmodified existing tests |
| 12 | R5.1-migrated tests (authcode, PKCE, refresh+rotation, claims, OIDC, device, RAR, PAR, MFA, introspect incl. batch, token 401s) → green on form wire; cc **and authcode** still mint 200 | Swept tests (3.5 step 5) |
| 13 | `TestIntrospect_RejectsMissingCreds`/`RejectsWrongSecret` on form → 401 `invalid_client` | Migrated existing tests |
| 14 | Unauthenticated form-encoded introspect with valid token field → 401 (auth gate reached for every bindable request) | New case in `credential_content_type_test.go` |
| 15 | Basic-over-body precedence on `/token`, `/token/introspect`, `/token/revoke`, `/par` | `TestFormEncoded_BasicAuthOverridesBodyCreds` unmodified + table-driven strict variants |
| 16 | `Cache-Control: no-store` + `Pragma: no-cache` on success AND error at every credential site | Existing `token_no_store_test.go` + new asserts on the 415 rows of `credential_content_type_test.go` |
| 17 | cc 200 body: `access_token`/`token_type`/`expires_in`/`scope`, no `refresh_token` key | Existing cc tests assert the body; pin absence of the key where not already asserted |
| 18 | `shared/security` compare coverage, `-race -count=10` → green (timing-independent) | `go test ./shared/security/ -race -count=10` |
| 19 | Config fallback: key unset → strict default; `false` → legacy byte-identical; explicit `true` → strict | New config test: `ServerOptions()` appends only when set; `validate()` warns on explicit `false` |
| 20 | `oauthwire` strict-binder unit cases: canonical set (form binds; JSON/missing/multipart reject; charset param binds; empty form body binds empty; malformed percent-encoding → `ParseForm` error) **plus the wire-semantics rows U1-U15 of §3.6a** (duplicate/comma-joined/empty-value CT, case/OWS, query-never-binds, reject-before-body-read) | `bind_strict_test.go` (package `oauthwire`, white-box) |
| 21 | `FuzzBindParamsFormOnly`: arbitrary CT+body → never panic, never successful bind for non-form CT (normalize the **first** slice value only — multi-value CT is legal and first-wins) | New fuzz target |

### 3.6a Content-Type semantic rows (review-added; empirically validated, Go 1.26.5)

Coverage gaps in the original cases 4-8/20: duplicate CT headers (first wins), comma-joined CT, present-but-empty CT value, case/whitespace variants, query-params-never-bind, chunked bodies. Rows U1-U15 land in `bind_strict_test.go` (package `oauthwire` — white-box so `errors.Is(err, errFormOnly)` is assertable); rows E4b-E16 land in `test/credential_content_type_test.go` (black-box, strict harness, HTTP/1.1 httptest). U7/U13/U15 assert a non-sentinel `ParseForm` error — same 400 on the wire, distinguishable only inside the package (that distinction is exactly the design's sentinel contract).

Unit rows (`bind_strict_test.go`; requests via `httptest.NewRequest` + `core.NewContext`; CT set with `Header.Set` / `Header["Content-Type"]` slices):

| Row | Request setup | Expected |
|---|---|---|
| U1 | form CT, `grant_type=client_credentials&scope=audit:event:write` | binds (scope flattened via `formStringSlice`) |
| U2 | `application/json` + valid JSON body | `errors.Is(err, errFormOnly)` |
| U3 | no CT + JSON-shaped body | `errors.Is(err, errFormOnly)` |
| U4 | `multipart/form-data; boundary=----x` | `errors.Is(err, errFormOnly)` |
| U5 | `; charset=UTF-8` / `;charset=utf-8` / `; charset="UTF-8"` | binds |
| U6 | form CT + empty body | binds empty, no error, zero fields set |
| U7 | form CT + `grant_type=%zz` / `grant_type=%` / `grant_type=%2` / `grant_type=%2G` | non-sentinel `invalid URL escape` error; no partial bind |
| U8 | `Header["Content-Type"] = ["application/json","application/x-www-form-urlencoded"]` and reversed | first wins: reject / binds |
| U9 | comma-joined single value `application/json, application/x-www-form-urlencoded` (both orders) | `errors.Is(err, errFormOnly)` (never split) |
| U10 | empty value `""` and param-only `; charset=UTF-8` | `errors.Is(err, errFormOnly)` |
| U11 | `Application/X-WWW-Form-Urlencoded`, surrounding OWS ` application/x-www-form-urlencoded `, `application/x-www-form-urlencoded ; charset=UTF-8` | binds (unit level has no transport OWS trim — normalize is load-bearing) |
| U12 | form CT + target `?grant_type=refresh_token&scope=query` + body `grant_type=client_credentials&scope=body` | binds body only; query values never reach `formIntoStruct` |
| U13 | valid form body + malformed query `?x=%zz` | non-sentinel `ParseForm` error (query malformed rejects a valid body — same as today's form branch) |
| U14 | `application/json` + malformed JSON body `{` | `errors.Is(err, errFormOnly)` — media-type rejection precedes any body read/decode |
| U15 | `application/x-www-form-urlencoded; charset="unterminated` + form body | non-sentinel `mime: invalid media parameter` error via `ParseForm` |

E2e rows (`credential_content_type_test.go`; every 415 row and the form-400 arms also assert no-store headers per case 16):

| Row | Endpoint / setup | Expected |
|---|---|---|
| E4b | `/token`, CT `Application/JSON` and `application/json;charset=utf-8` | 415 `invalid_request` (case-4 variants) |
| E5b | `/token`, empty-value line (`Header.Set("Content-Type", "")` — client sends a present-empty line, verified) and `Content-Type: ; charset=UTF-8` | 415 `invalid_request` (present-but-empty ≡ missing) |
| E8b | `/token`, `Application/X-WWW-Form-Urlencoded` and trailing-space value | 200 cc mint (server trims OWS, normalize lowercases) |
| E9 | `/token`, duplicate CT lines json→form (`Header.Add` twice) and form→json | 415 / 200 — first value wins on the wire |
| E10 | `/token`, comma-joined single line (both orders) | 415 `invalid_request` |
| E13 | `/token`, form body + `?grant_type=refresh_token&client_id=evil`, Basic auth | 200 cc mint — query params are never credentials |
| E14 | `/token`, `Transfer-Encoding: chunked` (`req.TransferEncoding`, `ContentLength=-1`): form CT → 200; JSON CT → 415 | chunked transparency pin (transport-level — e2e only, invisible at unit level) |
| E15 | `/token`, form CT + `grant_type=%zz` | 400 `invalid_request` (ParseForm error path) |
| E16 | `/token`, form CT + empty body | 400 `invalid_request` via downstream grant_type validation — bind-succeeded-empty is indistinguishable from bind-reject (oracle-safe) |

### 3.7 Billing-consumer pin (R7; the module's distinctive deliverable)

**R7.1 — in-module wire asserts (test-only, `cmd/snaplink-billing`).**
`assertQuotaTokenRequest` (`quota_relay_test.go:149`) and `assertRetentionTokenRequest` (:94) additionally assert the request carries exactly
`Content-Type: application/x-www-form-urlencoded` (header equality; no parameters), alongside the existing form-body asserts (`grant_type=client_credentials`, `scope`, `resource`). `TestQuotaRelayWiringUsesExactMachineContract` (:20) keeps pinning the exact form contract. Any future drift to a JSON mint fails at the source.

**R7.2 — strict-mode end-to-end pin (`test/billing_form_e2e_test.go`, package `ssotest`, test `TestBillingFormE2E` — matching requirements §10 step 4; the name `billing_strict_form_e2e_test.go` is retired; style of `test/quota_projection_e2e_test.go`).**

- Build `sso.NewServer` with `sso.WithCredentialFormOnly(true)` (**mandatory, not robustness**: the option is opt-in default-off — `sso.go:76` seeds `credentialFormOnly = false` — so without it the harness is the legacy dual-mode server and the test cannot fail), wiring the same pieces `newFormHarness` uses (memory user provider, memory client store, password authenticator, Ed25519 JWT issuer, refresh-token store) plus a seeded client: `Active: true`, `TokenStrategy: "jwt"`, `GrantTypes` incl. `client_credentials`, `AllowedScopes` covering the three billing scope sets (empty allowlist = unrestricted also works; the scope registry is nil/unwired in the harness, matching the default-off baseline). Serve via `httptest.NewServer(srv.Handler())`.
- Wire the **real** token sources exactly as `cmd/snaplink-billing` does — audit `NewOAuthTokenSource` (`relay.go:46-51`), retention `NewPlatformTokenSource` (`quota_relay.go:347-352`), quota `NewOAuthTokenSource` (`quota_relay.go:427-431`) — with `AllowInsecureLoopback: true` for the httptest URL. One fresh source per identity: each constructor site owns an independent mutex + singleflight token cache, so reusing one instance would mask every mint after the first (zero HTTP within TTL).
  - Audit relay: `NewOAuthTokenSource(OAuthTokenConfig{TokenURL: srv.URL+"/token", ClientID, ClientSecret, SourcePrefix, Scope: "audit:event:write" (defaultAuditScope, config.go:22), Resources: [resource], Timeout, AllowInsecureLoopback: true}, httpClient)`.
  - Quota relay: same constructor, `Scope: "tenant-quota:projection:write"` (quota_relay.go:144).
  - Retention projector: `NewPlatformTokenSource(PlatformTokenConfig{..., Scope: auditgovernance.PlatformRetentionScope = "audit:platform:cross_tenant audit:policy:write" (platform_token.go:18), AllowInsecureLoopback: true}, httpClient)`.
- Drive each source's token fetch against the strict server's `/token`; assert 200-equivalent success (non-empty `access_token`, `expires_in > 0` via the sources' own validation in `fetchToken`/`platformTokenRequest`). This is the missing pin: these are the exact code paths the billing relays wire, exercised against a real strict-mode `/token`, without importing `package main` (Go forbids it).
- **JSON control arm (mandatory — the form arm alone is vacuous).** Both sources hardcode the canonical form CT (`oauth_token_source.go:200-210`, `platform_token.go:151-162`), so a strict and a legacy dual-mode server both answer 200 to the form arm; a strict-mode regression is invisible to it. The control arm is therefore a **raw JSON POST** (reuse `rawPost`, `test/credential_content_type_test.go:119`) to the **same TokenURL with the same BasicAuth credentials** each real source uses, against the same strict server: assert **exact 415** + `exact415Body` (`{"error":"invalid_request"}\n`; `assert415` at `credential_content_type_test.go:142-156` also checks both no-store headers on the row). The form-200 / JSON-415 pair is load-bearing: the bind gate precedes client auth (`server_token.go:30` → :35), so the form arm proves the credentials valid and binding while the JSON arm isolates media-type enforcement — neither arm alone distinguishes CT rejection from credential rejection. Belt-and-braces: reuse `mintCountingIssuer` (`credential_content_type_test.go:43-58`) and assert exactly **3 `Issue` calls** after all arms — one per fresh source (no cache masking) and zero from the JSON arm (side-effect-free 415).
- Readiness observable: the mint success is precisely what `auditModule.Ready` / `quotaRelay.Ready` (`app.go:100,103`) depend on, so the e2e proves the T-8(e) operational contract; the readyz handler wiring itself stays covered by existing billing tests (no `package main` import possible).

## 4. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/oauthwire/... -run 'TestBindStrict|FuzzBindParamsFormOnly' -v
go test ./protocols/oauth/ -run 'TestBindParams|TestBindCredentialParams|Fuzz' -v   # legacy pins stay green
go test ./cmd/snaplink-billing/ -run 'TestQuotaRelay|TestRetention' -v              # R7.1
go test ./test/ -run 'TestFormEncoded_|TestToken_|TestIntrospect_|TestRevoke_|TestPAR|TestDevice|TestMFA|TestCIBA|TestCredentialContentType|TestBillingFormE2E|TestTokenNoStore' -v
go test ./shared/security/ -race -count=10                                           # T-9 case 18
go test ./... -race
go test ./test/ -run TestE2E -v
make ci
```

Handoff uses the **six-step** verification plan of requirements §10 (steps 1-5 targeted checks, step 6 `make ci`); the command list above is that plan's targeted expansion and already carries the amended test name `TestBillingFormE2E`.

Pre-existing failures to report separately: none known in the cited surface; `checks/directory_fanout.py` state unchanged (no new packages, no new non-test files in ceiling directories).
