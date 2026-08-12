# Requirements Spec: B4-4 — Form-urlencoded-only /token family (opt-in, default-off)

**Revision 2 — supersedes the 2026-08-07 revision** of this file (which pinned a
default-ON strict flip for a differently-worded direction entry). The analysis
file was revised and this direction entry re-selected: strict mode is now
**opt-in, default-off**, rejection is **415** (or the documented form-only error),
and the acceptance adds the mode-off baseline pins and the deploy-tree single
flip point (T-8(a-e)).

- Direction: B4-4 Content-Type hardening, entry 3 of
  `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`
  ("Enforce application/x-www-form-urlencoded on the /token family credential
  endpoints (B4-4 Content-Type hardening), opt-in for wire compatibility")
- Direction scores: value 6 / risk_reduction 7 / effort 4 / confidence 10
- Module label: `cmd/snaplink-audit-provisioner` (analysis-file label; the module
  is a **consumer** of `/token` — it mints `client_credentials` via
  `auditgovernance.PlatformTokenSource`, verified §1 C8). Actual owning layers:
  `protocols/oauth/oauthwire` (parsing surface), `protocols/oauth`
  (`handle_introspect.go`, `handle_revoke.go`, `handle_par.go`), `interfaces/sso`
  (`server_token.go`), `config` (switch), `ops/deploy` (single flip point).
- Status: requirements (all citations re-verified against the working tree, HEAD
  `1881c55d`; the strict-mode knob is confirmed unlanded)
- Prior art: accepted sibling spec
  `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md`
  (cited by the direction as precedent) and the earlier revision of this file.
  This spec keeps the sibling's verified shared-surface facts and mechanism
  shape, and inverts the default per this direction's explicit "gated
  (default-off) to preserve the byte-identical baseline" mandate.

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Direction citation | Measured reality | Verdict |
|---|---|---|
| `protocols/oauth/oauthwire/bind.go:30-45` — dispatches on Content-Type; default branch accepts JSON, missing CT, and any unexpected CT | `func BindParams` at :28. CT read :30, parameter-strip + lowercase normalization :31-35, `switch ct` :37, form case :38-42 (`r.ParseForm` + `formIntoStruct`), `default:` :43-45 → `decodeSingleJSON` (call at :46) for `application/json`, missing CT, and any unexpected media type. Doc comment :15-25: JSON is "a non-standard convenience for SPAs"; "Empty body + no Content-Type is treated as JSON for backward compatibility" | Confirmed exact (dispatch spans 28-47) |
| `protocols/oauth/oauthwire/auth_code_handler.go:83-85` — existing constant-time PKCE | `VerifyPKCE` :78; the two `subtle.ConstantTimeCompare` calls sit at **:83** (S256 derived) and **:85** (plain/"" method) | Confirmed exact |
| `interfaces/sso/server_token.go:204` — `rejectUnregisteredScopes` seam | Comment block :189-200, `func (s *Server) rejectUnregisteredScopes` :201, `return scoperegistry.RejectUnregistered(...)` :203, closing brace :204. The seam the direction cites is at :201-203 | Confirmed with 1-line drift (the :204 line is the function's closing brace; the seam body is :203) |
| `shared/security/constant_time.go` | `ConstantTimeStringEq` :5 — `crypto/subtle` wrapper with explicit length check; used by `CompareClientSecret` (`client_secret.go:19`) | Confirmed exact — no work |
| `domains/authenticators/apikey.go` | `subtle.ConstantTimeCompare(hash, got[:])` at :76 inside the API-key verify path | Confirmed exact — no work |
| Sibling precedent `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md` | Exists; default-ON pin for the billing campaign item, same shared surface, plus the billing-consumer pin | Confirmed (its §1 C1-C8 facts re-verified independently below) |
| Direction's claim: "no strict-mode knob exists anywhere in oauthwire or interfaces/sso" | `grep` for Content-Type gates: `bind.go:30` is the only Content-Type read in `oauthwire` (non-test); no `BindParamsFormOnly` / `CredentialFormOnly` / `require_form_content_type` / `form_only` identifiers anywhere in the tree | Confirmed exact — mechanism unlanded |
| Direction's claim: "The rest of the hardening item is already present" | Body-only parsing (`r.PostForm` in `formIntoStruct`); no-store before parse at every credential site (`server_token.go:22` via `tokenNoStoreHeaders`; `middleware.TokenNoStoreHeaders` at `handle_introspect.go:113`, `handle_revoke.go:69`, `handle_par.go:56`); cc no-refresh_token (`internal/handler/tokengrant/token_client_credentials.go:20-23,67-73`); introspection caller auth (`handle_introspect.go:134/202`, identical `401 invalid_client` collapse); Basic-over-body precedence (pinned by `test/oauth_bind_test.go:146` `TestFormEncoded_BasicAuthOverridesBodyCreds`) | Confirmed exact — no work; kept as regression pins |
| T-8(d) premise — "oauth/bind_bench_test.go, SDK compat tests" | `protocols/oauth/bind_bench_test.go` exists: `BenchmarkBindParamsForm` :74, `BenchmarkBindParamsJSON` :89 (both drive dual-mode `BindParams`). SDK compat tests = `test/credential_sdk_form_test.go` (`TestSdkForm_*`, build `sso.NewServer` WITHOUT any strict option). `TestFormEncoded_JSONStillWorks` (`test/oauth_bind_test.go:272`) and `TestBindParamsJSONDefault` (`protocols/oauth/bind_extra_test.go:148`) pin the JSON/missing-CT acceptance | Confirmed exact — these are the mode-OFF baseline pins (must pass unchanged, zero migration) |
| T-8(e) premise — deploy tree | sso-server config in the deploy tree: `ops/deploy/compose/config.yaml` (`server:` block :9-16; the B4-2 `oauth.scope_registry` block :63-67 is the in-tree precedent for a campaign flag). Every `/token` consumer in the compose tree mints form-encoded with the Content-Type header: billing quota relay `:112` + stripe `:190` via `auditgovernance` sources (`oauth_token_source.go:200-210`, `platform_token.go:151-162`), stripe adapter's own `clientToken` (`cmd/snaplink-stripe-adapter/billing.go:157-165`), audit-provisioner `:237` via `NewPlatformTokenSource`. No sso-server delivery check exists today (only `checks/test_billing_delivery.py` / `test_stripe_delivery.py` patterns) | Confirmed exact — the flip point is safe for every in-tree consumer; the sweep assertion is new |

Additional verified facts that shape the spec:

- **C1 — the four named bind sites.** `/token` `server_token.go:30` (`bindOAuthParams` alias, `server_jar.go:304` → `protocols/oauth/aliases.go:97`); `/token/introspect` `handle_introspect.go:120`; `/token/revoke` `handle_revoke.go:75`; `/par` `handle_par.go:66` — the latter three call `oauth.BindParams` directly from `protocols/oauth`. All four map a bind error to `400 invalid_request` today (`server_token.go:33` via `errorBody`; the protocol sites via plain `core.ErrorBody`).
- **C2 — shared binder, non-credential consumers must NOT change.** `oauth.BindParams` is also used by `/device/code` (`server_device.go:53`), `/device/verify` (:242), `/auth/mfa` (`server_mfa.go:255`), CIBA (`handle_ciba.go:87`), and non-credential surfaces (`interfaces/commerce/*` REQUIRES JSON at `payment_ingest.go:99`, `interfaces/admin/*`, `protocols/selfservice/*`). This direction's acceptance names **four** endpoints (`/token`, `/introspect`, `/revoke`, `/par`). Enforcement is scoped to those four sites via a flag-aware dispatcher; a global `BindParams` default flip is rejected (same disposition as the sibling spec).
- **C3 — T-9 precedence.** Body parse precedes client auth today (`server_token.go:30` → `authenticateTokenClient` :35; `handle_introspect.go:120` → `authenticateIntrospectClient` :134). Under strict mode an unauthenticated **JSON** introspect 415s at the parse stage (that is T-8(a)); every request that binds on the form wire still reaches the auth gate and returns `401 invalid_client` (T-9). Client-auth-before-parse is rejected — it would make body-credential authentication unreachable and break the AGENTS.md invariant "HTTP Basic wins over body credentials".
- **C4 — mechanism seams (verified for the opt-in wiring).** `sso.Option` pattern (`interfaces/sso/options.go`, `WithMaxTokenBytes` :103); `NewServer` seeds defaults before applying options (`interfaces/sso/sso.go:58-80`, `issuer = DefaultIssuer` :67, limiter seed :80); accessors live in `interfaces/sso/accessors_handlers.go` (:405 `IntrospectionCache` precedent); the three protocol handlers take Deps interfaces satisfied by `*sso.Server` (`IntrospectDeps` `handle_introspect.go:27`, `PARDeps` `handle_par.go:18`, `RevokeDeps` `handle_revoke.go:16`); `ServerConfig` at `config/config_server.go:16`; `Config.ServerOptions()` at `config/config_load.go:301` appends `sso.WithX` options append-only-when-set (the `FeatureGatesConfig.anySet()` precedent :342-345); `cmd/sso-server/build_app_core.go:154` consumes `cfg.ServerOptions()`.
- **C5 — contract docs.** `docs/openapi.yaml` declares BOTH `application/x-www-form-urlencoded` and `application/json` request bodies on `/token`, `/token/introspect`, `/token/revoke`, `/par`. Because the mode is **default-off**, the JSON variant must STAY (delta vs the sibling default-ON specs, which removed it); only a description note naming the opt-in key is added. `/register` is JSON-only (RFC 7591 §3.1, `ctx.Bind`) and untouched. `/auth/login` JSON-only, untouched.
- **C6 — module consumer (C8 of the direction's problem).** `cmd/snaplink-audit-provisioner/run.go:50-58` builds `auditgovernance.NewPlatformTokenSource` (TokenURL from `settings.env`); `defaultPlatformTokenConfig` (`platform_token.go:65-68`) defaults `Scope` to `PlatformProvisioningScope` (`platform_token.go:17`); `platformTokenRequest` (`platform_token.go:151-162`) sends `url.Values{grant_type,scope,resource}`, Basic auth, and `Content-Type: application/x-www-form-urlencoded` (:162). The provisioner's mint **already speaks the mandated wire format** — the strict flip is a no-op for the module; nothing in `cmd/snaplink-audit-provisioner` needs changing (only 6 non-test `.go` files; budgets untouched).
- **C7 — fuzz harness.** `FuzzBindParams` at `protocols/oauth/bind_fuzz_test.go:34` seeds form/JSON/`text/plain`/missing-CT classes; the strict binder needs its own fuzz entry (re-seed per R5.3), never a panic, never a successful bind for non-form CT.
- **C8 — pre-existing cross-item condition (not ours).** `test/credential_sdk_form_test.go` documents `TestSdkForm_PARClaimsThreaded` as deliberately RED until a sibling PAR-claims form branch lands in `oauthwire/bind.go`; unrelated to this direction, reported for CI triage. Its header comment (:8-9) describing the JSON-rejection control arm as "400 invalid_request" is updated to the 415 pin in the same change (R5.2).

## 2. Goal and user outcome

RFC 6749 §3.2 / RFC 7662 §2.1 / RFC 7009 §2.1 / RFC 9126 §4.1 mandate
`application/x-www-form-urlencoded` on `/token`, `/token/introspect`,
`/token/revoke`, and `/par`. Today `oauthwire.BindParams` (bind.go:43-46) accepts
`application/json` and defaults missing and any unexpected Content-Type to JSON
decoding on all four. Because JSON acceptance is a documented convenience for
SPAs and internal callers, the enforcement is an **opt-in strict mode, default
OFF**: untouched deployments keep the byte-identical baseline (the SDK compat
tests, the JSON bench, and every JSON-body test keep passing unmodified), and an
operator flips ONE config key to make the four endpoints reject
`application/json`, missing Content-Type, and any unexpected Content-Type with
`415 Unsupported Media Type` + the documented form-only error body before any
body parse — never minting, never storing a PAR, never revoking.

Completion marker: with `server.require_form_content_type: true`, every
form-urlencoded happy path on the four endpoints is byte-identical to today
(client_credentials, authcode+PKCE, refresh+rotation, device grant on `/token`,
exchange, delegation, introspection single+batch, revocation, PAR), JSON /
missing / unexpected Content-Type return the same 415 envelope on all four
endpoints, an unauthenticated form-encoded introspect still returns
`401 invalid_client` (T-9), the deploy tree flips the mode in exactly one place
(`ops/deploy/compose/config.yaml`) proven by a sweep assertion, and the
audit-provisioner's real `PlatformTokenSource` mint still returns 200 against a
strict-mode server with zero module code changes.

## 3. Product boundary

- Surface: server wire contract (`protocols/oauth/oauthwire` strict binder +
  `protocols/oauth` handlers `handle_introspect.go`/`handle_revoke.go`/
  `handle_par.go` + `interfaces/sso/server_token.go` + `config` switch +
  `ops/deploy/compose/config.yaml` flip point); module consumer pin in `test/`
  (ssotest).
- Default: **strict mode OFF** (opt-in). `sso.NewServer` without the option and
  `cmd/sso-server` without the config key are byte-identical to today. This is
  the direction's explicit "gated (default-off) to preserve the byte-identical
  baseline" mandate and the delta vs the superseded revision and the billing
  sibling.
- Explicit non-goals (do not implement):
  - No flip of `/device/code`, `/device/verify`, `/auth/mfa`,
    `/backchannel-authentication` (CIBA) — the direction's acceptance names four
    endpoints. They share the binder; a design-stage extension decision is
    recorded in §8, but no acceptance depends on it and the change is NOT made
    here.
  - No change to non-credential `BindParams` consumers (commerce/admin/
    selfservice) — byte-identical (C2).
  - No change to `/auth/login` (JSON-only, `server_login.go:27`) or `/register`
    (JSON-only per RFC 7591 §3.1, `ctx.Bind`).
  - No in-repo JSON caller migration, no `TestFormEncoded_JSONStillWorks` /
    `TestBindParamsJSONDefault` inversion, no openapi `application/json`
    requestBody removal — the opposite of the sibling default-ON specs, because
    the mode is off by default (acceptance T-8(d) pins these unchanged).
  - No change to client-authentication ordering (body parse → client auth stays;
    R4).
  - No new routes, no store changes, no gensdk emission changes, no
    `cmd/snaplink-audit-provisioner` production-code change (C6).
  - Not in scope: B4-1 (issuer allowlist), B4-2 (scope registry — sibling spec
    exists), B4-3 (discovery truthiness), B4-5 (governance outbox) from the same
    analysis file.

## 4. Module classification

- [x] OAuth/OIDC/protocol flow (credential-endpoint wire hardening, opt-in)
- [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization
- [x] Infrastructure/config (the opt-in key) · [ ] Cold module · [ ] Refactoring only

Owning layers: `protocols/oauth/oauthwire` (strict binder), `protocols/oauth`
(`handle_introspect.go`, `handle_revoke.go`, `handle_par.go`), `interfaces/sso`
(`server_token.go`, options, accessor), `config`, `ops/deploy`.
`cmd/snaplink-audit-provisioner` contributes a consumer pin only (tests in
`test/`, package ssotest). Dependency direction unchanged; nothing imports
`cmd/`.

## 5. Requirements

### R1 — Opt-in strict mode: the four /token family endpoints accept only `application/x-www-form-urlencoded`

A server built with the strict option enabled rejects any other Content-Type on
these four endpoints **before any body parse and before any credential/request
processing**:

| Endpoint | Handler / bind site | Rejection (strict mode) |
|---|---|---|
| POST `/token` (all grants: authcode, refresh, device, cc, exchange, delegation) | `handleToken`, `server_token.go:30` | `415` + `{"error":"invalid_request"}` |
| POST `/token/introspect` | `HandleIntrospect`, `handle_introspect.go:120` | `415` + `{"error":"invalid_request"}` |
| POST `/token/revoke` | `HandleRevoke`, `handle_revoke.go:75` | `415` + `{"error":"invalid_request"}` |
| POST `/par` | `HandlePAR`, `handle_par.go:66` | `415` + `{"error":"invalid_request"}` |

- The 415 body is the plain `core.ErrorBody(ErrInvalidRequest)` shape — no
  trace_id, byte-identical on all four endpoints for every rejection cause
  (JSON, missing CT, unexpected CT): no new oracle (AGENTS.md §3). The status
  code is the direction's primary choice ("415 (or the documented form-only
  error)") and is documented as the form-only rejection in `docs/error-codes.md`
  and openapi.
- Content-Type comparison is parameter-tolerant exactly as today (bind.go:31-35
  strips `;charset=…`): `application/x-www-form-urlencoded; charset=UTF-8`
  binds; `application/json; charset=utf-8` rejects.
- Form parsing keeps `r.ParseForm` + `formIntoStruct` semantics unchanged
  (multi-value and space-separated `scope`/`resource`).
- No-store headers (`tokenNoStoreHeaders` / `middleware.TokenNoStoreHeaders`
  at `handle_introspect.go:113`, `handle_revoke.go:69`, `handle_par.go:56`) are
  already set before parsing — the 415 responses carry
  `Cache-Control: no-store` + `Pragma: no-cache` like every other credential
  response.

### R2 — Missing and unexpected Content-Type are rejected (strict mode)

- Missing `Content-Type` header → 415 (the "empty body + no Content-Type is
  treated as JSON" default at bind.go:26-27 is gone from the four sites).
- Unexpected Content-Type (`multipart/form-data`, `text/plain`,
  `application/octet-stream`, `application/json`, …) → 415.
- Valid form CT with an empty body continues to reach the existing per-endpoint
  validation (e.g. `/token` → `400 invalid_request` for missing `grant_type`),
  unchanged.

### R3 — Form-urlencoded requests are byte-identical to today (strict mode)

With the option enabled, every request that binds on the form wire produces the
same response as today, byte for byte: the grant matrix (client_credentials,
authcode+PKCE, refresh+rotation+family-reuse, device, exchange, delegation),
introspection (single + batch), revocation (idempotent 200), PAR → authorize.
The strict binder shares the form path (`ParseForm` + `formIntoStruct`) with
`BindParams` — one definition of form semantics, so no drift is possible.
HTTP Basic precedence over body credentials stays (regression-pinned by
`TestFormEncoded_BasicAuthOverridesBodyCreds`).

### R4 — T-9 regression preserved: `/introspect` without credentials still 401

Preserved from the direction's problem statement ("introspection caller auth …
already present"): for every request whose body binds on the form wire, an
unauthenticated `/token/introspect` returns `401 invalid_client`, never 415 and
never 200 — the auth gate (`authenticateIntrospectClient`,
`handle_introspect.go:134/202`) is reached for every bindable request. An
unauthenticated **JSON** introspect request 415s at the parse stage — that is
T-8(a), the intended precedence. Client-auth-before-parse is rejected: it would
make body-credential authentication unreachable and break the AGENTS.md "HTTP
Basic wins over body credentials" invariant.

### R5 — Mechanism: scoped strict binder + config option, default OFF ([PROPOSED] per the direction)

The direction mandates the change be "gated (default-off)". Pinned decisions
(mechanism shape reuses the superseded design's verified seams; only the
default and the status code change):

1. **Strict binder in `oauthwire`**: a new small file `bind_strict.go` adds
   `BindParamsFormOnly(ctx, v)` — form CT → `ParseForm` + `formIntoStruct`
   (shared helpers factored out of `bind.go` :31-42, byte-identical); any
   other/missing CT → an exported sentinel error `oauthwire.ErrFormOnly` before
   reading the body (exported so the four sites can map it to 415; never written
   to the wire — it is an internal sentinel, not an `Err*` wire code;
   `docs/error-codes.md` gains no code, only the 415 note). A predicate
   `oauthwire.IsFormOnly(err)` may be used instead at design time; naming
   [PROPOSED].
2. **Flag-aware dispatch**: `protocols/oauth` aliases the strict binder
   (aliases.go:97 sibling) and `interfaces/sso/server_jar.go:304` gains
   `(s *Server) bindCredentialParams(ctx, v) error` returning
   `bindOAuthParams(ctx, v)` unchanged when the flag is false (zero behavioral
   delta — mode off is the byte-identical baseline) and
   `oauth.BindParamsFormOnly(ctx, v)` when true. The three protocol-layer sites
   read the flag through a new `RequireFormContentType() bool` accessor on
   `*sso.Server`, added to `IntrospectDeps` (`handle_introspect.go:27`),
   `PARDeps` (`handle_par.go:18`), `RevokeDeps` (`handle_revoke.go:16`) —
   matching the `IntrospectionCache()` accessor precedent
   (`accessors_handlers.go:405`). `/token` uses the Server method directly.
3. **Handler mapping**: at the four sites, `errors.Is(err, oauthwire.ErrFormOnly)`
   → 415 + plain `{"error":"invalid_request"}`; any other bind error → the
   existing 400 path unchanged.
4. **Option + config key**: `sso.WithCredentialFormOnly(v bool) Option`
   (`interfaces/sso/options.go` beside `WithMaxTokenBytes` :103) sets
   `Server.credentialFormOnly`, **seeded `false`** in `NewServer`
   (`interfaces/sso/sso.go:58-80` — the seed is the default-off pin for SDK
   embedders). `ServerConfig.RequireFormContentType *bool`
   (`yaml:"require_form_content_type"`, `config/config_server.go:16`): `nil`
   (unset) → option NOT appended (byte-identical `ServerOptions()`, matching the
   `FeatureGatesConfig.anySet()` precedent at `config_load.go:342-345`); `true`
   → `WithCredentialFormOnly(true)`; `false` → `WithCredentialFormOnly(false)`
   (explicit legacy, same as unset). `cmd/sso-server/build_app_core.go:154`
   needs no change. No deprecation warning for `false` (it is the default, not a
   migration hatch).
5. **Fuzz re-seed**: `FuzzBindParams` (`bind_fuzz_test.go:34`) gains a
   strict-binder entry: arbitrary CT+body bytes under `BindParamsFormOnly` never
   panic and never produce a successful bind for non-form CT; form CT binds or
   fails only via the `ParseForm` error path.

### R6 — Deploy tree: one flip point + sweep assertion

- The mode is flipped in exactly one place in `ops/deploy`:
  `ops/deploy/compose/config.yaml` gains `require_form_content_type: true` under
  the `server:` block (:9-16) — the canonical sso-server config of the deploy
  tree (the B4-2 `oauth.scope_registry` block :63-67 is the in-tree precedent
  for a campaign flag living there). Every `/token` consumer in the compose tree
  already mints form-encoded with the Content-Type header (C6: billing quota
  relay, stripe adapter `billing.go:157-165`, audit-provisioner), so the flip is
  provably safe and is the point of the acceptance.
- **Sweep assertion** (new, Go, `test/` package ssotest — the harness gate; the
  `checks/test_*_delivery.py` Python reports are supplementary):
  `TestDeployTreeRequireFormContentTypeSingleFlipPoint` reads
  `ops/deploy/compose/config.yaml` and asserts (a) the key exists under
  `server:` with value `true`; (b) the key appears in NO other file under
  `ops/deploy/` (single flip point — the helm chart
  `ops/deploy/helm/sso-server/values.yaml` and `ops/deploy/audit-provisioner/`
  stay on the default-off posture); (c) `docs/config-reference.md` documents the
  key with its default. The test fails if a second flip point is introduced
  (guards drift).
- `ops/deploy/audit-provisioner/settings.env` is unchanged: its
  `SNAPLINK_AUDIT_PROVISIONER_TOKEN_URL` points at the sso-server `/token`, and
  the provisioner's mint is form-encoded by construction (R7).

### R7 — Module consumer pin (this module's distinctive deliverable)

The strict flip must be proven not to break the audit-provisioner mint. A new
e2e test in `test/` (style of the sibling's billing pin): build `sso.NewServer`
with `sso.WithCredentialFormOnly(true)` (the harness constructs the server
directly, so the option is the seam), register a `client_credentials` client
with the provisioner identity (`id: snaplink-audit-provisioner`, secret, the
`audit-governance` resource), then drive the REAL
`auditgovernance.PlatformTokenSource` — exactly as `cmd/snaplink-audit-provisioner/run.go:50-58`
wires it, with no `Scope` so the `PlatformProvisioningScope` default
(`platform_token.go:17,65-68`) applies — against the server's `/token` and
assert 200 + non-empty Bearer token. This is the exact code path the module
uses, so the pin holds without importing `package main`. Cross-item ordering:
the pin does NOT enable `oauth.scope_registry` (default-off); under the B4-2
sibling, the client's `allowed_scopes` must carry `PlatformProvisioningScope` —
both gates are independent and compose.

### R8 — Contracts in the same change (AGENTS.md §5.6)

- `docs/config-reference.md` — the `server.require_form_content_type` key,
  default off, byte-identical when unset.
- `docs/error-codes.md` — note on the `invalid_request` row(s): under the opt-in
  strict mode the four credential endpoints return 415 with this body for
  JSON/missing/unexpected Content-Type; no new codes.
- `docs/openapi.yaml` — the dual requestContentType declarations on the four
  paths stay (JSON remains valid by default); each gains a description note
  naming the opt-in key and the 415 behavior. Do NOT touch `/register`, the
  admin paths, or the device/MFA/CIBA paths.
- CHANGELOG — opt-in hardening entry (non-breaking by default).

## Testable acceptance (Given/When/Then — preserves the supplied T-8(a-e) verbatim)

T-8(a) — strict mode rejects JSON and missing Content-Type on `/token` and never mints:

1. Given a strict-mode server (`WithCredentialFormOnly(true)`), a valid
   client_credentials body sent as `application/json` (and
   `application/json; charset=utf-8`), when POSTed to `/token`, then `415` with
   `{"error":"invalid_request"}` and NO token minted (assert via a non-200 and a
   recorder/issuer spy that no issuance occurred); repeat for authcode exchange,
   refresh, device-poll, exchange, delegation bodies — same 415, no side effect.
2. Given the same JSON body with VALID client credentials (HTTP Basic), when
   POSTed to `/token`, then 415, not 200 (rejection precedes client auth and
   grant processing).
3. Given a bare POST to `/token` with no Content-Type header and a JSON-shaped
   body, then 415 (the JSON-default path at bind.go:43-46 is gone under strict
   mode); given no Content-Type with an empty body, then 415 (not the old
   empty-body JSON default).
4. Given `application/x-www-form-urlencoded; charset=UTF-8` with the same
   client_credentials body, then the request binds and mints 200 — parameter-
   tolerant comparison (R1).

T-8(b) — form-urlencoded requests are byte-identical to today:

5. Given the full `TestFormEncoded_*` family (`test/oauth_bind_test.go` incl.
   `TestFormEncoded_BasicAuthOverridesBodyCreds` :146,
   `TestFormEncoded_ScopeSpaceSeparated`), `protocols/oauth/bind_extra_test.go`
   `TestBindParamsContentTypeWithCharset` :162, `test/scope_registry_test.go`,
   `test/ciba_*`, and `test/credential_sdk_form_test.go`, when run against BOTH
   a strict-mode and a default server, then every request/response pair matches
   byte for byte (status, headers incl. no-store, body).
6. Given a strict-mode server, a refresh grant with rotation, then the rotated
   response matches the non-strict response byte for byte and the old token is
   single-use as today.

T-8(c) — /introspect, /revoke, /par behave identically:

7. Given JSON bodies (valid token+creds, valid revoke payload, valid PAR
   request) on `/token/introspect`, `/token/revoke`, `/par`, when the server is
   strict, then 415 `{"error":"invalid_request"}` in all three cases and NO side
   effect (no introspection result, no revocation, no PAR stored).
8. Given missing Content-Type on the same three endpoints, then 415.
9. Given `multipart/form-data`, `text/plain`, `application/octet-stream` bodies
   on all four endpoints, then 415 in all twelve combinations (T-8(e) of the
   sibling matrix, restricted to the four endpoints).
10. Given form-encoded requests on the same three endpoints (introspect single +
    batch, revoke idempotent, PAR), then byte-identical to the default server
    (case 5 comparison).
11. Given an unauthenticated form-encoded `/token/introspect` with a valid token
    field, then `401 invalid_client` — the auth gate is reached for every
    bindable request (T-9, R4); `TestIntrospect_RejectsMissingCreds` /
    `TestIntrospect_RejectsWrongSecret` / `TestIntrospect_AcceptsBasicAuth`
    (`test/handle_introspect_test.go`) stay green unmodified.
12. Given HTTP Basic + form body with conflicting body credentials on the four
    endpoints, then Basic wins exactly as
    `TestFormEncoded_BasicAuthOverridesBodyCreds` asserts today (regression-
    pinned).
13. Given every 415 and every 400/401 credential response on the four endpoints,
    then `Cache-Control: no-store` + `Pragma: no-cache` are present
    (no-store is stamped before parsing; pinned).

T-8(d) — mode off: existing JSON-body tests pass unchanged:

14. Given a default (no-option, no-config-key) server, then
    `TestFormEncoded_JSONStillWorks` (`test/oauth_bind_test.go:272`),
    `TestBindParamsJSONDefault` (`bind_extra_test.go:148`), the JSON arm of
    `BenchmarkBindParamsJSON` (`bind_bench_test.go:89`), and the SDK compat
    tests (`test/credential_sdk_form_test.go` `TestSdkForm_*`) pass UNCHANGED —
    zero test migration, zero wire change. `bind_bench_test.go` is not modified.
15. Given `ServerOptions()` with `require_form_content_type` unset, then the
    option is NOT appended (byte-identical option list vs today — the
    `anySet()` precedent); with `true` it is appended exactly once; with
    `false` it is appended with the legacy value.

T-8(e) — deploy-tree flip in one place with a sweep assertion:

16. Given the sweep test `TestDeployTreeRequireFormContentTypeSingleFlipPoint`,
    then it passes: the key exists exactly once in the deploy tree
    (`ops/deploy/compose/config.yaml` `server:` block, value `true`), in no
    other `ops/deploy` file, and is registered in `docs/config-reference.md`.
17. Given the strict-mode e2e pin with the REAL `auditgovernance.PlatformTokenSource`
    wired exactly as `cmd/snaplink-audit-provisioner/run.go:50-58` (no Scope →
    `PlatformProvisioningScope`), then the mint returns 200 with a non-empty
    Bearer access token — the audit-provisioner deploy tree (`settings.env`)
    requires NO change (R7).

Unit level:

18. Given new `oauthwire.BindParamsFormOnly` unit tests, then: form CT → binds;
    `application/json` → `ErrFormOnly`; missing CT → `ErrFormOnly`;
    `multipart/form-data` → `ErrFormOnly`; `application/x-www-form-urlencoded;
    charset=UTF-8` → binds; empty body with form CT → binds empty (per-endpoint
    validation downstream); malformed percent-encoding → `ParseForm` error path
    (NOT `ErrFormOnly`).
19. Given the re-seeded `FuzzBindParams` (strict entry), then arbitrary CT+body
    bytes under `BindParamsFormOnly` never panic and never produce a successful
    bind for non-form CT.
20. Given the existing constant-time coverage (`shared/security/client_secret_test.go`,
    PKCE at `auth_code_handler.go:83-85`, apikey at `domains/authenticators/apikey.go:76`)
    run with `-race -count=10`, then green — the "already present" hardening
    items stay regression-pinned (no work).

## 6. Engineering-gate constraints (verified)

- **Budgets**: no new packages. `oauthwire/bind.go` (140 lines) gains a small
  `bind_strict.go` (well under 500 lines/file, 50 lines/function, complexity 15,
  nesting 3). `interfaces/sso` is at its 60-file ceiling: `server_token.go`
  changes its call target only, the accessor lands in the existing
  `accessors_handlers.go`, the option in the existing `options.go` — no new
  files. `cmd/snaplink-audit-provisioner` is untouched (6 non-test files).
- **Oracle safety**: the 415 body is one deterministic plain
  `{"error":"invalid_request"}` shape shared by all four endpoints and all
  rejection causes; `ErrFormOnly` never reaches the wire. No new `Err*` codes.
  `/auth/mfa` is untouched, so the `mfa_invalid` oracle table row is
  unchanged.
- **Wire compatibility**: default-off is the byte-identical baseline (R5.2);
  non-credential `BindParams` consumers unchanged; `/auth/login` and `/register`
  untouched; the JSON requestBody variants stay in openapi.
- **Headers/middleware**: no-store/Pragma stamping stays at the top of every
  handler before parsing; middleware order and probes-outside-rate-limiting
  posture untouched.
- **Dependency direction**: strict binder in `protocols/oauth/oauthwire`;
  `interfaces/sso` imports downward; the Deps accessor pattern is the existing
  one; nothing imports `cmd/`.

## 7. Files

### Create

```text
protocols/oauth/oauthwire/bind_strict.go — BindParamsFormOnly + ErrFormOnly sentinel
    (+ IsFormOnly predicate if the design prefers); shares normalizedMediaType/bindForm
    factored byte-identically from bind.go:31-42.
protocols/oauth/oauthwire/bind_strict_test.go — unit acceptance cases 18 (+19 fuzz hooks).
test/credential_content_type_test.go — endpoint-level strict-mode negative tests
    (cases 1-4, 7-10, 13) on the newFormHarness pattern (test/oauth_bind_test.go:28).
test/audit_provisioner_form_e2e_test.go — R7: strict sso.NewServer + real
    PlatformTokenSource, provisioner identity/scopes; case 17.
test/deploy_form_only_sweep_test.go — R6 sweep assertion; case 16.
```

### Modify

```text
protocols/oauth/oauthwire/bind.go — factor CT normalization (:31-35) and the form path
    (:38-42) into shared helpers (byte-identical); doc comment notes the strict surface
    is additive and the JSON default applies to non-credential consumers.
protocols/oauth/aliases.go — alias BindParamsFormOnly beside BindParams (:97).
protocols/oauth/handle_introspect.go:120, handle_revoke.go:75, handle_par.go:66 —
    switch the bind call to the flag-aware dispatcher (accessor via Deps; 415 mapping).
interfaces/sso/server_token.go:30 — same switch via s.bindCredentialParams (R5.2).
interfaces/sso/server_jar.go:304 — s.bindCredentialParams beside bindOAuthParams.
interfaces/sso/options.go — sso.WithCredentialFormOnly(bool) beside WithMaxTokenBytes (:103).
interfaces/sso/sso.go:58-80 — seed Server.credentialFormOnly = false in NewServer.
interfaces/sso/accessors_handlers.go — RequireFormContentType() accessor (:405 sibling).
protocols/oauth/handle_introspect.go:27, handle_par.go:18, handle_revoke.go:16 —
    one new accessor member on each Deps interface.
config/config_server.go:16 — ServerConfig.RequireFormContentType *bool (yaml key).
config/config_load.go:301 — append the option iff the key is set (anySet precedent).
protocols/oauth/bind_fuzz_test.go:34 — strict-binder fuzz entry (R5.5).
test/credential_sdk_form_test.go:8-9 — update the control-arm comment to the 415 pin
    (comment-only; the tests themselves stay green unmodified).
ops/deploy/compose/config.yaml:9-16 — server.require_form_content_type: true (R6).
docs/config-reference.md — the R6/R8 key, default off.
docs/error-codes.md — 415 form-only note on the invalid_request row(s).
docs/openapi.yaml — description note on the four credential paths (JSON variant stays).
CHANGELOG — opt-in hardening entry.
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go:43-46 dual-mode default — the byte-identical baseline
    under the default-off mode; non-credential consumers depend on it.
interfaces/sso/server_device.go:53,242, server_mfa.go:255, protocols/oauth/handle_ciba.go:87 —
    device/MFA/CIBA stay on the dual-mode binder (non-goal; §8 design note).
interfaces/sso/server_login.go, protocols/oauth/handle_register.go — JSON-only surfaces.
interfaces/commerce/*, interfaces/admin/*, protocols/selfservice/* — unchanged wire.
test/oauth_bind_test.go:272, protocols/oauth/bind_extra_test.go:148, protocols/oauth/
    bind_bench_test.go — unchanged (mode-off pins, T-8(d)).
cmd/snaplink-audit-provisioner/* — control-plane consumer, untouched (C6).
ops/deploy/audit-provisioner/*, ops/deploy/helm/sso-server/values.yaml — unchanged
    (single flip point is compose config.yaml; sweep asserts absence elsewhere).
shared/security/constant_time.go, domains/authenticators/apikey.go, oauthwire/
    auth_code_handler.go:83-85 — verified present; no work (case 20 pins them).
```

Confirm file/function/directory frozen ceilings before implementation.

## 8. Dependencies and compatibility

- New/changed SPI: `oauthwire.BindParamsFormOnly` + `ErrFormOnly` (internal
  sentinel) + alias; `sso.WithCredentialFormOnly(bool)`; one new
  `RequireFormContentType() bool` accessor on three Deps interfaces; one new
  config key `server.require_form_content_type` (default off). No interface
  store changes, no routes, no proto.
- New YAML/env keys: one (`server.require_form_content_type`), default off.
- Storage migration: none.
- HTTP compatibility: **non-breaking by default** — untouched deployments are
  byte-identical. With the mode enabled, the four endpoints return 415 for
  JSON/missing/unexpected Content-Type; out-of-tree JSON callers must either
  send form-encoded or leave the key off. In-tree consumers are all
  form-encoded already (C6).
- Rollout/rollback: flipping the key off (or deleting it) restores the legacy
  behavior exactly; the mode is boot-time config like `oauth.scope_registry`
  (no hot-reload).
- Cross-module ordering: independent of the B4-2 scope-registry sibling (both
  gate `/token` acceptance; disjoint behaviors). Independent of the gensdk
  form-emission module — with default-off, committed JSON-emitting SDKs keep
  working (T-8(d)); no ordering constraint. The PAR-claims form branch noted in
  C8 is a pre-existing sibling condition, reported separately.
- Design-stage note (non-goal): the direction's acceptance names four endpoints;
  the sibling campaign items enforced eight (adding `/device/code`,
  `/device/verify`, `/auth/mfa`, `/backchannel-authentication`). Extending the
  flip to those four later is a one-line-per-site change on the same
  dispatcher; it is NOT part of this direction and must not be smuggled in
  (scope discipline).

## 9. Documentation

- [x] `docs/config-reference.md` — `server.require_form_content_type` (default
  off).
- [x] `docs/error-codes.md` — 415 form-only note; no new codes.
- [x] `docs/openapi.yaml` — description notes on the four credential paths.
- [x] CHANGELOG — opt-in hardening entry.
- [ ] ADR — not required (additive, config-flagged, default-off). The
  audit-provisioner README is untouched (consumer behavior unchanged).

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/oauthwire/... -run 'TestBindStrict|Fuzz' -v   # new unit surface
go test ./test/ -run 'TestCredentialContentType|TestAuditProvisionerForm|TestDeployFormOnly|TestFormEncoded_|TestSdkForm_|TestIntrospect_|TestRevoke_|TestPAR' -v
go test ./test/ -run TestE2E -v
go test ./shared/security/ ./domains/authenticators/ -race -count=10   # case 20 pins
go test ./... -race
make ci
```

Pre-existing failures to report separately: `TestSdkForm_PARClaimsThreaded`
(deliberately RED until a sibling PAR-claims form branch lands in
`oauthwire/bind.go`, per its header comment — C8) and any
`checks/directory_fanout.py` state (no new packages in this change).
