# Design: B4-4 credential form-only enforcement — opt-in strict binder (default OFF), four endpoints, single deploy flip point, module consumer pin

**Revision 3 — oracle-safety hardening** (2026-08-09): independent hardening
review re-derived every oracle claim from the working tree (HEAD `3ef27fa5`)
and added §3.8 pins D1-D6 (exact 415 bytes, body-independence rows,
credential-state independence rows, no-store on both headers, dispatch
fail-closed contract, fuzz invariant). All Rev 2 decisions stand unchanged;
Rev 3 only makes the guarantees test-enforced. Evidence:
`docs/architect-analysis/auto/runs/enforce-application-x-www-form-urlencoded-on-the-0a23f017/artifacts/adversarial_review-9c87f3a7/hardening-oracle-safety.md`.

- Direction: B4-4 Content-Type hardening, **entry 3** of
  `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`
  ("Enforce application/x-www-form-urlencoded on the /token family credential
  endpoints (B4-4 Content-Type hardening), opt-in for wire compatibility");
  scores value 6 / risk_reduction 7 / effort 4 / confidence 10. Entry-3 text and
  the T-8(a-e) acceptance were re-extracted from the analysis file and matched
  verbatim against this document (verified §1).
- Module label: `cmd/snaplink-audit-provisioner` (analysis-file label; the module
  is a **consumer** of `/token` — it mints `client_credentials` via
  `auditgovernance.PlatformTokenSource`, verified §1). Owning layers:
  `protocols/oauth/oauthwire` (strict binder), `protocols/oauth`
  (`handle_introspect.go`, `handle_revoke.go`, `handle_par.go`), `interfaces/sso`
  (`server_token.go`, options, accessor, state), `config` (switch),
  `ops/deploy` (single flip point).
- Requirements baseline: `docs/architect-analysis/cmd-snaplink-audit-provisioner-b4-4-credential-form-only-requirements.md`
  **Revision 2** (supersedes the 2026-08-07 revision and this file's previous
  revision, which pinned a default-ON flip for direction entry 2, "kill the JSON
  fallback in BindParams"). All citations re-verified against the working tree
  at HEAD `61455c06`; one stale HEAD label and three sub-line drifts recorded in
  §2.
- Status: design Rev 3 (Rev 2 evidence re-verified at HEAD `3ef27fa5`; oracle-safety hardening pins D1-D6 added in §3.8; `go build ./... && go vet ./...` clean at design time — verified below)
- Prior art: accepted sibling spec/design
  `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-{requirements,design}.md`
  (same shared surface, default-ON pin) and the superseded default-ON revision
  of this file (mechanism seams reused). Two deltas are pinned by THIS module's
  requirements Rev 2 and restated in §3.4: (1) strict mode is **opt-in,
  default OFF** (the sibling and the superseded revision flipped it on);
  (2) the rejection is **415** with the plain `invalid_request` envelope (the
  superseded revision used the sites' existing 400); (3) the surface is the
  **four** named endpoints, not the sibling's eight.

## 1. Verification verdict (untrusted claims → measured reality)

Every citation in the requirements evidence summary and in the direction text
was re-checked against the working tree. All confirmed; the drifts are recorded
in §2.

| Evidence claim | Measured reality | Verdict |
|---|---|---|
| `oauthwire/bind.go:30-45` — dispatch on Content-Type; default branch accepts JSON, missing CT, and any unexpected CT | `func BindParams` :28; CT read :30; `;`-parameter strip + lowercase normalization :31-35; `switch ct` :37; form case :38-42 (`r.ParseForm` + `formIntoStruct(r.PostForm, v)`); `default:` :43-46 → `decodeSingleJSON`. Doc comment :20-25: JSON is "a non-standard convenience for SPAs"; "Empty body + no Content-Type is treated as JSON for backward compatibility" | **Confirmed exact** |
| `oauthwire/auth_code_handler.go:83-85` — existing constant-time PKCE | `VerifyPKCE` :78; the two `subtle.ConstantTimeCompare` calls at **:83** (S256 derived) and **:85** (plain/"" method) | **Confirmed exact** |
| `interfaces/sso/server_token.go:204` — `rejectUnregisteredScopes` seam | Comment block :189-200, `func (s *Server) rejectUnregisteredScopes` :201, `return scoperegistry.RejectUnregistered(...)` :203, closing brace :204. The seam the direction cites is :201-203 | **Confirmed** (the requirements already disclose the 1-line drift: :204 is the closing brace) |
| `shared/security/constant_time.go`, `domains/authenticators/apikey.go` | `ConstantTimeStringEq` wrapper at `constant_time.go:5-14` (`crypto/subtle` with explicit length check); `subtle.ConstantTimeCompare(hash, got[:]) != 1` at `apikey.go:76` | **Confirmed exact** — no work |
| Sibling precedent `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md` | Exists; default-ON pin for the billing campaign item over the same shared surface, plus the billing-consumer pin | **Confirmed** |
| Direction claim: "no strict-mode knob exists anywhere in oauthwire or interfaces/sso" | Repo-wide grep for `BindParamsFormOnly` / `CredentialFormOnly` / `require_form_content_type` / `form_only` (`.go`, `.yaml`, `.yml`, `.md` outside `docs/architect-analysis`) returns **zero hits**. `bind.go:30` is the only Content-Type read in `oauthwire` (non-test) | **Confirmed exact** — mechanism unlanded |
| Direction claim: "The rest of the hardening item is already present" | Body-only parsing (`r.PostForm` in `formIntoStruct`); no-store before parse at every credential site (`tokenNoStoreHeaders` `server_token.go:22`; `middleware.TokenNoStoreHeaders` at `handle_introspect.go:113`, `handle_revoke.go:69`, `handle_par.go:56`); cc no-refresh_token (`internal/handler/tokengrant/token_client_credentials.go:20-23,67-73`); introspection caller auth (`handle_introspect.go:134/202`, identical `401 invalid_client` collapse); Basic-over-body precedence (pinned by `test/oauth_bind_test.go:146` `TestFormEncoded_BasicAuthOverridesBodyCreds`) | **Confirmed exact** — no work; kept as regression pins |
| T-8(d) premise — `oauth/bind_bench_test.go`, SDK compat tests | `protocols/oauth/bind_bench_test.go`: `BenchmarkBindParamsForm` :74, `BenchmarkBindParamsJSON` :89 (both drive dual-mode `BindParams`). SDK compat tests = `test/credential_sdk_form_test.go` (`TestSdkForm_*`, server built WITHOUT any strict option; cc form-wire test at :69). `TestFormEncoded_JSONStillWorks` (`test/oauth_bind_test.go:272`) and `TestBindParamsJSONDefault` (`protocols/oauth/bind_extra_test.go:148`) pin JSON/missing-CT acceptance | **Confirmed exact** — these are the mode-OFF baseline pins (pass unchanged, zero migration) |
| T-8(e) premise — deploy tree | sso-server config: `ops/deploy/compose/config.yaml` `server:` block :9-16; compose.yaml mounts it at `/etc/sso/config.yaml` (:42, :57). Every `/token` consumer in the compose tree mints form-encoded with the Content-Type header: billing quota relay + stripe adapter via `auditgovernance` sources (`platform_token.go:151-162` sends `url.Values{grant_type,scope,resource}` + Basic + `Content-Type: application/x-www-form-urlencoded` at :162), stripe adapter's own `clientToken` (`cmd/snaplink-stripe-adapter/billing.go:157-165`), audit-provisioner (`run.go:50-58` → `NewPlatformTokenSource`, `TokenURL` from `settings.env`). `ops/deploy/audit-provisioner/settings.env` pins `SNAPLINK_AUDIT_PROVISIONER_CLIENT_ID=snaplink-audit-provisioner`, `RESOURCE=audit-governance`, `TOKEN_URL=…/token`. No sso-server deploy-sweep check exists today (only `checks/test_billing_delivery.py` / `test_stripe_delivery.py` patterns) | **Confirmed exact** — the flip point is safe for every in-tree consumer; the sweep assertion is new |
| C1 — the four named bind sites | `/token` `server_token.go:30` (`bindOAuthParams` alias, `server_jar.go:304` → `protocols/oauth/aliases.go:97`); `/token/introspect` `handle_introspect.go:120`; `/token/revoke` `handle_revoke.go:75`; `/par` `handle_par.go:66` — the latter three call `BindParams` directly from `protocols/oauth`. All four map a bind error to `400 invalid_request` today (`server_token.go:33` via trace-aware `errorBody`; the protocol sites via plain `core.ErrorBody`) | **Confirmed exact** |
| C2 — shared binder, non-credential consumers must NOT change | `oauth.BindParams` is also used by `/device/code` (`server_device.go:53` via `bindOAuthParams`), `/device/verify` (:242), `/auth/mfa` (`server_mfa.go:255`), CIBA (`handle_ciba.go:87`), and non-credential surfaces (`interfaces/commerce/*` REQUIRES JSON at `payment_ingest.go:99`, `interfaces/admin/*`, `protocols/selfservice/*`). This direction's acceptance names **four** endpoints | **Confirmed exact** — enforcement is scoped to the four sites; a global default flip is rejected |
| C3 — T-9 precedence | Body parse precedes client auth today (`server_token.go:30` → `authenticateTokenClient` :35; `handle_introspect.go:120` → `BasicClientCreds` :124 → `authenticateIntrospectClient` :134). Under strict mode an unauthenticated **JSON** introspect 415s at the parse stage (T-8(a)); every request that binds on the form wire still reaches the auth gate → `401 invalid_client` (T-9) | **Confirmed** — client-auth-before-parse rejected (would make body-credential auth unreachable and break the AGENTS.md "HTTP Basic wins over body credentials" invariant) |
| C4 — mechanism seams for the opt-in wiring | `sso.Option` pattern (`interfaces/sso/options.go`, `WithMaxTokenBytes` :103); `NewServer` seeds defaults before applying options (`interfaces/sso/sso.go:58-80`, `issuer = DefaultIssuer` :67); `Server` struct :33 embeds `protocolState` (`sso_protocol.go:38`) — the new field lands there; accessors in `interfaces/sso/accessors_handlers.go` (`IntrospectionCache()` :405 precedent); the three protocol handlers take Deps interfaces satisfied by `*sso.Server` (`IntrospectDeps` `handle_introspect.go:29`, `PARDeps` `handle_par.go:18`, `RevokeDeps` `handle_revoke.go:16`; `interfaces/sso/handlers.go:35/99/104` pass `s`); `ServerConfig` at `config/config_server.go:16`; `Config.ServerOptions()` at `config/config_load.go:301` appends `sso.WithX` options append-only-when-set (`FeatureGatesConfig.anySet()` precedent :342-345); `cmd/sso-server/build_app_core.go:154` consumes `cfg.ServerOptions()` | **Confirmed exact** |
| C5 — contract docs | `docs/openapi.yaml` declares BOTH `application/x-www-form-urlencoded` and `application/json` request bodies on `/token` (:1102), `/token/introspect` (:1280), `/token/revoke` (:1347), `/par` (:1477); the "Form + JSON" paragraph :1063-1066. `/register` and `/auth/login` are JSON-only (`ctx.Bind`) and untouched | **Confirmed** — because the mode is default-off, the JSON variants STAY; only a description note naming the opt-in key is added |
| C6 — module consumer | `cmd/snaplink-audit-provisioner/run.go:50-58` builds `auditgovernance.NewPlatformTokenSource` (TokenURL from `settings.env`); `defaultPlatformTokenConfig` (`platform_token.go:65-68`) defaults `Scope` to `PlatformProvisioningScope` (`platform_token.go:17`); `platformTokenRequest` (`platform_token.go:151-162`) sends the form body with `Content-Type: application/x-www-form-urlencoded` (:162). The provisioner's mint **already speaks the mandated wire format** — the strict flip is a no-op for the module | **Confirmed exact** — nothing in `cmd/snaplink-audit-provisioner` changes |
| C7 — fuzz harness | `FuzzBindParams` at `protocols/oauth/bind_fuzz_test.go:34` seeds form/JSON/`text/plain`/missing-CT classes | **Confirmed exact** — the strict binder gets its own fuzz entry (R5.5) |
| C8 — pre-existing cross-item condition | `test/credential_sdk_form_test.go` header (:8-12) documents `TestSdkForm_PARClaimsThreaded` (:150) as **deliberately RED** until a sibling `json.RawMessage` form branch lands in `oauthwire/bind.go`; the header's control-arm sentence names "400 invalid_request" (updated to the 415 pin in the same change, comment-only) | **Confirmed** — not ours; reported for CI triage |
| Direction acceptance text | Entry 3 of the analysis JSON (extracted from the markdown-fenced JSON at `docs/architect-analysis/auto/analyses/cmd-snaplink-audit-provisioner-7492095d.json`): T-8(a-e) verbatim, incl. "415 (or the documented form-only error)", "byte-identical to today", "deploy-tree config flips the mode in one place (ops/deploy) with a sweep assertion" | **Confirmed** — the requirements Rev 2 preserves this verbatim and expands it into the 20 Given/When/Then cases mapped in §3.7 |
| 415 body shape | `core.ErrorBody(code)` returns the plain `{"error": code}` envelope (`shared/core/error_body.go:11-14`); `interfaces/sso`'s `errorBody(ctx, code)` (`handlers.go:399-402`) is `ErrorBodyWithTrace` — trace_id only when a trace context is present. The requirements pin the 415 as the **plain** `core.ErrorBody(ErrInvalidRequest)` shape, byte-identical on all four endpoints | **Confirmed** — design decision §3.3: the 415 branch uses `core.ErrorBody` directly, deliberately skipping the /token site's trace-aware `errorBody` (deterministic shared shape, no per-request variance, no oracle) |
| Budgets | `oauthwire` = 6 non-test files (new `bind_strict.go` → 7 ≤ 10); `protocols/oauth` = 12 non-test files (NO new file; inline switches only); `interfaces/sso` = **60 non-test files (at ceiling)** — no new files; `cmd/snaplink-audit-provisioner` = 6 non-test files, untouched; `bind.go` = 158 lines (requirements said 140 — cosmetic drift) | **Confirmed** — all new Go lives in `oauthwire` + `test/` |

## 2. Material corrections to the evidence

- **Stale HEAD label**: the requirements Rev 2 pins "HEAD `1881c55d`"; the
  current HEAD is `61455c06`. `1881c55d` IS an ancestor (four commits back, all
  pi-batch stage commits), and every citation re-verified above matches the
  working tree — only the label is stale. No content correction.
- **Sub-line drifts (all within the cited surface, no content change)**:
  `IntrospectDeps` `type` keyword is at `handle_introspect.go:29`, not :27
  (requirements C4); `bind.go` is 158 lines, not 140 (requirements §6);
  `errorBody`'s trace semantics (above) are not spelled out in the requirements
  and shaped the §3.3 pin.
- **Compose-tree note**: `ops/deploy/compose/config.yaml` already carries the
  B4-2 `oauth.scope_registry.enabled: true` block (:63-67) and its `clients`
  list has no `snaplink-audit-provisioner` entry (the provisioner client is
  registered out-of-band through the control plane per the settings.env
  comment). Neither fact affects the flip: the provisioner mint is
  form-encoded by construction, and the sweep assertion only pins the new key.
  The B4-2 interplay (registry-enabled compose stack must register the
  provisioner's scopes) is the sibling's acceptance, not this change's.
- The superseded revision of this file (default-ON, entry 2, eight endpoints,
  400) is fully replaced; its verified mechanism seams (shared form helpers,
  option/accessor/config wiring) are reused with the Rev 2 deltas (default,
  status code, surface, single flip point, consumer pin).

## 3. Design

### 3.1 API changes

**Wire API (additive, opt-in — no change to any untouched deployment):**

| Endpoint | Handler / bind site | Under strict mode (`server.require_form_content_type: true` or `WithCredentialFormOnly(true)`) |
|---|---|---|
| POST `/token` (all grants: authcode, refresh, device, cc, exchange, delegation) | `handleToken`, `server_token.go:30` | `415` + `{"error":"invalid_request"}` before body parse; never mints |
| POST `/token/introspect` | `HandleIntrospect`, `handle_introspect.go:120` | `415` + `{"error":"invalid_request"}` before body parse; never introspects |
| POST `/token/revoke` | `HandleRevoke`, `handle_revoke.go:75` | `415` + `{"error":"invalid_request"}` before body parse; never revokes |
| POST `/par` | `HandlePAR`, `handle_par.go:66` | `415` + `{"error":"invalid_request"}` before body parse; never stores a PAR |

**Go API (all additive):**

| Symbol | Location | Notes |
|---|---|---|
| `oauthwire.ErrFormOnly` (exported sentinel) | new `protocols/oauth/oauthwire/bind_strict.go` | `errors.Is`-able Go sentinel, **never written to the wire** (internal dispatch signal only; `docs/error-codes.md` gains no code — only the 415 note). Exported because the four mapping sites span two packages (`interfaces/sso` + `protocols/oauth`); resolves the requirements' [PROPOSED] naming in favor of the sentinel over an `IsFormOnly` predicate (matches the `errors.Is` convention already used across the tree) |
| `oauthwire.BindParamsFormOnly(ctx core.HandlerContext, v any) error` | bind_strict.go | Form CT → shared `bindForm` (byte-identical to `BindParams`'s form path); any other or missing CT → `ErrFormOnly` **before reading the body**. Malformed percent-encoding under a form CT → `ParseForm` error (NOT `ErrFormOnly`) |
| `oauth.BindParamsFormOnly`, `oauth.ErrFormOnly` | `protocols/oauth/aliases.go` (var block beside `BindParams` :97) | Preserves the `oauth.*` import surface for `interfaces/sso` |
| `(s *Server) bindCredentialParams(ctx HandlerContext, v any) error` | `interfaces/sso/server_jar.go` beside `bindOAuthParams` (:304) | Flag-aware: `s.credentialFormOnly == false` → `bindOAuthParams(ctx, v)` (byte-identical baseline); `true` → `oauth.BindParamsFormOnly(ctx, v)`. Used by `/token` only; `bindOAuthParams` stays for device/MFA/admin sites |
| `sso.WithCredentialFormOnly(v bool) Option` | `interfaces/sso/options.go` beside `WithMaxTokenBytes` (:103) | Sets `s.credentialFormOnly`; **seeded `false`** in `NewServer` — the default-off pin for SDK embedders |
| `Server.credentialFormOnly bool` | `interfaces/sso/sso_protocol.go:38` `protocolState` | Field on the embedded protocol state (no new file — `interfaces/sso` is at its 60-file ceiling) |
| `(s *Server) RequireFormContentType() bool` | `interfaces/sso/accessors_handlers.go` (:405 `IntrospectionCache` sibling) | Satisfies the new Deps members |
| `RequireFormContentType() bool` on `IntrospectDeps`, `PARDeps`, `RevokeDeps` | `handle_introspect.go:29`, `handle_par.go:18`, `handle_revoke.go:16` | One new accessor member per interface, matching the `IntrospectionCache()` precedent; `*sso.Server` implements it via the accessor; the protocol-layer unit fakes (`protocols/oauth/handle_{introspect,par,revoke}_test.go`) gain the member in the same change |
| `ServerConfig.RequireFormContentType *bool` (`yaml:"require_form_content_type"`) | `config/config_server.go:16` `ServerConfig` | `nil` (unset) → option NOT appended (byte-identical `ServerOptions()`, the `anySet()` precedent); `true` → `WithCredentialFormOnly(true)`; `false` → `WithCredentialFormOnly(false)` (explicit legacy, same as unset). **No deprecation warning for `false`** — it is the default, not a migration hatch (delta vs the superseded revision) |

**Config wiring** (`config/config_load.go:301` `ServerOptions()`, one block):

```go
// Opt-in credential wire hardening: server.require_form_content_type.
// Unset (nil) appends nothing so ServerOptions() stays byte-identical to
// a pre-B4-4 build; false is the explicit-legacy spelling of the same
// default. Only true changes the wire behavior of the four credential
// endpoints (415 for JSON/missing/unexpected Content-Type).
if c.Server.RequireFormContentType != nil {
    opts = append(opts, sso.WithCredentialFormOnly(*c.Server.RequireFormContentType))
}
```

`cmd/sso-server/build_app_core.go:154` needs no change.

**`bind.go` refactor (byte-identical)**: extract CT normalization (:31-35) into
`normalizedMediaType(r *http.Request) string` and the form path (:38-42) into
`bindForm(r *http.Request, v any) error`; `BindParams` becomes a thin switch
over the helpers. `bind_strict.go` is the only other consumer. `bind.go` stays
well under the 500-line / complexity-15 budgets. A comment on the extracted
default branch records the regression boundary: the JSON/missing-CT default
serves non-credential consumers and the default-off posture — never "clean it
up" into a global flip (failure mode F9).

### 3.2 Binder semantics (pinned)

- `normalizedMediaType` strips `;parameters` and lowercases —
  `application/x-www-form-urlencoded; charset=UTF-8` binds;
  `application/json; charset=utf-8` rejects. Identical parameter tolerance to
  today (bind.go:31-35).
- Missing Content-Type → `ErrFormOnly` (the "empty body + no Content-Type is
  treated as JSON" default is dead on the four sites under strict mode). Empty
  body WITH form CT → `ParseForm` succeeds, zero struct, per-endpoint
  validation runs unchanged (e.g. `/token` → 400 `invalid_request` for missing
  `grant_type`).
- `r.ParseForm` + `formIntoStruct(r.PostForm, v)` semantics unchanged
  (multi-value and space-separated `scope`/`resource`).
- Flag dispatch: mode OFF → the sites call exactly what they call today
  (byte-identical baseline, zero behavioral delta); mode ON → the strict binder.
- No new telemetry: the requirements do not pin an Info log on the
  `ErrFormOnly` path (the superseded revision proposed one); this design adds
  none — the 415 status is itself the operator's gauge, and an extra log line
  would be speculative scope.

### 3.3 Handler mapping and the 415 envelope

At each of the four sites, the bind-error branch becomes:

```go
if err := s.bindCredentialParams(ctx, &req); err != nil { // /token; the three
    // protocol sites use: if d.RequireFormContentType() { err = BindParamsFormOnly(...) }
    //                    else { err = BindParams(...) }
    if errors.Is(err, oauthwire.ErrFormOnly) {
        // 415 envelope is the PLAIN core.ErrorBody shape on all four sites:
        // deterministic, no trace_id, byte-identical across endpoints and
        // across rejection causes (JSON / missing CT / unexpected CT) — no
        // new oracle (AGENTS.md §3). Deliberately not the trace-aware
        // errorBody: per-request trace variance would break the
        // byte-identical-across-sites pin. Exact wire bytes (pinned, D1):
        // status 415, Content-Type: application/json, body
        // {"error":"invalid_request"}\n (ctx.JSON appends the newline). The
        // branch is reached ONLY via errors.Is(err, ErrFormOnly); the body is
        // never read before it, so the envelope cannot distinguish malformed
        // percent-encoding (400 invalid_request via ParseForm), unknown/
        // consumed codes (400 invalid_grant), or any credential state —
        // those causes never reach this branch (D2/D3, §3.8).
        ctx.JSON(http.StatusUnsupportedMediaType, core.ErrorBody(core.ErrInvalidRequest))
        return
    }
    // existing 400 path unchanged
}
```

- `/token` uses `s.bindCredentialParams` (Server method — the layer's single
  flag source); the three protocol-layer sites use the inline flag conditional
  on `d.RequireFormContentType()` (no new file in `protocols/oauth` — 12
  non-test files, budget-sensitive; the 4-line conditional is the pinned
  shape, one definition per site, mirroring the file list in requirements §7).
- No-store headers are already stamped before parsing at all four sites
  (`tokenNoStoreHeaders` `server_token.go:22`;
  `middleware.TokenNoStoreHeaders` at `handle_introspect.go:113`,
  `handle_revoke.go:69`, `handle_par.go:56`), so the 415 responses carry
  `Cache-Control: no-store` + `Pragma: no-cache` like every other credential
  response (acceptance case 13 pins this).
- Ordering is unchanged: body parse precedes client auth on `/token` and
  `/token/introspect`. Under strict mode an unauthenticated JSON introspect
  415s at the parse stage (T-8(a)); every bindable (form) request still reaches
  the `401 invalid_client` gate (T-9). Client-auth-before-parse is rejected
  (C3).

### 3.4 Compatibility constraints

- **Regression boundary — untouched deployments are byte-identical**: mode OFF
  is the seed (`NewServer`), the config default (nil → no option), and the
  single `bindCredentialParams` dispatch. `TestFormEncoded_JSONStillWorks`,
  `TestBindParamsJSONDefault`, `BenchmarkBindParamsJSON`, and the
  `TestSdkForm_*` family pass unchanged (T-8(d)) — zero test migration, zero
  wire change.
- **Non-credential `BindParams` consumers are byte-identical**: all 44
  dual-mode sites outside the four (commerce, admin, selfservice, device/MFA/
  CIBA via `bindOAuthParams`, `/register`, `/auth/login`) keep JSON/form
  semantics. `bind.go`'s default branch is untouched.
- **Device/MFA/CIBA are NOT flipped** (direction acceptance names four
  endpoints): `/device/code`, `/device/verify`, `/auth/mfa`,
  `/backchannel-authentication` stay on the dual-mode binder. Extending the
  flip later is a one-line-per-site change on the same dispatcher — a
  design-stage note, NOT implemented here (scope discipline).
- **Contract docs stay dual**: openapi keeps both requestContentType variants
  on the four paths; only description notes naming the opt-in key and the 415
  behavior are added. `/register`, admin paths, device/MFA/CIBA paths untouched
  (C5).
- **Oracle safety**: one deterministic 415 envelope shared by all four
  endpoints and all rejection causes; `ErrFormOnly` never reaches the wire; no
  new `Err*` code; `/auth/mfa` untouched (`mfa_invalid` oracle row unchanged).
- **Headers/middleware**: no-store stamping stays at the top of every handler
  before parsing; middleware order and probes-outside-rate-limiting posture
  untouched.
- **Dependency direction**: strict binder in `protocols/oauth/oauthwire`
  (leaf); `interfaces/sso` imports downward; Deps accessor is the existing
  pattern; nothing imports `cmd/`.

### 3.5 Failure modes

| # | Failure mode | Behavior | Guard |
|---|---|---|---|
| F1 | JSON caller (in-tree or out-of-tree) hits a strict server | `415 {"error":"invalid_request"}` before any processing; no mint, no revoke, no PAR store, no introspection result. Loud and visible — never silent | Endpoint tests cases 1-3, 7-9 |
| F2 | Proxy/edge strips Content-Type | Missing CT → 415 (the old JSON default is dead on the four sites under strict mode) | Case 3, 8 |
| F3 | A second deploy-tree flip point appears (helm values, baremetal, k8s configs) | Sweep test fails CI — drift guard | `TestDeployTreeRequireFormContentTypeSingleFlipPoint` (case 16) |
| F4 | SDK embedder enables the option and forgets JSON callers | 415 everywhere on the four endpoints — obvious, not silent; operator flips off | Docs note; option is explicit by construction |
| F5 | `errors.Is` mapping bug | 415 degrades to the site's existing 400 — same `invalid_request` body, wrong status. No oracle either way, but the acceptance pins the status | Unit case 18 + endpoint cases 1-3, 7-9 pin both directions |
| F6 | Malformed percent-encoding under a form CT | `ParseForm` error → the existing 400 path (NOT 415, NOT `ErrFormOnly`) — smuggled `%ZZ` bodies cannot masquerade as media-type rejections | Unit case 18 |
| F7 | Config `false` vs unset drift | Both are byte-identical (append-only-when-set) | Case 15 |
| F8 | Future "cleanup" flips the `BindParams` default globally | Would break non-credential consumers (commerce REQUIRES JSON) and the default-off baseline | Regression-boundary comment in `bind.go`/`bind_strict.go` (F9 note) |
| F9 | `TestSdkForm_PARClaimsThreaded` stays RED | Pre-existing sibling condition (C8): the PAR-claims `json.RawMessage` form branch is a different campaign item; this change must NOT land that branch (scope) and must report the RED test separately | Reported at handoff; CI triage |

### 3.6 Migration steps and rollback

The change ships default-off; there is nothing to migrate for existing
deployments.

1. **Land the mechanism** (this change): strict binder, option, config key
   (nil default), docs, tests. Every deployment is byte-identical; SDK
   embedders are unaffected. Contract docs (config-reference, error-codes,
   openapi notes, CHANGELOG) land in the same change (AGENTS.md §5.6).
2. **Flip the compose dev stack** (same change, the acceptance's single flip
   point): add `require_form_content_type: true` under `server:` in
   `ops/deploy/compose/config.yaml` (:9-16). Every compose `/token` consumer
   already mints form-encoded with the header (verified §1), so the stack stays
   green — proven by the sweep assertion and the consumer e2e pin.
3. **Leave every other deploy posture default-off**: helm
   (`ops/deploy/helm/sso-server/values.yaml`), baremetal-ha, k8s,
   k8s-distributed stay without the key; the sweep test asserts their absence.
   Operators of those trees flip later by adding the same key under `server:`.
4. **Rollback**: delete the key or set `false` — boot-time config, no
   hot-reload; the four endpoints return to the JSON-default baseline exactly
   (no state, no store, no rotation side effects to unwind).
5. **Out-of-tree JSON callers** (if an operator enables the mode): the
   documented contract is form-urlencoded per RFC 6749 §3.2 / 7662 §2.1 /
   7009 §2.1 / 9126 §4.1; JSON callers must either switch to form encoding or
   keep the key off.

Cross-module ordering: independent of B4-2 (scope registry — disjoint gate;
the compose tree's registry-enabled state is the sibling's concern), B4-3, and
the gensdk form-emission module (default-off keeps committed JSON-emitting SDKs
working, T-8(d)). The PAR-claims form branch (C8) is a pre-existing sibling
condition.

### 3.7 Testable acceptance mapping (T-8(a-e) → cases → files)

| Acceptance (direction, verbatim) | Cases (requirements Rev 2) | Test file / function (new unless noted) |
|---|---|---|
| T-8(a): strict mode rejects JSON/missing CT on `/token` and never mints | 1-4 (+D1-D3) | `test/credential_content_type_test.go` — `TestStrictToken_JSONRejected`, `TestStrictToken_MissingCTRejected`, `TestStrictToken_BasicAuthStill415`, `TestStrictToken_CharsetParamBinds`, `TestStrictToken_Exact415Envelope` (D1 exact bytes), `TestStrictToken_BodyIndependent415` (D2: `%ZZ` + bindable body under wrong CT → 415), `TestStrictToken_DPoPProofStill415` (D3: DPoP header + JSON → 415, no nonce stamp) (strict-server harness mirroring `newFormHarness`, `test/oauth_bind_test.go:28`, with `sso.WithCredentialFormOnly(true)`; issuer spy asserts zero issuance on the 415 rows; no-store both headers on every row, D4) |
| T-8(b): form-urlencoded requests byte-identical to today | 5-6 | Existing `TestFormEncoded_*` (`test/oauth_bind_test.go:146/272/288`), `TestBindParamsContentTypeWithCharset` (`bind_extra_test.go:162`), `TestSdkForm_*` run UNCHANGED against both modes; `test/credential_content_type_test.go` `TestStrictToken_FormByteIdentical` (refresh-rotation arm) |
| T-8(c): `/introspect`, `/revoke`, `/par` behave identically | 7-13 (+D1-D4) | `test/credential_content_type_test.go` — `TestStrictIntrospect_*`, `TestStrictRevoke_*`, `TestStrictPAR_*` (415 rows, missing-CT rows, twelve CT-combination rows, form byte-identical rows, exact-envelope rows per D1, body-independence rows per D2, no-store BOTH headers on every 415 row + the `%ZZ` 400 row per D4); T-9 row = existing `TestIntrospect_RejectsMissingCreds` / `_RejectsWrongSecret` / `_AcceptsBasicAuth` (`test/handle_introspect_test.go`) stay green unmodified |
| T-8(d): mode off — existing JSON-body tests pass unchanged | 14-15 | `TestFormEncoded_JSONStillWorks`, `TestBindParamsJSONDefault`, `BenchmarkBindParamsJSON` (`bind_bench_test.go:89` — NOT modified), `TestSdkForm_*` unmodified; `test/credential_content_type_test.go` `TestServerOptions_AppendOnlyWhenSet` (nil/true/false → option list) |
| T-8(e): deploy-tree flip in one place + sweep assertion; module consumer pin | 16-17 | `test/deploy_form_only_sweep_test.go` — `TestDeployTreeRequireFormContentTypeSingleFlipPoint` (stdlib-only scan: key exists under `server:` with value `true` in `ops/deploy/compose/config.yaml`; the literal appears in NO other file under `ops/deploy/`; documented in `docs/config-reference.md`); `test/audit_provisioner_form_e2e_test.go` — `TestAuditProvisionerPlatformTokenSourceStrictServer` (REAL `auditgovernance.NewPlatformTokenSource`, no Scope → `PlatformProvisioningScope`, against a strict `sso.NewServer` over httptest with `AllowInsecureLoopback: true` + `ts.Client()`, provisioner identity `snaplink-audit-provisioner`/`audit-governance` per `settings.env`; assert 200 + non-empty Bearer) |
| Unit level | 18-20 (+D5-D6) | `protocols/oauth/oauthwire/bind_strict_test.go` (form binds / JSON / missing / multipart / text/plain / whitespace-only CT → `ErrFormOnly` / charset + case tolerance binds / empty form body / `%ZZ` → ParseForm error with target struct untouched — D5); `FuzzBindParamsFormOnly` in `bind_fuzz_test.go` (never panics, non-form CT never binds AND target struct unchanged — D6); existing constant-time suites (`shared/security`, `domains/authenticators`, `oauthwire` PKCE) re-run `-race -count=10` unmodified |

Fakes updated in the same change: the protocol-layer Deps fakes
(`protocols/oauth/handle_introspect_test.go:78` `introspectDeps` and the
`parDeps`/`revokeDeps` siblings) gain `RequireFormContentType() bool` returning
`false` (legacy posture → existing JSON-post unit tests stay green
unmodified); the strict-mode rows live in `test/` against the real
`*sso.Server`, which satisfies the Deps via the new accessor.

### 3.8 Oracle-safety hardening pins (Revision 3 — test-enforced, not asserted)

D1-D6 below are folded into the acceptance rows of §3.7 (the four-digit row
labels are the new test functions in `test/credential_content_type_test.go`).
All pins were re-verified against the working tree; each maps to a measured
fact listed in the hardening-review artifact (§1-§4, §7).

- **D1 — exact 415 bytes.** Every 415 row asserts status `415`, `Content-Type:
  application/json` (no charset), and the exact body `{"error":"invalid_request"}\n`
  (`ctx.JSON` → `json.Encoder.Encode`, router.go:141-147, appends `\n`).
  Byte-identical on all four endpoints, all rejection rows.
- **D2 — body-independence (the envelope cannot distinguish internal causes).**
  Rows: wrong CT + `%ZZ` body → 415 (proves the 415 path never reads the body);
  wrong CT + a body that would otherwise bind → 415 (proves the envelope does
  not depend on body content); form CT + `%ZZ` → 400 `invalid_request` (F6
  pin: ParseForm error is never `ErrFormOnly`); unknown/consumed code → 400
  `invalid_grant` (unchanged collapse, token_authcode.go:182-215). The 415 is
  reachable only via the media-type class and consults no server state.
- **D3 — credential-state independence.** Rows: JSON body + valid Basic creds
  → 415 byte-identical to the no-creds row; JSON body + valid DPoP proof
  header → 415 byte-identical (no nonce stamp, no `invalid_dpop_proof` —
  `captureSenderConstraint` runs after bind, server_token.go:250-295); form
  authcode exchange with wrong PKCE verifier → 400 `invalid_grant`
  byte-identical to the unknown-code row; form `client_credentials` with a
  valid DPoP proof → 200 with `cnf` claim (form wire exercises DPoP
  unchanged). Under mode OFF these paths are byte-identical by the
  pass-through dispatch (§3.3; `RequireFormContentType()` false → the exact
  `BindParams` call of today — `errors.Is(err, ErrFormOnly)` structurally
  false).
- **D4 — no-store on both headers, every error path.** Every 415 row AND the
  malformed-`%ZZ` 400 row assert BOTH `Cache-Control: no-store` and `Pragma:
  no-cache` (both stamped before the bind at all four sites: server_token.go:22,
  handle_introspect.go:112, handle_revoke.go:68/:182, handle_par.go:55 — so
  every in-handler error branch carries them). Pre-existing drift reported,
  not fixed: the config-gated `bodyLimitMiddleware` 413
  (internal/handler/health.go:56-65) fires outside the handler and carries
  neither header — mode-independent, outside this change.
- **D5 — dispatch fail-closed contract (code + unit rows).** bind_strict.go's
  doc comment pins: (1) dispatch is a pure function of the normalized CT
  (bind.go:31-35 normalization, extracted verbatim); (2) `decodeSingleJSON` is
  unreachable — the strict binder is a separate function, never a flag inside
  `BindParams`; (3) `if err := r.ParseForm(); err != nil { return err }` runs
  BEFORE `formIntoStruct` — no partial bind; (4) `ErrFormOnly` is returned
  only from the CT branch, never wrapped, never produced by the form path;
  (5) zero-struct form bodies hit unchanged per-endpoint validation. Unit
  rows: multipart/form-data, text/plain, `application/json; charset=utf-8`,
  missing CT, whitespace-only CT → `ErrFormOnly`; `application/x-www-form-
  urlencoded; boundary=x` and `Application/X-WWW-Form-Urlencoded` → binds
  (tolerance preserved); `%ZZ` → ParseForm error, never `ErrFormOnly`, target
  struct untouched.
- **D6 — fuzz invariant.** `FuzzBindParamsFormOnly` (bind_fuzz_test.go sibling
  of `FuzzBindParams` :34): non-form CT → `ErrFormOnly` AND target struct
  unchanged (never partially bound); form CT → never panics.

## 4. Engineering-gate constraints (verified)

- **Budgets**: no new packages. `oauthwire/bind_strict.go` (~40 lines) —
  under 500/file, 50/function, complexity 15, nesting 3. `interfaces/sso` at
  its 60-file ceiling: field in `sso_protocol.go`, option in `options.go`,
  accessor in `accessors_handlers.go`, dispatch method in `server_jar.go`,
  seed in `sso.go`, `/token` switch in `server_token.go` — no new files.
  `protocols/oauth` (12 non-test files): no new files — alias in
  `aliases.go`, inline switches in the three handlers. `cmd/snaplink-audit-
  provisioner` untouched (6 non-test files).
- **Oracle safety**: one deterministic 415 envelope; `ErrFormOnly` never on
  the wire; no new `Err*` codes; `/auth/mfa` untouched.
- **Wire compatibility**: default-off byte-identical baseline; non-credential
  consumers unchanged; `/auth/login` and `/register` untouched; openapi JSON
  variants stay.
- **Dependency direction**: unchanged (strict binder lives in the leaf
  `oauthwire` package).

## 5. Files

### Create

```text
protocols/oauth/oauthwire/bind_strict.go — BindParamsFormOnly + ErrFormOnly;
    shares normalizedMediaType/bindForm factored byte-identically from bind.go.
protocols/oauth/oauthwire/bind_strict_test.go — unit acceptance cases 18 (+19 fuzz).
test/credential_content_type_test.go — endpoint-level strict-mode tests
    (cases 1-4, 7-13, 15) on the newFormHarness pattern with a strict-server
    variant (sso.WithCredentialFormOnly(true)); includes the Rev 3 D1-D4 rows
    (TestStrictToken_Exact415Envelope, TestStrictToken_BodyIndependent415,
    TestStrictToken_DPoPProofStill415, TestStrictIntrospect/Revoke/PAR_* exact-
    envelope + body-independence + no-store-both-headers rows).
test/audit_provisioner_form_e2e_test.go — R7/case 17: strict sso.NewServer +
    REAL auditgovernance.PlatformTokenSource (provisioner identity/scopes).
test/deploy_form_only_sweep_test.go — R6/case 16 sweep assertion.
```

### Modify

```text
protocols/oauth/oauthwire/bind.go — factor normalizedMediaType (:31-35) and
    bindForm (:38-42) into shared helpers (byte-identical); regression-boundary
    comment on the JSON default.
protocols/oauth/aliases.go — BindParamsFormOnly + ErrFormOnly aliases beside
    BindParams (:97).
protocols/oauth/handle_introspect.go:120, handle_revoke.go:75, handle_par.go:66 —
    inline flag conditional on d.RequireFormContentType() + 415 mapping.
protocols/oauth/handle_introspect.go:29, handle_par.go:18, handle_revoke.go:16 —
    RequireFormContentType() bool member on each Deps interface.
protocols/oauth/handle_{introspect,par,revoke}_test.go — fakes gain the member
    (return false — legacy posture).
interfaces/sso/server_token.go:30 — s.bindCredentialParams + 415 mapping.
interfaces/sso/server_jar.go:304 — (s *Server) bindCredentialParams.
interfaces/sso/options.go — sso.WithCredentialFormOnly(bool) beside WithMaxTokenBytes (:103).
interfaces/sso/sso.go:58-80 — seed s.credentialFormOnly = false in NewServer
    (explicit default-off pin with comment; zero value is false but the seed
    guards a future default flip).
interfaces/sso/sso_protocol.go:38 — protocolState.credentialFormOnly bool.
interfaces/sso/accessors_handlers.go — RequireFormContentType() accessor (:405 sibling).
config/config_server.go:16 — ServerConfig.RequireFormContentType *bool (yaml key).
config/config_load.go:301 — append the option iff the key is set (anySet precedent).
protocols/oauth/bind_fuzz_test.go:34 — FuzzBindParamsFormOnly entry (R5.5).
test/credential_sdk_form_test.go:8-9 — control-arm comment 400 → 415
    (comment-only; the tests stay green unmodified).
ops/deploy/compose/config.yaml:9-16 — server.require_form_content_type: true (R6).
docs/config-reference.md — server.require_form_content_type row, default off.
docs/error-codes.md — 415 form-only note on the credential invalid_request row(s).
docs/openapi.yaml — description notes on the four credential paths (JSON variants stay).
CHANGELOG.md — opt-in hardening entry.
```

### Do not modify

```text
protocols/oauth/oauthwire/bind.go:43-46 dual-mode default — the byte-identical
    baseline under the default-off mode; non-credential consumers depend on it.
interfaces/sso/server_device.go:53,242, server_mfa.go:255,
    protocols/oauth/handle_ciba.go:87 — device/MFA/CIBA stay on the dual-mode
    binder (non-goal; §3.4 note).
interfaces/sso/server_login.go, protocols/oauth/handle_register.go — JSON-only.
interfaces/commerce/*, interfaces/admin/*, protocols/selfservice/* — unchanged wire.
test/oauth_bind_test.go:272, protocols/oauth/bind_extra_test.go:148,
    protocols/oauth/bind_bench_test.go — unchanged (mode-off pins, T-8(d)).
cmd/snaplink-audit-provisioner/* — control-plane consumer, untouched (C6).
ops/deploy/audit-provisioner/*, ops/deploy/helm/sso-server/values.yaml,
    ops/deploy/baremetal-ha/sso/config.yaml, ops/deploy/k8s{, -distributed}/config.yaml —
    unchanged (single flip point is compose config.yaml; sweep asserts absence).
shared/security/constant_time.go, domains/authenticators/apikey.go,
    oauthwire/auth_code_handler.go:83-85 — verified present; no work (case 20).
```

Confirm file/function/directory frozen ceilings before implementation
(`python cli.py checks filesize complexity directory-fanout`).

## 6. Dependencies and compatibility

- New/changed SPI: `oauthwire.BindParamsFormOnly` + `oauthwire.ErrFormOnly`
  (+ `oauth.*` aliases); `sso.WithCredentialFormOnly(bool)`; one new
  `RequireFormContentType() bool` accessor on three Deps interfaces; one new
  config key `server.require_form_content_type` (default off). No interface
  store changes, no routes, no proto.
- New YAML/env keys: one (`server.require_form_content_type`), default off.
- Storage migration: none.
- HTTP compatibility: non-breaking by default. With the mode enabled, the four
  endpoints return 415 for JSON/missing/unexpected Content-Type; out-of-tree
  JSON callers must send form-encoded or leave the key off. In-tree consumers
  are all form-encoded already (verified §1).
- Rollout/rollback: flip the key off (or delete it) restores legacy behavior
  exactly; boot-time config like `oauth.scope_registry`, no hot-reload.
- Cross-module ordering: independent of B4-2/B4-3 and the gensdk form-emission
  module; the PAR-claims form branch (C8) is pre-existing sibling work.

## 7. Documentation

- [x] `docs/config-reference.md` — `server.require_form_content_type` row
  (default off, 415 behavior when enabled).
- [x] `docs/error-codes.md` — 415 note on the credential `invalid_request`
  rows; no new codes.
- [x] `docs/openapi.yaml` — description notes on the four credential paths
  (JSON variants stay; `/register`, admin, device/MFA/CIBA untouched).
- [x] CHANGELOG.md — opt-in hardening entry.
- [ ] ADR — not required (additive, config-flagged, default-off). The
  audit-provisioner README is untouched (consumer behavior unchanged).

## 8. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./protocols/oauth/oauthwire/... -run 'TestBindStrict|FuzzBindParamsFormOnly' -v
go test ./test/ -run 'TestCredentialContentType|TestStrict|TestAuditProvisionerPlatformTokenSource|TestDeployTreeRequireFormContentType|TestFormEncoded_|TestSdkForm_|TestIntrospect_|TestRevoke_|TestPAR' -v
go test ./test/ -run TestE2E -v
go test ./shared/security/ ./domains/authenticators/ ./protocols/oauth/oauthwire/ -race -count=10
go test ./... -race
make ci
```

Pre-existing failures to report separately: `TestSdkForm_PARClaimsThreaded`
(deliberately RED until the sibling PAR-claims `json.RawMessage` form branch
lands in `oauthwire/bind.go` — C8) and any `checks/directory_fanout.py` state
(no new packages in this change).
