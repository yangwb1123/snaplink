All claims verified against the working tree. Here is the RFC/OIDC wire-contract assessment.

## Verdict: spec-compliant, safe, and the strict binder preserves both pinned semantics — with two minor caveats (status-code split, loose "44 sites" phrasing)

## 1. Requiring form-urlencoded on the four endpoints: mandated, not optional

Every endpoint in the flip has an explicit "MUST use `application/x-www-form-urlencoded`" requirement:

| Endpoint | Contract | Text |
|---|---|---|
| `/token` | RFC 6749 §3.2 | "the parameters are sent using the 'application/x-www-form-urlencoded' format with a character encoding of UTF-8" |
| `/token` refresh | RFC 6749 §6 | same §3.2 binding |
| `/token` device grant | RFC 8628 §3.4 | token request uses the §3.2 format |
| `/token` exchange | RFC 8693 §2.1 | POST + form |
| `/token` JWT-bearer | RFC 7523 §2.1 | POST + form |
| `/token/introspect` | RFC 7662 §2.1 | "parameters sent as 'application/x-www-form-urlencoded' data" |
| `/token/revoke` | RFC 7009 §2.1 | "using the 'application/x-www-form-urlencoded' format" |
| `/par` | RFC 9126 §4.1 | "request parameters are sent using the 'application/x-www-form-urlencoded' format" |
| OIDC | Core §3.1.3.2 | token endpoint parameters "using the 'application/x-www-form-urlencoded' format per Appendix B" |

The current JSON acceptance is a *non-standard extension* — `bind.go:20-25` says so explicitly ("JSON is accepted as a non-standard convenience for SPAs"). The strict mode therefore aligns the server **with** the RFC text rather than diverging from it. The default-off posture is the right call because the extension is load-bearing for non-credential consumers (commerce/admin/selfservice rely on the JSON default; `payment_ingest.go:99` requires it).

**415 vs 400**: RFC 6749 §5.2 prescribes the `{"error": ...}` envelope but does not mandate 400 for media-type rejection; 415 Unsupported Media Type (RFC 9110 §15.5.16) is the correct HTTP semantic, and the requirements pin "415 (or the documented form-only error)". Keeping `invalid_request` in the envelope preserves §5.2 parseability for clients. The design's 415-before-body-parse also means the body is never read on the reject path — no ParseForm side effects, no 10MB cap interaction. RFC 6750 is untouched: bearer usage on protected resources is out of this change's surface.

## 2. Compose-tree consumers: every one verified form-encoded

- **Provisioner**: `infrastructure/auditgovernance/platform_token.go` `platformTokenRequest` — `url.Values` + `SetBasicAuth` + `Content-Type: application/x-www-form-urlencoded` at :162; wired via `run.go:50-58` with `settings.env` identity. ✅
- **Stripe adapter**: `cmd/snaplink-stripe-adapter/billing.go:157-165` `requestClientToken` — form + Basic + CT header. ✅
- **Billing quota relay** (third compose consumer, design lists it): `infrastructure/auditgovernance/oauth_token_source.go:201,210` — form + CT. ✅
- **SDK** (in-tree consumer of the flipped endpoints): revoke at `interfaces/ssoclient/remote/auth.go:334-337` (form, with a comment that form is *required*), PAR/token form wire pinned by `test/credential_sdk_form_test.go` (form posts at :80/:122/:161). ✅
- **Device/MFA/CIBA**: their *endpoints* stay dual-mode (`bindOAuthParams` at `server_device.go:53/:242`, `server_mfa.go:255`; `BindParams` at `handle_ciba.go:87` — all verified), so those paths are untouched; their *token exchanges* at `/token` are form-mandated by RFC 8628 §3.4 and the CIBA spec, and the SDK mints form. ✅
- **Config seams**: `server:` block at `ops/deploy/compose/config.yaml:9-16`; `ServerOptions()` append-only-when-set precedent at `config_load.go:301/:345`; `WithMaxTokenBytes` at `options.go:103`. ✅

## 3. `BindParamsFormOnly` preserves both pinned semantics

**Form-over-JSON precedence**: dispatch is Content-Type-only (one body, one parser — there is no dual-parse). `BindParamsFormOnly` delegates the form case to the identical `ParseForm` + `formIntoStruct(r.PostForm, v)` path, so a JSON-looking body under a form CT binds to a zero struct and hits the unchanged per-endpoint 400 validation — byte-identical to today. Missing/unexpected CT → `ErrFormOnly` before body read, which is the correct reading of the requirement ("empty body + no CT treated as JSON" dies only on the four sites). The `;`-parameter strip + lowercase normalization (:31-35) is preserved, so `charset=UTF-8` binds (pinned by `TestBindParamsContentTypeWithCharset`).

**Basic-auth-wins**: bind precedes client auth everywhere (`server_token.go:30` → `authenticateTokenClient` :35; `BasicClientCreds` override after bind on the three protocol sites), and that precedence is media-type-independent — unchanged for every bindable (form) request. `TestFormEncoded_BasicAuthOverridesBodyCreds` (`oauth_bind_test.go:146`) stays green. The design's C3 reasoning is correct: client-auth-before-parse would make body-credential auth unreachable for public clients and break the AGENTS.md invariant. A JSON body with valid Basic creds gets 415 under strict mode — but such a request is malformed per §3.2 regardless of authentication, so no invariant is broken.

**Error boundary (F6)**: form CT + `%ZZ` → `ParseForm` error → existing 400, never `ErrFormOnly`/415 — the correct distinction between a malformed form body and a media-type mismatch.

## 4. Caveats (non-blocking)

1. **Status split on `/token`**: strict-mode 415 uses the plain `core.ErrorBody` while the existing `/token` 400 bind-error path uses trace-aware `errorBody` (`handlers.go:399-402`). Deterministic and non-oracle (both are pure functions of request shape, not credentials), but a client must map both 415 and 400 → `invalid_request`. This asymmetry is deliberate (§3.3) and documented — worth keeping in the openapi description note.
2. **415 vs 401 on `/token/introspect` and `/par` under strict mode**: unauthenticated JSON requests get 415 instead of the RFC 9126 §3.1 401 — media-type-deterministic, not a credential oracle; the T-9 pin (every form request still reaches the `401 invalid_client` gate) holds.
3. **"44 dual-mode sites" phrasing**: I count ~40 direct `BindParams(` call sites plus the 4 `bindOAuthParams` alias sites (= 44 total), of which the four flipped are a subset — the substance (nothing outside the four changes) is correct, but the doc's "44 outside the four" reads loosely.
4. **Device grant note**: the flip covers *all* grants at `/token` including `device_code` and `ciba` exchanges — correct per RFC 8628 §3.4/CIBA, and consistent with the four-endpoint scope, but the design's §3.4 statement "Device/MFA/CIBA are NOT flipped" refers only to their dedicated endpoints; a reader could misread it. The requirements' T-8(a) wording ("never mints") already covers this.

All structural claims in the design checked out (file counts 6/12/60, bind sites at `server_token.go:30`/`handle_introspect.go:120`/`handle_revoke.go:75`/`handle_par.go:66`, `settings.env` pins, openapi dual declarations, `TestSdkForm_PARClaimsThreaded` deliberate-RED header at `credential_sdk_form_test.go:8-9`). No RFC violation, no oracle regression, and every documented compose-tree consumer already speaks the mandated wire format — the flip is a no-op for the in-tree tree.
