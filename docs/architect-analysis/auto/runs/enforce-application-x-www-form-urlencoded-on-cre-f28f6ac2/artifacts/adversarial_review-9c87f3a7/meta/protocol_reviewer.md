All verification complete. Here is the assessment.

---

# Verification: BindParamsFormOnly strict mode — RFC compliance, consistency, and contract docs

**Status:** design-stage verification. No Go implementation exists yet (`BindParamsFormOnly`/`StrictCredentialContentType` have zero hits outside `docs/architect-analysis/`). All claims below were checked against the working tree (HEAD `5cd5ff74`, design authored against `807719ea`) and against the RFC texts fetched from rfc-editor.org.

## 1. RFC verification — strict mode against the four endpoints

| RFC | Normative requirement (verified text) | Enforced by | Verdict |
|---|---|---|---|
| 6749 §3.2 | "The client MUST use the HTTP `POST` method when making access token requests"; form-encoded entity body per §4.1.3/§4.3.2/§4.4.2/§6 ("using the `application/x-www-form-urlencoded` format per Appendix B with a character encoding of UTF-8 in the HTTP request entity-body") | POST-only routes (`server_routes.go:181-186`); strict CT gate at `/token` | ✓ |
| 7662 §2.1 | "calls the introspection endpoint using an HTTP POST [RFC7231] request with parameters sent as `application/x-www-form-urlencoded` data" | Strict CT gate at `/token/introspect` | ✓ |
| 7009 §2.1 | "constructs the request by including the following parameters using the `application/x-www-form-urlencoded` format in the HTTP request entity-body" | Strict CT gate at `/token/revoke` | ✓ |
| 9126 §2.1 | "The client constructs the message body of an HTTP `POST` request with parameters formatted with `x-www-form-urlencoded`" | Strict CT gate at `/par` | ✓ (see F1) |

**F1 — citation defect (must fix before implementation).** The design's `BindParamsFormOnly` doc comment (§2.1 of the design) and the requirements artifact both cite **"RFC 9126 §3.1"**. RFC 9126 has no §3.1: its structure is §2 Pushed Authorization Request Endpoint → **§2.1 Request** (the citation target), §3 "The 'request' Request Parameter". The existing `bind.go:23-24` comment's other citations (6749 §3.2, 7662 §2.1, 7009 §2.1, 8628 §3.1) are all correct — only the PAR reference is wrong. Correct it to §2.1 in both artifacts before it ships in code.

Positive confirmations: the strict gate is a *superset* of RFC conformance — any RFC-conformant client sending the CT header passes; only CT-less bodies (rejected per RFC 7231 §3.1.1.5's optional-header rule, a deliberate T-8(a) hardening) and non-form types fail. The `; charset=` acceptance after normalization is consistent with the permissive form path and not a smuggling vector. Note the gate is a *format* gate only: §3.2's "parameters MUST NOT be included more than once" and "sent without a value … omitted" rules stay unenforced in both modes (pre-existing, first-wins/merge semantics via `formIntoStruct`/`formStringSlice`) — out of scope, but worth one sentence in the design so strict mode isn't over-claimed.

## 2. Consistency assessment — strict-on-four vs permissive default

Sound, with no blocking inconsistencies found:

- **Single gate, no drift:** one extracted `normalizeContentType` shared by both binders; all four endpoints select via one site each (`s.bindCredentialParams` / `aliases.go` helper). Verified: `BindParams` form path already uses `PostForm` (body-only) — query-param smuggling is closed in *both* modes; the strict binder mirrors it.
- **Byte-identical rejection:** all four handlers map bind errors to `400 invalid_request` via `core.ErrorBody` with no `WWW-Authenticate`; no-store stamped pre-bind at all four sites (`server_token.go:22`, `handle_introspect.go:112`, `handle_revoke.go:68`, `handle_par.go:55`). Strict rejections are oracle-safe and identical across modes (the 400-vs-401 boundary moves only for JSON/CT-less bodies — the intended, documented breaking change of the opt-in).
- **Default off = byte-identical:** zero-value field, no-arg option precedent (`WithJTIReplayFailClosed`, `options_security.go:39`), and committed JSON tests (`test/handle_token_test.go:59,87`, `test/handle_introspect_test.go:89,237`) pass unmodified. The ~36 non-credential `BindParams` callers are untouched — a global flip would violate AGENTS.md wire-compat, so the scoped gate is the right call.
- **Boot-time-only is real:** `config/reload/reload.go` applies only an explicit `safeReloadPaths` allowlist; the new key automatically lands in `ignored_requires_restart` on SIGHUP — no reload-side code needed, matching the design's claim.
- **Documented asymmetry:** `/device/code`, `/device/verify`, `/auth/mfa`, CIBA stay permissive despite RFC 8628 §3.1/CIBA form mandates — an explicit non-goal; the config row/startup log naming the four endpoints mitigates operator misreading. Fine as scoped.
- **AC-2 correction is sound:** `jti` is `crypto/rand`-generated per token (`ed25519_issue.go:35-43`), so byte-identical success bodies were indeed unachievable; the structural-equivalence re-anchor is correct.

## 3. Public-contract confirmation

**Current state:** nothing is reflected yet — `security.strict_credential_content_type`, `WithStrictCredentialContentType`, and the three accessor additions have zero hits in `docs/`, `config/`, or code outside the design artifacts. The design's §2.5 plan covers: config-reference row (placement verified — `security.jti_replay.fail_closed` sits at `docs/config-reference.md:25` in the OAuth table), feature-matrix row (format verified against "OAuth 2.1 strict" at `feature-matrix.md:132`), no error-codes change needed (`invalid_request` documented at `error-codes.md:81`), reflection-generated schema (`config/schema/generate.go` — no artifact to regenerate), and all code seams verified (`accessors.go:369-371`, `sso_protocol.go:184`, `build_app_oidc.go:301-304`, `aliases.go:97`, test structs at `handle_introspect_test.go:28`/`handle_par_test.go:17`/`handle_revoke_test.go:19`, `RoutesDeps` embedding at `grant_handler.go:36`).

Three findings:

- **F2 — "no OpenAPI change" is wrong for `/token/revoke`.** `docs/openapi.yaml` postRevoke (lines 1341-1360) documents only **200 and 401** — the bind-failure `400 invalid_request` is absent, and strict mode makes that 400 the headline rejection for JSON callers on revoke. The other three endpoints document 400. Per AGENTS.md ("endpoint → `docs/openapi.yaml`"), postRevoke must gain a `400 invalid_request` response in the same change. (The `application/json` request-body entries on all four ops stay accurate for the default deployment — no edit required there, matching the `scope_registry` precedent of documenting default behavior only.)
- **F3 — config-row placement (minor).** The design's OAuth-table placement is defensible (that's where `security.jti_replay.fail_closed` lives), but the *other* hardening knobs mapping to `sso.With*` options (`rar_limits`, `scope_limit`, `max_token_bytes`, `client_registration_rate_limit`) sit in the **Security** table (lines 69-77) with a "Maps to `sso.WithX`" convention. Recommend placing the row there with "Maps to `sso.WithStrictCredentialContentType`" + the four-endpoint/boot-time-only language — pick one table, exactly one row.
- **F4 — Deps accessors need no prose doc** (GoDoc-only, consistent with `IntrospectionCacheTTL`/`TokenUsageRecorder` precedent); the feature-matrix row covering the option + config is the right public surface.

**Verdict: the strict-mode design is RFC-consistent (with the §9126 citation fix) and internally consistent for the four-endpoint gate; the contract-doc plan is complete except the postRevoke OpenAPI 400 gap (F2) and the RFC 9126 §2.1 citation (F1). Both are small, concrete amendments to make before implementation.**
