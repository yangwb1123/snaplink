Spec written. Summary of the evidence-backed deliverable:

**Deliverable:** `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-requirements.md`

**Every direction citation verified** (all confirmed, with measured drift):

| Citation | Verdict |
|---|---|
| `oauthwire/bind.go:28-53` JSON + missing-CT-to-JSON default | Confirmed exact (function 27–53; JSON default branch 43–45) |
| `bindOAuthParams` at server_token.go:29, server_device.go:53/242, server_mfa.go:255, server_admin_handlers.go:293 | Confirmed (token drifted 1 line to 30; others exact) |
| Constant-time compare, cc-no-refresh, no-store headers | Confirmed present — no work |
| `apiclient.go:102` CLI JSON-only-to-admin | Confirmed, mechanism newly proven: CLI admin routes go through the admin **gRPC-gateway** (`cmd/sso-server/build_http.go`), never BindParams |
| T-8(b)(c)(e)/T-9 | Campaign IDs; restated testably in §5 |

**New findings the direction missed** (reported as evidence, scope kept bounded):
1. **Global BindParams flip is wire-breaking**: 44 non-test call sites; `interfaces/commerce/payment_ingest.go:99` *requires* JSON (`normalizedJSON`), plus `interfaces/admin/*`, `protocols/selfservice/*` are JSON-first. Spec resolves this with a scoped strict binder at the 10 credential bind sites (incl. the uncited `options_admin.go:414` and CIBA `handle_ciba.go:87`).
2. **Sweep is larger than claimed**: `TestFormEncoded_JSONStillWorks` must be inverted; ~25 test files post JSON to credential endpoints; the **generated TS/Python SDKs emit JSON to /token** (gen_ts_runtime.go:158, gen_py.go:103) — now required work items in R5.
3. **T-9 precedence conflict**: body parse precedes client auth today (handle_introspect.go:120 → 133), so "401 before any body parsing" is not current behavior and is jointly unsatisfiable with T-8(b) for JSON bodies; the spec pins the testable regression (401 for every *bindable* unauthenticated request) and rejects auth-before-parse (would kill body-credential auth).
4. **Error-shape nuance**: `/auth/mfa` bind failure collapses to `400 mfa_invalid`, not `invalid_request` (AGENTS.md oracle table) — preserved per-site in R1.
5. **Contract drift**: openapi.yaml declares `application/json` request bodies on all seven credential paths — removal is a required same-change contract update.
