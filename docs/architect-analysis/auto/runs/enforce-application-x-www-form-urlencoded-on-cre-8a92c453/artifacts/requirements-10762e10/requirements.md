The spec is written and every citation re-verified against the working tree. Summary:

**Deliverable:** `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-requirements.md`

**Evidence verification results** — all direction citations confirmed, with measured reality:

| Citation | Verdict |
|---|---|
| `oauthwire/bind.go:16-41` JSON default branch | Confirmed (func at :28, JSON/missing-CT default at :43-45) |
| `auditgovernance/oauth_token_source.go:201-210` form-encoded mint | Confirmed, 1-line drift (:200); `Content-Type` set at :209 |
| `tokengrant/token_client_credentials.go:21` cc no refresh_token | Confirmed (comment :20-23, response map :67-73 has no `refresh_token`) |
| `server_token_clientauth.go:193,239` client auth | Confirmed exact; introspect twin at `handle_introspect.go:134/202` |
| `shared/security` `CompareClientSecret` | Confirmed (`client_secret.go:19`, constant-time fallback via `constant_time.go:5`) |
| `server_token.go` `tokenNoStoreHeaders` | Confirmed (:22, before bind :30; success + error per `no_store.go`) |
| Billing consumer paths | Confirmed: `relay.go:46`, `quota_relay.go:347,427`; ready checks `app.go:100,103` |
| **Pin missing** | Confirmed: zero hits for `BindParamsFormOnly`/`require_form_content_type`/`WithCredentialFormOnly`; billing tests assert form body but never the Content-Type header, and no mint ever runs against a real strict `/token` |

**Key decisions pinned:**
- **R6 mechanism** — scoped strict binder (`oauthwire.BindParamsFormOnly` naming proposed) at the 8 credential sites, config key `server.require_form_content_type` **default true** (consistent with the accepted audit-provisioner sibling design; satisfies the G5 gate), legacy fallback OFF-path; dual-mode `BindParams` kept for commerce/admin/selfservice consumers.
- **R7 billing pin (the distinctive element)** — test-only: extend `assertQuotaTokenRequest`/`assertRetentionTokenRequest` with Content-Type assertions, plus a new `test/billing_strict_form_e2e_test.go` driving the **real** `auditgovernance` token sources (the exact code paths billing wires — `package main` can't be imported) against a strict-mode `sso.NewServer`, proving **no billing code change**.
- **T-9 precedence resolved** — form-bindable unauthenticated introspect → `401 invalid_client`; JSON introspect → `400` at parse (that *is* T-8(b)); all 21 acceptance cases preserved verbatim and made testable.
- **Budgets** — `cmd/snaplink-billing` is at the 10-file non-test fan-out ceiling and `quota_relay.go` at 485 lines; R7 is tests-only, so no budget is crossed.
