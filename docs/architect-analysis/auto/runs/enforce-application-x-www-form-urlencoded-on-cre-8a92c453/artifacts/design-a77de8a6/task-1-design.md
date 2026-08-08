All claims verified. Design delivered at `docs/architect-analysis/cmd-snaplink-billing-b4-4-credential-form-only-design.md`.

## Verification verdict

Every evidence citation was checked against the working tree — **all confirmed**, including the distinctive pin claim (zero hits for the three proposed symbols; no test in `test/` references `NewOAuthTokenSource`/`NewPlatformTokenSource`; `assertQuotaTokenRequest`/`assertRetentionTokenRequest` never assert the request Content-Type header). Budgets verified exactly: `interfaces/sso` = 60 non-test files (ceiling), `cmd/snaplink-billing` = 10 (ceiling), `quota_relay.go` = 485 lines. MFA bind-failure → `400 mfa_invalid` confirmed at `parseMFACompleteRequest`.

**Drifts found beyond the spec's own disclosures** (all minor, resolved in the design):
1. Spec R7.2 cites `NewOAuthTokenSource` at `oauth_token_source.go:143`; actual is `:77`.
2. R5.1's migration inventory is a sample — complete sweep adds `handle_token_test.go:59,87,284`, `refresh_token_test.go:118,342,375,496`, `refresh_rotation_claims_test.go:57`, `rar_test.go:265,429,480,527`, `introspection_jwt_test.go:70`, `handle_device_test.go:66,111,187,200,361`, `mfa_test.go:200`.
3. R5.2/R5.3 "flip/re-seed" wording conflicts with the accepted sibling's D2 resolution (legacy `TestBindParamsJSONDefault` + legacy fuzz stay green — they test the untouched dual-mode binder; strict cases go in new files).
4. Spec §7 lists `build_app_core.go:154` as a Modify; the sibling pins no change there (`*bool` config key appended only when set).
5. The four protocol Deps interfaces (`PARDeps`/`RevokeDeps`/`IntrospectDeps`/`CIBADeps`) must each gain `RequireFormContentType() bool` — the spec omitted this compile-time surface; six protocol-test fakes must be updated.

## Design summary

- **API**: `oauthwire.BindParamsFormOnly` + unexported `errFormOnly` sentinel (wire-invisible Info log, bounded classes); `oauth.BindCredentialParams(ctx, v, formOnly)` dispatch; `s.bindCredentialParams` for the four `interfaces/sso` sites; `sso.WithCredentialFormOnly(bool)` with **default true seeded in `NewServer`**; `ServerConfig.RequireFormContentType *bool` (`nil` → strict; `false` → deprecated legacy + startup warn). No new `Err*`, no store changes.
- **Compatibility**: breaking by design on the 8 sites; 44 non-credential `BindParams` call sites, `/auth/login`, `/register`, admin API byte-identical; gensdk form emission must land before/with the flip; rollback is one config line.
- **Failure modes**: billing `/readyz` → 503 if a mint ever drifts (killed by the R7 pins); external JSON clients 400 (fallback + CHANGELOG/OpenAPI); SDK embedder breakage (deliberate, escape hatched); fuzz/panic and oracle-leak guards.
- **Migration**: 9 ordered steps keeping build/vet/architecture gates green, ending at `make ci`.
- **Acceptance mapping**: all 21 cases + T-9 pinned to concrete tests, including the new `test/billing_strict_form_e2e_test.go` driving the real `auditgovernance` token sources with the exact billing scopes (`audit:event:write`, `tenant-quota:projection:write`, `audit:platform:cross_tenant audit:policy:write`) against a strict-mode server — the missing pin, with zero billing code change.
