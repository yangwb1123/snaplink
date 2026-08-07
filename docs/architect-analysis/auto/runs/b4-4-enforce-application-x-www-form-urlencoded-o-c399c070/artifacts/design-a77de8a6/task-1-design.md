All evidence claims verified against HEAD; design delivered. Summary:

## Verification verdict (evidence was accurate)

Every claim checked out; only sub-line drift on three rows:

| Claim | Verdict |
|---|---|
| `oauthwire/bind.go:28-53`, JSON default branch 43–45 | **Exact** |
| `bindOAuthParams` sites (token 29, device 53/242, mfa 255, admin 293) | **Confirmed** (token drifted to 30) |
| Constant-time compare / cc-no-refresh / no-store headers | **Confirmed present** — no work |
| `apiclient.go:102` CLI JSON-only-to-admin | **Exact** (gRPC-gateway mechanism confirmed) |
| Global flip wire-breaking: 44 sites; `payment_ingest.go:99` JSON-required | **Exact** — 38 `oauth.BindParams` + 6 `bindOAuthParams` = 44; `normalizedJSON` gate at :99 |
| 10 credential sites incl. uncited `options_admin.go:414`, `handle_ciba.go:87` | **Exact**; additionally verified `/token/revoke-all` is bearer-only, correctly absent |
| Sweep: `JSONStillWorks` invert + ~25 test files | **Confirmed** (func at :272-283; 16-file line inventory spot-checked) |
| SDKs emit JSON: `gen_ts_runtime.go:158`, `gen_py.go:103` | **Exact**; committed outputs at `docs/sdks/{typescript,python}/` |
| T-9 precedence conflict (`handle_introspect.go:120`→auth) | **Confirmed** (auth gate at :134, 1-line drift); body-parse-before-auth is current order |
| `/auth/mfa` → `mfa_invalid` collapse | **Exact** (`authzErrorBody(ErrMFAInvalid)`, no audit) |
| openapi.yaml JSON bodies on all seven credential paths | **Exact** (incl. "Form + JSON" text at :1064) |

Baseline: `go build ./... && go vet ./...` clean at design time.

## Deliverable

`docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-4-credential-form-only-design.md` — contains:

- **API changes**: additive `oauthwire.BindParamsFormOnly` + `oauth.BindParamsFormOnly` alias + `bindOAuthParamsFormOnly` delegate; unexported sentinel (no new `Err*`, oracle-safe); `bind.go` refactor into shared `normalizedMediaType`/`bindForm` (byte-identical)
- **Compatibility**: 44-site non-credential boundary byte-identical; `/auth/login` untouched; budgets checked (oauthwire 6→7 files, interfaces/sso stays at 60, no new packages)
- **Failure modes**: 10 rows incl. array-field mapping slip (repeated-keys rule), login-only posts, MFA shape drift, SDK artifact drift, T-9 precedence misread, rollback
- **Migration**: 6 ordered same-change steps (binder → 10-site switch → 16-file sweep + inverted test + new negative suite → SDK emission + regeneration → OpenAPI/error-codes/CHANGELOG → gates)
- **Acceptance mapping**: all 16 requirements cases → named tests, typed NEW / SWEEP / UNCHANGED / REGRESSION-PIN, incl. the T-9 form-wire 401 pin and a post-change grep audit for sweep completeness
