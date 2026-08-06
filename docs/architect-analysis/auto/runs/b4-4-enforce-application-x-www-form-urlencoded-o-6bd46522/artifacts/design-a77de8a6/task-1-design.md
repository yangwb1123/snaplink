Design complete. **`docs/architect-analysis/auto/runs/b4-4-enforce-application-x-www-form-urlencoded-o-6bd46522/artifacts/design-6bd46522/task-1-design.md`**

## Verification outcome

Every evidence claim was checked against HEAD. **All confirmed** — seam at `server_jar.go:304` + 10 call sites (6 sso + 4 via `aliases.go:97`), `TestFormEncoded_JSONStillWorks` at `test/oauth_bind_test.go:272`, fuzz seeds encoding the old JSON-default contract, constant-time sites (`client_secret.go:15-31`, `mesh_authz.go:443`, `server_native_sso.go:102`, `dpop.go:130,243`, redis `:167/:207`), no-store-before-bind on all 10 endpoints, openapi JSON bodies, Python SDK JSON credential ops, audit-provisioner untouched, MFA→`mfa_invalid` and introspect→401 `invalid_client` mappings.

**One material gap in the evidence that reshaped the design (F1):** the "shared seam" `oauth.BindParams` is also the binder for ~30 **JSON-native non-credential** consumers (`interfaces/admin/*`, `interfaces/commerce/*` incl. the wallet adjustments API, `protocols/selfservice/*`, `internal/adminuser`). A semantic change to the shared function would break all of them. The design therefore adds a strict variant — `oauthwire.BindParamsFormOnly` (form CT required, body-only `PostForm`, missing/unknown CT rejected before the body is read) — and switches exactly the 10 credential call sites to it. `BindParams` stays byte-identical for everyone else.

**Secondary corrections:** openapi actually has **10** ops to update (8 credential + 2 admin compromise, JSON-only bodies at ~:5004/:5502); `/register*` are JSON-only per RFC 7591/7592 but bind via `ctx.Bind` (not the seam) and keep JSON; `/auth/login` is the JSON-only CSRF mirror and must be explicitly excluded; `interfaces/sso` is at its 60-file ceiling (zero new files there).

## Deliverable contents

- **API changes**: new `BindParamsFormOnly` + shared `requestContentType` helper; seam rewiring in 2 files; full old-vs-new behavior table
- **Compatibility**: 8 constraints incl. form byte-identity lock, Basic-wins, PKCE/DPoP/mTLS untouched, DCR/login exclusions, SDK hand-fix (7 Python methods, not the rejected gensdk path)
- **Failure modes**: 9-row table with fail-open/fail-closed classification; fuzz no-panic guarantee; drift guard
- **Migration**: 8 ordered, gate-clean steps (seam → invert compat test → seam unit tests → fuzz re-seed → ~20-file test migration with assertions unchanged → AGENTS.md:113 + openapi → SDK → `make ci`)
- **Acceptance mapping**: T-8(b)/T-8(c)/T-9/no-store/MFA-oracle/constant-time/fuzz/exclusions mapped to concrete tests and pass criteria, with pre-existing failures flagged separately
