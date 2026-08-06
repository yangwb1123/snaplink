Requirements specification complete. Written to the pipeline output path:
`docs/architect-analysis/auto/runs/b4-4-enforce-application-x-www-form-urlencoded-o-6bd46522/artifacts/requirements-10762e10/requirements.md`

## Verification summary (all citations checked against HEAD)

**Confirmed as cited:**
- `protocols/oauth/oauthwire/bind.go:28-57` — `BindParams` explicitly accepts JSON "as a non-standard convenience" and defaults missing/unexpected Content-Type to `decodeSingleJSON` (bind.go:51-53)
- `interfaces/sso/server_jar.go:304` `bindOAuthParams` seam; call sites `server_token.go:29`, `server_mfa.go:255`, `server_device.go:53,242`
- Constant-time side: `shared/security/client_secret.go:19-31` (bcrypt + `ConstantTimeStringEq`), `mesh_authz.go:443`, `server_native_sso.go:102`, `ssoclient/rs/dpop.go:130,243` — all exact
- Hardening set: body-only parsing (PostForm), introspection caller auth (401 `invalid_client`), cc no `refresh_token` + no-store

**Corrections/findings that shaped the spec:**
- `infrastructure/redis/code_store.go:153` is off by a few lines — actual `ConstantTimeCompare` at :167/:207 (substance confirmed)
- The seam has **4 additional call sites** beyond the direction's list: `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`, `handle_ciba.go:87` (via the `aliases.go:97` alias), plus 2 opt-in admin compromise endpoints — a shared-seam change necessarily covers them; per-endpoint error mappings verified (all `400 invalid_request`, MFA collapses to `400 mfa_invalid`)
- `test/oauth_bind_test.go` `TestFormEncoded_JSONStillWorks` **explicitly locks in the JSON fallback** — must be inverted; `protocols/oauth/bind_fuzz_test.go` encodes the old contract in seeds
- ~20 test files (≈45 JSON posts to seam endpoints, enumerated with line numbers) must migrate to form-urlencoded, assertions unchanged
- **Contract conflicts to update in the same change**: AGENTS.md:113 ("Bind form and JSON…") and `docs/openapi.yaml` (JSON request bodies on 8 operations)
- **Impacted consumer, documented only**: committed generated SDKs (`docs/sdks/`) hardcode JSON bodies for credential ops — the rejected gensdk direction; in-repo clients (`ssoclient/remote` revoke, auditgovernance token source) are already form-compliant
- `cmd/snaplink-audit-provisioner` itself is untouched (nominal campaign owner; serves only health endpoints)

**Acceptance preserved and made testable**: T-8(b) JSON → 400 `invalid_request` (never decoded), T-8(c) missing/unknown CT rejected, form byte-identical (existing form tests as the lock), T-9 introspect-no-credentials still 401 `invalid_client`, no-store on the new 400s, constant-time untouched, MFA `mfa_invalid` oracle shape, plus a seam-level unit test file and fuzz re-seeding. Selected 400 over 415 (zero new error codes, existing bind-error path).
