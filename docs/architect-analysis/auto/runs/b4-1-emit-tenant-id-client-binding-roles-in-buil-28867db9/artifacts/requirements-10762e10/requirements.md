The requirements specification is complete and verified. Final deliverable:

**`docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-client-binding-roles-in-buil-28867db9/artifacts/requirements-10762e10/requirements.md`** (the pipeline's requirements artifact path for this exact prompt)

## Verification results — every cited claim re-checked

**Confirmed as cited (E1–E9):**
- `buildAccessPayload` (`infrastructure/defaultimpl/issue_payload.go:26-50`) emits no `tenant_id`/`roles`; `Subject.TenantID` self-documents "NOT a token claim" (`shared/core/types_token.go:231-233`); no `Roles` field exists
- `resolveIssuer` Host fallback (`interfaces/sso/server_discovery.go:251-259`); discovery `Issuer: base` (`server_discovery_config.go:142-146`, base at :62)
- Client binding/tenant source at `server_token_clientauth.go:193` → `Client.TenantID`, threaded into `Subject.TenantID` at all 10 mint sites (8 in `internal/handler/tokengrant` + login + native-sso) — plumbing exists, only emission is missing
- `domains/permissions/memory.go:9-22` roles maps confirmed as the *proposed* source, with existing fail-open seams to reuse: `ResolveForLogin` (handlers.go:110), `Server.Permissions()` (accessors.go:124), `deriveMeshIdentity` pairwise pattern (mesh_authz.go:304-335)
- Sink-side 422 gate is cross-repo (B1-8, gate doc row 7); in-repo relay maps 400/422 to dead (relay.go:255)

**Corrections found (flagged in the spec):**
- **E8**: `kid` citation is wrong file — the header is `infrastructure/defaultimpl/ed25519_types.go:10-13`, not `shared/core/types_token.go:12`. Conclusion (kid present, no re-add) holds
- **E10**: token `iss` is *never* Host-derived — it's the issuer's own name (`WithEd25519Issuer(srv.Issuer)`). And crucially, `cmd/sso-server` **does** wire `sso.WithIssuer` (`config/config_load.go:305`) with a non-sentinel default (`"sso-server"`, sentinel rejected at :183-184) — so the Host fallback is reachable only for SDK embedders leaving `WithIssuer` unset. The allowlist requirement is framed accordingly: make the fallback structurally unreachable when configured + enforce token iss == discovery issuer == RFC 9207 iss

## Spec contents
- **R1** `tenant_id` claim (omitempty, zero mint-site changes), **R2** `roles` claim (dependency-free `Subject.Roles []string`, fail-open provider lookup keyed by local subject, one shared hook on the 6 grant-deps interfaces, client_credentials omitted), **R3** kid untouched, **R4** `server.issuer_allowlist`/`WithIssuerAllowlist` with mode-off byte-identical legacy, **R5** byte-identity regression, **R6** required doc/comment updates (incl. the now-false `oauth_token_source.go:44-46` statement)
- All 5 acceptance checks preserved verbatim in intent and mapped to concrete tests (AC-1 → `test/token_claims_contract_test.go`, AC-3 → `test/oidc_discovery_test.go` extension + config validation tests, AC-5 → `serving_region_test.go`-pattern unit tests)
- Scope boundaries respect the 60-file `interfaces/sso` ceiling (existing files only) and exclude the sibling directions (configcmd validation, B4-4 hardening, sink-repo work)
