Requirements specification delivered to `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/requirements-10762e10/requirements.md` (the pipeline's requirements artifact path).

## Verification results — every cited claim re-checked

**Confirmed as cited:**
- `buildAccessPayload` (`infrastructure/defaultimpl/issue_payload.go:26`) emits no `tenant_id`/`roles`; `ed25519Payload` (`ed25519_types.go:15`) lacks both fields; shared by Ed25519/ECDSA/RSA issuers (`ed25519_issue.go:43`, `ecdsa_issue.go:37`, `rsa_issue.go:29`).
- `Subject.TenantID` at `shared/core/types_token.go:225-231` self-documents "NOT a token claim"; `kid` already in header (`ed25519_issue.go:33`, `ecdsa_jwt_issuer.go:439`, `rsa_jwt_issuer.go:436`).
- `resolveIssuer` Host fallback (`server_discovery.go:251-260`); discovery issuer base-derived (`server_discovery_config.go:146,264`), multi-host behavior documented as intentional (:62-64) — which is why the proposal's `require_configured` switch (marked [PROPOSED]) is the right framing, not unconditional removal.
- Roles exist only as login embedding (`options_misc.go:28`, `server_finish_login.go:336`, `server_discovery.go:370`); openapi.yaml:4807 doc/code drift confirmed; `permissions.Provider` already exposed to grants via `handler.ServerDeps.Permissions` (`serverdeps.go:30`, `accessors_handlers.go:265`).

**Corrections found and flagged in the spec (E6):** the analysis's cited `Subject.TenantID` population lines (`server_oauth.go:197`, `server_login_client.go:329`, `server_helpers.go:126/144`) are `tokenpolicy.PolicyInput`/`TrustSignals` sites, not `Subject` construction. The real sites are `server_login.go:118`, `server_native_sso.go:193`, and nine `internal/handler/tokengrant/*` sites — the "plumbing exists, only emission missing" claim itself holds.

**Key finding added:** `cmd/sso-server` never wires `sso.WithIssuer` — token `iss` ("sso-server") already disagrees with the Host-derived discovery `issuer`, violating the RFC 9207 invariant documented at `server_discovery.go:246-249` in the default deploy tree (E10); the spec requires closing this under `require_configured`.

## Spec contents
- R1 `tenant_id` emission (omitempty, no call-site changes — all 10 sites verified populated), R2 `roles` (wire shape mirroring `permissions.Role` for element-for-element equality, dependency-free `shared/core` type per AGENTS.md §4, one shared fail-open helper, user-bound grants only), R3 `kid` untouched, R4 `iss` allowlist with `require_configured` (token + resolveIssuer + discovery + RFC 9207 consistency, mode-off byte-identical), R5 byte-identity regressions.
- Acceptance checks preserved verbatim in intent and made testable (T-2 five checks mapped to concrete tests + T-8(a) gate + fail-open outage variant from the sibling analysis); scope boundaries keep the change inside the direction (no gensdk/SDK regeneration, no introspection echo, no verify-side, no config-key design — that is the sibling configcmd direction).
