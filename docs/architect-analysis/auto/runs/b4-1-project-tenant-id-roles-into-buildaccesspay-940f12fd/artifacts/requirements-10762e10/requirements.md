Spec complete. **`docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-1-tenant-claims-requirements.md`** (185 lines), following the sibling configcmd B4-1 spec's structure.

## Verification results (every citation re-checked)

**Confirmed exactly as cited:**
- `buildAccessPayload` at issue_payload.go:26 — no `tenant_id`/`roles`; `ed25519Payload` (ed25519_types.go:15) has no such fields
- `Subject.TenantID` (types_token.go:231) — its doc comment literally states "**NOT a token claim — issuers emit only fields they enumerate in buildAccessPayload**", direct confirmation of the problem
- Shared `buildAccessPayload` calls at ed25519_issue.go:43 / ecdsa_issue.go:37 / rsa_issue.go:29; kid header at ed25519_issue.go:33 (must not be re-added)
- All 8 grant-path `TenantID: client.TenantID` stamps (authcode/refresh/cc/device/ciba/jwt-bearer/saml2/exchange) — content exact, line drift 10–17
- `resolveIssuer` Host fallback (server_discovery.go:251–258); request-time roles only (mesh_authz.go:326 exact; accessors_handlers.go:103, drift 1); `entitiescmd/tenants.go` surface

**Key findings that shape the spec:**
1. **Issuer nuance**: under the cmd path `WithIssuer(cfg.Server.Issuer)` is wired at boot (config_load.go:308), so Host-derivation is reachable only for SDK embedders — the spec's T-1.2 acceptance asserts the minted-token side (iss == discovery == WithIssuer != request Host), while fallback removal stays server work
2. **Roles confirmed PROPOSED**: no Roles field on `Subject`, no permissions provider in tokengrant — kept conditional with explicit fail-open/oracle-safe semantics
3. **Admin wire protocol has no `Client.TenantID`** (grpcadmin/admin_clients.go:59) — the e2e must bind the CLI-created tenant at the store level
4. **CLI↔gateway wire contract verified** against `proto/admin/v1/tenants.proto` (`body: "tenant"` flat POST matches `RunTenants` exactly) — so **zero production-code changes** are needed in entitiescmd; the deliverable is the acceptance harness + contract pins

## Acceptance preserved and made testable
- 12 Given/When/Then cases: CLI e2e (real `TenantAdminService` + real `domains/tenant/memory` store + real `sso.Server` issuance, no cmd→cmd imports), per-grant `tenant_id` matrix (7 grants in `test/`, `ssotest`), issuer coherence vs Host, conditional roles semantics, T-9 byte-identity regression
- Engineering constraints honored: `cmd/sso-ctl` at 16/16 fan-out ceiling (no new package), `interfaces/sso` 60-file ceiling untouched, no `cmd/` imports by library packages, R0 enabling dependency (server module) explicitly separated
