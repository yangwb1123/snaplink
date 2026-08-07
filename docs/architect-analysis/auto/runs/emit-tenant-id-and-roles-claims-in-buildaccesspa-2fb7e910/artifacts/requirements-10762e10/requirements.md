Requirements specification complete. Summary of the deliverable:

**Output:** `docs/architect-analysis/auto/runs/emit-tenant-id-and-roles-claims-in-buildaccesspa-2fb7e910/artifacts/requirements-10762e10/requirements.md`

**Evidence verification (all 7 citations checked against the tree):**
- **Exact ✓ (6/7):** `issue_payload.go:26` `buildAccessPayload`; `types_token.go:226-231` `Subject.TenantID` "NOT a token claim"; `ed25519_types.go:12` header `Kid`; `server_oauth.go:207` `in.SubjectRoles`; `mesh_authz.go:326` `permissions.Roles`; `{ed25519,ecdsa,rsa}_issue.go:43/37/29` shared `buildAccessPayload` callers.
- **Minor drift (1/7):** `KeyRoles` is at `consts_wire.go:277`, not 267 — symbol verified, line off by 10.
- **Bonus findings that constrain the design:** `KeyTenantID = "tenant_id"` already exists (consts_wire.go:169); all 9+ mint seams already stamp `Subject.TenantID = client.TenantID`; `sso.Subject = core.Subject` (aliases.go:132) has **no** Roles field; no `tenant_id`/`roles` emission exists anywhere in defaultimpl today; deterministic-test machinery (`With{Ed25519,ECDSA,RSA}Clock`) and the `TestECDSAJWT_RFC9068Claims` pattern are in place; `go build ./...` is green and all touched files stay well under the 500-line budget.

**Requirements (R1–R5, bounded to the direction):**
- R1: `tenant_id`/`roles` fields (omitempty) on the shared `ed25519Payload`
- R2: projection in `buildAccessPayload` (ServingRegion discipline for `tenant_id`; AMR guard+copy pattern for `roles`)
- R3: `Subject.Roles []string` carrier (TenantID needs no change)
- R4: the one existing fail-open roster lookup (server_oauth.go:202-213) wired into the direct-login mint — token-endpoint seams explicitly left empty → claim omitted
- R5: feature-matrix row per the `sid`-claim precedent; no error-code/openapi/config changes (none of AGENTS.md §5.6's three contract classes apply)

**Acceptance T-2 preserved and made testable:** per-issuer tests asserting `tenant_id` equals the binding value and `roles` the set value, `kid` emitted exactly once (`strings.Count(headerJSON, "kid") == 1`), and empty-case byte-identity via golden claim-set comparison (modulo the RFC 9068-mandated random `jti`, with fixed clock for determinism). The `interfaces/snapshot/loader` module is confirmed orthogonal — zero changes there.
