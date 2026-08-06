Design produced at `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/design-a77de8a6/task-1-design.md`.

## Verification outcome (evidence treated as untrusted)

**Confirmed (V1–V5):** `buildAccessPayload` emits no `tenant_id`/`roles` and the payload struct lacks both fields (shared by all three issuers); `Subject.TenantID` self-documents "NOT a token claim"; `resolveIssuer` Host fallback and discovery base-derivation are real; roles exist only in login embedding with the openapi.yaml:4807 drift; `permissions.Provider` is exposed via `ServerDeps.Permissions`; the E6 corrections are themselves correct (`server_oauth.go:197` is `PolicyInput`, `server_login_client.go:329` is `TrustSignals`; the real sites are `server_login.go:118`, `server_native_sso.go:193`, and 8 — not "nine" — tokengrant files; 10 total).

**Refuted (E10):** the requirements' headline "key finding" — *"cmd/sso-server never wires `sso.WithIssuer`; token iss already disagrees with Host-derived discovery issuer in the default deploy tree"* — is **false**. `config.ServerOptions()` wires `sso.WithIssuer(c.Server.Issuer)` (`config_load.go:305`), `build_app_core.go:154` appends it, `build_app.go:257` passes it to `NewServer`, and the default `"sso-server"` is a deliberate non-sentinel guarded by `issuer_test.go` — so token `iss` == discovery `issuer` == authz `iss` in the default tree, and `resolveIssuer` never touches the request Host there. The sibling peertrust analysis repeats the same error. The design therefore re-frames `require_configured` as opt-in hardening for SDK embedders/untrusted edges, not a default-tree bugfix.

## Design highlights

- **R1** — `tenant_id,omitempty` on `ed25519Payload` + one literal assignment in `buildAccessPayload`; zero call-site changes (all 10 sites populated).
- **R2** — dependency-free `core.RoleClaim` mirroring `permissions.Role`'s JSON tags (shared/core can't import domains per AGENTS.md §4), `Subject.Roles`, AMR-style defensive copy in `applyOptionalClaims`, one shared fail-open helper `permissions.RolesForSubject` + `Server.RolesForSubject` accessor, 9 user-bound call sites (client_credentials excluded), pairwise-local-sub discipline, and a wire-equality test pinning element-for-element identity.
- **R3** — `kid` regression-only.
- **R4** — `WithIssuerAllowlist`/`WithRequireConfiguredIssuer` options; `resolveIssuerStrict` for the RFC 9207 surfaces (503 via new `ErrIssuerNotConfigured`), boot-time panic validation, 28 `resolveIssuer` callers untouched; mode-off byte-identical.
- **R5** — golden byte-identity tests across all three issuers.
- **Constraints/failures/migration** — additive claims, file-ceiling compliance (extend existing files only, `interfaces/sso` is at 60), fail-open roles outage, token-size risk, rollback = revert; **acceptance mapping A1–A9** ties T-2's five checks, T-8(a), and the fail-open outage variant to concrete test homes.
