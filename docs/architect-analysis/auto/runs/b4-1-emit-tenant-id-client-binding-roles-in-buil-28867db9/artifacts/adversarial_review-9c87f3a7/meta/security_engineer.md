Review complete. Written to `docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-client-binding-roles-in-buil-28867db9/artifacts/adversarial_review-9c87f3a7/meta/security_reviewer.md`, all claims verified against committed code (not the evidence summary).

## Verdict by area

**1. Roles fail-open vs fail-closed scope-expansion — no direct conflict, one genuine adjacency**
- **Safe**: omission-on-outage is a *narrowing* (least privilege); the scope-expansion gates are all widen-proof (exchange subset → `invalid_scope`, refresh re-stamps original `grantScopes`, JWT-bearer via `GrantedScopes`). Mesh roles are advisory only (`X-Auth-Roles`, ALLOW never depends on them, `mesh_authz.go:422-423`). JWT/SAML-bearer subject control adds no privilege beyond `sub` — roles are keyed by (asserted subject, client).
- **Blocking (F2)**: the live `TokenRoles` hook at refresh/token-exchange can **widen** the rotated token's claim set, while every other rotated attribute is frozen (`Claims: info.Attributes`, cloned `authorization_details`, locked SID). Roles re-read at rotation is the one place the design behaves like scope expansion. Must decide freeze-in-refresh-record vs documented live-read, and test it.

**2. Spoofing/collision — wire containment safe; one shadowing vector exists today**
- **Safe**: provider attributes land only in `ext` (namespaced, never merged top-level — userinfo/introspection are enumerated projections); DCR open registration *drops* body `tenant_id`; PUT never changes tenant; every mint site has the local (pre-pairwise) subject in scope.
- **Blocking (F5)**: `interfaces/admin/governance.go:478-482` reads `claims.Extra["tenant_id"]` — the **untrusted provider-attribute path** — as the admin write-quota tenant bucket. Adding structured `TokenClaims.TenantID` creates two sources named `tenant_id`, and the existing consumer keeps trusting the attacker-influenced one. Migrate the consumer + reserve/scrub `tenant_id`/`roles` keys from the `ext` vocabulary.

**3. WithIssuerAllowlist — no oracle; one design flaw**
- **No oracle**: all failure paths are boot-time; in the misconfigured state no request is served; `Validate` never re-checks `iss` (signature + exp/nbf only), so no validation-side oracle either. The pin (token iss == discovery == RFC 9207) holds via the single non-sentinel `s.issuer` path.
- **Blocking (F8)**: option-order dependence — `NewServer(WithIssuerAllowlist(...), WithIssuer(...))` would panic on a *valid* final config if validation runs inside the option closure. Must be a post-options final-state check (`NewServer` already has the `apply*` step for this). Panic precedent exists (`WithCustomGrant`).
- Residual to document: fleet skew (mixed allowlist/legacy replicas mint different `iss` → RP rejections) and empty-mode Host influence at untrusted edges.

Three blocking items for design revision: **F2** (roles rotation semantics), **F5** (tenantHintFromClaims migration + ext key reservation), **F8** (post-options validation). No code was changed, so no gates were run.
