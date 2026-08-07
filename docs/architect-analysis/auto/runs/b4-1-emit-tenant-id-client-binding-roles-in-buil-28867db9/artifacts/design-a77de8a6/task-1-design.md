Design complete. The document is at the pipeline output path: `docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-client-binding-roles-in-buil-28867db9/artifacts/design-a77de8a6/task-1-design.md`

## Verification summary (evidence treated as untrusted)

**Confirmed (E1–E8):** all claim emission gaps (`buildAccessPayload` claim set, `Subject.TenantID` "NOT a token claim" doc, no `Roles` field), the `resolveIssuer` Host fallback + base-derived discovery issuer, all 10 mint sites threading `Client.TenantID`, the permissions fail-open seams (`ResolveForLogin`, `deriveMeshIdentity` pairwise pattern, `Provider.Roles`), `kid` presence, cmd's `WithIssuer` wiring with sentinel rejection, and the stale `oauth_token_source.go:43-46` statement.

**Corrections found:**
- **C1 (evidence said "6 grant-deps interfaces")**: there are **8** — `AuthCode`, `Refresh`, `Device`, `CIBA`, `JWTBearer`, `SAML2Bearer`, `TokenExchange`, and `ClientCredentials` deps, all guarded at `accessors_handlers.go:362-369`. The hook lands on the 7 end-user interfaces; `ClientCredentialsDeps` is untouched (roles omitted there per spec).
- **C2**: `deriveMeshIdentity` is at `interfaces/sso/mesh_authz.go:303-335`, not `domains/permissions/mesh_authz.go`.
- **C3 (new)**: ID tokens do **not** flow through `buildAccessPayload` — they use `ed25519IDPayload`/`oidc.IDTokenRequest` (`ed25519_issue.go:80-110`), so the claims are access-token-only per the direction's own naming; the design pins this boundary with an explicit ID-token-absent test.
- C3/C4 from the evidence (kid file, Host-fallback reachability) re-confirmed.

## Design highlights

- **R1/R2**: `tenant_id` (omitempty, zero mint-site changes, ServingRegion discipline) + `roles` (`Subject.Roles []string`, one shared `TokenRoles(ctx, userID, clientID) []string` hook on the 7 end-user deps interfaces, single fail-open `*Server` implementation keyed by local subject, pairwise-safe), both on the shared `ed25519Payload` covering all three signers; round-trip into `TokenClaims` but **not** into introspection (enumerated projection boundary).
- **R4**: `WithIssuerAllowlist`/`server.issuer_allowlist` — non-empty mode panics at construction (SDK) / errors at config load (cmd) unless `issuer` is non-sentinel and allowlisted, making the Host fallback structurally unreachable and pinning token `iss` == discovery `issuer` == RFC 9207 `iss`. Empty mode is byte-identical legacy.
- **Compatibility**: no new `Err*`, endpoints, `go.mod` changes, or `interfaces/sso` files (60-file ceiling honored); internal test fakes need one nil-returning stub.
- **Failure modes**: provider outage fails open (log + claim omitted); allowlist misconfiguration fails fast at startup; roles documented as mint-time snapshots.
- **Acceptance mapping**: all 5 checks mapped — AC-1 → new `test/token_claims_contract_test.go`; AC-2 → in-repo predicate (claim == client tenant) with the 422 gate cross-repo; AC-3 → option/config unit tests + `test/oidc_discovery_test.go` extension; AC-4/AC-5 → `serving_region_test.go`-pattern per-signer tests with fixed clocks and Validate round-trip.
