All line references in the spec are verified accurate. The requirements specification is complete.

## Summary

**Deliverable:** `docs/architect-analysis/auto/runs/b4-1-emit-tenant-id-roles-in-buildaccesspayload--7df5e5c3/artifacts/requirements-10762e10/requirements.md` (this run's requirements-stage artifact for module `cmd/snaplink-billing`, direction B4-1).

**Evidence verification (all 9 cited items re-read in the tree, all confirmed):**
- `buildAccessPayload` (issue_payload.go:26) emits no tenant_id/roles; `ed25519Payload` (ed25519_types.go:15) lacks both; kid already at header :12 — no re-add
- `token_client_credentials.go:40-53` populates `Subject.TenantID` at mint; `Subject.TenantID` at types_token.go:226-231 (spi.go:171 alias), self-documented "NOT a token claim"
- `resolveIssuer` (server_discovery.go:251-258) Host fallback via `requestBaseURL` (server_federation.go:40); `TestDiscovery_IssuerComesFromWithIssuer` (oidc_discovery_test.go:80); `cmd/snaplink-billing/README.md:170` documents the missing claim; `token_exchange.go:446` `guest.Roles` is guest-entitlement narrowing, not a mint-path source

**Key decisions pinned (learned from the prior run's design-gate FAIL):**
- **Roles owner: client binding** — `core.Client.Roles` threaded into `Subject.Roles` at the client_credentials + refresh mint sites; the only source that can satisfy T-8(a)'s client_credentials roles requirement (RBAC is user-keyed)
- **Allowlist validated post-options** in `NewServer`'s `apply*` block (option-order independent, remediation-naming panic); `server.issuer_allowlist` config with load-time error; `resolveIssuer` Host fallback removed (sentinel instead), discovery `Issuer: base` replaced — minted iss == discovery issuer == RFC 9207 iss in every state
- **Wire hygiene:** ext-key scrub of tenant_id/roles + `tenantHintFromClaims` structured-claim precedence with pre-change fallback; ID-token absence pinned per signer; introspection boundary documented (no echo)

**Acceptance preserved and testable:** T-8(a) → per-issuer ×3-signer unit tests + rootcov-style wire test (with `resource` param for `aud`, seeded tenant+roles client); T-2 → four falsifiable construction/discovery/config tests; T-1.2 → testkit tenant-binding option + fixture assertion (the 422 gate itself stays cross-repo, stated explicitly). Non-goals, byte-identity compatibility, and the R8 doc updates (including the stale `oauth_token_source.go:43-46` and `types_token.go` comments) are enumerated; no scope expansion, no new Err*, endpoints, proto, or `interfaces/sso` files (60-file ceiling).
