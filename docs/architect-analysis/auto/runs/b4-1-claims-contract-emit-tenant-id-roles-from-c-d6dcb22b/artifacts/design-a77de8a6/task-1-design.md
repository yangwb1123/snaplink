## Summary

**Evidence verification: all 10 primary claims + 6 supporting facts confirmed against HEAD**, with three refinements that shaped the design:

- `internal/handler/tokengrant` and `domains/permissions` are both at their 10-file ceilings → the roles helper extends existing files, no new files anywhere (also honoring the `interfaces/sso` 60-file ceiling).
- `sso.NewServer` returns `*Server` (no error) → SDK-side "fail-loud" must be runtime fail-closed + loud logging; true boot validation lives in `config.validate()` (cmd path).
- The discovery issuer override is mis-homed inside `applyMFAIssuerSigning` (`server_discovery_config.go:264-266`) → design pins it to a single `effectiveIssuer()` helper so the RFC 9207 invariant (`resolveIssuer` == discovery `issuer`) holds by construction.

**Design** (written to `docs/architect-analysis/auto/runs/b4-1-claims-contract-emit-tenant-id-roles-from-c-d6dcb22b/artifacts/design-a77de8a6/task-1-design.md`, 170 lines):

- **R1a `tenant_id`**: `ed25519Payload`/`TokenClaims` gain `tenant_id,omitempty` fields; `buildAccessPayload` gets one unconditional literal; `claimsFromPayload` round-trips it; zero mint-site changes (all 8 already bind `TenantID`).
- **R1b `roles`**: `Subject.Roles` + `permissions.RoleCodes()` domain free function (fail-open, mirroring `ResolveForLogin`) + `Server.ResolveMintRoles` accessor + one new method on 7 grant dep interfaces; roles resolved fresh per mint; client_credentials emits none by design.
- **R2 allowlist**: `server.issuer_allowlist` config key → `WithIssuerAllowlist`; boot fails loudly on incoherent combos (issuer ∉ allowlist / non-URL entries / allowlist without explicit issuer); non-allowlisted request base → discovery 503 fail-closed; empty allowlist = byte-identical legacy (Host fallback retained, protected by re-pointed trusted-proxy tests).

**Deliverable sections**: API changes (file-by-file), 10 compatibility constraints, 10 failure modes, 6 migration steps, and testable acceptance mapping (A1 = T-8(a) per-signer + byte-compat negative + wire round trip, A2 = T-1.2 local round trip + cross-repo fixture contract, A3 = six falsifiable allowlist tests incl. the `oidc_discovery_test.go:80` extension and trusted-proxy re-pointing, plus B-series boot-validation tests).

I also caught and corrected one of my own A3 mappings during self-review: an untrusted peer's forwarded host is ignored, so the re-pointed test asserts 200 with config-pinned issuer, not 503 (503 is the non-allowlisted-base case, covered separately).
