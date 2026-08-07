Verification complete. Report written to `docs/architect-analysis/auto/runs/emit-tenant-id-and-roles-claims-in-buildaccesspa-2fb7e910/artifacts/design-a77de8a6/task-1-ac-closure-verification.md`. All six feasibility items checked against executable code at HEAD `718345d6`:

## Verdict: all acceptance gaps closable — with one reviewer claim refuted

**1. Error-injecting `core.TenantUserStore` stub — FEASIBLE.** `MemoryTenantUserStore.Get` can only return `ErrNoMembership`/nil (confirmed, no outage path). The stub is a 5-method type satisfying the interface (aliased at `aliases.go:125`, wired via `options_passwd.go:363`). Direct precedent: `erroringTenantStore` + `TestResidency_StoreOutageFailsOpen` + `capturingLogger`/`recordingErrorLogger` in `tenant_residency_test.go:196-242,433-442`.

**2. Per-issuer AC-4/AC-5 — CLOSABLE.** `serving_region_test.go` is the exact per-issuer table harness (`servingRegionIssuers(t)` + `decodePayload`). The three header structs are distinct types, each with exactly one `Kid` field (`ed25519_types.go:9`, `ecdsa_jwt_issuer.go:436`, `rsa_jwt_issuer.go:433`). `decodeJWTSegments` (`ed25519_rfc9068_test.go:27`) plus `With{Ed25519,ECDSA,RSA}Clock` give deterministic golden claim-sets (only `jti` is random — delete before comparing).

**3. Pairwise AC-6 variant — FEASIBLE.** `TestRcov2D_PairwiseSubject` (`rootcov2_discovery_test.go:187`) is the full precedent. The proof is structurally airtight: `TenantUserStore` is keyed `(TenantID, UserID)` and `issuedSub` is computed before `Issue` (`server_login.go:107`), so `roles == ["member"]` alongside a pseudonym `sub` can only come from `result.UserID` keying.

**4. `s.metrics` nil-guard — NOT NEEDED (reviewer claim refuted).** `ObserveTokenPolicyRoleResolutionError` is nil-safe by design (`platform/metrics/metrics_token.go:119-123`: `if m == nil || ... { return }`). A nil `*metrics.Metrics` receiver returns before dereference — no panic in the outage test even through `rcovNewServer` (which doesn't wire `WithMetrics`). The helper can keep the seam byte-identical; a guard would be redundant. (The reviewer's concern was directionally right — `s.metrics` IS nil by default — but this specific method is guarded.)

**5. Harness patterns — CONFIRMED.** `rootcov_options_test.go:92-93` (`WithJITMembership`+`WithTenantUserStore`), `:143` (`WithMetrics(metrics.New())`), `rcovNewServer`/`rcovPostJSON`/`rcov2PasswordAuth`/rcov consts, `WithLogger` (options.go:345), `MemoryTenantUserStore` re-export, `sso.TenantRoleMember` const (`aliases.go:476`). Test files are excluded from the 500-line budget (`maintainability_budget_test.go:31-33`); prod deltas fit (server_login.go 469→~487, server_oauth.go 479→~474).

## Plan highlights

- **AC-1..3, 4, 5, 7** → new `infrastructure/defaultimpl/tenant_roles_test.go` (mirrors `serving_region_test.go`; AC-7 uses `core.KeyTenantID`/`core.KeyRoles` as map keys).
- **AC-6 + 6f** → new `interfaces/sso/rootcov2_tenant_roles_test.go` (base, pairwise-keying, JIT-ordering, no-membership, tenant-less, and outage-fail-open variants).
- **Five required implementation decisions carried forward** (blockers from the security review, not the ACs): `tenant_id` ext-collision strip + raw-byte pin test, refresh-rotation roles-drop pin test, outage audit event, `Subject.TenantID` doc-comment update (`types_token.go:226`), feature-matrix row.
