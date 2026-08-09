All three asks verified against the working tree. The flip (`binding == nil || claims.TenantID != input.TenantID`) is already applied at http.go:241 as uncommitted partial landing; the scratch test `verify_flip_scratch_test.go` already exercises the A16 shape and passes post-flip while the A15 pin correctly fails. Full report:

## 1. A16 — implementable and sufficient ✅

**Mechanism verified**: all four user-path causes funnel into one writer call `writeCheckoutChallenge(writer, 403, ErrTenantMismatch, "")` (http.go:250-251) — `scope==""` means no scope attribute is appended, so the challenge is byte-exact `Bearer realm="stripe-adapter", error="tenant_mismatch"` (matches the `tenantMismatchChallenge` const) and the body is byte-exact `{"error":"tenant_mismatch"}\n`.

**Proof it's a real pin, not vacuous**: I ran the tree. `TestVerifyFlipUserPathFourCauseByteIdentity` (scratch, models A16 exactly — all four causes + empty-input edge + 201 control, asserting status, exact body, exact challenge equality, and `bytes.Equal` + `reflect.DeepEqual` header-map identity) **passes** post-flip; `TestCheckoutUserAcceptsTenantlessConsoleToken` (A15) **fails with 403** — pre-flip, cause 4 (claim-less + bound input) returned 201, so the four-cause byte-identity assertion genuinely detects the regression.

**Cause-4 path confirmed distinct**: claim-less token, `input.TenantID="tenant-one"` → `binding != nil`, `claims.TenantID ("") != "tenant-one"` → 403. The `""`-input edge is sound: `validIdentity("")` is false (config.go:362-363), so `TenantBindings[""]` can never be configured → `binding == nil` short-circuits first.

**Sufficiency vs. acceptance**: exact body ✅, exact challenge (equality, not Contains — pins no-scope-attribute) ✅, byte-equality across all four causes ✅ (A5's 3-cause shape already proves the comparison works on this writer; scratch proves 4). Wrong-scope class keeps its `scope="admin:write"` attribute via the existing R2.3 row — the two classes stay distinguishable. Transitivity with A5/A8 comparison shape is exactly the scratch's pattern.

**Delivery notes**: scratch file (untracked) must be deleted and replaced by `TestCheckoutUserRejectsClaimlessToken` inside http_test.go — the package is at its 10-file non-test fan-out ceiling (10 non-test files confirmed), so edits only; `_test.go` is exempt from the 500-line budget (maintainability_budget_test.go:71), so folding ~60 lines in / ~28 out keeps it clean.

## 2. A15 deletion — safe ✅

Helper `testAdapterHandlerSubjectWithoutTenantClaim` (http_test.go:456-464) is referenced by:
- **A9** `TestCheckoutMachineRejectsMissingTenantClaim` (http_test.go:301) — survives deletion, and its machine semantics are untouched by the user-path flip (verified passing).
- A15 itself (:325) — being deleted.
- The scratch (:51, :107) — deleted/replaced by A16, which uses the same helper for cause 4.

After the run, A9 + A16 both use it → never orphaned. Coverage: A15's bound-201 half is inverted by the flip (correct new behavior); its unbound companion is subsumed by A5/A16. No coverage loss.

**Two outstanding tree items to fold into the run**: (a) the D1 comment at http.go:243-248 is now **stale** — it still says "A claim-less token … passes when the input tenant is bound; the HasTenantID guard is the policy carve-out" (false post-flip; R1's comment rewrite not yet applied); (b) the helper comment at http_test.go:455 still cites "(A9) and the D1 pin (A15)" (R2 comment drop).

## 3. A17/A18 — feasible in test/, exact recipe ✅

**Mint path exists and is proven**: production `/auth/login` direct-mint (`response_type: "token"`) — the identical pattern already used by `srLogin` (test/scope_registry_test.go:148-160) and `loginAs` (test/e2e_test.go:197). I verified every gate on that path:

- `mintAccessToken` stamps `TenantID: client.TenantID` (server_login.go:119) → `buildAccessPayload` unconditional literal → wire `tenant_id`, omitempty for legacy (issue_payload.go:46) — same B4-1 discipline as cc.
- `subject != clientID`: `applyPairwiseSubject` defaults to identity with no pairwise store → `sub` = user ID (server_pairwise.go:19-22). `client_id` claim = client.ID.
- `admin:write` scope: `req.Scope` passes verbatim to `Issue` (server_login.go:129); the login path has **no AllowedScopes intersection** (only resource/claims/RAR/param gates, server_login_gates.go:304-340) — and the seeds already include `"admin:write"` anyway.
- Legacy client (`TenantID ""`): `clientTenantOK` returns true for empty tenant (domains/tenant/client_gate.go:19-21); no GrantTypes gate on `/auth/login`; `IsAuthenticatorAllowed`/`AreResourcesAllowed` treat empty lists as "any" — mint is 200, token claim-less (proven twin: E-3 cc test).
- `aud`: `resource: ["stripe-adapter"]` → `Subject.Resources` → compact single-string aud. **Mandatory** — without it the adapter-shaped middleware rejects `ErrAudienceMismatch` (already pinned by `TestStripeAdapterTenantClaim_ResourceRequired`).

**Harness delta** (`newStripeAdapterHarness`, currently 200 lines → ~310, fine):
1. Add `sso.WithUserProvider(users)` + seed user, `sso.WithAuthenticator(passwordVerifier)`, `sso.WithSessionManager(...)` — **session manager is mandatory** (`createSessionRecord` → `sessionMgr.Create` would nil-panic); refresh/auth-code stores are not needed (buildE2E proves).
2. Seed `console-e2e` (`TenantID: "tenant-e2e"`) and `console-legacy` (`TenantID: ""`), both `TokenStrategy: "jwt"`, `Active`, `AllowedScopes: ["admin:write"]`, `AllowedAuthenticators: ["password"]`.
3. Helper `saLogin(t, srv, clientID)` mirroring `srLogin`: `POST /auth/login` with `{"provider":"password","client_id":...,"response_type":"token","credential":{"username":"console-user","password":"x"},"scope":["admin:write"],"resource":["stripe-adapter"]}`.

**Assertions** (mirroring the A11-A13 leg's shape): A17 — 200; wire `sub`="console-user" ≠ `client_id`; `scope`="admin:write"; `tenant_id`="tenant-e2e" present; `aud` compact string; production rs middleware (JWT-mode: Issuer + JWKSCache + ExpectedAud, exactly the adapter mount shape) → `ClaimsFromContext` has `TenantID="tenant-e2e"`, `HasTenantID()==true`. A18 — 200; **no `tenant_id` key** on the wire; `HasTenantID()==false` through the same middleware. The gate decision (this claim-less shape → 403) stays unit-side in A16 — the `test/`-cannot-import-`package main` boundary is honored because test/ imports only `interfaces/sso`, `interfaces/ssoclient/rs`, `infrastructure/defaultimpl`, `domains/authenticators`; e2e proves mint-side trustworthiness, unit pins prove gate-side rejection.

**Verdict**: the acceptance mapping is implementable and sufficient as specified; the run's remaining mechanical steps are: delete A15 + scratch, rewrite the stale D1 comment, add `TestCheckoutUserRejectsClaimlessToken`, then the e2e leg per the recipe above. openapi.yaml already carries the fail-closed wording, so A19's contract side is in place.
