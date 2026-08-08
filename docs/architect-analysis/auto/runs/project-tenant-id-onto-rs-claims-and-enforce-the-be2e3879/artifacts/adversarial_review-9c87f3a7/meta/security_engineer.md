All four review dimensions are now verified against HEAD (design doc, requirements doc, `http.go`, `claims.go`, `introspect.go`, `issue_payload.go`, the three grant handlers, `config.go`, `model.go`, `http_test.go`, `error-codes.md`, `openapi.yaml`, `scope_registry_test.go`, `shared/core/errors.go`, rs middleware). Every evidence citation in the design re-verifies line-exact; I found one factual error, two precision nits, and several classification notes. Full review follows.

---

# Adversarial review: tenant-isolation and oracle-safety claims

## Q1 — Rollout asymmetry vs AGENTS.md, and the inert-user-gate window

**Verdict: asymmetry is accurately characterized and AGENTS.md-compliant; the pre-B4-1 window does permit cross-tenant user checkouts, but the design discloses this honestly and it is bounded by campaign sequencing — the "hole closed" claim is correctly scoped to the post-mint, IdP-bound-console world.**

Verified facts underpinning the asymmetry:
- Authcode/refresh stamp `client.TenantID` unconditionally (`token_authcode.go:136`, `token_refresh.go:292`, `refreshRotatedSubject`), identical to cc (`token_client_credentials.go:52`). The "console client's binding, not the user's" nuance is line-exact.
- `issue_payload.go:46` stamps unconditionally with omitempty omission; `claimsWithoutEmittedKeys` (115-135) strips the `ext` copy. A tenant-less client (`TenantID == ""`) genuinely mints no claim.
- The proposed user gate `claims.HasTenantID() && claims.TenantID != input.TenantID` is provably inert when no claim exists; the machine gate `claims.TenantID != binding.TenantID` fails closed on `""`.

AGENTS.md mapping:
- **Machine gate fail-closed on absent claim is the correct classification** — it is a validation-family fail-closed, and there is a direct in-tree precedent: `validateClaims`'s region gate runs *last* and fails closed on an absent `serving_region` ("unverifiable provenance is a mismatch, not a pass", claims.go ~190). The design mirrors this discipline.
- **User gate D1 is not an AGENTS.md "fail-open with audit" case** — that list covers outage/helper failures (geo, risk scoring, sink errors, suspension-lookup outage). D1 is a static policy for a legitimate configuration (tenant-less shared console). However, the design never *says* this classification; §8 only states "no audit path exists on this surface." One sentence making "D1 is a policy carve-out, not an outage fail-open" would preempt the literal reading of AGENTS.md's fail-open-with-audit list.

The window question, answered directly: **yes — pre-B4-1 (and during rolling upgrades), the exact hole the direction describes ("a token minted for tenant A passes for any bound tenant B") remains open for user checkouts, because the gate cannot fire without a claim.** This is not a defect: the design states it twice (§1.1 nuance 1, §4 constraint row 1), the direction's T-8(b) acceptance is inherently post-mint, and the campaign's G1→G5 ordering plus the 1h default TTL (`defaultTokenTTL`, issue_payload.go:17-19) bounds the only uncontrolled exposure (tokens minted by pre-B4-1 nodes during upgrade). Two residuals the design should state more sharply:
1. The same window is *simultaneously* availability-breaking for machine flow (all bound-client checkouts denied) and isolation-gaping for user flow (cross-tenant checkouts allowed). F1 and F6 document each half, but nowhere does the design state they are simultaneous properties of one deployment state. An operator mid-rollout will see both.
2. Post-mint, a console *newly* bound after mint mints claim-less tokens for up to TTL (1h); the gate is inert for those. Same shape as F6, covered by the TTL bound, but not enumerated.

## Q2 — Probe distinctions (user `tenant_mismatch` vs machine fold; timing/order)

**Verdict: no new probe distinction in either flow; the cross-flow code difference is direction-mandated and constant-within-class.**

- **User flow, configured vs unconfigured tenants:** verified sound. All three causes (`binding == nil` for missing/`""`/unbound; claim-mismatch) collapse into one writer call with `ErrTenantMismatch` and `scope:""` — `writeCheckoutChallenge` appends `scope=` only when non-empty (http.go:241-250), so the challenge is constant. The only non-403 outcome is 201 for input == the holder's *own* claim tenant, which reveals nothing about other tenants' config (it is the enforcement's pass case, inherent to any gate). The A5 byte-equality pin is the right mechanism and is deterministic (same writer, same header order, no Date header in `httptest.NewRecorder`).
- **Machine flow, claim-state via timing/order:** verified sound. All four causes (scope fail, `binding == nil`, input mismatch, claim mismatch/absent) share one `writeCheckoutChallenge(writer, 403, "insufficient_scope", scopeCheckoutCreate)` call. Absent-claim and mismatched-claim are indistinguishable (both 403; only a 201 on `input == ""` reveals claim==binding for the holder's *own* client). Short-circuit order differences are nanosecond-scale and the scope-first order is unchanged from today — no observable timing class.
- **Cross-flow code distinction:** the user-flow `tenant_mismatch` vs machine-flow `insufficient_scope` difference is itself mandated by the direction (T-8(b) demands `tenant_mismatch`; D4 folds machine drift for oracle-safety), and both codes are constant within their class. The user-flow wire change (missing/unbound tenant: `insufficient_scope`+scope attr → `tenant_mismatch`) creates the intended scope-vs-tenant distinction but adds no tenant-existence signal.
- **One edge the design should state explicitly:** a *claim-less* user token holder can still enumerate bound tenants (bound input → 201, unbound → 403). This is byte-identical to today's behavior (the binding check predates this change) and A5's no-leak pin covers claim-bearing tokens only; §2's "No-oracle" paragraph could be misread as universal. D1 implies it, but it deserves one sentence.

## Q3 — A5/A8 under the two-branch rewrite; `claims.Subject == ""` placement

**Verdict: all no-oracle invariants hold; the Subject placement is safe (and unreachable).**

- Constant code: `ErrTenantMismatch` in model.go's exported wire block (no collision; `shared/core/errors.go:106` already defines the same string in a package the adapter doesn't import — a local const is consistent with the block's style).
- No scope attr: verified `writeCheckoutChallenge`'s `if scope != ""`.
- No tenant value on the wire: body `{"error":"tenant_mismatch"}`, challenge `Bearer realm="stripe-adapter", error="tenant_mismatch"` (constants only; `QuoteAuthParam` on constants).
- No metric/audit delta: verified the full metrics list (writeMetrics, http.go) has no denial counter; `grep -c audit` across all adapter files is zero; the rs layer logs nothing per-claim. The design adds none.
- `claims.Subject == ""` in the scope branch: **provably unreachable** — `authorizeCheckout` 401s subject-less claims at http.go:199-202 before dispatching. Even under a hypothetical dispatch change, both branches are constant-response, so placement cannot leak tenant state in any reachable execution. Keeping it in the scope branch is the right call (preserves "tenant class ⇒ tenant_mismatch" hygiene).
- A8 byte-equality: machine claim denial and input-mismatch denial are the *same call* with the same args — identical by construction, and the new A8 test's byte-compare against the recorded input-mismatch response is the right pin.

## Q4 — F2/F3 re-binding drift

**Verdict: no cross-tenant checkout path is introduced; both drift modes strictly narrow the current surface.**

- **F2 (console re-bind A→B):** post-change, user checkouts are possible only for `input == claim` (IdP-signed B) *and* B adapter-bound; everything else is constant `tenant_mismatch`. Today the same console's users can checkout *any* bound tenant. So the drift moves authorization from A to B but **cannot widen beyond one tenant and cannot reach an unbound tenant**. The "silent switch" is policy/accounting drift (users land in B's billing binding) requiring IdP-side admin action; reconciliation + cold restart is the correct recovery. The F2 row's "input B → pass" is accurate and disclosed ("enforcement follows the IdP").
- **F3 (checkout-client re-bind A→B):** every machine request fails closed (`input B ≠ binding A` fires the input-mismatch branch; `input A` fires the claim-mismatch branch — both the same constant bytes), so **zero checkouts can be created in the interim**. This is exactly the direction's goal, and it holds.
- Residual (disclosed, not a defect): the F2 drift window is bounded by operator detection, not by the adapter — the claim is signed, so the adapter cannot detect the re-bind; the pre-flight (migration step 3) is the mitigation.

## Findings

1. **[Factual error, design text only]** §3.4: "`TestCheckoutRejectsUserIdentityUsingBoundClient` (asserts 403 only; **now tenant_mismatch** — no assertion change)". Traced: sub=`user-one` ≠ client_id=`checkout-client` → user flow; scope=`billing:checkout:create` lacks `admin:write` → the **scope branch fires first** in the proposed code → the response stays `403 insufficient_scope` + `scope="admin:write"`, never `tenant_mismatch` (same as today). Assertion impact: zero (403-only pin), so R4.2's "only these two pins change" survives — but the parenthetical is wrong and should read "stays insufficient_scope".
2. **[Precision]** §4's "(short TTL)" overstates: `defaultTokenTTL` is **1 hour** (issue_payload.go:17-19); the rolling-upgrade machine-denial window is bounded by 1h or per-client `AccessTokenTTL`. The F6/F1 "bounded by token TTL" wording is accurate; "short" is not.
3. **[Classification]** D1 should be explicitly labeled a policy carve-out, not an outage fail-open, so it cannot be read as violating AGENTS.md's fail-open-with-audit list (§8 currently says only that no audit path exists).
4. **[Suggestion, non-blocking]** R2 (user gate) is inert pre-B4-1 and could ship with zero risk ahead of mint; only R3 is breaking. Bundling R2+R3 (migration step 4) is simpler and G5-enforced, but splitting would decouple the breaking risk and give operators a safe intermediate deploy.
5. **[Scope statement]** A5's no-leak guarantee covers claim-bearing tokens only; claim-less holders retain the pre-existing bound→201/unbound→403 enumeration signal. State this explicitly next to the A5 mapping (D1 implies it).
6. **[Phrasing]** A4's "(today 201)" is only true once the fixture gains `tenant-other` in the same change (today's fixture lacks it → today returns 403 via `binding == nil`). The design's R4 ordering handles this coherently; the parenthetical should reference the fixture-updated baseline.
7. **[No violation]** The machine-flow fold into `insufficient_scope` does not breach AGENTS.md's "Tenant mismatch is 403 tenant_mismatch": the adapter's own documented contract already folds cross-tenant machine rejections into `insufficient_scope` (error-codes.md Stripe section prose + the `TestCheckoutMachineRejectsCrossTenantRequest` pin predate this design), the sibling billing direction set the same precedent, and the fold follows the oracle table's collapse principle. The user flow actually adds a literal `tenant_mismatch` compliance point.

## Overall verdict

**The design's tenant-isolation and oracle-safety claims survive adversarial review.** The rollout asymmetry is real, correctly characterized, and consistent with AGENTS.md fail-open/fail-closed discipline (with the classification note in finding 3); the inert-user-gate window is honestly disclosed, campaign-sequenced away, and TTL-bounded — the "hole closed" claim is correctly scoped to post-mint bound consoles; the two-branch rewrite preserves A5/A8 byte-constancy with no timing/order oracle and no wire/metric/audit delta; and F2/F3 strictly narrow the checkout surface with no new cross-tenant path. One factual error (finding 1), two nits (2, 6), and three clarity/classification improvements (3-5) should be folded into the design before implementation; none block the G5 landing.
