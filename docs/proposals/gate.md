I have everything I need. Here is my cross-check.

---

# Gatekeeper cross-check: review findings vs. design

**Artifacts examined:** `docs/auto/interfaces-adapters-direction1-design.md` (388 lines, **zero diff vs. HEAD** — unrevised), `docs/auto/interfaces-adapters-direction1-spec.md`, `interfaces-adapters-direction1-security-review.md`, and the implementer's deliverable. All claims below re-verified against code and echo v4.15.2 / gin module sources.

## Are the review findings resolved or dismissed?

| Finding | Severity | Status in design doc |
|---|---|---|
| **QA F1 / Arch F3** — implementor inventory wrong ("two test fakes") | High | **UNRESOLVED.** Design line 75 still says "plus the two test fakes". Verified: **8** standalone fakes exist (`fakeContext`, `testHandlerContext`, `tmCtx`, `testCtx`, `ssfCtx`, `brandingHandlerCtx`, `rebacTestCtx`, `rcovCtx`). Step 1 fails at `go vet`/`go test` as written. |
| **QA F2 / Arch F6** — acceptance asserts 400; wire is 401 | High | **UNRESOLVED.** Design line 385 still says "wrong-secret replay → 400 `invalid_client`". Verified: `server_token_clientauth.go:160,167` → `StatusUnauthorized`; `rootcov_flow_test.go:371` asserts 401. Spec line 214 also still says 400. |
| **Arch F1** — echo capture recursion (`ResponseWriter()` returns `*echo.Response`) | High | **UNRESOLVED, and live in the worktree.** `echo/adapter.go:90` returns `c.Response()`; `idempotency.go:105` wraps it; `SetResponseWriter` sets `c.Response().Writer = capture` → `Response.Write → capture.Write → Response.Write → …` infinite recursion. No test exercises it (grep: zero), so it ships silently. |
| **Sec F1** — generic cache keyed on raw header, cross-tenant bleed | High | **DISMISSED without fix.** Decision 6: "The generic middleware keeps its simpler raw-key semantics". No principal/tenant scoping added. |
| **Sec F2** — oracle-safe ordering is a doc comment, not a property | High | **DISMISSED.** Failure table still classifies misorder as "Fail closed by position invariant"; nothing enforces it (architect F5 also flags the mislabel). |
| **Sec F3** — `trackingResponseWriter` lacks `Unwrap`/Flusher; SSE dies on StdRouter | High | **UNRESOLVED.** Design never mentions SSE/`Unwrap`/`http.NewResponseController` (grep: zero). Verified `platform/sse/handler.go:72` does `http.NewResponseController(ctx.ResponseWriter()).Flush()` — the new tracking wrapper breaks admin/user streams on StdRouter. |
| **QA F4 / Arch F4** — echo `Flush`/`Hijack` misdescribed | Medium | **UNRESOLVED.** Risk #9 still claims they "reach the original Writer … not the capture". Verified echo `response.go:89-102`: `r.Writer` is read at call time → after swap they hit the capture; `Flush()` **panics**. |
| **Sec F5** — gin facade "loud failure" claim wrong | Medium | **UNRESOLVED.** Risk #1 still claims gin adding a method breaks compilation; embedding `gin.ResponseWriter` compiles silently. |
| **Arch F2** — step-1 `SetResponseWriter` re-wrap silently kills commit path | Medium | **UNRESOLVED.** No sequencing change; dead window from step 1→3 unaddressed. |
| **QA F3** — generic middleware entirely untested; step 3 deletes untested code | Medium | **UNRESOLVED.** No generic-path test plan in design. |
| **QA F5** — no concurrency test for the wire contract | Medium | **UNRESOLVED.** No concurrent-retry case in acceptance mapping. |
| **Sec F4 / F6** — replay regenerates headers; chain-stop drops downstream middleware | Medium | **UNRESOLVED.** Neither addressed. |
| QA F6/F7/F8, Arch F5/F7/F8, Sec F7/F8 | Low/Info | Unresolved (doc-level); the three Highs above already block. |

## Implementation-plan check

**The code-implementer's deliverable is for the wrong design.** `docs/architect-analysis/auto/domains-tokenpolicy-direction3-implementation-plan.md` implements *tenant-dimension token-policy selectors* (`denyTokenScopeCombo`, `BuildTokenPolicyStore`, `subject_roles`). It does not reference `interfaces/adapters`, `HandlerContext` growth, `Abort`/`Written`/`SetResponseWriter`, or idempotency capture anywhere. **No implementation plan exists for interfaces-adapters-direction1**, and none of its review findings are addressed by any deliverable.

## Additional blocking observation

The worktree (uncommitted, post-review mtimes) already contains an implementation of the uncorrected design — `shared/core/router.go` (+84), `interfaces/middleware/idempotency.go` (+220), both adapters — embedding the unfixed bugs: the echo recursion cycle (Arch F1), tracking writer without `Unwrap`/Flusher (Sec F3), and the raw-key generic cache (Sec F1). This contradicts the "design-only revision" convention and would ship all three Highs.

## Verdict

The design was **never revised**: zero diff against HEAD. Every review explicitly conditioned implementation on corrections (QA: "must not proceed … with F1 and F2 uncorrected"; architect Option A mandates F1–F6 fixes in the design commit; security lists 3 Highs). None were applied. The implementer delivered a plan for an unrelated design. Three Highs are live in the uncommitted worktree implementation.

VERDICT: FAIL - (1) design doc unrevised: QA F1/F2, arch F1, sec F1/F2/F3 all still open; (2) echo capture recursion (arch F1) live in worktree code; (3) tracking writer breaks SSE streaming (sec F3); (4) acceptance still asserts 400 where the wire contract is 401 (QA F2); (5) implementer's plan is for domains-tokenpolicy-direction3, not this design — no implementation plan exists for interfaces-adapters-direction1.
