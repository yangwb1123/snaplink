All mechanical checks are complete. Let me compile the final verification summary:

**Independent verification performed** (design §4 template + §5 helper byte-extracted from the committed artifact, rendered with the exact `templateData()` grant case, helper run verbatim):

| Check | Result |
|---|---|
| §4 template parses/renders (text/template), zero backticks | ✓ |
| §5 helper passes on §4 text; marker report matches §6 exactly | ✓ — all 8 markers count=1 at 734/754/854/1076/2001/2911/3053/3087; window 3482 bytes |
| Probes: branch removed, raw req.Scope, note dropped, note reordered, errorBody trace-wrapped, note quotes literal, 2nd issuance, roles dropped, tenant dropped | ✓ — all fail with the exact named assertions §6/§8 claim |
| Red proof: current committed template fails the helper (A1 found 0) | ✓ gate is load-bearing |
| ResolveRoles swap passes (FP-3 documented tolerance) | ✓ |
| All code anchors at HEAD (dispatchCustomGrant@383, seam@132, handle_ciba.go:306-308, tokengrant@38-40, errors.go:170, types_token.go:164/231, issue_payload.go:26, provider.go:38, server_setup.go:271/283, options_saml2_bearer.go absent, generate.go:82, aliases.go:119-120, error-codes.md:298, implementation-gate rows 1-2, 37-line test fn) | ✓ |
| **Status 400→500 regression (prober FN-4 / M2' recommendation)** | ✗ **as-designed helper PASSES it** (probe p5, pass=true) — yet FM-1's detection column claims "or status 500 fails" and §8 asserts the detection column is "otherwise complete" |

All blocking items from the two adversarial reviews (design body, note markers, composite A1, count guard, window-scoping, F7 deferral, two-gates beat, quoted literals, stale-citation review-only declaration, R4 duty) are resolved and mechanically verified. But the prober's FN-4 finding — a confirmed detection gap for a wire-contract regression (taught 400 invalid_scope) — is neither adopted (one-line M2' fix, prober-verified) nor explicitly rejected as a residual (§8's declared-residuals list covers only roles-symbol swap and server seam rename), and the design affirmatively misrepresents the coverage in FM-1/§8, which my independent probe disproves.

VERDICT: FAIL - The prober's FN-4 finding is unresolved and misrepresented: my independent run of the design's own §4/§5 text proves the helper passes a 400→500 status regression while FM-1/§8 falsely claim detection; adopt the verified one-line status-inclusive composite (`http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope)`) or explicitly declare the residual in §8 — everything else (design body, note markers, composite A1, count guard, window-scoping, F7 deferral, red proof, all code anchors and budgets) is resolved and verified.
