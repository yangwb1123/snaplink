Product proposal written to `docs/auto/interfaces-middleware-product-review.md`. Doc-only change; no gates required.

## Summary

**Problem, users, outcome.** The request admission pipeline is the product's security boundary, but its 12-slot canonical order is enforced by prose comments across seven hand-written functions in three `interfaces/sso` files; the package mixes two middleware signatures; `Auth`/`CORS` are dead legacy surfaces. Desired outcome: a typed `middleware.Chain` (compile-time order enforcement), one construction site, one signature with a single `FromCore` adapter, four committed invariant tests — with **zero observable behavior change**. Users: sso maintainers, security/observability engineers, SDK consumers (compile-time break), stock-binary operators (no change).

**Key product framing.** All four independent reviews converge on one material flaw (High-1): the design's Tracing-slot relocation breaks `feature_gate_hotreload_test.go`'s byte-identity oracle (gated-off ≡ never-mounted, including *absence* of correlation headers — 9 tests, 17 `X-Request-Id` assertions, verified). The proposal makes D1=Option A (request-ID stays on `Router.Use`; chain Tracing slot hosts OTel only) a **Must**, with the empty-diff of that test file as the strongest regression indicator. The design also under-scoped the blast radius: 16 direct `core.NewContext` call sites in `middleware_extra_test.go` (verified), the `FromCore` propagation gap (F2), and the unimplementable test-(d) negative control.

**Scope.** Must: M0 decision gate → M1 chain subpackage (additive) → M2 collapse (behavior-identical) → M3 signature migration + SDK break → M4 full gates → M5 same-change doc updates (feature-matrix removal note is currently absent; `observability.md` stack diagram is already drifted). Should: inline auth stub for test (d), `FromCore` writer-identity tests, chain contract tests, growth-path corrections. Won't: Option B, "fixing" the per-`Handler()` rateLimitStore reset, probe rate-limiting, any frontend/nested-module/`cmd/` work.

**MVP boundary.** MVP = M0+M1+M2 (typed chain + collapse, zero behavior change, no SDK break — shippable even if D2 stalls). Full release adds M3-M5.

**Seven unresolved decisions** with recommendations: D1 request-ID placement (A), D2 SDK-break approval, D3 Idempotency commit-position semantics, D4 test-(d) stub mechanism, D5 canonical doc copy, D6 spec §2 grep amendment, D7 `FromCore` propagation spec.

No adoption, latency, staffing, or delivery targets were invented; external SDK-consumer counts are marked Unknown.
