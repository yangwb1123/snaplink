Spec written to `docs/auto/interfaces-middleware-spec.md`. Every citation was verified against the code before writing (line numbers, signatures, alias targets, budget ceilings).

## Summary

**Direction**: formalize the middleware chain as a typed pipeline with named slots. Verified the analysis claims: dual signatures coexist in `middleware.go` (`Recover` is `http.Handler`-shaped, `Auth`/`CORS`/`Logger`/`Tracing`/`Idempotency` are `core.MiddlewareFunc`); ordering invariants are comment-only across `server_routes.go:360-470`, `sso_wiring.go:389-421`, `server_health.go:347-351`; probes bypass the stack via a hand-written `buildProbeMux` (`server_routes.go:475`). Also confirmed binding budgets: `interfaces/middleware` at exactly 10 non-test files, `interfaces/sso` at the 60-file ceiling, `directory_fanout_test.go:34,59`.

### Three improvements (each with name / problem / evidence / proposed behavior / acceptance check)

1. **`middleware.Chain` — named-slot typed pipeline**: fixed slot fields (Recover → Tracing → Metrics → TrustedProxies → RateLimit → Degradation → AcceptVersion → BodyLimit → Compression → CORS → SecurityHeaders → RequestLog → Router) with probes as a structural pre-chain slot; wrong order unrepresentable at compile time. Collapses all seven hand-written assembly functions in `interfaces/sso` into one construction (edits to existing files only).

2. **Single-signature pipeline + one `FromCore` boundary adapter**: standardize on `func(http.Handler) http.Handler`; migrate the in-use `core.MiddlewareFunc` middlewares; delete legacy `Auth`/`CORS` (verified dead server-side — only `aliases.go:43-44` re-exports and tests reference them); `core.MiddlewareFunc` stays for route-level `Router.Use`.

3. **Ordering invariants as executable tests**: four regression tests bound to the chain — forged-XFF rate-limit bucketing, degradation-gate position (rate-limited outside, body-limit short-circuit), probe bypass (byte-identical with/without chain), and the route-level idempotency-after-auth oracle invariant (`idempotency.go:142-153`) — each designed to fail on a deliberate slot swap.

Budget constraints drove key decisions: chain code extends `middleware.go` (or a new `chain/` subpackage) since the directory is at its 10-file ceiling; `interfaces/sso` changes are edits only; the consolidation relieves `server_routes.go`'s line-budget pressure. No changes to `core/router.go`, the capture mechanism, or observability (directions 2–3, out of scope).
