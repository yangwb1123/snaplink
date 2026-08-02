Spec written to `docs/auto/interfaces-cors-observability-spec.md` (docs-only change, no Go edits so no build gates needed). Three evidence-backed decisions for direction 三:

**Shared mechanism (prerequisite):** `cors.Middleware` gains a variadic `BlockObserver` option, wired by sso at `server_routes.go:452` — the reject branch in `cors.go` currently forwards silently with zero signal, and CORS sits innermost so the observer covers every path, not just `/auth/login`.

**## 1. `sso_cors_blocked_total` counter** — the middleware reject branch has no counters (`cors.go` `Middleware()` silent `next.ServeHTTP`); `metrics.Middleware` only labels `method, status_class`, so blocked origins are indistinguishable from normal traffic. Proposes a `reason`+`preflight` labeled CounterVec registered beside the `CIBAPingTotal` precedent (`metrics_ctor.go:316`), explicitly rejecting the analysis's raw `{origin,path}` labels to honor the bounded-cardinality invariant (`observability.md:7`, `sanitizeMethod` precedent).

**## 2. `cors_origin_blocked` audit event** — `server_login.go:174`'s `logger.Info("origin_blocked")` is the tree's only signal: log-only, login-path-only, no trace/audit correlation. Proposes a `RecordCORSOriginBlocked` event mirroring `RecordCIBAPingFailed` (`recorder_events.go:139`), classification in `auditreport` (drift test at `:41`), and removal of the login gate's duplicate log so the invariant is exactly one event per rejected request.

**## 3. Contract + E2E coverage** — `observability.md:100` documents CORS in the chain but no rejection telemetry, and no `test/` case exercises the boundary with the login CSRF gate. Proposes the docs rows plus a `ssotest` E2E case proving no double-count across enforcement points and that `PathOverrides`-allowed origins stay uncounted.

Each decision carries evidence with exact file/symbol citations and a concrete acceptance check; non-goals keep scope tight (no allow/deny semantics, no new Err*/endpoints, no cardinality drift).
