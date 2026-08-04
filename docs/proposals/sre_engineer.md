Review complete: `docs/auto/interfaces-ratelimit-sre-review.md`. Every claim was checked against the code this session (read-only; no Go changes, no gates triggered — advisory only, per `ai-dev/prompts/README.md`). All five required output sections are in the file.

## Summary of findings

**Verdict:** the design is operationally sound at its core; no decision is a hard launch blocker — but three items must be resolved in the same change as the implementation.

**High — H-1: fail-open is silent *and* stalled.** Both limiter backends return `(true, 0)` on every error path with no log, no metric, no audit (zero `log.*` calls in `interfaces/ratelimit`), and Redis `Allow` runs on `context.Background()` with no deadline — go-redis defaults (3 retries, 5s dial, 3s read) apply when config is unset, so a dead Redis turns every checkpoint into a multi-second stall on `/token`, `/userinfo`, admin — exactly when a flood is likely. The design's own Decision 8 verification item ("verify fail-open is logged") **cannot pass as written**; `SSOLatencyP95High` is the only indirect signal.

**High — H-2: admin rejections are unobservable.** `checkRateLimit` and the design's tier-2 "direct Allow" never call `recordRejection` (`Metrics: nil` in the admin stores), so the design's headline scenario — admin A floods, B is protected — produces zero rate-limit metric signal. Decision 1's "metrics for free" holds only for /token and /userinfo.

**Medium — M-3:** `SSORateLimitSaturated` alerts on **all 4xx**, not 429s, and nothing alerts on `sso_rate_limit_hits_total`; phase-2 adds three 429 surfaces without adding a signal dimension (suggested: bounded `surface` label).

**Medium — M-4:** phase-2 stores get no `/readyz` wiring and no reload close discipline — a naive Decision 6 hook leaks one `*sql.DB`/pruner-goroutine generation per SIGHUP; the `main_wiring.go:165` comment claiming SQLiteLimiter is a "silent no-op" for `closeIfCloser` is factually wrong (it implements `io.Closer`).

**Medium — M-5:** Decision 7/8's cross-replica claims are wrong for SQLite — deferred BEGIN (decision race), wall-clock-coupled refill (skew ⇒ over/under-admission), no WAL by default; Redis fixed-window is the honest cross-replica contract.

**Notable corrections to other deliverables:** I traced the reload path (`prev` starts nil, closes the *previous* reload generation) — the readyz-wedge scenario feared by the distributed/QA reviews does **not** occur (boot limiters are never closed), and phase-1's leak is bounded to one generation + boot. The real leak risk is phase-2's, since the design leaves closing unspecified.

**Info:** baremetal-ha RUNBOOK has no rate-limit coverage (drills, Redis memory sizing); the OpenResty edge has a 60s JWKS-staleness window after key rotation, no `limit_req`, and 60s permission-cache linger; no committed SLOs anywhere — Decision 9's numbers are design budgets, and `rate_limited` 429s should be excluded from any future availability error budget.

The doc also contains the service/dependency map, a 14-row readiness table (signal → dependency → failure behavior → alert → runbook), five staging drills (D-1 backend outage, D-2 admin NAT-flood saturation, D-3 subject scraper, D-4 bad-rollout SIGHUP, D-5 DR cutover), rollback triggers, eight monitoring gaps, and residual risks — plus a claim-by-claim verification mapping table.
