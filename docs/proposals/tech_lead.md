Plan written to `docs/auto/interfaces-ratelimit-implementation-plan.md`. Summary:

## What the plan delivers

**22 tasks across 6 phases**, every one mapped to concrete files, symbols, dependencies, relative size, owner skill, and an executable acceptance check. Two planning inputs beyond the design+reviews: I re-derived the line-count/budget arithmetic from the tree this session, and it changes the sequencing.

## Key findings that shape the plan

1. **Budget ceilings bite before feature work** (the design's placements would fail the gate):
   - `options_grants.go` (499), `sso_protocol.go` (499), `server_routes.go` (488) have 1-12 lines of headroom. The design's "option in options_grants.go, setters beside SetRateLimitPolicy" does **not** fit.
   - `interfaces/admin` is at its 10-file ceiling, with `governance.go:483`/`middleware.go:492` — no new files, no room.
   - `cmd/sso-server/build_app.go:498` — the per_admin wiring overflows by ~10.
   - **Task K4** (relocate `WithClientRegistrationRateLimit` → `quota.go` where its consumer lives; consolidate all rate-limit state into `wiringState`) plus a quota-block move in T5 and a shuffle in C5 are hard pre-requisites, ordered *before* the feature edits.

2. **P0.2 golden test is a hard dependency of the admin work** — nothing pins `rate_limit_exceeded` today; the byte-identical-default acceptance is unverifiable without capturing the current wire (status/headers/body incl. trailing `\n`) from HEAD first. The graph enforces P0.2 → T5.

3. **Critical path**: `K1 → T1 → C3 → C4 → E1 → E4 → gates`, converging with `P0.2 → T5 → C5 → E1`. Four parallel groups identified (kernel/context/config, three surfaces, wiring, e2e/docs).

4. **15-item risk register** with triggers and fallbacks, including the ones the reviews surfaced as design-omissions: pruner/`*sql.DB` leak per SIGHUP (R4), `(0,0)`-config-maps-to-deny-all hazard (R5, not in any review), `store.Set`-never-field-pointer rule (R3), SQLite deferred-BEGIN race + wall-clock coupling as a *documented* storage contract with a deferred backlog (R11), Redis outage latency on the auth path (R12), and the burst-not-rate e2e sizing formula (R6).

5. **Deferred (verified, not backlog-padded)**: SQLite `_txlock=immediate`/`SharedDB` hardening, fail-open observability, admin tier-1 global-cap — each explicitly non-goaled or documented in this change.

Milestones M1-M4 each close on verifiable deliverables, and the final gate/rollout checklist covers the handoff commands, contract-docs-in-same-change obligation, rolling-SIGHUP mixed-window caveat, and the restart-required rollback semantics. No Go code was touched; no gates were triggered.
