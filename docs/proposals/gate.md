# Gatekeeper cross-check: review findings vs design

I read the design (all 9 decisions), the five review files, the implementation plan, and the requirements spec, and re-verified the two contested residuals against the plan's task table and risk register.

## Resolved — planned tasks with executable acceptances

| Finding (source) | Resolution |
|---|---|
| Budget ceilings: `options_grants.go` 499, `mesh_authz.go` 499, `server_routes.go` 488, admin files, `build_app.go` 498 (arch F3, tech R1) | Split-first K4 shuffle + governance quota move + C5 shuffle, ordered *before* feature edits; per-task ≤500 acceptance |
| Golden capture for byte-identical admin default (qa #1, arch F6, tech R7) | P0.2, hard dependency of T5; asserts status/headers/body incl. trailing `\n` |
| Reload close discipline + `main_wiring.go:165` comment drift (arch F5, qa #2, db F7, sre M-4 half, M-6) | C4: close replaced phase-2 limiters, close-counting test, comment fixed |
| Setter must swap via `store.Set`, never field pointer (qa #4, arch F8, tech R3) | R3 + concurrent `-race -count=10` tests in T1/T4 |
| Admin e2e sizing: burst not rate (qa #3, arch F7, keying #4, tech R6) | R6/E1: `tier-1 burst ≥ flood + B + 2× margin`, both blocks configured |
| `-run TestE2E` regexp miss (qa #6, tech R15) | E1 names tests `TestE2E_RateLimit*` |
| Grant-limiter migration equivalence table (qa #5, arch F9) | T2 semantics table (negative/0/positive) |
| Design-claim corrections: Decision 7 Memory-centric + "no clock coupling", Decision 8 fail-open "logged" item, mesh rationale, 4 `HandlerContext` implementers, tier-1 conditionality (all reviewers) | P0.1 (G0, parallel) with grep-verifiable checklist; Redis fixed-window named as cross-replica contract; SQLite documented with skew bound and DSN guidance |
| SQLite deferred-BEGIN race / WAL posture / clock coupling (db F1-F3, sre M-5) | Dismissed with reason (R11): pre-existing phase-1 behavior, cross-replica contract is Redis; DSN guidance documented; hardening in deferred backlog. Acceptable per arch Option A and SRE M-5 remediation |
| Silent fail-open + Redis outage stall (db F4/F5, sre H-1, arch F2) | Resolved as decision (R12/R13): fail-open accepted, silence documented, redis timeouts requirement text in E4 |
| Namespace invariant (4 stores), bare-keyspace, public-client residual, shared-IP channel, setup-account sub collision, 429-precedence, `KeyByClientID` UNSAFE warning (keying, arch F12/F13) | E4 contract docs |
| `(0,0)`→off, not deny-all (tech R5) | C1/C2 + unit test |
| Per-surface backend override (arch F14), schema boot gate (db F9), pool serialization (db F10) | Dismissed with reasons (shared dispatch accepted; v2 follow-up; measure at fleet scale) |

## Not resolved, not dismissed — blocking

1. **SRE launch blocker M-4, readiness half.** The SRE names "phase-2 reload close discipline **+ readiness wiring**" as a must-resolve-before-launch item. The plan covers only the close discipline (C4). Zero occurrences of readyz/`AppendRateLimitReadyChecks`/readiness in the design or the 22-task table — phase-2 stores get no `/readyz` signal and the misleading `sqlite-` prefix is not addressed. Neither fixed nor explicitly declined.

2. **SRE High H-2 — admin rejections unobservable.** Design Decision 1 claims "Metrics for free" for all three surfaces, but Decision 5's tier-2 is a direct `Allow` mirroring `checkRateLimit` (`Metrics: nil`) — admin 429s never touch `sso_rate_limit_hits_total`. The plan's E2 acceptance ("metrics counter increments on **each surface's** 429") is unsatisfiable for the admin surface as designed, no task wires Metrics into the admin stores, and no explicit "admin rejects stay unobservable by decision" statement exists anywhere. This is an internal contradiction in the deliverable set, not a dismissed tradeoff.

Everything else in the corpus (protocol, distributed, performance, security, QA, database, SRE findings I-1/I-2/M-3) is either planned with an executable acceptance or dismissed with a documented reason; no gate changes or threshold relaxations are needed anywhere.

VERDICT: FAIL - admin observability (H-2): design claims "metrics for free" for all three surfaces but admin tier-2 direct-Allow bypasses recordRejection, and plan E2's per-surface metric acceptance is unsatisfiable as designed — needs an explicit task (Metrics-wired admin stores / Checkpoint-equivalent recording) or an explicit accept-silence decision; SRE launch blocker M-4 readiness half: phase-2 stores have no /readyz wiring anywhere in the design or plan (only the close-discipline half of M-4 is planned) — needs a readiness task or an explicit exclusion decision before implementation proceeds.
