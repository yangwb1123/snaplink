# Principal review: `domains/userlifecycle` direction 1 — lifecycle state as an enforced auth gate

Synthesis of five role reviews (architect, security, distributed-systems,
protocol, QA) of `docs/auto/domains-userlifecycle-direction1-design.md`,
against the working tree at `f0b83ce96526799bcd8a71b45055a8798cf59a0a`.
Advisory only; no code was changed by any reviewer, and this review binds no
maintainer or release owner.

**Evidence standard.** Material claims are labeled **Verified** (source- or
command-confirmed at this revision), **Proposed** (design intent), **Missing**
(no evidence). In addition to the five reviews' own verification work
(≈90 source inspections, 30+ commands run, all green), this review
independently spot-checked the load-bearing facts:

| Claim | Status | This review's check |
|---|---|---|
| Line budgets: 493/413/471/491/495/474/431; `interfaces/sso` at exactly 60 non-test files | **Verified** | `wc -l` + `ls \| grep -v _test.go \| wc -l` |
| Five enforcement points (4 `rejectDeactivatedUser` + inline SCIM at `server_oauth.go:221`) | **Verified** | `grep -rn rejectDeactivatedUser` (3 sites + definition + oauth comment; 4th call at `server_oauth.go:221`) |
| `haCoherenceIssues` omits the lifecycle store | **Verified** | `build_stores.go:95-120`: checks oauth/session/JTI/CIBA/identity/MFA/identity-link/pairwise only |
| `wireAudit` early-returns on `audit.enabled:false` → `b.recorder` nil | **Verified** | `build_app_core.go:197-202` |
| Reactions dispatch synchronously on the admin request ctx; `OnAsync` uses bus ctx | **Verified** | `interfaces/admin/lifecycle.go:85-97` (`RecordTransition(ctx.Request().Context(), ...)`), `bus.go` `On`/`invoke`, `OnAsync` doc |
| `DeleteAllForSubject(userID, "")` = every client, all backends | **Verified** | `oauthspi/refresh_token.go:234-242`; in-repo callers use `""`; `revoke_on_archive.go:58-74` instead loops `clients.List()` per-client and aborts the whole leg on a List error |
| `account_locked` drift: doc 423, code 403 | **Verified** | `docs/error-codes.md:139` vs `server_login_auth.go:79,123,152` |
| `context.WithoutCancel` in-repo precedent | **Verified** | `server_backchannel_logout.go:171,217`, `codestore.go:147` |
| Token-exchange chain cap default-off (0 = disabled); fresh TTL per hop; refresh mint fail-open | **Verified** | `docs/config-reference.md:19`; `token_exchange_stages.go:417,457-482`; `token_exchange.go:332-336` |
| `Store.Get` no-record → `DefaultState`, never error | **Verified** | `memory/memory.go:34-41` |
| Three stale "NEVER gates authentication" docs | **Verified** | `options_admin.go:277`, `config-reference.md:695`, `userlifecycle.go` package doc |
| No implementation exists (no predicate/gate/reaction/bus wiring) | **Verified** | grep across non-test Go |

**Gates run for this stage:** no `.go` edits by any role, so no mandatory
gates were triggered. QA additionally ran `go build/vet`, maintainability/
architecture gates, 4-package `-race` + coverage, and 19 refresh E2E tests —
all PASS. `make ci`, `-race` on the full module, config validation, and the
new-feature E2E are implementation-stage acceptances, not design-stage
evidence.

---

## 1. Advisory recommendation

**Conditionally ready — proceed to implementation only after the design
revision absorbs the amendments in §4 (P1–P7) and the owner decisions in §5
are ratified. Evidence confidence: High.**

The design is the smallest viable option for the stated scope (login gate +
refresh gate + transition-time revocation). Every mechanical claim — the five
enforcement points, the frozen budgets and the mandatory 73-line
device-context move, the refresh seam, the bus/wiring mechanics, oracle-safe
collapse shapes, no new error codes/events/options/storage — was verified
independently by multiple reviewers and re-checked here. No Critical
findings. The conditionality is not about unverified facts; it is about
three High findings that are *amendments, not re-architectures* (a
`context.WithoutCancel` call, a `haCoherenceIssues` entry, doc corrections,
a residual-list addition), plus six decisions that need accountable owners.
The design as written contains one factually wrong mitigation claim
(risk-10) and two gaps in its own disclosure list (token-exchange/device
paths) that cannot ship in that form.

---

## 2. Consolidated findings

Deduplicated across the five reviews. Sources cited as [Arch F#] [Sec F#]
[DS F-#] [Proto F-#] [QA F#]. Severity is this review's consolidation;
disagreements are noted.

### Critical

None. No verified exploit, data-loss path, or hard-gate violation exists in
the design (no code yet, and the plan's additions are config-gated).

### High

**H1 — Multi-replica divergence is unguarded and the design's risk-10
mitigation claim is factually wrong.** [Proto F-1 High, DS F-2 High, Sec F2
Medium]
- Evidence (**Verified**): lifecycle store is per-process memory
  (`serverbuildplatform/build_userlifecycle.go` → `memory.New()`); no-record
  reads `DefaultState` = ACTIVE (`memory/memory.go:34`); `haCoherenceIssues`
  (`build_stores.go:95-120`) has no lifecycle entry, so a multi-replica
  topology with `user_lifecycle.enabled` boots clean; the D3 reaction
  publishes nothing on the cluster bus (contrast `KindTenantSuspension` at
  `server_login.go:465`).
- Impact: replica B (or any restarted replica) reads no record and treats a
  suspended user as ACTIVE — login and refresh rotation succeed there
  **indefinitely**, not "until convergence". Design risk-10's claim that
  "the refresh gate narrows the blast radius" holds only for families the
  transition-serving replica already deleted from a *shared* token store;
  families minted on B survive. The design's headline promise ("suspension
  revokes access") is deployment-topology-dependent, silently.
- Required amendments: (1) correct risk-10 and Decision 4 wording in the
  design; (2) add a lifecycle-store check to `haCoherenceIssues` (or refuse
  the config pair at boot) so the limitation is loud, plus a wiring/unit
  regression test; (3) state single-replica enforcement semantics and
  "restart = un-suspension" in `docs/config-reference.md` §User Lifecycle.
  Direction 3 (SQL peer + cross-replica invalidation) stays the tracked fix.
- Severity note: two reviewers rate High, security rates Medium. The facts
  are undisputed; the divergence is inherited from the existing memory-only
  state machine and disclosed (inaccurately) in the design. Consolidated as
  High because it is a silent security-invariant failure in a permitted
  deployment mode — but the fix is cheap loudness, not a redesign.

**H2 — Synchronous reactions run on the admin request context; a client
disconnect truncates revocation mid-flight, and the retry is a 409 trap.**
[DS F-1 High, Sec F3 Medium/Low]
- Evidence (**Verified**): `applyLifecycleTransition` (`interfaces/admin/
  lifecycle.go:85-97`) calls `RecordTransition(ctx.Request().Context(), ...)`
  after `Append` commits and before the 200; the bus dispatches `On`
  reactions synchronously with that ctx (`bus.go` `invoke`); `OnAsync`
  already uses the bus's own ctx. `SUSPENDED → SUSPENDED` is illegal, so the
  natural retry returns `409 lifecycle_state_conflict`; recovery requires a
  `SUSPENDED → ACTIVE → SUSPENDED` double transition that fires
  `OnUserActivated` spuriously.
- Impact: the design's Decision 3.2 headline property ("the admin response
  implies revocation completed") is false under cancellation; state is
  committed with revocation incomplete and no automatic repair.
- Required amendment: run sync reactions on a request-detached context —
  `context.WithoutCancel` (in-repo precedent at
  `server_backchannel_logout.go:171,217`, `codestore.go:147`), applied in
  the bus or in `RecordTransition`. Test: cancel the admin request context
  mid-reaction (blocking `SessionManager.Destroy`) and assert revocation
  still completes and the transition still 200s.

**H3 — Token-exchange and Native-SSO device-secret chains bypass suspension
and are absent from the design's residual list.** [Sec F1 Medium (High in
exchange-enabled deployments), Arch F3 Low, Proto F-5 (names only the
auth-code gap)]
- Evidence (**Verified**): `HandleTokenExchangeGrant` validates the subject
  token statelessly and mints a fresh `AccessTokenTTL` per hop
  (`token_exchange_stages.go:417`), with refresh-token mint fail-open
  (`:457-482`); the chain bound `MaxTokenExchangeChainLifetime` defaults to
  0 = disabled (`config-reference.md:19`) and the grant is live in the
  stock binary (`server_token.go:226`); `HandleDeviceSecretExchange`
  (`server_native_sso.go:77-115`) checks subject/session *match*, never
  session *liveness*. Design Decision 6.6 names only the auth-code gap.
- Impact: a pre-suspension access token or device secret can be re-exchanged
  after SUSPENDED, hop-by-hop, indefinitely (chain cap off), minting fresh
  tokens and refresh families — the suspension promise is chainably
  bypassable on a default build.
- Options (owner decision): (a) gate `HandleTokenExchangeGrant` with the
  same `AllowsAuthentication` predicate collapsing to `invalid_grant` — the
  predicate already lands in the same package for D2, so the marginal cost
  is small; (b) document as residual + decide the chain-cap default. This
  review recommends (a) for exchange and a documented residual for the
  device-secret ladder; minimum bar is (b) with the residual list extended
  and the cap decision made explicitly.

### Medium

**M1 — D1 helper signature does not fit site 4.** [Arch F1, Sec F7]
`rejectLifecycleBlockedUser(ctx, req *login.Request, userID)` cannot serve
`finalizeCallbackSession` (no `req`; needs 401 `callback_failed` +
`recordCallbackFailure`, not 403 `account_locked`), and a second helper in
`server_login_resolve.go` blows the budget (486+30+15=531 > 500). Fix:
parameterize the denial shape or spec an inline ~3-line guard at site 4
(`server_oauth.go` 495 → ~498 fits); pin both variants in
`server_login_auth.go` post-move (~450).

**M2 — Refresh burn-and-kill on lifecycle-store outage/transient error.**
[Arch F2, DS F-5, QA F7] The D2 gate consumes the presented token before
denial; a fail-closed store-error denial followed by a client retry triggers
reuse detection and kills the whole family — correct for suspended users,
self-inflicted lockout for healthy ones. Latent today (memory `Get` never
errors), reachable via SDK embedder stores or a direction-3 SQL peer. Keep
the after-`Consume` placement; document in `config-reference.md` ("do not
retry refresh on `invalid_grant`; outage denials are logged distinctly") and
pin both halves of the choreography in a test.

**M3 — `audit.enabled: false` silently disarms transition revocation.**
[Proto F-3, Sec F4, DS F-8, design risk 7] The bus is an audit sink; a nil
recorder means the D3 reactions never fire (boot warning only). Read gates
still hold; surviving sessions/tokens decay by TTL. Acceptable for direction
1 with the warning + a hard-requirement line in `config-reference.md`;
mixed-fleet (one replica with audit disabled) halves enforcement and should
be documented too. Optional hardening (explicit reaction seam into
`applyLifecycleTransition`/`SweepOnce`) deferred.

**M4 — The per-client revocation loop is weaker than the SPI's
revoke-across-every-client call.** [Proto F-2]
`revokeRefreshTokens` (`revoke_on_archive.go:58-74`) loops `clients.List()`
and calls `DeleteAllForSubject(userID, c.ID)` per client; a `List()` error
kills the refresh leg with **zero** tokens deleted, violating "never less
locked out" in the exact failure mode the legs exist to survive; de-registered
clients' tokens are never deleted; N round-trips instead of 1. Fix: one
`DeleteAllForSubject(ctx, userID, "")` per subject and drop the
`clients core.ClientStore` parameter from both reactions — strengthens
`RevokeAccessOnArchive` too, happy path unchanged. Regression test: failing
`ClientStore` injection must still revoke.

**M5 — `account_locked` 423-vs-403 drift plus an OpenAPI gap the design's
contract list omits.** [Proto F-4; confirmed by all] Code and tests pin 403;
`docs/error-codes.md:139` says 423; `openapi.yaml` never documents
`account_locked` as a `/auth/login` denial and the `/token` `invalid_grant`
descriptions carry no lifecycle cause. Reconcile all three in the same
change (AGENTS.md §5.6). The 423 row may encode earlier product intent —
maintainers must ratify 403 before Milestone 0 locks it.

**M6 — Crash between `Append` and bus dispatch loses the reaction; failures
are logged and forgotten (no replay, no compensation).** [DS F-3, DS F-4]
At-most-once-per-process semantics, currently undisclosed. Acceptable for
direction 1 if documented in `lifecyclereactions/doc.go` and the design's
failure-mode table (whose "best-effort, never fails the transition" row
understates the silence); the proposed idempotent `ListByState(SUSPENDED|
ARCHIVED)` reconcile loop (reseeding pattern already in-repo) is cheap and
recommended before any durable store lands.

**M7 — Sweep-driven `INACTIVE → ARCHIVED` becomes destructive; a forward
clock jump converts a previously side-effect-free transition into fleet-wide
access cutoff.** [DS F-6, Arch F8] Bounded by `MaxPerSweep`; recoverable by
re-login/admin reinstate, but mass and silent. Document the clock assumption
and the destructive consequence next to the `auto_deprovision` config rows;
consider making the archive reaction opt-in; release note (Arch F8).

**M8 — QA test-plan gaps: the D2 "reactivation restores rotation" acceptance
is not E2E-constructible, and three fixtures are unnamed.** [QA F1, QA F2,
QA F9] The gate runs after `Consume` and families hold one live token, so a
denial leaves nothing to rotate E2E; grace-window re-presentation
short-circuits *before* the gate. Fix: unit choreography in a new
`internal/handler/tokengrant/token_refresh_test.go` with a two-token
same-family fake store (denial consumes A, reactivation rotates B).
Fixtures: 3-method failing `userlifecycle.Store` double (shared by `test/`
and `tokengrant`; pins audit meta `lifecycle.state` present-but-empty),
`RefreshGrantDeps` recording double (call-order pin
`[Consume, LifecycleState, deny]` / `[..., Resolve, Velocity, Issue]`),
trusted-device harness for site 3 (none exists today). None block the
design; all fit the planned test surface.

### Low

**L1 — `AllowsAuthentication(StateNone) == true` is unreachable today but is
a latent fail-open in the most security-critical predicate.** [Sec F5, Proto
F-7, Arch F6] A buggy future SQL peer returning a zero-value record would be
allowed exactly when the fail-closed philosophy says deny. Keep the branch
(dead-safe) or make the predicate pure `s == StateActive`; either way, one
documented source of truth + a unit pin.

**L2 — sqlite `DeleteAllForSubject` is two non-transactional statements; a
crash between them leaves orphan family markers and spurious reuse-audit
events.** [DS F-7] Security-neutral; one-line transaction fix.

**L3 — With `audit.async.enabled`, revocation can precede durable audit
evidence; crash after reaction, before flush = revocation with no evidence.**
[DS F-8] Consistent with the async sink's lossy contract; one doc line.

**L4 — Timing oracle on refresh denial (valid-but-denied slower than
unknown).** [Sec F6] Pre-existing class shared with
`refreshCheckSessionLiveness`; document, do not "fix" with dummy reads.

**L5 — Federated-site audit delta: SCIM leg logs only, lifecycle leg records
`callback_failure`.** [QA F3, Arch F7, Proto F-8] Wire-identical, audit-
divergent — deliberate but unpinned. Add the byte-compare + exactly-one-
event test to `handle_callback_test.go`.

**L6 — Rolling deploys: old binaries enforce no gate and no reaction.**
[DS F-9] Wire-compatible (all denial shapes pre-exist); document that
enforcement is meaningful only after the fleet is fully upgraded.

**L7 — Cosmetic: design cites `accessors_token_grant.go` (does not exist;
guard is `accessors_handlers.go:363`), liveness at "~93" (actual 106), and
"every `interfaces/sso` file is 488–500" (413/471/474 exist).** [Proto F-8,
Arch F4/F5] Fix refs; the operative 493-line claim is exact.

---

## 3. Trade-off ledger

| Conflict | Options | Recommendation | Consequence | Owner |
|---|---|---|---|---|
| Fail-closed lifecycle gates vs neighbors' fail-open (SCIM, tenant-suspension) | (a) fail-closed (design); (b) fail-open with audit | Keep (a): suspension is a security invariant; outage = byte-indistinguishable mass 403/400, differentiated only by log line + `login_failure` audit meta | Availability cost is latent today (memory `Get` never errors), real with a durable peer; operators may misdiagnose | Product/release owner ratifies the spec's posture |
| Gate exchange/device-secret paths in direction 1 vs document as residual | (a) gate exchange (predicate already lands in same package); (b) residual + cap decision | (a) for exchange, (b) for device-secret ladder with explicit cap-default decision | Scope grows by ~1 gate + tests; without it, suspension is chainably bypassable on default builds (H3) | Design owner + security |
| Sync reactions on request ctx ("200 implies done") vs detached ctx | (a) `context.WithoutCancel` (precedent); (b) `OnAsync` (gives up the property) | (a): small, precedented, keeps "200 written only after reaction returned" | 3-line change + 1 test; closes H2 and the 409 trap | Architect/implementer |
| Bus-as-audit-sink coupling (`audit.enabled` dependency) vs explicit reaction seam | (a) coupling + loud warning; (b) direct seam into transition handlers | (a) for direction 1; revisit with durable store | `audit.enabled:false` = no revocation, documented; mixed fleets halve enforcement | Design owner |
| Memory-only lifecycle store in multi-replica topologies (scope cut) vs blocking the config pair | (a) keep store + `haCoherenceIssues` entry (loud); (b) refuse boot; (c) SQL peer now | (a), with direction 3 tracked as the fix | Divergence becomes loud and documented instead of silent; enforcement remains per-replica until direction 3 | CTO/roadmap owner |
| Per-client revocation loop vs single `DeleteAllForSubject("")` | (a) single call, drop `clients` param (Proto F-2); (b) keep loop | (a): fewer round-trips, no whole-leg failure, revokes de-registered clients | Touches pre-existing archive reaction; happy path unchanged, strictly stronger | Protocol reviewer/implementer |
| Deny INVITED login now vs future invitation flow | (a) deny (design); (b) allow | (a) is safe today (no production INVITED writer, `transitions.go` seeds only `StateNone → {INVITED, ACTIVE}`); direction-2 "accept invite = first login" must advance state first | Latent coupling; single revisit point (`AllowsAuthentication`) | Product |
| `account_locked` 423 (doc) vs 403 (code/tests) | (a) pin 403; (b) change code to 423 | (a): non-breaking, aligns docs to shipped behavior | Loses the documented 423 if that encoded intent | Maintainers |
| Sweep-driven ARCHIVED fires destructive revocation unconditionally | (a) unconditional (design); (b) opt-in knob | (a) matches archive semantics; document clock assumption + blast radius (M7) | Forward clock jump = mass fleet-wide cutoff, bounded by `MaxPerSweep` | Product/ops |
| At-most-once bus vs idempotent reconcile loop | (a) document only; (b) `ListByState` reconcile loop | (b) recommended before any durable store; (a) acceptable for direction 1 | Crash window (M6) stays manual (409 trap + TTL) without it | DS engineer/design owner |

**Accepted-risk note (no owner change requested):** the login↔reaction
TOCTOU (design risk 5) is accepted by all five reviews — same class as the
existing SCIM race; the MFA-second-leg and login-transaction re-checks shrink
but cannot eliminate it. On multi-replica it widens from "until TTL" to
"until convergence" (H1).

---

## 4. Preconditions, acceptance checks, rollback, monitoring, exclusions

### Preconditions before implementation (design revision, same change)

1. **P1 — Design absorbs the amendments**: corrected risk-10 and Decision 4
   wording (H1); residual list extended with token-exchange/device-secret
   (H3) and the F1 decision; site-4 helper shape pinned (M1);
   `config-reference.md` failure-mode paragraphs: fail-closed self-lockout,
   refresh burn-and-kill + "do not retry on `invalid_grant`", single-replica
   semantics + restart = un-suspension, `audit.enabled` hard requirement,
   destructive sweep + clock assumption, unsupported topologies (DS §4 list).
2. **P2 — H2 fix**: `context.WithoutCancel` for sync reactions (bus or
   `RecordTransition`) + ctx-cancel regression test.
3. **P3 — H1 loudness**: `haCoherenceIssues` entry for the lifecycle store
   (or boot refusal of multi-replica + `user_lifecycle.enabled`) + wiring
   test.
4. **P4 — M4 leg change**: single `DeleteAllForSubject(userID, "")`,
   `clients` param dropped from both reactions.
5. **P5 — Contracts in the same change (AGENTS.md §5.6)**: the three "NEVER
   gates" docs, `docs/error-codes.md` 423→403, `openapi.yaml` (`/auth/login`
   403 lists `account_locked`; `/token` refresh `invalid_grant` lifecycle
   cause), `config-reference.md` per P1. Acceptance: `grep -rn "NEVER gates"
   .` empty; error-codes row = 403; openapi regenerated/validated.
6. **P6 — QA fixtures and test-plan amendments (M8)**: failing `Store`
   double, `token_refresh_test.go` unit (two-token family, call-order pin,
   byte-compare), trusted-device harness, bus-aware `test/` builder,
   `-count=10` idempotency, outcome-set `-race` concurrency test.
7. **P7 — Ratifications**: fail-closed posture (product), exchange decision
   (design+security), INVITED semantics (product), 423-vs-403 intent
   (maintainers), restore-from-archive UX (product), direction-3 commitment
   (CTO/roadmap).

### Executable acceptance checks (per milestone)

- **D1**: `go build ./... && go vet ./...`; `go test -run
  'TestMaintainability_|TestArchitecture_' .`; `wc -l` ≤ 500 on both touched
  files; six-state table; byte-compare vs SCIM at sites 1–3 and vs
  callback-failure at site 4; store-error injection → deny with
  `lifecycle.state` present-but-empty audit meta; nil-store byte-identical;
  gate precedes `RegisterSuccess` and any session/token mint.
- **D2**: `-race`; denied body byte-identical to unknown-token; no
  `RecordRotation` before denial (call-order pin); family unchanged with no
  bus wired and no retry; second presentation kills the family; store-error
  → fail-closed deny; nil-store/no-record byte-identical; reactivation via
  two-token unit choreography; D2 verified independently of D3.
- **D3**: transition → session cookie 401, `RefreshTokenSubjectIndex` empty,
  refresh → `invalid_grant`; idempotent second run (`-count=10`);
  one-store-error isolation (`errors.Join`); ctx-cancel completion (P2);
  `audit.enabled:false` boot warning; `len(b.opts)` assertions unchanged;
  `DeleteAllForSubject("")` single-call assertion (P4); `haCoherenceIssues`
  unit (P3).
- **Full handoff**: `go test ./... -race`; `go test ./test/ -run TestE2E -v`;
  `make ci` (incl. doc/config drift checkers and nested modules).

### Rollback triggers

- The feature is config-gated (`user_lifecycle.enabled`, default false) and
  adds no new wire codes/endpoints/options — rollback is re-disable + deploy;
  no data migration (memory store only).
- Triggers: mass 403/400 with empty `lifecycle.state` meta (fail-closed
  outage signature); family-kill complaints during store errors; sweep-driven
  mass ARCHIVED; 409 traps after admin disconnects; audit-disabled builds
  where operators expect revocation.
- Mixed-version fleets are wire-safe but enforcement-versioned (L6): complete
  the rollout before relying on gates.

### Monitoring

- Fail-closed log lines (`lifecycle gate lookup failed`, refresh-denial log)
  and the `login_failure` audit stream with `lifecycle.state` meta — the only
  outage-vs-suspension differentiators; alert on volume.
- Reaction-error handler logs (D3); boot warning for `audit.enabled:false` +
  lifecycle enabled; `haCoherenceIssues` boot message after P3; healthy-user
  rotation/velocity metrics unchanged (regression pin).

### Explicit exclusions (all reviews agree; record in the contract update)

- Access-token revocation on suspension (no enumeration SPI; introspection/
  CAEP is the lever).
- Auth-code exchange residual (short TTL, single-use; per-subject index is
  the follow-up).
- Device-secret/CIBA/bearer-grant paths (per the H3 decision).
- PURGED-state reactions (direction 2 Eraser); chain-store reaction leg
  (nothing wired in the composition root); blocking logins during transitions
  (TOCTOU hard fix); SSF/CAEP-fed suspension triggers; SQL lifecycle store +
  cross-replica invalidation (direction 3).

### Residual risks (accepted, must be stated in the contract)

- TOCTOU login↔reaction (widened to "until convergence" on multi-replica);
  restart = un-suspension (memory backend); at-most-once bus (crash window);
  `audit.enabled:false` → no revocation; fail-closed self-lockout (latent
  today); INVITED/future-invitation coupling; grace-window family-kill
  choreography; timing oracle (pre-existing class).

---

## 5. Missing reviews/evidence and next actions

**Not evidence gaps for this stage** (design-only, no `.go` edits): the
mandatory per-edit gates, `make ci`, config validation, and new-feature E2E
are implementation acceptances, already enumerated in §4.

**Genuinely missing or thin**:
1. **Owner decisions are the binding unknowns** — six from the architect
   review (exchange parity, fail-closed ratification, INVITED semantics,
   multi-replica convergence/direction-3 commitment, restore-from-archive
   UX, 423-vs-403 intent) plus the H3 decision and the H2/H1 amendment
   sign-off. None have sign-offs anywhere in the tree. Do not start Milestone
   0 before these are recorded (they change the contract text).
2. **No SRE/runbook review**: monitoring/alerting guidance exists at design
   level only; fold the §4 monitoring rows into `config-reference.md` and
   let the ops reviewer see the implementation diff.
3. **No performance review**: D1 adds up to one memory-map read per login leg
   (worst case three reads on a full ceremony), D2 one per refresh — the
   marginal cost is negligible against existing store reads, and no reviewer
   contested this, but no formal estimate exists.
4. **No compliance review**: DS F-8 notes SOC-2-relevant audit-evidence
   ordering under `audit.async`; out of scope for direction 1, flagged for
   the durable-store follow-up.

**Narrow next actions**:
1. Design owner revises the design per P1–P4 (one doc revision; largest
   change is a ~10-line `haCoherenceIssues` entry + wording corrections).
2. Owners record the §3 decisions (one ratification memo; no code).
3. QA lead locks P6 fixtures into the test plan (they are additive to
   Decision 7).
4. Then implement per the arch review's milestones (contracts → D1 → D2 →
   D3 → full gates), with the mandatory gates after every edit.

*No sign-offs, deadlines, or approval statuses are asserted anywhere in this
review; the owner assignments above are this review's recommendation, not
evidence of acceptance.*
