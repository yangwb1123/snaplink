# Principal Review: `domains/tokenexchange` direction 1 (ChainStore → revocation control plane)

Role: principal reviewer synthesizing the three supplied reviews (protocol,
distributed-systems, security), the design, the spec, and my own source
verification. Advisory only; does not bind maintainers or release owners.

Checks that ran for THIS review revision: full reads of
`protocols/oauth/handle_revoke.go`, `protocols/oauth/handle_introspect.go`,
`protocols/oauth/introspect_cache.go`, `domains/tokenexchange/chainstore.go`
(excerpts), plus `wc -l` on all budgeted files and `rg` for the disputed
symbols. No build/test execution (the feature is unimplemented). Labels:
**Verified** = I read the code; **Consensus** = ≥2 supplied reviews agree,
source-checked by me or them; **Single-source** = one review's claim.

## 0. Advisory recommendation

**Conditionally ready** (design phase — nothing is implemented).

The keystone (jti-keyed deny seam), the extension-interface approach, the
subject/actor pin, and the fail-closed discipline are sound and
source-verified. But the design cannot go to implementation as written:
it contains one **false factual claim** (200-before-cascade), one
**undecided High-severity security question** (cascade blast radius), one
**consensus High defect** (silent session-cap truncation), and one
**infeasible placement fallback** (compile-enforced budget). All are
fixable in the design document before any `.go` edit.

Blocking preconditions (must be pinned in the design before step 1 of the
implementation order): B1 (blast radius), B2 (`HopsBySession` truncation
signal), B3 (correct the 200-ordering claim + document the timing
residual), B4 (expire-closure placement split), B5 (pre-v2 row policy +
introspection/bus-exp residual declarations). See §3.

Evidence confidence: **High** for every disputed fact (I re-verified each
against source); **Medium** for severity judgments, which are advisory
classifications, not measured impact.

## 1. Consolidated findings

### Critical

None. No review found a verified exploit or data-loss path; the feature is
unimplemented and the strongest finding (C1) is a design decision left
undecided, not a shipped defect.

### High

**H1 — Cascade blast radius is undecided; `/token/revoke` becomes a
cross-tenant, cross-client destruction primitive.** [Single-source:
security F1, but source-verified by me]
- Evidence: `HandleRevoke` authenticates the client but never binds the
  presented token to it (`handle_revoke.go`); `revokeAccess` receives only
  `(d, ctx, token)`. Cross-tenant exchange is a live feature
  (`tokExEnforceTenantCollaboration`, `token_exchange.go:427`), and
  `ChainHop.ClientID` is recorded (`chainstore.go:49-50`), so scoping is
  feasible. The design's Decision 5 cascades to ≤1000 descendants with no
  ClientID/tenant filter, and the jti deny key has no tenant dimension.
- Impact: any registered client holding one valid token string can kill
  other clients'/tenants' descendant tokens (≤1000) until TTL.
- Recommendation: pin the scope — (a) recommended: filter the cascade to
  hops whose `ClientID` equals the authenticating client (plumb `req.ClientID`
  into the cascade; note the security review's parenthetical "`revokeAccess`
  has `req.ClientID` in scope" is imprecise — `revokeAccess` takes no `req`;
  `HandleRevoke` does — plumbing is required); (b) if cross-tenant cascade
  is intended, document it in OpenAPI + endpoint contract and emit an
  explicit audit signal per cross-tenant kill. The admin endpoint remains
  the trusted break-glass either way.
- Executable check: integration test — tenant-A client revokes a root whose
  descendant was minted for a tenant-B client; assert survival (option a)
  or audited kill (option b).
- Owner: **security + maintainers** (blast-radius posture is a security
  decision).

**H2 — `HopsBySession` silently truncates the session cascade: the exact
silent-partial-revocation class Decision 1 forbids, reintroduced at the
session boundary.** [Consensus: protocol F1 (High), DS F-1 (High), security
F3 (Medium)]
- Evidence: Decision 3 pins sqlite `HopsBySession` as `LIMIT ?` with "no
  truncation hazard"; its only consumer (Decision 6 session cascade) expires
  each returned hop. A session (or human cohort via `RevokeAllForHuman`)
  with >1000 recorded mints — breadth is unbounded; `MaxActChainDepth` caps
  depth, not children per node — silently leaves the oldest mints (and
  their derived subtrees) alive while `auditRevokeCohort` reports success.
- Recommendation: return `(hops, truncated bool, err)` (fetch `LIMIT+1`),
  treat `truncated` as `ErrChainWalkTruncated`, flip the audit outcome to
  failure with the partial list — mirroring Decision 1's own discipline.
- Executable check: seed 1001 hops on one session; `RevokeAllForHuman`
  must error/flag truncation, audit failure, and report the remainder.
- Owner: **maintainers** (contract addition to the new optional interface;
  zero existing callers).

### Medium

**M1 — The design's oracle-safety rationale is factually false: the cascade
runs in-band before the 200, widening the existing `/token/revoke` timing
channel.** [Consensus: protocol F6, DS F-6 (Low), security F2 (Medium)]
- Verified: `HandleRevoke` writes `ctx.JSON(200)` after `revokeAccess`
  returns (`handle_revoke.go:100-117`); the design's "200-empty-body
  response is written by the existing path before/independent of the
  cascade; the cascade runs on a side channel" is **False**. The wire-body
  contract (200 always, empty, gated on `len(revoked) > 0`) is preserved;
  the *timing* claim is not.
- Impact: a valid root with a large subtree costs ~1000 point queries +
  marks + persists + publishes before the 200 vs. fast-fail for unknown
  tokens — a widened validity/lineage oracle with a valid-credentials
  precondition and the token destroyed in the probe. Bounded: the endpoint
  already leaks validity timing via per-issuer `Validate` and
  `RevokeAcrossIssuers`.
- Severity resolution: Medium (design-correctness fix required; security
  impact bounded). DS's Low and security's Medium differ on whether the
  widened delta is a *new* class — it is not (same channel, larger
  magnitude), but the false claim must be corrected regardless.
- Recommendation: (1) correct the design text; (2) document the residual in
  the endpoint contract; (3) optional time/count budget; (4) do NOT move
  the cascade to a post-response goroutine (request-context lifetime,
  audit correlation, shutdown semantics — DS F-6's reasoning stands).
- Executable check: instrumented test asserting the unknown/opaque-token
  path performs **zero** chain-store reads.
- Owner: **maintainers**.

**M2 — Pre-v2 hops permanently poison the admin cascade; pre-v2 roots can
never be denied.** [Consensus: protocol F5, DS F-3, security F5]
- Verified premise: `ExpiresAt == 0` pins `ErrHopMissingExpiry` abort;
  rows are append-only; the admin holds only a jti, so the per-token path
  is unreachable for the root. The abort itself is correct (never
  deny-for-zero); the *permanence* is the gap.
- Recommendation: adopt the minimal refinement — the walk/orchestrator
  skips hops provably expired (`ExpiresAt` in the past; `Validate` rejects
  on `exp` regardless, so no security regression) and aborts only on
  unprovable zeros; optionally backfill `expires_at = recorded_at + max
  TTL` at migration v2; at minimum document the permanent-500 consequence
  in the endpoint contract and migration notes.
- Executable check: migration test from a v1-schema DB with a recorded
  root asserting the chosen behavior (fallback-TTL denial or documented 500
  + failure audit).
- Owner: **maintainers / ops** (upgrade-runbook consequence).

**M3 — The expire-closure placement fallback is infeasible: the stated
fallback home has 17 lines of headroom.** [Single-source: security F4;
verified by me]
- Verified: `accessors_threat.go` 427/500 (73 headroom), fallback
  `server_token_clientauth.go` 483/500 (17), `accessors_feature_gates.go`
  498 (2), `sso.go` 499 (1), `server_routes.go` 488 (12). The ~75+ line
  surface (2 mounts, 2 wrappers, 1 accessor, ~35-line closure) exceeds the
  primary home and far exceeds the fallback.
- Recommendation: split before writing — bus-publish leg into
  `server_extensions.go` (461/500, 39), durable-persist leg next to the
  issuer wiring, assembly + mounts + accessor in `accessors_threat.go`;
  `wc -l` before each edit (AGENTS.md §5).
- Executable check: `make ci` maintainability gate.
- Owner: **implementer + maintainability gate** (compile-enforced).

**M4 — The jti bus event's `exp` is trusted as-is; the token arm's
re-derivation safety net does not transfer.** [Single-source: DS F-2]
- Evidence: `ApplyTokenRevocation` re-derives `exp` from the token;
  `KindTokenRevokedJTI`'s `MetaRevokedExp` is the whole message, and a
  zero/absent value is pruned immediately on the peer (`revocation_set.go`
  prune discipline) — silent peer-side non-denial while the origin believes
  the jti is denied everywhere.
- Recommendation: pin receiver-side validation — reject `exp <= now`,
  clamp to a conservative floor (e.g. `DefaultJTIReplayWindow` or issuer
  TTL), never store 0. Over-denial is the accepted safe direction (jti
  collision posture, Decision 10).
- Executable check: bus-adoption test with absent/zero `MetaRevokedExp` →
  entry survives (clamped), not pruned.
- Owner: **maintainers**.

**M5 — Introspection-cache staleness for jti-killed tokens is unaddressed.**
[Single-source: protocol F2; verified by me — resolves the apparent
conflict with DS's S1c row]
- Verified: `handle_introspect.go:95-97` returns a cached body on a cache
  hit **before** `Validate`; the cache contract documents revoke-to-TTL
  staleness as intentional, narrowed by point-eviction keyed on the token
  string (`InvalidateIntrospectionCache`). A jti kill has no token string
  (D2 rejects the jti→token index), so no eviction is possible — stale
  `active:true` up to TTL on every replica, including the marking one, for
  tokens introspected before the kill. DS's S1c row ("introspection funnels
  through `Validate`") holds only for cache misses.
- Recommendation: declare the residual in the endpoint contract +
  OpenAPI description; note jti-keyed cache invalidation as an explicit
  non-goal (requires the rejected index). A regression test asserting the
  documented-behavior staleness, not a fix.
- Owner: **maintainers** (documentation).

**M6 — Dropped-event staleness with no periodic reconciliation; the
cascade multiplies a stale replica's blast radius.** [Single-source: DS F-5;
parity-accepted]
- Re-seed exists only at boot and bus-recovery; no periodic loop; a
  silently-dropped `KindTokenRevokedJTI` leaves peers honoring the jti
  until the token's own `exp`. Parity with the token set is explicit design
  intent (Decision 8).
- Recommendation: either add a low-frequency periodic
  `SeedJTIRevocations` loop (idempotent, cheap) or state the
  no-periodic-reconciliation guarantee explicitly. Document.
- Owner: **maintainers**.

**M7 — The cascade is not linearizable against the mint path: a concurrent
exchange escapes, silently.** [Consensus: security F6 (Low/Med), DS F-4
(Medium)]
- Evidence: the sqlite walk is non-transactional point queries; `RecordHop`
  commits fail-open after the exchange response is decided; a hop recorded
  mid-walk is neither marked nor reported.
- Recommendation: do not add locks to the mint path (must never block on
  the control plane). State point-in-time semantics in the contract and
  audit `walked_at`; optionally one bounded re-walk after marking; assert
  the documented outcome in acceptance (`-race -count=10+` concurrent mint).
- Owner: **maintainers**.

### Low

**L1 — OpenAPI `subject_token_type` enum drift (pre-existing).** [Single-
source: protocol F4] `docs/openapi.yaml:12490` advertises
`refresh_token` (no code path) for ordinary exchange; `txn-token` is valid
only via the RFC 9321 dispatcher. Fix in the same change that adds the two
admin routes to OpenAPI (AGENTS.md §5).

**L2 — Design rationale inverted for path-const placement; `chainstore.go`
line count wrong.** [Consensus: protocol F5/F7, DS F-8; verified] `consts.go`
is 466/500 (34 headroom), not "at budget"; `consts_wire.go` is 490/500 (10)
— the *tighter* file; `chainstore.go` is 155 lines, not ~250. Placement
still fits; correct the stated reason.

**L3 — New admin cascade revoke bypasses the destructive-confirm governance
its sibling bulk-revoke has.** [Single-source: security F7] The `X-Confirm`
gate is path-list-driven (`DestructiveSet`); `HandleBulkRevoke` enforces
soft-cap-100/hard-cap-10000. Document the new POST in destructive-actions
guidance + OpenAPI; optionally mirror the soft cap.

**L4 — Mixed-version peers + the local-event-type precedent.** [Single-
source: security F8] Old replicas drop `KindTokenRevokedJTI` at the default
arm (acceptable parity; state in rollout notes); do NOT imitate
`eventAdminTokensBulkRevoked` (`token_portfolio.go:38`), which bypasses the
`auditreport` gate — keep the new types in `auditspi` + CC6.1, and keep the
`/token/revoke` cascade-failure event non-admin-typed (a client-credentialed
actor must not emit `EventAdmin*`).

**L5 — Repeated `/token/revoke` of a revoked token audits `failed`
(pre-existing quirk).** [Single-source: DS F-7] Cascade gate (`len(revoked)
== 0`) correctly yields no second cascade; no action, note for
implementers.

**L6 — Clock-jump can prune denies early (inherited from the token set).**
[Single-source: DS K2] No new clock dependency; document as residual.

**L7 — Discovery does not advertise the `delegation_token` grant (optional).**
[Single-source: protocol F8] RFC 8414 §2 makes `grant_types_supported`
optional — a completeness gap, not a violation; also update the
`ChainHop.SubjectID` doc ("the subject_token's Subject") since delegation
mints will record hops.

### Info

- jti deny check is proposed after signature verification — DoS-neutral
  (token-string check stays early); optional optimization: check before
  verify (security review).
- Admin descendants GET exposes cross-tenant topology — admin-only, in line
  with the trusted boundary.
- Hops are never pruned — pre-existing unbounded-growth property; the new
  deny maps are exp-bounded, so the cascade side stays bounded.

### Positive controls worth preserving (Consensus, all source-verified)

- Keystone soundness: a jti-keyed deny seam is genuinely required; the
  `JTIReplayStore` rejection is correct on both axes (fail-open direction;
  JAR/PAR/DPoP/tokex-act replay namespace conflation).
- Decision 6's subject/actor pin follows the minted token's own claims
  (`sub=agent`, `act=human`; `grant.go:182-205`) — the spec's "subject =
  human, actor = agent" would mislabel every agent token; implementers must
  follow the pin, not the spec prose.
- Optional-capability idiom (`ChainRevoker`, `chainRevokeCapability`,
  `chainStoreProvider`) preserves every test fake and the
  `ChainStore`/`RevokeDeps`/`Deps` contracts.
- Fail-closed discipline: `ErrChainWalkTruncated`, `ErrHopMissingExpiry`,
  partial-list surfacing in body + audit, abort-on-first-error.
- Unclaimed positive (security review): denied descendants are also blocked
  from re-exchange, because subject-token validation funnels through issuer
  `Validate` — the design should claim it.
- Oracle body-safety: 200-always byte-identical, gated on `len(revoked) > 0`;
  admin 404/501/500 are explicit, audited states, not OAuth oracle surfaces.
- Cross-replica parity: `KindTokenRevokedJTI` + local-only adoption +
  boot/recovery re-seed + degraded readiness mirror the token path; ordering
  (subscribe → re-seed → clear degraded) verified.

## 2. Deduplication note

Of the 23 unique findings across the three reviews: H2 (session truncation),
M1 (200-ordering/timing), M2 (pre-v2 rows), M7 (revoke-during-mint) were
independently found by ≥2 reviewers; the rest are single-source. The
protocol F2 (introspection staleness) and DS S1c (introspection rides
`Validate`) appear to conflict but are complementary: cache-hit vs
cache-miss paths (verified). Security F1's parenthetical about `req.ClientID`
scope is imprecise but does not weaken the finding.

## 3. Trade-off ledger

| Conflict | Options | Recommendation | Consequence | Owner |
|---|---|---|---|---|
| `/token/revoke` cascade blast radius (H1) | (a) scope to presenting client's `ClientID`; (b) cross-tenant kills intended, explicit audit; (c) undecided | (a) — admin endpoint stays the cross-tenant break-glass; RFC 7009 §2.1 SHOULD scope | Cross-tenant descendants survive client-initiated revokes until TTL; requires plumbed `clientID` | **Security + maintainers** |
| Session-cap truncation (H2) | (a) truncated flag → `ErrChainWalkTruncated` + failure audit; (b) silent cap, documented; (c) unbounded | (a) | >1000-hop session cascade fails closed with partial list; audit outcome flips | **Maintainers** |
| Pre-v2 rows (M2) | (a) abort + document permanence (design pin); (b) skip provably-expired + abort unprovable; (c) migration backfill | (b), plus (c) as optional; document either way | Legacy roots revocable or explicitly 500; no deny-for-zero regression | **Maintainers / ops** |
| Timing channel (M1) | (a) correct text + document residual; (b) time/count budget; (c) off-request-path worker | (a) + optional (b); reject (c) | Known residual delta on an authenticated endpoint; oracle suite + no-reads test hold | **Maintainers** (security input) |
| In-band cascade cost (protocol F3, overlaps M1) | (a) walk cap with audible truncation, 200 preserved; (b) async durable/bus legs; (c) as-is | (a) — never silent downgrade (H2 discipline) | Bounded latency on `/token/revoke`; admin path unaffected (admin-gated, low volume) | **Maintainers** |
| Expire-closure placement (M3) | (a) split across `server_extensions.go` + `accessors_threat.go`; (b) squeeze 17-line fallback; (c) new file | (a) | Compile-enforced gate satisfied; mid-change scramble avoided | **Implementer** (+ gate) |
| Introspection staleness (M5) | (a) declare non-goal + document; (b) jti→token index (rejected D2); (c) cache flush by jti | (a) | Documented `active:true`-up-to-TTL window for jti-killed tokens; cache contract already sanctions TTL staleness | **Maintainers** |
| Bus `exp` trust (M4) | (a) receiver clamp/floor; (b) trust as-is; (c) drop event on bad exp | (a) | Over-denial is the safe direction; peers converge | **Maintainers** |
| Periodic re-seed (M6) | (a) add low-frequency loop; (b) document no-reconciliation | (b) minimum; (a) preferred | Stale-replica window = token TTL worst case; parity with token set | **Maintainers** |
| Revoke-during-mint (M7) | (a) document point-in-time + `walked_at`; (b) bounded re-walk; (c) lock mint path | (a) + optional (b); reject (c) | Escaped mints are TTL-backstopped and audited, never silent | **Maintainers** |

Decisions requiring maintainers/CTO/security authority (not implementer
discretion): H1 blast radius (security + maintainers); M2 pre-v2 upgrade
policy (ops/runbook); the acceptance of the M1 timing residual (security
input). Nothing in this review fabricates a sign-off; the feature has no
release owner or deadline and none is assumed.

## 4. Preconditions, acceptance, rollback, monitoring, exclusions

### Preconditions (design-doc amendments before implementation step 1)

1. **B1**: blast radius pinned (H1, option a or b with audit).
2. **B2**: `HopsBySession` truncation signal (H2).
3. **B3**: correct the 200-ordering claim; document the timing residual and
   the introspection-cache window (M1, M5).
4. **B4**: expire-closure placement split pre-planned with `wc -l`
   verification (M3).
5. **B5**: pre-v2 row policy (skip-expired + abort-unprovable, or documented
   permanence) and bus `exp` clamping pinned (M2, M4).

### Executable acceptance checks (consolidated P0/P1; none have run)

P0 (keystone tripwires): validation-level deny test on **all three**
issuers (mark a jti via the wired `expire`, `Validate` a real token carrying
it → rejected); e2e descendant rejection before TTL after root revoke;
existing `/token/revoke` oracle suite unchanged **plus** zero chain-store
reads on the unknown-token path (instrumented); cross-tenant blast-radius
test (H1).
P1: >1000-hop session cascade fails closed with partial list (H2); bus
adoption of absent/zero `exp` clamps (M4); migration v2 on fresh + populated
v1 DB with pre-v2 root behavior asserted (M2); `-race -count=10+` concurrent
cascades + concurrent-mint-during-cascade (M7); audit assertions (admin
success/failure events carry root + full/partial list; mint event carries
jti; cascade-failure event is non-admin-typed; auditreport drift gate);
`make ci` at each step (budgets, auditreport, module validation).

### Rollback triggers

- Any P0 keystone test fails on any issuer → the "revoked" response lies;
  stop and fix the seam before any surface ships.
- Any existing revoke-oracle test changes bytes → wire-contract regression;
  revert the cascade seam.
- `make ci` maintainability gate failure (file budgets) → stop and split
  before further edits (compile-enforced, so this is a hard stop).
- Post-release: a replicated jti denial that fails to re-seed at boot keeps
  the replica degraded (fail-closed) — roll forward, not back.

### Monitoring (proposed; none exists yet)

- Audit: `EventAdminTokenExchangeChainRevokeFailed` and the non-admin
  cascade-failure event with partial lists are the operational signal for
  truncation/abort — alert on them.
- Metric: `expire` durable-persist and bus-publish failure counters
  (best-effort legs) — sustained failures indicate the restart-resurrection
  window is open.
- Introspection: no jti-specific signal; the documented TTL-staleness window
  is the residual.

### Explicit exclusions (declared unsupported; do not silently expand)

- `subject_token_type: refresh_token`; SAML1/2 `requested_token_type`;
  opaque/non-JWT subject tokens (no jti → no hop).
- Cascade for opaque/refresh tokens presented at `/token/revoke`.
- jti→token index; jti-aware introspection-cache eviction (both rejected by
  D2 — accept the documented windows).
- Cycle detection / depth-cap changes (in-request enforcement unchanged).
- Session cascade remains unreachable in production until a future surface
  wires `RevokeOptions` (design risk 8 — accepted; must not be mistaken for
  a live control).
- No OIDF/FAPI/CIBA certification claim exists or is added (RFC 8693 has no
  OIDF certification track; consistent with
  `docs/architect-analysis-mfa-protocol-review.md`).

### Residual risks (accepted, to be documented in endpoint contracts)

- Cross-replica jti convergence via best-effort bus + boot/recovery re-seed
  only; no periodic reconciliation (M6); stale replica honors jti until the
  token's own `exp`.
- Clock-jump can prune denies early (L6; pre-existing for the token set).
- Revoke-during-mint escapes (M7); point-in-time semantics.
- Restart-resurrection for in-process-only deployments; shared-sqlite-file-
  over-NFS writer hazard (DS unsupported topologies).
- Admin root-kill is jti-deny-only: out-of-band validators bypassing issuer
  `Validate` honor the root until TTL (design risk 11).

## 5. Missing reviews/evidence and next actions

**Missing (no role assumed to have run):** QA/acceptance-mapping review of
the spec's acceptance table; SRE/performance review (in-band cascade cost is
unmeasured — protocol F3/M1 need a latency bound or a stated budget);
implementation review (nothing is implemented — all three reviews ran
source reads only; no build/test/gates ran for this feature). No product
authority has weighed the admin UX (descendants view + one-click revoke) or
the blast-radius decision.

**Narrow next actions to reach a decision:**
1. Maintainers + security: pin H1 blast radius (the only High-severity
   undecided question).
2. Design-doc amendment pass for B1–B5 (small, text-only).
3. QA review of the acceptance mapping; a stated latency budget for the
   `/token/revoke` cascade.
4. Then implement steps 1–2 of the design's order with the P0 keystone
   tests first — the keystone tripwire is the release gate.
