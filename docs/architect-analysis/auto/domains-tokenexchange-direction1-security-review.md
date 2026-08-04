# Security Review: `domains/tokenexchange` direction-1 design (ChainStore as a fail-closed revocation control plane)

Reviewer role: principal security engineer (adversarial production behavior).
Input: `docs/auto/domains-tokenexchange-direction1-design.md` + the underlying
`domains-tokenexchange-direction1-spec.md` + `AGENTS.md` invariants.

This is an advisory review of a **proposal** — no `.go` file was changed, so no
Go gate ran. Every material claim below was re-verified against the current
tree by source inspection; the design's own claims are labeled **Verified** /
**Partial** / **False** against that inspection. Worktree state: only the
review document is added; no other files were touched.

## Verification run for this review (all source-level, no gates executed)

- `ChainStore` is a 3-method interface (`domains/tokenexchange/chainstore.go:82-88`),
  `ChainHop` has exactly 7 fields; `GetDescendants` production callers: **zero**
  (only `test/token_exchange_chain_store_test.go` + `_test.go` files).
  **Verified**
- Sqlite walk: BFS, one `getChildren` query per visited node, loop condition
  `len(visited) < maxChainWalk` (`sqlite/chain_store.go:185-210`) — silently
  returns success on truncation. Memory walk unbounded (`memory/chain_store.go:78-102`).
  `maxChainWalk = 1000` (`sqlite/chain_store.go:48-51`). **Verified** — the
  design's "silent-truncation hazard" framing is accurate.
- RFC 9068 deny-set keyed by FULL TOKEN STRING in all three issuers
  (`rsa_validate.go:25`, `ed25519_validate.go:23`, `ecdsa_validate.go:25`);
  exp-bounded, prune-not-early, lazy prune under the existing write lock
  (`revocation_set.go`); `Revoke` validates the token first, then marks, then
  best-effort durable persist (`ecdsa_validate.go:133-147`). No jti-keyed
  surface anywhere. **Verified**
- `security.JTIReplayStore.MarkSeen` errors are documented fail-open
  (`shared/security/jti_replay.go:32-35`); `DefaultJTIReplayWindow` = 5 min.
  **Verified** — Decision 2's rejection rationale is accurate.
- `agentidentity.RevokeSession`/`RevokeAllForHuman` (`revoke.go:17,36`): zero
  production callers (only a doc mention at `interfaces/sso/options_grants.go:410`).
  **Verified**
- File budgets (`wc -l`): `interfaces/admin` = 10 non-test files (ceiling);
  `lifecycle.go` 481, `governance.go` 483, `connections.go` 498,
  `token_portfolio.go` 404; `interfaces/sso` = 60 non-test files (ceiling);
  `accessors_threat.go` 427, `server_token_clientauth.go` 483,
  `accessors_feature_gates.go` 498, `server_extensions.go` 461, `sso.go` 499,
  `server_routes.go` 488. **Verified** — and see Finding 4: the design's
  fallback home for the expire closure has 17 lines of headroom, not enough.
- Admin middleware: default scope policy GET → `admin:read`, else `admin:write`
  (`interfaces/admin/middleware.go:66-74`); chain = IP policy → rate limit →
  destructive-confirm → bearer auth (`middleware.go:325-339`); the
  destructive-confirm gate applies only to paths in the operator-configured
  `DestructiveSet` (`governance.go:351-393`, `X-Confirm: true`). **Verified**
- `HandleRevoke` writes the 200 **after** `revokeAccess`/`revokeRefresh`
  return (`protocols/oauth/handle_revoke.go:100-117`); `revokeAccess` at
  `:152`; the `RefreshTokenInspector` optional-capability idiom at `:163-168`.
  **Verified** — and see Finding 2: the design's "200 written before the
  cascade" claim is False against this code shape.
- `revokeAcrossIssuers` (`interfaces/sso/server_token_clientauth.go:432-462`)
  funnels every revocation path, evicts introspection cache, and has **no
  token→client ownership check**; `RevokeAcrossIssuers`
  (`accessors_feature_gates.go:222-228`) publishes `KindTokenRevoked` when
  `len(revoked) > 0`. **Verified**
- Subject-token validation in token exchange goes through
  `d.ValidateAnyToken` → issuer `Validate`
  (`internal/handler/tokengrant/token_exchange_stages.go:104-125`) — so a jti
  denied in `Validate` also blocks re-exchange of a denied descendant
  (invalid_grant collapse). **Verified** — a positive control the design does
  not claim but that makes Decision 2 stronger.
- All three issuers stamp `JTI` on every issue (`rsa_issue.go:114`,
  `ed25519_issue.go:217`, `ecdsa_issue.go:122`). **Verified** — every minted
  token is jti-deniable.
- Agent mint: `sub = agent.ID`, `act = sess.HumanSubject`
  (`agentidentity/grant.go:182-205`); `auditDelegationMint` records session +
  scopes but no jti (`grant.go:210-226`); `AgentSession.ID` exists
  (`session.go:18-31`). **Verified** — Decision 6's subject/actor deviation is
  correct; the spec's mapping would mislabel every agent token.
- Bus: `KindTokenRevoked` + `MetaRevokedToken`/`MetaRevokedExp` payload keys
  (`platform/cluster/bus.go:121,156-170`); `ApplyTokenRevocation` adopts
  local-only, no re-publish (`internal/handler/cross_replica.go:89-117`);
  `reseedRevocationDenySets` at `server_extensions.go:449`, error keeps the
  replica degraded. **Verified** — Decision 8's parity claims hold.
- `migrate.Run` is versioned, forward-only, per-namespace, single
  BEGIN IMMEDIATE transaction (`platform/migrate/migrate.go`). **Verified** —
  migration v2 with `ALTER TABLE ... ADD COLUMN` + index is supported.
- Audit classification gate: `auditreport/drift_test.go:95-126` enforces that
  every `auditspi.KnownEventTypes` entry is claimed or allowlisted;
  `EventAgentSessionRevoked`/`EventAgentDelegationTokenIssued`/
  `EventCrossTenantTokenExchange` are classified in CC6.1
  (`control_areas.go:54-70`). **Verified**. Caveat: the locally-declared
  `eventAdminTokensBulkRevoked` (`token_portfolio.go:39-41`) is NOT in
  `auditspi` and bypasses the gate — a pre-existing drift the design must not
  imitate (see Finding 8).
- Sibling governance: bulk-revoke workflow enforces soft cap 100 (needs
  confirm) / hard cap 10000 (`token_portfolio.go:29-37`). **Verified** — the
  new cascade endpoint has no equivalent guard (Finding 7).

---

## 1. Assets, trust boundaries, attacker capabilities, entry points

### Assets

| Asset | Protection today | Protection after design |
|---|---|---|
| RFC 9068 access tokens (all 3 issuers) | per-token string deny-set, exp-bounded, cross-replica via `KindTokenRevoked` + re-seed | + jti-keyed deny-set consulted in `Validate`; cascade marks ≤1000 descendants per revoke |
| `tokenexchange_chain_hops` records | append-only observability; admin `GetChain` read | + `SessionID`/`ExpiresAt`; revocation walk consumes the same data |
| Agent delegation tokens (`delegation_token`) | next-mint-only revocation; live to TTL | mint hops recorded; `RevokeSession`/`RevokeAllForHuman` cascade |
| Admin surface (`/api/v1/admin/*`) | AdminMiddleware: IP policy, rate limit, destructive-confirm, bearer + `admin:read`/`admin:write` | + descendants GET / cascade revoke POST under the same middleware |
| `/token/revoke` (RFC 7009) | 200-always, oracle-safe; per-token kill | + chain-aware side-effect, still 200-always |
| Audit trail | `audit.SetMeta` only, bounded cardinality | + 2 admin events + mint jti + cascade meta on `EventAgentSessionRevoked` |

### Trust boundaries

1. **OAuth client ↔ `/token/revoke`** — client credentials only; no ownership
   binding between the presented token and the authenticating client (pre-existing,
   now amplified — Finding 1).
2. **Admin operator ↔ admin API** — `admin:read`/`admin:write` bearer; trusted.
3. **Replica ↔ replica** — mesh-internal bus; `KindTokenRevokedJTI` adopted
   local-only; mixed-version peers drop unknown kinds (Finding 8).
4. **Request hot path ↔ chain store** — hop recording is fail-open; the
   cascade is fail-closed; the store never gates issuance.
5. **Issuer `Validate` ↔ deny sets** — in-process maps are authoritative;
   durable store + bus are best-effort; re-seed keeps degraded replicas
   non-authoritative for new denials only if seeding fails (stays degraded).

### Attacker capabilities (reachable, credentialed)

- **C1: any registered active OAuth client** (valid creds) — can call
  `/token/revoke` with any token string it possesses; today kills that one
  token; with the design, kills ≤1000 descendants across clients and tenants
  (Finding 1) and can measure a validity/provenance timing channel (Finding 2).
- **C2: admin with `admin:read`** — sees full chain topology including
  cross-tenant hops.
- **C3: admin with `admin:write`** — one-call cascade revoke (intended
  break-glass), plus 404/501/500/partial-list responses.
- **C4: unauthenticated** — no new surface; admin routes are not mounted
  without a wired store; `/token/revoke` still requires client auth.

### Entry points

1. `POST /token/revoke` (existing, modified) — cascade side-effect.
2. `GET /api/v1/admin/tokenexchange/chains/:jti/descendants` (new).
3. `POST /api/v1/admin/tokenexchange/chains/:jti/revoke` (new).
4. Issuer `Validate` (all 3) — new `jtiRevoked` consultation.
5. `RevokeSession`/`RevokeAllForHuman` (existing functions, new optional
   cascade; zero production callers today — dead until wired).
6. Bus `ApplyTokenRevocation` arm + `reseedRevocationDenySets` (extended).

---

## 2. Findings

### Finding 1 — HIGH: `/token/revoke` cascade is an authenticated cross-tenant, cross-client token-destruction primitive

**Evidence.** `HandleRevoke` authenticates the client but never binds the
presented token to it (`handle_revoke.go:86-117`; `revokeAccess` receives only
`(d, ctx, token)`); this permissiveness is pre-existing. The design's Decision 5
cascades from the presented token's jti to **all** descendants with no
ClientID/tenant filter, and Decision 2's jti deny-set is global (no tenant
dimension in the deny key). Cross-tenant exchange is a live feature
(`tokExEnforceTenantCollaboration`, `EventCrossTenantTokenExchange`), so a
descendant hop's `ClientID` can belong to a different tenant than the root's.
`ChainHop.ClientID` is recorded (`chainstore.go:56-59`) — filtering is feasible.

**Exploit preconditions and steps.** (1) Attacker holds valid credentials for
any active client in tenant A and a valid access-token string T (its own, or
leaked) whose lineage crosses into tenant B — reachable via the existing
cross-tenant collaboration flow. (2) `POST /token/revoke` with T. (3) The
cascade marks the jti of every descendant (≤1000) on every armed issuer; bus
events propagate to all replicas. (4) Tenant-B resource servers reject the
descendant tokens until their TTL. RFC 7009 §2.1's "token issued to the
presenting client" SHOULD-scope is not enforced for the root today, and the
design does not decide the blast-radius question for the cascade at all.

**Impact.** Cross-tenant availability destruction with an authenticated-client
precondition. Tenant isolation is a hard invariant in this repo (AGENTS.md §3);
the admin surface is the trusted break-glass and is unaffected by this finding.
The single-token kill becomes a ≤1000-token, cross-tenant kill.

**Remediation.** Pin the blast-radius scope explicitly: (a) recommended —
scope the `/token/revoke` cascade to hops whose `ClientID` equals the
authenticating client (the `chainRevokeCapability` signature gains `clientID`;
`revokeAccess` has `req.ClientID` in scope), leaving the admin endpoint as the
only cross-party/cross-tenant kill; (b) if cross-tenant cascade is intended,
document it in `docs/openapi.yaml` + the endpoint contract and emit an explicit
audit signal for every cross-tenant kill. Either way the design text must
state the decision.

**Regression test.** Integration (`test/`, `ssotest`): tenant-A client revokes
a root whose descendant was minted for a tenant-B client → assert the tenant-B
descendant **survives** (option (a)), or assert the cross-tenant kill is
audited with the intended event (option (b)). Plus a same-client descendant
still dies.

### Finding 2 — MEDIUM: the design's oracle-safety rationale is factually wrong; the cascade widens an existing `/token/revoke` timing channel by ~2 orders of magnitude

**Evidence.** Design Decision 5 states: "the 200-empty-body response is written
by the existing path before/independent of the cascade; the cascade runs on a
side channel". **False against the current code**: `HandleRevoke` writes
`ctx.JSON(200)` **after** `revokeAccess` returns (`handle_revoke.go:100-117`),
and the cascade per the design's own flow sketch runs inside `revokeAccess`
(before the 200). The sqlite walk is one query per visited node
(`sqlite/chain_store.go:185-210`): a known root with a large subtree costs
~1000 queries + ≤1000 marks + durable writes + bus publishes, i.e. tens of
milliseconds, versus fast-fail signature rejection for an unknown token (the
existing valid-vs-invalid delta today is ~sub-millisecond).

**Exploit preconditions and steps.** C1 (valid client credentials) measures
response latency for a candidate token string: unknown/opaque → fast; valid
root with recorded descendants → slow. The probe destroys the token in the
process, but reveals (a) the token was valid on this server at probe time and
(b) whether it is a token-exchange root with a derived lineage — precisely the
"is this token live" enumeration RFC 7009 §2.2 and the AGENTS.md oracle table
exist to prevent.

**Impact.** Wire bytes stay identical (200, empty body — the pinned contract is
preserved), but the design's stated reason *why* it is oracle-safe is
incorrect, and the timing delta is materially widened. An implementer
restructuring "after the response is decided" would still leave a
connection-close timing channel unless the cascade leaves the request path
entirely.

**Remediation.** (1) Correct the design text: the cascade is in-band today and
only "unobservable on the wire" in the body sense. (2) Bound the channel:
run the cascade with a hard time/count budget (the 1000 cap alone does not
equalize timing), and/or defer it off the request path to a bounded worker
with audit ordering preserved. (3) Document the residual timing delta in the
endpoint contract. Do not claim byte-and-timing indistinguishability.

**Regression test.** A test asserting the unknown/opaque-token path performs
**no** chain-store reads (instrument the store with a read counter), and a
coarse timing-bound assertion (known-root cascade must not run on the
unknown-token path).

### Finding 3 — MEDIUM: `HopsBySession` truncation is silent — the session cascade can be a silent partial revocation reported as success

**Evidence.** Decision 1 makes `RevokeDescendants` truncation an error
(`ErrChainWalkTruncated`) — the right fail-closed call — but `HopsBySession`
is "bounded by the same 1000 cap" (memory) / `LIMIT ?` (sqlite) with **no
truncated flag**. `RevokeAllForHuman` then kills only the newest 1000 hops of
a >1000-hop session, and `auditRevokeCohort` (`revoke.go:28-36`) reports
`OutcomeSuccess` whenever the store-side revocation succeeded.

**Exploit preconditions and steps.** A long-lived AgentSession that minted
>1000 delegation tokens (a busy agent; mint hops are fail-open recorded per
mint; sessions may be revocation-only with no expiry — `session.go:24-29`).
The human is offboarded; `RevokeAllForHuman` runs; the oldest (still within
TTL) minted tokens survive while the audit trail says the cohort was revoked.

**Impact.** The exact "partial revocation silently dropped" failure the spec
and Decision 1 forbid, reached through the session surface instead of the walk
surface.

**Remediation.** Give `HopsBySession` the same fail-closed truncation contract
as `RevokeDescendants` (return a truncated flag / `ErrChainWalkTruncated`),
and flip the audit outcome to failure with a `truncated` meta when the bound
is hit — mirroring the design's own Decision 1 discipline.

**Regression test.** Seed 1001 hops for one session; `RevokeAllForHuman`
returns an error (or truncated flag), the audit outcome is failure, and either
every hop's jti is denied or the remainder is explicitly reported.

### Finding 4 — MEDIUM: the expire-closure placement fallback cannot fit the compile-enforced line budget

**Evidence.** The design places the mounts + wrappers + accessor + `expire`
closure in `accessors_threat.go` (427/500, 73 lines headroom) and states "if
the closure overflows, it moves to `server_token_clientauth.go` (the
issuer/revocation home)". `server_token_clientauth.go` is 483/500 — **17 lines
headroom**. `accessors_feature_gates.go` (the actual issuer/revocation file,
498/500) has 2; `sso.go` 499/500; `server_routes.go` 488/500. The added
surface (2 route registrations, 2 wrappers, 1 accessor, a ~35-line closure
with mark + durable-persist + bus legs) is ~75+ lines — over the 73-line
primary home and far over the stated fallback.

**Impact.** The maintainability gate is compile-enforced; the implementation
as designed fails `make ci` and must scramble for a home mid-change, risking
the "incomplete validation seam" failure mode (Decision 10 risk 1) under time
pressure.

**Remediation.** Split before writing: the bus-publish leg into
`server_extensions.go` (461/500, 39 lines — home of `notifyTokenRevoked`),
the durable-persist leg next to the issuer wiring, and only the assembly +
mounts + accessor in `accessors_threat.go`. Re-verify `wc -l` before each
edit, per AGENTS.md §5.

**Regression test.** The existing maintainability gate (`make ci`) — no new
test needed.

### Finding 5 — MEDIUM (operational): pre-v2 hops are unrevocable from the admin surface

**Evidence.** Decision 3 pins `ExpiresAt == 0` → `ErrHopMissingExpiry` abort,
and Decision 4 kills the root **only** via the jti deny-set (the admin holds
no token string). A root recorded before the v2 migration therefore cannot be
revoked at all: the cascade aborts with 500 and the root stays valid until
TTL.

**Impact.** Fail-closed and loud (no silent deny-for-zero), so not a security
regression — but a functional gap for every upgraded deployment with recorded
hops: the break-glass control silently does not exist for legacy roots, and
the design offers no fallback TTL.

**Remediation.** Pin an explicit fallback: deny with a conservative floor
(now + server-max access-token TTL) and audit the fallback, or keep the abort
and document the 500 + new error code as the expected behavior for legacy
roots, plus an operator runbook step (re-mint/re-exchange to re-record).
Backfilling `expires_at = recorded_at + max TTL` at migration time is a
third option worth evaluating.

**Regression test.** Migration test from a v1-schema DB with a recorded root:
admin revoke asserts either the fallback-TTL denial or the documented
`ErrHopMissingExpiry` 500 with failure audit.

### Finding 6 — LOW/MEDIUM: revoke-during-mint race — a hop recorded mid-cascade escapes revocation

**Evidence.** The sqlite walk is a per-node BFS with no snapshot/transaction
(`sqlite/chain_store.go:185-210`), and `RecordHop` upserts concurrently. A
mint completing after the walk fetched its parent's children — but before the
cascade finishes — produces a descendant that is never marked.

**Impact.** A token minted concurrently with an admin/client revoke survives
the cascade until its TTL. Window is small (milliseconds) and the TTL is the
backstop, but for a "kill all of it" control this is a correctness gap the
design does not mention.

**Remediation.** At minimum document it as an accepted, TTL-backstopped race
in the fail-closed contract table. Stronger: after marking, run one bounded
re-walk and mark any newly-visible descendants (bounded, idempotent); the
memory store can hold the store lock across walk+mark trivially.

**Regression test.** Deterministic test with a hop recorded mid-walk (hook
between parent fetch and mark): either the re-walk kills it or the race is
documented and asserted as accepted behavior.

### Finding 7 — LOW: the new admin cascade revoke bypasses the destructive-confirm governance that its sibling bulk-revoke has

**Evidence.** The admin middleware's `X-Confirm` gate applies only to paths in
the operator-configured `DestructiveSet` (`governance.go:351-393`); the design
does not register or document the new `POST .../revoke` path there, while the
sibling `HandleBulkRevoke` enforces soft-cap-100-needs-confirm /
hard-cap-10000 (`token_portfolio.go:29-37`).

**Impact.** A fat-fingered admin call destroys up to 1000 tokens with no
confirmation where the sibling workflow demands one. Not a vulnerability
(admin is trusted), but inconsistent governance of a one-click mass
revocation.

**Remediation.** Document the new path in the destructive-actions guidance and
`docs/openapi.yaml` so operators can classify it; optionally mirror
`bulkRevokeSoftCap` (confirm above 100).

**Regression test.** Handler test: with the path registered in a `DestructiveSet`,
the endpoint returns 409 without `X-Confirm: true`.

### Finding 8 — LOW: mixed-version replicas and the local-event-type precedent

Two bounded notes:

1. **Rolling upgrades.** An old replica drops `KindTokenRevokedJTI` at its
   default arm and has no jti store to seed from — descendants stay valid
   there until the replica runs the new binary. This is parity with the token
   deny-set's own mixed-version behavior (documented in `bus.go:100-121`), so
   it is acceptable, but the rollout section should say so explicitly.
2. **Audit registration.** `eventAdminTokensBulkRevoked` is declared locally
   in `interfaces/admin/token_portfolio.go:39-41` and is absent from
   `auditspi.KnownEventTypes`, bypassing the `auditreport` drift gate — a
   pre-existing drift. The design's Decision 7 correctly puts the new event
   types in `auditspi` + `control_areas.go`; keep it that way and do not
   imitate the local-declaration precedent. Also keep the `/token/revoke`
   cascade-failure event distinct from the admin failure event (the design
   already leans that way): an `EventAdmin*` type emitted for a
   client-credentialed actor would corrupt the admin-actions audit bucket.

**Regression test.** None new; the existing `auditreport` drift gate covers
item 2 once the types are declared in `auditspi`.

### Info-level observations (no action required)

- The jti deny check is proposed "after claims decode", i.e. after signature
  verification — a denied token still pays signature cost. DoS-neutral (the
  token-string check stays early), but placing the jti check before the
  signature verify (payload decode only, `JTIFromJWTUnsafe`-style) would make
  revocation rejection cheaper and would also catch the case where a future
  issuer path reorders validation. Optional.
- The admin descendants GET exposes cross-tenant hop topology; admin-only, in
  line with the trusted admin boundary.
- `ChainHop` upsert semantics mean an attacker who can mint (a legitimate
  exchange) can grow the store unboundedly — pre-existing (hops are never
  pruned); the new deny maps are exp-bounded so the cascade side stays bounded.

---

## 3. Abuse-case table

| Abuse case | Reachable? | Path | Outcome / mitigation |
|---|---|---|---|
| Identity spoofing (wire) | No | jti deny marks require admin:write or possession of a valid token; minted jtis are random per mint (`generateJTI`), so a denied jti cannot be forged onto a fresh token; a forged token fails signature anyway | No spoof path; per-issuer maps bound a collision to one jti (design risk 10, accepted) |
| Identity spoofing (forensic) | Yes, if spec followed | Spec's "subject = human, actor = agent" mapping would mislabel every agent token in `GetChain`/admin UI — misattribution during incident response | **Design fixed it** (Decision 6, Verified against `grant.go:182-205`); implementers must follow the minted token's claims, not the spec prose |
| Token replay | Partially mitigated | Re-presenting a denied token within TTL → `Validate` rejects (new jti check, all 3 issuers); re-exchange of a denied subject token → `invalid_grant` (subject validation funnels through `ValidateAnyToken`, Verified) | Deny-set prune-not-early discipline preserved; acceptance must include the 3-issuer validation-level test (the keystone tripwire) |
| `/token/revoke` replay | Safe | Repeated revoke of the same token → 200 again; cascade marks are set-inserts (idempotent); `len(revoked)==0` for unknown tokens skips the cascade | 200-always contract preserved on the wire |
| Cross-tenant access (confidentiality) | No | No data crosses tenants; deny keys are jti/exp only | — |
| Cross-tenant destruction (availability) | **Yes** | Finding 1: any authenticated client revoking a root kills ≤1000 descendants minted for other clients/tenants | High-severity finding; scope the cascade to the presenting client or explicitly decide + audit cross-tenant kills |
| Proxy/header forgery | No | No new header trust; new routes ride the existing AdminMiddleware (IP policy → rate limit → confirm → bearer) and `/token/revoke` client-auth path; no XFF/host/proto consumption added | Verified no new proxy surface |
| Resource exhaustion (admin) | Bounded | Walk caps (1000) on both backends; admin rate-limit bucket; jti maps exp-bounded with lazy prune; audit lists capped + comma-joined | Bounded; Finding 7 (no confirm gate) is a governance gap, not an exhaustion path |
| Resource exhaustion (`/token/revoke`) | Bounded but in-band | Cascade runs on the request path before the 200 (Finding 2); each call ≤1000 queries + marks; authenticated-client-only | Fix = time/count budget + correct the design's false "side channel" claim |
| Sensitive-data leakage | No new | Admin responses/audit carry jti, subject/actor/client IDs — admin-only; bus payload carries jti, never the token string (mirrors `MetaRevokedToken`'s "never in Key" rule, Verified) | jti alone is not a credential; bounded cardinality preserved |

---

## 4. Positive controls verified, residual risks, prioritized validation plan

### Positive controls verified (source-level)

1. **Keystone soundness.** The design correctly identifies that a jti-keyed
   deny seam is *required* (`Validate` + issuer maps + durable sibling +
   re-seed), and correctly rejects `JTIReplayStore` (fail-open direction +
   semantic conflation — both Verified against `jti_replay.go:32-35`).
2. **Fail-closed cascade.** Walk/expire errors abort with partial lists surfaced
   in body + audit; `ErrChainWalkTruncated` converts today's silent
   truncation into an error; `ErrHopMissingExpiry` prevents deny-for-zero.
3. **Oracle-safe surfaces.** `/token/revoke` 200-always and byte-identical
   response preserved; cascade gated on `len(revoked) > 0`; admin 404/501/500
   states are explicit and audited, and the admin surface is not an OAuth
   oracle.
4. **Deny-set hygiene.** exp-bounded maps under the existing `revokedMu` (no
   new locks, no lock-ordering surface); prune-not-early discipline reused.
5. **Validation coverage.** Every minted token carries a jti (all 3 issuers);
   subject-token validation funnels through issuer `Validate`, so denied
   descendants are also blocked from re-exchange — a control the design does
   not claim but which materially strengthens it.
6. **Cross-replica parity.** `KindTokenRevokedJTI` + local-only adoption +
   boot/recovery re-seed + degraded readiness mirror the token path exactly.
7. **Optional-wiring idiom.** `ChainRevoker` extension interface,
   `chainRevokeCapability`, and `chainStoreProvider` type-asserts keep every
   test fake and the `ChainStore`/`RevokeDeps`/`Deps` contracts untouched
   (Verified: `test/token_exchange_chain_store_test.go` fakes implement the
   3-method interface).
8. **Fail-open recording preserved.** Hop recording (exchange + mint) never
   fails a grant; unwired store is byte-identical everywhere.
9. **Admin governance inherited.** New routes get IP policy, rate limit, and
   `admin:read`/`admin:write` scoping for free; 401 stays `Bearer
   realm="admin"`.
10. **Audit discipline.** New types in `auditspi` + CC6.1 classification;
    `SetMeta` only; bounded cardinality; mint audit gains `KeyJTI`.

### Residual risks (accepted, documented)

- Replica convergence window for jti denials (best-effort bus; parity with the
  token deny-set; re-seed closes it on restart/recovery).
- Admin-root kill is jti-deny-only: out-of-band validators that bypass issuer
  `Validate` would still honor the root until TTL (design risk 11).
- jti collision across issuers (negligible; random per mint).
- Session cascade ships acceptance-tested but unreachable in production until
  an admin/self-service session surface wires `RevokeOptions` (design risk 8).
- The revoke-during-mint race (Finding 6) unless a re-walk is added.
- Timing delta on `/token/revoke` (Finding 2) unless the cascade leaves the
  request path.

### Prioritized validation plan

| # | Check | Proves | Priority |
|---|---|---|---|
| 1 | Validation-level deny test on **all three** issuers: mark a jti via the wired `expire`, then `Validate` a real token carrying that jti → rejected | The keystone (Decision 10 risk 1) — the whole direction's tripwire | P0 |
| 2 | Integration (`test/`, `ssotest`): root revoke at `/token/revoke` → descendant rejected before TTL; unwired store → byte-identical no-op | Decision 2 + 5 end-to-end | P0 |
| 3 | Existing `/token/revoke` oracle suite unchanged + no store reads on the unknown-token path (instrumented) | Finding 2 | P0 |
| 4 | Cross-tenant blast-radius test (tenant-B descendant survives tenant-A client revoke, or audited if scoping declined) | Finding 1 | P0 |
| 5 | >1000-hop session cascade → error/truncated flag + failure audit | Finding 3 | P1 |
| 6 | Migration v2 on fresh + populated v1 DB; pre-v2 root revoke behavior asserted | Finding 5 | P1 |
| 7 | `-race -count=10+` concurrent cascades; sqlite index + cap test; mid-walk record hook | Decision 1 + Finding 6 | P1 |
| 8 | `make ci` (line budgets, auditreport drift gate, module validation) before and after each step | Finding 4 + Decision 7 | P0 (gate) |
| 9 | Audit assertions: admin revoke success/failure events carry root + full/partial list; mint event carries jti; cascade failure event is non-admin-typed | Decision 7 | P1 |
