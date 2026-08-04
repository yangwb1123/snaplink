# domains/tokenexchange — Direction 1 QA review (risk-based test review)

Review of `docs/auto/domains-tokenexchange-direction1-design.md` +
`docs/auto/domains-tokenexchange-direction1-spec.md` at worktree HEAD
`c7f226a8` ("Stage: design"). The feature is **Proposed** — design + spec
only; no implementation landed (Verified: no `RevokeByJTI`/`SeedJTIRevocations`
on any issuer, no `ChainHop.SessionID`/`ExpiresAt`, no `ChainRevoker`, no
`KindTokenRevokedJTI` bus kind, no `ErrChainWalkTruncated`/`ErrHopMissingExpiry`,
no new admin routes). This review re-verifies every evidence claim the design
makes, maps each decision + spec acceptance to existing/required tests, and
measures the baseline the change builds on. All commands below ran for this
revision; no result is inherited from other reviews or documentation.

## 0. Design-evidence re-verification (all claims checked against source)

| Design claim | Verified |
|---|---|
| `ChainStore` 3-method read/append contract (`RecordHop`/`GetChain`/`GetDescendants`); `ChainHop` 7 fields, no `SessionID`/`ExpiresAt` | Verified (`domains/tokenexchange/chainstore.go:67-89, 25-56`) |
| Zero production `GetDescendants` callers; callers only in `test/token_exchange_chain_store_test.go` + package `_test.go` files | Verified (grep: only doc comments + 3 test files) |
| `maxChainWalk = 1000` silent truncation in sqlite (`len(visited) < maxChainWalk` loop, returns success); memory walk unbounded (visited cap absent, `limit` only trims output) | Verified (`sqlite/chain_store.go:48, 180-205`; `memory/chain_store.go:78-108`) |
| Deny-set keyed by FULL token string in all 3 issuers, consulted before signature verification; `map[string]int64` exp-bounded, prune-not-early under `revokedMu` | Verified (`rsa_validate.go:25`, `ed25519_validate.go:23`, `ecdsa_validate.go:25`; `revocation_set.go` `markRevoked`/`pruneRevoked` + prune-not-early doc) |
| No jti→token index anywhere; `KeyJTI = "jti"` exists | Verified (`shared/core/consts_wire.go:177`; grep for jti-keyed deny/index: nothing) |
| `security.JTIReplayStore` fail-open direction + `DefaultJTIReplayWindow = 5min` | Verified (`shared/security/jti_replay.go:29, 51` — "fail-open: store failures shouldn't block valid requests") |
| `interfaces/admin` at 10 non-test-file ceiling; `lifecycle.go` 481, `governance.go` 483, `connections.go` 498, `token_portfolio.go` 404, `middleware.go` 492 | Verified (`wc -l`; 10 non-test files) |
| Admin middleware default policy GET → `admin:read`, else `admin:write` | Verified (`interfaces/admin/middleware.go:72` area doc) |
| `revokeAccess` at `protocols/oauth/handle_revoke.go:152`, per-token only; `RefreshTokenInspector` type-assert idiom in `revokeRefresh` (:163-170); `InvalidateIntrospectionCache` point-evicts the presented token after revoke | Verified |
| **"200 written before the cascade" — False** (see F3): `HandleRevoke` calls `revokeAccess` (:99-100) then `InvalidateIntrospectionCache` (:109) then `ctx.JSON(200)` (:111); the cascade is in-band, the 200 is *decided* but not *written* | Verified — design text needs correcting |
| Introspection cache serves stale `active:true` up to TTL; doc admits it ("A revoked token might be served from cache for up to TTL seconds") | Verified (`protocols/oauth/introspect_cache.go:30`) |
| `mintDelegationToken` mints `sub=agent.ID, act={Subject: sess.HumanSubject}`; `auditDelegationMint` omits the minted jti (no `KeyJTI`); mint records no ChainHop | Verified (`grant.go:165-213, 213-228`) |
| `RevokeSession`/`RevokeAllForHuman` zero production callers; `outcomeOf` helper exists | Verified (grep: only `session.go` decl, `memory_session.go` impl, doc mention `options_grants.go:410`) |
| `KindTokenRevoked`/`MetaRevokedToken`/`MetaRevokedExp`; `ApplyTokenRevocation` local-only adoption with exp re-derivation ("receiver never trusts this value over the token's own claim"); `reseedRevocationDenySets` at `server_extensions.go:449` | Verified (`platform/cluster/bus.go:121, 156-170`; `internal/handler/cross_replica.go:89-118`) |
| `EventCrossTenantTokenExchange` + `EventAgentDelegationTokenIssued` classified CC6.1 in auditreport | Verified (`platform/audit/auditreport/control_areas.go:55-56`) |
| OpenAPI `subject_token_type` enum lists `refresh_token` + `txn-token`; code accepts only access_token/jwt/id_token as subject types | Verified (`docs/openapi.yaml:12482-12487`; `token_exchange_stages.go:62-66`) — pre-existing drift, F11 |
| File budgets: `consts.go` 466/500, `consts_wire.go` 490/500, `accessors_threat.go` 427/500, `server_token_clientauth.go` 483/500 | Verified — **the design's fallback home has 17 lines of headroom, not enough for the expire closure** (F6) |
| `chainstore.go` is 155 lines, not ~250 | Verified — cosmetic nit only (budget unaffected) |
| Test foundation exists: `TestHandleRevoke` oracle subtests incl. "valid creds unknown token still 200 (RFC 7009 §2.2)"; `tokenexchange_chains_test.go` 5 handler tests via REAL memory store; `test/token_exchange_chain_store_test.go` 3 wire tests via `newTokenExchangeChainPolicyHarness` | Verified |
| **No test anywhere wires `WithAgentDelegationGrant`** (only a comment in `grant_test.go:22`); no `test/` file exercises the delegation grant over the wire | Verified (grep) — see F2 |
| Issuer deny-set test patterns exist per issuer: `Test{Ed25519,ECDSA,RSA}Revoke_HonoredUpToExp`, `TestPruneRevoked_NeverDropsLiveEntry` (reads unexported map directly), restart-survival `TestEd25519Issuer_RevocationSurvivesRestart_{Memory,SQLite}`, cross-replica adoption `issuer_extras_test.go:362` | Verified — the keystone's test skeleton already exists (D2 is Extend, not Add) |
| `TestChainStoreMaxVersion_MatchesLiveSchema` asserts max == live schema — self-updates when migration v2 lands | Verified (`sqlite/chain_store_test.go:177`) |

## 1. Test inventory and commands actually run for this revision

| Command | Result | Notes |
|---|---|---|
| `go build ./... && go vet ./...` | PASS | full module at HEAD `c7f226a8` |
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | PASS | budget/architecture gates |
| `go test ./domains/tokenexchange/... -race -count=1` | PASS | 4 packages (root, agentidentity, memory, sqlite) |
| `go test ./protocols/oauth/ -run 'TestHandleRevoke|TestHandleRevokeAll' -v` | PASS | 20 subtests incl. RFC 7009 §2.2 oracle + inspector no-op |
| `go test ./interfaces/admin/ -run 'TestHandleTokenExchangeChain' -v` | PASS | 5 handler tests (happy/unknown/missing/nil/scope) |
| `go test ./test/ -run 'TestTokenExchange_ChainStore' -v` | PASS | 3 wire tests (record-on-success, unwired no-op, fail-open) |
| `go test ./test/ -run TestE2E -v` | PASS | 4 `TestE2E_*` tests |
| `go test -cover` touchpoints | see below | line coverage only; adequacy argued in §3 |
| `gofmt -l .` | 2 files | pre-existing fmt blockers, F12 |
| Source verification | ~30 greps + `wc -l` + targeted reads | §0 ledger |

Coverage baseline (measured this revision):

| Package | Coverage | Relevance |
|---|---:|---|
| `domains/tokenexchange` (root) | **34.5%** | the new `ChainRevoker` orchestrator + `RevokeRootAndDescendants` land HERE — lowest coverage of the touched set (F9) |
| `domains/tokenexchange/agentidentity` | 94.0% | D6 edit site; `RevokeOptions` cascade is net-new |
| `domains/tokenexchange/memory` | 98.2% | D1/D3 edit site |
| `domains/tokenexchange/sqlite` | 83.7% | D1/D3/D8 edit site (migration, walk, jti table) |
| `protocols/oauth` | 89.1% | D5 edit site |

## 2. Requirement-to-test matrix

Status: **Exists** (green today), **Extend** (existing test gains an arg/assert), **Add** (net-new), **Blocked** (not testable in-repo). "Design acceptance" = the spec/design's own acceptance mapping.

| Design decision / spec acceptance | Status | Evidence / required test |
|---|---|---|
| D1 — `ChainRevoker` extension interface (no `ChainStore` growth) | **Add** | interface compile check + `var _ ChainRevoker = (*sqlite.ChainStore)(nil)`/memory; test fakes keep compiling (compile-gated) |
| D1 — 3-hop cascade root→a→b marks a,b only; sibling subtree untouched | **Add** | memory + sqlite unit (fixture pattern exists: `TestChainStore_GetDescendants` seeding) |
| D1 — idempotent re-run | **Add** | same test, second `RevokeDescendants` call succeeds, marks unchanged |
| D1 — injected `expire` error propagates with partial `revoked` list | **Add** | design acceptance; assert partial list + wrapped error, audit-side caller test at admin level |
| D1 — walk truncation → `ErrChainWalkTruncated` (fail-closed, never silent subset) | **Add** | 1001-hop linear chain (sqlite, in-memory DB — fast) + cyclic graph via direct `RecordHop`; `GetDescendants` keeps returning rows (contract unchanged), `RevokeDescendants` errors |
| D1 — `HopsBySession` newest-first, bounded | **Add** | **missing from the design's acceptance table entirely** — see F1 |
| D1 — concurrent cascades race-clean | **Add** | `-race -count=10+` (design acceptance; pattern: existing `-race` runs) |
| D1 — sqlite walk uses parent index + `maxChainWalk` bounds | **Add** | cap test (above) + optional `EXPLAIN QUERY PLAN` or index-presence assert on `idx_tokenexchange_chain_hops_parent`/`_session` (F10) |
| D2 — keystone: `expire`-marked jti rejected by `Validate` on ALL THREE issuers | **Extend** | mirror `Test{Ed25519,ECDSA,RSA}Revoke_HonoredUpToExp` (`revocation_set_test.go:82,136,172`) with `RevokeByJTI`; assert rejection BEFORE exp and acceptance after exp |
| D2 — jti deny map prune-not-early | **Extend** | `TestPruneRevoked_NeverDropsLiveEntry` covers the shared helper; add per-issuer honored-up-to-exp for the jti map (same accessor pattern: unexported map read) |
| D2 — `JTIRevocationStore` memory + sqlite round-trip/prune | **Extend** | `TestMemoryRevocationStore_RoundTripAndPrune` pattern; sqlite sibling per `revocations.go` contract |
| D2 — `SeedJTIRevocations` boot/recovery + nil-store no-op | **Extend** | `TestEd25519Issuer_RevocationSurvivesRestart_{Memory,SQLite}` + `TestEd25519Issuer_NilStore_SeedNoOp` patterns; sqlite backend = restart survival |
| D2 — `expire` closure: issuer mark fail-closed; durable/bus best-effort | **Add** | interfaces/sso unit: injected failing mark aborts; failing store/bus logged + metric, mark stands |
| D3 — migration v2 (`session_id`, `expires_at`, session index) | **Extend** | `TestChainStoreMaxVersion_MatchesLiveSchema` self-updates to v2; **Add** downgrade-guard already exists (max-1 → `ErrSchemaTooNew`) |
| D3 — pre-v2 rows read-compatible, `ExpiresAt==0` → `ErrHopMissingExpiry` abort | **Add** | **migration test: v1-schema store → v2 migrate → legacy row cascade aborts** — see F7 |
| D3 — `ExpiresAt` flows through `scanHop` (9 cols) both directions | **Add** | round-trip test via `getHop`/`getChildren`/`GetChain`/`GetDescendants` |
| D3 — `RecordExchangeHopFailOpen` + `expiresAt` param; sole call site | **Extend** | compile-gated; `token_exchange.go:227` call site update; wire test asserts hop carries `ExpiresAt == now+ExpiresIn` |
| D4 — GET descendants bounded/ordered newest-first, `?limit` cap 1000, default 100 | **Add** | `interfaces/admin` handler tests in the `tokenexchange_chains_test.go` pattern (real memory store) |
| D4 — GET unknown jti → 404; known jti + no descendants → 200 `[]` | **Add** | GetChain-first 404 ordering |
| D4 — POST revoke: 200 + revoked list (root first), 500 + partial body + failure audit, 501 non-revoker | **Add** | handler tests + audit drain (existing `token_portfolio_test.go` audit patterns) |
| D4 — unwired store → routes not mounted | **Add** | `test/` level (mount gate is in `accessors_threat.go`); assert route 404/405 not 401-admin |
| D4 — scope gating GET read / POST write, `Bearer realm="admin"` | **Extend** | `TestHandleTokenExchangeChain_ScopeGating` pattern for both new routes |
| D5 — `/token/revoke` oracle suite byte-identical | **Exists** | `handle_revoke_test.go` 20 subtests must pass UNCHANGED (regression boundary) |
| D5 — cascade only when `len(revoked)>0`; opaque/refresh/unknown → no cascade | **Add** | unit at interfaces/sso capability impl + `test/` wire test |
| D5 — wired store: root revoke at `/token/revoke` kills descendant before TTL | **Add** | `test/` E2E via `newTokenExchangeChainPolicyHarness` (real Ed25519 issuer, 1-min TTL) — assert descendant rejection through `Validate`/protected route |
| D5 — cascade error → log + audit, 200 preserved | **Add** | injected-failure test at the capability boundary |
| D6 — mint records hop: `SessionID`/`JTI`/`SubjectID=agent`/`ActorSubject=human`/depth 1 | **Add** | `grant_test.go` — `testDeps` gains the `chainStoreProvider` capability; real memory store |
| D6 — `auditDelegationMint` carries jti (`KeyJTI`) | **Add** | audit drain assertion (existing recorder harness in `grant_test.go`) |
| D6 — `RevokeSession` cascade kills that session's minted tokens only | **Add** | `revoke_test.go` + memory store; per-session isolation |
| D6 — `RevokeAllForHuman` kills every minted jti for the human, none for another | **Add** | two-human fixture |
| D6 — failing cascade: audit outcome failure + partial list, session revoke still applied | **Add** | injected `expire` failure; assert store-side revocation + `outcomeOf` flip |
| D6 — `opts == nil` byte-identical, no new audit meta | **Add** | existing `TestRevokeSession_*`/`TestRevokeAllForHuman_*` stay green unchanged |
| D6 — integration: post-`RevokeAllForHuman` `delegation_token` rejected before TTL | **Add** | **net-new harness — no delegation composition test exists (F2)** |
| D7 — new event types registered + classified (auditreport gate) | **Extend** | `auditspi/event_types.go` known-types map + `control_areas.go` CC6.1; gate enforced in `make ci` |
| D7 — admin revoke success/failure events with actor + lists; bounded cardinality | **Add** | admin handler tests drain recorder; comma-joined list bounded assert |
| D8 — `KindTokenRevokedJTI` wire format + payload keys | **Add** | mirror `TestPublishTokenRevocation_WireFormat` (`cross_replica_test.go:114`) |
| D8 — `ApplyTokenRevocation` jti arm adopts locally, no re-publish, foreign jti no-op | **Add** | mirror `TestApplyTokenRevocation_AdoptsAndCounts`/`_NoOpPaths` |
| D8 — mixed-version peer drops unknown kind at default arm | **Extend** | `bus_test.go` default-arm coverage |
| D8 — re-seed extension + degraded-on-seed-failure | **Extend** | existing `reseedRevocationDenySets` test pattern; jti seed failure keeps degraded |
| D9 — fail-closed/fail-open consolidated table | see rows | each row maps to a test above; the two oracles (admin explicit states, `/token/revoke` 200-always) are the regression boundaries |
| D10.1 — keystone tripwire (validation-level, 3 issuers) | **Extend** | F1 row above; **this is the P0 test of the whole direction** |
| D10.2 — zero-TTL hop aborts (`ErrHopMissingExpiry`) | **Add** | D3 migration test (F7) |
| D10.3 — subject/actor mapping pin | **Add** | D6 mint-hop test asserts `SubjectID == agent.ID`, `ActorSubject == human` (NOT the spec's backwards mapping) |
| D10.4 — truncation-as-error | **Add** | D1 truncation test |
| D10.5 — fakes keep compiling | **Exists** | compile-gated; `testDeps`/`RevokeDeps`/admin fakes unchanged |
| D10.6 — file budgets | **Exists** | `TestMaintainability_` gate; F6 risk on the closure fallback |
| D10.7 — oracle drift | **Exists/Add** | existing oracle suite + F3 timing bound |
| D10.8 — session cascade dead in production | **Add** | unit + integration level per design; documented as unreachable until a future surface |
| D10.9 — restart/late-join resurrection | **Extend** | D2 restart-survival + D8 reseed tests |
| D10.10 — jti collision cross-issuer | **Info** | 128-bit random jtis (verified in all 3 issuers); accepted, no test |
| D10.11 — out-of-band validators + admin root kill via jti only | **Add** | documented-behavior note; F5's introspection staleness pin covers the in-server surface |
| D10.12 — deny-map races | **Add** | `-race -count=10+` concurrent cascade + concurrent revoke/validate |
| Docs — openapi endpoints + error codes + observability + feature-matrix | **Add** | F11 (enum drift fix in the same change); docs-validate in `make ci` |

## 3. Findings

### F1 — High — `HopsBySession` truncation is the one place the design's own "never silent partial revocation" rule is silently dropped, and the acceptance table has NO test for it

The design pins (D1) "truncation at `maxChainWalk` becomes `ErrChainWalkTruncated` — never silent partial revocation", and D6's sqlite sketch is
`WHERE session_id=? ORDER BY recorded_at DESC LIMIT ?` — a silent cap with no
truncation signal. The D6 failure-mode table lists `HopsBySession` errors but
no truncation case, and the acceptance mapping has no store-level
`HopsBySession` test at all (boundedness, ordering, cap). Breadth is
unbounded today: `MaxActChainDepth` caps depth, not children per node, and a
session can accumulate >1000 recorded mints (agent mints + exchanges into
them). A human-cohort cascade (`RevokeAllForHuman`) on a compromised account
would then kill only the newest 1000 and audit success — the exact class the
design forbids, on the most security-sensitive surface. This agrees with the
protocol review (F1), DS review (F-1), and security review (finding 3); the
QA-specific gap is that the test list never exercises it.

- **Exact test to add** (`domains/tokenexchange/sqlite/chain_store_test.go`):
  seed 1001 hops on one `SessionID` (1001 direct `RecordHop` calls, in-memory
  DB — sub-second), call `RevokeSession`-shaped cascade (or the orchestrator
  free function) with a recording `ExpireFunc`.
- **Acceptance assertion**: the cascade returns an error (truncation sentinel
  or `ErrChainWalkTruncated`), the revoked/partial list is reported (audit
  carries it), the kill count is NOT silently 1000-of-1001 with success. If
  the design instead pins "truncated = fail-closed error", assert that; the
  test forces the decision to be made before ship.

### F2 — High — Improvement-3's integration acceptance has no existing harness: the delegation grant has ZERO composition tests anywhere

The design's step 7 says "Integration (`test/`, `ssotest`): after
`RevokeAllForHuman`, a previously minted `delegation_token` is rejected by
RFC 9068 validation before its TTL" — inherited from the spec as if a harness
exists. Verified: `WithAgentDelegationGrant` appears in no `_test.go` except a
comment (`agentidentity/grant_test.go:22`); no `test/` file exercises
`grant_type=urn:snaplink:params:oauth:grant-type:delegation` over the wire;
the `agentidentity` unit tests assemble `testDeps` directly and never compose
through `interfaces/sso`. The improvement's flagship claim — a revoked human
session kills already-minted agent tokens — has no precedent fixture to
extend. The `token_exchange_chain_policy_test.go` harness covers the exchange
grant only.

- **Exact test to add** (`test/`, new file or extension of
  `token_exchange_chain_policy_test.go`): new harness wiring
  `sso.WithAgentDelegationGrant(memProvider, memSessions, entitlementsFunc)` +
  `sso.WithTokenExchangeChainStore(memory.NewChainStore())` + a real issuer;
  mint a delegation token over the wire; extract jti; call
  `agentidentity.RevokeAllForHuman` against the wired session store; then
  assert the minted token fails `Validate` (resource-server path or direct
  issuer) while its `exp` is still in the future.
- **Acceptance assertion**: validation rejects the minted token before TTL;
  the mint audit event carries the jti; `GetChain(jti)` returns the hop with
  `SubjectID == agent.ID`, `ActorSubject == human`, `SessionID` set. This is
  the E2E tripwire for Decisions 2 + 3 + 6 combined.

### F3 — Medium — the cascade runs before the 200 is written; the design's oracle-safety wording is wrong and the timing channel is unmeasured

Verified: `HandleRevoke` executes `revokeAccess` (:99-100, where the cascade
would live) and only then `ctx.JSON(200)` (:111). The property that holds is "the
200 is decided and unalterable by the cascade", not "written before it" — the
design text ("written by the existing path before/independent of the
cascade", D5 pinned semantics) is factually wrong and must be corrected. The
in-band cascade also widens the pre-existing known-vs-unknown-token timing
channel by up to ~1000 sqlite queries (one `getChildren` per visited node +
up to 1000 × 3-issuer marks + durable persist + bus publish) on a public
credential endpoint. Both the protocol (F6/F3) and security (finding 2)
reviews agree. The QA obligation: the design must either bound the
side-effect or move the durable/bus legs off the request path, and the E2E
must assert a latency bound so the channel cannot silently regress.

- **Exact test to add**: `test/` — build a subtree of N=500 descendants via
  the exchange grant (harness exists), revoke the root at `/token/revoke`,
  assert completion within a stated bound (e.g. < 2s for 500 hops, chosen
  from a measured baseline, asserted as a generous ceiling); plus a unit test
  that a failing cascade still returns 200 and the response body is
  byte-identical to the unwired case.
- **Acceptance assertion**: response body identical to unwired; elapsed time
  within the stated bound; failure audit event emitted with partial list.

### F4 — Medium — cross-tenant cascade blast radius is untested and the design is silent on scoping

The security review's finding 1 is confirmed testable: `/token/revoke` never
binds the presented token to the authenticating client (pre-existing), the
cascade walks the pure `parent_jti` graph with no `ClientID`/tenant filter
(`ChainHop` has no tenant field), and cross-tenant exchange is a live,
tested feature (`EventCrossTenantTokenExchange`,
`test/cross_tenant_collaboration_test.go`). A tenant-A client revoking a root
token would cascade-kill tenant-B descendants minted from it. The design's D5
pins no scoping and D10 lists no cross-tenant risk.

- **Exact test to add** (`test/`, extending the cross-tenant harness):
  tenant-A client exchanges into a token, tenant-B client exchanges THAT into
  a descendant (cross-tenant hop recorded), tenant-A revokes the root at
  `/token/revoke`; assert the tenant-B descendant is either (a) NOT killed
  (if the design adopts client/tenant scoping for the cascade) or (b) killed
  and this is documented + audited as intended. The test forces the decision.
- **Acceptance assertion**: whichever the design pins, the audit trail
  records the full killed set with tenant attribution; the admin revoke
  endpoint remains the break-glass that CAN cross tenants (documented).

### F5 — Medium — jti-kill introspection-cache staleness has no declared residual window and no regression pin

The token path point-evicts (`InvalidateIntrospectionCache`,
`handle_revoke.go`), but a jti kill has no token string (D2 rejects the
index), so neither the admin root kill nor any cascade descendant can be
evicted: `/token/introspect` answers `active:true` for a cascade-killed token
for up to cache TTL. Enforcement on the RS/validation path is immediate; the
introspect path is not. The protocol review (F2) flags the same. This is
cache-contract-consistent, but it must be a declared residual window with a
regression test that documents it (so a future "fix" can't silently change
the contract either way).

- **Exact test to add**: wire the introspection cache, jti-kill a token via
  the wired `expire`, introspect within TTL → `active:true` (documented
  behavior); after TTL/eviction → `active:false`.
- **Acceptance assertion**: the test is annotated as documenting the residual
  window; the endpoint contract (OpenAPI description) states the bound.

### F6 — Medium — the expire-closure fallback home is infeasible: `server_token_clientauth.go` has 17 lines of headroom

`wc -l`: `server_token_clientauth.go` = 483/500. The design's D4 fallback
("if the closure plus mounts exceed it, the closure moves to
`server_token_clientauth.go`") cannot hold a 3-leg closure (issuer marks +
durable persist + bus publish + error/metric handling, realistically 30-40
lines) without blowing the compile-enforced `TestMaintainability_` gate.
`accessors_threat.go` (427/500, 73 lines) is also tight once mounts + 2
accessors + the closure land. The security review independently measured the
same. QA angle: this is a gate risk, not a test gap — the acceptance steps 4
and 5 cannot run until the closure has a real home.

- **Exact remediation**: budget the closure against BOTH files before
  implementation (`wc -l` per edit, per AGENTS.md); if either overflows, the
  closure is a separate small file in `interfaces/sso` (the package has
  non-test file headroom at the directory level — verify with the fan-out
  gate) or split across the two files as the security review suggests.
- **Acceptance assertion**: `go test -run 'TestMaintainability_|TestArchitecture_' .`
  green after every edit; no new `layerExemptions` entry.

### F7 — Medium — the pre-v2 legacy-row path (permanently poisoned cascades) is untested and the operational consequence is unstated

`ALTER TABLE ... DEFAULT 0` means every hop recorded before the upgrade has
`ExpiresAt == 0`, and D3 pins abort-on-zero (`ErrHopMissingExpiry`). A
pre-upgrade root is then permanently un-revokable from the admin surface
(admin holds only a jti; the per-token path is unreachable) and any legacy hop
inside a subtree 500s the whole cascade forever (rows are append-only).
The pin is right (never deny-for-zero), but the design ships a migration
without a migration test, and the endpoint contract doesn't state that the
new surface applies only to post-upgrade mints. Protocol (F5) and DS (F-3)
reviews agree.

- **Exact test to add**: build a store at schema v1 (insert a v1 row with the
  v1 SQL), run the v2 migration (the real `migrate.Run` path), assert the
  legacy row reads back with `ExpiresAt == 0` and that
  `RevokeRootAndDescendants` over it returns `ErrHopMissingExpiry` with a
  partial/empty list; assert the admin revoke surfaces the 500 + failure
  audit, not a silent deny.
- **Acceptance assertion**: `ErrHopMissingExpiry` propagates; error-code doc
  entry + endpoint contract carry the post-upgrade-only note.

### F8 — Medium — the jti bus event's `exp` is trusted as-is; a bad value prunes the deny immediately, and no test pins the adoption behavior

The token arm's safety net is re-derivation ("the receiver never trusts this
value over the token's own claim", `bus.go:170`) — a jti-only payload has no
token to re-derive from, so the DS review's F-2 holds: a garbage/zero `exp`
adopts a deny entry that `pruneRevoked` drops on the next sweep, silently
un-revoking a peer's cascade. The design (D8) doesn't pin the receiver
behavior for malformed `exp`, and no acceptance test exists.

- **Exact test to add**: `TestApplyTokenRevocation_JTI`-style — publish
  `KindTokenRevokedJTI` with (a) valid exp, (b) missing exp, (c) non-numeric
  exp, (d) exp in the past; assert the adopted deny entry survives per the
  pinned rule (e.g. reject-then-fail-closed, or floor the TTL), and that
  adoption never re-publishes (no broadcast loop) and counts metrics.
- **Acceptance assertion**: a malformed-`exp` event can never produce a
  deny entry that is pruned before the receiver's next re-seed; the behavior
  is documented on the bus kind const.

### F9 — Low — the new orchestrator lands in the lowest-coverage package with no planned direct tests

`domains/tokenexchange` root package coverage is 34.5% (measured this
revision) — `chainstore.go`'s fail-open helpers are thin and mostly exercised
via `test/`, but `RevokeRootAndDescendants` (root expire + cascade +
combined list + error joins) and `walkDescendants` are new, non-trivial,
fail-closed logic. The acceptance table tests the walk via `RevokeDescendants`
but never composes `RevokeRootAndDescendants` at the unit level (admin
handler tests will cover it indirectly, but the error-join + partial-list
semantics deserve direct tests in both backends).

- **Exact test to add** (`domains/tokenexchange/...`): root hop with a
  descendant; failing `expire` on the root → partial list == nil + error;
  failing `expire` on the 2nd descendant → partial list == [root, first
  descendant] + error (order pinned); unknown root jti → empty + nil error.
- **Acceptance assertion**: partial-list ordering and error wrapping match
  the D1 contract in both backends.

### F10 — Low — "indexed query" claims are unasserted

D1/D3 claim the sqlite walk uses `idx_tokenexchange_chain_hops_parent` and
`HopsBySession` is an indexed `WHERE session_id` query. No existing test
asserts index usage or even index existence (schema test only checks
version). A future schema edit could drop the index and degrade the cascade
to a full scan with all tests green.

- **Exact test to add**: extend `TestChainStoreMaxVersion_MatchesLiveSchema`
  or add a schema test asserting `idx_tokenexchange_chain_hops_parent` and
  `idx_tokenexchange_chain_hops_session` exist; optionally an
  `EXPLAIN QUERY PLAN` assertion on the `HopsBySession` query.
- **Acceptance assertion**: both indexes present at max schema version;
  `HopsBySession` plan uses the session index.

### F11 — Info — pre-existing OpenAPI `subject_token_type` enum drift must ride along (docs discipline, AGENTS.md §5)

`docs/openapi.yaml:12482-12487` lists `refresh_token` and `txn-token` as
`subject_token_type` values; code accepts only access_token/jwt/id_token
(`token_exchange_stages.go:62-66`); `txn-token` is valid only via the RFC 9321
dispatcher keyed on `requested_token_type`. A client generator following
OpenAPI gets `invalid_request`. Fix in the same change that adds the two
admin routes: drop `refresh_token` (no code path), keep `txn-token` with its
RFC 9321-scoped description. Protocol review F4 agrees. Docs-only; no test
change (the code side is already pinned by `tokExValidateRequestTypes`).

### F12 — Info — `make ci` is blocked by two pre-existing fmt failures unrelated to this design

`gofmt -l .` flags `infrastructure/defaultimpl/sqlite/refresh_tokens_schema.go`
(modified, unrelated in-progress work) and `test/region_token_contract_test.go`
(untracked — flagged in the direction-3 QA review and still unfixed). The
design changed no `.go`, so handoff is unaffected, but exit-criteria `make ci`
cannot reach vet/race/examples/proto-lint/route-contract/docs gates until
these are formatted (with authorization, per AGENTS.md). Also: any new E2E
must be named `TestE2E_*` or `-run TestE2E` will not execute it.

## 4. Prioritized scenario list

P0 = acceptance-blocking for the three improvements; P1 = invariant guards;
P2 = hardening.

**Happy path (P0)**
1. **Keystone tripwire (D10.1)**: wire `expire` → `RevokeByJTI` on all 3
   issuers → `Validate` a real token carrying that jti → rejected on Ed25519,
   ECDSA, RSA; accepted after exp; foreign jti is a clean no-op per issuer
   (extend `Test{Ed25519,ECDSA,RSA}Revoke_HonoredUpToExp`).
2. `RevokeDescendants` 3-hop root→a→b: a,b marked; sibling subtree untouched;
   idempotent re-run; injected `expire` error → partial + error (memory +
   sqlite).
3. Admin GET descendants: bounded (`?limit` 100 default, cap 1000), newest
   first, known-jti-empty → 200 `[]`, unknown → 404, unwired → not mounted.
4. Admin POST revoke: 200 + root-first list + success audit; 500 + partial
   body + failure audit; 501 non-revoker; scope gating read/write.
5. `/token/revoke` wired: root revoke kills descendant before TTL (E2E,
   harness exists); oracle suite byte-identical; unknown/opaque → no cascade.
6. Delegation mint hop: `SessionID`/`JTI`/`SubjectID=agent`/`ActorSubject=
   human`/depth 1; audit carries jti (F2 harness — net-new).
7. `RevokeSession`/`RevokeAllForHuman` cascade: per-session isolation,
   per-human cohort, failing cascade audited while session revoke applies,
   `opts==nil` byte-identical.

**Boundary (P0/P1)**
8. Truncation: 1001-hop chain + cyclic graph → `ErrChainWalkTruncated` on
   `RevokeDescendants`; `GetDescendants` keeps its current return-rows
   contract.
9. `HopsBySession` cap: >1000 hops on one session → cascade fails closed with
   partial list (F1 — forces the design decision).
10. `ExpiresAt == 0` (pre-v2 row): `ErrHopMissingExpiry` abort; migration v1→v2
    round-trip (F7).
11. JTI store: restart survival (memory + sqlite), nil-store seed no-op,
    prune-not-early.
12. Bus: `KindTokenRevokedJTI` wire format; valid/missing/garbage/past `exp`
    adoption (F8); no re-publish; mixed-version default-arm drop; late-join
    re-seed.
13. `RevokeRootAndDescendants` unit: error-join ordering + partial lists (F9).

**Error (P1)**
14. Cascade with failing issuer mark → abort + partial (fail-closed); failing
    durable persist/bus publish → logged + metric, mark stands (fail-open).
15. `/token/revoke` cascade error → 200 preserved, byte-identical body,
    failure audit (F3).
16. Cross-tenant cascade blast radius (F4 — forces scoping decision).
17. Reseed failure at boot → replica stays degraded (extend existing pattern).

**Race (P1)**
18. `-race -count=10+`: concurrent cascades over one subtree; concurrent
    revoke + `Validate` on the same jti (deny maps under existing
    `revokedMu`); concurrent admin revokes (idempotent marks).
19. Revoke-during-mint: hop recorded mid-walk escapes the current cascade —
    pinned as documented (next cascade/expiry covers it); assert no panic/race.

**Recovery (P1/P2)**
20. Restart with sqlite `JTIRevocationStore`: deny survives; late-joining
    replica converges via boot seed.
21. Introspection cache: jti-killed token still `active:true` within TTL —
    documented-behavior regression pin (F5).
22. Oracle no-store headers: credential endpoints unchanged; new admin routes
    are not credential surfaces (401 stays `Bearer realm="admin"`).

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**CI gaps**
- `make ci` fmt gate blocked by two pre-existing unformatted files (F12).
- No delegation-grant composition test exists anywhere — F2's harness is the
  first; without it, Improvement 3 ships with unit-only proof and the
  direction's flagship E2E claim is untested.
- No test asserts a `HopsBySession` truncation signal (F1) — the design's own
  fail-closed rule is unenforced at the session boundary.
- No latency/behavior bound test for the in-band `/token/revoke` cascade
  (F3); no cross-tenant cascade test (F4).
- `domains/tokenexchange` root package at 34.5% coverage — the new
  orchestrator must land with direct tests (F9), not only admin-handler
  coverage.
- `docs/openapi.yaml` enum drift is pre-existing; the docs change for the two
  new routes must fix it in the same commit (F11) or `docs-validate`-style
  review will keep flagging a wire contract that lies.

**Flake risks**
- The sqlite truncation tests (1001 rows) and the E2E "before TTL" tests must
  use deterministic time (the harness issuer uses `time.Minute` TTL — mint,
  revoke, assert within the window; no sleeps; the walk tests seed
  `RecordedAt` explicitly as the existing tests do).
- The `-race -count=10+` concurrent-cascade tests must assert final state
  (all marks present), never intermediate counts — marks are set-inserts.
- The timing-bound test (F3) must assert a generous ceiling (e.g. 2s for 500
  hops) to avoid CI flake on loaded runners; the meaningful assertion is
  "bounded and non-quadratic", not a tight constant.
- E2E additions must be named `TestE2E_*` or the design's own verification
  line will not run them (F12).

**Fixtures needed (all in-repo; no mocks)**
- `newTokenExchangeChainPolicyHarness` (`test/token_exchange_chain_policy_test.go`)
  — extend for the `/token/revoke` descendant-rejection E2E and the admin
  route E2E (already wires a real Ed25519 issuer + memory ChainStore).
- **Net-new**: delegation-grant harness (F2) — `WithAgentDelegationGrant` +
  `WithTokenExchangeChainStore` + real issuer over `httptest`.
- `revocation_set_test.go` unexported-map accessor pattern — extend for
  `jtiRevoked`; `Test{Ed25519,ECDSA,RSA}Revoke_HonoredUpToExp` — jti variants.
- `cross_replica_test.go` wire-format + adoption patterns — `KindTokenRevokedJTI`
  variants (F8).
- `cross_tenant_collaboration_test.go` harness — cross-tenant cascade
  blast-radius test (F4).
- `revoke_test.go`/`grant_test.go` (`agentidentity`) — `testDeps` gains the
  `chainStoreProvider` capability; real memory stores.
- Migration fixture: a v1-schema DB file or v1 SQL exec before `migrate.Run`
  (F7).

**Exit criteria for the design's landing**
1. F1 pinned: `HopsBySession` returns a truncation signal (or the design
   explicitly accepts and documents silent capping — the test forces the
   decision), and the >1000-hop session-cascade test asserts fail-closed
   behavior with a partial list.
2. F2 green: delegation E2E — minted `delegation_token` rejected before TTL
   after `RevokeAllForHuman`; mint audit carries jti; hop fields match the D6
   pin.
3. Keystone green on all 3 issuers: `expire`-marked jti rejected by
   `Validate` before exp (P0 scenario 1); unwired-store byte-identical
   regression; E2E descendant rejection.
4. Oracle suite unchanged: `handle_revoke_test.go` green without edits;
   `/token/revoke` wired-store test proves 200-identity + descendant kill.
5. F3: design text corrected ("decided", not "written"); cascade work bounded
   or moved off-request-path; timing-bound test green.
6. F4 decision made + tested: cross-tenant cascade scoped or documented.
7. Migration test (F7): v1→v2 with `ErrHopMissingExpiry` abort + error-code
   doc note.
8. Docs in the same commit: openapi (2 routes + enum drift fix F11),
   error-codes (`ErrChainWalkTruncated`, `ErrHopMissingExpiry`, 501 code),
   observability (3 event types + classification), feature-matrix.
9. Gates: `go build ./... && go vet ./...`; `go test -run
   'TestMaintainability_|TestArchitecture_' .` green after EVERY edit (F6
   budget checks per edit); `-race -count=10+` on all touched packages;
   `go test ./test/ -run TestE2E -v` incl. new `TestE2E_*`; `make ci` green
   after the pre-existing fmt blockers are resolved (F12, with
   authorization).

**Verdict**: the design is sound against the source — every evidence claim
re-verified, and its test-planning instinct (real memory implementations,
extend-don't-break fakes, E2E tripwires) matches the codebase's strongest
suites. Two High findings are test-plan completeness issues with a design
decision embedded (F1: the session-cascade truncation contract; F2: the
missing delegation harness — the single biggest gap between the spec's
integration acceptance and any executable test today). F3/F4 are design
decisions the QA plan forces (cascade cost bound; cross-tenant scoping). The
keystone, D1's cascade, and the oracle boundaries all have existing test
patterns to extend — the direction is testable with in-repo fixtures plus one
new harness.
