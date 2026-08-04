# Feature Spec: domains/tokenexchange — Direction 1: 委托链级联撤销（ChainStore 升级为撤销控制面）

Scope: expansion direction 1 from `docs/auto/domains-tokenexchange-analysis.md`.
ChainStore moves from append-only observability to a fail-closed revocation
control plane. Wire contracts (oracle-safe `invalid_grant` collapse,
`/token/revoke` 200-always) are regression boundaries and stay intact.

- Surface: stock `sso-server` admin API + `tokenexchange` SPI + `agentidentity`
- Default: opt-in wiring (nil store = byte-identical no-op, per existing
  `WithTokenExchangeChainStore` contract)
- Non-goals: cycle detection / depth cap changes (unchanged in-request
  enforcement in `internal/handler/tokengrant`); policy-rule operations
  (analysis direction 2); audit deny-event backlog (direction 3, except the
  jti correlation key improvement 3 needs)
- Classification: store implementation + admin endpoint + audit/observability

## Improvement 1: RevokeDescendants — fail-closed cascade revocation primitive on ChainStore

**Name**: `ChainStore.RevokeDescendants(ctx, rootJTI, ...)` fail-closed
cascade primitive consuming the existing forward-walk data plane.

**Problem**: `ChainStore` is deliberately scoped as append-only observability
("no cascade-revocation ... scoped deliberately narrower than those, as
follow-on work"), so the one response action the RFC 8693 threat model
demands — "this token became what, kill all of it" — has no code path. The
forward traversal already exists and is fully implemented in both backends,
but has **zero production callers**: the entire data plane for cascade
revocation is built and unused. Revocation today is per-token only, blind to
derivation.

**Evidence**:
- `domains/tokenexchange/chainstore.go` — `ChainHop` doc self-limitation
  ("no cascade-revocation ... as follow-on work"); `ChainStore` interface
  exposes only `RecordHop` / `GetChain` / `GetDescendants` (read-only).
- `domains/tokenexchange/sqlite/chain_store.go:185` and
  `domains/tokenexchange/memory/chain_store.go:82` — BFS forward walk over the
  parent index (`idx_tokenexchange_chain_hops_parent`) fully implemented;
  `grep -rn GetDescendants --include='*.go' .` finds callers only in
  `test/token_exchange_chain_store_test.go` and package `_test.go` files.
- `protocols/oauth/handle_revoke.go:152` (`revokeAccess`) — per-token
  revocation via `RevokeAcrossIssuers`; no chain awareness.

**Proposed behavior**:
- Add a fail-closed revocation primitive to the SPI. Prefer an OPTIONAL
  extension interface (e.g. `ChainRevoker`) implemented by both backends so
  the existing `ChainStore` read contract stays untouched:
  `RevokeDescendants(ctx, rootJTI string, expire func(ctx, jti string) error) (revoked []ChainHop, err error)`.
- Semantics: walk `GetDescendants` (BFS, bounded by the same walk caps), and
  for each descendant hop JTI call `expire` to mark it in a JTI deny store
  (the `security.JTIReplayStore` family / revocation deny-set) with the
  descendant token's remaining lifetime. RFC 9068 access-token validation
  consults the deny set, so a marked JTI is rejected before TTL.
- Fail-closed (AGENTS.md §3): a walk or `expire` error ABORTS the cascade and
  returns the error; partial revocation is never silently dropped — the
  caller audits `revoked` + the error. Idempotent: a second call over an
  already-marked subtree is a no-op success. `rootJTI` itself is not killed
  by this primitive (callers kill the root via the existing per-token path).
- Nil store / unwired: no-op, byte-identical to today.

**Acceptance check**:
- Unit (memory + sqlite): 3-hop chain root→a→b — `RevokeDescendants(root)`
  marks a and b only (an unrelated sibling subtree untouched); second call
  idempotent; injected `expire` error propagates and returns the partial
  `revoked` list for audit; concurrent cascade calls race-clean
  (`-race`, `-count=10+`).
- Sqlite test proves the walk uses the existing parent index and respects
  `maxChainWalk` bounds.
- Gate: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .` pass; the
  `ChainStore` interface itself gains no new method (extension interface
  only), so existing fake stores in `test/` keep compiling.

## Improvement 2: Admin control surface — descendants view + one-click cascade revoke

**Name**: Admin end-to-end revocation entry
(`GET .../descendants` + `POST .../revoke` on the existing chain route), with
a chain-aware opt-in side-effect on `/token/revoke`.

**Problem**: The admin surface exposes only the ancestor query
(`HandleTokenExchangeChain` → `GetChain`), so an operator who identifies a
compromised root token can SEE where it came from but not what it became, and
has no supported action beyond revoking the single presented token. The
"break-glass leakage / service-A-impersonates-B" scenario needs a
revoke-root-kills-descendants primitive reachable in one audited admin call;
today the response time is manual per-token hunting.

**Evidence**:
- `interfaces/admin/lifecycle.go:109` (`HandleTokenExchangeChain`) — only
  `store.GetChain(ctx, jti)`, returns 404 on unknown jti; no descendants
  surface, no write operation.
- `interfaces/sso/accessors_threat.go` (`WithTokenExchangeChainStore` /
  `mountAdminTokenExchangeChainRoutes`) — only
  `GET /api/v1/admin/tokenexchange/chains/:jti` mounted, `admin:read`.
- `protocols/oauth/handle_revoke.go:152` (`revokeAccess`) — `/token/revoke`
  kills exactly the presented token; no chain awareness.

**Proposed behavior**:
- `GET /api/v1/admin/tokenexchange/chains/:jti/descendants` (`admin:read`):
  `GetDescendants(jti, limit)` with a bounded positive limit (the interface
  doc already mandates this for admin surfaces); 404 when the jti is unknown.
- `POST /api/v1/admin/tokenexchange/chains/:jti/revoke` (`admin:write`):
  runs the Improvement-1 cascade and returns `{revoked: [...JTIs]}`; on walk
  failure returns 500 with partial `revoked` list in the body AND in audit —
  never a silent partial success.
- New audit event type(s) (e.g. `EventTokenExchangeChainRevoked`,
  `EventTokenExchangeChainRevokeFailed`) registered in
  `platform/audit/auditspi/event_types.go` and classified in `auditreport`,
  carrying root JTI, revoked JTI list, admin actor, and the failure reason —
  the oracle-safe channel for "why" (AGENTS.md §3). Admin mutations must also
  invalidate the cross-replica revocation cache/deny-set per the
  invalidation-bus invariant.
- `/token/revoke` keeps its wire contract byte-identical (200 always,
  idempotent, oracle-safe) but, when a ChainRevoker is wired, invoking it on
  the presented token's jti cascades to descendants as a side-effect before
  the 200. Unwired: exactly today's behavior.
- Routes mount only when a ChainStore is wired (existing mount pattern);
  admin 401 identifies `Bearer realm="admin"`.

**Acceptance check**:
- `interfaces/admin` handler tests in the
  `tokenexchange_chains_test.go` pattern: descendants listing bounded and
  ordered newest-first; revoke returns killed JTIs; unknown jti → 404;
  failing walk → 500 with partial list; unwired store → endpoint not mounted.
- Audit assertions: revoke emits the new event with admin actor + full
  revoked list; failure event carries the error and partial list.
- `/token/revoke` oracle tests still pass (200 for unknown/consumed/mismatched
  token, credentials-only), and a wired-store test proves a root revoke at
  `/token/revoke` invalidates a descendant's access token before its TTL.

## Improvement 3: Agent delegation joins the chain — session revocation cascades to already-minted agent tokens

**Name**: `mintDelegationToken` records ChainHops (with session link + jti in
audit); `RevokeSession` / `RevokeAllForHuman` cascade-revoke minted tokens.

**Problem**: `agentidentity` revocation is next-mint-only: it kills the
session's ability to mint again but already-issued `delegation_token`s stay
valid until TTL. And the chain data plane is blind to agent delegations —
`mintDelegationToken` never records a `ChainHop`, so a revoked human
session's previously minted agent tokens are neither visible in the chain nor
reachable by any cascade. The delegation trail's mint audit also omits the
minted token's `jti`, so no hop can be correlated back to its issuing
session. This is the gap that makes improvement 1/2 useless for the most
common delegation primitive (human → agent).

**Evidence**:
- `domains/tokenexchange/agentidentity/agent.go:43` — "any one of the three
  narrowing (an operator tightening an agent's policy, a revoked session, or
  the human losing a permission) narrows or kills the token on its very NEXT
  mint".
- `domains/tokenexchange/agentidentity/revoke.go:17,28` — `RevokeSession` /
  `RevokeAllForHuman` touch only `AgentSessionStore`; no token-level effect.
- `domains/tokenexchange/agentidentity/grant.go:200,213` — mint success path
  calls `auditDelegationMint` only; the sole production
  `RecordExchangeHopFailOpen` call site is
  `internal/handler/tokengrant/token_exchange.go:227`, so agent mints never
  appear in `GetChain`/`GetDescendants`.
- `domains/tokenexchange/chainstore.go` — `ChainHop` has 7 fields, no session
  reference; `auditDelegationMint` (`grant.go:213`) records session id and
  scopes but not the minted jti.

**Proposed behavior**:
- `ChainHop` gains an optional `SessionID` field (omitempty; set only by the
  agent mint path, never by the token-exchange handler — the natural
  parent-key for a delegation mint that has no `ParentJTI`).
- `mintDelegationToken`'s success path calls `RecordExchangeHopFailOpen`
  (or a sibling assembly) with the minted token's jti, subject = human,
  actor = agent, client, chain depth, and session id — fail-open as always
  (a store error never fails the mint). `auditDelegationMint` additionally
  records the minted jti so logs ↔ chain ↔ token correlate.
- `RevokeAllForHuman` (and `RevokeSession`) gains an optional cascade step:
  when a ChainRevoker is wired, look up hops by session id, mark their JTIs
  in the deny set (Improvement 1 primitive), and audit the killed set — the
  revocation audit event's outcome reflects cascade failures (fail-closed
  reporting, store-side session revocation still applies regardless).
- Unwired: `RevokeSession`/`RevokeAllForHuman` behavior is byte-identical to
  today (nil store = no cascade, no new audit events).

**Acceptance check**:
- Unit (`agentidentity` + memory store): mint records a ChainHop whose
  `SessionID`/`JTI` match; `RevokeAllForHuman` marks every minted jti for the
  human's sessions and none for another human's; `RevokeSession` marks only
  that session's tokens; failing cascade is audited and reported while the
  session revocation itself still succeeds; nil store → no cascade, no new
  events.
- Integration (`test/`, package `ssotest`): after
  `RevokeAllForHuman`, a previously minted `delegation_token` is rejected by
  RFC 9068 validation before its TTL; the mint audit event carries the jti.
- Wire contract: mint responses and `/token` oracle behavior unchanged
  (fail-open chain recording); gates pass including
  `go test ./... -race` and `make ci`.
