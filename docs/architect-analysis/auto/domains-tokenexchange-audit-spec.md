# Requirements Specification: `domains/tokenexchange` audit observability

Source baseline: `docs/auto/domains-tokenexchange-analysis.md`, expansion
direction 3 — 委托决策的审计盲区：deny 事件缺失 + 令牌↔授权会话不可反查.
Scope: exactly 3 evidence-backed improvements. Every claim below was verified
against the current tree.

Governing contracts (AGENTS.md §3/§4/§5): token-exchange failures collapse to
one wire `invalid_grant` and the internal cause belongs in audit, not on the
wire (oracle-safe discipline, `docs/error-codes.md` token-endpoint table);
audit metadata is added only via `audit.SetMeta`; every new event type must be
registered in `auditspi.KnownEventTypes` and classified in `auditreport`
(CC6.1 access control already hosts `EventCrossTenantTokenExchange` +
`EventAgentDelegationTokenIssued`), enforced by `auditreport/drift_test.go`.

## 1. Emit a dedicated token-exchange deny audit event (`token_exchange_denied`)

### Problem

The hop-authorization gate — the module's entire reason to exist — is a
SIEM blind spot. `tokExEnforcePolicy` denies (explicit rule deny AND
policy-evaluation error, both fail-closed) with only a server log line; no
audit event is emitted. AGENTS.md §3 requires wire failures to collapse to
`invalid_grant` with the cause carried "only in audit", and the audit
catalogue already provides deny-event precedents (`mfa_failure`,
`device_code_denied`, `ciba_denied`) — but there is no token-exchange deny
event at all, so "who tried to act as whom, and which rule blocked it" is
unqueryable in SIEM. The audit layer, not the wire, is the designated carrier
of deny reasons.

### Evidence

- `internal/handler/tokengrant/token_exchange.go:373-398` (`tokExEnforcePolicy`):
  deny path is `d.SrvLogger().Error("token exchange policy evaluation failed;
  denying (fail-closed)", ...)` (line 391) followed by
  `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))`
  (line 396). No `d.Auditor()` call anywhere in the function.
- `platform/audit/auditspi/event_types.go:179-181` — the only token-exchange
  events are `EventCrossTenantTokenExchange` (success-only) and
  `EventSPIFFEJWTSVIDAccepted` (success-only); the `KnownEventTypes` catalogue
  (lines 230-330) contains no token-exchange deny class.
- `platform/audit/recorder_events.go:78-95` (`RecordDeviceCodeDecision`) —
  the established deny-event pattern: `Outcome = OutcomeFailure`,
  `SetMeta` for the decision context; the event is the carrier while the wire
  stays oracle-collapsed.
- `docs/error-codes.md:290` — `/token` `invalid_grant` row: "collapses every
  sensitive cause into one wire response (oracle-leak hardening)"; the
  cross-tenant paragraph (line 278) shows the contract style: internal reason
  lives in an audit event, never on the wire.
- `platform/audit/auditspi/event.go:42-44` — `Event` already promotes
  first-class, SQLite-sink-indexed `SessionID` / `TokenID` / `Reason` fields,
  exactly sized for this event.
- `domains/tokenexchange/tokenexchange.go:50-58` — `Policy.Allow(ctx, Hop)
  (bool, error)` carries NO deny reason; the matched rule name is only
  recoverable inside a `Rule`-driven implementation (`memory.Store`,
  `tokenexchange.go:74-84` `Evaluate`), so the handler needs an optional
  capability hook (codebase precedent: optional type-asserted
  `FacetQuerier`, `docs/observability.md:76`).

### Proposed behavior

1. New constant `EventTokenExchangeDenied EventType = "token_exchange_denied"`
   in `platform/audit/auditspi/event_types.go`; register in `KnownEventTypes`;
   classify in `auditreport/control_areas.go` under CC6.1 (access control),
   next to `EventCrossTenantTokenExchange`.
2. In `tokExEnforcePolicy`, on BOTH terminal outcomes (`err != nil` and
   `!allow`), record a fail-open audit event (nil `Auditor` = no-op; a
   recorder error never changes the already-decided `invalid_grant`
   response), mirroring `tokExAuditCrossTenant`:
   - `Type=EventTokenExchangeDenied`, `Outcome=OutcomeFailure`,
     `ActorID=st.actor.Subject` (fallback `st.claims.Subject`),
     `ClientID=client.ID`, `ActorIP=audit.ClientIP(ctx.Request())`;
   - first-class correlation fields: `TokenID=st.claims.JTI` (the
     subject_token being exchanged — no new token exists on deny),
     `SessionID=st.claims.SID` (the authorization session the chain is
     anchored to), `Reason` = fixed bounded vocabulary
     (`"policy_denied"` | `"policy_error"`);
   - `audit.SetMeta` only (AGENTS.md §4): `scope` (space-joined `st.scopes`),
     `resource` (space-joined `st.resources`), `requested_token_type`,
     `subject_id`, `actor_subject`, and `rule` (matched rule name when
     available — see 3).
3. Optional deny-reason capability so "命中规则" reaches the audit without
   breaking the SPI: add to `domains/tokenexchange` an optional interface
   (e.g. `DenyReasoner { DenyReason(ctx, Hop) string }`), type-asserted at
   the call site like `FacetQuerier`; `memory.Store` implements it by
   returning the first matching rule's `Name` (`Evaluate` already computes
   the match). Unimplemented or no-match falls back to the fixed
   `"policy_denied"` vocabulary — bounded cardinality preserved
   (AGENTS.md §4).
4. Wire response stays byte-identical `400 invalid_grant` for every deny
   class; `docs/error-codes.md` token-endpoint section gains the
   audit-event contract note in the same change (AGENTS.md §5).

### Acceptance check

- Unit/integration test (extend `test/token_exchange_chain_policy_test.go`
  harness with a memory audit recorder): a `memory.Store` policy with a
  matching `Deny: true` rule yields exactly one event —
  `Type=EventTokenExchangeDenied`, `Outcome=Failure`, `TokenID` == subject
  token jti, `Reason="policy_denied"`, `rule` == the rule's `Name`,
  `ActorID` == actor subject — while the wire response is still
  `400 invalid_grant`.
- Policy returning `(false, err)` yields the same event with
  `Reason="policy_error"`; an unwired (nil) Policy emits no event.
- `go test ./platform/audit/auditreport/` drift tests
  (`TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`) pass with
  the new constant classified exactly once.

## 2. ChainHop carries scopes/resources/requested-token-type/session — token↔authorization-session reverse lookup at the chain layer

### Problem

A recorded hop answers "what produced token X" but not "with which
entitlements, and under which authorization session" — the two questions
incident response asks first about a suspicious delegated token. `ChainHop`
has only 7 fields and the SQLite schema mirrors them 1:1, so neither
`GetChain` nor `GetDescendants` can reconstruct the granted scopes, target
resources, requested token type, or the `sid` session anchor of a hop; the
token↔authorization-session link (`sid`, propagated unchanged through every
exchange hop per RFC 9068 §2.2) is dropped at the persistence boundary.

### Evidence

- `domains/tokenexchange/chainstore.go:31-68` — `ChainHop` fields are only
  `JTI`, `ParentJTI`, `SubjectID`, `ActorSubject`, `ClientID`, `ChainDepth`,
  `RecordedAt`; no scopes/resources/requested_token_type/session.
- `internal/handler/tokengrant/token_exchange.go:218-229`
  (`tokExRecordChainHop`) — the single production call site
  (`RecordExchangeHopFailOpen`, line 227; verified no other callers) passes
  only `st.token.AccessToken, st.claims.JTI, st.claims.Subject, st.actor,
  client.ID, actChainDepth(st.actor)` — while `st.scopes`/`st.resources`/
  `req.RequestedTokenType`/`st.claims.SID` are all already resolved on the
  `tokExState` at that point.
- `domains/tokenexchange/sqlite/chain_store.go:14-28` — `chainSchema` has the
  same 7 columns; `chainMigrations` is v1-baseline only; `scanHop` (lines
  277-292) scans exactly those 7.
- `test/handle_token_exchange_test.go:122-129`
  (`TestTokenExchange_PropagatesSIDToAccessToken`) — locks the invariant
  that the subject session's `sid` survives into every exchanged token, so
  `st.claims.SID` is the correct hop-level session anchor.
- `interfaces/admin/lifecycle.go:109` (`HandleTokenExchangeChain`) +
  `interfaces/sso/accessors_threat.go:158-187` — admin surface
  `GET /api/v1/admin/tokenexchange/chains/:jti` (admin:read) serializes
  `[]ChainHop` directly, so enriched hops surface without a new endpoint.

### Proposed behavior

1. Extend `ChainHop` with `Scopes []string` (`json:"scopes,omitempty"`),
   `Resources []string` (`json:"resources,omitempty"`),
   `RequestedTokenType string`, `SessionID string` (from `st.claims.SID`).
2. Extend `RecordExchangeHopFailOpen`'s parameters to carry
   scopes/resources/requestedTokenType/sessionID; update the one call site
   (`tokExRecordChainHop`) to pass `st.scopes`, `st.resources`,
   `req.RequestedTokenType`, `st.claims.SID`. Fail-open semantics and the
   JTI-less skip rule are unchanged.
3. SQLite: add migration v2 appending `scopes TEXT NOT NULL DEFAULT ''`,
   `resources TEXT NOT NULL DEFAULT ''`, `requested_token_type TEXT
   NOT NULL DEFAULT ''`, `session_id TEXT NOT NULL DEFAULT ''` (flat scalar
   columns per the package's documented column-not-JSON philosophy); encode
   scope/resource sets space-joined; update `RecordHop`, `scanHop`,
   `getHop`/`getChildren`; old rows read back with empty correlation fields.
   Memory backend needs no schema change (struct copy).
4. No `ChainStore` SPI method changes: reverse lookup is token(jti) →
   hop(session/scopes) through the existing `GetChain`/`GetDescendants`;
   session→tokens indexing is explicitly out of scope (belongs to the
   direction-1 cascade-revocation work, not this audit fix). Document the
   chain-endpoint hop schema where the endpoint is contracted (the endpoint
   currently has no `docs/openapi.yaml` entry — pre-existing drift; do not
   expand scope to fix it, report separately).

### Acceptance check

- Unit round-trip in `domains/tokenexchange/sqlite` and `.../memory`:
  `RecordHop` → `GetChain`/`GetDescendants` preserves Scopes/Resources/
  RequestedTokenType/SessionID exactly (space-join encoding is symmetric).
- Migration test: a v1-schema database upgrades to v2 via
  `migrate.Run` and pre-existing rows return empty correlation fields
  without error.
- Integration test in `test/`: perform a scoped exchange with an
  actor_token and a session-anchored subject; `GET
  /api/v1/admin/tokenexchange/chains/:jti` returns a hop whose `scopes`
  equals the granted scope set and whose `session_id` equals the propagated
  `sid`; `GetDescendants` rows carry the same fields.

## 3. Mint/issuance audit events carry the issued jti (+ session) — join key across token, audit, and chain

### Problem

Even with a deny event (decision 1) and enriched hops (decision 2), the
SUCCESS side of the audit trail cannot be joined to a specific token: the
agent-delegation mint audit records session ID and scopes but not the minted
token's `jti`, and the RFC 8693 exchange's success audit is the generic
`token_issued` event with no `jti`/`sid`/scope. A SIEM holding a suspicious
bearer token (e.g. from resource-server logs) cannot find the mint event,
and the mint event cannot be joined to `ChainStore` rows (keyed by jti) or
back to the authorization session. "令牌↔授权会话不可反查" fails at the
audit layer precisely because the mint audit lacks the one identifier that
ties all three records together.

### Evidence

- `domains/tokenexchange/agentidentity/grant.go:213-229`
  (`auditDelegationMint`) — emits `EventAgentDelegationTokenIssued` with
  `SetMeta(KeyOriginalSubject, ...)`, `SetMeta(MetaAgentSessionID, sess.ID)`,
  `SetMeta(KeyScope, ...)`; no jti anywhere. Call site
  `mintDelegationToken` (line 200) holds `token.AccessToken` — the jti is
  one `JTIFromJWTUnsafe` call away.
- `internal/handler/tokengrant/token_exchange_stages.go:376` —
  `d.RecordTokenIssued(ctx, client.ID, st.strategy, st.claims.Subject)` for
  every successful exchange; `platform/audit/recorder_events.go:22-29`
  (`RecordTokenIssued`) sets only Type/Outcome/ClientID/TokenStrategy/
  ActorID — no `TokenID`, no `SessionID`, no scope.
- `platform/audit/auditspi/event.go:42-43` — `TokenID`/`SessionID` are
  first-class indexed fields (SQLite sink), purpose-built for this join.
- `domains/tokenexchange/chainstore.go:216-240` — the chain record is keyed
  by the minted jti (`RecordExchangeHopFailOpen` derives it via
  `JTIFromJWTUnsafe`), so jti is the natural join key that already exists on
  the chain side; only the audit side is missing it.
- Precedent for a dedicated exchange event alongside the generic
  `token_issued`: `tokExAuditCrossTenant` emits
  `EventCrossTenantTokenExchange` in addition to `RecordTokenIssued`
  (`token_exchange.go:250-268`), and `EventNativeSSOExchange` /
  `EventNativeSSOExchangeFailure` form an existing success/failure pair.

### Proposed behavior

1. Agent-delegation mint: `mintDelegationToken` derives
   `jti := tokenexchange.JTIFromJWTUnsafe(token.AccessToken)` (subpackage →
   parent import is acyclic; the parent never imports `agentidentity`) and
   passes it into `auditDelegationMint`, which sets first-class
   `evt.TokenID = jti` and `evt.SessionID = sess.ID` (indexed reverse-lookup
   fields), KEEPING the existing `SetMeta` keys unchanged so existing
   audit consumers stay wire-compatible.
2. RFC 8693 exchange issuance: new constant
   `EventTokenExchangeIssued EventType = "token_exchange_issued"`, emitted
   at the same point as `tokExRecordChainHop` (after the mint, fail-open,
   nil `Auditor` = no-op): `Outcome=Success`, `ActorID=st.claims.Subject`,
   `ClientID=client.ID`, `TokenID=JTIFromJWTUnsafe(st.token.AccessToken)`,
   `SessionID=st.claims.SID`, `SetMeta` for `scope`, `resource`,
   `parent_jti` (= `st.claims.JTI`), `actor_subject`,
   `requested_token_type`. The generic `token_issued` event and its shared
   helper stay untouched (no cross-grant blast radius).
3. Register both events in `auditspi.KnownEventTypes` and classify in
   `auditreport` CC6.1; add the audit-event contract notes to
   `docs/error-codes.md` in the same change (AGENTS.md §5).

### Acceptance check

- `domains/tokenexchange/agentidentity` test: the mint audit event carries
  `TokenID == tokenexchange.JTIFromJWTUnsafe(issued access token)` and
  `SessionID == AgentSession.ID`, with the pre-existing metadata keys
  unchanged.
- `test/handle_token_exchange_test.go` extension: a successful exchange
  emits exactly one `EventTokenExchangeIssued` whose `TokenID` equals the
  `jti` of the access token in the response and whose `SessionID` equals the
  propagated `sid`; the generic `EventTokenIssued` is still emitted, and
  other grants (e.g. `authorization_code`) emit no `token_exchange_issued`.
- End-to-end join check: `TokenID` from the audit event resolves through
  `GetChain` to the same hop recorded at mint time — token, audit event, and
  chain row are now one joinable set.
- `go test ./platform/audit/auditreport/` drift tests pass.
