# Design: `domains/tokenexchange` audit observability — deny events, chain correlation, mint jti join

Source: `docs/auto/domains-tokenexchange-audit-spec.md` (three evidence-backed
decisions). Every line reference below was re-verified against the current
tree while writing this design, including two constraints the spec does not
surface and that shape the design materially:

- `internal/handler/tokengrant/token_exchange.go` is 499/500 lines and
  `token_exchange_stages.go` is 495/500 (`maxFileLines = 500`, exemption map
  frozen empty in `maintainability_budget_test.go`). Both files that must
  change are 1–5 lines from the ceiling.
- `internal/handler/tokengrant` holds exactly 10 non-test `.go` files and is
  NOT in `dirFileCountExemptions` (`maxGoFilesPerDir = 10` in
  `directory_fanout_test.go`) — no new file may be added to the package.

Section 4 is the resulting mandatory placement plan; every decision below
assumes it.

Shared conventions relied on (all verified):
- `audit.Event` (platform/audit/auditspi/event.go:42-44) promotes first-class,
  SQLite-sink-indexed `SessionID` / `TokenID` / `Reason`; the SQLite sink
  (`platform/audit/sqlite/sink.go:99-101`) has `session_id`, `token_id`,
  `reason` columns.
- Recorder helpers (`platform/audit/recorder_events.go`) are nil-`Recorder`-
  safe and the audit path is fail-open (AGENTS.md §3); `RecordDeviceCodeDecision`
  (lines 78-95) is the deny-event pattern.
- `audit.EventFromRequest` / `audit.SetMeta` / `audit.ClientIP`
  (`platform/audit/handler_helpers.go:37,110,123`); metadata keys are exported
  per-package consts (`agentidentity/consts.go:8` pattern) or `shared/core`
  keys (`consts_wire.go`).
- `auditreport/drift_test.go:95`
  (`TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`) fails unless
  every `KnownEventTypes` entry is claimed exactly once in
  `auditreport/control_areas.go` (CC6.1 bucket hosts the token-exchange events
  at lines 55-56) or explicitly uncategorized.

## 1. `token_exchange_denied` — dedicated deny-path audit event

### 1.1 API surface

- **New event type** in `platform/audit/auditspi/event_types.go`, beside the
  existing token-exchange cluster (lines 179-181):
  `EventTokenExchangeDenied EventType = "token_exchange_denied"`. Register in
  `KnownEventTypes` (line ~321 cluster) and claim in `auditreport`
  `controlAreaDefs` CC6.1 (line ~55 cluster) in the same change.
- **New recorder helper** in `platform/audit/recorder_events.go`, modeled on
  `RecordDeviceCodeDecision` (nil-safe, `EventFromRequest`, `audit.SetMeta`
  only):
  `RecordTokenExchangeDenied(rec *Recorder, ctx core.HandlerContext, clientID, actorSubject, tokenID, sessionID, reason, rule string, scopes, resources []string, requestedTokenType string)`.
  Emits `Type=EventTokenExchangeDenied`, `Outcome=OutcomeFailure`,
  `ActorID=actorSubject` (fallback `st.claims.Subject` when no actor),
  `ClientID`, `ActorIP=audit.ClientIP(ctx.Request())`; first-class
  `TokenID` = the subject_token's `jti` (no new token exists on deny),
  `SessionID` = the `sid` the chain is anchored to, `Reason` = fixed
  vocabulary; `SetMeta`: `scope`, `resource`, `requested_token_type`,
  `subject_id`, `actor_subject`, `rule` (matched rule name, metadata only).
- **Reason vocabulary** is bounded and fixed: `"policy_denied"` (explicit
  deny) | `"policy_error"` (evaluation error, fail-closed). The rule name
  goes to `Metadata`, never first-class `Reason` — bounded cardinality of the
  indexed column is preserved (AGENTS.md §4).
- **New optional capability** in `domains/tokenexchange/tokenexchange.go`
  (~105 lines, +~10):
  ```go
  type DenyReasoner interface {
      DenyReason(ctx context.Context, hop Hop) string
  }
  ```
  plus an exported matcher refactor: `MatchRule(hop Hop, rules []Rule) (Rule, bool)`
  extracted from the unexported `ruleMatches` (line 94) and used by both
  `Evaluate` (line 84) and the new capability. Single source of truth — `Allow`
  and `DenyReason` cannot disagree about which rule matched the same snapshot.
  Type-asserted at the call site exactly like the optional `FacetQuerier`
  (docs/observability.md:76); the `Policy` SPI itself is untouched (wire and
  SPI stay byte-identical).
- **`memory.Store` implements `DenyReasoner`**: under the existing `RLock`
  snapshot, call `MatchRule`, return the first matching rule's `Name` ("" when
  no rule matched or no `DenyReasoner` — caller falls back to
  `"policy_denied"` without the `rule` metadata).
- **Handler wiring** in `tokExEnforcePolicy` (`token_exchange.go:373-425`): on
  the combined terminal `err != nil || !allow`, compute
  `reason := "policy_denied"` / `"policy_error"` from `err != nil`, resolve the
  rule name via the type assertion, call `RecordTokenExchangeDenied`, then
  write the byte-identical `400 invalid_grant` (`ctx.JSON` line 396 unchanged).
  The `hop` value is already constructed above the `Allow` call — no rebuild.
  The audit call happens BEFORE the response write so the event precedes the
  wire decision in the audit stream.
- New metadata-key consts (e.g. `"rule"`, `"requested_token_type"`) as
  exported package consts in `internal/handler/tokengrant`, following the
  `agentidentity/consts.go` pattern; reuse `core.KeyScope` /
  `core.KeyOriginalSubject` where they already exist.

### 1.2 Storage model

No new tables or columns. The event is an ordinary row in the audit SQLite
sink; `token_id` / `session_id` / `reason` are already first-class indexed
columns there, so "who tried to act as whom, which rule blocked it, under
which session, against which subject token" is queryable without JSON scans.
The correlation context (scopes, resources, requested type, rule) lives in the
sink's metadata column as canonical-JSON via `SetMeta`. Retention, hash
chaining, and webhook fan-out follow the existing audit pipeline unchanged.

### 1.3 Failure modes

| Failure | Behavior |
|---|---|
| `Auditor()` nil (unwired) | Helper short-circuits; no event, no behavior change |
| Recorder/sink error | Fail-open (AGENTS.md §3); the already-decided `400 invalid_grant` is never revisited |
| `Policy` not a `DenyReasoner` | `rule` metadata omitted; event still emitted with the fixed `Reason` |
| `DenyReason` returns `""` | Same fallback |
| `DenyReason` panics | Propagates like any handler panic (consistent with the `FacetQuerier` precedent; only in-tree `memory.Store` implements it — no `recover` added) |
| Subject token opaque / no jti, no sid | First-class `TokenID`/`SessionID` empty; event still emitted (audit is the complete record — deliberately asymmetric with the chain store's skip rule) |
| Nil `Policy` (unwired) | No event, no call — byte-identical to today |

### 1.4 What could break this design

- **`auditreport` drift gate**: the constant must be claimed in CC6.1 exactly
  once. Both edits (`event_types.go` + `control_areas.go`) must land in the
  same change or `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`
  fails — a gate failure, caught in `go test ./platform/audit/auditreport/`.
- **Oracle-safety regression**: the deny reason is the entire point of the
  event and must never leak onto the wire. Guard: the existing wire tests
  (extended `test/token_exchange_chain_policy_test.go` harness) assert
  byte-identical `400 invalid_grant` on every deny class; the response
  construction line is untouched.
- **TOCTOU between `Allow` and `DenyReason`**: `memory.Store.Replace` is
  copy-on-write, so the two calls snapshot independently; the reported rule
  could come from a newer snapshot than the one that denied. Bounded
  staleness, advisory (audit-only, fail-open), documented in the capability's
  doc comment. The alternative (a single combined SPI call) was rejected — it
  changes the `Policy` interface and every implementation.
- **`Evaluate` refactor risk**: `MatchRule` extraction must preserve the exact
  truth table; the existing table tests in `domains/tokenexchange/memory/
  store_test.go` and `Evaluate`'s own tests lock it.
- **Cardinality creep**: a third-party `Policy` implementing `DenyReasoner`
  with unbounded strings would pollute `Metadata`. Mitigation: rule names are
  operator-defined human labels (bounded by the admin rule-set surface), and
  the doc contract states the rule name is for display/audit only.
- **File budget**: `tokExEnforcePolicy` grows ~8 lines in a 499-line file —
  the relief moves of section 4 are a prerequisite, not optional.

## 2. ChainHop correlation keys — scopes / resources / requested-token-type / session

### 2.1 API surface

- **`ChainHop`** (`domains/tokenexchange/chainstore.go:31-68`) gains four
  fields:
  ```go
  Scopes             []string `json:"scopes,omitempty"`
  Resources          []string `json:"resources,omitempty"`
  RequestedTokenType string   `json:"requested_token_type,omitempty"`
  SessionID          string   `json:"session_id,omitempty"`
  ```
  `SessionID` is the RFC 9068 §2.2 `sid`, propagated unchanged through every
  hop (locked by `test/handle_token_exchange_test.go:122-129`), i.e. the
  hop-level authorization-session anchor.
- **`RecordExchangeHopFailOpen`** (`chainstore.go:115`) gains four parameters
  (`scopes, resources []string, requestedTokenType, sessionID string`) and
  forwards them into the `ChainHop`. Verified: exactly one production call
  site (`token_exchange.go:227`, inside `tokExRecordChainHop`) and zero test
  call sites — the signature change is fully contained and the compiler
  guards it.
- **`tokExRecordChainHop`** (`token_exchange.go:226`) gains the `req`
  parameter (needed for `req.RequestedTokenType`; the only call site at line
  147 has `req` in scope) and passes `st.scopes`, `st.resources`,
  `req.RequestedTokenType`, `st.claims.SID` — all already resolved on
  `tokExState` at that point. The JTI-less skip rule and fail-open semantics
  are unchanged.
- **No `ChainStore` SPI change.** Reverse lookup is token(jti) → hop through
  the existing `GetChain` / `GetDescendants`; the admin endpoint
  `GET /api/v1/admin/tokenexchange/chains/:jti`
  (`interfaces/admin/lifecycle.go:109`) serializes `[]ChainHop` directly, so
  the enriched fields surface automatically (additive JSON, backwards
  compatible). session→tokens indexing is explicitly out of scope (belongs to
  the direction-1 cascade-revocation work).

### 2.2 Storage model

- **SQLite**: append migration v2 to `chainMigrations`
  (`domains/tokenexchange/sqlite/chain_store.go:19-21`):
  ```sql
  ALTER TABLE tokenexchange_chain_hops ADD COLUMN scopes TEXT NOT NULL DEFAULT '';
  ALTER TABLE tokenexchange_chain_hops ADD COLUMN resources TEXT NOT NULL DEFAULT '';
  ALTER TABLE tokenexchange_chain_hops ADD COLUMN requested_token_type TEXT NOT NULL DEFAULT '';
  ALTER TABLE tokenexchange_chain_hops ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
  ```
  Flat scalar columns per the package's documented column-not-JSON philosophy
  (file doc, lines 1-13). `migrate.Run` (platform/migrate/migrate.go:135)
  applies v2 to existing v1 databases and runs v1→v2 in order on fresh ones.
- **Encoding**: scope/resource sets are space-joined. Safe because OAuth scope
  grammar excludes U+0020 (`%x21 / %x23-5B / %x5D-7E`) and RFC 8707 resource
  values are URIs (no raw spaces). The round-trip is symmetric by construction
  and locked by a unit test.
- **`scanHop`** (line 277) extends to the 11-column projection; `getHop` /
  `getChildren` SELECT lists and `RecordHop`'s INSERT + `ON CONFLICT` clause
  (lines 138-157) extend in lockstep. Old rows scan as `""` → empty slices.
- **Memory backend**: no schema change — `hops` map stores `ChainHop` values
  (struct copy), `children` map untouched.
- JSON: empty sets/strings are `omitempty`-omitted, so pre-upgrade rows and
  old admin consumers see identical output.

### 2.3 Failure modes

| Failure | Behavior |
|---|---|
| Store error / nil store | `RecordHopFailOpen` unchanged — log-and-continue, never affects the grant |
| Migration failure (corrupt v1 DB, permission) | `New`/`NewWithDB` return an error; wiring fails closed at startup (config error, not request path) — same as today |
| Value containing U+0020 (grammar-forbidden) | Space-join round-trip would silently split into extra elements. Worst case: slightly wrong observability data in an admin read — never a grant decision. Locked by a round-trip test; documented invariant |
| Opaque/non-JWT strategy | jti empty → hop skipped (unchanged); correlation fields never recorded for that hop |
| Service-to-service subject (no sid) | `session_id` empty; consistent with the audit side |

### 2.4 What could break this design

- **Signature change blast radius**: any hidden caller of
  `RecordExchangeHopFailOpen` (verified none outside the one call site, tests
  included) breaks compilation — the Go toolchain is the guard.
- **Projection drift**: three SQL sites (`RecordHop`, `getHop`, `getChildren`)
  share one `scanHop`; they must change together. The round-trip test
  (`RecordHop` → `GetChain`/`GetDescendants`) and the migration test
  (v1 → v2 with pre-existing rows returning empty correlation fields) lock the
  symmetry.
- **Migration versioning**: v2 must append after v1 in `chainMigrations` —
  never reorder or edit v1 (migrate's version table would desync). `ALTER
  TABLE ADD COLUMN NOT NULL DEFAULT ''` is SQLite-legal for existing rows.
- **`GetDescendants` / `GetChain` walk logic** (bounded by `maxChainWalk`,
  cycle-defensive) is untouched; existing tests lock ordering and limits.
- **Pre-existing drift, out of scope**: the chain endpoint has no
  `docs/openapi.yaml` entry today. Do NOT expand scope to add one; report
  separately per AGENTS.md §5.
- **File budgets**: `chainstore.go` 155 → ~175, `sqlite/chain_store.go` 245 →
  ~295 — both comfortably under 500; no relief needed here.

## 3. Mint/issuance audit jti correlation — join key across token, audit, chain

### 3.1 API surface

- **Agent-delegation mint** (`domains/tokenexchange/agentidentity/grant.go`):
  `mintDelegationToken` (line ~200, holds `token.AccessToken`) derives
  `jti := tokenexchange.JTIFromJWTUnsafe(token.AccessToken)` and passes it to
  `auditDelegationMint` (line 213), which sets first-class `evt.TokenID = jti`
  and `evt.SessionID = sess.ID`. The existing `SetMeta` keys
  (`original_subject`, `agent_session_id`, `scope`) stay byte-identical —
  audit consumers of `agent_delegation_token_issued` see only additive
  fields. Import direction `agentidentity → domains/tokenexchange` is
  verified acyclic (agentidentity currently imports nothing from the parent;
  the parent never imports agentidentity) and stays within the domains layer.
- **New event type**: `EventTokenExchangeIssued EventType =
  "token_exchange_issued"` — registered in `KnownEventTypes`, claimed in CC6.1
  (same change, both files).
- **New recorder helper** in `platform/audit/recorder_events.go`:
  `RecordTokenExchangeIssued(rec *Recorder, ctx core.HandlerContext, clientID, subjectID, tokenID, sessionID, parentJTI, actorSubject, requestedTokenType string, scopes, resources []string)`.
  Emits `Outcome=Success`, `ActorID=st.claims.Subject`, `ClientID`,
  `TokenID=JTIFromJWTUnsafe(st.token.AccessToken)` (the just-minted token),
  `SessionID=st.claims.SID`; `SetMeta`: `scope`, `resource`,
  `parent_jti` (= `st.claims.JTI` — the SUBJECT token's jti, the pre-exchange
  hop's parent), `actor_subject`, `requested_token_type`. Doc contract must
  state `parent_jti` is the inbound subject jti, never the minted one — the
  acceptance check (event `TokenID` == response access-token jti) locks the
  naming.
- **Emission point**: folded into `tokExRecordChainHop` (which gains the `req`
  parameter per decision 2) — the single observability assembly point at
  `token_exchange.go:147`, after the mint, before response assembly. This
  keeps `HandleTokenExchangeGrant` at zero added lines and guarantees the
  chain row and the audit event derive the same jti from the same token.
- **Generic `token_issued` untouched** (`recorder_events.go:18-29` and the
  `RecordTokenIssued` helper): no cross-grant blast radius — other grants
  keep emitting exactly what they emit today, and they emit no
  `token_exchange_issued`.

### 3.2 Storage model

No schema change. Both new events are ordinary rows in the audit SQLite sink;
`token_id` / `session_id` are already indexed first-class columns. The join
completes: a suspicious bearer token from resource-server logs resolves
jti → `token_exchange_issued` row (and `agent_delegation_token_issued` row)
via `token_id`, → chain hops via `GetChain(jti)` (keyed by the same jti), →
authorization session via `session_id`/`sid`. Three stores, one identifier.

### 3.3 Failure modes

| Failure | Behavior |
|---|---|
| `Auditor()` nil | No-op (fail-open) |
| Recorder/sink error | Fail-open; grant already decided |
| `JTIFromJWTUnsafe` returns `""` (opaque strategy, decode failure) | `TokenID` empty; event still emitted — audit completeness takes precedence. Deliberately asymmetric with the chain store's skip rule (chain needs a key to be useful; audit does not) — documented at both sites |
| Opaque minted token | Same as above; `parent_jti`/`SessionID` may still be populated |
| Import cycle | Guarded by the architecture layer test; `tokenexchange` must never import `agentidentity` |

### 3.4 What could break this design

- **Drift gates**: both new constants (`token_exchange_issued` here,
  `token_exchange_denied` in decision 1) must be claimed exactly once —
  same-change rule as in §1.4.
- **Event-count regressions**: existing success-path tests assert exact event
  sets; the extended `test/handle_token_exchange_test.go` must assert exactly
  one `token_exchange_issued` per exchange, and that other grants
  (`authorization_code`, refresh, client_credentials) emit none — this is what
  proves the generic `token_issued` path was not accidentally widened.
- **`parent_jti` semantic confusion**: the field carries the INBOUND subject
  jti while `TokenID` carries the OUTBOUND minted jti. A future reader
  assuming parent==minted would corrupt chain joins; the doc comment and the
  acceptance check (TokenID == response jti, parent_jti == subject jti) pin
  the semantics.
- **Volume**: one extra audit row per successful exchange — bounded, matches
  the `cross_tenant_token_exchange` precedent (which already fires alongside
  `token_issued`). Note in `docs/error-codes.md` for SIEM operators.
- **Agent-identity test churn**: existing tests asserting the mint event's
  exact shape must be extended for `TokenID`/`SessionID`; pre-existing
  metadata keys must be asserted unchanged (wire-compat for consumers).
- **File budgets**: `grant.go` 228 → ~235 ✓; `recorder_events.go` absorbs
  both new helpers plus the section-4 moves (see below).

## 4. Engineering gates — placement plan and verification (mandatory)

### 4.1 The constraint

- `token_exchange.go` 499/500, `token_exchange_stages.go` 495/500; exemption
  maps frozen empty. Adding ~8 lines (deny audit) + ~6 (chain-hop args) + ~6
  (issued audit, folded into `tokExRecordChainHop`) to `token_exchange.go`
  would cross the cap.
- `internal/handler/tokengrant` is at 10/10 non-test files and not exempt —
  no new file. All new code must land in existing files, and ~16+ lines must
  move OUT of `token_exchange.go`.

### 4.2 The plan (in order)

1. **New helpers go to `platform/audit/recorder_events.go`** (354/500,
   ~146 lines of headroom) — the canonical home of `Record*` helpers
   (`RecordTokenIssued`, `RecordDeviceCodeDecision`, `RecordCIBAAuthRequest`):
   `RecordTokenExchangeDenied` (~30), `RecordTokenExchangeIssued` (~30).
   Result ~414.
2. **Move `tokExAuditCrossTenant` (16 lines, `token_exchange.go:484-499`) into
   `recorder_events.go`** as a generalized primitive-taking
   `RecordCrossTenantTokenExchange(rec, ctx, clientID, homeTenant, guestTenant,
   subjectID)`; the call site at line 458 stays a one-liner (net −15 in
   `token_exchange.go`). This is the enabling split — the function is an
   audit helper that belongs with its peers, and the move is required for
   budget compliance (AGENTS.md §2 "split before feature work").
3. **If the final count lands at or above 497** (the implementer should aim
   for ≥3 lines of margin): move `tokExAuditSPIFFE` (22 lines,
   `token_exchange_stages.go:432`) to `recorder_events.go` as
   `RecordSPIFFEJWTSVIDAccepted(...)` (net −21 in stages, freeing headroom
   there), and optionally `tokExActorChainHasCycle` (11 lines,
   `token_exchange.go:352`) into stages for further `token_exchange.go`
   margin.
4. **`domains/tokenexchange`**: `MatchRule` + `DenyReasoner` into
   `tokenexchange.go` (105 → ~115 ✓); `ChainHop` fields + extended
   `RecordExchangeHopFailOpen` into `chainstore.go` (155 → ~180 ✓); migration
   v2 + 11-column `scanHop`/queries into `sqlite/chain_store.go` (245 → ~295 ✓);
   `memory.Store.DenyReason` into `domains/tokenexchange/memory/store.go`;
   `agentidentity/grant.go` 228 → ~235 ✓.

### 4.3 Verification (proportional to the change)

- Per-edit: `go build ./... && go vet ./...` and
  `go test -run 'TestMaintainability_|TestArchitecture_' .`
- `go test ./platform/audit/auditreport/` (drift, both new constants).
- Round-trips: `domains/tokenexchange/sqlite` and `.../memory` (hop
  correlation fields survive `RecordHop` → `GetChain`/`GetDescendants`);
  migration v1→v2 with pre-existing rows.
- Integration: extended `test/token_exchange_chain_policy_test.go` (deny event
  shape + wire byte-identity) and `test/handle_token_exchange_test.go`
  (issued event TokenID/SessionID join; no cross-grant leakage);
  `test/token_exchange_chain_store_test.go` (admin endpoint hop JSON).
- Handoff: `go test ./... -race`, `go test ./test/ -run TestE2E -v`,
  `make ci`.
- Contract updates in the same change: `docs/error-codes.md` audit-event
  notes for both new events; the chain endpoint's missing `docs/openapi.yaml`
  entry reported as pre-existing drift, not fixed here.

### 4.4 Residual risks

- Line-count estimates carry ±3-line error bars; step 3 is the agreed margin
  mechanism — execute it before the feature work, not after the gate fails.
- The `tokExAuditCrossTenant`/`tokExAuditSPIFFE` relocations are behavior-
  neutral moves of audit-only code, but they touch the diff surface; the
  existing cross-tenant and SPIFFE audit tests must pass unmodified to prove
  the moves are pure.
