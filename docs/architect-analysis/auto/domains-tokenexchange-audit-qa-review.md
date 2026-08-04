# QA Lead Review — Token-Exchange Audit Observability Design

**Revision reviewed:** `docs/auto/domains-tokenexchange-audit-design.md` (377 lines) and its spec `docs/auto/domains-tokenexchange-audit-spec.md` against the tree at HEAD `64b08185`. No files modified; docs-only revision.

**Role basis:** risk-based test review per `ai-dev/prompts/README.md` + `qa_lead.md`. Every claim below is labeled Verified/Partial/Missing/Proposed; coverage numbers come from commands actually run for this revision (section 1), never from prior reports.

## 1. Test inventory and commands actually run for this revision

| Command | Result | Notes |
|---|---|---|
| `go test -run 'TestMaintainability_|TestArchitecture_' .` | ok (0.176s) | Gate baseline green |
| `go test ./domains/tokenexchange/... ./platform/audit/auditreport/` | ok (5 packages) | Domain + drift gate green |
| `go test ./interfaces/admin/ ./interfaces/sso/` | ok | Admin endpoint tests green |
| `go test ./test/ -run 'TestTokenExchange_' -v` | 20+ PASS | Full token-exchange integration surface green, incl. `TestTokenExchange_PropagatesSIDToAccessToken`, `TestTokenExchange_PolicyDeniesSpecificHop`, `TestTokenExchange_ChainStoreFailOpen` |
| `go test ./domains/tokenexchange/... -cover` | 34.5% / 94.0% / 98.2% / 83.7% | tokenexchange / agentidentity / memory / sqlite |
| `go test ./test/ -run 'TestTokenExchange\|TestCrossTenant' -coverpkg=./internal/handler/tokengrant/...,./domains/tokenexchange/... -coverprofile=/tmp/tx_cov.out` | 31.5% combined | Function-level numbers below are from `go tool cover -func=/tmp/tx_cov.out` |

**Function-level coverage (measured this revision, integration run):** `HandleTokenExchangeGrant` 95.0%, `tokExEnforcePolicy` **92.3% (12/13 — the `err != nil` branch is the single uncovered line)**, `tokExRecordChainHop` 100%, `tokExAuditSPIFFE` **20.0%**, `tokExActorChainHasCycle` 100%, `tokExAuditCrossTenant` 85.7%, `RecordExchangeHopFailOpen` 100%, `Evaluate` 100%, `ruleMatches` 71.4%, `tokExResolveActor` 59.1%, `tokExResolveSubject` 64.7%.

Not run this revision (nothing to build, docs-only): `go build ./... && go vet ./...` (compiled transitively by the test runs above), `-race`, `go test ./test/ -run TestE2E -v`, `make ci`. The design's §4.3 handoff sequence is the pinned implementation gate.

## 2. Requirement-to-test matrix

Status: **V** = covered by a passing test today · **P** = partial (wire half covered, event/field half not) · **M** = no test exists · **Proposed** = design intent, no test yet.

| # | Requirement (spec §) | Status | Evidence (test) | Gap for the design |
|---|---|---|---|---|
| R1 | Deny path: policy deny → 400 `invalid_grant` (wire half) | **V** | `TestTokenExchange_PolicyDeniesSpecificHop` (test/token_exchange_chain_policy_test.go:218) | Assertions are error-code only — no byte-identity, no no-store headers, no event |
| R2 | Deny event emitted, `Reason=policy_denied`, `rule` metadata == rule name | **M** | Harness wires no audit recorder (`newTokenExchangeChainPolicyHarness`, zero `WithAuditRecorder`) | Spec acceptance check has no test vehicle |
| R3 | `(false, err)` → `Reason=policy_error` | **M** | No error-returning `Policy` double exists anywhere (grep: only `memory.Store.Allow`, which never errors); the `err` branch is the one uncovered line of `tokExEnforcePolicy` (92.3% = 12/13) | Spec acceptance check has no test vehicle |
| R4 | Nil/unwired Policy → no event, byte-identical | **P** | `TestTokenExchange_PolicyUnwiredByDefault` (wire only; no recorder to assert no-event) | Extend with recorder |
| R5 | `Evaluate`/`MatchRule` truth table preserved | **V** | `TestEvaluate_*` ×4 + `TestStore_AllowDefaultAndRules`/`TestStore_Replace` (domains/tokenexchange/tokenexchange_test.go, memory/store_test.go); `Evaluate` 100% measured | Refactor guard exists; extend `ruleMatches` coverage (71.4%) |
| R6 | ChainHop 4-field round-trip (sqlite + memory) | **M** | `TestChainStore_GetChain_MultiHop`/`GetDescendants` assert only the 7 old fields (both backends) | Extend both |
| R7 | Migration v1→v2; pre-existing rows → empty correlation fields | **M** | `sqlite/chain_store_test.go` has no migration test at all (only `TestChainStoreMaxVersion_MatchesLiveSchema`) | Precedent exists: `platform/audit/sqlite/migration_test.go:35` `TestNewWithDB_AdoptsPreMigrationSchema` |
| R8 | Admin endpoint returns enriched hop JSON, `omitempty` for old rows | **P** | `interfaces/admin/tokenexchange_chains_test.go` (5 HTTP tests incl. happy path decoding `[]ChainHop`, 404/400/nil-store, admin:read scope gating) — **the design's §4.3 points at the wrong file** (`test/token_exchange_chain_store_test.go` is store-level only) | Extend `TestHandleTokenExchangeChain_HappyPath` |
| R9 | Space-join symmetric round-trip (incl. degenerate U+0020 value) | **M** | No encoding test exists; no charset validation on the path (protocol review F2) | Add unit test both backends |
| R10 | Fail-open: failing ChainStore never fails grant | **V** | `TestTokenExchange_ChainStoreFailOpen` + `alwaysFailingChainStore` double | Must pass **unmodified** after the signature change (compiler-guarded, zero test call sites — verified) |
| R11 | Exactly one `token_exchange_issued` per exchange; `TokenID` == response jti; `SessionID` == sid | **M** | `test/handle_token_exchange_test.go` harness has zero audit-recorder wiring (grep: 0 `WithAuditRecorder`) | Extend harness |
| R12 | Other grants (authcode/refresh/cc) emit no `token_exchange_issued` | **M** | `test/audit_oauth_events_test.go` asserts `token_issued` for other grants but there is no assertion set that would catch widening | Add negative assertions |
| R13 | Agentidentity mint event: `TokenID` == jti, `SessionID` == session, pre-existing metadata keys unchanged | **P** | `TestHandleGrant_Success` (grant_test.go:268) asserts metadata keys (`original_subject`, `agent_session_id`) but not `TokenID`/`SessionID` (fields don't exist yet) | Extend |
| R14 | End-to-end join: audit `TokenID` → `GetChain` same hop | **M** | No test combines audit recorder + ChainStore in one harness (chain-policy harness accepts both `WithTokenExchangeChainStore` and `WithAuditRecorder` — feasible) | New test |
| R15 | Drift gate: both constants claimed exactly once | **V** | `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` + `TestControlAreaDefs_NoEventTypeClaimedTwice` (auditreport/drift_test.go) — mechanism proven; currently green | Same-change rule; gate fails until both land |
| R16 | Wire byte-identity across all deny classes + no-store headers | **P** | `test/token_no_store_test.go:41-45` asserts `Cache-Control: no-store` / `Pragma: no-cache` on `/token` responses; the token-exchange deny tests assert neither byte-identity nor headers | Add to deny tests |
| R17 | Deny-event emission precedes response write (stream causality) | **M** | No ordering assertion exists anywhere in the audit tests | Proposed: assert sink order (deny event before `token_issued`-adjacent rows in the ring) |
| R18 | `token_exchange_issued` fires before fail-closed id_token failure (protocol F6) | **M** | `token_exchange_id_token_test.go` covers wire only | Pin with test: 500 response + event already recorded |
| R19 | `TokenID`/`SessionID`/`Reason` are "first-class **indexed** columns" (design §1.2/§3.2) | **D** | `auditspi/query.go:14-27` has NO TokenID/SessionID/Reason filters; `platform/audit/sqlite/sink.go:109-114` indexes only ts/type/actor/client/request/trace (+tenant v2); `MemorySink.Query` mirrors | The join story is **untestable through the product API** — see F2 |

## 3. Findings

Sorted by severity. Each: evidence → impact → exact test to add → acceptance assertion.

### F1 — High — The deny-event acceptance checks have no test vehicle: harness lacks an audit recorder and no error-returning Policy double exists; the `policy_error` branch is the only uncovered line of the function being changed

**Evidence (Verified):** `newTokenExchangeChainPolicyHarness` (test/token_exchange_chain_policy_test.go:34-66) wires no `sso.WithAuditRecorder`; grep of all `*_test.go` finds no `Policy.Allow` implementation that returns an error (`memory.Store.Allow` never errors — `store.go:38-43`); measured `tokExEnforcePolicy` coverage 92.3% with the `err != nil` branch uncovered.

**Impact:** The spec's acceptance checks ("exactly one event … `Reason=policy_denied`", "Policy returning `(false, err)` yields … `Reason=policy_error`") cannot be implemented as written — a copy-paste of the existing policy test would silently pass without ever emitting an event, because the harness has no recorder to observe. The `policy_error` class would ship with zero coverage of the only code path that distinguishes it.

**Test to add:** extend `test/token_exchange_chain_policy_test.go`:
1. Harness: add `sso.WithAuditRecorder(audit.New(audit.NewMemorySink(100)))` (capacity 100 — each exchange emits ≥2 events; the 10k default is unnecessary).
2. `TestTokenExchange_PolicyDenyEmitsDeniedEvent`: `memory.New(true, Rule{Name:"block-actor-a-for-subject", SubjectID:…, ActorSubject:…, Deny:true})` → exactly one `EventTokenExchangeDenied`, `Outcome=Failure`, `TokenID == JTIFromJWTUnsafe(subject token)`, `SessionID == sid of the login session`, `Reason="policy_denied"`, `Metadata["rule"] == "block-actor-a-for-subject"`, `ActorID == actor subject`, wire `400 invalid_grant` with raw-body bytes equal to a non-policy deny.
3. `TestTokenExchange_PolicyErrorEmitsDeniedEvent`: a 3-line `erroringPolicy` double (`Allow` returns `(false, errors.New("boom"))`) → same event with `Reason="policy_error"`, `Metadata["rule"]` absent, wire byte-identical to the deny case (proves oracle collapse between the two classes).

**Acceptance assertion:** `sink.Query(ctx, audit.Query{Type: audit.EventTokenExchangeDenied})` returns exactly 1 event with the exact field values; the raw response bytes for deny vs error cases are `bytes.Equal`; no event when Policy is nil (extend `TestTokenExchange_PolicyUnwiredByDefault` with a recorder).

### F2 — High — The design's core join acceptance story is untestable through the product audit API: `audit.Query` has no TokenID/SessionID/Reason filters and the sink has no such indexes

**Evidence (Verified):** `auditspi/query.go:14-27` (`Query` struct: Type/ActorID/ClientID/TenantID/Provider/Outcome/RequestID/TraceID/Since/Until/Limit/Offset — no TokenID/SessionID/Reason); `MemorySink.Query` (memory_sink.go:67) uses `Query.Match`; `platform/audit/sqlite/sink.go:109-114` indexes only ts/type/actor/client/request/trace (+tenant); `buildWhere` (sqlite/query.go:22-67) and `parseQuery` (handlers.go:146-193) mirror. The design's §1.2/§3.2 "already indexed first-class columns" claim is **false on the indexing half**, and §4.3's validation plan never exercises a `token_id` lookup.

**Impact:** The §3.2 acceptance story — "a suspicious bearer token from resource-server logs resolves jti → `token_exchange_issued` via `token_id` → `GetChain(jti)`" — cannot be executed in-product, and a direct-SQL lookup is a full table scan of an unpruned-by-default monotonic table. The QA consequence: the design's E2E join test (R14) can be written against `MemorySink` iteration and would pass while the product-level retrieval story remains unimplemented — the test would certify a capability the API doesn't expose.

**Test to add (if the DB-architect F1 option-1 recommendation is adopted — Query filters + audit migration v4 indexes):**
1. `TestSink_QueryTokenIDAndSessionIDFilters` in `platform/audit/sqlite/sink_test.go` (mirror `TestSink_QueryFilters` at line 124): record events with distinct `TokenID`/`SessionID`/`Reason`, filter each, assert exact row selection and empty-wildcard behavior.
2. `TestAuditQuery_TokenIDUsesIndex` in `platform/audit/sqlite`: `EXPLAIN QUERY PLAN SELECT … WHERE token_id = ?` reports an index scan on `idx_audit_events_token_id`.
3. HTTP: extend `test/audit_handler_test.go` `parseQuery` coverage with `?token_id=` and `?session_id=` parameters.
4. `TestTokenExchange_AuditToChainJoin` (test/): wire ChainStore + audit recorder, exchange, assert `issued.TokenID == JTIFromJWTUnsafe(response access_token) == store.GetChain(...)[0].JTI` and `issued.SessionID == hop.SessionID`.

**Acceptance assertion:** the three identifiers (audit `TokenID`, chain `JTI`, token `jti`) are equal for one exchange; the SQLite query plan for `token_id` is an index scan; `GET /api/v1/audit/events?token_id=<jti>` returns the issued row. If the offline-SQL-only option is chosen instead, the design must say so and the join test (R14) must be relabeled as an offline-inspection contract — it does not certify an API.

### F3 — Medium — The design's verification plan names the wrong home for the admin-endpoint JSON test; the real HTTP suite (`interfaces/admin/tokenexchange_chains_test.go`) is never mentioned

**Evidence (Verified):** `interfaces/admin/tokenexchange_chains_test.go` exists with 5 HTTP tests: `TestHandleTokenExchangeChain_HappyPath` (decodes `[]ChainHop` JSON through the real handler), `_UnknownJTI` (404), `_MissingJTI` (400), `_NilStore` (404), `_ScopeGating` (admin:read 403/200). Design §4.3 says "`test/token_exchange_chain_store_test.go` (admin endpoint hop JSON)" — that file is store-level only (RecordHop/GetChain/GetDescendants/fail-open) and has no HTTP surface.

**Impact:** An implementer following §4.3 would extend the wrong file, and the enriched-JSON claim (additive fields, `omitempty` for old rows) would land with no assertion that the admin contract actually surfaces `scopes`/`resources`/`requested_token_type`/`session_id` — exactly the contract whose OpenAPI schema also needs the same-change update (architect/security/protocol F1, confirmed at `docs/openapi.yaml:7074-7129`, `operationId: getAdminTokenExchangeChain`, chain-item schema enumerating exactly the 7 current fields).

**Test to add:** extend `TestHandleTokenExchangeChain_HappyPath` (or add `_EnrichedHopFields`): record hops with the 4 new fields set and one pre-upgrade row without them; assert the response JSON contains the 4 fields for the new row and omits them (`omitempty`) for the old row; assert `recorded_at`/`chain_depth` unchanged.

**Acceptance assertion:** `json.Unmarshal` into a struct with the 4 fields: new row round-trips exactly (space-join re-split matches the original sets, order-preserving); old row leaves them zero; the OpenAPI chain-item schema (updated in the same change per AGENTS.md §5) lists the 4 new properties.

### F4 — Medium — Migration v2 has no test pattern in the chain-store package and the design's line refs for it are stale; the version-pin gate (`TestChainStoreMaxVersion_MatchesLiveSchema`) is the only migration-adjacent test

**Evidence (Verified):** `chainMigrations` is at `sqlite/chain_store.go:44-45` (design §2.2 cites 19-21); the sqlite package has no migration test; `TestChainStoreMaxVersion_MatchesLiveSchema` (chain_store_test.go:169) pins `CheckSchema`/`ErrSchemaTooNew` and auto-derives from `chainMigrations` — it will silently absorb v2 rather than prove it. The audit sink provides the exact precedent needed: `platform/audit/sqlite/migration_test.go:35` (`TestNewWithDB_AdoptsPreMigrationSchema` — hand-built baseline schema + seeded row, then `NewWithDB`, assert version + row survival).

**Impact:** The design's §2.4 projection-drift guard ("migration test v1→v2 with pre-existing rows returning empty correlation fields") has no template in the package; without it, the most dangerous failure (a botched v2 that mis-scans old rows, or a v1 edit that desyncs the version table) would surface only as admin-endpoint JSON drift in the integration suite.

**Test to add:** `TestChainStore_MigratesV1ToV2` in `domains/tokenexchange/sqlite/chain_store_test.go`, mirroring the audit precedent: create a bare pool, execute the v1 DDL (copy of the 7-column `chainSchema`), seed 2 rows with distinct `parent_jti` shapes, close; then `New` on the same file → assert `migrate.CurrentVersion == 2`, `PRAGMA table_info` shows 11 columns, both rows read back with empty correlation fields, and a fresh `RecordHop` with all 4 fields round-trips through `GetChain` and `GetDescendants`. Also extend `TestChainStoreMaxVersion_MatchesLiveSchema` to assert `ChainStoreMaxVersion() == 2`.

**Acceptance assertion:** pre-migration row count preserved; `scopes='' AND resources='' AND requested_token_type='' AND session_id=''` for every old row; `GetDescendants` returns the enriched fields identically to `RecordHop`.

### F5 — Medium — No test asserts the "exactly one `token_exchange_issued`, zero for other grants" invariant; the harness has no recorder and no audit-event set is asserted anywhere on the exchange path

**Evidence (Verified):** `test/handle_token_exchange_test.go` contains zero `WithAuditRecorder` (grep count 0); `test/audit_oauth_events_test.go` asserts `token_issued`-family events for login/refresh/device-code grants but no test asserts the complete event set of a token-exchange request. The design's own risk table (§3.4 "event-count regressions") names the exact missing test.

**Impact:** The design's central no-blast-radius claim — "other grants keep emitting exactly what they emit today, and emit no `token_exchange_issued`" — would be certified only by absence of compiler errors, not by assertion. A later refactor that widens `RecordTokenIssued` (the shared helper at `recorder_events.go:18-29`) would pass CI silently.

**Test to add:** extend `test/handle_token_exchange_test.go` with a recorder-equipped variant of the harness (the chain-policy harness pattern): `TestTokenExchange_IssuedEventExactOnce` — one exchange → exactly one `EventTokenExchangeIssued` (count by type in the sink), `TokenID == JTIFromJWTUnsafe(response access_token)`, `SessionID == propagated sid`, `Metadata["parent_jti"] == subject jti`, `Metadata["scope"]` == space-joined granted scopes; and `TestTokenExchange_IssuedEventAbsentForOtherGrants` — an `authorization_code` grant and a `client_credentials` grant against the same recorder emit zero `EventTokenExchangeIssued` while still emitting `EventTokenIssued`.

**Acceptance assertion:** `len(sink.Query(ctx, audit.Query{Type: EventTokenExchangeIssued})) == 1` per exchange, 0 for authcode/refresh/cc; `EventTokenIssued` count unchanged by the feature (assert before/after parity in the same test).

### F6 — Low — The three §4.2 relocations have unequal test backing: `tokExAuditSPIFFE` (the stages-file relief move) is at 20% coverage, the weakest of the three

**Evidence (Verified, measured):** `tokExAuditSPIFFE` 20.0% (1 of 5 lines) in the integration coverage run; the only in-tree assertion is `test/spiffe_svid_test.go:235` (`sink.Query` for `EventSPIFFEJWTSVIDAccepted`); `tokExAuditCrossTenant` 85.7% with strong harness coverage (`test/cross_tenant_collaboration_test.go:245` asserts the event's metadata); `tokExActorChainHasCycle` 100%.

**Impact:** The design's purity proof ("existing cross-tenant and SPIFFE audit tests must pass unmodified") is meaningful for the cross-tenant move but nearly vacuous for the SPIFFE move — 80% of the moved function's lines are uncovered today, so a behavior-changing refactor of `RecordSPIFFEJWTSVIDAccepted` could pass the unmodified suite.

**Test to add:** extend `test/spiffe_svid_test.go` to assert the full event shape (`Type`, `Outcome=Success`, `ActorID`, `ClientID`, metadata keys) so the move has a real oracle; re-run after the relocation and require byte-identical assertion results.

**Acceptance assertion:** the extended SPIFFE test passes unmodified before and after the §4.2 step-3 move; `tokExAuditSPIFFE` coverage ≥ 80% post-move.

### F7 — Low — The deny-path oracle-safety guard is asserted as error-code only; byte-identity and credential-endpoint headers are not asserted on any deny class

**Evidence (Verified):** `TestTokenExchange_PolicyDeniesSpecificHop` asserts `status == 400` and `body["error"] == ErrInvalidGrant` only; `test/token_no_store_test.go:41-45` proves the no-store header convention (`Cache-Control: no-store`, `Pragma: no-cache`) is enforced on `/token` responses generally, but no token-exchange test asserts headers.

**Impact:** The design's guard ("wire byte-identical `400 invalid_grant` on every deny class; no-store headers untouched") is stronger than any current assertion. Since the deny path is the one place the design *adds code* (`RecordTokenExchangeDenied` before `ctx.JSON`), a regression that leaks the reason into the response body or drops a header would go uncaught by the suite the design names as the guard.

**Test to add:** in the F1 harness, capture the raw body + headers of: policy-deny, policy-error, actor-cycle deny, chain-TTL deny; assert `bytes.Equal` across all four bodies (they must be the same `invalid_grant` JSON) and `Cache-Control: no-store` + `Pragma: no-cache` on all four.

**Acceptance assertion:** all four deny classes produce byte-identical response bodies and identical no-store header sets; the design's documented "response construction line is untouched" is thereby enforced rather than assumed.

### F8 — Info — Concurrency: the copy-on-write `Allow`/`DenyReason` TOCTOU and the memory ChainStore maps have no concurrent test; the design relies on `-race` at handoff only

**Evidence (Verified):** `memory/store.go:38-60` — `Allow` under `RLock` snapshot, `Replace` copy-on-write; `TestStore_Replace` is single-threaded. The memory `ChainStore` maps (`hops`/`children`) are append-only with no eviction (database-architect F3) and no concurrent test.

**Impact:** Advisory-only TOCTOU (design §1.4) is documented but never exercised; the memory model is simple enough that risk is low, but the design's own acceptance plan runs `-race` only at handoff.

**Test to add:** `TestStore_ConcurrentAllowDenyReasonReplace` in `memory/store_test.go`: N goroutines calling `Allow` + `DenyReason` while one goroutine `Replace`s rule sets in a loop, run with `-race` (`go test -race ./domains/tokenexchange/memory/ -count=10`). Optionally a concurrent `memory.ChainStore.RecordHop` test (map writes under the store's lock — verify it has one).

**Acceptance assertion:** zero race reports under `-race -count=10`; no panic; `Allow` never observes a partially-applied rule set.

### F9 — Info — Design line-ref drift that a test planner would trip on

`chainMigrations` at `sqlite/chain_store.go:44-45` (design: 19-21); `JTIFromJWTUnsafe` at `chainstore.go:139` (design: 216); `tokExEnforcePolicy` at 373-399 (design §1.1: 373-425); `mintDelegationToken` at `grant.go:179` (design: ~200). All regions exist; the §4 line math is unaffected (the ±3 error bars stand). Re-verify refs at implementation time; the design's blanket "every line reference was re-verified" claim is overstated (matches architect F3 / protocol F5).

## 4. Prioritized scenario list

Priority P0 = blocks the design's acceptance checks; P1 = required for the same change; P2 = documented-behavior pinning.

| # | Priority | Path | Scenario | Test to add / extend | Oracle/regression risk it kills |
|---|---|---|---|---|---|
| S1 | P0 | Happy | Exchange with actor + scopes + resource → exactly one `token_exchange_issued`; `TokenID`==response jti; `SessionID`==sid; hop row carries 4 fields; admin JSON shows them | F3, F5 tests | Silent jti mismatch; projection drift across 3 SQL sites |
| S2 | P0 | Happy | Agent-identity mint event carries `TokenID`/`SessionID`; pre-existing metadata keys byte-identical | Extend `TestHandleGrant_Success` | Audit-consumer wire break |
| S3 | P0 | Error | Policy deny → deny event with `Reason=policy_denied` + rule name; wire 400 byte-identical + no-store | F1-2, F7 | Oracle leak; event never emitted |
| S4 | P0 | Error | Policy `(false, err)` → `Reason=policy_error`, no rule metadata; wire identical to S3 | F1-3 (`erroringPolicy` double) | `policy_error` class ships untested (currently the only uncovered line) |
| S5 | P1 | Error | Nil Policy / nil Auditor → no events, byte-identical wire | Extend `TestTokenExchange_PolicyUnwiredByDefault` | Fail-open regression |
| S6 | P1 | Boundary | No actor → `ActorID` falls back to `st.claims.Subject` | F1 harness variant | Actor attribution drift |
| S7 | P1 | Boundary | Opaque subject token (no jti/sid): deny event still emitted with empty `TokenID`/`SessionID`; hop skipped (asymmetric — documented at both sites) | New unit test at `tokExState` level + integration | The documented asymmetry silently becomes symmetric |
| S8 | P1 | Boundary | No `DenyReasoner` (custom `Policy` impl) → event without `rule` metadata; `DenyReason` `""` → fallback | F1 harness with bare `PolicyFunc` double | Cardinality/fallback drift |
| S9 | P1 | Recovery | Migration v1→v2 with pre-existing rows; old binary boot guard `ErrSchemaTooNew` | F4 migration test + extend `TestChainStoreMaxVersion_MatchesLiveSchema` | Silent schema desync |
| S10 | P1 | Regression | `RecordExchangeHopFailOpen` signature change: fail-open + JTI-skip preserved | `TestTokenExchange_ChainStoreFailOpen` + `TestChainStore_RecordHop_MissingJTI` pass **unmodified** | The design's own compiler-guard claim |
| S11 | P1 | Regression | Cross-grant leakage: authcode/refresh/cc emit zero `token_exchange_issued` | F5 negative test | Generic `token_issued` widened accidentally |
| S12 | P1 | Oracle | All deny classes (policy/cycle/TTL/cross-tenant/step-up) byte-identical bodies + headers | F7 | Reason leak via any deny class |
| S13 | P2 | Boundary | `requested_token_type=id_token` fail-closed 500 after Success event already recorded | Pin per protocol F6 | SIEM misreads Success-before-500 |
| S14 | P2 | Boundary | Space-join degenerate value (U+0020 in scope/resource): documented asymmetric round-trip or filtered at record boundary | Protocol-F2 test in both backends | Encoding convention silently broken by misconfiguration |
| S15 | P2 | Race | Concurrent `Allow`+`DenyReason`+`Replace`; concurrent `RecordHop` | F8 race test | TOCTOU memory-model regression |
| S16 | P2 | Error | Audit sink full (ring overflow) → fail-open, grant unaffected, event dropped | MemorySink-capacity harness variant | Drop-on-full semantics |
| S17 | P2 | Recovery | Chain store reopen after v2 (persistence proof) | `TestChainStore_PersistsAcrossReopen` passes unmodified | v2 breaks durable reopen |
| S18 | P2 | Contract | OpenAPI chain-item schema gains the 4 fields; kin-openapi validation green | F3 + `make ci` contract checks | Documented-contract drift (the design's false "missing entry" premise) |

## 5. CI/manual-suite gaps, flake risks, fixtures needed, exit criteria

**CI gaps (verified, current tree):**
1. **No drift check for OpenAPI content.** The CI openapi job runs kin-openapi *syntax* validation only (security review F1); nothing fails if the chain-item schema omits the 4 new `ChainHop` fields. Mitigation: the F3 admin-JSON test plus an explicit schema-review step in the same change (AGENTS.md §5 requires it regardless).
2. **No E2E token-exchange coverage** — `test/e2e_test.go` and the `*_e2e_test.go` files contain no token-exchange scenario (grep verified). The integration suite (`test/` + `interfaces/admin/`) is the right depth for this feature; no new E2E needed, but the design should not claim E2E coverage anywhere.
3. **`tokExAuditSPIFFE` at 20% coverage** — the weakest oracle for a §4.2 move (F6). Close before the relocation, not after.
4. **No `-race` suite covers the memory policy/chain stores** beyond the handoff gate (F8).
5. **The design's §4.3 verification list omits**: the admin-endpoint HTTP suite location (F3), the openapi.yaml same-change update (F3/S18), and any `token_id`/`session_id` lookup test (F2).

**Flake risks (assessed, current tree):**
- `TestTokenExchange_MaxChainLifetimeDeniesStaleChain`/`DisabledByDefault` use 5ms caps with 25ms sleeps — 5x margin, stable today; do not tighten when adding deny tests.
- New recorder-based tests: `MemorySink` ring capacity must exceed per-request event count (≥2 per exchange); use 100 like the existing harnesses (`account_lockout_test.go:167`, `cross_tenant_collaboration_test.go:75`).
- Event-count assertions must be scoped by `Query{Type: …}` (the cross-tenant harness pattern at `cross_tenant_collaboration_test.go:245`), never `Query{}` over the whole ring — other harness steps emit `token_issued`/`login` events.

**Fixtures needed (none exist today — all new):**
1. `erroringPolicy` — 3-line `Policy` double returning `(false, err)` (F1).
2. Bare `PolicyFunc`-style double without `DenyReasoner` (S8).
3. v1-schema chain DB fixture — inline DDL copy of the 7-column `chainSchema` + seeded rows (F4; precedent `platform/audit/sqlite/migration_test.go:35`).
4. Recorder-equipped variants of `newTokenExchangeChainPolicyHarness` and the `handle_token_exchange_test.go` harness (F1, F5).
5. Opaque-token subject fixture for S7 (a non-JWT `subject_token` accepted by a wired strategy — check existing opaque-strategy coverage in `test/` before writing; `token_format_hinter_test.go` may provide the pattern).

**Exit criteria for the design's implementation:**
1. All of P0/P1 tests green, including the four "pass unmodified" purity proofs (`TestTokenExchange_ChainStoreFailOpen`, `TestTokenExchange_ChainStoreRecordsHopOnSuccess`, cross-tenant + SPIFFE audit tests, `TestChainStore_PersistsAcrossReopen`).
2. `go test ./platform/audit/auditreport/` green with both new constants claimed once (R15).
3. OpenAPI chains schema updated in the same change (S18); kin-openapi validation green in `make ci`.
4. Handoff gate per design §4.3: `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci`.
5. F2 resolved in one of the two documented directions (Query filters + v4 indexes, or an explicit offline-SQL contract) — otherwise the design's headline §3.2 join story ships with no executable acceptance test.

**Bottom line.** The design's test plan is directionally right (extend the two `test/` files, round-trips, drift gate) and the existing suite gives it strong rails: `Evaluate` is table-locked at 100%, fail-open is proven with a real double, the admin endpoint has a real HTTP suite, and the drift gate mechanically enforces the same-change event registration. But three required tests have **no vehicle today**: the deny event (no recorder in the harness, no erroring-Policy double — and the `policy_error` branch is the one uncovered line of the function being modified), the join story (no `token_id`/`session_id` query surface exists, so the acceptance test would certify a nonexistent API), and the admin-enriched-JSON assertion (the design points at the wrong file and its OpenAPI premise is false). Fix the harness/vehicles in the same change as the feature, treat the §4.2 relocations as mandatory pre-work with the SPIFFE coverage gap closed first, and the design's own acceptance checks become executable rather than aspirational.
