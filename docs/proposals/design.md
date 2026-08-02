Design doc written to `docs/auto/domains-tokenexchange-audit-design.md`. All evidence re-verified against the tree before writing — and verification surfaced two constraints the spec didn't surface, which shaped the design:

**Key findings**

1. **File-budget collision (the big one)**: `token_exchange.go` is 499/500 lines and `token_exchange_stages.go` is 495/500 (exemption maps frozen empty), and `internal/handler/tokengrant` sits at exactly 10/10 non-test files with no fan-out exemption — so no new file can be created and ~16+ lines must move *out* of `token_exchange.go`. The design resolves this (§4): both new `Record*` helpers go into `platform/audit/recorder_events.go` (354/500, the canonical home of `RecordDeviceCodeDecision`-style helpers), and `tokExAuditCrossTenant` (16 lines) moves there as a generalized `RecordCrossTenantTokenExchange` to free the needed headroom, with `tokExAuditSPIFFE`/`tokExActorChainHasCycle` as the agreed margin mechanism.

2. **`tokExRecordChainHop` needs `req`**: both decisions 2 and 3 need `req.RequestedTokenType`, but the helper's signature is `(d, ctx, client, st)` — the design pins the signature change (single call site at line 147, `req` in scope).

3. **`ruleMatches` is unexported**: `memory.Store.DenyReason` can't reuse the matcher, so the design adds an exported `MatchRule(hop, rules) (Rule, bool)` used by both `Evaluate` and the new `DenyReasoner` — single source of truth so Allow and DenyReason can never disagree (modulo a documented copy-on-write TOCTOU that's advisory-only).

4. **Space-join encoding is safe**: OAuth scope grammar and RFC 8703/8707 resource URIs both exclude U+0020, so the flat-column space-join round-trips symmetrically — locked by a unit test, with the degenerate case documented as observability-only harm.

Each decision section covers API surface, storage model, failure modes (as tables), and what could break the design (drift gates, oracle-safety regression, migration versioning, `parent_jti` semantic confusion, event-count leakage, cardinality creep). No Go gates were run — this was a docs-only change; the doc pins the verification sequence for implementation.
