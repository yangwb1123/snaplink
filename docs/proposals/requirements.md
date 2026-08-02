Spec written to `docs/auto/domains-tokenexchange-audit-spec.md`. All evidence was verified against the current tree before writing. Summary of the three decisions:

## 1. `token_exchange_denied` audit event
- **Problem**: `tokExEnforcePolicy`'s deny path (`token_exchange.go:391` — `SrvLogger().Error` + `invalid_grant`) emits no audit event; `event_types.go` has no token-exchange deny class despite `mfa_failure`/`device_code_denied`/`ciba_denied` precedents. AGENTS.md §3's oracle-safe discipline designates audit as the only reason channel.
- **Behavior**: new `EventTokenExchangeDenied` (both `!allow` and policy-error paths), fail-open, `Outcome=Failure`, first-class `TokenID` (subject jti) / `SessionID` (sid) / fixed-vocabulary `Reason`, `SetMeta` for scope/resource/rule/subject/actor. Adds an optional `DenyReasoner` capability hook (FacetQuerier-style type assertion) so the matched rule name reaches audit without breaking `Policy.Allow`; wire stays byte-identical.

## 2. ChainHop correlation keys (scopes/resources/requested-token-type/session)
- **Problem**: `ChainHop` has 7 fields; `sqlite/chain_store.go` schema mirrors them; `tokExRecordChainHop` drops the already-resolved `st.scopes`/`st.resources`/`req.RequestedTokenType`/`st.claims.SID` at the persistence boundary — no token→session reverse lookup.
- **Behavior**: extend `ChainHop` + `RecordExchangeHopFailOpen` (single call site), sqlite migration v2 (flat scalar columns, space-joined sets), memory store struct-copy, no SPI method changes. Admin `GET /api/v1/admin/tokenexchange/chains/:jti` surfaces the enriched hops automatically.

## 3. Mint/issuance audit jti correlation
- **Problem**: `auditDelegationMint` (`grant.go:213-229`) records session+scopes but no jti; the exchange success audit is generic `token_issued` (`token_exchange_stages.go:376` → `recorder_events.go:22-29`) with no TokenID/SessionID — audit, chain, and token are unjoinable.
- **Behavior**: `mintDelegationToken` derives the jti via `JTIFromJWTUnsafe` and sets first-class `TokenID`/`SessionID` on the mint event; new `token_exchange_issued` event emitted beside `tokExRecordChainHop` with jti/sid/scope/parent-jti. Both events registered in `KnownEventTypes` + `auditreport` CC6.1; generic `token_issued` untouched (no cross-grant blast radius).

Each decision includes file/line evidence and an acceptance check (unit round-trips, drift tests, integration joins via `test/` harnesses). This is a docs-only change; no Go gates were required.
