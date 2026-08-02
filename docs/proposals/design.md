Design doc written to `docs/auto/domains-tokenpolicy-direction2-design.md`. I verified every evidence claim in the spec against the code first — all check out:

**Verified during review**
- Both deny seams confirmed audit-free: `enforceTokenPolicy` (server_helpers.go:99-104) and `sessionPolicyCapExceeded` (server_oauth.go:184-190, behind the `DenyActiveSessions` reason guard); the session seam is reached only via `createSession` (server_logout.go:357)
- `Event` struct has the needed `Reason`/`ActorID`/`ClientID`/`Metadata` fields; `HandlerContext = core.HandlerContext` so the helper's context parameter binds directly
- Precedents confirmed: nil-safe `RecordDeviceCodeDecision`, `audit.RecordRefreshRotationVelocityExceeded(s.auditor, ctx, ...)` at server_helpers.go:487, CC7.2 bucket, CEF/OCSF triplet mappings
- Budgets confirmed: server_helpers.go 493/500, server_oauth.go 481/500, recorder_events.go 354/500 — the whole change to the two tight files is two one-line calls

**Design decisions (## headings)**

1. **API surface — event type/alias/helper**: `EventTokenPolicyDenied = "token_policy_denied"` + SPI alias + `audit.RecordTokenPolicyDenied(rec, ctx, clientID, subjectID, policyName, reason)` with an explicit field-mapping table (Reason from the closed `DenyReason` set, `policy_name` via `SetMeta` only when non-empty, empty `ActorID` = honest absence at the scope-combo seam).
2. **`PolicyDecision.DeniedBy`**: the one real trap — it must be assigned in the *same first-deny branch* as `Reason`; a post-loop pass would silently flip attribution to the last deny.
3. **Wiring**: exact one-line insertions with placement rules — emission inside the deny branch only, wire write stays last, no double-emission (both token seams funnel through `enforceTokenPolicy`'s single deny branch; session seam is disjoint).
4. **Registration**: `KnownEventTypes` + CC7.2 claim + CEF/OCSF + `docs/observability.md`; flagged that adding the type to the *uncategorized list* instead of the CC7.2 claim would pass the drift test while silently hiding governance denials from the SOC2 report.

**Storage model**: no new storage, no schema, no migration — the event rides the existing recorder → sink pipeline; cardinality table per dimension with the explicit not-stored list (scopes, client lists, request input).

**Failure modes**: 10-row table — nil recorder, fail-open store/list errors (no manufactured deny records), default-off, sink errors fail open, canceled contexts.

**What could break the design**: 9 risks led by the file budgets (493/500 and 481/500 leave room for exactly the two lines), then `DeniedBy` branch drift, registration drift, name-based (not ID-based) attribution breaking across rule renames/reorders, cardinality creep, wire regression, double emission, seam-guard placement, and the docs gate.

No `.go` files changed, so no build gates run — consistent with the spec being spec-only.
