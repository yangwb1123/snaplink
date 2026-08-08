All six registration points are now verified against HEAD (`8598a26b`). Here is the complete verification report.

## Verification verdict: complete, with one material drift found in the SIEM guard

### 1. `KnownEventTypes` (auditspi) — ✅ complete, test-enforced
- `event_types_admin.go:21` — `EventAdminUserCreated EventType = "admin_user_created"`; the new const fits the flat `admin_` vocabulary beside it.
- `event_types.go:280-281` — map entries `EventAdminUserCreated: {}, EventAdminUserUpdated: {}, ...`; new entry fits.
- Enforced: `TestKnownEventTypesIsComplete` (event_types_completeness_test.go:29) AST-parses every `event_types*.go` and fails naming the missing const. **Running now: 173/173 consts in the map, PASS.**

### 2. `aliases_spi.go` — ✅ no bypass; compile-enforcement is double-anchored
- The alias block (175 `= auditspi.Event...` lines) is the **only** surface: grep confirms zero `EventType = "..."` const declarations in `platform/audit` outside `auditspi/`.
- Compile anchor is not single but double: `control_areas.go` (imports *only* `platform/audit`) **and** `protocols/compliance/soc2.go:32` (uses `audit.`) will both reference `audit.EventAdminUserImported`. Miss the alias → build fails.
- No bypass: defining the const directly in `platform/audit` would break the `auditspi.EventAdminUserImported` references in the auditsink tables and the `KnownEventTypes` entry (undefined identifier in `auditspi`).

### 3. `controlAreaDefs` CC6.3 (auditreport) — ✅ correct classification, test-enforced
- `control_areas.go:82` CC6.3 "Privileged and administrative actions" carries `audit.EventAdminUserCreated` (:94)/Updated/Deleted and the full admin mutation set. New type goes beside :94.
- Enforcement is stronger than the design claims: three drift tests (`NoEventTypeClaimedTwice`, `EveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` with `wantUncategorizedEventTypes`, `BuildSOC2Report_HandlesEveryKnownEventType` no-panic + sum invariant) — **all PASS at HEAD**. The allowlist contains no `EventAdminUser*` entries, so the design's "NOT added to `wantUncategorizedEventTypes`" is consistent.
- Bucketing is data-table driven (`soc2.go:115-140`, `claimed[e.Type]` map, no switch): the type lands in CC6.3 exactly once.

### 4. SIEM conformance — ⚠️ tables correct, but the guard has a live 44-type bypass
- `conformance_test.go:20` `allKnownEventTypes`; :159 `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` requires explicit non-fallback entries in both tables for every *transcribed* type. **PASS.**
- `cef.go:105` `"Admin: User Created"` / `ocsf.go:153` `{ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"}` — the design's proposed entries are exact pattern matches; OCSF activity 1 = Create is correct for bulk create.
- **Material finding:** the length guard `len(allKnownEventTypes) != len(KnownEventTypes)+2` (soft `t.Logf`) is **rotten at HEAD**: actual counts are 129 vs 173 — 44 SDK consts (BreakGlass, Change*, `EventAdminUserLifecycleChanged`, `EventNewDeviceLogin`, `EventTrustDecay`, …) are untranscribed and ride the silent generic fallback, and the "+2" comment's premise is inverted (both recovery-code consts *are* in `KnownEventTypes` now). The test cannot fail on this — it only logs a line that now misleads ("see comment on the +2 above"). The design correctly called the guard soft and D-6 correctly picks the stricter contract, but C1 reproduced the stale "+2" as fact. Since the change touches these three files anyway, the stale comment/guard should be corrected in the same change (AGENTS.md §5.6 contract hygiene), else the new transcription keeps the misleading log firing.
- Fallback safety is pinned: `TestConformance_UnknownEventTypeFallsBackSafely` proves non-empty generic output, no panic — so even a missed transcription cannot break formatters.

### 5. SOC2 `changeManagementEventTypes` — ✅ policy line confirmed
- `soc2.go:29` curated list (no blanket `admin_` prefix match, documented rationale); consumed by `buildChangeManagement` → `queryByTypes` (soc2.go:173-181). One additive line; unreachable by existing tests — matches D-7 exactly. Also serves as the second compile anchor for the alias.

### 6. Bounded cardinality — ✅ respected
- One const, no per-format/per-provider variants; metadata only via `audit.SetMeta` with exactly two keys `{target_user, provider}`; provider is the closed vocabulary `auth0|keycloak|okta|csv` (main.go:68, format flag :135).
- `TestBuildSOC2Report_NeverEmbedsRawEvents` (PASS) pins counts-only reporting; `areaAccumulator.add` (bucketing.go:22) skips empty `ActorID` — the CLI events carry none, so `DistinctActors` is unaffected. Facets treat Type as a fixed observed-values dimension (facets.go:14-17); one new value is in-design. W3C trace IDs N/A (no HTTP context).

### Consumers (export, verify, reporting) — ✅ no breakage on CLI-only emission
- **auditexport**: type-agnostic row reader; `--type` warning is advisory and the new type *is* in `KnownEventTypes` → no spurious warning (main.go:424-433).
- **auditverify**: hash-chain verification only — zero `KnownEventTypes` references; `verifyOptions` is generic.
- **soc2report**: `auditreport.VerifyAndBuildSOC2Report`; new type buckets into CC6.3; sum invariant holds.
- **Webhook validation** (build_audit_webhook.go:130): advisory log only, custom types allowed. **auditoutbox**: fail-closed to `EventLoginFailure` — the CLI chain event bypasses it entirely (direct recorder), no interaction.
- No panic-on-unknown-type `switch` exists in any consumer path (only `filtering_sink`/`severity` switches on non-type values).

**Bottom line:** five of six points are fully enforced as claimed; the SIEM conformance point is correctly specified and correctly curated per D-6, but the drift guard itself has a live 44-type bypass at HEAD with a stale comment — the design should record this correction (its C1 "+2" is outdated) and fix the guard/comment in the same commit, since the new transcription otherwise ships with a misleading soft guard that already fails to cover 44 shipped types.
