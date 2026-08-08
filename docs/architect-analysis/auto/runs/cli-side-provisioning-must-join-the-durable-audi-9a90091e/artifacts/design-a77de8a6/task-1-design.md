All verification and design work is complete. Summary:

## Verification results (all evidence claims checked against HEAD `b6794956`)

| Citation | Verdict |
|---|---|
| `importer.go:48-80` openDB — no `audit_events` in CLI migration path | **Confirmed with nuance** — openDB is at :51-88; migrates user schema + governance outbox (direction 1 landed); `grep -rln audit_events infrastructure/defaultimpl/` returns nothing |
| sqlite sink + `maintenance.go` — "audit" namespace migrations; `LastHash` = `ChainTip` | **Confirmed** (line drift: `New` :160 / `NewWithDB` :182 / `OpenReadOnly` :206; `LastHash` maintenance.go:75) |
| `chainer.go` — `WithHashChain`/`ChainTip` resume | **Confirmed** (recorder.go:55-77; `chain_resume_test.go` pins semantics) |
| postgres `audit_sink.go:24-58`; `NewAuditSinkWithDB` :121; `LastHash` :252 | **Confirmed exact** |
| `control_areas.go` + `bucketing.go` classification | **Confirmed — stronger than cited**: a fourth walker exists (`TestBuildSOC2Report_HandlesEveryKnownEventType`) |
| `auditexport`/`auditverify` consumers | **Confirmed with constraint**: sqlite-DSN-only offline; postgres in-harness |

## Material corrections found

1. **"Three registrations" is actually six**: const → `KnownEventTypes` → `platform/audit/aliases_spi.go` alias (**compile**-enforced) → `controlAreaDefs` CC6.3 → SIEM conformance (`allKnownEventTypes` + `cefEventNames` + `ocsfEventActivities` — `TestConformance_EveryEventTypeHasCEFAndOCSFMapping` makes fallbacks a deliberate gap for SDK-emitted types) → `protocols/compliance/soc2.go` `changeManagementEventTypes` (policy line, decision D-7).
2. Line drifts in three citations (all ≤2 lines or one directory level — `build_app_core.go` is in `cmd/sso-server/`, not `serverbuildauthn/`).
3. `audit.New` cannot fail — the only new `openDB` failure surface is sink construction (migrations).

## Design delivered (`docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-design.md`)

- **API**: one additive `EventAdminUserImported = "admin_user_imported"` const with six registration points; CLI-internal `importDB` bundle (embeds `userStore` + recorder) so existing test call sites compile unchanged; zero breaking changes, no new SPI/Err/endpoint/config.
- **Compatibility**: no DDL change (CLI runs the existing "audit"-namespace migrations over the provider pool); same-table `ChainTip` resume across server→CLI; mixed chainless-server boundary genesis documented; sink never Closed (pool ownership).
- **Failure modes**: 9-item table (F1 migration fail-fast, F3 fail-open record errors to stderr, F5 skipped rows record nothing, etc.).
- **Migration**: one commit, free deployment order, no server/config/schema dependency, rollback = old binary.
- **Acceptance mapping**: AC1–AC4 → concrete test files/functions with exact assertions, respecting the `test/`-cannot-import-`cmd/` split; postgres env-gated via the existing `SSO_TEST_POSTGRES_DSN` convention; export→verify loop legal inside `cmd/` (dispatcher imports both subcommands).
