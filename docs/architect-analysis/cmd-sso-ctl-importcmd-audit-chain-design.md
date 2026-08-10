# Design: CLI-side provisioning joins the durable audit chain — recorder over the shared sink, one bounded event type, CC6.3 classification

- Direction: "CLI-side provisioning must join the durable audit chain (sqlite/postgres sink + hash chain + auditreport classification)" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-importcmd-347a57c8.json`, entry 2; values value 8 / risk_reduction 8 / effort 5 / confidence 8)
- Module label: `cmd/sso-ctl/importcmd` (+ the chain it joins: `platform/audit` recorder/chainer, `platform/audit/sqlite` sink, `infrastructure/postgres` audit sink, `platform/audit/auditreport` + `platform/audit/auditsink` + `protocols/compliance` classification)
- Requirements baseline: `docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-requirements.md` (all citations re-verified against HEAD `b6794956`; three material corrections recorded in §2)
- Status: design (evidence re-verified against the working tree)
- Prior art: direction-1 spec `cmd-sso-ctl-importcmd-governance-outbox-requirements.md` (shipped; the outbox pair-write this design complements — the chain record is the attestation surface, the outbox event remains the governance delivery surface)

## 1. Verification verdict (untrusted claims → measured reality)

Every citation in the evidence summary was re-checked against HEAD. All six
citations and the four key findings hold; the sub-line drifts and the
registration-count correction are in §2.

| Evidence claim | Measured reality | Verdict |
|---|---|---|
| `importer.go:48-80` `openDB` — no `audit_events` in CLI migration path | `openDB` at importer.go:51-88 (drift). It migrates the user schema (`sqlite.NewUserProvider` / `postgres.NewUserProvider`) AND the governance outbox (`auditoutbox.Migrate` for sqlite, `tenantcommerce.NewWithDB` for postgres — direction 1 landed). It never touches `audit_events`; `grep -rln audit_events infrastructure/defaultimpl/` returns nothing | **Confirmed with nuance** (line drift + outbox migration present; core claim unchanged) |
| `platform/audit/sqlite/sink.go` + `maintenance.go` — audit schema via `migrate.Run(..., "audit", ...)`; `LastHash` = `ChainTip` | `migrations` = v1 baseline (`audit_events` with `prev_hash`/`hash` + indexes, sink.go:38-61), v2 `tenant_id`, v3 `server_version`. `New` (sink.go:160, drift from :116) and `NewWithDB` (sink.go:182, drift from :128) run `migrate.Run(ctx, db, "audit", migrations)`; `OpenReadOnly` (sink.go:206, drift from :157) verifies the recorded version without migrating; `LastHash` (maintenance.go:75, `ts_unix_ns DESC, rowid DESC`) implements `audit.ChainTip` | **Confirmed** (three line drifts) |
| `platform/audit/chainer.go` — `WithHashChain`/`ChainTip` | `ChainTip` (chainer.go:44) with `LastHash`; fail-open doc: tip error seeds genesis and continues; `WithHashChain` (recorder.go:55-77, drift from :61-77) seeds from `sink.(ChainTip).LastHash` at construction; `GenesisHash`, `VerifyChain` (chainer.go:157), `VerifyChainSegment` (:172), `VerifyEventIntegrity`; `chain_resume_test.go` pins memory-sink genesis + tip resume via `fakeTipSink` | **Confirmed** (2-line drift) |
| `infrastructure/postgres/audit_sink.go:24-58` — DDL; `NewAuditSinkWithDB` (:121); `LastHash` (:252) | `auditSchema` exactly lines 24-58 (`BIGSERIAL seq`, `prev_hash TEXT`, `hash TEXT`, indexes); `auditMigrations` v1+v2; `NewAuditSinkWithDB` at line 121 runs `Run(ctx, db, "audit", auditMigrations, dialect)`; `LastHash` at line 252 (`ts DESC, seq DESC`); `Query` newest-first (audit_query.go:85) | **Confirmed exact** |
| `control_areas.go` + `bucketing.go` — test-enforced classification | `controlAreaDefs` (control_areas.go:82 CC6.3 "Privileged and administrative actions" carries every `EventAdminUser*` type); `TestControlAreaDefs_NoEventTypeClaimedTwice` (drift_test.go:90) + `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` (drift_test.go:103) + `wantUncategorizedEventTypes` (:28) + `TestBuildSOC2Report_HandlesEveryKnownEventType` (:148); `auditspi.TestKnownEventTypesIsComplete` (event_types_completeness_test.go:29) AST-parses `event_types*.go`; `bucketing.go` `areaAccumulator.add` skips empty `ActorID` (:22) | **Confirmed — stronger than cited** (a fourth auditreport test also walks every known type; see §2 correction) |
| `auditexport`/`auditverify` consumers | `auditexport` is `--dsn`-only in v1 (main.go:26), reads via `auditsqlite.OpenReadOnly(o.dsn)` (main.go:186), never migrates; `auditverify` consumes bundles (`--from-file`) or the live API (`--from-url`) with `VerifyChain`/`VerifyChainAgainstCheckpoint`/`VerifyChainSegment`; postgres attestation is in-harness only (no offline postgres export) | **Confirmed with constraint** (encoded into AC1) |

### Key findings (also verified)

| Finding | Measured reality |
|---|---|
| Direction 1 is in HEAD and cannot carry import events into the chain | `importEventType = "snaplink.audit.user.import"` (importer.go:32); `writeBatch` → `p.ImportUser` writes one `commerce.OutboxEvent` per user in the user row's transaction (importer.go:122-142; `newImportFact` :144-170); `auditoutbox.FactFromAudit` is fail-closed to `EventLoginFailure` only (fact.go:78-80) — no connector exists; the chain route must be the CLI recording `audit.Event`s itself |
| No import audit event type exists | `grep -rn user_import platform/audit/auditspi/` → nothing. Admin vocabulary has `EventAdminUserCreated/Updated/Deleted` (`admin_user_created`, event_types_admin.go:21) — server-side emitters only |
| Server precedent, same DB file | `BuildPrimaryAuditSink` (cmd/sso-server/serverbuildauthn/build_audit_secrets.go:34-53) uses `auditsqlite.New(cfg.Sqlite.DSN)` / `postgresbackend.NewAuditSinkWithDB(pg, dialect)`; `audit.WithHashChain()` appended at `cmd/sso-server/build_app_core.go:385` (evidence cited the wrong directory); server user store opens the SAME sqlite file — `ChainTip` resume across the server→CLI seam is a same-table continuation |
| Pool ownership | sqlite `Sink.Close` (sink.go:241-249) and postgres `AuditSink.Close` (audit_sink.go:129-137) close the wrapped `*sql.DB`; the provider owns the pool (`p.DB()`); the sink/recorder must be process-lifetime and never Closed by the CLI |
| Query order | Both sinks `ORDER BY ts_unix_ns DESC` (sqlite query.go:82, postgres audit_query.go:85) — tests must reverse to chain order before `VerifyChain` |
| Test-home split | `test/` cannot import `cmd/`; `cmd/sso-ctl/main.go:22-23,47-48` imports `auditexport`/`auditverify` and dispatches their `Run` — an export→verify loop test inside `cmd/` is legal |
| Budgets | `importer.go` = 232 lines (room under 500); `importcmd` has 4 non-test files (under 10); `interfaces/sso` untouched (60-file ceiling); no new top-level package |

## 2. Material corrections to the evidence

- **C1 — "three registrations" is actually six registration points.** The
  requirements' R4 says a new type needs three test-enforced registrations
  (const → `KnownEventTypes` → `controlAreaDefs`). Verified reality:
  - `event_types_admin.go` const + `event_types.go` map entry — enforced by
    `TestKnownEventTypesIsComplete` (auditspi).
  - `control_areas.go` CC6.3 entry — enforced by the three auditreport drift
    tests (the evidence missed `TestBuildSOC2Report_HandlesEveryKnownEventType`
    at drift_test.go:148, a fourth walker over every known type).
  - `platform/audit/aliases_spi.go` const alias — NOT test-enforced but
    **compile-enforced**: `control_areas.go` references `audit.EventAdminUserImported`,
    and the alias block (aliases_spi.go:17-201) is the only way that symbol
    exists. Miss it → build fails.
  - `platform/audit/auditsink` SIEM conformance — `TestConformance_EveryEventTypeHasCEFAndOCSFMapping`
    (conformance_test.go:155) walks the hand-transcribed `allKnownEventTypes`
    list (:20) and requires an explicit (non-fallback) entry in BOTH
    `cefEventNames` and `ocsfEventActivities`; the length drift guard
    (`len(allKnownEventTypes) != len(KnownEventTypes)+2`, :161) is a `t.Logf`
    soft check, but the documented intent is "every EventType const the SDK
    defines today must yield an explicit entry". The stricter contract wins:
    the new const is transcribed into `allKnownEventTypes` and curated in both
    tables (3 lines), or the SDK ships its own emitted type on silent
    generic/unmapped fallbacks. The requirements' file list omits this; the
    design includes it (§3.1).
  - `protocols/compliance/soc2.go:29` `changeManagementEventTypes` — curated
    list (no completeness test, no fallback). Decision D-7 adds the type: a
    bulk import IS a change-management action, and the compliance pack is the
    SOC2 evidence consumer this direction exists to feed. One line, additive.
- **C2 — line drifts** (all within cited ranges or one directory level):
  `openDB` importer.go:51-88 (evidence :48-80); `WithHashChain` recorder.go:55-77
  (evidence :61-77); sqlite `New`/`NewWithDB`/`OpenReadOnly` at :160/:182/:206
  (evidence :116/:128/:157); `LastHash` sqlite at maintenance.go:75 (the :252
  citation was postgres, correct); `build_app_core.go` lives in
  `cmd/sso-server/`, not `cmd/sso-server/serverbuildauthn/`.
- **C3 — `audit.New` cannot fail.** Recorder construction returns no error
  (recorder.go:88); the only CLI-open failure point is sink construction
  (migrations). The design therefore has exactly one new failure surface in
  `openDB`, handled identically to the existing outbox-migration error path.

## 3. Design

### 3.1 API changes

**Go API (additive; zero breaking changes; no new SPI at `shared/core`):**

| Symbol | Location | Notes |
|---|---|---|
| `EventAdminUserImported EventType = "admin_user_imported"` | `platform/audit/auditspi/event_types_admin.go` (beside `EventAdminUserCreated` :21) | Flat admin vocabulary, `admin_` prefix; file matches the `event_types*.go` AST glob. Exactly ONE constant — no per-format/per-provider variants (bounded cardinality; the source format rides in Metadata) |
| `KnownEventTypes` entry `EventAdminUserImported: {}` | `platform/audit/auditspi/event_types.go` (beside `EventAdminUserCreated` :280) | Second of the three test-enforced registrations |
| `EventAdminUserImported = auditspi.EventAdminUserImported` | `platform/audit/aliases_spi.go` (const block, alphabetical) | Compile-enforced alias (C1); keeps `audit.*` import surface uniform |
| `audit.EventAdminUserImported` in CC6.3 `eventTypes` | `platform/audit/auditreport/control_areas.go` (beside `EventAdminUserCreated` :94) | Third test-enforced registration; NOT added to `wantUncategorizedEventTypes` |
| `auditspi.EventAdminUserImported` in `allKnownEventTypes` + `cefEventNames` + `ocsfEventActivities` | `platform/audit/auditsink/conformance_test.go:20`, `cef.go:105` block, `ocsf.go:153` block | SIEM conformance curation (C1): CEF "Admin: User Imported"; OCSF `{ocsfClassAccountChange, ocsfCategoryIAM, 1, "Create"}` (bulk create is the closest OCSF activity) |
| `audit.EventAdminUserImported` in `changeManagementEventTypes` | `protocols/compliance/soc2.go:29` | Decision D-7: import = change-management evidence; one additive line |

**CLI-internal API (`cmd/sso-ctl/importcmd`, package-private):**

```go
// importDB bundles the store seam and the process-lifetime audit recorder
// over the SAME pool the provider owns. The recorder's sink is never Closed:
// both sinks' Close closes the wrapped *sql.DB, which the provider owns.
type importDB struct {
    userStore
    recorder *audit.Recorder
}

func openDB(backend, dsn, dialect string) (*importDB, error)         // was (userStore, error)
func runImport(ctx context.Context, db *importDB, tenantID string, users []importedUser, batchSize int) error
func writeBatch(ctx context.Context, db *importDB, tenantID string, batch []importedUser) (int, error)
```

`*importDB` embeds `userStore`, so every existing store call site (`p.ImportUser`,
`p.Close`, `p.DB`) compiles unchanged; the two test helpers
(`newTestProvider`/`newTestProviderDSN`) change their return type from
`userStore` to `*importDB` and existing `runImport` call sites follow
mechanically (all in-package, ~8 sites).

**No changes:** `auditexport`, `auditverify`, `platform/audit/{chainer,recorder}.go`,
`platform/audit/sqlite/*`, `infrastructure/postgres/{audit_sink,audit_query}.go`,
`infrastructure/auditoutbox`, `domains/tenant/commerce`, `interfaces/sso`,
`cmd/sso-server`, config, OpenAPI, error-codes (no new `Err*`, endpoint, or
config knob).

### 3.2 CLI wiring (importer.go)

`openDB` gains, after the outbox migration succeeds, in each backend branch:

```go
case "", backendSQLite:
    p, err := sqlite.NewUserProvider(dsn)
    if err != nil { return nil, fmt.Errorf("sqlite: %w", err) }
    if err := auditoutbox.Migrate(context.Background(), p.DB()); err != nil {
        _ = p.Close(); return nil, err
    }
    sink, err := auditsqlite.NewWithDB(p.DB())   // runs "audit"-namespace migrations
    if err != nil { _ = p.Close(); return nil, err }
    return newImportDB(p, sink), nil
case backendPostgres:
    // ...provider + tenantcommerce.NewWithDB as today...
    sink, err := postgres.NewAuditSinkWithDB(p.DB(), postgres.Dialect(dialect))
    if err != nil { _ = p.Close(); return nil, err }
    return newImportDB(postgresUserStore{p}, sink), nil
```

```go
// newImportDB builds the one process-lifetime recorder. WithHashChain seeds
// the chainer from sink.(ChainTip).LastHash at construction (resume across
// server->CLI and CLI->CLI boundaries); WithErrorHandler surfaces recording
// failures on stderr, never failing the import (audit is fail-open).
func newImportDB(store userStore, sink audit.Sink) *importDB {
    rec := audit.New(sink,
        audit.WithHashChain(),
        audit.WithErrorHandler(func(err error) {
            fmt.Fprintf(os.Stderr, "%s: audit record failed: %v\n", progName, err)
        }),
    )
    return &importDB{userStore: store, recorder: rec}
}
```

`writeBatch` records exactly one chain event per successful `ImportUser`,
AFTER the (user, outbox) pair commits (fail-open: a recording failure must
never roll back an imported user):

```go
if err := db.ImportUser(ctx, ssoUser, newImportFact(tenantID, ssoUser)); err != nil {
    errs = append(errs, fmt.Sprintf("%s: %v", u.ID, err))
    continue          // failed/skipped row: NO chain event (pair semantics)
}
ok++
db.recorder.Record(ctx, newAuditEvent(tenantID, u))
```

```go
// newAuditEvent is the bounded, redacted chain event for one imported user.
// Metadata ONLY via audit.SetMeta: target_user (the operator-supplied ID) and
// provider (the closed parser vocabulary: auth0|keycloak|okta|csv). Never the
// password hash, hash format, email, or any attribute material. Event.Provider
// stays empty on purpose (D-3): that column means the auth-time identity
// provider; the import source format is a different semantic.
func newAuditEvent(tenantID string, u importedUser) *audit.Event {
    e := &audit.Event{
        Type:      audit.EventAdminUserImported,
        Outcome:   audit.OutcomeSuccess,
        TenantID:  tenantID,
        Timestamp: time.Now().UTC(),
    }
    audit.SetMeta(e, "target_user", u.ID)
    audit.SetMeta(e, "provider", u.Provider)
    return e
}
```

The recorder stamps `PrevHash`/`Hash` before the sink persists (chainer runs
inside `Record`, recorder.go:170-178); the sink assigns `ID`; the chainer's
monotonic timestamp bump (chainer.go:57-71) keeps `ts` order == chain order
within the run. `main.go:115-121` keeps `defer db.Close()` (closes the
provider only — the sink is never Closed, D-2; process exit tears down the
pool). Package doc + usage text gain one sentence: imports are recorded into
the server's `audit_events` chain (R6).

### 3.3 Wire/storage contract

- **Schema:** no DDL change anywhere. The CLI's `openDB` runs the EXISTING
  "audit"-namespace migrations (`platform/audit/sqlite` v1-v3;
  `infrastructure/postgres` v1-v2) over the provider's pool — byte-identical
  to the schema the server's `BuildPrimaryAuditSink` creates and
  `auditexport.OpenReadOnly` validates. Fresh DB → table created and stamped
  `schema_migrations_audit` at the binary's `MaxVersion`; server-migrated DB →
  no-op; newer file → fail fast with the `OpenReadOnly`-style version-mismatch
  error.
- **Row shape:** `type='admin_user_imported'`, `outcome='success'`,
  `tenant_id=<--tenant>`, `ts_unix_ns` (monotonic per chainer),
  `prev_hash`/`hash` (chain-stamped), `metadata_json={"target_user":...,
  "provider":...}`, all other columns empty. No request/trace IDs (no HTTP
  context — matches system/bootstrap events).
- **Chain continuity:** same-table `ChainTip` resume. Server ran with
  `cfg.Audit.HashChain` → the CLI's first event's `PrevHash` == last server
  event's `Hash`; one unbroken chain across the seam, no server change.
  Server ran without chaining (hash columns empty) → `LastHash` returns ""
  and the CLI seeds genesis at the boundary (documented `WithHashChain`
  fail-open); the CLI's own segment verifies via `VerifyChainSegment` anchored
  at the boundary.
- **Event payload:** bounded cardinality (one type); redacted (SetMeta-only);
  hashed over the redacted form (redaction precedes chaining,
  recorder.go:170-175).

### 3.4 Compatibility constraints

| Constraint | Behavior |
|---|---|
| DB files | Existing DBs need NO migration step: the audit schema is already present from the server; fresh DBs get it on first CLI open. Old CLI binaries against a newer DB: unaffected (they never touch the audit namespace) |
| Wire/Go API | Zero breaking changes; one additive `EventType` const; all six registration surfaces are additive map/slice/const entries |
| Chain hash wire contract | `audit.Event` field order untouched (eventHash stability, chainer.go:102-118) — no re-hash of existing chains |
| Export/verify consumers | `auditexport` (sqlite `OpenReadOnly`) and `auditverify` read the new rows as ordinary chained events; schema-version check passes because the CLI stamps the same namespace/version |
| Mixed chaining modes | Server-without-chain + CLI-with-chain yields a documented boundary genesis (fail-open resume); never a schema or API conflict |
| Re-import | Same IDs append new chain events (direction-3 dedupe out of scope); appends never rewrite past events, so existing chains verify unchanged |
| Concurrency | CLI is single-process; sqlite single-writer caveat applies (same as documented `Prune`); no lock is held between open and exit beyond normal pool usage |
| Rollout/rollback | New behavior only for imports run with the new binary; a rolled-back CLI writes no chain rows and leaves existing chains intact |

### 3.5 Failure modes

| # | Failure | Behavior | Contract |
|---|---|---|---|
| F1 | Audit migration fails at CLI open (locked file, newer schema version, I/O) | Provider closed, error returned, exit 1 — before any user row is written | Fail fast, identical to the existing outbox-migration path (importer.go:59-62) |
| F2 | `ChainTip.LastHash` read error at recorder construction | Seeds genesis and continues; only visible effect is a boundary chain break | `WithHashChain` documented fail-open (recorder.go:61-77) |
| F3 | Sink `Record` fails after `ImportUser` committed | Error handler prints to stderr; batch continues; user + outbox event committed WITHOUT a chain row | AGENTS.md "fail open with audit/logging: audit sink errors"; attestation gap is operator-visible on stderr |
| F4 | Server ran without hash chaining | CLI seeds genesis at the boundary; `VerifyChain` over the WHOLE table reports the boundary break; the CLI segment verifies via `VerifyChainSegment` | Documented on `WithHashChain` + sink `LastHash` |
| F5 | Failed/skipped import row | Records nothing (no chain event, no outbox event — pair semantics); batch continues; skip accounting unchanged (direction-1 R6) | R3 |
| F6 | Clock step-back across runs | `LastHash` (`ts DESC`) may select a non-head row; pre-existing behavior; production clocks slew, never step (AGENTS.md §3) | Not worsened by this change |
| F7 | Concurrent server + CLI on one sqlite file | Single-writer applies (same caveat as `Prune`); migrations are `IF NOT EXISTS`/idempotent | Documented |
| F8 | `--dry-run` | No DB open, no events | R3 |
| F9 | Recorder/sink `Close` accidentally called | Both sinks close the provider-owned `*sql.DB` — the design never Closes the sink (D-2); tests Close the provider only | Pool ownership |

### 3.6 Migration / rollout steps

1. Ship the additive registrations (§3.1) + the CLI change as ONE commit; the
   three test-enforced gates + SIEM conformance gate go green in the same
   commit (`go test ./platform/audit/... ./cmd/sso-ctl/...`).
2. Deploy order is free: the server is untouched; the new CLI can be shipped
   ahead of, with, or after the server (no config, no schema, no API
   dependency).
3. First CLI import on an existing deployment: `openDB` runs the idempotent
   "audit" migrations (no-op on server-migrated DBs) and resumes the chain
   from the durable head (or seeds the documented boundary genesis when the
   server ran chainless).
4. Evidence collection is unchanged tooling: `sso-ctl audit-export --dsn ...`
   then `sso-ctl audit-verify --from-file ...` (optionally `--anchor`); import
   events appear in the bundle under CC6.3 in `sso-ctl soc2report` (via
   `auditreport`) and in the compliance pack's change-management section
   (D-7).
5. Rollback: deploy the previous CLI binary. No data migration; no cleanup;
   existing chains and bundles verify unchanged; imports simply stop producing
   chain events until the new binary returns.

### 3.7 Testable acceptance mapping

Test homes per the verified split: `test/` (package `ssotest`) cannot import
`cmd/`, so AC1/AC2 store-level proofs drive the EXACT package calls the CLI
makes (`sqlitestores.NewUserProvider` → `auditoutbox.Migrate` →
`auditsqlite.NewWithDB(p.DB())` → `audit.New(sink, audit.WithHashChain())` →
`ImportUser` + `rec.Record`), mirroring `test/importcmd_governance_outbox_test.go`
(which already provides `importEvent`, `newImportDB`, `importUsers` helpers).
`cmd/sso-ctl/importcmd/main_test.go` proves the real CLI wiring, and — legal
because `cmd/sso-ctl/main.go:22-23` imports both subcommands — the real
export→verify loop. Postgres is env-gated (`SSO_TEST_POSTGRES_DSN`,
`SSO_TEST_POSTGRES_DIALECT`, the same convention as main_test.go:783 and
tenantcommerce/import_test.go:22).

| AC | Test (file → function) | Assertions |
|---|---|---|
| AC1 sqlite | `test/importcmd_audit_chain_test.go` → `TestImportAuditChain_FreshSQLite` | Fresh file DSN; N users via `ImportUser` + `Record`; read back via `sink.Query` (newest-first) → reverse → `audit.VerifyChain` nil; `events[0].PrevHash == audit.GenesisHash`; exactly N rows, all `Type == auditspi.EventAdminUserImported`, all `TenantID == tenant` |
| AC1 postgres | `test/importcmd_audit_chain_test.go` → `TestImportAuditChain_Postgres` (env-gated) | Same chain proof over `postgres.NewAuditSinkWithDB(p.DB(), dialect)` + `Query` + `VerifyChain` (no offline postgres export exists in v1 — attested in-harness per the verified constraint) |
| AC1 real tool path | `cmd/sso-ctl/importcmd/main_test.go` → `TestAuditChain_ExportVerifyLoop` | CLI import into fresh sqlite file → `auditexport.Run([]string{"--dsn", dsn})` → bundle → `auditverify.Run([]string{"--from-file", bundle}) == 0`; bundle contains exactly N `admin_user_imported` events |
| AC2 | `test/importcmd_audit_chain_test.go` → `TestImportAuditChain_Resume` | After AC1: `head := sink.LastHash`; simulate the process boundary with a FRESH recorder (`audit.New(sink, audit.WithHashChain())`); import M NEW distinct IDs; first new event's `PrevHash == head`; `VerifyChain` over all N+M nil; exactly ONE genesis (`PrevHash == ""`) in the table |
| AC3 | `platform/audit/auditreport/` new unit test (e.g. `control_area_import_test.go` → `TestImportEventsFileUnderCC63`) + existing gates | `BuildSOC2Report` over a bundle of N import events → CC6.3 `TotalEvents == N`, "Uncategorized" == 0; exactly one control-area claim. Existing gates green: `TestKnownEventTypesIsComplete`, `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized`, `TestControlAreaDefs_NoEventTypeClaimedTwice`, `TestBuildSOC2Report_HandlesEveryKnownEventType`, `TestConformance_EveryEventTypeHasCEFAndOCSFMapping`. Exactly one vocabulary constant (no per-format variants) |
| AC4 | `cmd/sso-ctl/importcmd/main_test.go` → `TestAuditChain_ExportVerifyLoop` (+ a skip-row variant `TestImportAuditChain_SkippedRowRecordsNothing`) | Bundle contains exactly N `admin_user_imported` events; `Metadata["target_user"]` matches the imported set; zero events for the skipped identity (same failing-row trigger as the direction-1 skip-accounting tests, main_test.go:555-578); `auditverify --from-file` exits 0; re-export is byte-stable for the event set (export is a read) |
| R1 schema | `cmd/sso-ctl/importcmd/main_test.go` → `TestOpenDB_MigratesAuditSchema` | Fresh sqlite: `audit_events` exists + `schema_migrations_audit` current version == `migrate.MaxVersion(migrations)` (both backends; postgres env-gated); re-open same file succeeds (idempotent no-op) |
| R3 semantics | `cmd/sso-ctl/importcmd/main_test.go` → `TestRunImport_WritesChainEvents` / `TestDryRun_NoAuditRows` | N users → N events via the real `Run` path; dry-run opens no DB; metadata keys ⊆ {`target_user`, `provider`} |

All existing tests keep passing with the signature change: the two provider
helpers (`newTestProvider`/`newTestProviderDSN`) return `*importDB`, which
embeds `userStore`, so store-only call sites compile unchanged.

### 3.8 Gates, budgets, and contracts

- Budgets: `importer.go` 232 → ~290 lines (≤ 500); `importcmd` 4 non-test
  files (≤ 10); no new top-level package (no `architecture_layer_test.go`
  change); `interfaces/sso` untouched (60-file ceiling); `event_types_admin.go`
  133 → ~136 lines (≤ 500).
- Contracts: no new `Err*` (no `docs/error-codes.md`), no endpoint (no
  `docs/openapi.yaml`), no config knob (no `docs/config-reference.md`); CLI
  package doc + usage text mention chain recording; event types remain bounded
  (one new const); metadata only via `audit.SetMeta`; W3C trace IDs not
  applicable (no HTTP context).
- Verification commands:

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./platform/audit/auditspi/ ./platform/audit/auditreport/ ./platform/audit/auditsink/ \
  -run 'TestKnownEventTypesIsComplete|TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized|TestControlAreaDefs_NoEventTypeClaimedTwice|TestBuildSOC2Report_HandlesEveryKnownEventType|TestConformance_EveryEventTypeHasCEFAndOCSFMapping' -v
go test ./cmd/sso-ctl/importcmd/... -run 'TestOpenDB|TestRunImport|TestAuditChain|TestDryRun' -v
go test ./test/ -run TestImportAuditChain -v          # AC1/AC2 (postgres env-gated)
go test ./... -race
make ci
```

## 4. Files touched

### Modify

```text
cmd/sso-ctl/importcmd/importer.go        — importDB bundle; openDB wires sink+recorder (R1/R2); writeBatch records one event per successful import (R3); newAuditEvent (D-3); ~232 → ~290 lines
cmd/sso-ctl/importcmd/main.go            — package doc + usage note (R6); Run wires *importDB
cmd/sso-ctl/importcmd/main_test.go       — helper return-type change; R1 schema test; AC1 wiring + export→verify loop (AC1/AC4); skip-row variant (AC4); dry-run test
platform/audit/auditspi/event_types_admin.go  — EventAdminUserImported const (R4)
platform/audit/auditspi/event_types.go        — KnownEventTypes entry (R4)
platform/audit/aliases_spi.go                 — const alias (C1, compile-enforced)
platform/audit/auditreport/control_areas.go   — CC6.3 entry (R4)
platform/audit/auditsink/conformance_test.go  — allKnownEventTypes entry (C1)
platform/audit/auditsink/cef.go               — cefEventNames entry (C1)
platform/audit/auditsink/ocsf.go              — ocsfEventActivities entry (C1)
protocols/compliance/soc2.go                  — changeManagementEventTypes entry (D-7)
platform/audit/auditreport/control_area_import_test.go — AC3 unit test (new file)
```

### Create

```text
docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-design.md  — this spec
test/importcmd_audit_chain_test.go  — AC1/AC2 store-level proofs (package ssotest; sqlite file-backed; postgres env-gated)
```

### Do not modify

```text
cmd/sso-ctl/auditexport, cmd/sso-ctl/auditverify      — consumers, unchanged (R5)
platform/audit/chainer.go, recorder.go, platform/audit/sqlite/*, infrastructure/postgres/{audit_sink,audit_query}.go — consumed as-is
infrastructure/auditoutbox/fact.go                    — login-failure-only gate stays fail-closed
domains/tenant/commerce, infrastructure/auditgovernance — direction-1 machinery, untouched
interfaces/sso, cmd/sso-server, config, shared/core   — untouched
```

## 5. Decisions (with rationale)

- **D-1** — recorder built in `openDB` via `audit.New(sink, WithHashChain(), WithErrorHandler(stderr))`; one recorder per run. Rationale: the resume seam is construction-time (`recorder.go:61-77`); the process is one-shot; `audit.New` cannot fail.
- **D-2** — the sink is never Closed (both sinks' `Close` closes the provider-owned `*sql.DB`); teardown is process exit. Tests Close the provider only.
- **D-3** — metadata keys `target_user` + `provider` via `audit.SetMeta`; `Event.Provider` stays empty. Rationale: that column means the auth-time identity provider; the import source format is a different semantic, and one redaction surface (the JSON blob, carried in export bundles) beats dual-source drift.
- **D-4** — `openDB`/`runImport`/`writeBatch` take a bundled `*importDB` (embeds `userStore` + `recorder`). Rationale: existing store-only call sites compile unchanged; the recorder cannot be forgotten at a call site.
- **D-5** — `--dry-run` unchanged: no DB, no events, no chain rows.
- **D-6** — SIEM curation in scope (C1): the conformance test's documented intent covers SDK-emitted types; shipping our own type on fallbacks would be a silent conformance gap.
- **D-7** — `changeManagementEventTypes` gains the type (one line). Rationale: bulk import is a change-management action; the compliance pack is the SOC2 evidence consumer this direction feeds; additive and unreachable by existing tests.

## 6. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./platform/audit/auditspi/ ./platform/audit/auditreport/ ./platform/audit/auditsink/ -v
go test ./cmd/sso-ctl/importcmd/... -v
go test ./test/ -run 'TestImportAuditChain' -v
go test ./... -race
make ci
```
