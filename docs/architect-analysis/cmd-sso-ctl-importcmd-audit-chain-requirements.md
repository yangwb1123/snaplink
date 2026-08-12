# Requirements Spec: CLI-side provisioning joins the durable audit chain (sqlite/postgres sink + hash chain + auditreport classification)

- Direction: "CLI-side provisioning must join the durable audit chain (sqlite/postgres sink + hash chain + auditreport classification)" (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-importcmd-347a57c8.json`, entry 2)
- Module: `cmd/sso-ctl/importcmd` (+ the audit chain it must join: `platform/audit` recorder/chainer, `platform/audit/sqlite` sink, `infrastructure/postgres` audit sink, `platform/audit/auditreport` classification)
- Status: requirements (evidence-verified against HEAD)
- Values from direction: value 8, risk_reduction 8, effort 5, confidence 8

## 1. Evidence verification

Every citation in the direction was re-checked against the repository, plus the
files the direction's own acceptance implies. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/importcmd/importer.go:48-80` — `openDB`, user schema only | `openDB` is at importer.go:51-88. It migrates the user schema (`sqlite.NewUserProvider` / `postgres.NewUserProvider`) **and**, since direction 1 landed, the governance outbox (`auditoutbox.Migrate` for sqlite, `tenantcommerce.NewWithDB` for postgres). It does NOT touch `audit_events`. `grep -rln audit_events infrastructure/defaultimpl/` returns nothing — the audit schema is not under the CLI's migration path | Confirmed (nuance: the outbox migration is now also present; the "audit schema absent from the CLI's migration path" claim is unchanged) |
| `platform/audit/sqlite/sink.go` + `maintenance.go` — audit schema lives outside the CLI's migration path | `migrations` (sink.go:24-30: v1 `audit_events` baseline with `prev_hash`/`hash` columns + indexes; v2 `tenant_id`; v3 `server_version`) run via `migrate.Run(ctx, db, "audit", migrations)` in `New` (sink.go:116) and `NewWithDB` (sink.go:128). `OpenReadOnly` (sink.go:157) verifies the schema version without migrating — the offline-tool contract. `LastHash` (maintenance.go) implements `audit.ChainTip` (`ts_unix_ns DESC, rowid DESC`) | Confirmed |
| `platform/audit/chainer.go` — `WithHashChain`/`ChainTip` restart resume | `ChainTip` interface (chainer.go:44) with `LastHash`; doc: "" on an empty store seeds genesis, a tip error seeds genesis and continues (fail-open). `WithHashChain` (recorder.go:61-77) builds the `chainer` and seeds it from `sink.(ChainTip).LastHash` at `Recorder` construction. `GenesisHash` (chainer.go:128), `VerifyChain`, `VerifyChainSegment`, `VerifyEventIntegrity`. `chain_resume_test.go` pins memory-sink genesis and tip-resume semantics | Confirmed |
| `infrastructure/postgres/audit_sink.go:24-58` — `audit_events` DDL with `prev_hash`/`hash` | `auditSchema` is exactly lines 24-58 (`BIGSERIAL seq`, `prev_hash TEXT`, `hash TEXT`, indexes); `auditMigrations` v1+v2; `NewAuditSinkWithDB` (line 121) runs `Run(ctx, db, "audit", auditMigrations, dialect)` — same "audit" namespace as sqlite; `LastHash` (line 252, `ts DESC, seq DESC`); `Get`/`Query` in `audit_query.go:27/79` (newest-first) | Confirmed |
| `platform/audit/auditreport/control_areas.go` + `bucketing.go` — classification requirement | `controlAreaDefs` data table (control_areas.go) with each event type in AT MOST one area, enforced by `TestControlAreaDefs_NoEventTypeClaimedTwice` (drift_test.go:86); `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` (drift_test.go:95) requires every `KnownEventTypes` entry to be claimed or explicitly listed in `wantUncategorizedEventTypes`; `bucketing.go` `sortEventTypes` + soc2.go "Uncategorized" catch-all. Additional enforcement the direction implies: `auditspi/event_types_completeness_test.go` AST-parses `event_types*.go` and requires every declared const in the `KnownEventTypes` map (event_types.go:233) — so a new type needs THREE registrations (const, map, control area) or CI fails | Confirmed (requirement is test-enforced, not advisory) |
| `cmd/sso-ctl/auditexport` (+ `cmd/sso-ctl/auditverify`) — downstream consumers that must see import events | `auditexport` reads `audit_events` directly via `auditsqlite.OpenReadOnly(o.dsn)` (main.go:186) — never migrates; `auditverify` consumes the bundle (`--from-file`) or the live API (`--from-url`) and runs `audit.VerifyChain` / `VerifyChainAgainstCheckpoint` / `VerifyChainSegment` (segment.go). Nuance: `auditexport` is sqlite-DSN-only in v1 (main.go:26) — there is no offline postgres export; the postgres acceptance is proven in-harness (sink `Query` + `VerifyChain`) or via a live server's `/api/v1/audit/events` | Confirmed (with the postgres testability constraint below) |

Decisive additional findings (not cited by the direction, binding on the design):

| Finding | Measured reality |
|---|---|
| Direction 1 is implemented in HEAD, and it cannot carry import events into the chain | `runImport`/`writeBatch` → `p.ImportUser` writes one `commerce.OutboxEvent` (`snaplink.audit.user.import`, importer.go:32) per user in the user row's transaction (importer.go:122-142; `newImportFact` :144-170). Those events drain via `auditgovernance.Relay` to a control-plane client — they never enter `audit_events`. `auditoutbox.FactFromAudit` is fail-closed to `login_failure` only (fact.go:78-93), so no relay-side connector exists that could translate them. The only in-scope route for import events to join the chain is the CLI recording `audit.Event`s itself through the same `platform/audit` recorder/chainer the server uses |
| No import audit event type exists | `grep -rn user_import platform/audit/auditspi/event_types*.go` → nothing. The admin vocabulary has `EventAdminUserCreated/Updated/Deleted` (`admin_user_created` etc., event_types_admin.go:21-23) emitted by server-side admin paths, not the CLI. A new bounded const is required |
| Server wiring precedent for exactly this shape, same DB file | `BuildPrimaryAuditSink` (cmd/sso-server/serverbuildauthn/build_audit_secrets.go:34-53): `auditsqlite.New(cfg.Sqlite.DSN)` or `postgresbackend.NewAuditSinkWithDB(pg, dialect)`; `audit.WithHashChain()` appended when `cfg.Audit.HashChain` (build_app_core.go:385). The server's user store opens the SAME sqlite file (`sqlitestores.NewUserProvider(cfg.SQLite.DSN)`, build_identity_stores.go:252) — so users + `audit_events` share one DB, and `ChainTip` resume across the server→CLI boundary is a same-table continuation, exactly what `WithHashChain`'s construction-time seed implements (recorder.go:61-77) |
| Pool ownership constraint | sqlite `Sink.Close` closes the wrapped `*sql.DB` (sink.go:241-249) and postgres `AuditSink.Close` likewise (audit_sink.go:129-137) — the CLI's provider owns the pool (`p.DB()`). The recorder/sink must live for the process and never be Closed before/with `provider.Close`; the CLI is one-shot (Run → exit), so never Closing the sink is the correct posture |
| Query order | Both sinks' `Query` return newest-first (sqlite query.go:82 `ORDER BY ts_unix_ns DESC`; auditverify's doc says URL mode reverses before `VerifyChain`). Tests must reverse to chain order |
| Budgets and boundaries | importer.go ~180 lines (room under the 500-line ceiling); no new top-level package needed; `interfaces/sso` stays untouched (60-file ceiling); auditreport/auditspi changes are small additive edits. AGENTS.md §4: "New event types must be classified in auditreport; preserve bounded cardinality and W3C trace IDs"; metadata only via `audit.SetMeta` (platform/audit/handler_helpers.go:110) |
| Test-home split | `test/` cannot import `cmd/` (direction-1 spec §1; AGENTS.md "no package imports `cmd/`") — the sqlite/postgres chain proof is driven through the same packages the CLI calls; `cmd/`-side tests prove the wiring. `cmd/sso-ctl` (the dispatcher) already imports its subcommands, so an in-`cmd/` export→verify loop test is legal |
| Direction-1 spec already scoped this direction out | `cmd-sso-ctl-importcmd-governance-outbox-requirements.md` §3 lists "Direction 2 (CLI-side audit chain, `auditreport` classification, audit schema migration in the CLI)" as a non-goal of that change — this spec is that work, against HEAD where direction 1 is already shipped |

Net verification result: the direction's factual core is fully confirmed —
import events never reach `audit_events`, the CLI's migration path omits the
audit schema, the chainer + `ChainTip` resume + `prev_hash/hash` sinks all
exist and are wired server-side against the same DB the CLI writes, and a new
audit event type is test-enforced to be classified in `auditreport`. The
acceptance below preserves the supplied checks in structure and re-anchors
their testability to the verified constraints: postgres is proven in-harness
(`audit_sink.Query` + `VerifyChain`), sqlite offline via the real
`auditexport`/`auditverify` path, the sink is never Closed by the CLI, and
re-import dedupe stays out of scope (direction 3).

## 2. Goal and user outcome

A bulk user import through `sso-ctl import` becomes attestable provisioning:
every successfully imported user produces one `audit.Event` in the same
`audit_events` table the server writes, stamped into the same tamper-evident
hash chain (resumed across process boundaries via `ChainTip`, so a chain begun
by the server continues across the CLI seam with no spurious genesis),
classified into a SOC2 control-area evidence bucket with bounded cardinality,
and visible to `sso-ctl audit-export` / `sso-ctl audit-verify` unchanged.

Completion marker: importing N users into a fresh sqlite (or postgres) DB
yields exactly N chain events whose first event seeds genesis and whose
`audit.VerifyChain` over the whole table passes; a second CLI run resumes from
the previous head (first new event's `PrevHash` == old head, exactly one
genesis in the table); the new event type is filed under control area CC6.3 in
the SOC2 evidence report (not "Uncategorized"); the export bundle contains one
event per imported user and `audit-verify` exits 0 on it.

Maps to: the B4 governance surface for the import CLI, and — as the direction
states — supplements T-2 (claims emitted on tokens must correspond to
provisioned state) by making the provisioning action itself attestable: the
T-2 claim is only auditable if the provisioning that produced the state is on
the chain (`docs/architect-analysis/cmd-sso-ctl-importcmd-governance-outbox-requirements.md`
§1 verified the T-2/T-8/T-9 test IDs).

## 3. Scope

### In scope

1. `audit_events` schema migration in the CLI's open path for both backends,
   via the SAME "audit"-namespace migrations the server and
   `auditexport.OpenReadOnly` use (forward-only, idempotent, fail fast).
2. A CLI-side `audit.Recorder` over the same DB the provider owns, built with
   `audit.WithHashChain()` so the chain resumes from the durable head
   (`ChainTip.LastHash`) — the "same chainer" the direction requires.
3. One new bounded `audit.EventType` constant, registered in
   `auditspi.KnownEventTypes` and classified in `auditreport.controlAreaDefs`
   (CC6.3), satisfying the three test-enforced registrations.
4. One chain event per successfully imported user, redacted and
   bounded-cardinality (metadata only via `audit.SetMeta`).
5. Evidence: in-package `cmd/sso-ctl/importcmd` wiring tests; the sqlite
   offline export→verify loop through the real `auditexport`/`auditverify`
   paths; the postgres in-harness chain proof; the auditreport/auditspi
   classification tests.

### Explicit non-goals (must not be implemented in this change)

- Direction 1 (outbox pair-write, relay drain) is already implemented and
  untouched; the outbox event remains the governance delivery surface, the
  chain event is the attestation surface.
- Direction 3 (stable run IDs, idempotency keys for audit events, crash-replay
  markers): out of scope. A re-import of the SAME user IDs may append new
  chain events; the chain still verifies (appending is legal). AC2's count
  assertions therefore use new distinct IDs.
- Widening `auditoutbox.FactFromAudit`'s login-failure-only gate, or changing
  `auditgovernance` relay/delivery — the chain record is CLI-local.
- In-tx coupling of the audit row with the user upsert: the sinks'
  `WithTxAppender` seam is server-side; the CLI records AFTER the (user,
  outbox) pair commits. A recording failure must not roll back an imported
  user (audit is fail-open; `WithErrorHandler` surfaces it on stderr).
- Any change to `auditexport`, `auditverify`, the chainer, the sinks, the
  server (`cmd/sso-server`), `core.UserProvider`, or `interfaces/sso`.
- Server config: `cfg.Audit.HashChain` is not touched; the CLI does not read
  server config.

## 4. Requirements

### R1 — Audit schema migrated on CLI open (both backends)

`openDB` (importer.go:51) additionally wires the audit sink over the SAME
pool the provider owns, which runs the canonical migrations:

- sqlite: `auditsqlite.NewWithDB(p.DB())` — runs
  `migrate.Run(ctx, db, "audit", migrations)` (sink.go:128), creating
  `audit_events` with `prev_hash`/`hash` (baseline v1, sink.go:38-61).
- postgres: `postgresbackend.NewAuditSinkWithDB(p.DB(), dialect)` — runs
  `Run(ctx, db, "audit", auditMigrations, dialect)` (audit_sink.go:121-125).

Same namespace "audit" as the server's `auditsqlite.New(cfg.Sqlite.DSN)` /
`NewAuditSinkWithDB` and as `auditexport.OpenReadOnly`'s schema check, so: a
fresh DB gets the identical schema; an existing server-migrated DB is a no-op;
a schema-version mismatch fails fast (the migrations are forward-only; an
older binary refuses a newer file, mirroring `OpenReadOnly`'s contract).
Migration failure closes the provider and returns the error, matching the
existing outbox-migration error handling (importer.go:59-62).

Testable: opening a fresh sqlite file creates `audit_events` plus
`schema_migrations_audit` stamped at the binary's `migrate.MaxVersion`;
re-opening the same file is a no-op and succeeds.

### R2 — One recorder through the same chainer, resumed via ChainTip

`openDB` constructs, once per run: `audit.New(sink, audit.WithHashChain())`.
`WithHashChain` (recorder.go:61-77) seeds the chainer from
`sink.(ChainTip).LastHash` at construction — so the FIRST CLI event's
`PrevHash` equals the last event the server (or a previous CLI run) persisted
in the same table; an empty table seeds `GenesisHash` (""). A tip-read error
seeds genesis and continues (fail-open, documented on `WithHashChain`).

Lifetime: the sink and recorder are process-lifetime objects and are never
Closed — sqlite `Sink.Close` and postgres `AuditSink.Close` close the wrapped
`*sql.DB`, which the provider owns (`p.DB()`); the CLI exits after `Run`, so
the pool teardown is the process exit. Tests that Close must close the
provider only.

Testable: seed a DB with a server-style chain (or a prior CLI run), then
import — the first new event's `PrevHash` equals the pre-import head read via
`LastHash`; `audit.VerifyChain` over the whole table passes.

### R3 — One chain event per imported user, bounded and redacted

In `writeBatch`, after a successful `p.ImportUser` (the (user, outbox) pair
committed), record exactly one `audit.Event`:

- `Type`: the new constant (R4); `Outcome`: `audit.OutcomeSuccess`;
  `TenantID`: the `--tenant` value; `Timestamp`: now (the chainer enforces
  strict monotonicity, chainer.go:57-71, so chain order == import order).
- `ActorID`: empty — CLI/system semantics, not a user session; the
  auditreport accumulator already handles empty actors (bucketing.go:22).
- Metadata: ONLY via `audit.SetMeta` (handler_helpers.go:110), bounded keys —
  `target_user` = the imported user ID, `provider` = the closed parser format
  tag ("auth0"|"keycloak"|"okta"|"csv"). Never the password hash, hash
  format, email, or any request input.
- Failed/skipped rows record NOTHING (their outbox event is likewise absent —
  direction-1 pair semantics), and the batch continues (R6 of the
  direction-1 spec's skip accounting is preserved).
- Recording failure: surfaced via `audit.WithErrorHandler` to stderr,
  never fatal to the import (fail-open, per AGENTS.md §3 "fail open with
  audit/logging: ... audit sink errors").

Testable: N users → exactly N events of the new type; a failing row
contributes zero events; each event's `TenantID` == `--tenant`; metadata
contains only the bounded keys.

### R4 — One new bounded event type, registered and classified

- Const in `platform/audit/auditspi/event_types_admin.go`:
  `EventAdminUserImported EventType = "admin_user_imported"` (flat admin
  vocabulary, matching `EventAdminUserCreated = "admin_user_created"`
  at event_types_admin.go:21; the file name must match the `event_types*.go`
  AST glob of `TestKnownEventTypesIsComplete`).
- Entry in the `KnownEventTypes` map (event_types.go:233).
- Classification in `controlAreaDefs` under CC6.3 "Privileged and
  administrative actions" (control_areas.go) — alongside the other
  `EventAdminUser*` types.
- Bounded cardinality: exactly ONE constant. No per-format or per-provider
  variants — the provider rides in Metadata from the parsers' closed
  vocabulary (bounded by the parser switch in parser_okta.go/parsers.go).

The three existing enforcement tests become the gate: `TestKnownEventTypesIsComplete`
(auditspi), `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` +
`TestControlAreaDefs_NoEventTypeClaimedTwice` (auditreport). The type must NOT
be added to `wantUncategorizedEventTypes`.

Testable: a unit test builds an `auditreport.SOC2Report` over a bundle
containing the new type and asserts it is counted under CC6.3 and absent from
"Uncategorized"; a second vocabulary constant would fail the completeness
test by construction.

### R5 — Export/verify consumers unchanged and green

`auditexport` (reads `audit_events` via `OpenReadOnly`, never migrates) and
`auditverify` (runs `VerifyChain`/`VerifyChainAgainstCheckpoint`/
`VerifyChainSegment` over the bundle or API) are pure consumers: no changes.
They are the acceptance vehicles for "attestable imports".

Testable: run the real export path on an import DB → bundle contains the new
events; run the real verify path on the bundle → exit 0.

### R6 — Engineering gates and contracts

- No new `Err*` (no `docs/error-codes.md` change); no endpoint (no
  `docs/openapi.yaml` change); no server config knob (no
  `docs/config-reference.md` change). CLI usage text and the package doc
  mention that imports are recorded in the audit chain.
- Budgets: `importer.go` stays ≤ 500 lines (~180 today); no new top-level
  package (no `architecture_layer_test.go` change); `interfaces/sso` untouched
  (60-file ceiling).
- Verification per AGENTS.md §2: `go build ./... && go vet ./...`,
  `go test -run 'TestMaintainability_|TestArchitecture_' .`, then
  `go test ./... -race` and `make ci` before handoff.

## 5. Acceptance criteria

The direction's four acceptance checks, preserved in structure and made
testable. Test homes follow the verified split: `test/` (package `ssotest`)
cannot import `cmd/`, so the DB-level chain proofs live there against the same
packages the CLI calls; `cmd/`-side tests prove the wiring; `cmd/sso-ctl`
already imports its subcommands, so the export→verify loop is testable inside
`cmd/`.

### AC1 — Fresh-DB import: auditverify reports a verifiable chain over all import events (sqlite offline, postgres in-harness)

Given a fresh sqlite DB and N users through the CLI's open path
(`openDB` + import), then:

- `audit_events` contains exactly N rows of the new type, each with
  `tenant_id` == the `--tenant` value;
- reading them back oldest-first (sink `Query` newest-first → reverse) and
  running `audit.VerifyChain` returns nil; the first event's `PrevHash` ==
  `audit.GenesisHash`;
- the real tool path attests them: `auditexport --dsn <file>` produces a
  bundle, and `auditverify --from-file bundle.json` exits 0 (verified
  offline in `cmd/` tests by calling the two packages' `Run` entry points,
  as the dispatcher does).

Postgres: same import through the CLI's postgres path against the repo's
postgres test harness; the chain proof is `audit.VerifyChain` over
`postgres.AuditSink.Query` output (audit_query.go:79) — there is no offline
postgres export in v1 (`auditexport` is sqlite-DSN-only), so the postgres
attestation equivalence is the live API mode (`auditverify --from-url`),
which is covered by `auditverify`'s own tests and out of this change's scope
to extend.

### AC2 — Restart the CLI and import again: new events chain onto the previous head (ChainTip, no spurious genesis)

Given the AC1 DB: read the head `H` (`sink.LastHash` — the most recent row's
Hash), then simulate the process boundary by constructing a fresh recorder
(`openDB` → `audit.New(sink, audit.WithHashChain())` — the resume happens at
construction, recorder.go:61-77) and importing M new distinct users. Then:

- the first event of the second run carries `PrevHash == H` (resumed, not a
  new genesis);
- `audit.VerifyChain` over all N+M events returns nil;
- exactly ONE genesis event (`PrevHash == ""`) exists in the whole table.

M uses new distinct IDs: re-import dedupe of identical IDs is direction 3
(out of scope, §3); appending duplicate-content events is legal for the chain
and must not break verification.

### AC3 — The new event type appears in auditreport control areas with bounded cardinality

- `go test ./platform/audit/auditreport/` and
  `go test ./platform/audit/auditspi/` pass — the completeness, no-double-claim,
  and claimed-or-explicitly-uncategorized tests all green (R4's three
  registrations in place);
- a unit test asserts the type resolves to exactly control area CC6.3 and a
  `BuildSOC2Report` over a bundle containing it files the events under CC6.3
  with a count of N, and zero events under "Uncategorized";
- exactly one vocabulary constant exists for imports — no per-provider or
  per-format variants (bounded cardinality; provider is a `SetMeta` Metadata
  value from the closed parser vocabulary).

### AC4 — Audit export contains one event per imported user

Given the AC1 DB (N users, one skipped bad row in the batch): the export
bundle contains exactly N events of the new type — one per successfully
imported user ID (`Metadata["target_user"]` matches the imported set), and
zero events for the skipped identity (R3); `auditverify --from-file` over the
bundle exits 0 (`VerifyChain`). Re-exporting the same DB is byte-stable for
the event set (export is a read).

## 6. Files

### Create

```text
docs/architect-analysis/cmd-sso-ctl-importcmd-audit-chain-requirements.md — this spec
test/importcmd_audit_chain_test.go — AC1/AC2 store-level chain proofs (package ssotest; sqlite file-backed; postgres where the repo harness provides a DB; mirrors test/auditoutbox_governance_test.go harness)
```

### Modify

```text
cmd/sso-ctl/importcmd/importer.go — openDB wires the audit sink + recorder (R1/R2); writeBatch records one event per successful ImportUser (R3); ~180 → stays ≤ 500
cmd/sso-ctl/importcmd/main.go — package doc + usage text note on audit-chain recording (R6)
cmd/sso-ctl/importcmd/main_test.go — R1 schema assertions; AC1/AC2 wiring tests; AC4 export→verify loop through the auditexport/auditverify packages (legal: cmd/sso-ctl already imports its subcommands)
platform/audit/auditspi/event_types_admin.go — EventAdminUserImported const (R4)
platform/audit/auditspi/event_types.go — KnownEventTypes entry (R4)
platform/audit/auditreport/control_areas.go — CC6.3 entry (R4)
platform/audit/auditreport/ — optional unit test pinning the type's CC6.3 bucket (AC3)
```

### Do not modify

```text
cmd/sso-ctl/auditexport, cmd/sso-ctl/auditverify — consumers, unchanged (R5)
platform/audit/chainer.go, recorder.go, platform/audit/sqlite/*, infrastructure/postgres/audit_sink.go, audit_query.go — consumed as-is (the CLI calls NewWithDB / NewAuditSinkWithDB + WithHashChain)
infrastructure/auditoutbox/fact.go — login-failure-only gate stays fail-closed
domains/tenant/commerce, infrastructure/auditgovernance — direction-1 machinery, untouched
interfaces/sso — 60-file ceiling, untouched
cmd/sso-server/* — server unchanged
```

Confirm file/function/directory/fan-out ceilings before implementation
(AGENTS.md §2); no `architecture_layer_test.go` change is expected (no new
package).

## 7. Dependencies and compatibility

- New/changed SPI: none at `shared/core`; the recorder is CLI-local. One new
  `audit.EventType` const in `auditspi` with the three test-enforced
  registrations (const → `KnownEventTypes` → `controlAreaDefs` CC6.3).
- Storage migration: `audit_events` via the existing "audit" namespace
  migrations on CLI open — idempotent, forward-only, byte-identical to the
  server's schema. A CLI binary with older migrations fails fast against a
  newer file (same contract as `OpenReadOnly`).
- Chain continuity contract: with the server running `cfg.Audit.HashChain`,
  the CLI's first event's `PrevHash` equals the last server event's `Hash` —
  one unbroken chain across the boundary, no server change. If the server ran
  without chaining (hash columns empty), `LastHash` returns "" and the CLI
  seeds genesis at the boundary; the CLI's own chain is still internally
  consistent and verifies (documented `WithHashChain` fail-open resume).
- Event payload: bounded, redacted, `SetMeta`-only metadata; no credentials,
  no PII beyond the user ID the operator supplied in the import file; W3C
  trace IDs are not applicable (no HTTP request context — `RequestID`/
  `TraceID` empty, matching system/bootstrap events).
- Concurrency: the CLI is single-process; the chainer's monotonic timestamp
  bump keeps ts order == chain order (chainer.go:57-71). SQLite
  single-writer applies (imports are offline; same caveat as the documented
  audit `Prune`).
- Rollout/rollback: chain events appear only for imports run with the new
  CLI; a rolled-back CLI writes no rows; existing chains verify unchanged
  (appends never rewrite past events).

## 8. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./platform/audit/auditspi/ ./platform/audit/auditreport/ -run 'TestKnownEventTypesIsComplete|TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized|TestControlAreaDefs_NoEventTypeClaimedTwice' -v
go test ./cmd/sso-ctl/importcmd/... -run 'TestOpenDB|TestRunImport|TestAuditChain' -v
go test ./test/ -run TestImportAuditChain -v   # AC1/AC2 (sqlite; postgres per harness)
go test ./... -race
make ci
```
