completion_report:
  summary: "Implemented durable SQLite and Postgres audit checkpoint stores and fail-open Notary restart continuity without producer wiring."
  changed_files:
    - "docs/design/audit-notary-durable-storage.md"
    - "docs/campaigns/reports/audit-notary-durable-storage.md"
    - "platform/audit/chainer.go"
    - "platform/audit/recorder_events_util.go"
    - "platform/audit/notary_test.go"
    - "platform/audit/sqlite/sink.go"
    - "platform/audit/sqlite/maintenance.go"
    - "platform/audit/sqlite/checkpoint_test.go"
    - "infrastructure/postgres/audit_sink.go"
    - "infrastructure/postgres/audit_test.go"
    - "infrastructure/postgres/audit_readonly_test.go"
  requirements_covered:
    - "SQLite audit migration v4 creates an independent audit_checkpoints table and implements parameterized Append, Latest, and List."
    - "Postgres audit migration v3 creates the equivalent table and uses the existing rebind and migration runner conventions."
    - "Durable stores reject nil checkpoints, reject duplicate sequence primary keys, return nil Latest for empty storage, sort List by sequence ascending, include since, and treat limit <= 0 as unlimited."
    - "Closed and nil sinks return explicit errors; signatures and signer keys round-trip as bytes."
    - "NewNotary verifies Latest during construction, restores sequence and previous head only for a valid checkpoint, and logs read or signature failures without blocking construction."
    - "MemoryCheckpointStore behavior, checkpoint JSON, signing algorithm, unchanged-head behavior, audit events, CLI verification, and server wiring remain unchanged."
  tests_added:
    - "platform/audit/sqlite/checkpoint_test.go: migration/table, round-trip, List ordering/bounds/limit, empty/nil/duplicate/closed behavior, and durable Notary restart continuity."
    - "platform/audit/notary_test.go: memory restart regression, invalid Latest fail-open, and Latest read-error fail-open logging."
    - "infrastructure/postgres/audit_test.go: env-gated checkpoint round-trip/List coverage plus the production compile-time audit.CheckpointStore assertion."
  commands_executed:
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./platform/audit/sqlite"
      result: passed
    - command: "go test ./platform/audit"
      result: passed
    - command: "go test ./platform/audit/..."
      result: passed
    - command: "go build ./infrastructure/postgres/... && go vet ./infrastructure/postgres/..."
      result: passed
    - command: "go test ./infrastructure/postgres/..."
      result: passed
    - command: "go test ./platform/audit/sqlite -race -count=10"
      result: passed
    - command: "go test ./platform/audit -race -count=10"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "go test -count=1 ./infrastructure/postgres -run '^TestAudit_CheckpointStoreRoundTrip$' -v"
      result: passed
      reason: "The package command passed, but the env-gated integration test skipped because SSO_TEST_POSTGRES_DSN was not set."
    - command: "TestAudit_CheckpointStoreRoundTrip against a live Postgres/CockroachDB"
      result: not_executed
      reason: "No SSO_TEST_POSTGRES_DSN was available; no live database result is claimed."
    - command: "grep evidence for pre-change CheckpointStore/NewNotary callers"
      result: passed
      reason: "The initial source grep found only the interface/Memory implementation and test or definition references, with no production NewNotary caller."
  architecture_checks:
    import_layering: "No new package or upward import; existing platform/audit and infrastructure/postgres ownership retained."
    platform_audit_production_files: 16
    chainer_lines: 500
    changed_production_file_budgets: "All changed production Go files remain under 500 lines; no exemption was added."
    server_config_api_event_registry_changes: "None."
    nested_module_dependencies: "No new dependency or go.mod/go.sum change; infrastructure/postgres was built and vetted from the current repository module layout."
  security_checks:
    recovery_trust: "Invalid checkpoint signatures and Latest read failures do not advance lastSeq or lastSigned; logger errors are emitted when a logger is supplied."
    persistence_failure: "Checkpoint Append failures retain the existing fail-open Notary behavior and do not write a success event back into the attested hash chain."
    sql_safety: "Checkpoint values, since, and limit are parameterized; only fixed SQL identifiers are composed."
    isolation: "Checkpoints use a separate table and do not alter audit_events or event migrations/queries."
  compatibility:
    breaking_change: false
    details: "The additions are storage and construction-time behavior only; MemoryCheckpointStore, wire JSON, signing, CheckpointNow unchanged-head handling, audit-verify, routes, OpenAPI, and event types are unchanged."
  migration:
    required: true
    versions: "SQLite v4 add_audit_checkpoints; Postgres v3 add_audit_checkpoints."
    forward_upgrade_verified: true
    rollback_verified: false
    rollback_details: "Migrations are forward-only; restore-from-snapshot rollback was not executed in this local run and no down migration was added."
  residual_risks:
    - "HA leader election or distributed Notary leases are not part of this batch; concurrent producers can race on a sequence and one Append can fail with a duplicate-key error."
    - "The Postgres round-trip test remains unexecuted without a live database."
    - "No sso-server producer wiring exists in this batch; a later batch must supply producer lifecycle and signer provisioning."
  assumptions:
    - "Notary-generated timestamps are UTC, so UnixNano persistence reconstructs the signed checkpoint without changing its JSON bytes."
    - "The pre-existing untracked .pi-batch.lock was preserved and is not part of this change."
    - "This batch adds no server wiring and no new event type."
