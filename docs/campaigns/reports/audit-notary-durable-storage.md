completion_report:
  summary: "Durable SQLite/Postgres checkpoint storage and fail-open Notary restart continuity; no server wiring."
  changed_files: ["docs/design/audit-notary-durable-storage.md", "docs/campaigns/reports/audit-notary-durable-storage.md", "platform/audit/chainer.go", "platform/audit/recorder_events_util.go", "platform/audit/notary_test.go", "platform/audit/sqlite/sink.go", "platform/audit/sqlite/maintenance.go", "platform/audit/sqlite/checkpoint_test.go", "infrastructure/postgres/audit_sink.go", "infrastructure/postgres/audit_test.go", "infrastructure/postgres/audit_readonly_test.go"]
  requirements_covered:
    - "SQLite v4 and Postgres v3 create independent audit_checkpoints tables."
    - "Append, Latest, and List are parameterized and cover nil/closed, duplicate, empty, inclusive-since, ascending-sequence, limit, and byte round-trip semantics."
    - "NewNotary restores only a valid Latest; failures log and preserve genesis/zero state."
    - "No success event, server wiring, config, route, OpenAPI, event type, or audit-verify change."
  tests_added: ["SQLite migration/storage/round-trip/restart tests.", "Memory restart and invalid/read-error recovery tests.", "Env-gated Postgres round-trip/List test and compile-time interface assertion."]
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./platform/audit/sqlite", result: passed}
    - {command: "go test ./platform/audit", result: passed}
    - {command: "go test ./infrastructure/postgres/...", result: passed}
    - {command: "go build ./infrastructure/postgres/... && go vet ./infrastructure/postgres/...", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "baseline grep and go env GOMOD review", result: passed}
    - {command: "check-completion-report.py", result: passed}
  not_executed:
    - {check: "Live Postgres/CockroachDB round-trip", reason: "SSO_TEST_POSTGRES_DSN was unset; integration tests skipped."}
    - {check: "Snapshot rollback", reason: "Forward-only migration; no snapshot was available."}
  architecture_checks: "16 platform/audit production files; chainer.go 500 lines; changed Go files under 500; no new package/upward import. infrastructure/postgres resolves to root go.mod."
  security_checks: "Bad recovery data cannot advance sequence/PrevHash; storage remains fail-open; SQL values, since, and limit are parameterized; HA races surface as duplicate keys."
  compatibility:
    breaking_change: false
    details: "Memory store, checkpoint JSON/signing, unchanged-head behavior, public HTTP/config/event surfaces, and audit-verify are unchanged."
  migration:
    required: true
    versions: "SQLite v4; Postgres v3, both add_audit_checkpoints."
    forward_upgrade_verified: true
    rollback_verified: false
  residual_risks: ["HA leader election/leases are not included; concurrent producers can get duplicate-sequence errors.", "Later work must wire producer lifecycle and signer provisioning."]
  assumptions: ["docs/design/audit-chain.md is absent; executable code and direction-one evidence were used.", "No event type or server wiring is added."]
