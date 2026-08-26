completion_report:
  summary: "Implemented opt-in signed audit checkpoint producer wiring and partial-build cleanup."
  changed_files: [config/config_audit.go, config/config_load.go, config/config_test.go, config/schema/integration_test.go, cmd/sso-server/config.yaml, cmd/sso-server/serverbuildauthn/build_audit_secrets.go, cmd/sso-server/serverbuildauthn/build_audit_secrets_test.go, cmd/sso-server/build_app_core.go, cmd/sso-server/build_app_oidc.go, cmd/sso-server/build_stores.go, cmd/sso-server/main_shutdown.go, cmd/sso-server/main_shutdown_test.go, cmd/sso-server/audit_advanced_test.go, docs/design/audit-notary-producer.md, docs/config-reference.md, docs/feature-matrix.md, CHANGELOG.md, docs/campaigns/reports/audit-notary-producer.md]
  requirements_covered:
    - "Default-off audit.notary requires enabled audit, hash_chain, durable sqlite/postgres, and absolute key_file in config and build validation."
    - "Only provisioned PKCS#8 Ed25519 PRIVATE KEY PEM is accepted; signer is independent and never logs or writes private material."
    - "Raw durable primary alone supplies ChainTip and CheckpointStore; no memory fallback, new EventType, HTTP surface, exporter, flag, object store, or network channel."
    - "Notary lifecycle preserves async drain, exporter/notary close, primary close, build-failure cleanup, fail-open failures, and no success write-back."
  tests_added: ["config/schema validation", "Ed25519 signer round-trip/rejection", "SQLite persistence/signature/default-off/boot-gate/shutdown", "closer composition"]
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test ./config ./config/schema ./cmd/sso-server/serverbuildauthn ./cmd/sso-server", result: passed}
    - {command: "go test ./platform/audit ./platform/audit/sqlite ./infrastructure/postgres -run 'TestNotary|TestAudit.*Checkpoint|Test.*Checkpoint' -count=1", result: passed}
    - {command: "go test ./infrastructure/postgres/... && go build ./infrastructure/postgres/...", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' . && go test ./... -run 'TestMaintainability_|TestArchitecture_'", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
  architecture_checks: ["No production files added; audit and interfaces/sso ceilings unchanged; Go budgets remain within 500 lines.", "No upward imports or token-key reuse; SQLite v4/Postgres v3 schema reused without migration."]
  security_checks: ["Errors expose path/type/parser context, never key bytes; logs expose only path/public-key metadata.", "Default-off reads no key, starts no producer, adds no event, and preserves Recorder head.", "No success write-back, metrics, external exporter, download/refresh, or leader election."]
  compatibility: {breaking_change: false, default_off_byte_behavior: "Existing audit recording, endpoints, event registry, and hash-chain semantics preserved."}
  migration: {required: false, rollback_verified: false, notes: "Provision key first; rollback is disable audit.notary and restart. Schema rollback remains restore-from-snapshot."}
  residual_risks: ["Multiple HA producers may race on the checkpoint sequence primary key; failure remains logged/fail-open.", "Live PostgreSQL persistence integration was unavailable; nested compile/tests passed."]
  assumptions: ["One stable absolute Ed25519 key and one active producer per shared database.", "No new EventType, success write-back, metrics, or external exporter is in scope."]
  skipped: [{item: "Live PostgreSQL persistence integration", reason: "No live PostgreSQL service was available."}]
