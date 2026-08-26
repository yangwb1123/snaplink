completion_report:
  summary: "Wired an opt-in sso-server signed checkpoint producer over the existing durable audit checkpoint stores."
  changed_files:
    - config/config_audit.go
    - config/config_load.go
    - config/config_test.go
    - config/schema/integration_test.go
    - cmd/sso-server/config.yaml
    - cmd/sso-server/serverbuildauthn/build_audit_secrets.go
    - cmd/sso-server/serverbuildauthn/build_audit_secrets_test.go
    - cmd/sso-server/build_app_core.go
    - cmd/sso-server/build_app_oidc.go
    - cmd/sso-server/build_stores.go
    - cmd/sso-server/main_shutdown.go
    - cmd/sso-server/main_shutdown_test.go
    - cmd/sso-server/audit_advanced_test.go
    - docs/design/audit-notary-producer.md
    - docs/config-reference.md
    - docs/feature-matrix.md
    - CHANGELOG.md
    - docs/campaigns/reports/audit-notary-producer.md
  requirements_covered:
    - "Added audit.notary.enabled, interval, and key_file with config and build-time prerequisite validation."
    - "Loads only operator-provisioned PKCS#8 Ed25519 PRIVATE KEY PEM and returns an independent audit.CheckpointSigner."
    - "Starts StartNotary only for the raw durable SQLite/Postgres primary implementing both ChainTip and CheckpointStore."
    - "Composed notary cancel/done with the existing audit close chain for build failure and shutdown, without overwriting the external worker close."
    - "Preserved immediate-first-attempt, unchanged-head, fail-open runtime failure, and no-success-write-back semantics."
    - "Added configuration, signer, schema, wiring, shutdown-chain, persistence, signature, and default-off tests."
  tests_added:
    - "TestAuditNotaryValidation"
    - "TestGenerate_RealConfigIncludesAuditNotaryShape"
    - "TestLoadEd25519PrivateKeyPEM_ValidAndRejectsInvalidInputs"
    - "TestBuildApp_AuditNotaryPersistsSignedCheckpointAndStops"
    - "TestBuildApp_AuditNotaryDefaultOffAndBootGates"
    - "TestAddAuditCloserPreservesExistingClose"
  commands_executed:
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go test ./config ./config/schema"
      result: passed
    - command: "go test ./cmd/sso-server/serverbuildauthn -run 'TestLoadEd25519PrivateKeyPEM|TestBuildAuditCheckpointSigner' -v"
      result: passed
    - command: "go test ./cmd/sso-server -run 'TestBuildApp_AuditNotary|TestBuildApp_AuditHashChain|TestBuildPrimaryAuditSink' -v"
      result: passed
    - command: "go test ./platform/audit ./platform/audit/sqlite ./infrastructure/postgres -run 'TestNotary|TestAudit_Checkpoint|Test.*Checkpoint' -count=1"
      result: passed
    - command: "go test ./..."
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "go test ./infrastructure/postgres/... && go build ./infrastructure/postgres/..."
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_' . && go test ./... -run 'TestMaintainability_|TestArchitecture_'"
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks:
    - "No production files were added; interfaces/sso file count and platform/audit production file count are unchanged."
    - "The existing raw primary sink is asserted for both ChainTip and CheckpointStore; no MemoryCheckpointStore fallback or fan-out store is used."
    - "Line budgets remain satisfied: chainer.go 500, build_app.go 500, build_app_core.go 500, build_app_oidc.go 499, build_stores.go 500, main.go 494, main_shutdown.go 417, signer file 402, config_audit.go 429, and config_load.go 489."
    - "No new upward imports, schema version, CLI flag, HTTP route, plugin.Open, or external network channel were introduced."
  security_checks:
    - "The private checkpoint key is independent from the token signing registry and is never generated, serialized into YAML, or logged; only public-key/path metadata is logged."
    - "PEM type, PKCS#8, Ed25519 algorithm, empty, malformed, missing, and trailing-data inputs fail closed; errors do not contain private-key bytes."
    - "Successful checkpoint creation does not write an EventAuditChainCheckpoint success event or mutate the Recorder hash head; only existing failure-event semantics are used."
    - "Default-off configuration does not read key_file, construct a signer, or start a Notary goroutine."
  compatibility:
    breaking_change: false
    default_off_byte_behavior: "No key read, no producer goroutine, no new event type, no success write-back, and no HTTP/API surface."
  migration:
    required: false
    rollback_verified: false
    notes: "The producer reuses the already-applied SQLite v4/Postgres v3 audit_checkpoints schema. Rollback is disable audit.notary and restart; schema rollback remains restore-from-snapshot."
  skipped:
    - item: "Live PostgreSQL integration against a running database"
      reason: "Not required for this batch; existing infrastructure/postgres tests/build and environment-gated coverage were used, while the focused persistence test uses temporary SQLite."
  residual_risks:
    - "Two active HA producers can race on the durable checkpoint sequence; the existing primary-key conflict is logged/fail-open and no leader election was added."
    - "The existing Notary runtime tip/store/signing failure path remains fail-open by design."
  assumptions:
    - "Operators provision one stable absolute PKCS#8 Ed25519 private-key file before enabling the producer."
    - "A deployment sharing a durable audit database runs one active checkpoint producer until HA ownership is specified by a later batch."
    - "No new EventType, no success write-back, and no external exporter are intended in this batch."
