completion_report:
  summary: "Added read-only --anchor-latest checkpoint loading for audit-export."
  changed_files:
    - cmd/sso-ctl/auditexport/main.go
    - cmd/sso-ctl/auditexport/checkpoint.go
    - cmd/sso-ctl/auditexport/latest_checkpoint_test.go
    - docs/design/audit-export-latest-checkpoint.md
    - docs/campaigns/reports/audit-export-latest-checkpoint.md
  requirements_covered:
    - "Latest checkpoint is signature-verified and must exactly match the exported head."
    - "Uses only the existing read-only opener and narrow Latest reader; no Append, DDL, DML, HTTP endpoint, or server changes."
    - "Misuse exits 2; missing, invalid, tampered, filtered, or mismatched checkpoints exit 1 without output."
    - "Default, file-anchor, from-url, and verify behavior remains unchanged."
  tests_added:
    - "SQLite hash-chain and real Notary durable round trip."
    - "No checkpoint, misuse, head mismatch, tampered signature, and offline verify coverage."
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./cmd/sso-ctl/auditexport ./cmd/auditstore ./platform/audit/sqlite ./infrastructure/postgres ./platform/audit/auditexport"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "go test ./infrastructure/postgres/... && go build ./infrastructure/postgres/..."
      result: passed
      details: "Live DSN-gated tests skipped."
    - command: "python cli.py check-test && make docs-validate && make ci && git diff --check"
      result: passed
    - command: "SSO_TEST_POSTGRES_DSN=<live DSN> go test ./infrastructure/postgres"
      result: not_executed
      details: "No live PostgreSQL DSN available."
  architecture_checks: "Passed; main.go is 467 lines, no new package or upward import."
  security_checks: "Passed; exact-head and signature checks precede bundle writing; no PII/token/body leakage."
  compatibility:
    breaking_change: false
  migration:
    required: false
    rollback_verified: true
  residual_risks:
    - "Latest and event Query are separate reads; concurrent growth fails closed."
    - "Live PostgreSQL round-trip was not run."
  assumptions:
    - "Existing durable schemas and producer checkpoints are authoritative."
    - "PostgreSQL operators enforce read-only access."
