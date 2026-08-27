completion_report:
  summary: "Added the bounded read-only sso-ctl audit-export --anchor-latest seam; no server/API/schema/event changes."
  changed_files:
    - cmd/sso-ctl/auditexport/main.go
    - cmd/sso-ctl/auditexport/checkpoint.go
    - cmd/sso-ctl/auditexport/latest_checkpoint_test.go
    - docs/design/audit-export-latest-checkpoint.md
    - docs/campaigns/reports/audit-export-latest-checkpoint.md
  requirements_covered:
    - "--anchor-latest requires --dsn and rejects --anchor, --verify, and --from-url with exit 2."
    - "It uses only Latest on a narrow reader after the existing read-only opener; no Append, DDL, DML, raw query, or HTTP checkpoint path is exposed."
    - "Latest is signature-checked and exact bundle-head equality is required before output; missing, store-error, tampered, filtered, and incomplete cases fail closed."
    - "Default unanchored, file-anchor, --from-url, and --verify behavior is preserved."
    - "Usage documents read-only complete-export semantics and that this is not an out-of-band signer pin."
    - "No server, API, schema, configuration, error-code, feature-registry, or event changes."
  tests_added:
    - "Real SQLite hash-chain plus audit.NewNotary(sink, sink, signer, ...) durable checkpoint round trip."
    - "Latest equality, signature/head checks, offline --verify, no-checkpoint/no-output, misuse exit 2, head mismatch, and tampered-signature failures."
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
      details: "Live DSN-gated tests were skipped because SSO_TEST_POSTGRES_DSN was unset."
    - command: "SSO_TEST_POSTGRES_DSN=<live DSN> go test ./infrastructure/postgres"
      result: not_executed
      details: "No live PostgreSQL DSN was available; no Postgres round-trip is claimed."
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks: "passed: existing auditexport package only; no upward import or new package; main.go is 467 lines; concrete stores are asserted only through Latest."
  security_checks: "passed: signature and exact-head checks precede writeBundle; failures leave no bundle and expose no event/token/body; no server route, raw query, signer pin, generated ID, or key change."
  compatibility:
    breaking_change: false
    details: "Without --anchor-latest, output, read order, exit behavior, file-anchor behavior, and --verify remain unchanged."
  migration:
    required: false
    rollback_verified: true
    details: "The CLI reads the existing audit_checkpoints table only; rollback is omitting the flag."
  residual_risks:
    - "Latest and event Query are separate reads; concurrent growth can cause an exact-head failure rather than a false attestation."
    - "Live PostgreSQL export round-trip was not run because no DSN was available."
    - "Distributed producer ownership and database snapshot isolation remain out of scope."
  assumptions:
    - "The existing durable schemas are current and the existing producer rows are authoritative."
    - "PostgreSQL operators enforce read-only access through a role or transaction policy."
