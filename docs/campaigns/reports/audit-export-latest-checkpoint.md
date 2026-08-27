completion_report:
  summary: "Added a bounded read-only --anchor-latest seam for sso-ctl audit-export using the existing durable SQLite/Postgres checkpoint Latest path; no server/API/schema/event changes."
  changed_files:
    - cmd/sso-ctl/auditexport/main.go
    - cmd/sso-ctl/auditexport/checkpoint.go
    - cmd/sso-ctl/auditexport/latest_checkpoint_test.go
    - docs/design/audit-export-latest-checkpoint.md
    - docs/campaigns/reports/audit-export-latest-checkpoint.md
  requirements_covered:
    - "--anchor-latest is a bool export modifier requiring --dsn and rejecting --anchor, --verify, and --from-url with exit 2."
    - "Latest is read only through a narrow structural reader; Append, raw SQL, DDL, and HTTP checkpoint access are not exposed to the CLI."
    - "Stored checkpoints are signature-verified and require exact bundle-head equality before output."
    - "Missing, errored, or tampered latest checkpoints fail with exit 1 and no bundle output."
    - "Existing unanchored, explicit-file-anchor, --from-url, and --verify paths remain covered."
    - "Public usage documents read-only complete-export semantics and the absence of an out-of-band signer pin."
    - "No server, API, schema, configuration, error-code, feature-registry, or event changes."
  tests_added:
    - "Real SQLite hash-chain plus audit.NewNotary(sink, sink, signer, ...) durable checkpoint round trip."
    - "Bundle anchor equality with durable Latest, signature/head checks, and offline --verify."
    - "No-checkpoint failure with no stdout or bundle, misuse exit-2 matrix, and tampered stored signature failure."
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./cmd/sso-ctl/auditexport ./cmd/auditstore ./platform/audit/sqlite ./infrastructure/postgres ./platform/audit/auditexport"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "make ci-modules"
      result: passed
    - command: "go test ./infrastructure/postgres"
      result: passed
      details: "Environment-gated live Postgres tests were skipped because SSO_TEST_POSTGRES_DSN was unset; the package compiled and non-live tests passed."
    - command: "SSO_TEST_POSTGRES_DSN=<live DSN> go test ./infrastructure/postgres"
      result: not_executed
      details: "No live Postgres DSN was available."
    - command: "python cli.py check-test"
      result: passed
    - command: "python cli.py check"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks:
    - "No new package or upward import was added; implementation stays in the existing auditexport package."
    - "The CLI type-asserts only Latest(context.Context) and never asserts or calls the write-capable checkpoint interface."
    - "cmd/sso-ctl/auditexport/main.go is 467 lines, below the 500-line production budget."
    - "Existing Postgres and SQLite read-only constructors and Latest implementations are reused unchanged."
  security_checks:
    - "Checkpoint signatures are verified before BuildExportBundle and exact attested-head equality is enforced before writeBundle."
    - "Missing, store-error, bad-signature, and mismatch paths do not emit a bundle; diagnostics contain no event, token, or body."
    - "No server route, raw query path, bearer handling, signer pin registry, generated ID, or key change was added."
    - "The source remains the non-migrating read-only opener and --from-url has no new endpoint or checkpoint inference."
  compatibility:
    breaking_change: false
    details: "Without --anchor-latest, existing output, read ordering, exit behavior, --anchor file behavior, and --verify behavior are unchanged."
  migration:
    required: false
    rollback_verified: true
    details: "The seam reads the already-existing audit_checkpoints table; rollback is omitting --anchor-latest, with existing default and file-anchor tests passing."
  residual_risks:
    - "Latest and event Query are separate reads, so concurrent store growth or mutation can race; exact head checking fails closed rather than claiming a snapshot."
    - "A live Postgres audit-export round trip was not run without SSO_TEST_POSTGRES_DSN."
    - "Distributed producer ownership and database snapshot isolation remain outside this CLI seam."
  assumptions:
    - "Current durable schemas are already migrated to the binary's existing versions and Postgres operators enforce read-only access through role or transaction policy."
    - "The existing audit.NewNotary producer and durable checkpoint rows are the authoritative checkpoint source."
