completion_report:
  summary: "Redacted sso-ctl resolved config output using configaudit.Redact."
  changed_files:
    - cmd/sso-ctl/configcmd/main.go
    - cmd/sso-ctl/configcmd/main_test.go
    - platform/configaudit/redact.go
    - platform/configaudit/redact_test.go
  requirements_covered:
    - "Sensitive credentials and nested Authorization/X-API-Key headers print as ***."
    - "Issuer and benign headers remain visible; loaded config is not mutated."
    - "Validation commands, flags, ordering, and exit behavior remain unchanged."
  tests_added:
    - TestPrintConfig_RedactsResolvedCredentials
    - "Authorization and header coverage in TestIsSensitiveKey and TestRedact_DeepSnapshot"
  commands_executed:
    - {command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./cmd/sso-ctl/configcmd ./platform/configaudit", result: failed}
    - {command: "go test ./cmd/sso-ctl/configcmd ./platform/configaudit", result: passed}
    - {command: "python3 cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test ./... -race", result: failed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
  architecture_checks: "passed; no new package, production file, dependency, exemption, or gate change."
  security_checks: "passed; canonical recursive redaction is reused, Authorization is an exact case-insensitive key match, and non-sensitive fields remain visible."
  compatibility:
    breaking_change: false
    details: "Only printed credential values change to the existing marker; validation behavior is preserved."
  migration:
    required: false
    rollback_verified: false
    notes: "No data or configuration migration is required."
  residual_risks:
    - "Redaction remains key-name based; credentials under nonstandard unclassified keys are outside the existing heuristic."
  assumptions:
    - "The pre-existing untracked .pi-batch.lock is harness state and was not modified."
