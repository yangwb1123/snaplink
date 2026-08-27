completion_report:
  summary: "Added additive, default-off authenticators.password.policy wiring for the existing local password validator; it covers self-service writes, admin reset, local-user creation, and first-run setup."
  changed_files: [CHANGELOG.md, cmd/sso-server/build_app_selfservice.go, cmd/sso-server/config.yaml, cmd/sso-server/password_policy_wiring_test.go, cmd/sso-server/serverbuildauthn/build_authenticators.go, config/config_authn.go, config/config_load.go, config/password_policy_test.go, docs/campaigns/reports/password-policy-config.md, docs/config-reference.md, docs/design/password-policy-config.md, docs/error-codes.md, docs/feature-matrix.md, interfaces/admin/password_policy_test.go, interfaces/admin/users.go, interfaces/sso/password_policy_setup_test.go, interfaces/sso/server_setup.go, internal/adminuser/password_policy_test.go, internal/adminuser/service.go, shared/spi/password_health.go]
  requirements_covered: ["Maps min_length, four complexity booleans, and max_age_days to the existing SPI.", "Validates min_length 0..1024 and max_age_days 0..36500.", "Missing/all-zero policy is a no-op and the stock example remains disabled.", "Self-service, admin, local-user, and setup paths share the validator; setup validates before persistence.", "Expiry remains PasswordAgeReader-only, successful-password-only, and fail-open.", "History remains explicit wiring; no max_history YAML, HIBP setting block, migration, endpoint, or event was added."]
  tests_added: [config/password_policy_test.go, cmd/sso-server/password_policy_wiring_test.go, interfaces/admin/password_policy_test.go, internal/adminuser/password_policy_test.go, interfaces/sso/password_policy_setup_test.go]
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./config ./cmd/sso-server ./interfaces/admin ./internal/adminuser ./interfaces/sso ./protocols/selfservice -run 'PasswordPolicy|SetupPasswordPolicy|SetupRecovery' -count=1", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "python3 cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
  architecture_checks: ["No production Go file, package, import-direction change, or exemption was added.", "Optional provider assertions preserve existing Deps compatibility; required budgets and repository gates passed."]
  security_checks: ["Errors remain generic password_policy_violation or invalid_request; passwords, rules, tokens, and bodies are not exposed or logged.", "Setup rejection precedes role, user, and credential persistence; expiry does not affect WebAuthn or federation."]
  compatibility: {breaking_change: false, default_behavior: "Omitted or all-zero policy appends no option and preserves existing behavior.", new_endpoint: false, new_event: false}
  migration: {required: false, rollback_verified: true, rollback: "Remove authenticators.password.policy or zero its fields and restart; no data migration is needed."}
  residual_risks: ["Password history still requires explicit WithPasswordHistoryStore wiring.", "Missing PasswordAgeReader or age-read errors retain the existing fail-open expiry behavior."]
  assumptions: ["The stock cmd/sso-server YAML is the requested operator configuration surface.", "MaxHistory remains a programmatic SPI concern and is intentionally absent from YAML."]
