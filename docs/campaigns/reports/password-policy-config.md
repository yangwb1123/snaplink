completion_report:
  summary: >
    Added default-off stock configuration for the existing password policy SPI.
    The shared validator covers self-service writes, admin reset, local-user
    creation, and first-run setup; login expiry keeps its PasswordAgeReader
    fail-open contract.
  changed_files:
    - CHANGELOG.md
    - cmd/sso-server/build_app_selfservice.go
    - cmd/sso-server/config.yaml
    - cmd/sso-server/password_policy_wiring_test.go
    - cmd/sso-server/serverbuildauthn/build_authenticators.go
    - config/config_authn.go
    - config/config_load.go
    - config/password_policy_test.go
    - docs/config-reference.md
    - docs/design/password-policy-config.md
    - docs/feature-matrix.md
    - interfaces/admin/password_policy_test.go
    - interfaces/admin/users.go
    - interfaces/sso/password_policy_setup_test.go
    - interfaces/sso/server_setup.go
    - internal/adminuser/password_policy_test.go
    - internal/adminuser/service.go
    - shared/spi/password_health.go
  requirements_covered:
    - Added min_length, complexity booleans, and max_age_days YAML projection.
    - Validated min_length 0..1024 and max_age_days 0..36500.
    - Missing/all-zero policy remains a no-op.
    - Stock self-service, admin, local-user, and setup paths share the validator.
    - Setup rejects before role, user, or credential writes; recovery is not revalidated.
    - max_history, durable history YAML, setting-time HIBP, migration, endpoints, and events remain excluded.
  tests_added:
    - config/password_policy_test.go
    - cmd/sso-server/password_policy_wiring_test.go
    - interfaces/admin/password_policy_test.go
    - internal/adminuser/password_policy_test.go
    - interfaces/sso/password_policy_setup_test.go
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./cmd/sso-server/serverbuildauthn ./config ./interfaces/admin ./internal/adminuser ./interfaces/sso ./protocols/selfservice -count=1"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "python3 cli.py check-test && make docs-validate"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks:
    - No production files or exemptions were added; budgets and import layers passed.
    - Optional provider assertions preserve existing Deps source compatibility.
    - make ci passed nested-module, route, capability, SDK, and adapter checks.
  security_checks:
    - Failures remain generic password_policy_violation or invalid_request responses.
    - Passwords and validator details are not returned or logged.
    - max_age_days is post-success-password, reader-gated, and fail-open on unsupported/failed reads.
    - No network dependency, new event, error code, or endpoint was added.
  compatibility:
    breaking_change: false
    default_behavior: "Omitted or all-zero policy is disabled; existing responses, errors, timestamps, and seed hashes are unchanged."
  migration:
    required: false
    rollback_verified: true
    rollback: "Remove authenticators.password.policy or restore all fields to zero; no data migration is needed."
  residual_risks:
    - Password history remains explicit WithPasswordHistoryStore wiring without a stock durable YAML backend.
    - PasswordAgeReader absence or read failure continues to bypass expiry by design.
  assumptions:
    - The stock sso-server composition root is the requested YAML surface.
    - spi.PasswordPolicyConfig.MaxHistory remains a programmatic concern.
    - Independent final gates, not the timed-out runner retry, are the evidence.
