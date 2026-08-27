completion_report:
  summary: "Surface stored degraded IdP health through the existing login-discovery unavailable marker; no auth-policy change."
  changed_files:
    - docs/design/connection-health-degraded-ux.md
    - interfaces/sso/server_oauth.go
    - interfaces/sso/server_login_resolve.go
    - interfaces/sso/connection_health_degraded_ux_test.go
    - docs/openapi.yaml
    - docs/frontend-contract.md
    - docs/sdks/typescript/client.ts
    - docs/sdks/python/client.py
    - sdks/python/snaplink_sso/client.py
    - CHANGELOG.md
  requirements_covered:
    - "HealthDegraded and HealthUnreachable both set unavailable=true; healthy, unknown, nil, and read errors omit it."
    - "The marker remains stored-probe display metadata; no authentication, fallback, oracle, or route behavior changed."
    - "OpenAPI, frontend contract, and generated SDK artifacts describe the optional advisory marker."
    - "No probe scheduler, TTL, circuit breaker, backup/local fallback, new event/error/config/endpoint was added."
  tests_added:
    - "MemoryStore degraded/healthy/unknown login-discovery coverage."
    - "Health read-error fail-open coverage with a test-only Store wrapper."
    - "Existing unreachable regression retained."
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./domains/connections -run 'Test(RunProbe|HTTPProber)' -count=1"
      result: passed
    - command: "go test ./interfaces/sso -run 'Test(ConnectionHealth|Rcov2H_HomeRealmFlagsUnreachableConnection)' -count=1 -v"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "python cli.py sdk-surface generate"
      result: passed
    - command: "python cli.py check-filesize && python cli.py architecture && python cli.py check-exemptions"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
  architecture_checks: "Passed: no production file added, server_oauth.go remains 500 lines, route inventory unchanged, dependency direction and generated-contract checks passed."
  security_checks: "Passed: only stored health is read; errors/details are not exposed; no network probe, raw request input, auth decision, fallback, or provider oracle changed."
  compatibility:
    breaking_change: false
    details: "Additive optional JSON property; default healthy/unknown/read-error responses remain unchanged."
  migration:
    required: false
    rollback_verified: true
    details: "No persisted schema or config migration; rollback is the condition/docs revert."
  residual_risks:
    - "The marker reflects the most recent admin-triggered probe and can be stale; it is not a live availability guarantee."
    - "Cognitive-complexity diagnostics were unavailable; configured maintenance and architecture gates passed."
  assumptions:
    - "The existing /auth/login home-realm branch is the intended consumer of unavailable."
    - "Generated SDK files are synchronized contract artifacts."
