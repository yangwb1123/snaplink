completion_report:
  summary: >-
    Surfaced the existing unavailable=true advisory on /auth/login home-realm
    discovery when the stored connection health is degraded or unreachable,
    while preserving the existing fail-open and authentication behavior.
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
    - >-
      HealthDegraded and HealthUnreachable both map to unavailable=true in the
      existing respondLoginProviders health read.
    - >-
      HealthHealthy, HealthUnknown, nil health, and Health read errors omit the
      key; a read error still returns HTTP 200 with connection_required and the
      same connection_id.
    - >-
      The response remains a display signal from stored probe state only; no
      authentication decision, fallback, oracle, or explicit-provider behavior
      changed.
    - >-
      OpenAPI, frontend, generated SDKs, and changelog describe the optional
      advisory/stale marker and its non-account/non-final-auth meaning.
    - >-
      No probe, circuit breaker, half-open state, TTL, failure counter, backup
      IdP, local fallback, hidden connection, new event, error, config, or
      endpoint was added.
    - >-
      No production file was added and server_oauth.go remains at 500 lines;
      runtime route count remains unchanged.
  tests_added:
    - >-
      TestConnectionHealthDegradedUX uses rcovNewServer, rcovPostJSON, and
      MemoryStore to cover degraded=true plus healthy/unknown key absence.
    - >-
      TestConnectionHealthReadErrorFailsOpen uses a test-only Store wrapper to
      cover a Health read error without copying production logic.
    - >-
      Existing unreachable regression TestRcov2H_HomeRealmFlagsUnreachableConnection
      remains in place.
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
    - command: "python cli.py check-filesize"
      result: passed
    - command: "python cli.py architecture"
      result: passed
    - command: "python cli.py check-exemptions"
      result: passed
    - command: "python cli.py complexity"
      result: not_executed
      note: "Cyclomatic check passed, but the cognitive-complexity tool was unavailable in the environment."
    - command: "git diff --check"
      result: passed
    - command: "make ci (before committing generated SDK outputs)"
      result: failed
      note: "Only sdk-drift failed because the required generated SDK changes were uncommitted; the post-commit run passed."
    - command: "make ci (post-commit)"
      result: passed
  architecture_checks:
    production_file_budget: "interfaces/sso/server_oauth.go is 500 lines; no production file was added."
    function_budget: "Targeted maintenance and architecture gates passed; no new production function was added."
    dependency_direction: "Passed; no import or package boundary changed."
    route_inventory: "Passed: 244 runtime routes and 366 documented operations; no route was added."
    generated_contracts: "SDK regeneration and sdk-surface validation passed after generated outputs were committed."
  security_checks:
    - "Only the existing Store.Health result is read; no network probe, request-input fetch, or background work was introduced."
    - "Health is advisory display metadata and is not consulted for authentication, dispatch refusal, fallback, or authorization."
    - "Health read errors are swallowed as before; no raw errors, probe details, or response-body data are emitted."
    - "Unknown/disabled/cross-tenant/broken provider unsupported_provider oracle behavior is unchanged."
    - "Healthy, unknown, nil, and unreadable health retain absent-key behavior."
    - "No new event, error, configuration key, or endpoint exists."
  compatibility:
    breaking_change: false
    details: >-
      This is an additive optional JSON property. Existing default responses
      omit unavailable, and existing 200 status, connection_required,
      connection_id, and routing behavior are retained.
  migration:
    required: false
    rollback_verified: true
    rollback_basis: >-
      Static review confirmed rollback is a one-condition/documentation revert;
      there is no persisted schema, configuration, or health-state migration.
  residual_risks:
    - >-
      The marker reflects the most recent admin-triggered probe and may be stale;
      it is intentionally not a live availability guarantee.
    - >-
      Cognitive complexity diagnostics remain unavailable until the environment
      provides the configured checker; committed Go maintenance gates passed.
  assumptions:
    - >-
      The existing /auth/login home-realm branch is the intended consumer of
      unavailable; the direct /auth/home-realm resolver remains routing-only.
    - >-
      Existing generated TypeScript and Python SDK files are contract artifacts
      and must remain synchronized with docs/openapi.yaml.
    - >-
      The pre-existing untracked .pi-batch.lock is harness state and is not part
      of this change or the commit.
