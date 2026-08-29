completion_report:
  summary: "Closed the DNS domain-ownership verification TOCTOU with an additive token-bound promotion capability. DNS proof can promote only the claim carrying the proven token; promotion errors never return verified=true."
  changed_files:
    - domains/connections/domain_verification.go
    - domains/connections/memory_domain_verification.go
    - domains/connections/sqlite/domain_verification.go
    - domains/connections/domain_verification_test.go
    - domains/connections/sqlite/domain_verification_test.go
    - docs/campaigns/reports/domain-verification-atomic.md
  requirements_covered:
    - "VerifyDomainOwnership fails closed when the Store lacks the safe token-bound capability and never falls back to Store.VerifyDomain for DNS proof."
    - "MemoryStore checks the current token and promotes under one mutex lock; SQLite performs the conditional token update and routing promotion in one transaction."
    - "Token mismatch returns false,nil; missing claims and storage errors remain errors; trusted token-free VerifyDomain is unchanged."
    - "No endpoint, configuration, schema, or public wire error contract was changed."
  tests_added:
    - "Paused-resolver delete/recreate regression for MemoryStore."
    - "Paused-resolver delete/recreate regression for SQLite."
    - "Unsupported capability fails closed and promotion errors cannot report verified."
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./domains/connections/...", result: passed}
    - {command: "go test ./domains/connections/... -race -count=10 -run 'Test.*(Domain|Claim)'", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "python3 cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test -race ./infrastructure/redis -run '^TestRedisErrorPaths/auth_code_fail_closed$' -count=1", result: passed}
    - {command: "make ci (attempt 1)", result: failed}
    - {command: "make ci (attempt 2)", result: failed}
    - {command: "git diff --check", result: passed}
  architecture_checks: "Passed: only existing packages/files were changed, no production Go file or package was created, the Store interface stayed source-compatible, and no contract or dependency change remains. The full gate was attempted but stopped on unrelated pre-existing race failures (Redis on attempt 1; SAML idpsqlite on attempt 2)."
  security_checks: "Passed: stale DNS tokens cannot promote replacement claims; missing/storage failures are fail-closed; the direct trusted VerifyDomain path is unchanged; and true is never returned with an error."
  compatibility:
    breaking_change: false
    details: "The extension is additive. Built-in MemoryStore and SQLite implement it. Custom stores without it now fail closed for pending DNS proof instead of using unsafe token-free promotion."
  migration:
    required: false
    rollback_verified: false
    details: "No persisted schema or configuration migration is needed; no rollback was performed."
  residual_risks:
    - "A custom Store that opts into TokenBoundDomainVerifier must honor its documented atomicity contract."
    - "make ci remains non-green because of unrelated race failures outside this change; targeted domain tests and the root race suite passed."
  assumptions:
    - "The pre-existing harness lock was ephemeral and was not restored after the repository checks cleaned it up."
    - "Already-verified claims retain the existing no-DNS short circuit because that path is not DNS promotion."
