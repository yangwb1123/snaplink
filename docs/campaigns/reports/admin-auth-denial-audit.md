completion_report:
  summary: "Implemented Decision 2 HTTP admin authentication-failure auditing with exactly one admin_auth_denied event per caller-denial branch. Decision 3 was not implemented."
  changed_files:
    - interfaces/admin/governance.go
    - interfaces/admin/middleware.go
    - interfaces/admin/middleware_test.go
    - platform/audit/auditspi/event_types_admin.go
    - platform/audit/auditspi/event_types.go
    - platform/audit/aliases_spi.go
    - platform/audit/auditreport/control_areas.go
    - platform/audit/auditsink/cef.go
    - platform/audit/auditsink/ocsf.go
    - platform/audit/auditsink/conformance_test.go
    - docs/campaigns/reports/admin-auth-denial-audit.md
  requirements_covered:
    - "Registered EventAdminAuthDenied as admin_auth_denied in the event registry, alias, CC6.3 area, CEF, OCSF, and conformance list."
    - "Missing, invalid, forbidden, and expired HTTP authentication branches emit one failure event with required reason, ActorIP, metadata, and validated actor/client evidence."
    - "Invalid claims remain anonymous; HTTP responses and Decision 1 governance behavior remain unchanged."
    - "No Decision 3 correlation, gRPC stream, SSE, or other HTTP denial taxonomy was added."
  tests_added:
    - "Four-branch event shape, metadata, actor/client, and wired/unwired response parity table."
    - "Nil/failing sink fail-open and unconfigured/internal-authorizer exclusions."
    - "HTTP versus unary gRPC parity for no token, invalid token, and no scope."
    - "Real MemoryAdminTokenStore session-expiry case with old LastUsedAt."
  commands_executed:
    - command: "go test ./interfaces/admin ./platform/audit/... ./cmd/sso-server -run 'TestHTTPMiddleware_AuthDenialsAudited|TestHTTPMiddleware_AuthDenialAuditFailOpenAndExcluded|TestAdminAuthDenialAuditTransportParity|TestConformance_EveryEventTypeHasCEFAndOCSFMapping|TestBuildApp_FullFeatureSet' -count=1"
      result: passed
    - command: "go build ./... && go vet ./..."
      result: passed
    - command: "go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "go test ./... -race (initial flaky pre-existing failure)"
      result: failed
    - command: "go test ./... -race (retry)"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "make ci (initial formatting failure before gofmt)"
      result: failed
    - command: "make ci (retry after gofmt)"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "python3 /home/u1/ai-batch-runner/scripts/check-completion-report.py docs/campaigns/reports/admin-auth-denial-audit.md"
      result: passed
  architecture_checks:
    - "No production file, package, dependency, exemption, skipDir, or layerExemption was added."
    - "middleware.go, governance.go, and middleware_test.go remain at or below 500 lines."
  security_checks:
    - "Only validated Subject and selected client ID populate identity fields; invalid claims never do."
    - "No token, body, query, or geo detail is audited; sink failure remains fail-open."
    - "Request/trace correlation and gRPC unary/stream behavior were not changed."
  compatibility: "Status, body, WWW-Authenticate, error description, headers, middleware order, existing denial event shapes, and stock Auditor wiring remain compatible; no Err, OpenAPI, config, schema, or wire error code was added."
  migration: "none"
  residual_risks:
    - "A synchronous audit sink may add latency, but cannot change the decision or response."
    - "Decision 3 correlation and gRPC stream-denial auditing remain deferred."
  assumptions:
    - "The existing stock srv.Auditor is the HTTP middleware recorder."
    - "The untracked .pi-batch.lock is harness state and is not part of this change."
