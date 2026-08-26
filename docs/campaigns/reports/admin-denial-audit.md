completion_report:
  summary: "Decision 1 adds exactly-once, fail-open audit events to the four HTTP admin governance gates and completes their taxonomy/SIEM mappings. Decision 2 and Decision 3 were not implemented."
  changed_files:
    - interfaces/admin/governance.go
    - interfaces/admin/middleware.go
    - interfaces/admin/governance_test.go
    - platform/audit/auditspi/event_types_admin.go
    - platform/audit/auditspi/event_types.go
    - platform/audit/aliases_spi.go
    - platform/audit/auditreport/control_areas.go
    - platform/audit/auditsink/cef.go
    - platform/audit/auditsink/ocsf.go
    - platform/audit/auditsink/conformance_test.go
    - cmd/sso-server/build_app.go
    - cmd/sso-server/build_app_coverage_test.go
    - docs/campaigns/reports/admin-denial-audit.md
  requirements_covered:
    - "IP/geo, rate-limit, destructive-confirm, and write-quota denials emit one OutcomeFailure event when a recorder is wired; nil and failing recorders are fail-open."
    - "ActorIP uses geo.DefaultIPExtractor; metadata is only method/path/reason; write quota preserves actor and tenant event fields; query/token/body data is excluded."
    - "Wired and unwired responses, headers, Retry-After, WWW-Authenticate, and applicable HEAD behavior are equivalent."
    - "Existing IP/write events and new rate/destructive events are registered, aliased, classified, explicitly CEF/OCSF mapped, and conformance-covered."
    - "Stock sso-server wires srv.Auditor() to SetAuditRecorder; Decision 2 auth/session auditing and Decision 3 correlation/gRPC stream work remain absent."
  tests_added:
    - interfaces/admin exact-once event, metadata, actor/tenant, response-equivalence, nil/failure, and HEAD tests
    - cmd/sso-server stock auditor-wiring regression assertion
    - auditsink conformance snapshot entries for all four event types
  commands_executed:
    - {command: "go test ./interfaces/admin ./platform/audit/... ./cmd/sso-server -run 'TestHTTPGovernanceDenials|TestHTTPMiddleware_|TestConformance_|TestBuildApp_FullFeatureSet' -count=1", result: passed}
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test ./... -race (initial)", result: failed}
    - {command: "go test ./... -race (retry)", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "make ci (initial)", result: failed}
    - {command: "make ci (retry)", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "python3 /home/u1/ai-batch-runner/scripts/check-completion-report.py docs/campaigns/reports/admin-denial-audit.md", result: passed}
  architecture_checks:
    - "No interfaces/admin production file, package, dependency, exemption, skipDir, or layerExemption was added; no auth or gRPC code was changed."
    - "governance.go is 493 lines, middleware.go 492, and build_app.go 500."
  security_checks:
    - "Events contain no token, credential, body, query, raw geo detail, or unbounded extra metadata; audit cannot decide a gate."
    - "Gate order remains IP/geo, rate limit, destructive confirmation, authentication, idle timeout, then write quota."
  compatibility: "No Err*, OpenAPI endpoint, config knob, or wire error code was added; denial responses remain unchanged."
  migration: "none"
  residual_risks:
    - "A synchronous sink can add denial latency, but sink errors do not alter decisions or responses."
    - "Initial race/CI attempts failed transiently; immediate retries passed."
  assumptions:
    - "Server.Auditor() is the stock HTTP governance recorder and DefaultIPExtractor is canonical."
    - "The untracked .pi-batch.lock is harness state and is not part of this change."
