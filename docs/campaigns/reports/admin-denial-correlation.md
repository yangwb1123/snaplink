completion_report:
  summary: "Decision 3 implemented: denial correlation and gRPC stream-denial auditing. No new event type and no Decision 2 or authentication/authorization policy changes were made."
  changed_files:
    - interfaces/admin/governance.go
    - interfaces/admin/middleware.go
    - interfaces/sso/sse_admin_stream_test.go
    - platform/audit/handler_helpers.go
    - platform/audit/handler_helpers_test.go
    - test/admin_middleware_test.go
    - docs/campaigns/reports/admin-denial-correlation.md
  requirements_covered:
    - "HTTP denial events pass through request-id and valid traceparent TraceID/SpanID without minting IDs; malformed values remain empty."
    - "HTTP ActorIP remains geo.DefaultIPExtractor output and metadata remains method/path/reason via audit.SetMeta only."
    - "Unary and stream gRPC denials use transport peer Addr.String plus incoming request-id and validated traceparent; the full-method denied reason is unchanged."
    - "Stream denial is recorded before returning the original error; nil and failing recorders remain fail-open."
    - "A live authorized SSE stream receives admin_auth_denied and retains the login event assertion and framing."
  tests_added:
    - "Actual HTTP middleware/recorder correlation coverage for valid, absent, and malformed headers."
    - "gRPC stream denial coverage for peer, metadata, exact event count, handler reachability, and reason."
    - "Audit helper nil peer, nil metadata, and malformed traceparent coverage."
    - "Real SSE live denial coverage."
  commands_executed:
    - {command: "go test ./platform/audit -run 'TestEventFromGRPCContext|TestEventFromRequest_MalformedTraceparentIgnored' -count=1", result: passed}
    - {command: "go test ./test -run 'TestAdminHTTP_DenialCorrelation|TestAdminGRPC_StreamDenialIsCorrelatedAndAudited|TestAdminGRPC_AuditNetpolicyGated' -count=1", result: passed}
    - {command: "go test ./interfaces/sso -run TestSSEEventsStreamEndToEnd -count=1", result: passed}
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "python3 /home/u1/ai-batch-runner/scripts/check-completion-report.py docs/campaigns/reports/admin-denial-correlation.md", result: passed}
  architecture_checks:
    - "No production files, packages, dependencies, or exemptions were added; existing handler_helpers.go was reused."
    - "middleware.go and governance.go remain below 500 lines; capped production directory counts are unchanged."
  security_checks:
    - "Correlation is observational only and cannot affect auth, authorization, responses, or middleware order."
    - "HTTP IP uses only geo.DefaultIPExtractor; gRPC IP uses only transport peer; raw proxy headers are not used."
    - "No token, body, query, arbitrary header, or generated ID is recorded."
    - "HTTP/gRPC denial status/errors, challenges, reachability, event types, and reasons are unchanged."
  compatibility: "No OpenAPI, config, error-code, event-registry, dependency, SSE protocol, or framing changes."
  migration: "none"
  residual_risks:
    - "Synchronous audit sinks may add bounded latency, but failures remain fail-open."
    - "Correlation remains empty when callers provide no valid values."
  assumptions:
    - "The untracked .pi-batch.lock is harness state and is not part of this change."
    - "The existing SSE broker tap is the live event projection path."
