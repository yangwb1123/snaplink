completion_report:
  summary: "Decision 3 implemented. No new event type, Decision 2 change, or authentication/authorization policy change was made."
  changed_files:
    - interfaces/admin/governance.go
    - interfaces/admin/middleware.go
    - interfaces/sso/sse_admin_stream_test.go
    - platform/audit/handler_helpers.go
    - platform/audit/handler_helpers_test.go
    - test/admin_middleware_test.go
    - docs/campaigns/reports/admin-denial-correlation.md
  requirements_covered:
    - "HTTP denials pass through request-id and valid traceparent IDs only; malformed values stay empty."
    - "HTTP ActorIP remains geo.DefaultIPExtractor; only method/path/reason metadata uses audit.SetMeta."
    - "Unary and stream gRPC denials use transport peer, incoming correlation metadata, and unchanged full-method reason."
    - "Stream denial is recorded before returning; nil or failing recorders remain fail-open."
    - "A live authorized SSE stream receives admin_auth_denied without protocol/framing changes."
  tests_added:
    - "HTTP middleware correlation: valid, absent, and malformed headers."
    - "gRPC stream denial: peer, IDs, exact event, reachability, and reason."
    - "Audit helper nil transport and malformed traceparent safety."
    - "Real SSE live denial alongside the existing login assertion."
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
    - {command: "make ci (first run; unrelated AsyncSink timing threshold)", result: failed}
    - {command: "go test ./... -race (retry)", result: passed}
    - {command: "make ci (retry)", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "independent diff review: budgets, headers, IDs, stream order, clean status", result: passed}
    - {command: "completion checker", result: passed}
  architecture_checks:
    - "Existing production files only; no package, dependency, exemption, or capped-directory file was added."
    - "middleware.go and governance.go remain below 500 lines; handler_helpers.go was reused."
  security_checks:
    - "Correlation is observational and does not affect auth, authorization, responses, or middleware order."
    - "HTTP IP uses only geo.DefaultIPExtractor; gRPC IP uses only transport peer; proxy headers are not ActorIP."
    - "No token, body, query, arbitrary header, or generated ID is recorded."
    - "Existing denial status, challenge, reachability, event types, and reasons are preserved."
  compatibility: "No OpenAPI, config, error-code, event-registry, dependency, SSE protocol, or framing changes."
  migration: "none"
  residual_risks:
    - "Synchronous sinks may add bounded latency, but recording failures remain fail-open."
    - "Correlation is empty when callers provide no valid values."
    - "The first make ci run hit unrelated AsyncSink timing; immediate retries passed."
  assumptions:
    - "The existing SSE broker tap is the live event projection path."
