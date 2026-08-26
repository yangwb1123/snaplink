completion_report:
  summary: "Harden Geo provider cancellation at static-scan and MaxMind reader boundaries without changing fail-open middleware or wire behavior."
  changed_files:
    - platform/geo/geo.go
    - platform/geo/static/static.go
    - platform/geo/static/static_test.go
    - platform/geo/maxmind/maxmind.go
    - platform/geo/maxmind/maxmind_test.go
    - platform/geo/geo_test.go
    - platform/geo/middleware_test.go
    - docs/campaigns/reports/geo-context-cancellation.md
  requirements_covered:
    - "Provider.Lookup now MUST observe cancellation before work and between iterable or expensive operations, returning ctx.Err() rather than geo.ErrNotFound; middleware remains fail-open."
    - "Static Lookup checks cancellation before and after its read lock, between entries, and before hit/miss returns while keeping entries protected and longest-prefix behavior unchanged."
    - "MaxMind Lookup checks cancellation before and after Reader.Lookup; atomic snapshots, error wrapping, miss semantics, and Replace are unchanged. Reader.Lookup itself is not interruptible by this implementation."
    - "Composite is unchanged and a focused test verifies the original context reaches override and primary providers."
    - "Middleware timeout/cancellation remains fast and fail-open without stashing GeoInfo or changing error semantics."
    - "No extractor, trusted-proxy, configuration, OpenAPI, SDK, dependency, module, download/refresh/checksum, or Geo wire-contract changes were made."
  tests_added:
    - "Static canceled-context and existing hit/miss/longest-prefix regression coverage."
    - "MaxMind canceled-before-reader and canceled-after-reader coverage plus existing hit/miss/Replace coverage."
    - "Composite exact-context propagation and middleware canceled-request fail-open coverage."
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./platform/geo/...", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "make ci", result: passed}
    - {command: "python /home/u1/ai-batch-runner/scripts/check-completion-report.py docs/campaigns/reports/geo-context-cancellation.md", result: passed}
    - {command: "git diff --check", result: passed}
    - {command: "git status --porcelain", result: passed}
  architecture_checks: "passed: existing platform/geo packages only; no package, exemption, layerExemption, skipDir, or module changes."
  security_checks: "passed: cancellation is availability/fail-open behavior; trusted-proxy and security-boundary semantics are unchanged. Reader calls receive only boundary checks and cannot be interrupted here."
  compatibility:
    breaking_change: false
    details: "Normal hits, ErrNotFound misses, static longest-prefix matching, MaxMind snapshots/Replace, middleware fail-open behavior, and error semantics are preserved."
  migration:
    required: false
    rollback_verified: false
    details: "No configuration, data, dependency, or deployment migration is required."
  residual_risks:
    - "A MaxMind Reader.Lookup call may continue after cancellation because this implementation only checks before and after it."
    - "Static Lookup can wait for an in-progress writer while acquiring its read lock; cancellation is checked immediately after acquisition and throughout scanning."
  assumptions:
    - "The pre-existing untracked .pi-batch.lock is harness state and is not part of this change."
    - "Providers receive a non-nil context under the standard context contract."
