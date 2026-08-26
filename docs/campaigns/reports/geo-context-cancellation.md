# Geo provider context-cancellation hardening

This bounded change makes the Geo provider cancellation contract enforceable at
provider boundaries without changing Geo's fail-open middleware policy or any
wire/configuration surface. MaxMind reader calls are bounded only by checks
before and after the call; the reader call itself cannot be interrupted by this
implementation.

completion_report:
  summary: "Require Geo providers to honor context cancellation, check static CIDR scans between entries, and check MaxMind reader boundaries while preserving fail-open middleware behavior."
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
    - "Provider.Lookup documentation now uses a MUST cancellation contract: observe context before work and between iterable or expensive operations, and return ctx.Err() rather than geo.ErrNotFound when cancellation is observed."
    - "Static Lookup checks ctx.Err() before and after acquiring its read lock, between CIDR entries, before returning a hit, and before returning ErrNotFound; entries remain protected by the read lock."
    - "MaxMind Lookup checks ctx.Err() before and after the atomic snapshot reader call; snapshot loading, error wrapping, miss behavior, and Replace behavior remain unchanged."
    - "Composite behavior is unchanged and a focused test verifies the original context reaches both override and primary providers."
    - "Middleware timeout and cancellation remain fail-open, do not stash GeoInfo on cancellation, and retain OnError cancellation semantics."
    - "No DefaultIPExtractor, trusted-proxy, configuration, OpenAPI, SDK, Geo error wire contract, MaxMind lifecycle, module, or dependency changes were made."
  tests_added:
    - "Static canceled-context lookup returns context.Canceled and never geo.ErrNotFound."
    - "MaxMind canceled-context lookup returns context.Canceled before reader work."
    - "MaxMind post-reader context check returns context.Canceled when cancellation is observed at that boundary."
    - "Composite passes the exact context to override and primary providers."
    - "Middleware request cancellation fails open without storing GeoInfo and reports context.Canceled; existing timeout coverage remains in place."
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' . (run after each Go edit; 7 checkpoints)"
      result: passed
    - command: "go test ./platform/geo/..."
      result: passed
    - command: "go test ./platform/geo/... -race -count=10"
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "make ci"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "git status --porcelain"
      result: passed
  architecture_checks: "passed: only existing platform/geo packages and the requested report were changed; no packages, exemptions, layerExemptions, skipDirs, or module files were added."
  security_checks: "passed: cancellation remains an availability/fail-open concern, no security boundary or proxy trust behavior changed, and MaxMind reader calls are explicitly not interruptible by this implementation."
  compatibility:
    breaking_change: false
    details: "Normal hit, ErrNotFound miss, static longest-prefix, MaxMind snapshot, Replace, and middleware fail-open semantics are preserved."
  migration:
    required: false
    rollback_verified: false
    details: "No configuration, data, dependency, or deployment migration is required."
  residual_risks:
    - "A maxminddb Reader.Lookup call may still run to completion after cancellation because this change only checks context before and after that call."
    - "A static lookup can still wait for an in-progress writer while acquiring its read lock; cancellation is observed immediately after the lock is acquired and during the scan."
  assumptions:
    - "The pre-existing untracked .pi-batch.lock is harness state and is not part of this change."
    - "Geo providers receive a non-nil context, as required by the standard context contract."
