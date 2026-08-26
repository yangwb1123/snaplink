completion_report:
  summary: "Honor context cancellation in static and MaxMind Geo providers while preserving fail-open middleware behavior."
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
    - "Lookup implementations now check cancellation before work and during scans; cancellation returns ctx.Err(), not geo.ErrNotFound."
    - "Static preserves locking, hits, misses, and longest-prefix behavior."
    - "MaxMind checks context before and after Reader.Lookup; snapshot and Replace behavior are unchanged."
    - "Composite context propagation and middleware fail-open cancellation are covered."
    - "No proxy, configuration, OpenAPI, SDK, dependency, or Geo wire-contract changes."
  tests_added:
    - "Canceled static and MaxMind lookups."
    - "MaxMind post-reader cancellation boundary."
    - "Composite exact-context propagation."
    - "Middleware cancellation without stashing GeoInfo."
  commands_executed:
    - {command: "go build ./... && go vet ./...", result: passed}
    - {command: "go test -run 'TestMaintainability_|TestArchitecture_' .", result: passed}
    - {command: "go test ./platform/geo/... -race -count=10", result: passed}
    - {command: "python cli.py check-test", result: passed}
    - {command: "make docs-validate", result: passed}
    - {command: "go test ./... -race", result: passed}
    - {command: "go test ./test/ -run TestE2E -v", result: passed}
    - {command: "make ci", result: passed}
    - {command: "git diff --check", result: passed}
  architecture_checks: "passed: existing Geo packages only; no exemptions, new packages, or module changes."
  security_checks: "passed: fail-open availability semantics and proxy trust are unchanged; Reader.Lookup is checked only before and after because the library call is not interruptible here."
  compatibility:
    breaking_change: false
    details: "Normal hits, ErrNotFound misses, static longest-prefix matching, MaxMind snapshots, Replace, and middleware behavior are preserved."
  migration:
    required: false
  residual_risks:
    - "A MaxMind Reader.Lookup call may finish after cancellation."
    - "Static lookup may wait for a writer before observing cancellation."
  assumptions:
    - "Providers receive a non-nil context under the standard context contract."
