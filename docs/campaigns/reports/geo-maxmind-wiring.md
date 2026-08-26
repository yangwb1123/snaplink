# GeoIP MaxMind deploy-tree wiring

## Bounded specification

- Wire only the stock `sso-server` composition path for `geo.backend: maxmind`.
- Load exactly one local `.mmdb` from `geo.maxmind.mmdb_path` during startup construction.
- Keep `geo.static.entries` as the longest-prefix override layer and preserve the existing disabled, empty/static, and unknown-backend behavior.
- Add deterministic builder coverage without committing a database artifact.
- Do not add download, URL, checksum, refresh, external-service, OpenAPI, or SDK behavior.

The implementation uses the existing `platform/geo/maxmind.New` provider as the
primary and `geo.NewComposite` with the existing static provider as the override.
Read, empty-file, and parse errors are returned from `BuildGeoProvider` with
`geo.maxmind/mmdb` context before the server is assembled.

completion_report:
  summary: "Wire the stock sso-server maxmind GeoIP backend with a fixed local mmdb path and static overlay"
  changed_files:
    - "config/config_geo_tenant.go"
    - "cmd/sso-server/serverbuildstore/build_tenant_geo_region.go"
    - "cmd/sso-server/serverbuildstore/build_tenant_geo_region_test.go"
    - "cmd/sso-server/subsystem_builders_test.go"
    - "cmd/sso-server/config.yaml"
    - "docs/config-reference.md"
    - "docs/campaigns/reports/geo-maxmind-wiring.md"
  requirements_covered:
    - "geo.backend: maxmind reads geo.maxmind.mmdb_path only during BuildGeoProvider startup construction"
    - "The existing maxmind.New provider is the primary and geo.NewComposite preserves static longest-prefix precedence"
    - "Known mmdb lookup, static override, private/unmatched ErrNotFound, and missing/empty/malformed build failures are deterministic tests"
    - "The old maxmind-as-unknown regression test now uses carrier-pigeon"
    - "Configuration examples and reference document startup validation, static overlay behavior, and no automatic data lifecycle"
    - "No Go API, OpenAPI, SDK, root module dependency, binary, or dist artifact was added"
  tests_added:
    - "TestBuildGeoProvider_MaxMindStaticOverlay"
    - "TestBuildGeoProvider_MaxMindPathErrorsAtBuild"
    - "buildGeoMMDBFixture uses mmdbwriter bytes written only to t.TempDir"
  commands_executed:
    - command: "go build ./... && go vet ./..."
      result: passed
      notes: "Run after each Go edit and again through the final CI gate"
    - command: "go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./platform/geo/..."
      result: passed
    - command: "go test ./cmd/sso-server/serverbuildstore -run 'TestBuildGeoProvider' -count=1"
      result: passed
    - command: "go test ./cmd/sso-server -run 'TestBuildGeoProvider' -count=1"
      result: passed
    - command: "python cli.py check-test"
      result: passed
    - command: "make docs-validate"
      result: passed
    - command: "go test ./... -race"
      result: passed
    - command: "go test ./test/ -run TestE2E -v"
      result: passed
    - command: "make ci (first run)"
      result: failed
      notes: "The format gate identified the newly edited config/config_geo_tenant.go; gofmt was applied and the gate was rerun"
    - command: "make ci (rerun)"
      result: passed
    - command: "git diff --check (first run)"
      result: failed
      notes: "A trailing space in the new config-reference row was removed"
    - command: "git diff --check (final run)"
      result: passed
    - command: "git status --porcelain"
      result: passed
      notes: "The pre-existing untracked .pi-batch.lock was preserved and is not part of this change"
  architecture_checks: "No new package, exemption, layerExemption, skipDir, or upward import; builder logic stays in cmd/sso-server/serverbuildstore and uses the existing platform geo ports. Go file and function sizes remain within AGENTS.md budgets."
  security_checks: "The only production input is the configured local filesystem path; no request value, URL, downloader, checksum, refresh loop, or external service is involved. Read and parser errors fail closed at build time, and geo remains advisory."
  compatibility: "geo.enabled=false still returns (nil, nil); empty and static backends retain the prior static provider behavior; unknown backends still fail loudly; geo.Provider and the root module dependency files are unchanged."
  migration: "To opt in, provide an operator-managed valid local .mmdb, set geo.enabled=true, set geo.backend=maxmind, and set geo.maxmind.mmdb_path. Existing static deployments require no migration."
  residual_risks: "Download, checksum verification, publication of GeoIP data, and background refresh are intentionally not implemented; changing the local database requires an operator-controlled restart and stale data remains an operator lifecycle concern."
  assumptions: "The configured path is readable by the server process at startup and points to a database supported by maxminddb-golang; static entries are optional and remain the private/office override mechanism."
