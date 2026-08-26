completion_report:
  summary: "Wire stock sso-server geo.backend=maxmind to one fixed local MMDB with static CIDR overlay."
  changed_files:
    - config/config_geo_tenant.go
    - cmd/sso-server/serverbuildstore/build_tenant_geo_region.go
    - cmd/sso-server/serverbuildstore/build_tenant_geo_region_test.go
    - cmd/sso-server/subsystem_builders_test.go
    - cmd/sso-server/config.yaml
    - docs/config-reference.md
    - docs/campaigns/reports/geo-maxmind-wiring.md
  requirements_covered:
    - "BuildGeoProvider reads geo.maxmind.mmdb_path only at startup and fails closed on read, empty, or parse errors with geo.maxmind/mmdb context."
    - "maxmind.New is the primary; geo.NewComposite puts static longest-prefix entries first and preserves ErrNotFound misses."
    - "Disabled, empty/static, and unknown-backend behavior remains compatible; maxmind is no longer the unknown-backend fixture."
    - "Config comments and reference document the static overlay, startup validation, and absent automatic data lifecycle."
    - "No API, OpenAPI, SDK, root module dependency, binary, dist, download, URL, checksum, or refresh change."
  tests_added:
    - "TestBuildGeoProvider_MaxMindStaticOverlay"
    - "TestBuildGeoProvider_MaxMindPathErrorsAtBuild"
    - "Deterministic mmdbwriter fixture is written only under t.TempDir."
  commands_executed:
    - command: "go build ./... && go vet ./..."
      result: passed
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
    - command: "make ci (first attempt)"
      result: failed
      notes: "An unrelated nondeterministic domains/permissions conformance case failed; the focused rerun passed."
    - command: "go test ./domains/permissions -race -count=1 -run 'TestMemoryProvider_Conformance/List_ScopesEntries' -v"
      result: passed
    - command: "make ci (rerun)"
      result: passed
    - command: "git diff --check"
      result: passed
    - command: "git status --porcelain"
      result: passed
  architecture_checks: "passed: existing packages and imports only; no exemptions, layerExemptions, skipDirs, or budget changes."
  security_checks: "passed: only the configured local filesystem path is read during construction; request input, URLs, downloads, checksums, and refresh loops are not used; invalid MMDBs fail closed before assembly."
  compatibility:
    breaking_change: false
    details: "Disabled geo remains (nil, nil); empty/static remains the existing static provider; unknown backends remain loud; geo.Provider and root go.mod/go.sum are unchanged."
  migration:
    required: false
    rollback_verified: false
    details: "Existing static deployments need no change. Opt in with a valid operator-managed MMDB, geo.enabled=true, geo.backend=maxmind, and geo.maxmind.mmdb_path."
  residual_risks:
    - "Automatic download, checksum verification, publication of GeoIP data, and background refresh are intentionally not implemented and remain a separate boundary."
    - "MMDB freshness and replacement require an operator-controlled restart."
  assumptions:
    - "The configured path is readable by the server process and names a MaxMind database supported by maxminddb-golang."
    - "The pre-existing untracked .pi-batch.lock is harness state and is not part of this change."
