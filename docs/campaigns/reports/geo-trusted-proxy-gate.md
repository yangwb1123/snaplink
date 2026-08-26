completion_report:
  summary: "Moved the Geo default IP trust decision into platform/geo and made it consume the shared canonical peer-trust context."
  changed_files:
    - path: "platform/geo/middleware.go"
      changes: "DefaultIPExtractor parses peertrust.RequestInfo.ClientIP and otherwise uses only RemoteAddr."
    - path: "platform/geo/middleware_test.go"
      changes: "Covers trusted and untrusted canonical contexts, forged headers, fallback, IPv4, IPv6, and invalid addresses."
    - path: "cmd/sso-server/build_app_selfservice.go"
      changes: "Removed the duplicate trustedProxyIPExtractor and server-only Geo IP extractor wiring; retained timeout and error reporting."
    - path: "cmd/sso-server/geo_trusted_proxy_test.go"
      changes: "Clarified that the integration test exercises the module default through the stock middleware chain."
    - path: "interfaces/sso/options_misc.go"
      changes: "Documented the default Geo extractor and explicit extractor responsibility."
    - path: "interfaces/sso/options_passwd.go"
      changes: "Documented canonical peer trust, Geo RemoteAddr fallback, and legacy forwarded consumers."
    - path: "interfaces/sso/sso_protocol.go"
      changes: "Updated trusted-proxy field documentation without exceeding the 500-line budget."
    - path: "config/config_metrics_security.go"
      changes: "Separated Geo default behavior from legacy forwarded-header consumers in field documentation."
    - path: "docs/config-reference.md"
      changes: "Updated the trusted-proxy configuration contract."
    - path: "docs/campaigns/reports/geo-trusted-proxy-gate.md"
      changes: "Recorded the bounded implementation, verification, and residual-risk report."
    - path: "test/geo_login_test.go"
      changes: "Installed explicit trusted proxies for forwarded Geo fixtures and added a real SDK default-deny test."
    - path: "test/geo_middleware_test.go"
      changes: "Updated default extractor tests to use canonical RequestInfo or direct-address fallback."
    - path: "test/region_residency_test.go"
      changes: "Installed explicit trusted proxies for the forwarded Geo audit fixture."
  requirements_covered:
    - "Default Geo extraction never falls back to raw X-Forwarded-For or X-Real-IP."
    - "A valid canonical ClientIP is used for both trusted and untrusted peer verdicts; empty or malformed canonical data falls back to RemoteAddr."
    - "Custom MiddlewareOptions.IPExtractor behavior is unchanged and remains caller responsibility."
    - "The stock server uses outer TrustedProxies plus the platform default extractor with one shared RequestInfo."
    - "Other forwarded-header consumers and peertrust.ClientIP legacy behavior were not changed."
  tests_added:
    - "platform/geo DefaultIPExtractor canonical-context and forged-header cases."
    - "test/geo_login_test.go TestLogin_DefaultGeoExtractorIgnoresForgedForwardedHeaders."
    - "Expanded SDK and residency fixtures to install WithTrustedProxies when forwarding Geo addresses."
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' . (intermediate comment-budget attempt)"
      result: failed
    - command: "go test ./platform/geo -run 'Test(Middleware|DefaultIPExtractor|CountryCode)' -count=1; go test ./interfaces/middleware -run 'Test(TrustedProxies|RealClientIP|BaseURL|ForwardedHeadersTrusted)' -count=1; go test ./interfaces/sso -run 'Test.*Geo|Test.*Trusted' -count=1; go test ./cmd/sso-server -run 'TestWireGeoRegionRisk_TrustedProxiesGatesGeoIPExtraction' -count=1; go test ./test -run 'Test(Login_.*Geo|Audit_Geo|DefaultGeoIPExtractor|Residency_AuditCarriesServingRegionWithoutClobberingGeo)' -count=1"
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
  architecture_checks:
    - "platform/geo imports the existing shared/security/peertrust package in the platform-to-shared direction."
    - "No package, dependency, exemption, layerExemptions, or skipDirs was added."
    - "build_app_selfservice.go is 472 lines and interfaces/sso/sso_protocol.go remains exactly 500 lines."
  security_checks:
    - "Default Geo path is default-deny for forwarded headers when canonical peer trust is absent."
    - "Untrusted peers use the canonical direct-peer ClientIP produced by TrustedProxies."
    - "No CIDR or hop algorithm was duplicated; only RequestInfo is shared."
    - "The unset trusted_proxies warning remains: legacy forwarded-header consumers are still unsafe at an untrusted edge."
  compatibility: "Custom Geo extractors, peertrust.ClientIP, rate limiting, issuer and host handling, audit format, OpenAPI, SDK schema, and config schema are unchanged."
  migration: "No migration is required. Embedders that intentionally need forwarded Geo addresses must install WithTrustedProxies or provide an explicit IPExtractor; without canonical peer trust the default uses RemoteAddr."
  residual_risks:
    - "Legacy forwarded-header consumers still retain their documented first-hop behavior when trusted proxies are unset."
    - "An explicit custom IPExtractor can opt into another source and is the caller's trust-boundary responsibility."
  assumptions:
    - "TrustedProxies remains the producer of canonical peertrust.RequestInfo for stock HTTP server requests."
    - "RemoteAddr is the direct connection address and is the safe fallback when no canonical peer-trust result exists."
