completion_report:
  summary: "Converged Geo default IP extraction on shared peertrust.RequestInfo; raw forwarded headers are no longer a Geo fallback."
  changed_files:
    - "platform/geo/middleware.go"
    - "platform/geo/middleware_test.go"
    - "cmd/sso-server/build_app_selfservice.go"
    - "cmd/sso-server/geo_trusted_proxy_test.go"
    - "interfaces/sso/options_misc.go"
    - "interfaces/sso/options_passwd.go"
    - "interfaces/sso/sso_protocol.go"
    - "config/config_metrics_security.go"
    - "docs/config-reference.md"
    - "test/geo_login_test.go"
    - "test/geo_middleware_test.go"
    - "test/region_residency_test.go"
    - "docs/campaigns/reports/geo-trusted-proxy-gate.md"
  requirements_covered:
    - "DefaultIPExtractor parses only canonical ClientIP when RequestInfo exists; otherwise it parses only RemoteAddr. Empty or invalid canonical data also falls back to RemoteAddr."
    - "Trusted and untrusted RequestInfo, forged XFF/X-Real-IP, RemoteAddr, IPv6, invalid addresses, and custom extractor behavior are covered."
    - "The stock server removed duplicate Geo wiring and uses outer TrustedProxies plus the platform default through one RequestInfo."
    - "WithTrustedProxies and related fields distinguish Geo's RemoteAddr default from legacy first-hop forwarded consumers; unset trusted_proxies remains unsafe at an untrusted edge."
    - "No peertrust.ClientIP, rate limiting, issuer/host handling, audit format, OpenAPI, SDK/config schema, package, dependency, exemption, or algorithm was changed."
  tests_added:
    - "platform/geo canonical peer-trust and default-deny extractor cases"
    - "test/geo_login_test.go real SDK/server default-deny test with only WithGeoProvider"
    - "forwarded Geo fixtures explicitly install WithTrustedProxies"
  commands_executed:
    - command: "go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_' ."
      result: passed
    - command: "go test ./platform/geo ./interfaces/middleware ./interfaces/sso ./cmd/sso-server ./test -run targeted Geo/trusted-proxy/residency tests -count=1"
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
  architecture_checks:
    - "Existing platform-to-shared import direction is used; no package, dependency, exemption, layerExemptions, or skipDirs was added."
    - "build_app_selfservice.go is 472 lines and interfaces/sso/sso_protocol.go is 500 lines."
  security_checks:
    - "No raw XFF/X-Real-IP fallback exists in the default Geo path."
    - "Untrusted peers use the canonical direct peer; explicit custom extractors remain caller responsibility."
    - "Other forwarded consumers retain their legacy contracts and the trusted_proxies edge warning."
  compatibility: "Custom IPExtractor behavior and all non-Geo forwarded-header consumers remain unchanged."
  migration: "No migration is required; callers needing forwarded Geo addresses must install WithTrustedProxies or provide an explicit extractor. Without canonical peer trust, Geo uses RemoteAddr."
  residual_risks:
    - "Legacy forwarded-header consumers remain unsafe at an untrusted edge when trusted_proxies is unset."
    - "An explicit extractor can intentionally select another source and must establish its own trust boundary."
  assumptions:
    - "TrustedProxies is the producer of canonical RequestInfo in the stock HTTP chain."
    - "RemoteAddr is the direct connection address and is the safe default Geo fallback."
