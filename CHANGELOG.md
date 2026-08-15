# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Automatic degraded-mode transitions: with
  `degradation.auto_read_only_on_store_loss: true`, `sso-server` now runs an
  in-process driver that polls its wired storage-health sources (the same Ping
  probes behind the admin `/storage-health` report; audit sinks excluded
  because audit is fail-open by contract) and drops to `read_only` after a
  store has been continuously unhealthy for
  `degradation.auto_read_only.grace` (hysteresis — transient probe jitter
  never flaps the mode), restoring the configured `degradation.initial_mode`
  when health returns. Transitions flow through the same audit + metric path
  as the admin `POST /api/v1/admin/dr/mode` toggle. New keys:
  `degradation.auto_read_only.interval` (poll cadence, default 30s) and
  `degradation.auto_read_only.grace` (default 60s); `<=0` on either takes the
  package default.
- SMTP implicit TLS: the built-in email sender now establishes the TLS
  connection before the first SMTP verb on port `465` (auto-selected) or with
  `smtp.tls_mode: implicit`; STARTTLS (`587`) and plaintext (`25`) behavior is
  unchanged. Verification is fail-closed (ServerName pinned to the relay host,
  TLS 1.2 floor, no `InsecureSkipVerify`).
- API-only identity-platform capabilities added after `v0.10.0`:
  - OpenID Federation list, resolve, trust-mark status, and historical-key
    endpoints.
  - OpenID SSF configuration and Stream Management API.
  - ReBAC/FGA tuple CRUD, batch writes, reverse graph expansion, and access
    checks with memory and SQLite stores.
  - Tenant branding administration, provider inventory, trusted-device
    management, security activity, and login-history APIs.
  - Continuous session trust, device posture, token anomaly detection, and
    opt-in ITDR threat actions.
- `sso-ctl` tenant/user administration, interactive TUI, and fixed `generate`
  command dispatch.
- First-run setup API and runtime wiring for identity linking and user
  lifecycle reactions.
- Property, fuzz, adversarial, and end-to-end coverage for federation/SSF,
  ReBAC, device trust, self-service, anti-enumeration, and cryptographic
  policy.
- Engineering system infrastructure:
  - Committed Go gates for file/function budgets, protocol/layer imports,
    directory fan-out, and directory depth.
  - Python CLI diagnostics for declarative checks, invariants, root policy,
    coverage reporting, health, and acceptance reporting.
  - Source-controlled Agent OS references, ADRs, review/feature templates, and
    refactoring/security skill cards.
  - Engineering-scaffolding validation through `make harness`, plus trend and
    self-diagnosis reports.
- GitHub Actions workflow `.github/workflows/engineering.yml` for PR gating
- Dependabot configuration for automated dependency updates
- Issue templates (bug report, feature request, technical debt)
- CODEOWNERS file for PR routing
- Developer guide, release process, security policy documentation

### Changed
- Removed the embedded frontend bundles from the SDK and `sso-server`.
  Hosted login, admin, self-service, developer, and setup UIs are now separate
  frontend projects served through a reverse proxy; this repository is an
  API-only backend.
- Expanded live `SIGHUP` reload to supported feature gates and an
  already-wired rate-limit policy; stores, listeners, TLS, and unwired
  components still require restart.
- Physically organized library packages under `shared/`, `platform/`,
  `domains/`, `protocols/`, `infrastructure/`, and `interfaces/`, with
  `interfaces/sso` as the public Server API.
- Engineering scaffolding now validates source-controlled Markdown instead of
  overwriting Agent OS, review, feature-spec, or `.pi` documentation.
- Makefile: 15+ new targets added (harness, filesize, complexity, architecture,
  check-invariants, self-test, check-exemptions, health-report, diagnose,
  trend, generate-engineering, make help)
- `.golangci.yml` now uses its default correctness set plus `misspell` and
  `unconvert`; cyclomatic/function length are committed root gates and
  cognitive complexity is a Python diagnostic. This supersedes the retired
  `funlen`/`gocyclo`/`gocognit` lint configuration recorded in 0.10.0.
- AGENTS.md: Streamlined to focus on behavior rules and protocol invariants
- CONTRIBUTING.md: Updated with engineering system references
- ci.yml: Added engineering gates step before build

### Fixed
- Closed cross-tenant domain-claim races in SQLite and Postgres tenant stores.
- Added panic recovery to permanent background workers and every gRPC service.
- Preserved refresh-grace replay semantics with atomic SQLite consumption.
- Prevented admin update RPCs from wiping fields not represented on the wire
  and wired pagination across list RPCs.
- Hardened metadata, webhook, CIBA, LDAP, SAML, RADIUS, MQTT, SCIM, and KMS
  network/error paths.
- Oracle-leak hardening patterns documented and checked
- Anti-enumeration patterns (bcrypt dummy hash) verified
- Cache-Control: no-store and WWW-Authenticate presence verified across 9+ files

### Security
- Opt-in strict OAuth credential-wire Content-Type enforcement
  (`server.require_form_content_type: true` / `sso.WithCredentialFormOnly(true)`,
  default off): the four credential endpoints (`/token`, `/token/introspect`,
  `/token/revoke`, `/par`) reject a JSON body, a missing Content-Type, or any
  other media type with `415` and the plain `invalid_request` envelope before
  the body is read — nothing is minted, revoked, introspected, or stored, and
  every response carries `Cache-Control: no-store` + `Pragma: no-cache`.
  Default-off keeps the JSON acceptance and the wire byte-identical.
- `sso-ctl` no longer follows HTTP redirects from the admin API (`tenants`,
  `users`, `clients`, `tokens`, `sessions`, `tui`, and `audit-verify
  --from-url`). A 3xx response now fails the command (exit 1) instead of
  forwarding the bearer token — and, for 307/308 writes, the request body —
  to the redirect target. Operators must point `SSO_ADMIN_ADDR` at the
  canonical admin origin (for `audit-verify`, `--from-url`); redirecting
  admin gateways are no longer followed. The 3xx diagnostic names the
  redacted redirect target and the remediation hint on stderr.
- Security invariant checker reports repository-wide presence/absence patterns
  for no-store headers, bearer challenges, oracle-safe responses, and
  constant-time comparisons; behavioral tests remain the enforcement evidence.
- Security policy defines fail-open vs fail-closed boundaries
- Vulnerability reporting process documented

## [0.10.0] — 2026-06-30

### Added
- P0–P10 engineering system infrastructure (see Unreleased for details)
- Self-bootstrapping `make harness` target for engineering file generation
- Security invariant checker (10 checks) enforcing no-store headers, bearer challenges,
  oracle-safe error responses, and constant-time comparisons
- Engineering gates GitHub Actions workflow for PR gating

### Changed
- AGENTS.md streamlined to focus on behavior rules and protocol invariants
- CONTRIBUTING.md updated with engineering system references
- .golangci.yml: Added funlen, gocyclo, gocognit linters

### Fixed
- Oracle-leak hardening patterns across OAuth/OIDC token endpoints
- Anti-enumeration patterns (bcrypt dummy hash, uniform error responses)
- Cache-Control: no-store and WWW-Authenticate header presence across 9+ files

### Security
- Security policy defines fail-open vs fail-closed boundaries
- Vulnerability reporting process documented

## [0.9.0] — 2026-06-29

### Added
- Idempotency-Key support for safe retry on `/token` endpoint
- Request/response debug logging middleware
- `WithAdminRateLimit` server option for admin API rate control
- gRPC audit interceptor for admin RPCs
- Production gRPC keepalive, TLS, max message size, and connection timeout configuration
- `/api/v1/status` runtime info endpoint
- Per-IP signup rate limiter via `WithSelfServiceSignupRateLimiter`
- `/me/sessions*` alias routes for self-service portal
- Configurable JWKS body cache with `sync.Map`, ETag, and jitter TTL

### Changed
- JWKS body cache refactored to `sync.Map` with jitter TTL for thundering-herd protection
- Audit events now stamped with deploying server version
- Refresh grace window: concurrent double-submit made idempotent

### Fixed
- DCR: RFC 7592 PUT no longer bypasses `AllowedPKCEMethods` restriction
- DCR: RequirePKCE clients restricted to S256 by default
- Connections: home-realm discovery scoped to request tenant
- Consent: `authorization_details` bound to consent challenge (RFC 9396 §7)
- SCIM: closed two R27 post-fix verify bypass paths
- SCIM: reject empty `displayName` in path-less PATCH replace/add
- SCIM: block `/Bulk` as a recursive bulk operation target
- Admin: publish `KindConnectionChange` on connection CRUD to invalidate peer caches
- Token exchange: enforce RFC 8693 §4.4 `may_act` constraint
- OIDC: destroy server-side SSO session on RP-initiated logout
- WebAuthn: compare `user.Name` not session `UserID` bytes in bearer binding
- OAuth: constant-time comparison for initial access token
- WebAuthn: bind self-service `FinishRegistration` to authenticated bearer
- Token grant: report DPoP `token_type` in refresh, CIBA, and token-exchange responses
- SSO: block deprovisioned users in federated OAuth callback path
- Cmd: gate storage-health report behind `admin.enabled`
- Various security test gaps tightened (R25 T-01 through T-04)

## [0.8.0] — 2026-06-27

### Added
- Self-service registration abuse protection with per-IP rate limiter
- SQLite refresh grace store for concurrent double-submit tolerance
- Password policy SPI with configurable strength enforcement
- Monotonic clock safety for token expiry comparisons
- Email verification for self-service signup
- Per-user max sessions enforcement
- Introspection cache for high-throughput token validation
- KDF cost matching for bcrypt hash comparison
- Device flow HTML verification page with client info, inline login, and scope approval
- WebAuthn discoverable conditional-mediation (passkey autofill) flow
- gRPC admin E2E tests + proto versioning ADR

### Fixed
- Self-service: revoke-all endpoint now correctly destroys all sessions
- Login: `rejectUnverifiedEmail` fails closed on `GetByID` error
- Self-service: revoke-all destroys sessions correctly (test coverage added)
- Self-service: real client IP used in registration gates + correct `Retry-After` ceiling
- Login: nil guard for user provider + close MFA step-up verification bypass
- Wire `rejectUnverifiedEmail` gate (was dead code)
- Security: monotonic-clock-safe comparisons for token expiry
- Device: remove unauthenticated metadata endpoint + thread DPoP binding
- SCIM: preserve `userName` casing on write; `caseExact=false` is a match rule
- Self-service: clone user before mutating and check `ErrNoSuchUser` explicitly
- Config: validate schema version on load
- SSO: sanitize `/readyz` error body for unauthenticated callers
- Defaultimpl: lazy-sweep expired email verification tokens on `Issue`
- Bootstrap: stop persisting `seeded_password` plaintext; clear on upgrade
- Self-service: verify-email Mode A mount, nil guard, and failure audit
- Admin: body-size cap on REST gateway and auth-gate Discovery writes
- SCIM: filter DoS mitigation and case-insensitive `userName` uniqueness
- SCIM: preserve `userName` casing on write
- gRPC admin: redact credential attributes from admin user API responses
- Token grant: enforce DPoP/mTLS sender-constraint continuity on exchange
- SQLite schema version boot gates for all stores
- OIDC: DOM XSS + open redirect in device verification page
- Self-service: cancel stale pending token on concurrent re-registration (EV-F2)
- SSO: TOCTOU + cross-tenant + nil-guard in per-user session eviction
- Self-service: Mode B signup drops password + double-audit + no-fail-audit
- Self-service post-fix verify caught 2 self-regressions (HIGH)
- gRPC: gate AuditWriter and NetPolicy behind adminMW when admin enabled
- JWKS: add configurable debounce interval for tests
- Session: filter expired sessions in `Get/ListByUser` on memory and sqlite
- PAR: enforce RFC 9126 §4 client binding on `request_uri` consume
- SSO client: defend JWKS cache against kid-amplification DoS
- Consent: preserve existing grant scopes on refresh, skip write on store outage

## [0.7.0] — 2026-06-22

### Added
- Self-service signup flow with email verification (Mode A and Mode B)
- Password reset flow for self-service users
- Data export and account erasure self-service endpoints
- Compliance module: GDPR/CCPA/PIPL erasure and export
- OpenID SSF CAEP transmitter and receiver (push-only to affected client)
- `ListByTenant` for tenant-scoped CAEP event delivery

### Fixed
- Login: wire `rejectUnverifiedEmail` gate (was dead code)
- Self-service: corrected `verify-email` Mode A route mounting
- Various gate violation fixes across auth flows

## [0.6.0] — 2026-06-19

### Added
- OpenID Federation 1.0: entity configuration, trust chains, auto-registration, §8 fetch
- CAEP/SSF receiver (fail-closed; jti-replay verified before processing)
- Federation trust-chain validation (fail-closed)
- Auto-registration: pre-registered client wins on conflict

### Changed
- Pre-registered client wins during federation auto-registration
- Trust-chain failure produces byte-identical `invalid_client`

### Security
- CAEP receiver: fail-closed; jti-replay verified
- Federation: anchor keys never fetched from network; all failures → `ErrTrustChainInvalid`
- Client `caep_receiver_endpoint` validated at create/update (never request input)

## [0.5.0] — 2026-06-16

### Added
- SCIM 2.0 provisioning (RFC 7643/7644) with CRUD operations
- Multi-region data residency SPI with governance-mode resolvers
- Region mismatch rejection at token issuance
- `region_not_allowed` / `residency_violation` governance error codes

### Fixed
- SCIM: filter DoS mitigation and case-insensitive uniqueness enforcement
- SCIM: closed multiple bypass paths in PATCH operations
- SCIM: reject empty `displayName` in path-less PATCH replace/add
- Region: write-gate on login, read-gate on access with governance codes

## [0.4.0] — 2026-06-13

### Added
- FAPI 2.0 validator (Inspection/Enforce modes)
- Risk scoring SPI with async behavioral detection
- Anomaly detection framework (off request path, never feeds auth decision)
- JAR fetch and JWE support for request objects
- Pairwise subject identifiers
- mTLS client certificate binding
- Step-up authentication with ACR enforcement
- JTI replay protection store

### Security
- Lockout policy enforcement
- Asymmetric JWS algorithms only (EdDSA/ES256-512/RS256/PS256)
- `alg=none` rejected before signature verification

## [0.3.0] — 2026-06-11

### Added
- OpenID Connect core support: ID Token issuance, Userinfo endpoint, JWKS endpoint
- End-Session endpoint (RP-initiated logout)
- Silent renewal support
- Form Post response mode
- JARM (JWT Secured Authorization Response Mode)
- OIDC discovery document derived from server state
- `at_hash` claim when access token is in response

### Changed
- ID Tokens include `at_hash` when access token is in response
- `aud` claim: unmarshals string or array; marshals single-aud as compact string per OIDC spec

## [0.2.0] — 2026-06-02

### Added
- OAuth 2.0 authorization code grant with PKCE (S256 enforced)
- OAuth 2.0 device authorization grant (RFC 8628)
- OAuth 2.0 token refresh with rotation and family tracking
- OAuth 2.0 PAR (Pushed Authorization Requests, RFC 9126)
- DCR (Dynamic Client Registration, RFC 7591/7592)
- RAR (Rich Authorization Requests, RFC 9396)
- DPoP sender-constrained tokens
- Token exchange (RFC 8693)
- Client credentials grant
- Refresh family rotation with `DeleteFamily` on replay
- Oracle-leak hardening: unknown/expired/consumed/mismatch → `400 invalid_grant`
- Cache-Control: no-store on all credential error responses
- RFC 9207 `iss` parameter on auth response

### Fixed
- Oracle-leak: stale/missing PAR `request_uri` → `invalid_request_uri`
- Refresh family: reuse → `DeleteFamily` → `invalid_grant`
- Session refresh: refuses expired/revoked before extending

## [0.1.0] — 2026-05-17

### Added
- Core SPI interfaces: User, Client, Session, Token, Subject, AuthRequest, AuthResult
- Authenticator SPI with 7 pluggable authenticators (password, TOTP, SMS, email, WebAuthn, federated, passkey)
- WebAuthn authenticator with AAGUID and FIDO MDS support
- Memory stores for all interfaces (UserProvider, ClientStore, SessionManager, TokenIssuer)
- Ed25519/ECDSA/RSA token issuers (each accepts only its own alg)
- Audit module with pluggable sinks (memory, file, SQLite, HTTP)
- Permissions module with roles, menu tree, and wildcard matcher (`user:*` ⊇ `user:read`)
- Deploy artifacts: OpenResty gateway config, Dockerfile, Kubernetes manifests
- Service discovery (memory/etcd) with hostname-beats-CIDR classification
- Tenant resolution middleware with Host→Tenant mapping
- Geo enrichment middleware with CIDR-keyed provider
- Config: layered YAML + env + etcd + flag loader
- gRPC Phase A services: AuditWriter, Authorizer, Discovery
- gRPC Phase B: Network policy control plane (PolicyService, Classifier)
- gRPC Phase C: Admin services (clients, users, tokens, permissions)
- Bootstrap framework: first-run init with distributed lock (file/etcd), snapshot/restore
- Release pinning: Pinner SPI, health probes, auto-rollback
- Command-line: `sso-server` binary with production configuration and offline CLIs
- JWT/JWKS support with configurable signing key rotation and leaderless key aggregation
- RFC 9068 JWT access tokens with all required claims
- Anti-enumeration patterns (bcrypt dummy hash, uniform error responses)
- Cache-Control: no-store and 401 WWW-Authenticate on all credential endpoints
- RFC 9207 `iss` parameter on auth response
- SSO client SDK (local/remote/dev/bootstrap variants)
- Admin middleware: Bearer + admin scope on both HTTP and gRPC transports
- OpenResty gateway integration (JWT verify + request-id + audit + netpolicy)
- Community health files: issue templates, PR template, CODEOWNERS
- Makefile with build, test, lint, ci targets
- CI: GitHub Actions workflow with lint, build, test, Docker

[Unreleased]: https://github.com/yangwb1123/snaplink/compare/v0.10.0...HEAD
[0.10.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.10.0
[0.9.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.9.0
[0.8.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.8.0
[0.7.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.7.0
[0.6.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.6.0
[0.5.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.5.0
[0.4.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.4.0
[0.3.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.3.0
[0.2.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.2.0
[0.1.0]: https://github.com/yangwb1123/snaplink/releases/tag/v0.1.0
