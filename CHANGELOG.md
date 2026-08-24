# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- SDK release-readiness version gate: `python cli.py sdk-surface versions`
  reads only the four fixed TypeScript, Python, Rust and PHP manifests,
  validates SemVer 2.0.0, checks the TypeScript package-lock root, and reports
  a stable per-package verdict. `sdk-surface check` and `make ci` run the same
  gate; no version is changed automatically and versioned package publication
  remains an external registry-workflow boundary.
- Executable SDK-surface compatibility checking: `python cli.py sdk-surface diff`
  compares an explicit local baseline and reports added/removed/relocated
  operationIds deterministically. A `--baseline-ref` reads the registry and
  `docs/openapi.yaml` from the same local ref without fetching; a
  `--baseline-file` remains registry-only unless explicitly paired with
  `--baseline-openapi-file`. The bounded `components.schemas` diff rejects
  schema/property removals, new required properties, `$ref`/type/format changes,
  `additionalProperties` tightening, enum removals, and nested/items breaking
  changes; optional properties, required removals, and enum additions are
  additive. Description/title/examples/default changes are ignored, while
  composition and unsupported keyword changes are conservatively breaking.
  Bad baselines fail closed, there is no override flag or automatic version
  update, and this is not a complete vendor-level OpenAPI diff. Versioned
  package publication remains an external boundary.
- Public self-service preferences contract: `GET`/`PUT /me/preferences` now
  has an OpenAPI schema and generated TypeScript/Python SDK methods while
  retaining its allowlisted, default-deny attribute projection; the server
  remains API-only and serves no frontend assets.
- Lifecycle-managed ReBAC business check route: the stock `/authz/check`
  capability now uses a fixed route slot with match-time generation leases,
  readiness, graceful disable/activate, bounded `rebac_lifecycle_transition`
  audit events and shutdown draining.
- Typed external-module supervisor SDK under
  `platform/lifecycle/modules`: digest-pinned direct executable launch,
  Unix/TLS version and capability handshake, token authentication, optional
  detached Ed25519 artifact verification, SPIFFE-aware mTLS, readiness,
  heartbeat, quiesce/shutdown lifecycle and bounded audit-batch delivery.
- Stock `sso-server` audit-worker admission: `audit.external_worker` now
  manages one lifecycle-supervised audit-batch worker, checks signed local
  release provenance or remote mTLS/SPIFFE identity, contributes readiness and
  graceful shutdown, and emits bounded lifecycle audit events.
- Lifecycle-managed stock-server webhook exporter: `webhooks.enabled` now
  wires a precompiled audit tap with generation leases, readiness, graceful
  drain, shared subscription/dead-letter stores, safe SIGHUP delivery-policy
  replacement, and bounded `webhook_lifecycle_transition` audit events.
- Release workflow provenance attestations: after GoReleaser publishes the
  archive checksum set, GitHub Artifact Attestations emits signed SLSA build
  provenance for every archive subject listed in `dist/checksums.txt`.
- Optional configuration-baseline canary apply (`?canary=true&window=60s`):
  injected storage-health probes confirm a bounded observation window or
  atomically roll back to the predecessor; Memory/SQLite retain lifecycle
  state, restart recovery is fail-safe, and lifecycle audit events carry only
  redacted-safe identifiers. See `docs/design/config-canary-apply.md`.
- Opt-in per-client redirect-URI patterns (`redirect_uri_patterns`) for static
  configuration and the Snaplink DCR extension. Patterns are HTTPS-only,
  concrete-host, single interior path-segment wildcards validated by one shared
  matcher; exact `redirect_uris` behavior remains unchanged. SQLite migration v8
  and PostgreSQL schema v6 persist the field, and DCR POST/GET/PUT round-trip it.
- Per-client ID-token signing algorithm (`id_token_signed_response_alg`,
  OIDC Core §3.1.3.1 / RFC 7591 §2; design
  `docs/design/per-client-id-token-alg.md`): `core.Client.IDTokenSignedResponseAlg`
  names the JWS algorithm the AS signs a given RP's ID Tokens with, selected
  via the new SDK option `sso.WithIDTokenIssuerAlg(alg, issuer)` (whitelisted to
  `security.AsymmetricJWSAlgs` — EdDSA / ES256-512 / RS256 / PS256; `none` and
  anything unwired panic at construction). Resolution in
  `idTokenIssuerForClient` prefers the per-client alg, then falls back to the
  unchanged per-tenant/shared issuer path (byte-identical default when no
  client sets the field). DCR accepts and stores the field and rejects an
  unwired alg with 400 `invalid_client_metadata` (validated against the same
  set discovery advertises); static config gains `clients[].id_token_signed_response_alg`
  (boot-validated against `keys.signing.alg`); discovery's
  `id_token_signing_alg_values_supported` is the union of the default issuer's
  algs and the wired per-alg map. Fail-closed at issuance: an unwired alg
  omits id_token rather than sign with another key. Persisted in sqlite
  (migration v7) + postgres (schema v5). Product-level FAPI 2.0 conformance
  unblock per `docs/campaigns/reports/b11-fapi-conformance.md` / the archived
  `test/oidc-conformance/results/39ecdf7a-fapi/BLOCKER.md`: an RS256-only
  login client can coexist with ES256/PS256 FAPI clients on one issuer.
- Config-facing per-client id_token signing keys
  (`keys.id_token_algs`, design
  `docs/design/per-client-id-token-alg.md` Decision 1 + 2): the
  `sso-server` binary can now wire ADDITIONAL dedicated id_token signing
  issuers (the config form of `sso.WithIDTokenIssuerAlg`) — each entry
  (`alg` required eddsa/es256/rs256/ps256, optional `key_file`/`external`)
  serves clients that declare `id_token_signed_response_alg` with THAT
  algorithm while `keys.signing.alg` keeps signing everything else. Boot
  gate rejects an alg equal to the primary or a duplicate entry; the
  issuer's public key lands in the aggregated `/.well-known/jwks.json` and
  discovery advertises the union. Empty (default) = byte-identical
  behavior. This is what operationalizes the B12-1 FAPI unblock on the
  sso-server binary: `test/oidc-conformance/config-fapi.yaml` wires
  `id_token_algs: [{alg: rs256}]` so the suite's RS256 login client
  coexists with the ES256 FAPI clients.
- Always-on structured access log (`interfaces/middleware.AccessLogger`, design
  `docs/design/middleware-observability-unified.md` Decision 1 + 2): one INFO
  `"access"` record per request with a fixed low-cardinality field set
  (`method`, `path` — never `RawQuery`, `status` — default 200, `duration_ms`,
  `client_ip` — canonical `peertrust.ClientIP` with `audit.ClientIP` delegating
  to the one shared implementation, `request_id`, `trace_id`). `BodyLogPolicy`
  controls OPTIONAL request/response body capture behind an exact-path
  allowlist, a per-deployment `sample_rate`, a per-field byte cap, and a
  redaction vocabulary (exact-match + substring heuristic, replacement literal
  exactly `[redacted]`); the zero value never captures bodies, so credentials
  stay structurally impossible to log. The middleware sits inside trusted
  proxies (validated `client_ip`) and outside rate limiting (429 rejections
  leave access evidence); probes (`/livez`, `/readyz`, `/metrics`) bypass via
  the probe mux. SDK default is off (`sso.WithAccessLogging`); `sso-server`
  enables it by default via the new `logging.access_log.*` config block
  (tri-state `enabled`, body keys map 1:1 onto the policy, loud boot
  validation, not hot-reloadable). `sso.WithRequestLogging(bool)` is replaced
  by the policy signature — the old name is kept as a deprecated alias and
  `BodyLogPolicy{AllowAllPaths: true}` reproduces `logBodies=true`; the DEBUG
  `middleware.RequestLogger` and its `debugRequestLogging` fields are deleted.
- OIDC-conformance harness FAPI variant (`test/oidc-conformance/`):
  `config-fapi.yaml` (FAPI 2.0 Security Profile, inspection mode, PAR
  enabled, ES256 signing) plus `--fapi` in `run-headless.sh`
  (plan `fapi2-security-profile-final-test-plan`, variant plain_fapi /
  private_key_jwt / DPoP / unsigned-PAR / plain-response, module
  `fapi2-security-profile-final-happy-flow`) and PAR-aware logins in
  `drive_test.py`. The default basic topology is unchanged
  (`CONFORMANCE_CONFIG` defaults to `config.yaml`; verified via
  `docker compose --env-file config.env config`). The first FAPI run is
  archived under `results/39ecdf7a-fapi/` and is **blocked at the suite's
  own login**: the pinned OIDF suite validates its login ID token with an
  RS256-only decoder (Spring `OidcIdTokenDecoderFactory` default) while
  the FAPI 2.0 SP requires PS256/ES256/EdDSA — no FAPI module has run yet;
  see `docs/sso/oidc-conformance.md` §2 and the archived `BLOCKER.md`.
- `sso-operator` apply mode for `SSOConfigDrift` (nested module
  `cmd/sso-operator`): a CR that opts in via `spec.apply.enabled` AND
  carries the one-shot approval annotation
  (`sso.snaplink.io/apply-approve: "true"`) AND has a non-empty diff gets
  exactly one `POST .../config/apply?approve=true` per reconcile-approval
  pair — cluster A's already-server-redacted running snapshot, its
  canonical sha256 digest (byte-identical to `configaudit.Digest`, pinned
  by a known-answer test), and the mandatory `spec.apply.reason`. The
  outcome lands in `status.apply` (state applied/conflict/rejected/failed,
  lastAttemptAt, versionID, digest, message) and coexists with the drift
  fields: an apply failure is fail-open (recorded, never suppresses the
  drift report) and keeps the approval pending for the 30s retry;
  success consumes the annotation (at most one apply per approval — no
  auto-remediation). Report-only CRs are byte-identical to before, and the
  CRD gains the `apply` schema block + a CEL reason-when-enabled rule.
  Explicit CAS rollback is documented separately below. Design:
  `docs/design/operator-config-apply.md`.
- Explicit `sso-operator` rollback mode for `SSOConfigDrift`: an enabled
  rollback spec, non-empty reason, expected current version, and one-shot
  `sso.snaplink.io/rollback-approve` annotation are required. The controller
  sends the guarded rollback request, records `status.rollback`, consumes the
  approval only on success, and retains it for short-retry failures. Apply
  and rollback approvals are mutually exclusive; stale versions return
  `config_apply_conflict` without changing the baseline. Design:
  `docs/design/operator-config-rollback.md`.
- Config apply mode (`POST /api/v1/admin/config/apply` + `.../rollback`, admin:write):
  the declared peer-config baseline write path promoting the deferred-backlog
  "Declarative multi-cluster configuration governance" Partial boundary.
  An operator applies a peer cluster's config snapshot as this cluster's new
  applied baseline, verified against its sha256 digest (split-brain guard —
  mismatch is 409 `config_apply_conflict`), gated by mandatory `?approve=true`
  (400 `config_apply_approval_required` otherwise) and a mandatory `reason`.
  The write is transactional (`configaudit.Store.Apply`/`Rollback` — baseline
  + `config_history` entry in one write, sqlite via a new `config_applied`
  table, memory in-process), stores ONLY redacted snapshots, retains every
  version for rollback, and emits `admin_config_applied`/
  `admin_config_rolled_back` audit events (metadata only: apply_id,
  peer_digest, prev_id — never snapshot content), both classified in the
  SOC2 report's CC6.3 bucket. After apply, `GET .../config/applied` serves
  the new baseline and `.../config/diff` diffs against it; the running view
  and every diff-only endpoint are byte-identical until the first apply, and
  the routes are unmounted (404) unless both `WithConfigSnapshots` and
  `WithConfigAuditStore` are wired. Design:
  `docs/design/config-apply-mode.md`.
- User lifecycle transitions now emit OpenID CAEP/RISC Security Event Tokens
  through the existing SSF transmitter: `admin_user_lifecycle_changed` maps to
  `risc/account-disabled` + `caep/session-revoked` for non-active target states
  and `risc/account-enabled` on reactivation, pushed async + best-effort to the
  affected tenant's opted-in clients (receiver endpoints only from registered
  client metadata; tenant events query only that tenant) — the standardized
  event channel for resource servers that validate JWTs fully offline. Wiring
  is `caep.WithTenantUserStore` on the transmitter (nil ⇒ lifecycle events
  resolve to no receivers; the stock binary does not wire tenant membership),
  the CAEP receive side is untouched, and delivery failures stay fail-open
  (`caep_broadcast_failed`). Design: `docs/design/lifecycle-caep-events.md`.
- `sso-ctl` audit tooling durable-store read paths and live-API export source:
  `audit-verify --dsn <sqlite|postgres>` and `audit-export --dsn <postgres>` read
  the audit store offline through a shared read-only accessor
  (`cmd/auditstore`), which classifies a DSN by scheme
  (`postgres://`/`postgresql://` vs a sqlite path or `file:` URI), pages
  newest-first and reverses into chain order, and never migrates: sqlite opens
  via `auditsqlite.OpenReadOnly` (fail-closed `checkSchemaCurrent`), postgres
  via a new non-migrating constructor `postgres.OpenAuditReadOnly` (fail-closed
  `schema_migrations_audit` version check; operators enforce server-side
  read-only with a read-only role — there is no `?mode=ro` equivalent).
  `audit-export --from-url <base> --bearer <token>` exports over the live
  `/api/v1/audit/events` API through a `QueryPager` adapter (bearer-gated, no
  redirects, non-2xx diagnostics name the offset), shipping the previously
  documented planned follow-up; `--timeout-sec` applies to that mode.
  Verification cores are unchanged (`audit.VerifyChain` / `VerifyChainSegment`
  / `VerifyChainAgainstCheckpoint`, `BuildExportBundle`); a store whose schema
  version does not match the binary is reported (exit 1), never migrated.
  End-to-end acceptance covers a stock postgres-backed server (bundle
  `HeadHash` == store chain head, `--verify` 0, byte-tamper 1) and the URL leg
  (advertised `/api/v1/audit/events` never 404s; no/weak bearer → 401;
  `--from-url` without `--bearer` → exit 2).
- Prototype/minimal physical package extraction: the two small editions now
  build from dedicated composition roots (`cmd/sso-prototype` and
  `cmd/sso-minimal`) that share edition-generic composition code in
  `internal/composition`, instead of both compiling the same `cmd/sso-minimal`
  package. The minimal-only OIDC surface (discovery, ID Token, UserInfo,
  logout, tracing wiring) is compiled only into the minimal binary — the
  prototype root contains no OIDC surface code. The prototype profile selects
  `./cmd/sso-prototype`; `ops/build/profile-isolation.json` splits the former
  `small` row into per-edition `prototype`/`minimal` rows, and
  `python cli.py profiles evidence` now proves each binary links only its own
  cmd root (prototype never links `cmd/sso-minimal` and vice versa) while
  keeping the shared `interfaces/sso` SDK boundary documented.
- ssoext host-API registrars for the LDAP/Kerberos/RADIUS authenticator
  families: `interfaces/ssoext` now exposes `LDAPAuthenticatorRegistry` /
  `KerberosHandlerRegistry` / `RADIUSAuthenticatorRegistry` (plus the
  `Register*`/`Lookup*`/`Registered*` functions) on the standard
  `platform/registry/typed` machinery, with a per-family `*ServerDeps` bundle of
  stdlib + intra-repo types only — no go-ldap/gokrb5/layeh dependency enters
  the core module's go.mod. The nested modules each embed their `ssoext`
  Deps bundle (`ldapauth.Deps` / `kerberosauth.Deps` / `radiusauth.Deps`) and
  expose a `Build` factory adaptation, so a forked binary registers a
  name-addressed factory at boot and its own composition looks it up —
  process-local, panic-on-duplicate, fail-closed on an unregistered name,
  matching the SAML registry contract. Stock `cmd` wiring is unchanged
  (no ldap/kerberos/radius config sections; those surfaces remain
  fork-binary integrations).
- ssoext host-API registrar for the KMS external-signer family: `interfaces/ssoext`
  now exposes `ExternalSignerRegistry` / `RegisterExternalSigner` /
  `LookupExternalSigner` / `RegisteredExternalSigners` plus the
  `ExternalSignerDeps` bundle (stdlib + intra-repo types only — no vendor KMS
  SDK enters the core module's go.mod) on the standard `platform/registry/typed`
  machinery, completing the nested-module migration declared in
  `docs/deferred-backlog.md`. The four nested modules
  (`infrastructure/kms/{awskms,gcpkms,azurekeyvault,pkcs11}`) each add a
  `Build` adapter embedding `ssoext.ExternalSignerDeps`, mirroring the
  ldap/radius adapters, so a forked binary registers a name-addressed factory
  whose closure holds the vendor SDK client. `keys.signing.external` now
  resolves through the canonical `ssoext` registry;
  `serverbuildsign`'s `ExternalSignerFactory` / `ExternalSignerRegistry` /
  `RegisterExternalSigner` are kept as delegating aliases so existing fork
  binaries compile and behave identically (lookup error text, panic
  discipline, and the health/metrics/readiness wrapping are unchanged).
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
- FAPI 2.0 conformance harness progress (`test/oidc-conformance`): the
  `--fapi` run now registers the suite login client via DCR with
  `id_token_signed_response_alg: RS256` (served by the dedicated
  `keys.id_token_algs` RS256 key in `config-fapi.yaml`), unblocking the
  suite's own admin login (Spring's hard-coded-RS256
  `OidcIdTokenDecoderFactory`), and the FAPI plan-variant no longer repeats
  the plan-intrinsic `fapi_request_method`/`fapi_response_mode` keys (the
  suite rejects plans that set them twice). The
  `fapi2-security-profile-final-happy-flow` module now executes — its first
  run ends at the suite's static-client step (12 SUCCESS + 1 FAILURE); see
  `docs/campaigns/reports/b12-fapi-conformance.md` and the archived
  `results/<commit>-fapi/BLOCKER.md`.
- Unified OTel correlation (design `docs/design/middleware-observability-unified.md`
  Decision 7 + 8): `middleware.Correlation` is now the ONE middleware tying a
  request to a trace and a request ID — it wraps the otelhttp span and stamps
  `X-Trace-Id`/`X-Request-Id`/`Traceparent` response headers, the request
  context `trace_id` (`core.WithTraceID`), and a preserved-or-generated 32-hex
  `X-Request-Id`. The legacy `Tracing`/`RequestID` middleware and its
  traceparent parse/format/rewrite, `WithTracingMiddleware`/
  `WithRequestIDMiddleware`, the `requestIDMW` field, and the router-level
  `Use(TracingMiddleware())` install are deleted; `WithTracing(operation)` is
  the single switch (span tree + audit correlation + trace headers + error-body
  `trace_id`). Audit events are span-first: `audit.EventFromRequest` reads the
  live span's `TraceID`/`SpanID`/`ParentSpanID` (from the span's actual
  parent, via the new `platform/tracing.ParentSpanID` seam) and falls back to
  the incoming `Traceparent` header only for callers outside the middleware
  chain; the legacy `X-Parent-Span-Id` header is removed. The access log and
  audit events now share the span's trace id by identity — one correlation
  source. Deliberate behavior change (documented in the design's "What could
  break" item 1): with no OTLP endpoint configured the no-op provider yields
  invalid span contexts, so `X-Trace-Id`/`Traceparent` and audit/access-log
  `trace_id` are empty (the honest no-tracing state); `X-Request-Id` and audit
  `RequestID` keep working. `sso-server` logs a boot-time note when tracing is
  wired without an endpoint. The login-anomaly dispatch uses the same
  span-first trace id (`requestTraceID`).
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
