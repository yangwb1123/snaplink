# Wave 5a: two-application / two-tenant reference acceptance

## Goal and product boundary

Compose existing SDK surfaces into a reproducible HTTP-level reference
acceptance scenario: one API-only authorization server, Orders and Reports APIs,
two tenants, four independent confidential BFF/RP registrations. This consumes
existing Browser SSO and tenant/token behavior; it does not implement or claim
ownership of concurrent Browser SSO work.

The driver emulates an external login UI and server-side BFF exchanges. It is
not a browser UI, a separately deployable reference application, the stock
`cmd/sso-server` configuration, or production acceptance. No Go static frontend.
No public endpoint/config/SPI, SQL/schema, dependency, profile or policy changes.

## Ownership and budgets

Cross-server integration belongs in `test/` (`package ssotest`):

- `reference_apps_fixture_test.go`: real in-memory users/password credentials,
  clients, sessions, OAuth stores, tenant/permission stores, signer, AS and two
  RS HTTP servers; deterministic teardown.
- `reference_apps_client_test.go`: bounded HTTP driver, random PKCE/state/nonce,
  form/Basic exchanges, response hygiene and cryptographic claim assertions.
- `reference_apps_test.go`: named E2E positive/negative acceptance scenarios.
- `docs/sso/reference-apps.md`: runnable recipe, trust decisions and limitations.
- Update this tracker and `release-readiness.md`; no unrelated source cleanup.
- Document the existing logout response headers and selected-session boundary in
  `docs/openapi.yaml`; explicitly sync its declared OpenResty deploy copy via
  `python cli.py sdk-drift sync-deploy`, keeping `check` read-only.

No new production packages/directories. The reference tests reproduced a
pre-existing `/logout` cache-header gap: allow only an entry-point call to
`tokenNoStoreHeaders` in `interfaces/sso/server_logout.go` (496 lines before),
with adjacent `interfaces/sso/logout_no_store_test.go` coverage for early errors.
Preserve frozen budgets, exemptions and all unrelated worktree changes.
Apply U1-U9 and O1/O8-O10/S3-S4
as relevant; existing targeted suites retain other protocol coverage.

## Acceptance

1. Two users authenticate through the real stored-password verifier. An OP
   cookie allows the second RP in the same browser to obtain a new code without
   another password verification. All four registrations have independent
   access/refresh credentials, app audiences, scopes, client/tenant bindings and
   RP sessions; state, nonce, ID-token signature and `at_hash` are checked.
2. API guards use the real RS middleware (pinned issuer, audience, asymmetric
   algorithm), then explicitly enforce route tenant, bound client, scope and
   current application permission before returning fixture data. Same-audience
   cross-tenant requests must fail; different-app audience, missing/garbage and
   ID-token-as-access requests fail. Missing scope and revoked roles fail too.
3. Form/Basic code exchange and refresh work. Wrong PKCE/client or consumed/
   unknown code/refresh return ordinary no-store `400 invalid_grant`; no secret
   credentials/tokens/body dumps in diagnostics. Negative attempts use separate
   grants so a destructive consume is not mistaken for successful isolation.
4. Revoke affects the correct app credential; inactive introspection is exactly
   `{active:false}`. Online RS rejects on its next call; offline signature-only
   validation can still accept a non-expired revoked JWT. No offline-immediate-
   revocation claim, timer-based sleeps or relaxed gate.
5. Logout revokes the selected bearer/RP session, prevents its refresh and
   clears the OP cookie. Other independently authorized RP sessions are not
   claimed globally revoked without backchannel/session fan-out configuration.
6. Single-process signer rotation retains old-key verification and lets a JWKS
   consumer discover the new kid. Use bounded observation of the existing
   forced-fetch debounce, not lowered defaults or fixed-sleep assumptions.
   It is not key distribution/recovery or HA.

## Trust decisions and explicit non-goals

The common OP authenticates identity; client tenant bindings and API policy
isolate application data. Browser identity is not proof of tenant membership.
No JIT-membership, tenant-onboarding or organization-invitation claim is made.
BFF secrets stay on the emulated server side; fixture secrets are not deployment
credentials. Same-origin cookie jars use ephemeral loopback HTTP for tests only.

Two RS modes are explicit routes, not a fallback: an introspection outage must
fail closed, never switch silently to offline validation. Permissions are real
in-memory provider lookups, not a remote authorization-service availability test.

Remaining Wave 5: real external UI/browser/CSRF callback acceptance; independently
configured stock deployments; durable/shared multi-process state, key rotation
across replicas, backup/restore, failure/load/P99/RPO/RTO, native ARM/Mac and
protected publication/certification. Existing OCI evidence remains for older bytes.

## Verification

After every Go edit: `go build ./... && go vet ./...`, then committed
`TestMaintainability_|TestArchitecture_` gates. Run the new E2E cases with race
repetition, relevant existing browser/tenant/revoke tests, E2E and complete
`make ci` with isolated real PostgreSQL, followed by independent read-only review.
Log evidence under ignored `dist/release-readiness/reference-apps/`. Source
acceptance is not container runtime, public publication or product certification.

## Execution result

- All six reference scenarios passed under `-race -count=10`; selected existing
  Browser SSO/tenant/client/introspection/logout cases passed under race3.
- The initial reference logout case and adjacent success/early-error tests
  reproduced missing cache headers. The one-line existing-handler fix passed
  adjacent race10; the production file is 497 lines, without exemptions.
- A review-identified polling cancellation gap was fixed by sharing one bounded
  context across the JWKS lookup/HTTP request and polling select. Consumer
  debounce, token TTLs, protocol policies and test thresholds were not lowered.
- Final E2E and complete real-PostgreSQL-backed `make ci` passed; the local
  fixture used PostgreSQL16 / 300 connections and Go package parallelism8.
  Those are local test resources, not remote CI-default or capacity acceptance.
- Logout OpenAPI headers/selected-session semantics and its declared deploy
  copy were updated; explicit sync followed by read-only SDK drift check
  passed `regen 2/2, deploy 3/3`. No generated TypeScript/Python client changed.
- Independent source and contract closure reviews reported no remaining scoped
  P0/P1/P2. These were read-only reviews, not independent test execution,
  authenticated provenance or product/security certification.
- Logs/reviews: `dist/release-readiness/reference-apps/`; usage and limitations:
  `docs/sso/reference-apps.md`. Wave 5 remains incomplete beyond this local SDK
  slice; no UI, multi-process deployment, image rebuild, publication or commit.
