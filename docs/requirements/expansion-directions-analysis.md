# Expansion Directions Analysis

> **Author:** Architecture & Product Review
> **Date:** 2026-07-10
> **Scope:** Full codebase scan (2227 `.go` files, ~1300+ packages)
> **Goal:** Identify 5 high-value expansion directions beyond current feature set

---

## Executive Summary

The project is a remarkably comprehensive OAuth 2.0 / OIDC SSO platform with
~90 `WithXxx` options, covering virtually every major RFC (authorization code,
PKCE, DPoP, mTLS, JARM, JAR, CIBA, RAR, PAR, token-exchange, transaction
tokens, device flow, FAPI 2.0, and OpenID Federation 1.0). It ships with four
SPA surfaces (hosted login, admin console, self-service portal, developer
portal), multiple storage backends (memory, SQLite, Postgres, Redis, etcd), and
production-grade observability (Prometheus metrics, OpenTelemetry tracing,
audit with Merkle-chain verification).

The following five directions represent the highest-leverage expansion areas
identified after a comprehensive gap analysis.

---

## Direction 1: Passkeys & Passwordless-First Authentication

### What exists today

WebAuthn/passkeys are supported as an **authenticator option** — users can
register a passkey via `/webauthn/registration/*` and use it for login via
`provider=webauthn`. Conditional mediation is wired
(`authenticators/webauthn/conditional_login.go`), WebAuthn attestation
policy is configurable with MDS trust anchors, and backends exist for both
credentials (memory, SQLite, Postgres) and ceremony sessions (memory, SQLite,
Redis, SQLite). Passwordless-primary-only mode is supported per client
(`Client.AllowPasswordlessOnly`).

### The gap

Passkeys are treated as "another authenticator" when the industry is moving
toward **passkey-first as the primary paradigm**. The current UX requires a
user to know they should select `provider=webauthn` — there is no automatic
discovery of available passkeys, no silent platform mediation, and no upgrade
path from password+2FA to passkeys.

### What to build

| Component | Rationale |
|---|---|
| **Passkey-first login UI** — Auto-discover available credentials via conditional mediation (`mediation=conditional`), present passkey autofill as the default, fall back to password only when no passkey is available | Users should not need to know what "WebAuthn" means; the browser/platform should negotiate silently |
| **Passkey upgrade journey** — After successful password+MFA login, prompt the user to create a passkey and gradually deprecate their password | Reduces password dependency over time; aligns with OAuth 2.1 / passwordless industry trend |
| **Credential manager API** — REST endpoints to list, rename, and delete passkeys from the user's account, integrated into the self-service portal | Users need visibility and control over their registered authenticators |
| **Hybrid / cross-device authentication** — Support for CA (Cross-Device Authentication) flows so a user can authenticate on a new device using a passkey on their phone via QR code / Bluetooth | Critical for desktop-first deployments; the current spec is FIDO2 CTAP 2.2 hybrid |
| **Platform attestation & UV guide** — First-class support for Apple's App Attest, Android's Key Attestation, and TPM-based platform credentials with user-verification metadata surfaced in audit | Enables high-assurance authentication for enterprise scenarios |
| **Recovery codes → passkey re-registration flow** — When a user loses all passkeys, offer a streamlined recovery using pre-generated codes, then guide them to register new passkeys | Closing the gap between passwordless security and account recoverability |

### Edge cases to handle

- **Multiple passkeys per platform** — A user may have 3 passkeys on the same
  device (iCloud Keychain, 1Password, Chrome profile). The platform mediator
  presents a chooser; the server must handle all of them gracefully and let
  the user manage duplicates.
- **Sync lag across devices** — A passkey registered on the user's phone may
  take seconds to sync to their laptop (iCloud Keychain, Google Password
  Manager). The server should handle the credential-not-found error with a
  helpful "try another method or wait for sync" message.
- **Attestation privacy** — Enterprise deployments may require attesting the
  authenticator model (e.g., "this is a TPM-backed passkey, not a software
  one") while consumer deployments should minimize privacy exposure. The
  attestation policy framework must distinguish these.
- **Recovery race** — If a user recovers via email and immediately registers
  a new passkey, the old (lost) passkey becomes orphaned. Policy needed:
  automatic orphan detection and periodic cleanup.

### Performance considerations

- Sessionless verification: passkey authentication should not require a
  server-side session for the ceremony; the WebAuthn response is self-contained.
- Credential enumeration: the `allowCredentials` list is optional for passkey
  discovery, but when provided, should not reveal which users have which
  credentials (oracle-leak: respond identically whether the credential exists
  or not).

---

## Direction 2: Organization & Workspace Management Layer

### What exists today

Multi-tenancy is well-established via `domains/tenant/` (SQLite, Postgres,
memory backends). Tenants have isolation boundaries, data residency regions,
collaboration stores, client-gate policies, and tenant-level quotas. The admin
API supports tenant CRUD. Cross-tenant collaboration is wired
(`domains/identitylink/`). SCIM 2.0 provisioning exists for inbound and
outbound user provisioning.

### The gap

The tenant model is **isolation-only** — it separates data but provides no
collaborative workspace features. There is no organization hierarchy
(departments, teams), no membership management with tiered roles
(owner/admin/member/guest), no self-service org onboarding (sign up your
company), and no B2B enterprise portal where org admins configure their own
SSO settings. A company adopting the platform for workforce identity currently
must build all org semantics on top.

### What to build

| Component | Rationale |
|---|---|
| **Org membership & invitation engine** — Accept/reject invitations, role assignment (owner/admin/member/billing/auditor), bulk invite with CSV upload, expiration of pending invitations | Foundation for any enterprise deployment |
| **Self-service org admin console** — A dedicated SPA where org admins can manage members, view activity logs, configure SSO settings, set security policies, and view usage/billing | Closes the gap between "API-only admin" and what enterprise buyers expect |
| **Just-in-Time (JIT) provisioning** — On first SSO login by a user from a managed email domain, auto-provision their org membership with default role and initial group assignments | Reduces setup friction for B2B customers |
| **Department & team hierarchy** — Nested org units with inherited policies (e.g., "Engineering" inherits "require MFA" from the parent org, plus "require passkey" locally) | Enables large-enterprise deployments with fine-grained policy control |
| **Cross-org B2B federation gateway** — Org A (an enterprise) grants Org B (a partner) limited access to a subset of applications; support for `id_token` claims scoped to the B2B relationship | Opens the platform's total addressable market to partner/B2B scenarios |
| **Audit trail per-org** — Separate audit log scoped to the org's activity, visible to org admins without granting them global admin privileges | Compliance requirement for SOC 2, ISO 27001, and GDPR |

### Edge cases to handle

- **Orphaned org on last-admin-removal** — The existing `last_org_admin`
  protection prevents removing the last admin, but what if the last admin
  deletes their own user account? Need a fallback (super-admin escalation,
  grace period with email notification).
- **Domain collision** — Two orgs claim the same email domain
  (`@acmecorp.com`). The server must have a domain verification flow (DNS
  TXT record) and a dispute resolution process.
- **Org suspension cascade** — Suspending an org should: (1) terminate all
  active sessions (via cluster bus), (2) disallow new logins, (3) revoke all
  tokens (cross-replica revocation), (4) not delete data (billing dispute
  protection).
- **Invitation expiry vs. quota** — Expired invitations still count against
  the org's member quota until cleaned up; a periodic sweeper should reclaim
  expired invitations.

### Performance considerations

- **Org-scoped cache invalidation** — When org policies change, only sessions
  for that org's members need cache invalidation, not the entire server.
- **Bulk member listing** — An org with 50,000 members needs cursor-based
  pagination (not page/offset) to avoid performance cliffs under concurrent
  writes.

---

## Direction 3: Real-Time Risk-Based Session Intelligence

### What exists today

Token anomaly detection (`domains/tokenanomaly/`) records anomalous usage
patterns. Conditional access policies (`domains/conditionalaccess/`) evaluate
device fingerprint, geo-location, and risk at login time. Token usage recording
(`domains/tokenusage/`) tracks how tokens are used. Session hub
(`platform/lifecycle/sessionhub/`) provides session coordination. Trust scoring
(`shared/trust/`) provides composable geo/IP/device/behavior scorers. The
anomaly runner (`domains/anomaly/runner.go`) detects brute force, impossible
travel, velocity, and new-baseline deviations.

### The gap

These pieces exist but are **reactive and disconnected**:

- Risk is evaluated **at login only** — there is no mid-session re-evaluation
  (a session that starts from a trusted IP and then exhibits anomalous
  behavior receives no step-up challenge).
- Anomaly detection runs **off the request path** (async) and there is no
  feedback loop into conditional access enforcement (the detectors emit
  events but no policy engine acts on them).
- There is **no user-facing session intelligence dashboard** — a user cannot
  see their active sessions, login history, device trust scores, or risk
  events. This is both a UX gap and a security gap (users can't self-remediate
  by terminating a suspicious session).
- Session trust decay (`shared/trust/decay.go`) exists but has no automated
  trigger to step-up auth mid-session when trust falls below threshold.

### What to build

| Component | Rationale |
|---|---|
| **Mid-session risk re-evaluation engine** — A background evaluator that periodically recomputes trust scores for active sessions and triggers step-up auth, session termination, or admin alert when risk crosses configurable thresholds | Closes the "evaluate at login only" gap; enables continuous verification |
| **User session dashboard** — A `/me/sessions` SPA view showing active sessions with device info, created-at, last-used, IP/location, trust score, and a "terminate" button | Empowers users to self-remediate; reduces support burden |
| **Risk event feed** — Real-time SSE stream of risk events (new device login, unusual location, impossible travel, credential stuffing attempt) pushed to the self-service portal and optionally to admin console | Both users and admins gain visibility into suspicious activity |
| **Automated session termination on risk** — When a risk score drops below configurable floor, issue a cluster-wide session revocation for that session. User must re-authenticate with step-up (MFA or passkey). | Prevents attacker from lingering in a compromised session |
| **Anomaly → conditional-access feedback loop** — An anomaly signal (e.g., "velocity exceeded") should feed into the conditional access policy evaluator so a CAP rule can say `if anomaly.velocity then require_mfa` | Closes the disconnect between async detectors and synchronous enforcement |
| **Risk-based auth step-up via wire protocol** — OAuth 2.0 step-up auth (RFC 9470) is currently a resource-server helper only. Extend it to the wire protocol so an RP can request step-up mid-session and the AS issues a fresh token with elevated `acr`. | Enables Relying Parties to integrate continuous verification into their own session model |

### Edge cases to handle

- **Trust score oscillation** — If a user is traveling, their geo-location
  changes every few hours. The trust score should incorporate "travel mode"
  (known itinerary, time-zone-appropriate locations) rather than flip-flopping
  between trusted and suspicious.
- **Concurrent session evaluation race** — If a user logs in on a new device
  at the exact moment the background evaluator marks their existing session as
  risky, both actions should succeed without double-termination.
- **Privacy considerations** — Detailed location data, device fingerprints,
  and behavioral profiles should be PII-scoped (the data map in
  `protocols/compliance/datamap.go` must cover these). Users must be able to
  request erasure of their behavioral profile.
- **False positive rate** — An overly aggressive evaluator causes user
  friction. Every automated action (step-up, termination, admin alert) must
  have a configurable threshold and a "dry run" audit-only mode.

### Performance considerations

- **Scoring at scale** — Re-evaluating trust for 1M sessions must not scan all
  sessions on every tick. Use a tiered approach: sessions with a trust score
  above a high watermark are checked less frequently.
- **Event volume** — The SSE event feed must be bounded (last N events per
  user, not infinite history). Use pagination for historical review and a
  sliding window for real-time.

---

## Direction 4: Identity Verification & Trust Elevation

### What exists today

The project has no identity verification capabilities. There is no KYC
(Know Your Customer), no ID document verification, no liveness detection,
no identity assurance levels (IAL), and no verifiable credential issuance.

Password health checking exists (`infrastructure/defaultimpl/defaultrisk/`)
via HIBP and dictionary checks. Email verification exists
(`protocols/selfservice/verify_email.go`). Phone verification exists
(`domains/authenticators/phone.go`). These are "possession proofs" (you have
access to the email/phone) but not "identity proofing" (you are who you
claim to be).

### The gap

For many use cases — regulated industries (finance, healthcare, government),
high-value transactions, age-restricted services, or marketplace platforms —
knowing that a user controls an email address is insufficient. The operator
must verify the user's real-world identity. Currently, an operator adopting
this platform must build all identity verification from scratch.

### What to build

| Component | Rationale |
|---|---|
| **Identity verification SPI** — A `shared/spi/identity_verification.go` interface with methods `StartVerification(subject, level)` and `CheckVerification(subject, referenceID)`. Model the result as `VerifiedIdentity{GivenName, FamilyName, BirthDate, NationalID, IAL, VerifiedAt}`. | Clean abstraction decoupled from any provider (Persona, Onfido, Veriff, Stripe Identity, etc.) |
| **IAL enforcement in conditional access** — Extend the CAP engine to allow rules like `if required_ial > user.current_ial then route_to_verification`. Verifiers can check `acr` or a dedicated `ial` claim. | Allows applications to require identity verification for sensitive operations |
| **Verification status in self-service portal** — Show the user their current IAL, what documents they've uploaded, the verification status, and a "start verification" flow. | Transparent UX that builds trust and reduces support tickets |
| **Admin identity review dashboard** — A queue for manual review of edge-case verifications (blurry documents, mismatched names, suspected fraud). Support for approve/reject with reason. | Manual fallback for automated verification failures (regulatory requirement) |
| **Verifiable credential issuance** — After identity proofing, issue a W3C Verifiable Credential (VC) as an `id_token` extension or as a separate signed JWT that the user can present to other services | Enables portable identity — the user is verified once and can reuse proof across multiple relying parties |
| **Age verification** — A minimal subset of identity verification: only verify `birth_date >= required_minimum_age`, without collecting full PII. Support age-calculation-only providers. | Covers a common use case (age-gated services) without the full KYC overhead |
| **Step-up verification** — A user with IAL 1 (email verified) who needs IAL 2 (document verified) to perform a sensitive action should be routed through the verification flow automatically when they attempt that action. | Friction only when needed; aligns with progressive identity proofing |

### Edge cases to handle

- **Verification data retention** — ID document images are highly sensitive PII.
  Must support automatic deletion after verification (retain only the assurance
  level + verification date) with compliance attestation.
- **Verification expiry** — A driver's license expires. Should the IAL degrade
  after the document's expiry date? (Requires storing the document expiry.)
- **Multiple verifications** — A user may verify with a passport (IAL 2), then
  later verify with a driver's license (also IAL 2). The highest achieved IAL
  should be preserved; duplicate verifications should be allowed without
  degrading the user experience.
- **Verification failure anti-enumeration** — If an ID document doesn't match
  the provided name, the error should not reveal *which* field mismatched
  (preventing attackers from learning "that name doesn't match this ID").
- **Cross-tenant verification reuse** — If User A is verified in Tenant 1, can
  they reuse that verification in Tenant 2? (Privacy: the verification provider
  may not consent to data sharing between tenants.)

### Performance considerations

- Verification is inherently **synchronous-human** (document upload → AI
  analysis → optional manual review). The SPI should be fully asynchronous:
  `StartVerification` returns a reference ID and a polling URL; the server
  polls on behalf of the client or exposes a webhook callback.
- ID document images are **large payloads** (5-15 MB). Must have file size
  limits, content-type validation, and separate upload endpoints (not in the
  JSON request body).

---

## Direction 5: Developer Ecosystem & API Platform Maturation

### What exists today

The developer portal (`interfaces/web/developer/`) provides a minimal SPA for
OAuth client self-registration (DCR via RFC 7591/7592). The `ssoclient`
package delivers Go SDKs for local, remote, and dev modes. API docs are
served at `/api/v1/admin/docs`. The `cmd/gensdk/` scaffold generates Python
and TypeScript SDKs from the OpenAPI spec. Webhook engine exists
(`platform/lifecycle/webhook/`) with delivery, retry, dead-letter, and
subscription management.

### The gap

The developer portal is **bare-bones** — it registers clients but provides no
application management lifecycle. There is no API usage analytics, no
rate-limit visibility, no webhook testing console, no API key rotation UX,
and no playground for testing API calls. The generated SDKs are basic stubs.
A developer adopting the platform to build on top of it has a significantly
worse experience than comparable platforms (Auth0, Clerk, WorkOS, Stytch).

### What to build

| Component | Rationale |
|---|---|
| **Application management dashboard** — Full client management (list, edit, rotate secrets, toggle grants, configure redirect URIs, view scopes, approve/reject for admin-gated registration). Integrate with the existing admin API. | Replaces the bare-bones DCR form with a proper developer console |
| **Webhook testing console** — A UI to: (1) list registered webhook subscriptions, (2) view recent delivery attempts with status codes and payloads, (3) manually trigger a test event, (4) retry failed deliveries, (5) view dead-letter queue. | Debugging webhooks without external tools is a top developer experience request |
| **Usage analytics dashboard** — Per-client dashboards showing: token issuance rate, active users, API call volume, error rate, latency percentiles. Powered by existing `domains/metering/` and `domains/tokenusage/` data. | Developers need visibility into their application's SSO usage without asking the platform operator |
| **API playground / try-it console** — An interactive console where developers can: select an endpoint, fill in parameters, attach a bearer token, execute the request, and see the response — all from the browser via the developer SPA. Think Swagger UI but authenticating with the developer's own token. | Lowers the barrier to understanding the API; reduces support questions |
| **Rate limit & quota visibility** — Expose current rate-limit state per-client as HTTP headers (`X-RateLimit-Remaining`, `X-RateLimit-Reset`, `X-RateLimit-Limit`) on authenticated endpoints, and show usage in the developer dashboard. | Developers can build their own backoff/retry logic; reduces 429 surprises |
| **Sophisticated API key management** — Support for: multiple active keys per client (rolling rotation), key metadata (name, description, expiry), key-scoped permissions (restrict a key to `token:introspect` only), automatic expiry enforcement, and key revocation webhooks. | Enterprise API management pattern; essential for developer-facing platforms |
| **OpenAPI spec hosting & versioning** — Serve the OpenAPI spec at a stable URL (`/openapi.json`), support versioned specs (`/openapi/v1.json`, `/openapi/v2.json`), and provide a spec diff/CHANGELOG for breaking changes. | API consumers need stable contracts and migration guides |

### Edge cases to handle

- **API key vs. OAuth token confusion** — A developer may try to use an API
  key where an OAuth access token is expected (or vice versa). The error
  response should clearly distinguish `invalid_token` (bad OAuth token) from
  `invalid_api_key` (bad API key) with actionable guidance.
- **Webhook delivery ordering** — Webhook events for the same client must be
  delivered in order (at-least-once semantics with idempotency keys). Events
  across different clients have no ordering guarantees.
- **Playground security** — The API playground must never log or store the
  developer's bearer token server-side. All credential handling happens in the
  browser. The playground also should not allow mutation on production data
  without explicit confirmation ("I understand this will modify real data").
- **Usage analytics data delay** — Real-time analytics is expensive. Establish
  a clear SLA: "analytics data is available within 5 minutes" and show the
  refresh timestamp on the dashboard.

### Performance considerations

- **Analytics aggregation** — Metering data (`domains/metering/`) should be
  pre-aggregated into time-windowed rollups (1 min, 5 min, 1 hour, 1 day) for
  dashboard queries, with raw data retained only for a configurable window.
- **Key lookup fast path** — API key authentication must be as fast as JWT
  verification. Use a hash-based key lookup (SHA-256(key_prefix) → stored
  hash) to avoid a full scan.
- **OpenAPI spec caching** — The spec can be large (12K+ lines YAML). Serve
  with strong caching (`Cache-Control: public, max-age=3600, immutable`) and
  support `304 Not Modified` via ETags.

---

## Summary: Comparative Value & Effort

| Direction | Strategic Value | User Impact | Engineering Effort | Risk |
|---|---|---|---|---|
| 1. Passkeys & Passwordless-First | Very High | Very High | Medium | Low — well-understood standard |
| 2. Org & Workspace Management | Very High | Very High | High | Medium — complex domain model |
| 3. Risk-Based Session Intelligence | High | High | Medium-High | Medium — false positive sensitivity |
| 4. Identity Verification & Proofing | High | Medium-High | High | High — regulatory, PII, provider dependency |
| 5. Developer Ecosystem Maturation | High | High | Medium | Low — leverages existing APIs |

**Recommended sequencing:** 1 → 5 → 3 → 2 → 4. This prioritizes the highest
user-facing impact with the lowest execution risk first (passkeys, developer
portal), builds foundational risk intelligence, then tackles the complex
organization layer, and finally addresses the most regulated area (identity
verification) once the platform maturity supports it.

---

## Cross-Cutting Performance & Edge-Case Improvements

Beyond the five directions above, the following cross-cutting improvements
apply to the entire codebase:

### Performance

- **Token introspection cache** exists but is per-node in-memory; a shared
  Redis-backed introspection cache would reduce load on the token store in
  clustered deployments.
- **Client store cache** is TTL-based with bus invalidation; ensure the
  invalidation propagates to all nodes within bounded latency (currently
  etcd/memory only; MQTT-backed cluster bus exists in
  `infrastructure/mqtt/bus.go` and should be tested for this use case).
- **Refresh token family rotation** uses `DELETE RETURNING` in SQLite but
  Postgres could benefit from advisory locks for concurrent rotation safety
  under high contention.
- **JWKS body cache** exists (`interfaces/sso/jwks_body_cache_test.go`) but
  ensure it supports cache-stampede protection (singleflight pattern is in
  `servercache/sso_jwks_singleflight.go`; verify coverage).

### Edge Cases

- **Clock skew handling** — DPoP has configurable skew, but many verifiers
  (JWT `iat`/`exp`, session timeouts, auth code expiry, refresh rotation
  grace) use server time without configured bounds. Ensure all time-dependent
  operations accept a configurable `MaxClockSkew`.
- **Token bytes limit** — `WithMaxTokenBytes` gates inbound token size; ensure
  this applies uniformly across all token-accepting endpoints (`/token`,
  `/introspect`, `/userinfo`, `/end_session`, mesh, APIs).
- **Concurrent registration race** — DCR (`POST /register`) could race with
  itself under high concurrency, creating duplicate clients. Consider a unique
  constraint on `(client_name, client_uri, redirect_uris)` or use a
  registration lock per developer.
- **Backchannel logout fan-out** — If a user has sessions at 1000 RPs,
  broadcasting logout to all of them must be non-blocking with timeouts and
  per-RP failure isolation (one slow RP should not delay the other 999).
- **Tenant isolation in audit query** — The audit facet querier
  (`GET /api/v1/audit/facets`) must enforce that a tenant-scoped admin can
  only query their own tenant's audit events.
