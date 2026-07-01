# Expansion Directions: snaplink SSO Server

> **Scope:** 1,637 Go source files (~327K LOC), 55+ packages across 7 architectural layers.
> **Status:** Comprehensive OAuth 2.0/OIDC SSO server SDK with SAML/Kerberos/RADIUS/federation support.
> **Generated:** 2026-07-01 — based on full codebase scan, feature matrix audit, and architectural analysis.

---

## 0. Executive Summary

The project is exceptionally well-architected: every concern is a pluggable SPI, backends are swappable (memory / SQLite / etcd / Redis / Postgres / KMS), and the feature matrix covers virtually every OAuth 2.0 / OIDC / FAPI spec. The gaps are not in *what* is supported but in how the pieces compose into coherent **cross-cutting subsystems** that solve real production problems at scale. Below are the five highest-value directions — each builds on existing SPIs rather than requiring a rewrite.

---

## 1. Adaptive Authentication & Risk-Based Step-Up Engine

### Current State

The project has **all the building blocks** but no cohesive engine to combine them at runtime:

| Building Block | Where | Limitation |
|---|---|---|
| `anomaly.Detector` (off-path) | `domains/anomaly/` | Runs AFTER login returns; signals never feed the auth decision |
| `RiskScorer` (synchronous) | `spi.RiskScorer` / `defaultrisk/` | Returns a decision but has no standard policy envelope |
| `AccountLockout` | `security/account_lockout.go` | Binary lock/no-lock; no graduated response |
| `Geo` middleware + context | `platform/geo/` | UX-only enrichment, fail-open, never drives auth level |
| `MFAProvider` | `spi.MFAProvider` / `domains/authenticators/` | Always-on or not; no contextual triggering |
| `StepUpAuth` | `security/step_up_auth.go` | Resource-server-side helper only; server has no server-driven step-up |
| WebAuthn / TOTP | `domains/authenticators/webauthn/`, `totp_mfa.go` | Independent of risk/geo/velocity signals |
| `LoginEvent` | `domains/anomaly/types.go` | Rich event structure — but only consumed by off-path detectors |

### Why It Matters

Every login is treated equally: the same password check applies whether the request comes from Alice's trusted home IP or a Tor exit node in a high-fraud region. Operators must choose between:

- **Under-security** (password-only for everyone, hoping anomaly catches bad actors after the fact)
- **Over-security** (always-MFA, degrading UX for low-risk users)

Neither is acceptable in production. A **runtime policy engine** that consumes risk signals, geolocation, device fingerprint, and resource sensitivity to dynamically compute the required authentication level (`acr_values`) would be the single highest-value addition to the project.

### What a Solution Requires

1. **`AdaptivePolicyEngine` SPI** — consumes a `LoginContext` (risk score, geo, device fingerprint, resource sensitivity, account history) and returns the minimum ACR / required MFA / block decision **before** the login completes. Synchronous, fail-closed on evaluation error.

2. **`DeviceFingerprint` SPI** — a browser-/client-provided fingerprint (e.g., `Sec-CH-UA` headers, WebAuthn extension data, TLS client-hello attributes) collected at `/auth/login` entry and fed into the policy engine. Currently the server has zero device-intelligence capability.

3. **Risk-Weighted MFA Trigger** — integrate the policy engine into the existing login orchestration so that a medium-risk login prompts MFA *before* issuing tokens, a low-risk login proceeds with password only, and a high-risk login is blocked with a distinct error code.

4. **Metric & Audit Integration** — the policy decision (`outcome=allowed|mfa_required|blocked`, `risk_level=low|medium|high`) must be emitted as a structured audit event and Prometheus metric, since adaptive auth decisions are the highest-value signal for security operations.

### Edge Cases to Solve

- **VPN / Privacy-pass users** — geo velocity will look like impossible travel. Need configurable allowlists or VPN detection to avoid false-positive step-up.
- **New device enrollment** — first login from a device should not alone trigger MFA; combine with other signals (time of day, resource sensitivity).
- **Policy evaluation timeout (< 50ms)** — the engine must be synchronous on the hot path; a slow evaluator degrades UX for every login.
- **Cache warming** — pre-compute risk profiles for known users/credentials to avoid per-login database queries.

---

## 2. Token Exchange Chain Governance & Delegation Control

### Current State

- Token exchange (RFC 8693) is fully implemented with SPIFFE JWT-SVID fallback, act-chain tracking, and sender-constraint continuity (DPoP/mTLS).
- `MaxActChainDepth = 10` caps chain length.
- `act` claim is serialized as a linked list of `ActorClaim` structs with `Actor` pointer recursion.

### The Gaps

| Gap | Risk |
|---|---|
| **No scope minimization** — each exchange hop inherits the full scope set of the subject token. A token issued with `email profile admin` can be exchanged for another token with the same scope, including `admin`, even if the exchanging client only needs `profile`. | Privilege creep; the `admin` scope leaks to the third hop's downstream. |
| **No circulation detection** — token A → token B → token C → token A (where C self-loops) is undetectable. The chain is a linked list; nothing prevents a cycle. | Infinite exchange loops; denial-of-service via unbounded chain serialization; replay attacks. |
| **No audience restriction enforcement** — the `aud` claim from the subject-token's original issuance is ignored during exchange. A token intended for RS-A can be exchanged and used at RS-B. | Token misuse; resource server A's token used to access resource server B. |
| **No per-hop attestation** — each exchange records `client_id` in the audit log but not in the token itself. The `act` chain records only the *issuer* of each hop's token, not the *client* that performed the exchange. | Non-repudiation gap: "who exchanged token A into token B?" can only be answered from the audit log, not from the token itself. |
| **No chain-level TTL** — the issued token's `exp` is based on the current time + TTL. A 10-hop chain could have a total lifetime of 10× the per-hop TTL. No upper bound on total chain lifetime. | Stale delegation chain; a chain started 24 hours ago can keep being extended. |

### Why It Matters

Token exchange is the backbone of service-to-service auth in mesh architectures (Envoy, Istio, SPIFFE). As organizations deploy multi-hop delegation (API gateway → BFF → microservice A → microservice B), uncontrolled chain growth becomes both a security liability and a performance problem (bloated JWTs exceeding HTTP header size limits).

### What a Solution Requires

1. **`TokenExchangePolicy` SPI** — per-client or per-tenant rules for: max scope set (intersect with subject scope), allowed audiences, max chain depth, total chain TTL, prohibited clients (cannot exchange tokens issued by these clients). Evaluated at exchange time.

2. **Circulation Detector** — before prepending the `act` claim, walk the existing chain and check if the current client or actor subject already appears. If it does, reject with `invalid_grant` — no token should self-reference.

3. **Scope Narrows-by-Default** — change the default exchange behavior from "inherit all" to "inherit only what the requesting client is authorized for". The `scope` parameter on the exchange request narrows further. Privilege creep requires explicit `actor.allow_scope_expansion` opt-in.

4. **Chain-Aware Expiry** — compute the new token's `exp` as `min(currentTime + perHopTTL, subjectToken.exp)` so the chain's total lifetime never exceeds the original token's.

5. **Extended Audit Event** — `token_exchange` audit must include `chain_depth_before`, `chain_depth_after`, `scopes_narrowed_to`, and `circulation_detected` boolean so operators can monitor chain topology.

---

## 3. Cross-Protocol Session Hub & Convergence

### Current State

The server supports **separate session ecosystems**:

| Protocol | Session Mechanism | Store(s) |
|---|---|---|
| OAuth 2.0 / OIDC | `SessionManager` + `sid` claim + refresh token families | Memory, SQLite, Redis |
| SAML 2.0 (IdP + SP) | Session index, IdP session store, SP replay cache | SQLite (`idpsqlite/`, `spsqlite/`) |
| Kerberos / SPNEGO | Kerberos ticket-based (server-issued authenticator) | `kerberos/` nested module |
| WebAuthn | Conditional login sessions, credential records | SQLite, Redis, Postgres |

These sessions are **completely independent**: a user authenticated via SAML IdP and later via OAuth has no cross-protocol session identifier. Logging out of the OAuth session does not invalidate the SAML IdP session. The audit trail cannot trivially correlate "user X's actions across OAuth and SAML."

### Why It Matters

The project uniquely supports four authentication protocols in one binary — this is already a differentiator. But operators running multi-protocol deployments (OAuth for SPAs, SAML for enterprise IdP integration, Kerberos for internal tools) currently get **four siloed session stores** rather than a **unified identity plane**. The value of multi-protocol support is dramatically reduced when sessions cannot be cross-referenced, centrally managed, or jointly revoked.

### What a Solution Requires

1. **`SessionHub` SPI** — a registry that maps a user's global identity (`sub` + `tenant_id`) to one or more protocol-specific session IDs. When any session is created, it registers itself with the hub. When any session is destroyed (logout, timeout, revocation), the hub signals all associated protocol backends.

2. **Unified Logout Flow** — enhance `/end_session` (currently OIDC-specific) to enumerate all sessions for the user from the hub and trigger teardown on each protocol backend. SAML `LogoutRequest` / Kerberos ticket revocation / OAuth refresh family deletion — all from one endpoint.

3. **Cross-Protocol Session Identifier** — a `global_sid` claim or cookie that all protocol login flows emit. The same JWT `sid` is used for OIDC; SAML responses carry `SessionIndex` that includes the global SID; Kerberos authenticator metadata references it.

4. **Convergent Session Dashboard** — the existing admin SPA (`interfaces/web/admin/index.html`) and the self-service portal (`interfaces/web/portal/index.html`) can surface a unified "active sessions" view instead of per-protocol tables.

5. **Session Hierarchy Model** — some sessions are authoritative (OIDC session after password auth), some are derived (SAML SP session created via IdP-initiated SSO from the OIDC session). The hub must track parent-child relationships so revoking the parent cascades to children, but revoking a child does not destroy the parent.

### Edge Cases to Solve

- **Session index cardinality** — a user might have 100+ sessions across protocols. The hub must support large user fan-out without per-request full-table scans.
- **Cross-replica invalidation** — when a session is killed on replica A (via logout), the hub must publish a cluster bus event so replica B's sessions for the same user are also invalidated.
- **Graceful partial failure** — if SAML session revocation fails but OIDC succeeds, the hub should return a partial error rather than rolling back the OIDC revocation.

---

## 4. Auth Plane Observability: Token Lifecycle & Event Subscription System

### Current State

The project has excellent **operations-plane observability**:

| System | What it does |
|---|---|
| `platform/audit/` | Structured event recording with hash-chain integrity, W3C trace context, multi-sink pipeline |
| `platform/metrics/` | Bounded-cardinality Prometheus metrics (requests, logins, tokens, MFA, signing keys, FAPI violations, etc.) |
| `platform/tracing/` | Distributed trace propagation via OpenTelemetry-compatible span context |
| `platform/cluster/` | Cross-replica event bus (token revoked, key rotated, client changed, policy changed) |

But there is **no auth-plane observable surface** for *downstream consumers* — resource servers, API gateways, security operations centers, and B2B tenants who need to react to authentication events programmatically:

| Needed | What exists | Gap |
|---|---|---|
| Token-about-to-expire notification | None | Resource servers must poll introspection |
| Client credential rotation alert | None | Operators discover expired `client_secret` at runtime |
| Session change events | CAEP/SSF (security events only) | Only CAEP-relevant events; no general session-change subscription |
| Rate-limit threshold warning | Metrics (passive) | No push notification before hitting the limit |
| Token exchange chain depth warning | None | Silent linear degradation until JWT exceeds header limits |
| Failed login anomaly (human-readable) | Audit log (needs query) | No push to security team Slack/PagerDuty |
| Tenant activity digest | Metering (aggregated, internal) | No push to tenant admin |

### Why It Matters

The project already sells itself as a production SSO server. Production operators need to **know what's happening before it breaks**, not after. The audit system is a "pull" model (you query it); an event subscription system is a "push" model (it tells you). This is the difference between finding out about a client_secret expiry at 3 AM from an outage vs. getting a warning 7 days in advance.

More importantly, the CAEP/SSF transmitter is purpose-built for security events only. Many auth-plane events (token expiry, credential rotation, rate-limit warnings) are not security events — they are operational events that a general-purpose subscription system should handle.

### What a Solution Requires

1. **`EventSubscription` SPI + Store** — allows configuring webhook endpoints that subscribe to event types (beyond CAEP's limited set). Each subscription has a target URL, secret (for HMAC-signed payloads), retry policy, and event type filter.

2. **Event Type Taxonomy** — extend the existing `auditspi` event types with subscription-relevant events:
   - `token.expiry_warning` (7/3/1 day before access token or client_secret expiry)
   - `credential.rotation_needed` (client_secret age threshold)
   - `session.revoked` (user or admin-initiated — previously CAEP-only)
   - `ratelimit.threshold_breached` (per-client/per-IP at 80% of limit)
   - `token_exchange.chain_deep` (depth > N)
   - `login.anomaly_detected` (off-path detector found a signal)

3. **Webhook Delivery Engine** — a delivery subsystem (separate from the audit webhook sink, which is for audit forwarding) that:
   - Signs payloads with `HMAC-SHA256` using the subscription secret
   - Retries with exponential backoff (3 attempts, 10s/30s/90s)
   - Applies per-subscription rate limiting (don't overwhelm the subscriber)
   - Emits delivery metrics (`sso_subscription_delivery_total{outcome,event_type}`)
   - Supports dead-letter queue for persistent failures
   - Is itself async + best-effort (never blocks the request path)

4. **Scheduled Event Producers** — a background ticker that walks client credentials, tokens, and sessions and emits `_warning` events when thresholds are approaching. This is the piece that makes the system proactive rather than reactive.

### Edge Cases to Solve

- **Subscription storm** — 1,000 resource servers all subscribed to `token.revoked` would create a notification storm on every revocation. Needs subscription aggregation or fan-out with subscriber-side dedup via `jti`.
- **Replay safety** — webhook delivery must include `jti` + `timestamp` so subscribers can deduplicate. Delivery is at-least-once by nature.
- **Secret rotation** — each subscription has a `current_secret` and `next_secret` (dual state during rotation). The server signs with `current_secret` but accepts either during verification windows.
- **Backpressure from slow subscribers** — if one subscriber is down, it must not delay delivery to others. Implement per-subscription queues with bounded buffer per subscriber.

---

## 5. Token Introspection Enhancement Suite for Resource Servers

### Current State

- RFC 7662 introspection at `/token/introspect` — accepts any active token, returns `{"active":true, "scope":"...", "sub":"...", "client_id":"...", ...}`.
- Best-effort `IntrospectionCache` SPI (`protocols/oauth/introspect_cache.go`) — caches hashed-token-to-result mappings with configurable TTL.
- Admin gRPC `tokens.proto` provides management-level token operations.

### The Gaps

| Gap | Impact |
|---|---|
| **No batch introspection** — every token requires a separate HTTP call. At 50K RPS with 10 microservices each introspecting, that's 500K introspection calls. | CPU/RPS overhead; every RS pays full TLS + signature cost per request. |
| **No signed introspection response** — the response is a plain JSON body. A malicious RS cannot prove it received a valid response; a caching proxy could serve stale "active:true" for a revoked token. | Non-repudiation gap; stale-cache poisoning risk. |
| **No push-based revocation notification** — when a token is revoked, RSes must poll introspection to learn about it (or wait for cache TTL). CAEP/SSF covers SETs but is not integrated with the introspection cache. | Window of vulnerability between revocation and cache expiry; every RS has a TTL-sized blind spot. |
| **No RAR-aware introspection** — tokens with `authorization_details` (RFC 9396 RAR) return `"active":true` but do NOT include the authorization details in the introspection response. The RS must call `/userinfo` or decode the token. | Resource servers cannot make authz decisions from introspection alone for RAR-protected resources. |
| **No token-type-specific enrichment** — an access token and a refresh token return the same schema. A RS that receives a refresh token (shouldn't happen, but does) cannot distinguish. | Confused-deputy risk; refresh tokens used as access tokens are opaque. |
| **No introspection stats/health** — no metrics for introspection latency, cache hit ratio, token-type distribution, or per-resource-server call volume. | Ops cannot tune cache TTL or detect RS misconfiguration. |

### Why It Matters

Resource servers (RS) are the **largest consumer of the SSO server by request volume**. Every authenticated request to every microservice behind an API gateway typically triggers an introspection call. In mesh architectures, introspection traffic often dominates the SSO server's request profile.

Optimizing this path directly translates to:
- **Latency reduction** — signed cached responses served without crypto operations
- **Cost reduction** — fewer CPU cycles on the SSO server for signature verification
- **Security improvement** — push-based revocation closes the cache-window gap
- **Operational insight** — per-RS metrics detect misconfigured clients (e.g., RS that hasn't rotated its cache in 24 hours)

### What a Solution Requires

1. **`SignedIntrospectionResponse` SPI** — the server signs the introspection response body with a dedicated signing key (separate from token-issuance keys) using JWS. The RS verifies the signature once, then caches the signed response for its TTL. Even if an intermediary caches the response, the RS can verify it hasn't been tampered with. The RS never calls introspection again until the signed response's `exp` is reached.

2. **Batch Introspection Endpoint `POST /token/introspect/batch`** — accepts `{"tokens": ["hash1", "hash2", ...]}` and returns `{"results": {"hash1": {...}, "hash2": {...}}}`. Each result is individually signed (a JWS array, not a bundle). This allows a sidecar/agent to pre-warm the cache with a single HTTP call per batch window.

3. **Push-Based Revocation Channel via Cluster Bus Integration** — when a token is revoked (via `/token/revoke`, admin API, or refresh family kill), the existing cluster bus `KindTokenRevoked` message is extended with a dedicated delivery path for RS subscribers. An RS that has opted in via its client registration (`Client.Attributes["introspect_push_enabled"]`) receives an inline SET over a persistent connection (WebSocket or SSE) within seconds of revocation.

4. **RAR-Enriched Introspection** — when the token carries `authorization_details`, the introspection response includes `{"authorization_details": [...]}` in the `token` field. No more RS→/userinfo round-trip to get the rich authorization payload.

5. **Introspection Observability** — add Prometheus metrics:
   - `sso_introspect_requests_total{type, rs_client_id, outcome}`
   - `sso_introspect_cache_hit_ratio{rs_client_id}`
   - `sso_introspect_batch_size{rs_client_id}`
   - `sso_introspect_push_delivery_total{outcome}`
   
   This is the feedback loop operators need to tune their RS deployment.

### Edge Cases to Solve

- **Revocation→cache latency tension** — the whole point of caching is to avoid introspection calls. But caching means staleness. Signed introspection responses with short `exp` (30-60s) + push-based invalidation on revocation provides the best trade-off: RS serves from cache for normal reads, but gets a push invalidation on revocation that evicts the entry immediately.
- **Batch endpoint abuse** — `POST /token/introspect/batch` with 10,000 hashes is cheap for the server (no crypto per hash) but could be used as a oracle. The batch endpoint must apply the same oracle-leak rules as single introspection (unknown tokens return `{"active":false}`).
- **Sidecar vs. direct integration** — the signed response model is designed for sidecar/agent deployment (e.g., an Envoy ext_authz filter that verifies signed responses). The batch endpoint is for agents that want to pre-warm. Both patterns must be documented with clear trade-offs.
- **Clock skew** — signed introspection responses carry `iat` and `exp`. RS clock skew tolerance must be configurable (default 30s) to avoid false rejections during deployment updates.

---

## Summary Impact Matrix

| Direction | Security | Ops Efficiency | Differentiation | Effort Estimate |
|---|---|---|---|---|
| 1. Adaptive Authentication Engine | ★★★★★ | ★★★ | ★★★★★ | Large (new SPI + policy DSL + integration) |
| 2. Token Exchange Chain Governance | ★★★★★ | ★★★ | ★★★★ | Medium (new SPI + scope logic + circulation check) |
| 3. Cross-Protocol Session Hub | ★★★ | ★★★★★ | ★★★★★ | Large (new SPI + 4-protocol integration + dashboard) |
| 4. Auth Plane Event Subscriptions | ★★★ | ★★★★★ | ★★★★ | Medium (new SPI + webhook engine + producers) |
| 5. Introspection Suite for RS | ★★★★ | ★★★★★ | ★★★★★ | Medium (2 new endpoints + signed responses + push) |

**Recommendation:** Start with Directions **2** (Token Exchange Governance) and **5** (Introspection Suite) — they are self-contained, medium effort, and directly address production-scale pain points. Direction **3** (Session Hub) is the highest long-term value for the project's multi-protocol positioning but requires the most cross-cutting changes.
