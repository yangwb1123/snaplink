# Global Architecture Analysis — 5 High-Value Extension Directions

> **Date:** 2026-07-11  
> **Author:** Senior Architect / PM (fresh global scan)  
> **Scope:** Full codebase scan (2241 `.go` files, 55 prior analysis documents reviewed to avoid duplication)  
> **Method:** Protocol+product+security+operability quad-view, adversarial grep (assume "already done" until proven absent), cross-reference against existing ROADMAP v5.0 and deferred-backlog.

---

## Executive Summary

The project has achieved an extraordinarily complete OAuth 2.0 / OIDC SSO platform —
protocol coverage across ~30+ RFCs and OIDF specs, 7 backend engines (SQLite,
Postgres, Redis, etcd, MQTT, Kafka, KMS×5), both SAML and OIDC federation,
multi-tenancy with HRD and data residency, admin Console SPA, developer portal,
CAEP/SSF, SCIM provisioning, anomaly detection, and a security posture hardened
against oracle-leak / enumeration / replay.

After reading all 55 prior analyses and verifying code presence by grep, **every
item in those documents has been closed.** What remains are not "missed" features
but deliberate architectural boundaries — each is a distinct *product category*
the project has not yet entered. Below are 5 such categories, prioritized by
market signal / buyer demand / architectural leverage.

---

## Direction 1: Identity Verification & Proofing (KYC/IDV) Pipeline

### Why Now

The project's user model (`core.User`) has no concept of identity verification —
no `IdentityVerifiedAt` timestamp, no `IdentityProofingLevel` (NIST IAL), no
`VerifiedClaims` field. The `/me` self-service surface offers GDPR data export
and account erasure but no identity verification flow.

In regulated markets (FinTech, HealthTech, Govt, Crypto), the identity provider
is expected to be the **source of identity truth**, not just the authentication
gate. A login that says "this user controls this password/passkey" is different
from "this user is legally Alice Smith, age 25+, US resident". Platforms that
can assert both win procurement in regulated verticals.

### What Exists Today

- `core.User.Attributes` as a `map[string]string` (generic, unstructured)
- Authenticators for password, passkey, TOTP, SMS, email, OIDC federation
- `core.TrustSignals` carries device posture but no identity proofing
- No `verified_claims` in ID tokens (OIDC for Identity Assurance — OID4IDA — is
  not implemented: grep `verified_claims` → 0 hits in any JWT payload builder)
- No document verification, liveness check, or identity record model

### Scope

An opt-in identity verification subsystem that:

1. **Identity Record Model** — `IdentityRecord` with fields: `legal_name`,
   `date_of_birth`, `document_type` (passport, DL, national ID), `document_number`
   (hashed-at-rest), `verification_level` (IAL1/IAL2/IAL3), `verified_at`,
   `expires_at`, `provider` (Persona, Onfido, Veriff, manual review…), `status`
   (pending/verified/rejected/expired). Stored in a new store SPI backed by
   memory, sqlite, and postgres peers — NOT in the user profile itself (privacy
   separation).

2. **Verification Workflow** — A state machine: `unverified → pending →
   verified / rejected`. The `/me/identity` self-service endpoint lets the user
   initiate verification and check status. An admin endpoint allows manual
   override (with `admin_identity_verification_override` audit event, always).

3. **Proofing Provider SPI** — `IdentityProofingProvider` interface:
   `InitiateVerification(userID, redirectURL) → (verificationID, status)` and
   `HandleWebhook(verificationID, result)`. Reference implementations for
   Persona/Onfido/Digidentity as sub-modules (same pattern as KMS peers).

4. **ID Token `verified_claims`** — When proofing is at IAL2+, the ID Token
   (and UserInfo endpoint) includes a `verified_claims` JWT member per
   [OIDC for Identity Assurance (OID4IDA)](https://openid.net/specs/openid-connect-4-identity-assurance-1_0.html).
   The `claims` parameter `verified_claims` projection is honored.

5. **Elevated Assurance Session** — A session minted AFTER identity verification
   carries `acr` reflecting the IAL (e.g. `https://snaplink.dev/ial/2`).
   Sensitive client operations (billing scope, admin `admin:write`) can require
   a minimum IAL — enforced via the existing `AchievedACR` gate at `/token`
   exchange.

### Edge Cases

- **Expired documents** — `ExpiresAt` field; expired verification drops session
  ACR below threshold. Background job sends re-verification prompt.
- **Identity fraud** — If a proofing provider returns `fraud_detected`, the
  record status becomes `rejected` permanently (admin can override with audit).
  All sessions for that user are revoked immediately (reuse the existing
  `RevokeRefreshTokensByUser` + CAEP `account_disabled`).
- **Multi-tenant isolation** — Identity records are tenant-scoped; a user in
  tenant A cannot see records belonging to the same user in tenant B.
- **Privacy** — Document images/numbers are never stored; the proofing provider
  returns only a verified token + hashed identifier reference.
- **Migration** — Existing users get `IAL1` (self-asserted). No automatic
  backfill of verification.

### Sequencing & Effort

| Step | Effort | Independent |
|---|---|---|
| Identity Record SPI + memory/sqlite/postgres stores | L | Yes |
| Proofing provider SPI + Persona reference impl | M | Parallel with store |
| Self-service `/me/identity` endpoints | M | After store |
| ID Token `verified_claims` projection + ACR gating | M | After store |
| Admin manual override + audit events | S | After store |

**Total: XL** (but composable — stores go first as L)

---

## Direction 2: Organization Directory Sync Engine

### Why Now

The project has:
- LDAP **authenticator** (validate user credentials against an LDAP/AD bind)
- SCIM 2.0 **provisioning** (push/pull user and group CRUD)
- Enterprise Connections (per-tenant upstream IdP config)
- JIT membership (auto-join org on login via email domain)

What it does NOT have is a **directory sync engine** — a scheduled, fault-tolerant
process that reconciles users and groups from an authoritative external directory
(AD, Azure AD, Google Workspace, Okta SCIM) into the local user store, handling
delta sync, conflict resolution, soft-delete detection, and scheduled keeps-alive.

This is the #1 enterprise migration scenario: "I have 5,000 users in Azure AD /
Okta / Google Workspace. Sync them into this SSO so they can authenticate AND
manage their group memberships here. Keep them in sync bi-directionally (or at
least one-way with conflict alerts)."

Without this, every enterprise onboarding is a one-time bulk import script
followed by manual drift management.

### What Exists Today

- `cmd/sso-ctl/importcmd/` — one-time bulk import from Auth0/Okta/Keycloak JSON
  (does NOT support delta sync or scheduled runs)
- `scim/` — SCIM 2.0 server (receives pushes) + SCIM push provisioner (outbound)
- `ldap/` — authenticator only (LDAP bind auth, no user reconciliation)
- `domains/connections/` — enterprise connection config storage
- `authenticators/oidc_federation.go` — OIDC upstream IdP bridge
- `permissions/` — RBAC with roles, role assignments, groups

### Scope

1. **Directory Connector SPI** — `DirectoryConnector` interface:
   - `FullSync(ctx) → (SyncResult, error)` — pull ALL users and groups
   - `DeltaSync(ctx, since) → (SyncResult, error)` — pull incremental changes
   - `Health() → HealthStatus` — connection health for readiness
   - `Capabilities() → SyncCapabilities` (delta, groups, nested groups, photos…)

   Returned `UserEntry`/`GroupEntry` types with external ID, attributes, manager
   reference, group membership list, and a conflict marker.

2. **Connector Implementations** — Sub-module pattern (same as KMS peers):
   - `infrastructure/directorysync/ldap/` — AD/LDAP via `gokrb5` + LDAP search
   - `infrastructure/directorysync/azure/` — Microsoft Graph API (users, groups,
     group members, delta query)
   - `infrastructure/directorysync/google/` — Google Workspace Directory API
   - `infrastructure/directorysync/scim/` — Generic SCIM 2.0 client (sync FROM
     any SCIM provider)

3. **Sync Scheduler & Reconciliation Engine** — `platform/directorysync/`:
   - Configurable schedule (cron, interval, manual)
   - Diff engine: compare external vs local state → plan of INSERT/UPDATE/
     DISABLE/DELETE operations
   - Conflict resolution: local-wins, external-wins, manual-review (writes to
     a pending-changes table + admin approval)
   - Soft-delete: external user removed → local user status `suspended` (not
     deleted), with re-activation if they re-appear in a later sync
   - Group membership reconciliation: assign/remove local roles based on group
     membership

4. **Audit Trail** — Every sync cycle emits: `directory_sync_started`,
   `directory_sync_completed` with counts (created, updated, disabled,
   conflicts). Admin can view sync history and drill into specific conflicts.

5. **SCIM Bidirectional Bridge** — When the external source is a SCIM provider,
   local changes (user updates, group reassignments) can push back outbound
   via SCIM push.

### Edge Cases

- **Nested groups** — AD nested group membership must be flattened (configurable
  depth limit, default 10).
- **Large directories** — 100k+ users, paged enumeration, incremental sync via
  `changedAt` / `deltaLink` / `usnChanged`.
- **Credential rotation** — The directory connector uses its own service
  principal / OAuth client / LDAP bind DN. Certificate or secret rotation
  must not break active sync — support multiple overlapping credentials.
- **Chaos** — Source directory temporarily unreachable → fail-open (last known
  state preserved, sync `_failed` event, retry with backoff). Source returns
  empty delta → do NOT interpret as "delete everyone" (require min-count guard).
- **Schema mapping** — External attributes (`extensionAttribute1`, `custom:role`)
  map to `core.User.Attributes`. The operator configures mappings per connector.

### Sequencing & Effort

| Step | Effort | Independent |
|---|---|---|
| Directory Connector SPI + reconciler engine | L | Yes |
| Azure AD (Graph) connector | M | Parallel |
| LDAP/AD connector | M | Parallel |
| Google Workspace connector | M | Parallel |
| SCIM client connector | S | Parallel |
| Admin UI for sync config + history | M | After engine |
| Scheduled sync job | S | After engine |

**Total: XL** (connectors can be built in parallel)

---

## Direction 3: Identity-Aware Auth Proxy (Session Bridge & Header Injection)

### Why Now

The project has:
- `mesh_authz.go` + `extauthz/` — Envoy ext_authz v3 (binary allow/deny, used
  with service mesh sidecar)
- `ssoclient/` — SDK for app-side token verification (Go consumers)
- `protocols/federation/` — Trust chain resolution
- `protocols/caep/` — SSF event delivery

What it does NOT have is an **identity-aware auth proxy** — a standalone reverse
proxy that sits in front of legacy applications (non-Go, non-SDK-enabled) and:

1. Terminates user sessions (cookie-based or bearer-based)
2. Injects identity context as HTTP headers (`X-User-Id`, `X-User-Email`,
   `X-User-Roles`, `X-User-Org`, `X-User-IAL`)
3. Handles token exchange on behalf of downstream services
4. Provides a logout endpoint that clears the session and broadcasts BCL/CAEP
5. Supports path-level and method-level authorization checks

This is the dominant pattern in the industry — products like Pomerium, OAuth2
Proxy, Authentik, Keycloak Gatekeeper, Cloudflare Access all compete on this
capability. The OSS reference for this is [OAuth2 Proxy](https://github.com/oauth2-proxy/oauth2-proxy)
and [Pomerium](https://www.pomerium.com). Adding this makes the project a
**drop-in replacement** for those tools while leveraging the full OIDC/CAEP/
SCIM stack already built.

### What Exists Today

- `ssoclient/rs/` — Resource-server middleware for Go apps (DPoP, token
  introspection, authorization check)
- `ssoclient/remote/` — Remote-verifier SDK (fetch JWKS, verify JWT)
- `extauthz/` — Envoy ext_authz gRPC filter (mesh sidecar pattern, requires
  Istio/Envoy — not a standalone proxy)
- `stack/` — middleware chain for the SSO server itself (not a reverse proxy
  for downstream services)

### Scope

1. **Auth Proxy Core** — `cmd/auth-proxy/` (new standalone binary, separate
   nested Go module, depends only on `ssoclient` + standard library):
   - `--upstream` flag (target backend URL)
   - `--listen` flag (listener address, default `:4180`)
   - `--cookie-secure`, `--cookie-domain`, `--cookie-name` flags
   - `--header-map` flag (configures which claims map to which headers)

2. **Session Management** — The proxy establishes its OWN session with the SSO
   server (OIDC Authorization Code Flow + PKCE), stores the session in a
   cookie (encrypted `HttpOnly; Secure; SameSite=Lax`), and on each request:
   - Validates the session cookie (decrypt, check expiry)
   - Optionally performs token introspection (if `--introspect` flag)
   - Injects identity headers
   - If the session is expired / revoked, redirects to the SSO server's
     `/auth/login` with a `post_login_redirect` back to the original URL

3. **Authorization Logic** — Path-level and method-level allow/deny rules:
   - `--rule='allow path=/api/* method=GET scope=read'`
   - `--rule='deny path=/admin/* scope=superuser'`
   - Evaluated against the user's token claims (scopes, roles, entitlements)
   - Supports the existing `permissions.Provider` if wired

4. **Logout & Session Revocation** — `GET /oauth2/sign_out`:
   - Clears the proxy's session cookie
   - Calls the SSO server's `/end_session` (RP-Initiated Logout with
     `post_logout_redirect_uri`)
   - Optionally broadcasts a CAEP `session_revoked` event

5. **CAEP Event Receiver** — The proxy can receive CAEP push events from the
   SSO server (e.g., `session_revoked`, `account_disabled`) and proactively
   clear its local session cache, preventing access even before the session
   cookie expires.

### Edge Cases

- **X-Forwarded-* trust** — The proxy MUST set/override `X-Forwarded-User`,
  `X-Forwarded-Email`, `X-Forwarded-Groups` headers. It also MUST strip any
  incoming values of these headers to prevent client injection.
- **Session cookie rotation** — On token refresh, the cookie content (encrypted
  refresh token + claims) MUST be rotated. The cookie's `Expires` field MUST
  match the SSO session's `exp` claim.
- **Graceful degradation** — If the SSO server is unreachable, the proxy
  continues serving from its session cache (fail-open) but logs a
  `proxy_auth_unreachable` warning. When the session expires, it returns 502
  (unable to re-auth) rather than silently serving anonymous requests.
- **WebSocket / SSE** — The proxy must correctly handle WebSocket upgrade and
  SSE streaming, performing auth at connection time and then passing through.
- **Concurrent session limit** — Configurable max sessions per user, enforced
  by evicting oldest.

### Sequencing & Effort

| Step | Effort | Independent |
|---|---|---|
| Proxy skeleton (listen, upstream, cookie session) | M | Yes |
| OIDC login flow + token refresh | M | After skeleton |
| Header injection engine | S | After skeleton |
| Authorization rule engine | M | After skeleton |
| Logout + session revocation | S | After session mgmt |
| CAEP event receiver for cache invalidation | S | Independent |
| Envoy ext_authz adapter (if proxy used as sidecar) | M | After core |

**Total: L** (core skeleton is a focused ~1500-line binary)

---

## Direction 4: Delegated Organization Admin Console (B2B Multi-Tenant Self-Service)

### Why Now

The existing Admin Console (`interfaces/web/admin/`) is a **global operator**
console — it requires `admin:*` scope and operates across all tenants. For the
B2B SaaS use case (the tenant/collaboration model already built), a **delegated
organization admin console** is a distinct product: each tenant's admin (not the
global operator) manages their own org's users, groups, connections, SSO
settings, policies, and usage reports.

This is Auth0 Organizations, WorkOS Dashboard, Okta Admin Console — the "org
settings" page that a customer's IT admin logs into to configure their part of
the platform.

### What Exists Today

- `interfaces/web/admin/` — Global admin SPA (full CRUD for clients, users,
  tenants, domains, sessions, audit)
- `interfaces/web/login/` — Hosted login SPA (branded login pages)
- `interfaces/web/developer/` — Developer self-service portal (DCR registration)
- `permissions/` — Role-based authorization with scoped admin scopes
  (`admin:read.tenant.{tid}`)
- `tenant/` — Tenant model with branding, status, residency
- `domains/connections/` — Enterprise connections per tenant
- `domains/selfservice/` — End-user self-service

### Scope

1. **Org Admin SPA** — `interfaces/web/org-admin/` (opt-in via
   `WithOrgAdminPortalFS`, mounted at `/org-admin/`):
   - **Dashboard** — Active users, sessions, login activity (last 24h), usage
     summary (MAU, token issuance volume)
   - **Users** — List, invite, suspend, assign roles, view login history (NOT
     global CRUD — only users belonging to THE org)
   - **Groups** — CRUD for org-specific groups + role assignment
   - **Connections** — Manage enterprise connections (SAML/OIDC upstream) for
     the org — domain verification via DNS TXT record
   - **SSO Settings** — Org-level authentication policy (default authenticator,
     MFA requirement, session TTL, password policy)
   - **Audit Log** — org-scoped audit events (filtered to events where
     `tenant_id == org.id`)
   - **Billing** — Usage report, plan, payment method (if monetized)

2. **Authorization Model** — The Org Admin portal authenticates via the same
   OAuth2 PKCE flow, requesting `scope=admin:read.tenant.{tid} admin:write.tenant.{tid}`.
   The existing `permissions.Provider` + `wildcard` matcher already supports
   this scope granularity. The portal UI checks `scope` claims to show/hide
   actions.

3. **Domain Verification** — When an org adds a SAML/OIDC connection, they
   must verify domain ownership via DNS TXT record (existing
   `domains/connections/domain_verification.go`). The org admin portal
   provides a guided flow: "Add this TXT record to your DNS" → "Verify Now".

4. **User Invitation Flow** — Org admin invites users via email. The
   invitation creates a pending user record + sends an email with a magic
   link (existing `invitation` stores already handle this for global admin,
   but need an org-scoped variant).

### Edge Cases

- **Cross-org visibility** — An admin of org A MUST NOT see org B's data.
  The API gateway (admin REST handler) MUST enforce tenant-scoped queries.
  Today's admin API is global-scope — a new set of org-scoped endpoints (or
  a `tenant_id` filter enforced by the handler, NOT by the frontend) is
  needed.
- **Org admin deactivation** — If an org admin is suspended/deactivated,
  their session MUST be revoked (CAEP `admin_role_revoked` event or session
  re-validation on each admin API call).
- **Global admin override** — Global operator retains the ability to
  view/manage any org's data (via existing admin console). Org admin cannot
  lock out the global admin.
- **Orphaned orgs** — If the only org admin leaves the company, the global
  operator must be able to assign a new org admin.

### Sequencing & Effort

| Step | Effort | Independent |
|---|---|---|
| Org-scoped admin REST API endpoints | L | Yes |
| Org Admin SPA (Dashboard + Users + Audit) | L | Parallel with API |
| Invitation flow (org-scoped) | M | After org API |
| Domain verification guided UI | S | After connection API |
| Billing/usage panel | M | After metering infra |

**Total: XL** (but org-scoped API is prerequisite — that is L)

---

## Direction 5: Access Certification & Identity Governance Reviews

### Why Now

As the platform matures into a multi-tenant B2B identity system (Directions 2+4),
a natural need emerges: periodic **access certification** — the process where
org admins or resource owners review who has access to what, and certify
(approve) or revoke that access.

This is a SOC2 Type II / SOX / HIPAA requirement for medium-to-large enterprises:
"Prove that you review user access to sensitive applications at least quarterly."
It is also a direct upsell from "SSO" to "Identity Governance" (IGA), the
latter commanding 3-5× higher ACV.

### What Exists Today

- `domains/permissions/` — Full RBAC with roles, groups, role assignments, menus
- `domains/tokenpolicy/` — Token issuance policies (per-client)
- `domains/conditionalaccess/` — Zero-trust access policies (geography, device
  posture, trust score)
- `platform/lifecycle/admingovernance/` — Admin approval workflows (geo-locked,
  quota-gated, destructive-action approval)
- `protocols/lifecyclereactions/` — Automated reactions to lifecycle events
  (e.g., revoke access on user archived)
- `core.User.Active` — Active/suspended status
- `interfaces/admin/governance.go` — Admin governance middleware (scope-based
  access to admin endpoints)
- Audit trail with hash-chain verification

What does NOT exist: **access certification campaigns**, **entitlement
catalog**, **separation-of-duty (SOD) policies**, **remediation workflows**.

### Scope

1. **Access Certification Campaign** — A time-boxed review period where
   certifiers (org admins, resource owners, user managers) review a list of
   "who has what access":
   - **Campaign model**: `Campaign{ID, Name, Scope, Certifiers[], StartAt,
     EndAt, Status}` — scope is a query over the permissions assignments
   - **Certification tasks**: For each (user, resource, role) triple, the
     certifier chooses: `certify` (approved), `revoke` (remove access),
     `reassign` (move to another user), `don't know` (escalates to another
     certifier)
   - **Remediation**: On `revoke`, the system automatically removes the
     permission assignment, revokes active sessions (via CAEP), and logs
     `access_certification_revoked` + `session_revoked` events
   - **Re-certification**: Periodic campaigns (quarterly, yearly) can be
     auto-generated based on the previous campaign's template

2. **Entitlement Catalog** — A searchable registry of all permission-requiring
   resources across the org:
   - Auto-discovered from `Client.AllowedScopes`, `permissions.Role`, and
     `tokenpolicy.Policy`
   - Each entry: `{ResourceID, Name, Description, Owner, RiskLevel, RequiredIAM}`
   - Risk level (low/medium/high/critical) determines campaign frequency and
     certification requirements

3. **Separation-of-Duty (SOD) Policies** — Preventive + detective controls:
   - `SODRule{ID, Name, ConflictingRoles[][]string, Description, Enforcement
     (preventive|detective)}`
   - Preventive: `AssignRole` checks for conflict → rejects if forbidden
     combination would result
   - Detective: Periodic check alerts on existing conflicts (does not auto-revoke
     for detective mode — just reports)
   - Audit events: `sod_violation_detected`, `sod_violation_prevented`

4. **Certification Report / Compliance Export** — Standardized report format
   (PDF, CSV) showing: campaign scope, participation rate, certification
   decisions, overdue items, SOD violations. Exportable for auditor review.

### Edge Cases

- **Delegated certification** — A certifier can delegate their tasks to another
  user (with audit trail of the delegation).
- **Certifier leaves the org** — If the assigned certifier is deactivated or
  deleted, the campaign MUST reassign their outstanding tasks to the next
  available certifier or escalate to the global admin.
- **Emergency access** — Break-glass/impersonation sessions are flagged IN the
  certification report but are NOT subject to revocation by the campaign tool
  (only the break-glass initiator or global admin can terminate them).
- **Large campaigns** — For orgs with 10k+ users and 500+ roles, the
  certification task list must be paginated, filterable, and support bulk
  operations (certify all, revoke all).

### Sequencing & Effort

| Step | Effort | Independent | Prerequisites |
|---|---|---|---|
| Campaign model + store SPI + memory/sqlite/postgres | L | Yes | — |
| Certification task generation engine | M | After store | — |
| Remediation executor (revoke access + sessions) | M | After engine | CAEP bus, lifecycle reactions |
| Org Admin UI for campaigns | L | After engine | Direction 4 (org admin API) |
| Entitlement catalog | M | Parallel with store | — |
| SOD policy engine (preventive + detective) | L | Independent | Permission assignment hooks |
| Compliance report generator | S | After campaign | — |

**Total: XL** (but SOD + campaigns are two independent tracks)

---

## Summary Priority Matrix

| Direction | Customer Signal | Market Adjacency | Architectural Leverage | Effort | Verdict |
|---|---|---|---|---|---|
| **1. KYC/IDV Pipeline** | Regulated vertical RFP requirement | Persona/Onfido/Veriff (complement) | Adds `verified_claims` to existing ID Token | XL | High value for regulated B2B; prerequisite for financial/health verticals |
| **2. Directory Sync** | #1 enterprise migration blocker | Azure AD Connect/Google Cloud Directory Sync (replacement) | Uses existing SCIM + LDAP + connection stores | XL | Highest enterprise migration ROI; unblocks 5k+ user deployments |
| **3. Auth Proxy** | Proven OSS demand (OAuth2 Proxy 20k★) | Pomerium/Authentik/Cloudflare Access (replacement) | Leverages full OIDC + CAEP + introspection stack | L | Quickest time-to-market; creates a standalone product |
| **4. Org Admin Console** | B2B SaaS buyer expectation | Auth0 Organizations/WorkOS Dashboard (replacement) | Builds on existing tenant + connection infrastructure | XL | Required for B2B self-service but large investment |
| **5. Access Certification** | SOC2/HIPAA/SOX buyer requirement | SailPoint/Okta IGA (niche replacement) | Leverages full permissions + lifecycle + CAEP stack | XL | Higher ACV product; complements direction 4 |

### Short-term recommendation (next 90 days)

> **Direction 3 (Auth Proxy)** for quickest market differentiation + **Direction 2
> (Directory Sync) connector for Azure AD** as the highest-signal enterprise
> feature. Both can start independently. Direction 3 is a separate binary
> that proves the SSO's value for non-Go consumers; Direction 2's Azure AD
> connector is the single most-requested integration in B2B SSO procurement.
>
> Directions 1, 4, and 5 are XL efforts that depend on existing infra maturity
> and should be sequenced after the above two land and generate revenue signal.
