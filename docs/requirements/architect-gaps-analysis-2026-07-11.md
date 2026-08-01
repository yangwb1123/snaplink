# Gaps Analysis: 5 High-Value Extension Directions

> **Analyst:** Codebase scan + architecture review  
> **Date:** 2026-07-11  
> **Method:** Full global scan of 2241 `.go` files, 1114 test files, 14 nested `go.mod` modules,  
>   200+ packages, plus review of 30+ existing analysis documents in `docs/requirements/`.  
>   Each direction below was verified against both the codebase AND all existing  
>   analysis documents to confirm it is genuinely not implemented and not extensively  
>   analyzed in prior work.

---

## Preamble: Project Maturity Context

This project has achieved an exceptional level of capability coverage. It has:

| Domain | Coverage |
|---|---|
| **OAuth 2.0** | All major grants (auth code, client creds, refresh, device, CIBA, token exchange, PAR/JAR/JARM/RAR), DPoP, mTLS, PKCE, OAuth 2.1 strict mode, FAPI 2.0 |
| **OIDC** | Core, Discovery, RP-Initiated Logout, BCL/FCL, Session Management, Form Post, JWE, Silent Renewal, Step-Up (RFC 9470) |
| **SAML 2.0** | SP + IdP + SLO (nested module) |
| **SCIM 2.0** | Bidirectional + push provisioning |
| **CAEP/SSF** | Bidirectional transmitter + receiver |
| **WebAuthn** | Registration, authentication, passwordless primary login, attestation policy, self-service passkey registration |
| **Security** | Anti-enumeration (9 endpoint patterns), oracle-leak (10 scenarios), DPoP/mTLS/JKT, FAPI 2.0 enforce, break-glass (2-person + impersonation), per-tenant signing isolation, data residency, FIPS 140-3, session trust decay, conditional access, anomaly detection (4 detectors + Threat Action engine), account lockout, CSP Level 3 |
| **Storage** | Memory, SQLite, PostgreSQL, Redis, etcd, 14 nested modules (KMS×5, SAML×4, LDAP, Kerberos, RADIUS, ext_authz, Kafka, MQTT, Vault Transit) |
| **Operations** | DR framework (snapshot/RPO/RTO/replication), SIGHUP hot-reload (7 feature gates), Prometheus/Grafana (80+ metrics, 16 alerts), audit hash-chain, OTel tracing, pprof, k6 load tests, chaos tests (×4), K8s operator (SSOConfigDrift CRD), Terraform, Helm |
| **Product** | Hosted login SPA, Admin Console SPA (full CRUD), Developer Portal SPA, User Portal (/me), consent store, B2B enterprise connections, API docs viewer, SDK generation (TS + Python), MCP Server |

The 5 directions below are **not** covered by the 30+ existing analysis documents (v1–v7),  
are **not** in the deferred backlog, and have **zero** code implementation. They represent  
genuine, high-value expansion opportunities at the intersection of identity protocols,  
operational quality, and developer/user experience.

---

## Direction 1: OAuth 2.0 Token Status List (JWT Token Status)

> **Impact:** High — enables stateless token revocation awareness for Resource Servers  
> **Effort:** Medium (2–3 weeks)  
> **Risk:** Low — well-defined emerging IETF spec (draft-ietf-oauth-status-list)

### Current State

The project supports two revocation-awareness mechanisms for resource servers:

1. **`/token/introspect` (RFC 7662)** — every RS calls back to the AS per-request.
   Adds latency, AS load, and requires RS-to-AS connectivity.
2. **JWT `exp` claim** — stateless but cannot express revocation between minting and expiry.
   A revoked token remains valid until natural expiration.

**Neither mechanism helps a stateless RS determine whether a JWT access token has been revoked between `iat` and `exp` without calling introspection.**

### What Is Missing

There is **zero** code support for the OAuth 2.0 Token Status List pattern (as described in
`draft-ietf-oauth-status-list`). This pattern allows the authorization server to mint a
signed JWT status list (a bitfield mapping `jti` → revoked/valid) and serve it at a
well-known endpoint. Resource servers fetch and cache this list locally, checking token
liveness without per-request AS calls:

```
RS flow:
  1. Boot: GET /.well-known/oauth-status-list → signed JWT status list
  2. Cache: verify signature, decode bitfield
  3. Per-request: lookup token's position in the bitfield → valid/revoked
  4. Re-fetch: when the status list expires (exp claim), or on-demand via webhook
```

This is complementary to introspection — an RS can check the status list first (fast,
local, no AS load), then fall back to introspection for a definitive answer in edge cases.

### Concrete Code Gaps

| Area | What exists | What's missing |
|---|---|---|
| `protocols/oauth/` | Introspection (RFC 7662) + signed introspection (RFC 9701) | Status list issuer + verifier |
| `interfaces/sso/server_discovery.go` | OIDC Discovery, AS Metadata, signed_metadata | `status_list_endpoint` in discovery |
| `interfaces/sso/handlers.go` | Token, Introspect, Revoke handlers | `/.well-known/oauth-status-list` handler |
| `defaultimpl/` | Ed25519/ECDSA/RSA JWT issuers | Status list signer (reuses existing issuers) |
| `shared/core/` | JWT claim constants | Status list claim constants (`exp`, `jti`, `status_list`) |
| `interfaces/ssoclient/rs/` | Token validation (signature, exp, DPoP, mTLS) | Status list fetcher + cache + lookup |

### Edge Cases

| Edge case | Handling |
|---|---|
| Status list expired but no fresh one available | RS falls back to `/token/introspect` (degrade gracefully, never fail-open) |
| Status list signed with a different key than the JWKS `use=sig` | Reject the list; RS uses `kid` linkage to the same JWKS, using `use=statuslist` or a dedicated claim |
| Token not in status list bitfield | Treat as valid (bitfield entries are sparse; absence means "not revoked") |
| High-frequency token revocation storm | Status list `exp` can be shortened; RS poll intervals adapt via `Cache-Control: max-age` |
| Clock skew between AS and RS | Status list `nbf` accepts a configurable tolerance (default 30s, same as existing JWT verification) |

### Value Proposition

- Eliminates introspection callback for the majority of RS deployments
- Reduces AS load by orders of magnitude in high-traffic deployments
- Enables offline token liveness for edge/lambda/cloud-function RS deployments
- Works alongside existing introspection (not a replacement)

---

## Direction 2: OAuth 2.0 TLS Token Binding (RFC 8471/8472)

> **Impact:** Medium-High — defense-in-depth for token credential theft prevention  
> **Effort:** Medium (2–3 weeks)  
> **Risk:** Low — complementary to existing DPoP support

### Current State

The project supports two proof-of-possession mechanisms:

1. **DPoP (RFC 9449)** — application-layer binding using JWK thumbprint in `cnf.jkt`.
   Requires client support for DPoP headers.
2. **mTLS (RFC 8705)** — TLS-layer binding using `cnf.x5t#S256`. Requires mutual TLS.

**What is missing:** TLS Token Binding (RFC 8471, obsoleted by RFC 8472) provides a
third layer: binding the access token to the TLS connection itself using the
`TokenBinding` TLS extension. Unlike DPoP, it requires no application-level headers;
unlike mTLS, it does not require client certificates.

### What Is Missing

There is **zero** code support for TLS Token Binding. While the specification has
been superseded in parts by TLS 1.3's exported authenticator model, the concept of
binding tokens to TLS session parameters provides meaningful defense-in-depth:

| Mechanism | Layer | Client-side changes | Server-side complexity |
|---|---|---|---|
| DPoP (existing) | Application | Header injection | JKT validation |
| mTLS (existing) | TLS | Client certificate | TLS renegotiation |
| Token Binding (missing) | TLS | None (TLS extension) | Export key material |

For deployments where DPoP adoption is slow (e.g., legacy mobile SDKs, third-party
client libraries) and mTLS is operationally prohibitive, TLS Token Binding provides
a transparent proof-of-possession mechanism that works with any existing Bearer token
client.

### Concrete Code Gaps

| Area | What exists | What's missing |
|---|---|---|
| `interfaces/sso/server_token.go` | DPoP JKT + mTLS x5t#S256 binding | Token Binding ID extraction (`tls_unique` / `tls_export`) |
| `shared/security/` | JKT, x5t#S256 computation | Token Binding key computation (HKDF from TLS exported keying material) |
| `protocols/oauth/oauthspi/` | Token SPI interfaces | Token binding interface (`TokenBindingProvider`) |
| `interfaces/sso/options_security.go` | `WithDPoPNonceProvider`, `WithClientCertExtractor` | `WithTokenBinding(keyingMaterial)` |
| Discovery document | `dpop_bound_access_tokens`, `tls_client_certificate_bound_access_tokens` | `token_binding_bound_access_tokens` |

### Edge Cases

| Edge case | Handling |
|---|---|
| TLS 1.2 vs 1.3 key material format | Both supported via `tls_unique` (1.2) and `tls_export` (1.3) |
| Token Binding + DPoP double binding | Both checked independently; `cnf.jkt` AND `cnf.tbid` present — MUST match the corresponding proof on each layer |
| Load balancer TLS termination | Token Binding requires end-to-end TLS; document that TLS is NOT terminated at the LB, or use the `backend-to-backend` TLS binding variant |
| Connection reuse (HTTP keep-alive) | Token Binding ID is connection-scoped, not request-scoped; handle via connection migration |

### Value Proposition

- Transparent protection for existing Bearer-only clients (no app changes)
- Defense-in-depth alongside DPoP and mTLS
- Bridges the gap between "legacy bearer token" and "fully bound" deployments
- Aligns with enterprise zero-trust networking patterns

---

## Direction 3: WebAuthn Passkeys Lifecycle Management — Credential Management Protocol (CMP) & Cross-Device Passkeys

> **Impact:** High — unlocks consumer-grade passkeys UX for enterprise SSO  
> **Effort:** Large (4–6 weeks)  
> **Risk:** Medium — evolving browser/platform APIs

### Current State

The project supports:

- WebAuthn credential registration and authentication
- Passwordless primary login flow
- Self-service passkey registration (`/me/mfa`)
- WebAuthn attestation policy + MDS trust
- Attestation conveyance preferences

**What is missing:** Support for the W3C WebAuthn Credential Management Protocol (CMP),
Conditional UI (autofill-based passkeys), PRF extension, largeBlob extension, and
cross-device passkey synchronization lifecycle. These are the features that make
passkeys actually usable for end users.

### What Is Missing

| Capability | Code status | User impact |
|---|---|---|
| **Conditional UI** (`navigator.credentials.get({mediation: 'conditional'})`) | Not supported | Users must tap a "Sign in with passkey" button; no autofill |
| **PRF extension** (password-equivalent for passkeys) | Not supported | No deterministic passkey-to-password binding for account recovery |
| **largeBlob extension** (encrypted data on credential) | Not supported | No portable user data alongside passkey |
| **Cross-device credential sync** (platform-managed) | Out of scope (platform concern) | Document expected platform behavior vs. server-enforced policy |
| **Credential Protection** (`credProps`) | Not supported | Server cannot distinguish platform vs. cross-platform, single-device vs. multi-device cred |
| **Backup Eligibility / Backup State** | Not supported | Server cannot reason about credential availability after device loss |
| **Credential Management Protocol** (CMP — `credential management/get`, `credential management/store`) | Not supported | No standardized way for RPs to enumerate/manage user credentials across devices |

### Concrete Code Gaps

| Area | What exists | What's missing |
|---|---|---|
| `domains/authenticators/webauthn/` | Registration, auth, attestation | Conditional UI mediation parameter, PRF extension data |
| `domains/authenticators/webauthn/conditional_login.go` | Passwordless primary auth | The client-side `mediation: 'conditional'` flow is not yet integrated; the server must advertise `conditional_mediation: true` in its client-facing API |
| `domains/authenticators/webauthn/handlers.go` | `/webauthn/registration/begin`, `/webauthn/registration/finish` | No `credProps` parsing, no backup eligibility/state enforcement |
| `interfaces/sso/options_passwd.go` | `WithWebAuthnRegistrar` | No `WebAuthnRPRKPolicy` (resident key enforcement), no `WebAuthnCMP` option |
| `interfaces/web/login/` | Login SPA | No Conditional UI JavaScript (just a button-based flow) |
| Discovery | — | No `conditional_mediation` advertisement |

### Edge Cases

| Edge case | Handling |
|---|---|
| User has multiple passkeys on different devices | `allowCredentials` sent by server; RP filters by credential ID |
| Passkey synced to new device via platform (iCloud Keychain, Google Password Manager) | Back-up eligible flag (`credProps.rk`) tells server the credential can survive device loss |
| User lost device with sole passkey | Server MUST fall back to alternative authenticator (password, recovery code). Document as required UX pattern |
| PRF extension for deterministic password binding | PRF outputs are per-RP, per-credential, cryptographically bound; server stores PRF salt, client computes PRF value during assertion |
| CMP credential enumeration across origins | CMP is origin-scoped; only credentials registered with THIS RP are visible |

### Value Proposition

- Passkeys are the defined future of passwordless auth (Apple, Google, Microsoft)
- Enterprise SSO with passkeys unlocks consumer-grade UX = higher adoption, lower support costs
- Conditional UI eliminates the password field entirely — the single best UX improvement available
- PRF extension enables secure password-equivalent recovery without storing passwords

---

## Direction 4: Testing Quality Infrastructure — Property-Based Testing & Mutation Testing Framework

> **Impact:** High — catches edge cases traditional tests miss in security-critical code  
> **Effort:** Medium (2–4 weeks for initial rollout, ongoing)  
> **Risk:** Low — additive, no changes to production code

### Current State

The project has exceptional test quantity:

- **1114 test files** across the codebase
- **9 fuzz test files** (`*_fuzz_test.go`)
- **4 chaos test files** (`test/chaos/`)
- **5 benchmark test files**
- **Conformance suites** for permissions backends
- **E2E integration tests** in `test/` (cross-wired HTTP + JWKS + bufconn)

However, there are significant **qualitative** gaps:

| Gap | Impact | Example |
|---|---|---|
| **Zero property-based tests** | No systematic edge-case discovery for token validation, bind params, auth code exchange, session management | `rapid.Check` / `gopter` would find `BindParams` edge cases that hand-written tests miss |
| **Zero mutation testing** | No way to measure test quality — do existing tests actually catch real bugs? | A mutant that removes a security check (`if err != nil { return }` → never return) might survive |
| **No coverage budgets** | No committed minimum coverage per critical package | Security-sensitive packages (`security/`, `oauth/`, `oidc/`) could drop coverage silently |
| **Only 9 fuzz tests** | Limited fuzz coverage for 200+ packages | JWT parsing, SAML assertion, SCIM payload, federation metadata all unfuzzed |
| **Limited chaos scenarios** | Only 4 chaos tests (clock jump, JTI replay, panic recovery, refresh rotation) | No network partition, slow backend, disk-full, OOM, or config-corruption chaos scenarios |

### Concrete Code Gaps

| What exists | What's missing |
|---|---|
| Hand-written unit tests per package | `rapid.Check` property tests for: (a) JWT round-trip (issue → verify → claims match), (b) auth code single-use invariant, (c) refresh family rotation invariant, (d) `BindParams` arbitrary form/JSON equivalence |
| Fuzz tests: `bind_fuzz`, `jar_fetch_fuzz`, `jwks_verify_fuzz`, `jws_parse_fuzz`, `dcr_fuzz`, `end_session_fuzz`, `aud_claim_fuzz`, `jwe_unwrap_fuzz` | Fuzz tests for: SAML assertion parsing, SCIM payload parsing, federation metadata parsing, token policy evaluation, conditional access rule matching, OpenAPI/JSON parsing, i18n locale matching |
| — | Mutation testing framework (e.g., `go-mutesting`): weekly CI job that reports mutation score per critical package, with a committed floor (e.g., 70%) |
| — | Coverage budgets per package: `shared/security` ≥ 90%, `protocols/oauth` ≥ 85%, `protocols/oidc` ≥ 85%, `domains/` ≥ 80% (enforced in CI) |
| Chaos: clock jump, JTI replay, panic recovery, refresh rotation | Chaos: (a) network partition between replicas, (b) slow/latent storage backend, (c) disk-full on backup path, (d) config-corruption / partial SIGHUP, (e) concurrent sign-out during audit drainage |
| — | Fuzz test CI gate: every new function that parses external input MUST have a corresponding fuzz corpus entry |

### Edge Cases

| Edge case | Handling |
|---|---|
| Fuzz test found a nil-deref in `BindParams` with malformed JSON | CVE-level severity; triaged within SLA |
| Mutation test reveals an "unused" error check in the auth code exchange | The mutant removes the error check and all tests still pass — the code path is dead or poorly tested |
| Property test discovers a race in `sync.Map` usage during concurrent session creation | The property's `rapid` shrink minimizes the reproduction, making the fix trivial |
| Coverage drops below budget due to refactoring | CI fails before merge; coverage budget threshold is documented and actionable |

### Value Proposition

- **Property-based tests** discover edge cases that hand-written tests systematically miss — especially in parameter parsing, token validation, and state machine transitions
- **Mutation testing** reveals untested code paths and dead code — every survivor is either a test gap or dead code to remove
- **Coverage budgets** prevent silent quality regression as the codebase grows
- For a security-critical identity project, test quality is a **direct security control**

---

## Direction 5: OAuth 2.0 First-Party / Third-Party Client Classification & Application-Type Enforcement

> **Impact:** Medium — closes a real security gap in client registration and consent UX  
> **Effort:** Small (1–2 weeks)  
> **Risk:** Low — additive, backward-compatible

### Current State

The project supports dynamic client registration (RFC 7591/7592), consent management,
and scope descriptions. However, there is **no** concept of **first-party vs. third-party
client classification** — a fundamental distinction in OAuth 2.0 security models:

| Aspect | First-party client | Third-party client |
|---|---|---|
| **Ownership** | Same organization as the AS | External organization/individual |
| **Consent UX** | Optional (skip for trusted apps) | Required |
| **Scope restrictions** | Full scope access | Restricted scope access |
| **Token lifetime** | Standard | Reduced |
| **Refresh token** | Granted | May be denied |
| **Audience** | Internal services | External apps |

**What is missing:** The ability to classify a registered client as first-party or
third-party, and enforce distinct security policies based on that classification.

### What Is Missing

| Capability | Code status | User impact |
|---|---|---|
| `application_type` classification (`web`, `native`, `spa` vs. first-party flag) | Not supported | All clients treated equally — no differentiated consent UX |
| First-party consent bypass | Not supported | Users must consent even for internal, organization-owned apps |
| Third-party scope restriction | Not supported | A third-party app can request any scope the client allows |
| Third-party token lifetime reduction | Not supported | Third-party tokens live as long as first-party tokens |
| `software_id` / `software_version` (RFC 7591) | Registered but not enforced | No software identity verification for DCR clients |
| `logo_uri` / `policy_uri` / `tos_uri` display in consent UI | Not implemented | End users cannot make informed consent decisions |

### Concrete Code Gaps

| Area | What exists | What's missing |
|---|---|---|
| `protocols/oauth/handle_register.go` | DCR client creation | `application_type` validation, first-party flag, `software_id` enforcement |
| `interfaces/sso/options_passwd.go` | `WithConsentStore`, `WithScopeDescriptions` | `WithFirstPartyClients(clientIDs...)`, `WithThirdPartyScopeRestrictions(restrictions...)` |
| `interfaces/sso/server_logout.go` | `handleConsentGate` | Skip consent for first-party clients; enforce consent for third-party |
| `interfaces/web/developer/` | Developer portal SPA | Show policy_uri / tos_uri on register page |
| `interfaces/web/login/` | Login SPA (with consent screen) | Consent screen displays app name, logo_uri, policy_uri, tos_uri; differentiate first-party vs. third-party via badge/label |
| `shared/core/` | Client struct | `IsFirstParty` field, `ApplicationType` field, `SoftwareID` field |

### Edge Cases

| Edge case | Handling |
|---|---|
| First-party flag set on registration but client is external | Enforced at server level; first-party flag is SET by operator (static client config), not by DCR |
| Third-party app requests admin scope | `admin:read` / `admin:write` scopes are first-party-only; third-party requests receive `invalid_scope` |
| Consent was granted to third-party, but first-party later registered same scope | Existing consent is NOT reused — first-party bypass is independent of consent store |
| `software_id` reuse across registration | Same `software_id` on multiple DCR clients = same software identity (group policies apply together) |

### Value Proposition

- **Security**: Third-party scope restriction prevents external apps from accessing admin/admin-like scopes
- **UX**: First-party consent bypass eliminates unnecessary consent screens for internal apps
- **Transparency**: `policy_uri` / `tos_uri` / `logo_uri` in consent UI enables informed consent
- **Compliance**: `software_id` tracking enables software-level audit and policy enforcement
- **Backward compatibility**: All existing clients default to "third-party" (no policy change), first-party is opt-in

---

## Summary: Priority & Sequencing

| Direction | Impact | Effort | Risk | Sequence |
|---|---|---|---|---|
| **5. First/Third-Party Client Classification** | Medium | Small | Low | **P0 — quick win**; small, contained change with immediate security benefit |
| **4. Testing Quality Infrastructure** | High | Medium | Low | **P1 — foundational**; enables safe refactoring for all other directions |
| **1. Token Status List** | High | Medium | Low | **P2 — protocol feature**; significant RS UX and AS load benefit |
| **2. TLS Token Binding** | Medium-High | Medium | Low | **P3 — defense-in-depth**; lower urgency while DPoP and mTLS cover the majority of deployments |
| **3. Passkeys Lifecycle (CMP)** | High | Large | Medium | **P4 — UX evolution**; highest user-facing impact but depends on platform adoption of CMP and Conditional UI |

### Recommended Incremental Approach

1. **Start with Direction 5** (1 week) — add `application_type` / `IsFirstParty` to
   client struct, skip consent for first-party, restrict third-party scopes. This is
   contained, backward-compatible, and provides immediate security value.

2. **Layer Direction 4** alongside ongoing feature work (2–4 weeks, ongoing) —
   introduce property-based tests for critical packages first (`security/`, `oauth/`),
   add fuzz tests for unfuzzed parsers, wire mutation testing as a weekly CI job.
   This pays for itself through every subsequent direction by catching regressions.

3. **Build Direction 1** as the next protocol feature (2–3 weeks) — reuses existing
   JWT issuers and JWKS infrastructure, provides a clear RS-side benefit.

4. **Implement Direction 2** when DPoP/mTLS coverage analysis shows gaps (2–3 weeks) —
   useful for deployments that cannot adopt DPoP (legacy SDKs) or mTLS (operational cost).

5. **Pursue Direction 3** when the WebAuthn CMP specification stabilizes and browser
   support reaches critical mass (4–6 weeks) — the highest user-facing impact but
   depends on ecosystem maturity.

---

*This document is based on a thorough scan of the entire codebase and comparison
against all existing analysis documents in `docs/requirements/`. Each direction
has been verified to have zero code implementation and minimal analytical coverage
in prior work.*
