# Security Architecture Reference

> **Security policy (SLA, reporting, scope):** [`.github/SECURITY.md`](../.github/SECURITY.md).
> This document is the technical architecture companion — it documents hardened
> areas, fail-open/closed decisions, developer and operator checklists, and maps
> each security mechanism to its implementing package path.

---

## 1. Security Architecture Overview

The SSO server follows a layered architecture where security mechanisms are
applied at specific boundaries:

```
Client Request
     │
     ▼
┌─────────────────────┐
│  Middleware          │  ← TLS, rate-limit, CORS, tracing, geo
│  (interfaces/sso)    │     X-Forwarded-For trust model
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  AuthN/AuthZ        │  ← Authenticators, client auth, consent
│  (interfaces +      │     Oracle-leak response shaping
│   domains)          │
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Token Issuance     │  ← JWT/JWE, session, refresh rotation
│  (interfaces +      │     RFC 9068 claims, at_hash
│   protocols + infra)│
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Async Detection    │  ← Anomaly detector, token anomaly
│  (domains/anomaly,  │     Threat executor (Active ITDR)
│   domains/threataction)
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Audit / Webhook    │  ← Tamper-evident audit chain, CAEP/SSF
│  (platform/audit)   │     Fail-open recorder
└─────────────────────┘
```

The AuthN/AuthZ boundary spans request/client-auth orchestration in
`interfaces/sso` and end-user/policy capabilities in `domains/*`. Token
issuance spans `internal/handler/tokengrant`, `protocols/oauth`, and concrete
issuers in `infrastructure/defaultimpl`; `shared/core` defines their SPIs and
wire types rather than issuing tokens itself.

### Threat Model (Brief)

- **Primary trust boundary**: the IdP process boundary. Every component within
  the same process is equally trusted — compartmentalization is at the package
  level (layered imports, no upward dependency from protocols → interfaces).
- **Data in transit**: TLS is mandatory for all production deployments. When
  enabled and enforced, DPoP provides sender-constraint for bearer tokens.
- **Data at rest**: password and client credentials are hashed by their
  stores, and snapshots can be sealed. Active opaque OAuth artifacts are a
  separate risk: SQLite refresh tokens, authorization codes and device codes
  are currently stored as lookup keys, so database/Redis backups must be
  protected as bearer-secret material. Snapshot encryption does not encrypt a
  live backend.
- **Side channels**: timing side channels mitigated via bcrypt constant-time
  comparison; anti-enumeration prevents user/credential oracle leaks.

---

## 2. Hardened Areas

| Area | Mechanism | Package / File |
|---|---|---|
| Token consumption | Store-level atomic consume; SQLite uses `DELETE … RETURNING` for single-use artifacts | `infrastructure/defaultimpl/sqlite/auth_codes.go`, `infrastructure/defaultimpl/sqlite/refresh_tokens.go`, `infrastructure/defaultimpl/sqlite/device_codes.go`, `infrastructure/defaultimpl/sqlite/par.go` |
| Refresh token rotation | FamilyID + DeleteFamily on reuse | `internal/handler/tokengrant/token_refresh.go`, `protocols/oauth/oauthspi/refresh_token.go` |
| Anti-enumeration (bcrypt) | Cost-matched dummy hash for unknown users | `domains/authenticators/stored_hash_dummy_cost_test.go`, `domains/authenticators/stored_hash_verifier.go` |
| Anti-enumeration (WebAuthn) | 404 `session_invalid` on unknown user/session | `domains/authenticators/webauthn/` |
| Oracle-leak (auth code / refresh) | Unified error for unknown/expired/consumed/mismatch → `invalid_grant` | `internal/handler/tokengrant/token_authcode.go`, `internal/handler/tokengrant/token_refresh.go` |
| Oracle-leak (PAR) | `invalid_request_uri` for stale/missing `request_uri` | `interfaces/sso/server_login_resolve.go` |
| Oracle-leak (client) | `invalid_client` on `private_key_jwt` failure | `interfaces/sso/server_token_clientauth.go`, `interfaces/sso/server_pairwise.go` |
| Credential endpoints | `Cache-Control: no-store` + `Pragma: no-cache` | `interfaces/sso/server_extensions.go` |
| 401 responses | `WWW-Authenticate: Bearer` with `setBearerChallenge` | `interfaces/sso/server_extensions.go` |
| JWT algorithms | Allowlist only: EdDSA, ES256/384/512, RS256, PS256; `alg=none` banned | `shared/security/securityverify/jwks_verify.go` |
| Private key JWT | Verified with `AsymmetricJWSAlgs` before signature verification | `interfaces/sso/server_pairwise.go`, `shared/security/securityverify/jwks_verify.go` |
| DPoP | Optional nonce and JTI replay protection when their providers/stores are wired | `interfaces/sso/server_dpop.go` |
| JAR URL fetch | HTTPS-only, redirect-free, bounded and dial-time SSRF guarded | `shared/security/securityverify/jar_fetch.go` |
| SPIFFE | Strict audience + trust-domain validation | `shared/security/securityverify/spiffe_svid.go` |
| PKCE | S256 enforced at `/auth/login` in strict mode; verifier checked at `/token` | `interfaces/sso/server_finish_login.go`, `internal/handler/tokengrant/token_authcode.go` |
| Session refresh | Refuses expired/revoked sessions before extending | `infrastructure/defaultimpl/memorystoreidentity/memory_session.go`, `infrastructure/defaultimpl/sqlite/sessions.go`, `infrastructure/redis/session.go`, `infrastructure/postgres/session.go` |
| CAEP/SSF receiver | FAIL-CLOSED signature/issuer/audience/expiry/JTI validation | `protocols/caep/receiver.go` |
| CAEP/SSF outbound delivery | Reads stored client metadata, re-validates HTTPS before delivery; gRPC client writes validate it on create/update | `protocols/caep/broadcaster_retry.go`, `interfaces/grpcserver/grpcadmin/admin_clients.go` |
| Federation trust chain | FAIL-CLOSED; anchor keys NEVER fetched | `domains/federation/trust_chain.go` |
| Active ITDR | Off-path threat executor (session suspend, token revoke, MFA step-up) | `domains/threataction/` |

---

## 3. Fail-Open vs Fail-Closed Decision Matrix

| Component | Behavior | Rationale | Package |
|---|---|---|---|
| Audit sink error | Fail-open | Do not block auth for logging | `platform/audit/async_sink.go` |
| Geo enrichment | Fail-open | UX hint, not security | `platform/geo/` |
| Risk scorer error | Fail-open | Deny all could DoS | `shared/spi/risk.go` |
| Tenant suspension check | Fail-open | Outage should not block all auth | `domains/tenant/` |
| JTI replay store error | Fail-open (default) | Oracle-safe; `security.jti_replay.fail_closed` opts in | `shared/security/jti_replay.go`, `interfaces/sso/options_security.go` |
| Initial/auxiliary refresh issuance | Fail-open | Do not discard an otherwise valid access-token response | `interfaces/sso/server_finish_login.go`, `internal/handler/tokengrant/token_authcode.go`, `internal/handler/tokengrant/token_device.go`, `internal/handler/tokengrant/token_ciba.go`, `internal/handler/tokengrant/token_exchange_stages.go` |
| Anomaly detection runner | Fail-open | Never block login for detection | `domains/anomaly/runner.go` |
| Threat executor (ITDR) | Fail-open | Logged and audit-recorded; action failure never escalates onto the auth path | `domains/threataction/executor.go` |
| Signature validation | **Fail-closed** | Must not accept invalid tokens | `shared/security/securityverify/` |
| Scope expansion | **Fail-closed** | Must not grant unauthorized scopes | `internal/handler/tokengrant/token_refresh.go`, `internal/handler/tokengrant/token_exchange_stages.go` |
| Refresh family reuse | **Fail-closed after grace** | A concurrent double-submit inside the configured grace window replays its successor; later reuse triggers DeleteFamily + `invalid_grant` | `internal/handler/tokengrant/token_refresh.go`, `internal/handler/tokengrant/refresh_grace.go`, `protocols/oauth/oauthspi/refresh_token.go` |
| Federation trust chain | **Fail-closed** | Must not accept untrusted chains | `domains/federation/trust_chain.go` |
| CAEP/SSF receiver | **Fail-closed** | Must not accept unverified security events | `protocols/caep/receiver.go` |
| Session creation (suspended tenant) | **Fail-closed** | Must not mint tokens for suspended tenant | `interfaces/sso/server_tenant.go` |

---

## 4. Developer Security Checklist

Before submitting code, verify each item. Entries marked `[auto]` are
enforced by CI; `[manual]` must be verified by code review or manual
testing. `[diagnostic]` checks are useful presence scans, not proof that
every relevant call site is correct.

- [ ] `tokenNoStoreHeaders(ctx)` on every credential/bearer endpoint `[manual + diagnostic]` (`make check-invariants` confirms repository-wide marker presence only)
- [ ] `setBearerChallenge(ctx, ...)` on every 401 `[manual + diagnostic]` (`make check-invariants` confirms repository-wide marker presence only)
- [ ] Oracle-leak: unknown/expired/consumed/mismatch → one response `[manual]`
- [ ] Anti-enumeration: bcrypt dummy hash for unknown users `[manual]`
- [ ] Audit: `SetMeta(e, k, v)`, never `e.Metadata = map{...}` `[manual]`
- [ ] No mocks in tests — use `Memory*` implementations `[manual]`
- [ ] Error codes documented in `docs/error-codes.md` `[auto]` (`go test ./docs/docscheck/ -run TestErrorCodesDocumented`)
- [ ] Endpoint changes documented in `docs/openapi.yaml` `[manual]`
- [ ] `go build ./...` + `go vet ./...` passes `[auto]` (`make ci`)
- [ ] Architecture gates: `go test -run 'TestArchitecture_|TestMaintainability_' .` passes `[auto]` (`make ci`)
- [ ] File ≤ 500 lines; function ≤ 50 lines; cyclo ≤ 15 `[auto]` (`make ci`; `make filesize && make complexity` provide supplementary diagnostics)
- [ ] No TODO/refactor debt — refactor immediately `[manual]`
- [ ] New `Err*` constant → update `docs/error-codes.md` in same commit `[auto]` (`go test ./docs/docscheck/ -run TestErrorCodesDocumented`)
- [ ] New package classified in `architecture_layer_test.go` `[auto]` (`make architecture`)
- [ ] RFC 9207 `iss` — every `/auth/login` response uses `s.resolveIssuer(ctx)` `[manual]`
- [ ] `aud` claim handles string or array; marshals single-aud compact `[auto]` (`make ci`)
- [ ] DPoP/mTLS failure → `invalid_token` `[manual]`
- [ ] `private_key_jwt` failure → `invalid_client` `[manual]`

---

## 5. Operator Deployment Security Checklist

When deploying `snaplink/sso`, verify each item. Default values are
shown in parentheses where applicable.

- [ ] **Disable `interfaces/ssoclient/dev`** outside of dev environments.
- [ ] **Config file permissions** — set `--config` to a file that is
      **not** world-readable. The deployment must set ownership explicitly;
      use mode `0640` or stricter and an account/group appropriate to the
      runtime.
- [ ] **Snapshot encryption** — use the `passphrase` backend in
      production (`none` is for tests only).
- [ ] **Backend backup confidentiality** — treat SQLite files, Redis
      RDB/AOF exports and Postgres backups as live credential material; the
      snapshot sealer does not protect them.
- [ ] **TLS termination** — front the HTTP listener with TLS (either
      via OpenResty / Envoy or `--tls-cert` + `--tls-key`).
- [ ] **Bootstrap lock** — set `bootstrap.lock` to `file` or `etcd`
      (never `noop`) when running multiple replicas.
- [ ] **Signing key rotation** — rotate every configured JWT signing key
      (Ed25519, ECDSA or RSA) at the cadence your compliance posture requires;
      the JWKS cache supports multiple active `kid`s for rolling rotation.
- [ ] **Audit log shipping** — wire the `audit.WebhookSink` or a
      custom `audit.Sink` to a tamper-evident store rather than
      relying on the in-process `MemorySink`.
- [ ] **CAEP/SSF receiver SSRF** — receiver endpoints are
      admin/registration-gated and validated https-only, but they are
      **not** SSRF-filtered — the transmitter will POST a signed SET
      to whatever https host is registered. Do **not** delegate writes
      to client `Attributes` to untrusted tenant admins.
- [ ] **Wall clock monotonicity** — slew, never step the clock on
      running nodes (use chrony, not periodic `ntpdate`/`hwclock`
      steps). A backward clock step can transiently resurrect
      just-expired sessions/tokens. DPoP/JWT iat-window skew is
      configurable via `--dpop-skew` (default: 30s).
- [ ] **Rate limiting** — configure `security.rate_limit` in the config file
      (default in-memory limiter; swap for Redis in multi-replica
      deployments).
- [ ] **Multi-replica JTI replay** — wire a shared JTI replay store
      (normally Redis) rather than the per-process memory store to prevent
      replay across replicas. Per-pod SQLite is not shared; a network
      filesystem does not make SQLite a recommended HA database.
- [ ] **External frontend boundary** — terminate TLS, cookies, CSP and
      clickjacking policy for separately deployed login/admin/self-service
      UIs at their frontend/edge. `sso-server` does not serve those assets.

---

## 6. Dependency Supply Chain Security

- **Module verification**: `go mod verify` runs in CI. Dependencies
  are pinned in `go.sum`.
- **Vulnerability scanning**: root and nested modules are covered by
  `govulncheck`/`gosec` jobs in `.github/workflows/ci.yml`; CodeQL and Trivy
  have separate workflows. Some scanners are report-only, so release review
  must inspect their findings rather than treating job success as “no CVEs.”
- **SBOM generation**: GoReleaser emits an SPDX-JSON SBOM per archive through
  Syft and publishes it with a successful release.
- **Nested modules**: KMS backends under `infrastructure/kms/*`, protocol
  bridges under `infrastructure/{saml,ldap,kerberos,radius,extauthz}`, and
  adapters such as `infrastructure/{kafka,mqtt}` have their own `go.mod` —
  their dependency trees are independently verified. Redis and Postgres are
  root-module packages, not nested modules.
