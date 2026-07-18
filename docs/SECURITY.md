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
│  (protocols/*)      │     Oracle-leak response shaping
└─────────┬───────────┘
          ▼
┌─────────────────────┐
│  Token Issuance     │  ← JWT/JWE, session, refresh rotation
│  (shared/core)      │     RFC 9068 claims, at_hash
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

### Threat Model (Brief)

- **Primary trust boundary**: the IdP process boundary. Every component within
  the same process is equally trusted — compartmentalization is at the package
  level (layered imports, no upward dependency from protocols → interfaces).
- **Data in transit**: TLS is mandatory for all production deployments. DPoP
  provides sender-constraint for bearer tokens.
- **Data at rest**: SQLite/etcd stores contain hashed credentials, encrypted
  snapshots. The `passphrase` encryption backend is the minimum for production.
- **Side channels**: timing side channels mitigated via bcrypt constant-time
  comparison; anti-enumeration prevents user/credential oracle leaks.

---

## 2. Hardened Areas

| Area | Mechanism | Package / File |
|---|---|---|
| Token consumption | `DELETE … RETURNING` — single-use enforced at DB level | `protocols/oauth/handle_token.go`, `protocols/oauth/authcode_store.go` |
| Refresh token rotation | FamilyID + DeleteFamily on reuse | `protocols/oauth/refresh_token.go`, `oauthspi/refresh_spi.go` |
| Anti-enumeration (bcrypt) | Cost-matched dummy hash for unknown users | `domains/authenticators/stored_hash_dummy_cost_test.go`, `domains/authenticators/stored_hash_verifier.go` |
| Anti-enumeration (WebAuthn) | 404 `session_invalid` on unknown user/session | `domains/authenticators/webauthn/` |
| Oracle-leak (token) | Unified error for unknown/expired/consumed/mismatch → `invalid_grant` | `protocols/oauth/handle_token.go` |
| Oracle-leak (PAR) | `invalid_request_uri` for stale/missing `request_uri` | `protocols/oauth/handle_par.go` |
| Oracle-leak (client) | `invalid_client` on `private_key_jwt` failure | `protocols/oauth/handle_token_clientauth.go` |
| Credential endpoints | `Cache-Control: no-store` + `Pragma: no-cache` | `interfaces/sso/server_helpers.go` (`tokenNoStoreHeaders`) |
| 401 responses | `WWW-Authenticate: Bearer` with `setBearerChallenge` | `interfaces/sso/server_helpers.go` |
| JWT algorithms | Allowlist only: EdDSA, ES256/384/512, RS256, PS256; `alg=none` banned | `shared/security/jws_allowlist.go` |
| Private key JWT | Verified with `AsymmetricJWSAlgs` BEFORE signature check | `protocols/oauth/handle_token_clientauth.go` |
| DPoP | Nonces + JTI replay prevention | `protocols/oauth/dpop.go`, `protocols/oauth/dpop_nonce.go` |
| JAR URL fetch | HTTPS-only, no-redirect, bounded | `protocols/oauth/jar.go` |
| SPIFFE | Strict audience + trust domain validation | `shared/security/spiffe.go` |
| PKCE | S256 enforced at `/auth/login`; verified at `/token` | `protocols/oauth/authcode.go`, `bind.go` |
| Session refresh | Refuses expired/revoked BEFORE extending; monotonic wall clock | `protocols/oauth/handle_refresh.go` |
| CAEP/SSF receiver | FAIL-CLOSED; jti-replay; endpoint validated at registration | `protocols/caep/receiver.go` |
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
| JTI replay store error | Fail-open (default) | Oracle-safe; `fail_closed: true` opts in | `protocols/oauth/jti_replay.go` |
| Refresh issuance | Fail-open | Availability over strict rotation | `protocols/oauth/handle_refresh.go` |
| Anomaly detection runner | Fail-open | Never block login for detection | `domains/anomaly/runner.go` |
| Threat executor (ITDR) | Fail-open | Logged + metr'c'd, never escalates | `domains/threataction/executor.go` |
| Signature validation | **Fail-closed** | Must not accept invalid tokens | `shared/security/` |
| Scope expansion | **Fail-closed** | Must not grant unauthorized scopes | `protocols/oauth/handle_token.go` |
| Refresh family reuse | **Fail-closed** | DeleteFamily + `invalid_grant` | `protocols/oauth/refresh_token.go` |
| Federation trust chain | **Fail-closed** | Must not accept untrusted chains | `domains/federation/trust_chain.go` |
| CAEP/SSF receiver | **Fail-closed** | Must not miss revocation signals | `protocols/caep/receiver.go` |
| Session creation (suspended tenant) | **Fail-closed** | Must not mint tokens for suspended tenant | `interfaces/sso/server_tenant.go` |

---

## 4. Developer Security Checklist

Before submitting code, verify each item. Entries marked `[auto]` are
enforced by CI (`make ci` or `make check-invariants`); `[manual]`
must be verified by code review or manual testing.

- [ ] `tokenNoStoreHeaders(ctx)` on every credential/bearer endpoint `[auto]` (`make check-invariants`)
- [ ] `setBearerChallenge(ctx, ...)` on every 401 `[auto]` (`make check-invariants`)
- [ ] Oracle-leak: unknown/expired/consumed/mismatch → one response `[manual]`
- [ ] Anti-enumeration: bcrypt dummy hash for unknown users `[manual]`
- [ ] Audit: `SetMeta(e, k, v)`, never `e.Metadata = map{...}` `[manual]`
- [ ] No mocks in tests — use `Memory*` implementations `[manual]`
- [ ] Error codes documented in `docs/error-codes.md` `[auto]` (`go test ./docs/docscheck/ -run TestErrorCodesDocumented`)
- [ ] Endpoint changes documented in `docs/openapi.yaml` `[manual]`
- [ ] `go build ./...` + `go vet ./...` passes `[auto]` (`make check-quick`)
- [ ] Architecture gates: `go test -run 'TestArchitecture_|TestMaintainability_' .` passes `[auto]` (`make architecture && go test -run 'TestMaintainability_' .`)
- [ ] File ≤ 500 lines; function ≤ 50 lines; cyclo ≤ 15 `[auto]` (`make filesize && make complexity`)
- [ ] No TODO/refactor debt — refactor immediately `[manual]`
- [ ] New `Err*` constant → update `docs/error-codes.md` in same commit `[auto]` (`go test ./docs/docscheck/ -run TestErrorCodesDocumented`)
- [ ] New package classified in `architecture_layer_test.go` `[auto]` (`make architecture`)
- [ ] RFC 9207 `iss` — every `/auth/login` response uses `s.resolveIssuer(ctx)` `[manual]`
- [ ] `aud` claim handles string or array; marshals single-aud compact `[auto]` (`go test ./protocols/oidc/ -run TestAudClaim -v`)
- [ ] DPoP/mTLS failure → `invalid_token` `[manual]`
- [ ] `private_key_jwt` failure → `invalid_client` `[manual]`

---

## 5. Operator Deployment Security Checklist

When deploying `snaplink/sso`, verify each item. Default values are
shown in parentheses where applicable.

- [ ] **Disable `ssoclient/dev`** outside of dev environments.
- [ ] **Config file permissions** — set `--config` to a file that is
      **not** world-readable (default: `0640`, owner `root`).
- [ ] **Snapshot encryption** — use the `passphrase` backend in
      production (`none` is for tests only).
- [ ] **TLS termination** — front the HTTP listener with TLS (either
      via OpenResty / Envoy or `--tls-cert` + `--tls-key`).
- [ ] **Bootstrap lock** — set `bootstrap.lock` to `file` or `etcd`
      (never `noop`) when running multiple replicas.
- [ ] **Signing key rotation** — rotate the JWT signing key (Ed25519)
      at the cadence your compliance posture requires; the JWKS cache
      supports multiple active `kid`s for rolling rotation.
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
- [ ] **Rate limiting** — configure `rate_limiting` in the config file
      (default in-memory limiter; swap for Redis in multi-replica
      deployments).
- [ ] **Multi-replica JTI replay** — wire a shared JTI replay store
      (Redis, SQLite with shared DSN) rather than the per-process
      memory store to prevent replay across replicas.

---

## 6. Dependency Supply Chain Security

- **Module verification**: `go mod verify` runs in CI. Dependencies
  are pinned in `go.sum`.
- **Vulnerability scanning**: `govulncheck` is run periodically (see
  `.github/workflows/security-scan.yml`).
- **SBOM generation**: `make sbom` produces a CycloneDX SBOM via
  `cyclonedx-gomod`. The SBOM is published with each release.
- **Nested modules**: KMS backends (`kms/`), protocol bridges
  (`saml/`, `ldap/`, `kerberos/`, `radius/`, `extauthz/`), and
  infrastructure adapters (`redis/`, `kafka/`, `mqtt/`) each have
  their own `go.mod` — their dependency trees are independently
  verified.
