# Security Policy

## Reporting a Vulnerability

This project handles authentication, authorization, and identity data. If you discover a security vulnerability, please report it privately.

**Do not** open a public GitHub issue for security vulnerabilities.

### How to Report

1. **Email**: security@snaplink.dev (preferred)
2. **PGP key**: Available at `https://snaplink.dev/.well-known/pgp-key.txt`

Include the following in your report:
- Type of vulnerability
- Steps to reproduce
- Affected versions/modules
- Potential impact
- Suggested fix (optional)

### Response Timeline

- **24 hours**: Acknowledgment of receipt
- **7 days**: Initial triage and severity assessment
- **30 days**: Fix deployed (for critical severity)
- **90 days**: Fix deployed (for low/medium severity)

## Security Architecture

### Hardened Areas

| Area | Mechanism |
|---|---|
| Token consumption | `DELETE … RETURNING` — single-use enforced at DB level |
| Refresh token rotation | FamilyID + DeleteFamily on reuse |
| Anti-enumeration | bcrypt dummy hash for unknown users |
| Oracle-leak | Unified error for unknown/expired/consumed |
| Credential endpoints | `Cache-Control: no-store` + `Pragma: no-cache` |
| 401 responses | `WWW-Authenticate: Bearer` with `setBearerChallenge` |
| JWT algorithms | Allowlist only: EdDSA, ES256/384/512, RS256, PS256 |
| Private key JWT | Verified with `AsymmetricJWSAlgs` BEFORE signature check |
| DPoP | Nonces + JTI replay prevention |
| JAR URL fetch | HTTPS-only, no-redirect, bounded |
| SPIFFE | Strict audience + trust domain validation |

### Fail-Open vs Fail-Closed

| Component | Behavior | Rationale |
|---|---|---|
| Audit sink | Fail-open | Do not block auth for logging |
| Geo enrichment | Fail-open | UX hint, not security |
| Risk scorer error | Fail-open | Deny all could DoS |
| Tenant suspension check | Fail-open | Outage should not block all auth |
| JTI replay store error | Fail-open (default) | Oracle-safe; `fail_closed: true` opts in |
| Refresh issuance | Fail-open | Availability over strict rotation |
| Signature validation | **Fail-closed** | Must not accept invalid tokens |
| Scope expansion | **Fail-closed** | Must not grant unauthorized scopes |
| Refresh family reuse | **Fail-closed** | DeleteFamily + invalid_grant |
| Federation trust chain | **Fail-closed** | Must not accept untrusted chains |

## Security Checklist (for developers)

Before submitting code, verify:

- [ ] `tokenNoStoreHeaders(ctx)` on every credential/bearer endpoint
- [ ] `setBearerChallenge(ctx, ...)` on every 401
- [ ] Oracle-leak: unknown/expired/consumed/mismatch → one response
- [ ] Anti-enumeration: bcrypt dummy hash for unknown users
- [ ] Audit: `SetMeta(e, k, v)`, never `e.Metadata = map{...}`
- [ ] No mocks in tests — use `Memory*` implementations
- [ ] Error codes documented in `docs/error-codes.md`
- [ ] Endpoint changes documented in `docs/openapi.yaml`
- [ ] `make check-invariants` passes
- [ ] `make harness` passes
