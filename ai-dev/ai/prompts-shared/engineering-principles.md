# Engineering Principles

Project-specific invariants for Snaplink. These are GATES, not guidelines.
All review stages must check compliance against these principles.

---

## Code Budgets (Committed Gates)

| Metric | Limit | Gate |
|--------|-------|------|
| File lines (`.go`) | ≤ 500 | `maintainability_budget_test.go` |
| Function lines | ≤ 50 | `maintainability_complexity_test.go` |
| Cyclomatic complexity | ≤ 15 | `maintainability_complexity_test.go` |
| If-nesting depth | ≤ 3 | Code review |
| Directory depth | ≤ 3 | `maxdepth_test.go` |
| Go files per dir | ≤ 10 | `directory_fanout_test.go` |
| Subdirs per dir | ≤ 15 | `directory_fanout_test.go` |

**Rule**: If an edit pushes a file over 500 lines, split first, then continue.
**Rule**: Never add a new maintainability exemption. The exemption lists only shrink.

---

## Dependency Direction (Layer Imports)

```
interfaces/sso → protocols/oauth → shared/security → shared/core
interfaces/sso → protocols/oidc  → shared/security → shared/core
```

**Prohibits**:
- `protocols/oauth ↔ protocols/oidc` (peer imports)
- `cmd/ ← any` (cmd is consumer only)
- Any upward (toward-interfaces) import

---

## Oracle-Leak Hardening

| Scenario | Required Response |
|----------|-------------------|
| AuthCode/Refresh/Device/PAR: unknown/expired/consumed/mismatch | `400 invalid_grant` |
| Stale/missing PAR `request_uri` | `invalid_request_uri` |
| DPoP/mTLS failure | `invalid_token` |
| `private_key_jwt` failure | `invalid_client` |

**Rule**: Never distinguish between "token not found" and "token wrong" in error responses.

---

## Anti-Enumeration

| Endpoint | Required Behavior |
|----------|-------------------|
| `/register/:client_id` | Missing/wrong/unknown bearer → identical 401 `invalid_token` |
| `/token/revoke` | 200 on valid client creds regardless of token existence |
| `/token/introspect` inactive | `{"active":false}` only |
| bcrypt (unknown user) | Cost-matched dummy hash |
| WebAuthn (unknown user/session) | `404 session_invalid` |
| MFA `/auth/mfa` | All failures → `400 mfa_invalid` |

---

## Fail-Open vs Fail-Closed Catalog

**Fail-Open** (log + continue): refresh issuance, ID Token issuance, geo enrichment, risk-scorer, audit Sink errors, JTI-replay store errors (default), anomaly runner.

**Fail-Closed**: refresh rotation grant (500 on error), signature/validation failures, scope expansion, refresh family reuse → `DeleteFamily` → `invalid_grant`, trust-chain validation, CAEP receiver.

---

## Wire Contracts

- **Cache headers**: `/token`, `/introspect`, `/revoke`, `/par`, `/auth/login`, `/userinfo`, `/register*` → `Cache-Control: no-store` + `Pragma: no-cache`. Including errors.
- **401 WWW-Authenticate**: Missing token omits `error=`; validation failure → `error="invalid_token"`.
- **RFC 9207 `iss`**: Every `/auth/login` response uses `s.resolveIssuer(ctx)`.
- **Form + JSON**: All endpoints via `bindOAuthParams`. HTTP Basic > body creds.
- **PKCE**: Captured at `/auth/login`; verified at `/token` for `grant=authorization_code` only.

---

## RFC 9068 Claims (every token Issue)

- MUST set `Subject.ClientID`. `jti` always auto-generated.
- Login: `AuthTime` + `AMR` from live event; `acr` from `AuthResult.AchievedACR` (empty → omitted).
- Refresh: propagates original AMR without resetting `AuthTime`.
- `client_credentials`: `ClientID` only.

---

## Prohibited Patterns

| Pattern | Do instead |
|---------|------------|
| `TODO: refactor later` | Refactor immediately |
| Appending to 490+ line file | Split first |
| Mocks where Memory* exists | Use real `MemoryProvider` |
| `e.Metadata = map{...}` | Use `SetMeta(e, k, v)` only |
| Business code in root | Run hexagonal extraction |
| Error codes not in `consts.go` | Add to consts first |
| New error code without doc update | Update `docs/error-codes.md` in same commit |
