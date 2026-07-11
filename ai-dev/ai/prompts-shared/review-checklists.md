# Review Checklists

Domain-specific checklists for use across review stages.
Reference the relevant section from within each stage prompt.

---

## Security Checklist

### Authentication & Authorization
- [ ] Every protected endpoint verifies token before processing the request
- [ ] Authorization decisions use `Subject.ClientID` — not just client assertion
- [ ] Scope validation happens before any data is returned or mutated
- [ ] Bearer token absence and bearer token invalid are indistinguishable to the caller
- [ ] Admin endpoints enforce `admin:read` or `admin:write` scope

### Token Lifecycle
- [ ] Tokens have bounded TTL — no eternal tokens
- [ ] Refresh rotation: old token invalidated before new token issued
- [ ] Family reuse detection: `DeleteFamily` on replay, `invalid_grant` response
- [ ] `jti` claim present and unique in every JWT
- [ ] `aud` claim present and validated against the resource server
- [ ] Revocation propagates across replicas (via cluster bus or TTL)

### Input Validation
- [ ] All external inputs validated at system boundary before processing
- [ ] Redirect URIs validated against pre-registered exact match (no prefix/glob)
- [ ] Prompt parameters sanitized — no HTML injection into server-rendered pages
- [ ] `client_id` and `user_id` are opaque identifiers — no filesystem path traversal possible
- [ ] File uploads (if any) reject unexpected MIME types and enforce size limits

### Cryptographic
- [ ] `alg=none` rejected unconditionally
- [ ] Algorithm checked BEFORE signature verification
- [ ] Supported JWS algs: EdDSA, ES256, ES384, ES512, RS256, PS256 only
- [ ] No symmetric JWS algs (`HS256`) for tokens issued to external parties
- [ ] Key rotation window: demoted key stays verify-only through full TTL
- [ ] Nonces are cryptographically random and single-use

### SSRF / Open Redirect / Injection
- [ ] Outbound HTTP calls go to pre-registered (not caller-supplied) URLs
- [ ] `post_logout_redirect_uri` validated against registered URIs
- [ ] No HTTP header values constructed from user input without sanitization
- [ ] No SQL constructed from string concatenation — parameterized queries only

### Replay & CSRF
- [ ] PKCE `code_verifier` verified before token exchange
- [ ] `state` parameter validated by the RP (documented as requirement)
- [ ] DPoP nonce validated and single-use
- [ ] `iat` and `exp` validated in JWTs before processing claims

---

## Architecture Checklist

- [ ] Module has a single, clearly stated responsibility
- [ ] All external dependencies are behind interfaces (SPI pattern)
- [ ] No peer imports between `protocols/oauth` ↔ `protocols/oidc`
- [ ] State ownership is unambiguous — one writer per state type
- [ ] Every public interface has a `Memory*` implementation for testing
- [ ] No business logic in `interfaces/sso` root — thin wrappers only
- [ ] New package classified in `layerName()` in `architecture_layer_test.go`
- [ ] No new `layerExemptions` entries added

---

## Distributed Systems Checklist

- [ ] Operations are idempotent (safe to retry without side effects)
- [ ] No assumption of request ordering within a session
- [ ] Token operations use `DELETE RETURNING` (single-use atomic consume)
- [ ] Clock-sensitive operations tolerate ±30s skew without incorrect behavior
- [ ] Failure of one replica does not corrupt shared state for other replicas
- [ ] Redis operations avoid CROSSSLOT (multi-key ops use same hash slot or pipelines)
- [ ] All mutating RPCs have `rollback` or compensating transaction path

---

## Performance Checklist

- [ ] No N+1 queries in list/batch operations
- [ ] Redis pipeline used for multi-key reads/writes in same request
- [ ] Cryptographic operations (signing, verification) not in hot path without caching
- [ ] No unbounded `SELECT *` — projections specified
- [ ] Connection pool configured for expected peak concurrency
- [ ] Memory allocations per request bounded (no unbounded slice growth)
- [ ] Benchmark exists for every operation with latency SLO

---

## Production Readiness Checklist

- [ ] RED metrics (Rate, Errors, Duration) exported for every endpoint
- [ ] Structured logs with `trace_id`, `span_id`, `user_id`, `client_id` on every relevant event
- [ ] Health check (`/readyz`) reflects actual subsystem readiness
- [ ] Graceful shutdown drains in-flight requests before exit
- [ ] Feature flag or config switch exists for risky new behavior
- [ ] Rollback plan: what to do if this breaks in production after deploy
- [ ] Runbook: step-by-step operator actions for top-3 failure scenarios
- [ ] Alert: SLO breach fires within 5 minutes of onset
