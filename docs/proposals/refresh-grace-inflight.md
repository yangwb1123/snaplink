# Refresh grace: in-flight family safety

## Goal and product boundary

Prevent a concurrent, same-client refresh from revoking a valid family while
another replica is between atomic consume and publication of its successor.
This extends the existing opt-in refresh grace, not generic token idempotency.
Default strict single-use behavior remains unchanged. No exactly-once claim,
new YAML key, HTTP endpoint, token field or browser UI is introduced.

## Owners and classification

OAuth flow plus optional store capability: `internal/handler/tokengrant`,
`infrastructure/{redis,postgres,defaultimpl/sqlite}` and `shared/core` cache-key
constants. Existing production files are extended; no new layer/package,
SSO production file, root module dependency or budget exemption.

## State and safety

- Before consume, a current inspector may verify that the original record is
  live and bound to this client/DPoP key. A supported grace store atomically
  inserts a pending marker only if no live pending/completed entry exists.
- Pending state contains family/client identifiers and original expiry, never
  an issued credential. Retention is capped by the configured grace window
  and original grant deadline. Preparing again never overwrites or extends a
  live completed response. Preparation is best-effort; uncertainty retains
  strict fail-closed behavior, not issuance authorization.
- Atomic consume remains the exclusive issuance boundary. A pending marker
  never causes another token or refresh successor to be minted.
- Only a real `ErrRefreshTokenReused` with matching family evidence may use
  pending state. Wait briefly for completion (250 ms nominal, plus bounded
  backend calls), honoring request cancellation. A still-valid matching
  pending marker, rechecked after the final wait/cancellation, then yields
  the ordinary `400 invalid_grant`, without revoking the in-flight family. The caller may retry after completion.
- Missing, expired, malformed, wrong-client or wrong-family pending state
  cannot suppress normal family-reuse revocation. After completion, all
  existing successor/session/user/scope/sender/access checks still run;
  failed ready client/tenant/DPoP/mTLS binding retains family revocation.
- No marker means the original family-kill behavior. Pending inspection/store
  outages never yield a success. Crash-before-consume leaves an active token;
  crash-after-consume leaves pending state only until its bounded expiry.
- Internal pending fields are never serialized into successful wire responses.

## Compatibility and rollout

Additive structural `PreparePending(token, response, now)` capability; keep the
existing `Remember`/`Lookup` SPI intact for custom stores. All four stock grace
backends implement it. Custom stores without the capability retain completed-
response replay but do not gain the in-flight family protection. No migration:
use the existing expiring grace row/key, with atomic insert-if-absent semantics.
Mixed-version replicas may still revoke an in-flight family; coordinated
upgrade is required before relying on this additional protection. Security
failures remain indistinguishable `invalid_grant` with credential no-store.

## Acceptance and verification

Apply AGENTS and U1-U9/O1-O11/S1-S7 as relevant:

1. Two servers sharing stores race one original token. A blocked winner is not
   revoked by the loser; a completed retry returns the same successor.
2. Pending cannot overwrite a ready response, extend its deadline, survive
   original expiry or suppress wrong-client/family revocation. Recheck expiry
   after the final timer/cancellation wait. Prepare after pending expiry may
   insert a new bounded marker only for a live grant. Failed ready client,
   tenant, DPoP or mTLS binding must revoke siblings and the successor.
3. Feature-off behavior and custom old SPI remain strict single-use.
4. Test memory, SQLite, Redis and real PostgreSQL; repeat concurrency under
   `-race -count=10`, then root race, E2E and complete `make ci`.
5. Document the bounded incomplete-response error, custom-store limitation
   and coordinated rollout; independently review before handoff.

This is availability protection within an explicitly enabled grace window,
not proof of Redis failover durability or production HA acceptance.
