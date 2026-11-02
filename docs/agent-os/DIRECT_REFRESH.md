# Direct-login refresh authorization

## Goal, owner and scope

Users of direct-mint `/auth/login` must not obtain an unrequested refresh token
merely because a refresh store or custom token issuer is configured. Continue
Step25 by enforcing exact effective `offline_access` after client validation and
conditional-access narrowing. Owner: `interfaces/sso/server_finish_login.go`;
SDK and stock legacy direct-login surface, no new SPI, config, schema or import
edge. Strict OAuth2.1 still rejects direct mint; it is not made permissive.

## Policy and compatibility

- No effective offline scope: omit the refresh field, including an empty or
  issuer-provided value; do not contact the server-managed refresh store or
  record a refresh-issued event. Ordinary login sessions/access tokens remain.
- Effective offline scope and a managed store: discard any issuer refresh before
  managed issuance; on failure log and omit refresh without failing access/ID
  tokens. Never fall back to the issuer's independent refresh on store failure.
- Explicit offline with no managed store retains the existing issuer-provided
  refresh seam. This is not proof that the issuer token is redeemable by the
  server's `/token`, nor control of side effects inside a custom issuer's Issue.
- Clients requiring new direct-login refreshes must allow and explicitly request
  offline access. Empty requests retain Step25 defaults excluding openid/offline.
  Existing families, refresh rotations, session durations, browser default-off,
  PKCE/code exchange, roles, resources, errors and cache protection are preserved.
- Other initial refresh paths (WebAuthn ceremony, device, CIBA, token exchange)
  remain separately governed/unaccepted; do not advertise universal enforcement.

## Acceptance

Applicable U1-U9, O1/O8/O10/O11 and S2/S3/S4; committed Go gates and full make ci
are authoritative. Test exact/no/empty/lookalike/denied offline scopes, client
ceiling and conditional-access removal; real memory stores plus issuance counts
and audit events must show no hidden managed writes. Include issuer-provided
refresh with/without managed storage and permitted store errors, preserve
access/ID tokens and SID continuity, and keep old positive refresh/rotation tests
by authorizing their fixture scope (no removed/weakened assertions).

Owned loopback PostgreSQL, synthetic identities/clients/keys only: reproduce the
old direct defect; compare native refresh counts and events, verify default and
explicit scopes, normal restart, rotation, logout and injected expired-session
refusal. Explicit fixture legacy mode is required to exercise direct login;
separate strict-mode negative proves no bypass. Record actual normal exits,
whole-window bounds and failures; no uncertain-write automatic replay.

Update frontend/OpenAPI documentation and its generated SDKs, retaining all
previous handoffs. Production Go file <=500/function <=50/complexity <=15;
no new waiver/threshold/dependency/version or file-count expansion.

## Non-goals

No live configuration, historical source/credential import or acceptance,
production deployment, writer fencing, full DDL/relationships/audit-chain,
production topology/crash/restore/cutover, Vault/MySQL/three-engine certification,
or inherited Python complexity repair. No merge/commit/push authorization.
Source/archive limits remain unchanged; use exact patch/tree evidence and mark
an over-cap whole-source archive not_executed rather than widening its budget.
