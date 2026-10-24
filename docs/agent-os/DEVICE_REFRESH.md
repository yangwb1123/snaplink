# Device authorization: explicit offline access

## Goal and boundary

Device clients must not receive an initial server-managed refresh token merely
because a refresh store or a client `refresh_token` grant is configured. The
already-approved, atomically claimed device code must carry exact
`offline_access` in its effective stored scopes. This applies to the embeddable
Server and stock server using the existing device-grant handler; no feature flag,
configuration default, endpoint, SPI, schema or lifetime is added.

Owner: `internal/handler/tokengrant/token_device.go::deviceIssueRefresh` (interface
layer). Existing downward dependencies are sufficient. No OAuth-to-OIDC import,
new package, persistence abstraction or exemption is needed.

## Acceptance

- Exact stored `offline_access`, a wired refresh store, and the existing client
  grant-type policy are all required. Empty `GrantTypes` retains legacy grant
  compatibility but does not authorize offline scope.
- Missing/empty/resource-only/`openid` scopes, substrings, case aliases and an
  allowlist alone do not authorize initial refresh issuance. A scope supplied
  only in the later token poll cannot expand the stored code's grant.
- Unauthorized scopes return before refresh-store lookup or issue/audit calls.
  HTTP responses omit the refresh key entirely while access/ID issuance remains
  independent. The device response never adopts an issuer-provided refresh value.
- Authorized store failures preserve the existing log-and-omit behavior, without
  issuer fallback or restoration of the consumed code. Existing success metrics
  remain initial issuance (`rotation=false`).
- Preserve approved scope/resource/attribute values, sender constraint, client
  TTL, empty family/SID/authorization-details inputs and original authentication
  context. Do not alter scope resolution, device approval, atomic claim, client
  and tenant binding, poll errors, replay rejection, or existing refresh rotation.
- Positive legacy/explicit-grant fixtures must explicitly request offline access;
  retain their refresh/rotation assertions. Tests of denied refresh grants must
  request offline access so that the grant-type guard is still exercised.

Applicable evaluation: O1/O8/O10 and S2/S3/S4; no new SPI or authenticator.
Use committed
build/vet/architecture/maintainability gates, targeted unit and real-memory HTTP
flow tests, race repetitions, product E2E, all engineering checks and full
`make ci`. Supplementary records do not replace those gates. Existing file,
function, complexity, directory and evidence budgets do not change.

## Files and compatibility

- Change only the initial device refresh guard in production.
- Add `token_device_refresh_scope_test.go` and `test/device_offline_access_test.go`.
- Adjust existing positive/denied-grant fixtures in `test/handle_device_test.go`;
  default helper requests remain scope-less unless explicitly overridden.
- The Forge positive fixture in `interfaces/sso/rootcov2_device_errors_test.go`
  explicitly allows/requests offline access. Its exact scope assertion retains
  both conversation scopes and adds offline access; owner/audience/client binding,
  denied authorization-code grant and refresh-rotation assertions remain intact.
  The Console/observer client policies are not broadened.
- Synchronize OpenAPI/frontend scope documentation and checks registry. Regenerate
  derived SDK contracts if the unchanged generator reports affected outputs.

This intentionally removes refresh tokens from device authorizations that did
not grant offline access. Clients needing offline use must allow and explicitly
request that scope at `/device/code`; they must also permit `refresh_token` when
using an explicit grant allowlist. `openid` remains independently explicit.
Existing refresh families are not invalidated or given a new offline-scope gate.

## Non-goals and evidence limits

No WebAuthn/CIBA/token-exchange policy change, historical-runtime recertification,
custom issuer redemption guarantee, browser anchoring, 30-day SVERP policy change,
client reconfiguration, import/replay, production database operation, integration,
release, deployment or cutover. An owned synthetic fixture is not historical
credential, actual-time expiry, HA/crash/failover or production acceptance.
Step32's original idempotency CI failure remains unexplained; later passes do
not repair or waive it. Step34's finite Python complexity debt list is empty,
not a blanket whole-tool maintainability certification.
