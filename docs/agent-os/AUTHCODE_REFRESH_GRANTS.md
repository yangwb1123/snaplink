# Authorization-code initial refresh grant boundary

## Goal and candidate decision

Step41's owned stock rehearsal returned and persisted an initial refresh token for
an offline-authorized synthetic client whose nonempty grant list contained only
`authorization_code`. Implement the smallest local candidate restriction: initial
code-exchange refresh additionally requires exact `refresh_token` in a NONEMPTY
current-client grant list. This follows the existing device/CIBA allowlist pattern;
it is not a claim of production compromise or an OAuth specification violation.
The continued migration task authorizes candidate implementation/testing only,
not production policy activation, historical client edits or independent approval.

## Policy and compatibility

Owner: `internal/handler/tokengrant::authCodeIssueRefresh`; SDK and stock surface.
Effective code-bound exact `offline_access` remains mandatory, including allowed
token-time narrowing. Nil/empty client grant lists retain unrestricted legacy
compatibility. Nonempty lists need the exact refresh grant, not aliases, case
variants, prefixes, unsplit strings, allowed scopes or editable attributes.
Denied initial refresh omits the response key before refresh-store getter, issue
or issuance event access. Access/ID issuance, atomic code consumption, PKCE,
resource/scope/error ordering and original authentication context are unchanged.
Authorized store errors retain log-and-omit with no issuer fallback or restoration
of the consumed code. Existing family redemption/rotation, direct-login, device,
CIBA and token-exchange policies remain separate; no new CIBA offline requirement.

No new SPI, config key, schema, dependency, package, exemption or HTTP error.
This tightens new code-exchange issuance for explicitly restricted clients; review
compatibility before integration. Do not modify real/history client grants to pass.

## Acceptance

Applicable U1-U9, O1/O8/O10 and S2/S3/S4; committed Go/full CI authoritative.

1. Regression-first exact allow/deny/alias/nil/empty/no-offline/unwired/outage
   boundaries; denied cases do not touch managed issuance or emit issuance events.
2. Preserve all approved scopes/resources/attributes/RAR/SID/AMR/ACR/auth_time,
   TTL override, sender constraint and aliases. Unit counters are not persistence.
3. Identical real memory/SQLite HTTP cases before/after: access/ID independence,
   key omission, subject persistence/audit counts, consumed-code replay, managed
   rather than issuer refresh, authorized rotation and log-and-omit outages.
4. Fresh owned PG16 candidates/imports only. Rehearse actual stock default-off/on,
   no-offline/narrowing/grant denial, binding, userinfo, restart/rotation/reuse/
   logout and natural short-fixture expiry; stop at first failure. Preserve every
   original typed business PK/full row with control, and EACH candidate's complete
   original native histories/schema; do not compare independent init timestamps.
5. Record actual exits/source versions, retain prior failures, run unchanged full
   gates and owned-PG acceptance; exact resource reconciliation/private cleanup.

Historical password/admin/key authority, full HTTP/tenant/business parity,
positive-interval/deployed cleanup, HA/fencing/uncertain commit, actual MySQL/Vault,
independent security/integration/release review and production cutover remain
unexecuted until separately verified. Synthetic 30s session/45s family tests do
not change or certify SVERP's 30-day session/HMR/watch policy. No automatic commit,
merge, deployment, production contact or live-service restart.
