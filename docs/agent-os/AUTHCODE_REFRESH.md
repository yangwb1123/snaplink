# Authorization-code refresh authorization

## Goal and bounded outcome

Repair the current candidate's code-exchange issuance of a refresh token without
an effective `offline_access` grant. Prevent the client scope ceiling from
implicitly granting offline access when the scope parameter is omitted. Operators
get an observable no-refresh response and no refresh-store write in these cases.

Surface: embedded SDK and stock server. Owner: `internal/handler/tokengrant`
(code exchange) and `protocols/oauth/oauthvalidate` (shared scope authorization).
Dependencies keep composition -> interfaces -> protocols -> shared direction;
no new SPI, driver branch, YAML key, schema migration or dependency is required.

## Policy and compatibility

- The authorization code's stored scopes, after allowed token-time narrowing,
  are authoritative. An unrelated request scope or client allowlist cannot add
  offline access. Exact `offline_access` is required; substring/case aliases
  are not authorization. An unwired refresh store still yields no refresh token.
- Empty scope retains existing default resource scopes but excludes both
  `openid` and `offline_access`; requesting either remains explicit. Existing
  order/deduplication and scope-expansion rejection remain unchanged. This
  shared default rule applies wherever `GrantedScopes` is used.
- A permitted refresh issuance failure still omits only the refresh token,
  preserving existing access/ID-token fail-open behavior. No issuance audit or
  store mutation occurs for a grant that did not authorize offline access.
- This tightens new authorization-code grants. Clients relying on implicit
  refresh issuance must allow and request `offline_access` explicitly.
  Existing stored refresh families and their rotation/reuse behavior are not
  rewritten or invalidated. Direct-mint, device, CIBA and token-exchange refresh
  issuance policies are not certified or changed by the code-exchange guard.
- Browser sessions are independent: current primary already provides explicit
  `oidc.browser_sso.enabled` wiring. Default-off remains default-off; no
  authenticator session intent or browser authorization is invented. Its
  eight-hour browser-anchor ceiling is not SVERP's 30-day application session.

## Acceptance criteria

Applicable U1-U9, O1/O8/O10 and S2/S3/S4; universal Go gates and `make ci`
remain authoritative, Python acceptance supplementary.

1. Code-bound no-offline/empty/lookalike scopes do not write or return a refresh.
2. Authorized offline scopes do; permitted token-time narrowing that removes
   offline access does not. Attempted expansion is rejected as before.
3. PKCE, one-shot consumption, access/ID tokens, no-store headers and preserved
   original authentication/SID/resource data remain correct.
4. Empty shared defaults exclude only the two explicit protocol permissions;
   explicit allowed/offline and unauthorized-scope cases retain the contract.
5. New synthetic actors only on an owned loopback PostgreSQL: reproduce the old
   code failure, then test both browser-session flag states, explicit scopes,
   SID continuity, normal restart, rotation, logout and expired-session refusal.
   Actual process exits and bounded requests are required; failed runs retained.

Create regression tests in `test/` and `protocols/oauth/oauthvalidate/`; modify
only the owning functions, authorized positive fixtures and frontend/OpenAPI
documentation. Regenerate TypeScript, both Python canonical client copies and
the compiled TypeScript declaration after the OpenAPI description changes.
Keep production files <=500 lines, functions <=50, complexity <=15, nesting <=3;
no new exemptions, thresholds, dependencies, or version changes.

## Non-goals and authorization

No historical snapshot import or historical password/key acceptance, no real
client/config changes, no production service operations, no merge/deployment or
cutover. No full three-engine product certification, global writer fencing,
crash/failover/uncertain-commit acceptance, or repair of inherited Python debt.
A synthetic enabled-browser-session witness is not acceptance of the old
historical default-off runtime or an authorization to enable it in production.

## Bootstrap: the console keeps a refresh token

The admin console SPA holds a refresh token, so its public client needs
`offline_access` in `allowed_scopes`. Fresh deployments get it from the client
seed; deployments created before the rule get it from bootstrap step 8
(`grant_admin_console_offline_access`), which appends the scope once, only when
the client still carries the untouched default scope list and has no secret. An
operator-curated or confidential client with that ID is left exactly as
configured — the step never widens a hand-managed client.
