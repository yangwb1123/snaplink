Enumeration confirmed complete — the census is closed at exactly 15 sites. Deliverable written to `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-via-s-eacdbc35/artifacts/adversarial_review-9c87f3a7/meta/site_census_reconciler.md` (with `.meta.json`), mirroring the sibling reviewer convention. Summary:

## Definitive census: 15 mint sites (14 root + 1 nested)

Every `.Issue(ctx, subject, scopes)` call across all modules (grep-verified, including all nested `go.mod`s): **13 user-subject, 1 agent-subject (agentidentity), 1 client-subject (client_credentials)**.

| Count | Verdict |
|---|---|
| Design "10" | Correct only within its file set — missed break-glass, silent renewal, agentidentity, webauthn, kerberos |
| Security "11" | Correct within its evidence base (+break-glass only); still missed 4 sites in unread files |
| Wire-compat "14+kerberos" | **Correct enumeration** (its "13 user-bound by AuthTime" should read 12 root user-subject + kerberos = 13; agentidentity is agent-subject with no AuthTime) |

## TenantID verification
**13/15 stamped.** Missing exactly at **webauthn** (`cmd/sso-server/serverwebauthn/webauthn.go:217`) and **kerberos** (`infrastructure/kerberos/handler.go:268`) — both have `client.TenantID` in hand. R1's "zero call-site changes" claim must be amended: **+2 one-line additions** (break-glass's deliberate `""` is correct via `omitempty`). Side effect to pin: stamping activates tenant-scoped `max_ttl` clamping for those flows (they're fail-open-unclamped today, violating the ClampingIssuer MINT-SITE CONTRACT).

## R2 roles decision — INCLUDE 12, EXCLUDE 3
- **INCLUDE (12):** all 13 user-subject sites except break-glass — login, native_sso, authcode, ciba, device, exchange, jwt_bearer, refresh, saml2, silent renewal (needs local-sub threading — `ResolveLocalSubject` already used at :328 for session-liveness), webauthn, kerberos (optional nil-safe `Permissions` dep; module already requires root with `replace`). Keying is `(localSubject, clientID)` — the pairwise-local-sub discipline is load-bearing (provider keys on local ID, verified `memory.go:244`).
- **EXCLUDE (3):** break-glass (synthetic client URN, `issuerForClient(nil)`, non-bypass invariant — roles would be a dead lookup and an entitlement document the token refuses to express), agentidentity (agents aren't permission subjects; human roles on an agent `sub` would be misattribution — the human's authority already rides via `act` + scope intersection), client_credentials (client identity). Each gets a negative pin test.

## Parity-check (T-8(a)) implication
T-8(a) is undefined anywhere in the runs tree (the sibling run failed at requirements) — the report defines it: **byte-identical `tenant_id`/`roles` across all 12 included user-subject surfaces, with asserted-absence exemptions for the 3 excluded sites**. Under that definition it fails today at webauthn, kerberos, and silent renewal (roles), and break-glass must be an *exempted* pass — converting the wire-compat reviewer's "silent omission" objection into a tested contract. The parity test must compare decoded claims (not bytes — `iss`/`iat`/`jti` differ per mint) and must not compare `sub` shape: webauthn/kerberos mint raw local subs while /token surfaces pairwise-transform (pre-existing divergence, noted out of scope).

No `.go` edits were made, so no repo gates applied (consistent with the sibling reviewers).
