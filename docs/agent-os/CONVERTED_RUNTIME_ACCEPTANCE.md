# Converted historical candidate: bounded runtime acceptance

## Goal and non-goals

Exercise the current source combination against a **new owned disposable**
PostgreSQL candidate populated from the pinned, retained offline SQLite backup.
Close the gap between typed content comparison and actual stock-server behavior
without changing historical identities, credentials, client grants or keys.
This is rehearsal evidence, not a production import or cutover command.

The earlier converted-runtime report remains failed and immutable. Later
code-bound offline-access and opt-in browser-session repairs must be evaluated
on a fresh candidate; successful synthetic logins are not historical password
acceptance. No source/config/default/SPI/schema/security budget change is needed
merely to run this rehearsal. SQLite/MySQL/PostgreSQL product certification,
production PostgreSQL 15 recovery, historical external keys and actual users'
passwords remain separate gates.

## Ownership and one-shot admission

- Use the existing `import_snapshot.py` writer, never the legacy common-column
  mover. Each target is newly created and has a distinct ownership nonce.
- Pin the source SHA, exact conversion policy, native schema contract, current
  source combination, target identity and short-lived candidate intent.
- The import must complete locked empty admission, full mapped PK/content checks,
  unchanged native migration histories and canonical audit sequence restart.
  Require the normal child exit, durable report and complete attempt journal.
- Do not retry an unknown write, reset a populated target, infer relationships,
  fabricate audit hashes or copy SQLite migration histories into PostgreSQL.
- The source opens read-only/immutable; rehash it before and after. No production
  connection, persistent local service, existing fixture or live backend switch.

## Required evidence

1. Before runtime, compare all mapped historical business tables and rows, native
   schema facets, native migration histories and the canonical audit serial.
2. Compare public store API projections for every historical user/client,
   credential presence, RBAC role/assignment/menu and stored session. Preserve
   inactive-session rejection. Do not print raw identities, hashes or tokens.
3. Use new, explicitly synthetic users/clients only for current wire activity.
   Passwords are hashed through the real PostgreSQL credential store; request
   PKCE S256 and exact client grants/scopes. Give no synthetic admin grants.
4. Run separate default-off and explicitly enabled `oidc.browser_sso` profiles.
   Default-off must not acquire a fabricated session/SID/cookie. Enabled mode
   must bind login, stored code, refresh and ID/access tokens to the session.
5. Check omitted/no-offline/narrowed scopes, rejected scope expansion, code
   single-use, explicit offline issuance, HMAC token-at-rest representation,
   restart/key continuity, userinfo/RBAC and admin denial. Verify refresh
   rotation/reuse and durable logout rejection. Session-expiry injection is
   labelled injection, never an elapsed absolute-lifetime test.
6. After runtime, compare **every original typed PK and complete row digest**
   against the stopped control candidate, including every original audit row.
   Native histories must remain exact; new synthetic rows are separately counted.
   A table-wide digest cannot establish subset preservation after legitimate
   additions. Never filter history by guessed ID prefixes.
7. Keep all failures, contemporaneous helper source, commands, actual normal
   exits and bounded private evidence. Close owned processes and reconcile exact
   fixture identity/resources before removing its container and private inputs.

Use committed Go gates, full `make ci`, product E2E and the unchanged relevant
race workloads. The private runtime witness and Python acceptance supplement,
not replace, those gates. Missing owned PostgreSQL coverage must fail, not skip.

## Remaining migration blockers

A finite historical-data/synthetic-runtime pass does not establish historical
password login, historical admin authorization, external-key provenance, HTTPS,
least-privilege roles, production fencing, consistent live backups, elapsed
30-day SVERP sessions, uncertain-commit/crash recovery or HA. Normal restart is
not a crash/failover drill; local JWT payload comparisons are not independent
signature acceptance. A PostgreSQL 16.14 fixture does not certify deployed 15.18.

Source review/integration/release approval and production migration authority
remain explicit and separate. Preserve the original Step22 and idempotency
failure evidence; later passes neither erase failures nor diagnose their causes.
