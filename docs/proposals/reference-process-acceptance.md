# Wave 5b: independent-process grant and session acceptance

## Goal and product boundary

Extend the local reference evidence from one process with memory stores to two
independent SDK authorization-server processes using one real PostgreSQL schema.
The parent re-executes the current test binary with a dedicated helper test;
children have distinct PIDs, HTTP listeners, pools, signers and Go heaps. A
loopback parent gateway supplies one stable issuer/origin and deterministic
routing. It is a fixture, not a load balancer acceptance test.

Opt-in execution follows the existing `SSO_TEST_POSTGRES_DSN` convention. Tests
without that DSN skip the backend scenarios; an acceptance run must configure
it and contain no skipped scenarios. No new production option, route, config,
SPI, module, dependency, SQL migration or runtime default.

This is **SDK composition**, not the stock command, a browser frontend, an OCI
image, multi-host HA, database failover, backup/restore or production acceptance.
The previous reference applications retain their separately scoped API and
permission tests; this slice adds durable AS state, not durable application data.

## Ownership and files

Existing `test/` package `ssotest`, with no new production package/directory:

- `reference_process_fixture_test.go`: real PostgreSQL stores, parent-only seed,
  private fixture configuration and child HTTP lifecycle.
- `reference_process_driver_test.go`: bounded child startup/stop/crash/reap,
  canonical-origin gateway and reuse of reference HTTP/cryptographic checks.
- `reference_process_test.go`: cross-process grants, atomic code competition,
  crash/restart and shared-session logout.
- `reference_process_lifecycle_test.go`: real child exit/failure/panic/SIGKILL
  classification probes and shared-schema reap-guard regression checks.
- Extend `docs/sso/reference-apps.md` and `docs/proposals/release-readiness.md`.

Preserve unrelated worktree changes and all budgets/exemptions. Apply U1-U9,
O1/O7-O8/O10-O11 and S2-S4 to the exercised existing behavior. No production Go
edit is planned; any discovered defect requires an adjacent red regression and
a separately bounded fix rather than widening this test project silently.

## Acceptance

1. Two tenants and four confidential RP registrations are seeded once by the
   parent, using real PostgreSQL users/passwords/clients/tenants/sessions,
   authorization-code and refresh-token stores. Children open existing state,
   never reseed it. Default-cost stored-password verification remains real.
2. Private ephemeral fixture files hold a shared signing key, independent
   lookup-HMAC key and DSN; no keys, credentials, tokens or DSN in diagnostics,
   process arguments, public readiness records or tracked artifacts. Listeners
   bind loopback. Child readiness PID must equal its launched OS process PID,
   differ from the parent/peer, and return a loopback URL.
3. Login/code issuance on one process and form/Basic PKCE exchange on another
   succeed. The OP session can be resumed on the peer without sending a password.
   Signed ID-token/access claims retain issuer, client, tenant, resource, nonce,
   session and `at_hash` bindings. Independently registered RPs remain separate.
4. A single code exchanged concurrently by requests pinned to distinct children
   yields exactly one successful token response and one ordinary no-store
   `400 invalid_grant`. Unknown and already-consumed code errors match.
5. Kill and reap one child only after completed HTTP operations. The surviving
   child exchanges its peer's outstanding code and rotates its persisted refresh
   credential. A newly launched child opens the same DB/key without seeding;
   consumed-code rejection and refresh-family reuse survive that restart, and
   reuse kills the live successor across processes. No in-flight exactly-once,
   refresh grace/distributed claim, database crash durability or RPO/RTO claim.
6. Logout of a selected shared session on one child prevents refresh on the
   other. An independent RP grant remains usable. This does not claim access-JWT
   deny-set propagation, global RP logout or immediate offline revocation.
7. Parent teardown closes gateway/cache and all children before dropping its
   private schema. Normal child stop must exit successfully; intentional crash
   requires a successful kill request and actual POSIX SIGKILL wait status,
   not just a nonzero exit. Windows does not claim this crash acceptance.
   Startup, HTTP and shutdown waits are bounded; child race/panic/failure output
   is rejected. Reaped state is set only after Wait completion. If an OS failure
   prevents reaping even after checked forced cleanup, fail and retain the
   isolated schema rather than race DROP against a live child; it can require
   operator cleanup. A private test-local schema owner guards this DROP; the
   ordinary pgtest helper's unconditional cleanup is not reused here.

## Compatibility and non-goals

One signer key is pre-provisioned for all children; there is no distributed key
rotation/retirement acceptance. No invalidation bus or durable access-token
revocation is configured, so no live JWT-revocation propagation claim. No changes
to policy, TTLs, default debounce, fail-open issuance helpers, schema versions,
proxy trust, PKCE, Oracle-safe wire errors or refresh-family semantics.

Local loopback HTTP and plaintext PostgreSQL are isolated test transport, not
production TLS/edge guidance. `full` is not HA. External UI/callback/CSRF, stock
configuration/topology, real ARM/Mac, shared multi-host deployment, capacity/P99,
revocation SLA, backup/recovery, RPO/RTO, fresh OCI and protected publication stay
unaccepted. Existing OCI evidence remains bound to older bytes.

## Verification

After **every** Go edit: build, vet and committed architecture/maintainability
gates. Target all new scenarios with `-race -count=10` and a real isolated
PostgreSQL16 fixture. Run existing local reference/browser/grant compatibility,
E2E and complete `make ci`; PostgreSQL300 / Go package parallelism8 are local
fixture resources only. Obtain an independent read-only source/contract review
and close scoped findings. Keep local evidence under ignored
`dist/release-readiness/reference-process/`; never substitute Python reports
for committed root gates or release artifacts.

## Execution result

- All three process scenarios passed real-PostgreSQL `-race -count=10` after
  review fixes, with no skipped scenario. Logs record distinct parent/child
  PIDs; the competing exchanges are pinned directly to the two child URLs.
- Real child normal/fatal/panic/SIGKILL classification and reap-guard regressions
  also passed race10. The initial review's P1 (unexpected exit mistaken for kill)
  and P2 (DROP before reap) are closed; final independent read-only review
  reports no remaining scoped P0/P1/P2. It did not independently execute gates
  or authenticate evidence, builder identity or product security.
- Existing reference/browser/client/introspection/logout compatibility, all E2E
  and complete `make ci` passed on the updated merged tree. The isolated local
  fixture used PostgreSQL16 / 300 connections / Go package parallelism8, not a
  claim about remote CI defaults, service capacity or production pools.
- No production Go, public endpoint/config/SPI, schema, dependency, module or
  policy changes in this wave. Evidence is ignored local readiness data under
  `dist/release-readiness/reference-process/`, not a clean-tag release artifact.
- Normal child processes and the runner's owned database container were cleaned
  up. Unkillable-host cleanup deliberately fails and retains an isolated schema;
  this path is source/guard-reviewed, not an injected kernel failure test.
- Wave 5 remains incomplete: stock deployments, external browser/UI, multi-host
  shared state, distributed keys/revocation, database recovery/load, native
  ARM/Mac, updated OCI acceptance, protected publication and certification remain
  outstanding. No commit, push, image rebuild or publication was performed.
