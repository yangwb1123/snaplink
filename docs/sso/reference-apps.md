# Two applications / two tenants: local reference acceptance

This is the runnable **SDK composition / HTTP acceptance recipe** for Wave 5a,
not a deployable frontend or stock `sso-server` deployment. The Go server remains
API-only. A test driver stands in for an external hosted-login UI and each
application's server-side BFF; it does not execute browser JavaScript, callbacks,
DNS/TLS, CORS or CSRF protections in an actual browser.

## Run

From the repository root:

```bash
go test ./test -run '^TestE2E_ReferenceApps' -count=1 -v
go test ./test -run '^TestE2E_ReferenceApps' -race -count=10 -v
```

The scenario uses ephemeral loopback HTTP ports and real in-memory SDK stores;
no Docker, registry credentials or database is needed for these particular tests.
Each run closes its listeners, JWKS refresher and owned store reapers. The key
rotation case observes the existing JWKS forced-fetch debounce (normally about
10 seconds); it does not lower the consumer defaults or assume a fixed sleep.

These commands are targeted checks, not the handoff gate. `make ci` also runs
root race tests, nested-module/example/config/module/SDK contracts. PostgreSQL
integration gates need an independently provisioned `SSO_TEST_POSTGRES_DSN`;
a skipped optional backend is not real-backend acceptance.

## Composition

```text
external UI / BFF-shaped driver
       | JSON login + cookie; form/Basic code exchange
       v
one API-only AS (embedded SDK)
       | JWKS                     | authenticated introspection
       +--------------------------+
       v                          v
Orders API                   Reports API
  online / offline routes      online / offline routes
       |                          |
 tenant + client + scope + current application permission
```

| RP/BFF registration | Tenant binding | Access audience | API scope |
|---|---|---|---|
| `orders-tenant-a` | `tenant-a` | `orders-api` | `orders:read` |
| `reports-tenant-a` | `tenant-a` | `reports-api` | `reports:read` |
| `orders-tenant-b` | `tenant-b` | `orders-api` | `orders:read` |
| `reports-tenant-b` | `tenant-b` | `reports-api` | `reports:read` |

Two fixture users have separate cookie jars and per-client role assignments.
Passwords are checked by the real stored-password verifier, including its
credential-store policy. Fixture passwords/secrets are test-only; BFF secrets
belong on a server, never in browser code, image build arguments or application
logs. Verifiers, state and nonce are random per authorization transaction.

A common OP cookie restores **identity**, not authorization or tenant membership.
Each RP still requests its own code/scopes/resource and receives independent
access/refresh credentials and an RP session. The tenant assertion is the signed
client binding, not proof that an arbitrary authenticated user belongs to that
organization. Real applications must enforce membership/permissions too; this
fixture checks current per-client permission assignments at the API. It does not
prove organization onboarding, JIT membership or invitation policy.

The API tenant expectation comes from server-side route configuration. A token
for the other tenant can have the **same valid audience** and must still be
rejected. Neither the audience alone, a browser-supplied tenant header, decoded
unsigned claims nor hidden UI menus are authorization.

## Evidence covered

| Test suffix (`TestE2E_ReferenceApps…`) | Observable acceptance |
|---|---|
| `IndependentGrants` | Discovery pins the issuer; both tenants get two independent RP grants; the second app does not repeat password verification; signed ID-token issuer/audience/nonce/session/`at_hash`, access-token client/tenant/audience/scopes/JTI and returned API data are checked |
| `APIIsolation` | Missing/garbage/ID bearer, wrong app, same-audience wrong tenant and forged tenant claims fail; a legitimate token lacking API scope fails; removing a role denies the existing token without reissuance |
| `GrantIsolation` | Code/PKCE and form/Basic exchange; consumed/unknown/wrong-client/wrong-verifier codes remain indistinguishable `invalid_grant`; refresh preserves binding and rotates; reuse kills the successor family; cross-client refresh is refused |
| `RevocationModes` | Active online access succeeds before revoke, then fails on its next request; inactive introspection exposes only `active:false`; another app survives; introspection unavailability does not fall back to local validation |
| `Logout` | Selected bearer/session is revoked, refresh stops and OP cookie disappears; independent RP credentials remain usable without a configured global logout fan-out |
| `SigningKeyOverlap` | Single-process signer promotes a new key, the warm consumer discovers it without weakened debounce, and both old/new live tokens verify during overlap |

All credential exchanges assert `Cache-Control: no-store` and `Pragma: no-cache`,
including errors. The reference tests exposed an older `/logout` header gap;
its handler now stamps the existing headers before binding, with adjacent early-
error coverage. This does not change logout payloads, revocation or failure policy.

The `offline` route intentionally accepts a correctly signed, non-expired revoked
JWT: local signature validation cannot see the AS deny-set. The `online` route
introspects on each request. Pick a mode according to the application's outage /
revocation budget; do not add an implicit offline fallback. Refresh in this
scenario returns access/refresh credentials, not a new ID token.

## Independent SDK processes (Wave 5b)

The separate process suite re-executes the Go test executable into two real OS
processes, each with its own heap, signer, pool and HTTP listener. A parent
loopback gateway maintains one issuer/origin and pins each requested step to a
chosen child. This is not stock `cmd/sso-server`, an OCI image or a load balancer
acceptance test. Application API/permission checks above remain the Wave 5a
in-memory scenario, not independently persisted applications.

Provision a **dedicated disposable PostgreSQL** and inject its URL in
`SSO_TEST_POSTGRES_DSN` through a trusted environment (do not publish credentials
or use a production database). The test needs schema create/drop privileges:

```bash
go test ./test -run '^TestE2E_ReferenceProcesses' -race -count=10 -v
go test ./test -run '^TestReferenceProcess(ExitClassification|ReapGuard)$' -race -count=10 -v
```

No DSN means skipped backend tests, not acceptance. Each case creates a random
private schema, seeds the two users/four clients once, then children open real
PostgreSQL users/passwords/clients/tenants/sessions/code/refresh stores without
seeding. Usernames in this fixture are canonical user IDs. Bcrypt defaults are
unchanged. Private temporary configuration holds a shared signing seed, a
separate lookup-HMAC key and DSN; readiness/log summaries contain no credentials.

| Test suffix (`TestE2E_ReferenceProcesses…`) | Observable acceptance |
|---|---|
| `CrossReplicaGrants` | Distinct child/parent PIDs; code issued on one child exchanges on its peer with PKCE; peer OP-session resume, two-tenant/four-client signed bindings, independent RP sessions, peer refresh/introspection and mismatched-client/tenant denial |
| `AtomicCodeConsume` | Simultaneous requests pinned to different child URLs produce exactly one successful exchange; loser/consumed/unknown codes have byte-identical no-store `invalid_grant` responses |
| `CrashRecovery` | After an explicit SIGKILL and reap, the peer exchanges an outstanding code and rotates a previously issued refresh token; a new child opens the same state/key, rejects consumed code, detects old-refresh reuse and kills the peer successor; shared-session logout prevents peer refresh while an independent tenant grant survives |

Crash acceptance requires POSIX SIGKILL exit evidence; Windows skips that case.
Normal EOF shutdown must exit successfully. Separate lifecycle probes reject
ordinary failure/panic as crash evidence and verify the reap guard. Child race,
panic or failed-test output is an error. Waits are bounded; if an OS failure
prevents reaping, the test fails and retains its isolated schema instead of
racing a DROP against a live child. Use only disposable test databases; resolve
failed cleanup before reusing them. This is not proof that every host failure
can be drained, canceled or recovered within a production deadline.

PostgreSQL remains alive while AS processes are killed; only **completed HTTP
operations** precede the crash. These tests do not establish in-flight issuance
exactly-once, database crash/failover durability, grace ownership, backup/restore,
RPO/RTO or automatic failover. One signing key is pre-provisioned; distributed
rotation is not tested. No invalidation bus or persistent access-JWT deny-set is
configured: the logout assertion is shared-session refresh liveness, **not**
instant peer/offline access-token revocation or global RP logout.

Process sources: `test/reference_process_{fixture,driver,lifecycle}_test.go` and
`test/reference_process_test.go`; [bounded specification](../proposals/reference-process-acceptance.md).

## Actual stock command processes (Wave 5c)

A third suite launches a **real freshly built `cmd/sso-server` command**, not
`TestReferenceProcessChild`. Supply a trusted local executable and a disposable
PostgreSQL DSN. Build outside the source tree's committed artifacts:

```bash
mkdir -p dist/acceptance
go build -mod=readonly -race -o dist/acceptance/sso-server ./cmd/sso-server
export SSO_TEST_STOCK_BINARY="$(pwd)/dist/acceptance/sso-server"
# Inject SSO_TEST_POSTGRES_DSN using your trusted test environment.
go version -m "$SSO_TEST_STOCK_BINARY"
"$SSO_TEST_STOCK_BINARY" modules --json
go test ./test -run '^TestE2E_StockProcesses' -race -count=10 -v
```

Missing binary/DSN means skipped cases, not stock acceptance. The binary must
be an absolute regular executable with the stock command path and `-race=true`
in its Go build metadata. Each case logs its SHA-256; this binds a selected
local file, not authenticated builder identity, current-source provenance or
clean-tag release. Build and record that provenance separately on a trusted
runner. POSIX signals are required; this suite does not accept Windows runtime.

The fixture writes private stock config/key/log files and starts real command
processes with `--config` and gRPC disabled. It declares topology `multi` with
`allow_per_pod_state: false`, PostgreSQL identity/sessions/tenant/password/OAuth,
stock password authentication, code/refresh, Browser SSO and one pre-provisioned
signing key. Parent-only provisioning seeds users/clients once; stock config has
no user/client seeds and bootstrap is disabled. Unrelated `SSO_*` environment
config overlays are filtered. All listeners and proxy trust are loopback only.

`TestE2E_StockProcessesCrossReplicaGrants`, `…AtomicCodeConsume` and
`…CrashRecovery` reuse the Wave 5b assertion bodies unchanged. `…RejectLocalState`
starts a deliberately unsafe multi config and requires the specific critical-
store boot refusal. `--validate-only` does **not** prove runtime store wiring or
that boot-only coherence check. Normal stock teardown uses SIGTERM, not the
SDK helper's stdin EOF; stock gets a 20-second wait around its existing
15-second shutdown budget, without changing the SDK helper's 10-second wait.
All processes must be reaped before DROP; child panic/race is never accepted.

Actual stock startup revealed and repaired a SQLite schema query being sent to
PostgreSQL sessions/tenants. The SQLite helper now checks the driver; native
PostgreSQL constructors reject any namespace ahead of their own declared
migrations via existing `ErrSchemaTooNew`. An older binary must not be used on a
forward-migrated database: schema versions are not reduced, and data is not
silently downgraded. This tighter native constructor gate also applies to SDK
PostgreSQL stores. Real PostgreSQL regressions cover sessions, users, clients,
tenants and passwords; no live CockroachDB result is implied.

The command has no inherited-listener option: fixture ports are reserved then
released before spawn. On this trusted local runner readiness checks the live
OS child and HTTP `/readyz`; it is not an authenticated PID-to-socket mapping or
a production port allocator. No external TLS/edge, container, independently
persisted application API, distributed registry/keys/JWT deny-set or multi-host
HA claim. PostgreSQL remains alive across AS termination; only completed HTTP
operations precede the crash. The previous database recovery/load/RPO/RTO and
UI/browser limitations remain. Source: `test/reference_stock_test.go`;
[bounded stock scope and startup amendment](../proposals/stock-process-acceptance.md).

## PostgreSQL TCP outage attempt (cycle-02: blocked, not accepted)

The test-only `TestE2E_StockProcessesPostgresOutageRecovery` uses the same
private stock fixture with a loopback TCP gate and a direct read-only PG
observer. It requires both existing environment inputs above; a missing backend
or stock binary is a skip, not outage acceptance. Its intended fault boundary
is a completed TCP cut/drain **before** grant consume, while both original AS
processes and PostgreSQL remain alive. It does not cover database crash,
failover, ambiguous in-flight commit, HA, or helper fail-open behavior.

```bash
go test ./test -run '^TestStockPostgresOutage(DSNBinding|ProxyCutAndRestore|ProxyCancelsDial|ProxyCloseJoins|SchemaGuard)$' -race -count=10 -timeout=10m -v
go test ./test -run '^TestE2E_StockProcessesPostgresOutageRecovery$' -count=1 -timeout=10m -v
```

The first command passed locally. The second is a **retained red**: on the
fresh stock binary and new disposable PG16, healthy `/readyz` returned 200 but
omitted the required `postgres` check. `wirePostgres` registers it before
`wireSigningIssuer` replaces the accumulated options. Existing identity/OAuth
checks were present; this result does **not** establish what readiness would
return after a cut. The test stopped before fault injection. Do not remove the
assertion or substitute another check to obtain PASS. Production code is
outside this approved test-only slice; further repair needs separate approval.

The proxy helpers test cut/restore, canceled late dial results, joined copies,
idempotent Close, strict single-loopback DSN binding, and the added conjunctive
schema teardown guard. These helper results do not establish stock outage or
credential preservation/recovery. No production/public API/config/schema or
module change was made. Full source gates and independent acceptance remain
pending; OCI is stale after the new COPY inputs. New evidence is under the
24-hour run's `cycles/cycle-02/evidence/`, separate from historical checkpoints.

The same-scope review repair is recorded separately in `evidence/resolve-01/`.
Its private cleanup helper now requires exact fixture ownership, command-bound
Wait/join proofs and an actual empty-schema/no-client PG audit **before stop**;
an unknown join, retained schema or failed audit preserves the running backend.
The original unsafe helper and all earlier failures remain historical records.
Proxy probes now bound the upstream pipe read by the existing five-second limit,
unconditionally release controlled blockers, and join their own writer/Cut/Close
goroutines on assertion failures. `TestStockPostgresOutageProxyFailureCleanup`
re-executes three intentional child failures and requires exit1, Wait and actual
gate join; timeout/panic/race is not an acceptable child outcome. The six helper
names (the five above plus this new regression) each passed race10 locally, as
did the two existing lifecycle guards. Twelve private cleanup regressions and
new real-PG retained-schema/failed-query safety checks passed. A fresh stock
control passed, but the outage E2E again failed at the unchanged pre-cut check.
This repairs the two review findings, not the production blocker or outage
acceptance. Fresh runner full gates and final independent review remain pending;
current OCI remains stale, with no rebuild/rescan/publication claimed.

## Readiness option preservation follow-up

A separately bounded production prerequisite fixes the option overwrite above:
`wireSigningIssuer` now appends configured/base options after the already
registered options instead of discarding them. The earlier Redis/PostgreSQL
readiness callbacks survive, without changing the relative order of configured
and base options. The production owner stays at 500 lines; no exemption, public
API/config/schema or dependency change is involved.

The adjacent composition regression preserves its old-code failure and checks
healthy, unavailable and restored readiness plus unaffected liveness. Signing
and readiness regressions passed race10. A fresh stock race binary and a new
owned PostgreSQL fixture then passed the original CrossReplicaGrants control
and **ten independent race-enabled executions** of the unchanged outage E2E
(each `-count=1`, not a single `-count=10` invocation). Both stock processes
remained alive through TCP cut/restore; original credential/state, reuse and
tenant-isolation assertions were not relaxed. The guarded live-PG schema/client
audit, child/proxy joins, stop/PID0/remove and absence checks completed.

Evidence is in the current run's `production-readiness-fix-01/evidence/`.
Fresh full source gates and final independent acceptance are still pending at
this checkpoint. Current OCI remains stale after the production-byte change;
no database crash/failover, HA, native-platform, container rebuild or publication
acceptance follows from this TCP-path test. All earlier red records remain.

## Not yet accepted

- An implemented external UI, real-browser callback/state/nonce/CSRF validation,
  browser-origin cookie isolation, real reverse proxy or public HTTPS issuer.
- Independently deployed production stock services or multi-host deployments.
  Wave 5a AS/APIs use one process and memory; Wave 5b uses SDK test helpers;
  Wave 5c uses real stock commands with test-specific PostgreSQL config on one
  host. None proves production deployment, a browser UI or a container release.
- Database failover/crash recovery, distributed key rollout or revocation
  delivery latency, backup/restore, capacity/P99, RPO/RTO, optional profiles or HA.
- Native ARM/Linux or Apple Silicon execution, updated OCI runtime/scans,
  protected publication/signing, production acceptance or OIDC/FAPI certification.

Sources: `test/reference_apps_fixture_test.go`,
`test/reference_apps_client_test.go`, `test/reference_apps_test.go` and
`interfaces/sso/logout_no_store_test.go`.
See the [bounded specification](../proposals/reference-apps-acceptance.md).
