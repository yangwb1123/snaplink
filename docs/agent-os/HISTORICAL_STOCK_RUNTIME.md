# Historical candidate stock-runtime rehearsal

## Goal and boundary

Continue the read-only store/API handoff with the actual `cmd/sso-server` binary
on fresh, owned PostgreSQL candidates. This is an acceptance contract, not an
execution receipt or production authorization. No injected session-creating
verifier, source upgrade, existing candidate reset, historical password guess,
real-client grant edit, or production configuration change is permitted.

The three profiles are independently initialized/imported control, browser-off,
and browser-on. Each gets a different ownership nonce, version2 conversion
policy, full native schema contract, short-lived intent and durable writer
journal/report. Every import must preserve the complete mapped 18-table/10,558-row
snapshot, all native migration histories and the canonical audit sequence. A
populated or uncertain target is never a retry target.

## Startup and cleanup admission

Bind the actual stock file/environment/optional-etcd/flag source chain and all
runtime-only flags before interpreting an omitted interval. `config.Load(path)`
alone is not that chain. The [finite launch binding](STOCK_STARTUP_LAUNCH.md)
rejects overlays outside its exact owned-rehearsal context but does not establish
configuration bytes, complete effects, future use, fencing or startup authority.
Do not strip an enabled/unreviewed environment setting merely to pass the guard.

Inventory effective configuration and actual owners before traffic: constructors,
client/password seeding, OAuth reapers, sessions, refresh grace, audit retention,
snapshot retention and optional security/user-lifecycle schedulers. Include
unconditional `RevocationStore.Load -> Prune`, default builtin bootstrap (not
just YAML seeds), and the immediate client-secret scan's possible audit appends.
The [finite preservation prerequisites](STOCK_STARTUP_PRESERVATION.md) reject
known conflicts but do not establish the complete inventory or authorize startup.
Use separate owned bootstrap tracker paths for off/on; preserve each across its
own restart, never prefill history or share it to skip pending steps. Distinguish
an omitted default-zero interval from actively disabling a previously enabled
reaper. Do not tune intervals, disable cleanup, rewrite old timestamps or exclude
expired rows to satisfy historical retention. Record an incompatible genuine
cleanup policy as failed/partial and require a separate business decision.

The first running-stock checkpoint must compare every original typed business
PK/full row, including expired rows, against the untouched imported control.
Compare EACH independently initialized candidate's complete native history PK/
full-row digests and schema with its OWN original before-import observation;
independent initialization `applied_at` values are not a common historical baseline.
Do not ignore or rewrite timestamps within a candidate. Retain all 28 tables.
Repeat after each stopped runtime profile; new synthetic actors and
runtime/audit facts are additions, not rewritten historical facts. Count parity
alone is insufficient. Keep sensitive PK/row digest maps bounded and in memory;
publish only complete-coverage summaries. These independent observations do not
prove cross-database atomicity, global fencing or same-UID isolation.

## Bounded wire acceptance

Use only fresh synthetic passwords/keys and collision-checked actors. Exercise
stock password login, S256 PKCE, single-use code exchange and authenticated
userinfo; exact code-bound `offline_access`, omission/default/narrowing and
refresh-denial boundaries; persisted managed refresh HMACs, normal restart,
rotation/reuse and logout. Default-off must create no fabricated OP session/SID/
cookie. Only the explicitly enabled profile may create the supported OP anchor.

Verify the configured synthetic session duration and preserved authentication
context. An actual short refresh-family lifetime test is not a 30-day wall-clock
session test; injected expiry is not natural expiry. Report actual-session expiry,
tenant/client/resource/subject binding and every unexecuted dimension separately.
Do not promote a finite synthetic wire subset to full historical HTTP/business
parity or the previously failed Step22/38 runtime goals.

Requests, responses, logs, SQL, helper windows and subprocesses remain bounded.
Credentials stay in private files or memory, never argv, public reports or raw
wire logs. Attribute each listener to the exact owned child before sending
credentials. Require normal shutdown and joined log readers; retain failed
sources/output and reconcile unknown writes before continuation.

## Delivery and remaining gates

Retain exact changed-source bytes, bounded patches, contemporaneous helper
versions, native observations and real command exits. Run committed Go gates,
`make ci`, product E2E and owned-PG supplementary acceptance. No new exemptions,
skips, limits, assertions or favorable-timing retries.

Historical password/admin/external-key authority, full business HTTP equivalence,
independent security/integration review, final freeze/correlated backups/grants,
deployed PostgreSQL15 recovery/uncertain commits, actual MySQL/Vault and production
cutover remain separate. No automatic commit, merge, push, deployment, live-service
restart or SVERP HMR/backend-watch/30-day-session change. Remove only the exact
owned disposable fixture/private inputs after complete reconciliation; cleanup
is not rollback certification. See [the broader runtime contract](CONVERTED_RUNTIME_ACCEPTANCE.md)
and [the store-read handoff](HISTORICAL_API_READONLY.md).
