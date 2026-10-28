# Refresh-grace concurrent close

## Goal and ownership

Remove the grace-wrapper race identified during the stock lifecycle review:
forced HTTP shutdown can leave a handler unwinding while SQLite/PostgreSQL
`Close` clears its database pointer. Store methods must not race, panic or
acquire a new database snapshot after closure. This is infrastructure store
lifecycle work (U1-U9, S1/S4-S7 as applicable), not a new OAuth flow.

Owners: `infrastructure/defaultimpl/sqlite/refresh_grace.go` and
`infrastructure/postgres/refresh_grace.go`; dependencies remain downward.
The files start at 304/277 lines, below 500; functions remain <=50 lines.
No new production package/file, dependency, exemption or configuration.

## Bounded implementation

- Publish/read/detach each wrapper's database pointer atomically. Capture it
  once per operation and use that local snapshot for the entire operation.
- Detach before cancelling/draining the pruner; have pruning use the same
  guarded path. Retain worker-before-owned-database-close ordering.
- Serialize repeated/concurrent `Close` with `sync.Once`, including completion
  and the owned connection's close result, without locking around SQL calls.
- DSN-owned SQLite closes its database. Borrowed SQLite and PostgreSQL only
  retire their wrapper; the caller-owned pool remains usable.
- A call admitted with a snapshot before detach may finish or return a normal
  database error. This is not cancellation/draining of all foreground work.
  Existing two-second credential-store operation contexts remain unchanged;
  readiness/prune keep their caller-provided contexts.
- Calls after `Close` get nil DB, miss/no-op or existing closed-store errors.
  For borrowed SQLite this deliberately makes wrapper closure terminal too;
  callers needing only to stop pruning can use `CleanupStop` instead.

Reject a nil SQLite database at construction (matching PostgreSQL), rather
than panicking before the lifecycle guards can apply.

No changes to SQL/schema, TTL/deadlines, pending/ready semantics, atomic token
consume, family reuse/revocation, issuance fail-open helpers, public wire errors,
no-store headers, successful stock ownership transfer or shutdown ordering.
General concurrent-close safety for other store types is out of scope.

## Tests and acceptance

Adjacent backend tests use real SQLite (owned and borrowed) and isolated real
PostgreSQL. Reproduce the old race with concurrent DB/readiness/grace operations
and repeated closers. After closure assert wrapper miss/no-op/error behavior,
pruner completion, owned DB release, and caller-pool survival/no post-close
writes. Include nil/zero lifecycle handling and a nil-constructor regression.

A stock integration test uses actual HTTP shutdown with an expired deadline
and a blocked in-flight handler; let that handler unwind through the real grace
API while asynchronous scheduler cleanup closes the wrapper. No sleep-based
production timeout changes, mock credential store or relaxed assertions.

After every Go edit: build, vet and committed architecture/maintainability gates.
Then backend/forced-shutdown lifecycle tests `-race -count=10`, existing grace
security/backend matrix, E2E, complete real-PG-backed `make ci`, and independent
read-only review. No new endpoint/config/error code, so those contracts stay
unchanged. Record evidence under ignored
`dist/release-readiness/concurrent-close/`.

Previous OCI/runtime/scans remain evidence for older bytes only. This source
follow-up does not claim rebuilt container acceptance, native ARM/Mac runtime,
clean-tag publication, signing, production acceptance or certification.

## Execution result

- Pre-fix real SQLite and PostgreSQL tests both reproduced data races and nil
  database panics (`sqlite-red.log`, `postgres-red.log`). A separate negative
  test reproduced the pre-existing nil SQLite constructor panic.
- Atomic snapshots and joined close are implemented in the two owner files,
  now 320/292 lines. Build, vet and committed architecture/maintainability
  gates passed after every Go edit; no exemptions grew.
- Final adjacent backend tests, stock lifecycle/forced HTTP shutdown tests and
  the existing memory/SQLite/Redis/real PostgreSQL grace security matrix all
  passed with `-race -count=10`. The forced HTTP test covers real store APIs in
  an unwinding handler, not a complete token protocol flow at forced shutdown.
- E2E and complete `make ci` passed with isolated PostgreSQL16
  (`max_connections=300`) and `GOFLAGS=-p=8`. No assertions, time thresholds or
  scan policy were weakened; this does not verify remote CI defaults.
- Independent read-only closure review reported no remaining scoped
  P0/P1/P2 after the nil-constructor guard/test; it did not execute gates or
  independently authenticate runtime, artifacts or the product.
- Logs/review are under `dist/release-readiness/concurrent-close/`.
  Existing container evidence remains attached to older bytes. No new container
  acceptance, commit, push, publication, signing or external certification.
