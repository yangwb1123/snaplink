# Current-base PostgreSQL storage combination

## Goal and scope

Give maintainers one isolated, testable candidate on primary commit
`b3812299daeab6e8147b402418d6488a3faeb775`, rather than an old-base patch that
conflicts with the current Makefile. Combine the previously isolated session and
PostgreSQL security adapters, pinned offline proto tooling, explicit conversion
policy, content/schema/recovery readers, protected candidate importer, and
supported sequence inventory. Keep current-primary protocol/security work.

This is an **unmerged source combination**, not a production migration, release,
or three-engine certification. MySQL runtime support is not added. SQLite and
existing PostgreSQL configuration APIs remain unchanged; root Go dependencies
and engineering/security budgets do not change. There is no new public SPI,
HTTP contract, YAML option, or database migration in this integration slice.

## Ownership and boundaries

Composition owns backend selection and the shared pool. PostgreSQL infrastructure
implements stores; protocol/domain interfaces do not acquire driver branches.
Migration evidence lives in `ops/scripts/migration_guard/`; writer admission and
transaction handling remain separate from the read-only CLI.

- `migrate_snapshot.py`: default empty-target preflight, or exactly one explicit
  row/content/schema/sequence observation mode. Verification of a populated
  candidate does not relax default preflight or authorize copying/resetting.
- `import_snapshot.py`: explicit short-lived pinned intent, private new journal
  and report, exact owned disposable candidate, empty contents, locked schema
  admission and complete content/history/FK checks before commit. Its supported
  sequence scope remains **canonical audit serial only**. It does not inherit
  the inventory reader's broader serial profiles or all-schema coverage.
- `postgres_recovery_check.py`: compare pinned native observations; never execute
  an archive. Recovery checkpoint sequence scope also remains audit-only.
- Shared report creation remains private, create-only and file/directory-fsynced.
  Failure after linking may leave evidence: it is not proof of rollback/removal.
- Shared target inspection retains the importer's whole-window deadline support.
  The sequence reader retains exact states/floors, validated full inventory,
  complete framing and successful child exit. It never allocates or calibrates.

ACCESS SHARE read locks do not fence ordinary writers. Sequence state is non-MVCC;
finite repeated observations are not atomicity, fencing or all-state certification.
An explicit candidate intent is a caller claim, not independent exclusivity or
production authority. Uncertain write outcomes remain unknown; never auto-retry.

## Acceptance and compatibility

- Build/vet, committed Go architecture/maintainability gates and full `make ci`.
- All inherited engineering regressions plus combination controls for CLI
  separation, populated/default purposes, deadlines, shared transaction endings,
  create-only durable reports and directory-sync failure.
- Owned loopback real PostgreSQL: new synthetic facts only, explicit one-shot
  import, independent content/schema/sequence observations, native history
  preservation, populated replay rejection and read-only unsupported inventory
  rejection. Record actual child exits and preserve failed attempts.
- Source/patch/archive hashes and protected prior worktrees are checked. No
  production service/config/data, retained real-source transfer, commit, merge,
  push or deployment is part of acceptance.

The separate converted-runtime handoff reports missing password-code OP sessions
and refresh issuance without requested `offline_access`, despite its CI passing.
Those runtime goals are **not repaired or recertified** by this source integration.
Live freeze/fencing, complete DDL/business relationships, keys/grants, historical
audit-chain disposition, production restore/topology and cutover remain separate.

## Verification

```sh
python3 -m pytest checks/test_migration_storage_combination.py -q
python3 -m pytest checks/ -q
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
go test -race -count=1 ./test/ -run TestE2E -v
python3 cli.py accept
```

Real-engine gates require an explicitly owned fixture, not a production DSN.
Missing offline caches or fixture failures are failures, not skips or fallbacks.
Actual generation/wire-breaking and deployment legs are not implied by proto lint
or the source-only acceptance above. Do not merge or switch production on this
report alone; revalidate any subsequently changed primary/candidate source.
