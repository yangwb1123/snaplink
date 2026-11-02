# Step 32 — exact COPY business-table coverage

## Goal and owner

Extract one coherent coverage responsibility from
`ops/scripts/migration_guard/import_copy.py::copy_chunks`: business-table maps,
exact order-set/count and source/target coverage. Keep the existing lazy generator
as owner of SHA admission, SQLite lifetime, SQL/row emission and budgets. No new
writer or observer mode, option, dependency, schema or public SPI.

## Compatibility and acceptance

- `verify_snapshot` still executes only at first advancement and precedes all
  shape/coverage checks and SQLite opening. Invalid coverage emits no header.
- Keep metadata exclusion, map insertion order and original table references;
  preserve existing low-level duplicate-name behavior rather than introducing
  different grammar/defaults/exception ordering. No mutated/copy-normalized inputs.
- Keep caller order and sorted column list, explicit qualified COPY headers,
  exact UTF-8 escaped text, NULL/empty/bytea/stored JSON/int64/binary64/signed-zero,
  row counts, terminators and final copied marker. No inferred columns/defaults.
- Keep `mode=ro&immutable=1`, PRAGMA query_only, progress handler, deadline,
  2MiB row / 200k row / 128MiB byte limits, counter-before-check partial state,
  failure classes/reasons/ordering and final source SHA verification.
- Closing/cancelling a partially consumed generator closes its owned connection;
  it does not emit remaining rows, terminators or successful copied marker and
  cannot claim that downstream target effects rolled back. Generator output is
  proposed COPY input, not transaction/commit evidence.
- Import intent, empty-target locked admission, FK order, history verification,
  audit-only transactional restart, precommit verification, durable journal,
  commit acknowledgement plus successful child exit, no retry/unknown-write
  reconciliation and reader authority are byte-identical and unchanged.

Modify owner and `CHECKS_REGISTRY.md`; add this spec and
`checks/test_migration_copy_coverage_contract.py`. Reproduce unchanged conservative
AST16 before refactor. Every owner function <=15/50 lines, file <=500; no budget
or exemption change. Remaining admission/runner writer debts stay Partial.

Pin predecessor lazy byte/state/error/close/source-admission outcomes and compare
in fresh bounded interpreters. Use new owned PG16.14 candidates, one per before/
after writer run with new short-lived private pinned intent and durable outputs;
never reuse a populated/unknown destination. Synthetic native rows include exact
scalars, escaped control-shaped strings and declared parent-first FK dependency.
Compare normalized hash/metadata/status evidence and independent current content/
schema/sequence observations. Preserve nonempty rejection without replay or
cleanup-as-rollback claim; disclose fixture DDL/inserts and importer writes.
Native parity does not certify source provenance, exclusivity/global fencing,
uncertain commits, historical runtime, actual-time expiry, HA or cutover.

Run targeted/all checks, build/vet/committed Go gates, `make ci`, E2E, inherited
race x10 and supplementary acceptance. Freeze four-path scope, reconstruct exact
bounded patches, remove only verified owned fixture/private inputs, close and
rehash publication. Never rerun predecessor helpers against removed fixtures.

## Explicit non-goals

No import format/authorization/state-machine, reader, codec, policy, contract,
transport, journal/report, runtime refresh policy, production config/data,
historical transfer, restore, sequence allocation, SVERP live-mode, commit,
merge, push, release or deployment change. Reconstruction is not code approval.
