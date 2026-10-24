# Step 30 — read-only schema reader frame transitions

## Goal and owner

Migration-evidence maintainers need a readable frame dispatcher without changing
admission or completion. Refactoring only in
`ops/scripts/migration_guard/target_schema.py`: `SchemaReader.accept` remains the
explicit ordered stage/kind/field-set dispatcher. Identity assignment, validated
environment advancement and completion validation become named methods beside
existing catalog/facet/FK methods. No strategy table, state reset or new authority.

## Compatibility and acceptance

- Keep all dispatch conditions, envelope field sets, error classes/reasons and
  first-failure precedence exactly. Rejected/truncated/extra/repeated/wrong-stage
  frames never become successful schema evidence.
- Preserve before/after reader state even on failures, return values, frame
  immutability, stream sends/order/final markers and identity count-scope flags.
- Completion requires every expected FK frame, read-only `on`, and isolation
  `repeatable read`; valid completion does not replace successful child exit.
- Preserve FK flags, strict counts, total scan budget and partial failure state.
  Missing declared FKs still mean `not_executed`, not business relationship PASS.
- `RecoverySchemaReader` inherits the methods but retains its stricter catalog,
  history visibility and shape checks. Observe histories only on new synthetic
  fixtures, never reopen retained/historical databases.
- Keep catalog locks/SQL/FK SQL/fingerprints/content codecs/transport/deadlines/
  reports/checkpoints/importer/sequence limits unchanged. No writer dispatch.

Modify the owner and `CHECKS_REGISTRY.md`; add this spec and
`checks/test_migration_schema_reader_contract.py`. First pin predecessor behavior
and reproduce `accept`'s conservative AST18 violation. All owner functions/methods
must remain <=50 lines / <=15 on the unchanged supplementary metric; the committed
Go engineering gates remain authoritative. Other four Python debts stay Partial.

Compare bounded complete stage transcripts, aliases/state mutations/errors,
stream sends and evidence against Step29 in fresh interpreters. Compare complete
native schema reports and native Recovery observations on a new owned PG16.14
fixture, including history RLS denial. Controlled fixture setup/mutation/restores
are external writes, not observer behavior, fencing, archive or restore proof.
Run targeted/all `checks/`, build/vet/committed Go gates, `make ci`, product E2E,
inherited race x10 and supplementary acceptance. Freeze four-path scope,
reconstruct exact bounded patches, remove only owned fixtures/private inputs and
close publication. Never rerun predecessor removed-fixture helpers.

## Non-goals

No API/Go/config/dependency/SDK/schema change, historical runtime recertification,
production data/configuration operation, dump/restore/import, live writer fencing,
atomic backup/HA/three-engine/cutover certification, commit/merge/deploy, SVERP
live-mode change or independent code/integration approval.
