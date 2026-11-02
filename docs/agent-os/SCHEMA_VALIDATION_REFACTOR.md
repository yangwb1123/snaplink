# Step 29 — native schema contract, facet and declared-FK validation

## Goal and ownership

Refactor-only: migration-evidence maintainers need readable schema admission
without changing accepted inputs or facts. Owners are the existing
`ops/scripts/migration_guard/{schema_contract,schema_records,declared_fk}.py`.
Separate document/provenance/table validation, record grammar/name/support
checks, and FK column/behavior checks in those modules; no new package/framework.

## Required compatibility

- Preserve exact version/algorithm/field sets, SHA grammar and private pinned
  contract loading. Provenance hashes are evidence inputs, never operator grants.
- Preserve 100 tables / 80 columns / 256 facet records, exact integer/boolean and
  UTF-8 scalar grammar, duplicate detection, returned object identity and order.
- Preserve exception class/reason and first-failure precedence, including
  low-level helper edge behavior; the public facet-frame guard still rejects
  unknown facets. No new fallback, implicit baseline or empty success.
- Preserve native namespace/identity/generated, index readiness, relation hazards
  and collation-drift rejection. Existing finite supported scope is not full DDL.
- Preserve scoped public FK parents, ordered component membership/uniqueness,
  native equality/action/match admission and identifier validation order.
  MATCH SIMPLE/FULL SQL, NOT VALID/orphan blockers and missing-declaration
  `not_executed/no_declared_foreign_keys` remain unchanged. No business/tenant
  relations are inferred or certified.
- Leave SQL generation, reader state/locks/completion, fingerprints, transport,
  deadlines, reports, importer/recovery writers and sequence authority unchanged.

## Files and verification

Modify the three owners and `CHECKS_REGISTRY.md`; add
`checks/test_migration_schema_validation_contract.py` and this bounded spec.
First pin behavioral regressions and reproduce three inherited supplementary
AST violations; refactor responsibilities without moving/widening measurement.
All changed-owner functions stay <=50 lines / <=15 conservative AST complexity;
this diagnostic is supplementary, not the committed Go cyclomatic gate.

Compare exact predecessor/current results, aliases, exceptions and generated FK
SQL with bounded differential cases. On a new owned PostgreSQL16.14 fixture,
compare complete schema-only reports and explicit contract/FK/DDL rejection
outcomes. Controlled setup/mutation/restore writes are fixture actions only;
observers do not import, repair, reset sequences or grant cutover permission.
Run targeted/all `checks/`, build/vet/committed Go gates, `make ci`, product E2E,
inherited ten-repeat race and supplementary acceptance; freeze and reconstruct
exact bounded patches, remove owned fixtures/private inputs and close delivery.

## Non-goals

No API/config/schema/dependency/SDK or production Go change; no historical query,
import, production operation, live freeze/fencing/atomicity/HA/recovery proof,
three-engine certification, commit/merge/deployment. Unrepaired Python debt stays
Partial. Preserve every predecessor and other worktree; revalidate any change
before separately approved integration.
