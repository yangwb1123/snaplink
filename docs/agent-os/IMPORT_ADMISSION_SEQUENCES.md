# Candidate sequence-admission refactor

## Goal and boundary

Reduce the admission dispatch's inherited conservative AST complexity without
changing a writer's authority, protocol, errors or partial state. The operator
still needs an explicit pinned, short-lived intent for a new disposable
candidate; an admission-complete frame is not copied content or commit proof.
Classification: refactoring only, owned by `ops/scripts/migration_guard/`.
No public SPI, CLI, configuration, schema, dependency, SDK or Go change.

## Responsibility split

`AdmissionReader.accept` keeps identity → catalog → environment → ordered
facets first. `accept_sequence_admission` owns the following cohesive phase:
ordered declared-FK results → canonical audit BIGSERIAL descriptor → exact
public-sequence coverage. Ordered selectors, field sets, validators, SQL,
return values and terminal rejection remain the same; no strategy table,
fallback, reset or new accepted input is introduced.

- Descriptor admission requires all expected FK results and no relationship
  blockers **before** validating the descriptor. Missing declarations still do
  not prove undeclared business/tenant relationships.
- Descriptor fields/types/configuration and name grammar retain the existing
  strict validator. Its original object alias is retained.
- The public catalog query is sent before advancing to `sequences`. If sending
  fails, the actual descriptor assignment survives but the stage does not
  advance. FK scan-budget failure likewise retains the incremented counter
  without appending a result. Do not manufacture clean failure state.
- The complete stage requires exactly the existing ordered one-element list
  containing the audit sequence name. Extra, missing, duplicate or other
  public sequences reject; this does not expand import/recovery to the broader
  read-only sequence-inventory profile.
- Existing transaction/window/input/output budgets, exclusive existing-table
  locks and cooperative advisory lock are unchanged. They are not independent
  admin/global DDL fencing, same-UID isolation or cross-phase atomicity.
- `import_runner.py`, intent, journals, COPY, precommit verification, restart,
  child-exit/commit-ack and no-retry/uncertain-write reconciliation are unchanged.
  Admission never sends COPY, sequence restart or COMMIT itself.

## Files and acceptance

Modify `import_admission.py` and this registry; add this bounded specification
and `checks/test_migration_admission_sequence_contract.py`. Other predecessor
source bytes are preserved. All changed-owner functions must meet the unchanged
supplementary conservative AST ≤15 and ≤50-line budgets; files ≤500 lines.
This metric counts branches, exception handlers, comprehensions and Boolean
alternatives as before. It neither replaces committed Go gates nor waives the
separate inherited runner dispatch debt.

Tests first pin stage/envelope/value rejection order, FK errors and counters,
descriptor aliases, send failures, exact sequence coverage, full transcript
SQL/final flags and completion without commit authority. Supplementary exact
before/after comparisons include complete state, ordered outputs, aliases,
input continuity and exception class/reason. New owned PostgreSQL16.14
candidates supply separately disclosed import/negative/reader observations;
never replay an uncertain candidate or contact a retained historical database.

Required final validation: targeted tests, `python3 -m pytest checks/ -q`,
`go build ./...`, `go vet ./...`, committed root Go gates, `make ci`, product
E2E, inherited refresh-policy race regressions and supplementary acceptance.
Native fixtures, external DDL and actual candidate writes are not production,
historical authentication, full DDL/relationship, fencing, rollback, recovery,
three-engine or cutover acceptance. The predecessor's initial idempotency CI
failure retains an unknown cause; passing reruns are not its repair.
