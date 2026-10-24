# Candidate import commit-protocol refactor

## Goal, surface and owner

Finish the previously enumerated conservative AST complexity debt in
`ops/scripts/migration_guard/import_runner.py` without changing candidate
writer semantics. Classification: refactoring only, internal tooling owner.
No new CLI, public SPI, config, schema, dependency, SDK, Go or production mode.

`ImportExecution.accept` keeps the whole-window deadline check **first**, then
one kind lookup and the ordered admission → empty baseline → copied marker →
content selectors. `accept_commit_protocol` owns the cohesive remaining
post-copy FK → transactional audit restart → exact attempt acknowledgement
phase. Selectors, field/equality tests, handler calls, mutations and terminal
error are relocated, not rewritten. No strategy table, fallback, state reset,
extra deadline, input normalization or newly accepted frame is introduced.

## Compatibility and authority

- Missing/blocked post-copy FKs reject before private-input rechecks and
  `verified_uncommitted`; FK total-budget failure retains its real incremented
  counter and does not append a result.
- Source → connection → policy → contract → intent → deadline rechecks retain
  their first-failure order. Durable journal calls retain their order relative
  to restart SQL and COMMIT. Existing functions, SQL and writer intent stay
  unchanged; broader sequence inventory does not expand audit-only restart.
- Restart evidence is assigned before rechecking. `commit_requested` is durably
  appended before setting the ambiguity flag and sending COMMIT. A send failure
  can therefore retain `commit_requested=True` while the stage remains
  `restart`; do not invent clean state, rollback or safe replay.
- Only the exact existing committed kind/attempt envelope marks the in-memory
  acknowledgement. It never substitutes for normal transport completion,
  the final whole-window check or durable `committed_acknowledged`. Complete
  frame followed by child failure still fails and preserves the actual flags.
- Unknown/nonmatching frames reject. Existing low-level equality/validator
  sequencing (including numeric equality followed by strict sequence-state
  validation) is not silently tightened.
- 60-second total execution, private pinned intent, complete empty locked
  admission, source/COPY/content/history/FK budgets, exclusive existing-table
  locks, cooperative advisory lock, journal/report durability, child cleanup,
  no automatic retry and reconcile-before-replay are unchanged. They do not
  establish independent exclusivity, global/admin fencing, cross-phase atomicity,
  actual network/crash ambiguity, rollback, production recovery or cutover.

## Files and verification

Modify the runner and `CHECKS_REGISTRY.md`; add this specification and
`checks/test_migration_commit_protocol_contract.py`. Retain all other predecessor
bytes. Changed-owner files ≤500 lines; functions ≤50 lines and conservative
AST ≤15 under the unchanged branch/exception/comprehension/Boolean metric.
Zero enumerated >15 functions is only this finite migration-owner diagnostic,
not a whole-repository cognitive/maintainability or production acceptance claim.

Before refactoring, pin deadline-first dispatch, reader completion, FK errors,
input rechecks, exact restart/ack frames, journal/send failures, real partial
flags and complete-frame-versus-child-exit boundaries. Supplementary fresh
interpreter comparisons retain complete typed ordered values/state/calls/SQL,
selected aliases, input continuity and exception class/reason, without dropping
cases or increasing output caps.

New owned PostgreSQL16.14 candidates separately disclose external DDL and actual
synthetic imports. Two positive candidates and two acknowledgement-mismatch
candidates have distinct new intents/outputs. Fault injection changes the
application-visible attempt only after receiving the actual committed frame;
this is **not** a real lost network acknowledgement or crash/failover test.
Finite read-only content/schema/sequence reconciliation of populated fault
candidates never converts their failed/unknown writer reports to success or
rollback proof. Never replay/reset those candidates. No retained historical
source/database, dump, restore, production settings or deployment is contacted.

Final checks: targeted regression, `python3 -m pytest checks/ -q`,
`go build ./...`, `go vet ./...`, committed Go gates, `make ci`, product E2E,
inherited refresh-policy race×10 and supplementary acceptance. Preserve initial
failures and skip/partial legs. Step32's original idempotency failure remains
unknown and uncorrected by this Python refactor; later passing gates are not
its independent repair. Integration/release and historical/production/three-engine
acceptance remain separately gated.
