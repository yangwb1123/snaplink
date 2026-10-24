# Step 28 — read-only scalar and catalog contract refactor

## Goal and ownership

Migration-evidence maintainers need readable, independently testable validation
without changing the facts or admissions that the reader accepts. This slice is
refactoring only in `ops/scripts/migration_guard/target_codec.py` and
`target_content.py`; no Go/package boundary, SPI, CLI flag, dependency, schema,
configuration, SDK or engine support changes.

## Required compatibility

- Preserve cell/tag validation before scalar decoding, exact integer grammar and
  ranges, UTF-8 validation, binary64 bytes (including signed zero), bytea, and
  NULL/empty distinctions. Stored JSON text is never parsed or re-rendered.
- Preserve exception type/reason and validation order, catalog/table/column
  budgets, field sets, duplicate checks, native-type namespace and visibility
  rejection. Preserve original ordering and input objects without mutation.
- Preserve the existing metadata-only catalog seam; it is not business/history
  visibility or recovery certification. Recovery's stricter checks stay intact.
- Identity, locked catalog admission, data dispatch, completion, successful child
  exit, SQL/frame/scan deadlines, digest construction and report durability stay
  unchanged. ACCESS SHARE remains DDL protection, not ordinary-writer fencing.
- Populated observation never authorizes import, sequence reset or cutover.

## Files and verification

Modify the two owning modules and `CHECKS_REGISTRY.md`. Add
`checks/test_migration_reader_contract.py` and this bounded specification.
First run behavioral regressions against predecessor code and reproduce its
supplementary AST complexity failures; then extract scalar decoding and catalog
validation responsibilities within the existing owners. Keep the unchanged
conservative AST ceilings of 15 complexity / 50 lines for these owners; no new
exemptions. This metric is supplementary, not the committed Go gate.

Verify complete predecessor/current results and exact exception reasons with
bounded synthetic differential cases; compare read-only native PostgreSQL
content/PK evidence and rejection outcomes on a new owned fixture. Run targeted
and complete `checks/`, build/vet/committed Go gates, `make ci`, product E2E,
inherited offline-policy repeated race tests and supplementary acceptance.

## Non-goals and delivery

No historical source query/import, production contact, writer/recovery change,
HA/failover/fencing/atomic snapshot claim, other engine certification, commit,
merge or deployment. Preserve all predecessor deliveries and other worktrees.
Freeze exact source, retain failures, independently reconstruct bounded patches,
remove only this slice's fixtures/private inputs and publish a closed receipt.
Remaining complexity debt stays Partial; historical/production blockers remain.
