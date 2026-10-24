# Step 31 — recovery checkpoint document validation

## Goal and owner

Refactor only `ops/scripts/migration_guard/recovery_contract.py` so maintainers
can read distinct archive-fingerprint and source-identity responsibilities.
`validate_checkpoint` keeps ordered envelope/digest/content-shape/schema/audit
binding and returns the same unmutated document. No new migration/recovery mode.

## Exact compatibility

- Keep version1, algorithm, every exact field set and lowercase SHA grammar.
- Keep archive bytes as exact non-boolean integers 5..64MiB; same archive SHA
  validation precedes target-shape SHA, then source identity and content.
- Keep dedicated database regex, 1..256 username *character* limit and NUL
  rejection. No trimming, Unicode normalization, byte-budget substitution,
  role allowlist or implicit source/operator approval.
- Preserve all rejection classes/reasons/first-failure order, returned aliases,
  stored order and input continuity. Keep content totals/sorted PKs/metadata
  shape, schema coverage and canonical audit-only sequence validation unchanged.
- Preserve pinned read/no-follow/owner/private-mode/single-link/file-stability/
  bounded UTF-8 unique JSON, 256KiB checkpoint loading and successful complete
  observation. Archive evidence checks SHA/size/PGDMP prefix only, not full format,
  source provenance/consumption/correlation, restore execution or cutover authority.
- No SQL/transport/deadline/lock/schema/FK/scalar/report/checkpoint format or
  writer change. Keep strict Recovery history visibility and current refresh
  authorization unchanged; no historical source or retained database opening.

Modify the owner and `CHECKS_REGISTRY.md`; add this spec and
`checks/test_migration_checkpoint_validation_contract.py`. Pin predecessor
behavior and reproduce supplementary AST19. Every owner function remains <=50
lines / <=15 on the unchanged conservative metric; no new exemption or moving
measurement. Committed Go gates remain authoritative; three writer debts Partial.

Compare complete values, aliases, exceptions/order and checkpoint load outcomes
in bounded fresh interpreters. On a new owned PG16.14 fixture, create only
synthetic data, take one bounded public-only custom dump with matched native
pg_dump, and compare checkpoint capture/pinned-load/rejection outcomes. External
fixture DDL/inserts/audit calibration and pg_dump are disclosed separately;
verifiers never restore or write. Hash/prefix/native parity is not atomic backup,
archive provenance/correlation/consumption or production recovery proof.

Run targeted/all `checks/`, build/vet/committed Go gates, `make ci`, E2E,
inherited race x10 and supplementary acceptance. Freeze four-path scope,
reconstruct exact bounded patches, remove owned container/private connections/
synthetic source and dump, then close publication. Keep all predecessors immutable.

## Non-goals

No public SPI/Go/config/dependency/SDK/schema change; no historical credential,
key, grant/admin/session recertification, import/restore/data replay, production
operation, writer fencing/HA/full DDL/relationships/three-engine/cutover proof,
commit/merge/deploy or SVERP live-mode change. Integrity is not code approval.
