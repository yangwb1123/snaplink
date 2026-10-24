# Explicit client-policy zero projection

## Goal and boundary

Support the three target-only client policy columns introduced by native SQLite
migration 9 and PostgreSQL migration 7 when importing an older pinned snapshot
into a fresh owned candidate. Do not infer policy from editable client attributes
or claim newly projected defaults were historical facts.

Owner: `ops/scripts/migration_guard/`, tooling/evidence plus governed candidate
execution. Universal build/vet, committed Go architecture/maintainability gates
and full `make ci` apply. This changes no Go SPI, schema migration, OAuth flow,
client registration, runtime configuration/default, dependency or deployment.

## Explicit contract

- Existing policy version 1 keeps its exact two-entry legacy mapping grammar,
  limits and rejection ordering. It never authorizes client defaults.
- Version 2 opts into `client_policy_zero_v1` and must contain at least one such
  mapping. Its finite allowlist is the two legacy pairs plus exactly:
  `clients.skip_consent` (int4), `clients.consent_refresh_interval` (int8),
  `clients.allow_passwordless_only` (int4). Maximum five distinct mappings; the
  private 16KiB policy budget and all row/output/deadline budgets remain unchanged.
- Every entry still has exactly `table`, `column`, `mode`; arbitrary literals,
  default expressions, tables and columns are not accepted. Source SHA and
  column-shape SHA remain mandatory. The selected source column must be absent.
- The target column must be a non-PK NOT NULL native pg_catalog integer of the
  exact type and have canonical native constant DEFAULT 0, not identity/generated.
  Native catalog evidence adds optional Boolean `canonical_zero_default`; legacy
  frames without it remain readable but cannot authorize this new projection.
  The catalog computes it from exact `pg_get_expr(...) = '0'` and excludes
  identity/generated columns. Raw default expressions are not added to reports.
- Project literal integer zero explicitly into every row and COPY cell; never
  rely on omitted-column database defaults. The plan records new-policy origin,
  complete row counts and no rewriting/inference of historical fields.
- Full typed expected content/PK digests include the three new values. The writer
  revalidates the new mapping against its locked catalog before COPY; the pinned
  native schema contract and complete precommit content/history checks still
  apply. Missing evidence, drift or tampered literal values fail closed.

The shape hash still does not certify defaults or complete DDL. The added Boolean
is checked separately before projection, in current locked reader catalogs, and
before COPY; the native schema contract binds full default expressions. Existing
locks do not establish global/admin DDL fencing or production authority.

## Regression and native acceptance

Retain version-1 rejection of the original three columns. Test explicit opt-in,
partial mappings, all three exact types, absent source columns, native namespaces,
NULL/Boolean/integer flag confusion, duplicate/wrong mappings, stale pins,
nonempty target admission, literal tampering, reader/locked-writer drift,
attribute nonauthority, exact COPY and complete content mismatch detection.
Preserve original stored fields, NULL/empty, PKs, audit ordering and deadlines.

Use fresh owned PostgreSQL fixtures for successful synthetic/retained imports
and rejected native default drift. Preserve original failed test sources and
normal child exits. Do not replay finalized fixtures, upgrade/replace the retained
snapshot, delete target columns/history, reset populated candidates or use the
legacy common-column mover. Historical stock runtime/password/admin/key/expiry
acceptance and deployed PG15 restore/fencing remain separate; Step22/38 failures
are immutable. Synthetic/local/PG16 evidence is not production cutover approval.

## Verification

```sh
python3 -m pytest checks/test_migration_client_policy_zero.py checks/test_migration_client_policy_stream.py -q
python3 -m pytest checks/ -q
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
make ci
```
