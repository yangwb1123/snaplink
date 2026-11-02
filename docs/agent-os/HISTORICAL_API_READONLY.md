# Historical API parity without source migration

## Goal and classification

Compare current public store reads against an immutable retained SQLite snapshot
and a new owned PostgreSQL candidate, preserving every original field/PK and
native history. Infrastructure constructor + migration evidence tooling; U1–U9,
applicable S4/S5 and all committed/full CI gates apply. No new HTTP/proto/SPI,
config, backend, dependency, grant, credential or runtime-session behavior.

## Non-migrating client wrapper

`sqlite.NewClientStoreWithoutMigrations(db)` only wraps the provided database.
It deliberately does not run migrations, validate a schema, manufacture missing
columns, establish read-only access or grant execution authority. The caller
owns initialization/read-only enforcement; ordinary Get/List still require the
current projection. `Close` retains ClientStore's existing shared-DB behavior.
Existing `NewClientStore` and `NewClientStoreWithDB` migration/error semantics
remain unchanged. This is opt-in, not an automatic legacy-schema fallback.

## Bounded observer projection

`migration_guard.client_read_projection` requires valid explicit policy version 2,
source/target pins, complete compatible shape and the exact client zero mappings
from [CLIENT_POLICY_ZERO_PROJECTION.md](CLIENT_POLICY_ZERO_PROJECTION.md).
It produces a bounded manifest and a **connection-local TEMP VIEW**, selecting
all original client columns plus explicit integer zeros for only the selected
absent policies. Existing source policy columns remain exact reads. It neither
upgrades/replaces the snapshot nor modifies SQLite main tables/history. Zero
values are declared new policy projections, never historical facts or attribute
inference. Unknown modes/columns, stale pins, missing proof and mixed malformed
mappings fail; no generic default or source-column omission.

The probe must open the pinned source with `mode=ro&immutable=1`, keep one owned
connection, put temporary metadata in memory, create the declared view only in
the TEMP namespace, then enable `query_only=ON` before API reads. Verify the
physical main columns and source SHA before/after, with no source sidecars.
Use the non-migrating client wrapper, not the legacy client's best-effort ignored
migration error. Other existing constructors may attempt their existing
initialization transactions; the main source remains physically read-only and
pending upgrades must fail. Disclose constructor initialization separately from
the query-only API window. A temporary projected view is not evidence that the
current constructor natively accepts the unextended old schema.

The target is a new owned candidate imported once via Step39 policy and the
protected writer. Target constructors run only after canonical initialization;
record complete before/after native content/schema/history and enforce read-only
API queries. Never reset/replay an unknown import or reuse removed fixtures.

## Acceptance and honesty

- Regression-first: wrapper performs no schema/migration work; old missing
  columns still fail without the explicit view; Get/List decode all current
  client fields from a read-only projected view, preserving secrets as hashes,
  metadata, NULL/empty distinctions at the full-storage evidence boundary.
- Reject policy/shape/default/PK drift, source column replacement, arbitrary SQL
  identifiers and unapproved zero columns; prove SELECT coverage and source SHA.
- Compare all users/clients, ID/external-ID lookups, RBAC roles/assignments/raw and
  effective menus, credential presence and stored sessions/inactive admission.
  Record actual counts and named failures, never print identities/hashes/tokens.
- A fresh candidate with same counts but a changed client field must fail API
  parity. No field exclusion, broad normalization, source upgrade or weakened
  assertion to obtain equality. Preserve failures and contemporaneous source.
- Complete original-row, native-history, schema and audit-serial preservation
  after observation. Read-only API parity is not password login/admin authority,
  key provenance, stock browser/session/renewal/logout/expiry or production
  freeze/fencing/recovery acceptance. Step22/38 failures remain immutable.

```sh
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./infrastructure/defaultimpl/sqlite -run TestClientStoreWithoutMigrations -v
python3 -m pytest checks/test_migration_client_read_projection.py -q
make ci
```

Independent code/security/integration review, deployed-engine acceptance and
explicit production cutover authority remain separate. This contract specifies
requirements; only completed bounded receipts establish observed outcomes.
