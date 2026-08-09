All checks complete; temp artifacts removed and the working tree is untouched. Here is the validation verdict for the four claims.

## Verdict per claim

### 1. New SELECT vs partial index and query plan — ✅ CONFIRMED

- **Index unaffected**: `idx_clients_tenant` is schema-level DDL (`sqlite/clients.go:49-51`). The legacysync package contains zero DDL and never writes the `clients` table (`applyPlan` only touches users/password_credentials/permissions_roles/permissions_assignments). Verified via `sqlite_master` that the index is intact and still serving (`WHERE tenant_id <> ''` → `SCAN clients USING INDEX idx_clients_tenant`).
- **Plan unchanged in kind**: `EXPLAIN QUERY PLAN` on 5000 rows + `ANALYZE`, via both the sqlite3 CLI and the actual `modernc.org/sqlite` driver the tool uses:
  - `SELECT id FROM clients WHERE active=1` → `SCAN clients`
  - `SELECT id, COALESCE(tenant_id,'') FROM clients WHERE active=1` → `SCAN clients`
  
  Identical access path, identical predicate, identical unordered scan. `COALESCE` is a pure select-list expression — no join, subquery, or sort introduced; no index exists on `active` either way.

### 2. Missing-column failure — ✅ CONFIRMED (loud), with one cosmetic drift

- **Loud**: with the real driver, the proposed query on a column-less table fails at prepare time with `SQL logic error: no such column: tenant_id (1)` (verified in a live test). `run()` control flow (`main.go:43-47`) propagates it as `target clients query: ...` → `reportError` → stderr + exit 1, before `buildReport`, the write branch, and `printReport` — in both dry-run (`mode=ro`) and `--apply`.
- **"No server-created target can lack it" holds**: v1 (`clients.go:36-52`) is the baseline migration; git history shows the original ClientStore commit (`cacd7758`) created the byte-identical 10-column schema including `tenant_id TEXT NOT NULL DEFAULT ''` and the partial index. `migrate.Run` applies v1 on fresh DBs and no-ops onto the identical historical schema on pre-existing DBs — every server-created table has had the column since the store's introduction.
- **Cosmetic drift**: design §5 M4 quotes `target clients query: no such column: tenant_id`; actual text is `target clients query: SQL logic error: no such column: tenant_id (1)`. Substance identical.

### 3. Fixture parity — ⚠️ CONFIRMED for parity, but U4/U6 are self-contradictory

- **Parity is exact** for the column: `tenant_id TEXT NOT NULL DEFAULT ''` matches type/constraint/default. `seedTarget`'s existing `INSERT INTO clients(id,active)` keeps working (`DEFAULT ''` fills), and binding `sverp-web` is necessary to keep the two existing tests green under the new gate.
- **Real inconsistency**: U4 ("fixture row with `tenant_id` NULL fails identically to `''`") and U6 ("NULL yields `''`") **cannot** use the `NOT NULL` parity fixture — verified: `INSERT ... (tenant_id) VALUES (NULL)` fails with `constraint failed: NOT NULL constraint failed: clients.tenant_id (1299)`. A NOT NULL column cannot hold NULL. The design must state that U4/U6 build a separate hand-made schema with nullable `tenant_id TEXT DEFAULT ''` (which is exactly its own "NULL only occurs in hand-made schemas" premise); as written it contradicts itself.
- Minor: "representation change fully contained in target.go, 3 touch sites" — `target_test.go`'s composite literal `Clients: map[string]struct{}{}` is a 4th mechanical touch site (the doc does list the file as modified, so only the phrasing is off).

### 4. Operational UPDATE — ✅ SQL sound; ❌ "admin API/UI writes the same column" is FALSE

- **The UPDATE is sound**: with `NOT NULL DEFAULT ''`, NULL rows cannot exist (verified), so `AND tenant_id = ''` is the complete unbound predicate; the guard makes it idempotent and cannot clobber an existing binding. Consistent with the whitespace-is-bound rule (`' '` is not matched and the gate treats it as bound).
- **The admin API cannot write tenant_id — the design doc's parenthetical is wrong**:
  - `proto/admin/v1/clients.proto:85-88`: "Read-only over the admin API… Mutations never consume these fields — binding is established at registration time (YAML/DCR/federation)."
  - Code confirms: `protoToClient` never consumes `TenantId`; `applyProtoToExistingClient` never sets `c.TenantID`; grpcadmin comment "TenantID is intentionally read-only on the admin wire" (`admin_clients.go:59`); `interfaces/admin` (HTTP) has no client endpoints; `cmd/sso-ctl/clientscmd/clients.go:70-72` documents the same. The admin UI consumes this API, so it cannot write it either.
- **Actual write paths for `clients.tenant_id`**: (1) YAML bootstrap seed — `config/config_client.go:20-24` (`tenant_id` yaml knob, documented at `config.yaml:489`) → `seedClients` (`build_app_core.go:91`) → `ClientStore.Put` (INSERT OR REPLACE, `tenant_id` in the insert column list); (2) DCR `POST /register` — request field `tenant_id` (`protocols/oauth/handle_register.go:72,114`) stamped into `client.TenantID`; (3) direct SQL UPDATE. So the operational UPDATE is **not** "equivalent to the admin API/UI" — it is the only post-hoc rebinding path besides config re-seed or DCR. The migration step should say "config re-seed, DCR, or direct SQL" and drop the admin API/UI equivalence claim.

## Net

3 of 4 claims fully confirmed (1, 2, and the SQL half of 4); claim 3 and the parenthetical in claim 4 need design-doc corrections: U4/U6 require a nullable fixture variant, and the admin API/UI cannot write `tenant_id`. Two cosmetic drifts (error-text prefix, touch-site count) do not change substance. No code changes were made; no build gates were triggered (the temp test file was removed).
