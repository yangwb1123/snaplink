# Design: Postgres as a first-class OAuth hot-store backend

Status: design (sibling of `docs/auto/interfaces-sso-direction2-postgres-hotstore-spec.md`).

Scope: three decisions, landed in dependency order 1 → 2 → 3. Each decision
ships with `go build ./... && go vet ./...`, `go test -run
'TestMaintainability_|TestArchitecture_' .`, and — before handoff —
`go test ./... -race`, `go test ./test/ -run TestE2E -v`, and `make ci`.

Hard constraints that shape every decision below:

- `interfaces/sso` is frozen at its 60-file ceiling and its public options
  (`WithAuthCodeStore(store oauth.AuthCodeStore, ttl)` etc.) already accept
  any implementation — zero changes there.
- `infrastructure/postgres` is a root-module package (`package postgres`, no
  `go.mod`). Its existing `session.go` imports `interfaces/sso` under a
  grandfathered `layerExemptions` entry; the **new** store files must not
  create new upward edges — they import `protocols/oauth/oauthspi` (rank 3,
  below infrastructure rank 4), `platform/migrate`, `shared/core`.
- `infrastructure/postgres` may gain **exactly 4 new non-test files**
  (fan-out accounting per the spec acceptance check). Shared helpers
  (opaque-lookup HMAC) must fold into one of the four, exactly as the SQLite
  peers keep `opaqueLookupKey`/`opaqueLookupCandidates`/`cloneLookupKeys` in
  `defaultimpl/sqlite/auth_codes.go`.
- Every new file must stay under the 500-line file budget; every function
  under 50 lines, cyclo 15, `if`-nesting 3 — the SQLite peers already comply,
  so translations must preserve their extraction shape (scan/decode helpers
  pulled out of `Issue`/`Consume`).
- Oracle-safety table in AGENTS.md §3 is a regression boundary: all four
  stores collapse unknown/expired/consumed to the single `Err*NotFound`,
  and the refresh store collapses replayed-after-rotation to
  `ErrRefreshTokenReused`.

---

## Decision 1: Postgres implementations of the four OAuth hot-store SPIs

### API surface

Four new files in `infrastructure/postgres/`, same `package postgres`:

| File | Constructor | oauthspi interface satisfied |
|---|---|---|
| `auth_code.go` | `NewAuthCodeStoreWithDB(db *sql.DB, dialect Dialect) (*AuthCodeStore, error)` | `oauth.AuthCodeStore` (`Issue`, `Consume`) |
| `refresh_token.go` | `NewRefreshTokenStoreWithDB(db *sql.DB, dialect Dialect) (*RefreshTokenStore, error)` | `oauth.RefreshTokenStore` (`Issue`, `Consume`) |
| `device_code.go` | `NewDeviceCodeStoreWithDB(db *sql.DB, dialect Dialect) (*DeviceCodeStore, error)` | `oauth.DeviceCodeStore` (`Issue`, `GetByDeviceCode`, `GetByUserCode`, `Approve`, `Deny`, `UpdateLastPoll`, `Delete`, `ConsumeIfApproved`) |
| `par.go` | `NewPARStoreWithDB(db *sql.DB, dialect Dialect) (*PARStore, error)` | `oauth.PARStore` (`Issue`, `Consume`) |

Constructor contract, copied from the session-store precedent
(`infrastructure/postgres/session.go:93-105`): run the namespace's
migrations through `postgres.Run(ctx, db, namespace, migrations, dialect)`
at construction, fail loudly on error, and return the store. The caller owns
the pool (`New*WithDB` never closes it); `New*` DSN-openers are out of scope
— the shared-pool wiring (Decision 3) is the only production entry point,
mirroring `BuildSessionManager`.

Every store exposes the readiness trio the server builders consume today:

- `DB() *sql.DB` — satisfies `serverbuildsign.CheckSQLiteSchema`'s type
  probe (`build_readiness.go:44-54`), which is why Decision 3 must branch the
  schema gate; also feeds the storage-health reporter.
- `Ping(ctx) error` — attaches via `AppendReadyCheck`/`AppendStorageHealthSource`.
  Note: `AppendStorageHealthSource` only attaches sqlite schema-version
  reporting after `isSQLiteDB(db)`; postgres stores get the Ping-based entry
  only. That is acceptable parity — schema-version reporting for postgres
  pools is out of scope.
- `Close()` idempotent (no-op on nil/closed `db`), matching `SessionManager.Close`.

Configuration knobs are plain fields set by the builder after construction,
same names as the SQLite peers: `MaxEntries`, `ReapInterval` (auth_code /
device_code / par), plus `MaxRotationsPerWindow` / `RotationWindow` on the
refresh store.

Per-namespace max-version helpers (`AuthCodesMaxVersion()`,
`RefreshTokensMaxVersion()`, `DeviceCodesMaxVersion()`, `PARMaxVersion()`)
exported from `package postgres` — Decision 3's `CheckSchema` boot gate needs
them, and they keep migration/version knowledge in the owning package
(parallel to `defaultimpl/sqlite/maxversions.go`).

### Storage model

One namespace per store — `auth_codes`, `refresh_tokens`, `device_codes`,
`par` — each with its own `schema_migrations_<namespace>` version table and
per-namespace `pg_advisory_xact_lock` (CockroachDB: SERIALIZABLE + 40001
retry via `withRetry`, `migrate.go:75-120`). Because these namespaces are
new, a single baseline migration v1 carrying the **full** column set
suffices; the SQLite peers' v1..v8 backfill ladder
(`refresh_tokens_schema.go`) exists only for legacy SQLite databases and is
not translated. Version numbers are independent per backend.

DDL translation rules (all verified against the SQLite peers and the
`sessionSchema` precedent):

- Identifiers/column names verbatim; `TEXT` for codes/tokens and JSON
  columns, `BIGINT` for `unix_nano` timestamps, `INTEGER NOT NULL DEFAULT 0`
  for booleans/counters.
- JSON-encoded columns keep the exact sentinels: `'[]'` for
  scopes/resources/amr, `'{}'` for attributes, `''` for
  authorization_details/requested_claims/sid/acr, `0` for
  auth_time/generation/family_created_at (zero sentinel = "unset", never the
  Unix epoch).
- `expires_at` btree index per table; `refresh_tokens` additionally gets
  `(client_id)` and `(family_id)` indexes (subject index arrives in
  Decision 2).
- `refresh_token_families (token PK, family_id, expires_at)` ledger with
  `(family_id)` and `(expires_at)` indexes — the BCP §4.13 reuse ledger.
- `refresh_rotation_windows (family_id PK, count, window_start)`.
- Migration SQL strings must be single statements each (`splitStatements`,
  `migrate.go:150-166`): pgx's extended protocol rejects multi-statement
  Exec, and CockroachDB rejects multiple DDL in one explicit transaction.
  The baseline DDL is authored as separate CREATE TABLE / CREATE INDEX
  statements exactly like `sessionSchema`.

Semantics, translated statement-for-statement:

- **Atomic consume**: `DELETE FROM <table> WHERE <pk> = $1 RETURNING ...`
  for auth codes (`sqlite/auth_codes.go:303-320`), refresh tokens
  (`refresh_tokens.go:137-156`), device codes (`device_codes.go:253-272`),
  PAR (`par.go:164-180`). `sql.ErrNoRows` → `Err*NotFound`; an expired row is
  deleted and then reported as `Err*NotFound` — the same oracle collapse,
  with the row already gone so no separate cleanup is needed.
- **Device flow state machine**: `ConsumeIfApproved` is the same
  `DELETE ... RETURNING ... WHERE approved = 1` single statement — of N
  concurrent token-exchange polls exactly one wins (RFC 8628 single-use,
  race-safe across replicas).
- **Refresh family ledger**: `Issue` inserts the active row AND mirrors the
  `(token, family_id, expires_at)` ledger row. The SQLite peer does these as
  two statements relying on its single-connection serialization; Postgres
  needs explicit atomicity — wrap the pair in `runTx` (default isolation,
  append-only, no lost-update risk, still CRDB-40001-retried). A ledger-insert
  failure aborts the issue (fail closed): an active token without a ledger
  row would silently disable reuse detection for that family.
- **Reuse detection**: on `Consume` miss, look up the ledger; a hit returns
  `&oauth.RefreshToken{FamilyID: familyID}, oauth.ErrRefreshTokenReused` so
  the handler kills the family. Consumed ledger rows are retained for the
  token validity window (30-day default) and pruned by expiry — the SQLite
  v7 contract.
- **Rotation limiter**: `RecordRotation` is a read-modify-write
  (SELECT count/window_start, roll over the fixed window, upsert) — use
  `runTx` with `serializable` (`tx.go`) so CockroachDB 40001 retry semantics
  match the rest of the package. Fail-open contract per oauthspi: on store
  error return `(0, false, err)`, never `windowExceeded=true`.
- **Reaper**: `StartReaper(interval)` runs a background
  `DELETE FROM <table> WHERE expires_at < $1` (and the ledger prune for
  refresh tokens) using the `expires_at` index; `interval <= 0` disables it,
  and consume-time deletion still bounds growth — byte-identical to the
  SQLite behavior. Stop lifecycle mirrors the SQLite `Close()`/cancel
  contract so `go test -race` sees no goroutine leaks.

### Failure modes

| Failure | Behavior |
|---|---|
| Store outage (DB down) | `Issue`/`Consume` return wrapped errors → token endpoints 500. Errors are never mapped to `invalid_grant` — oracle table intact. |
| Migration failure at boot | Constructor error → boot fails loud (same as `NewSessionManagerWithDB`). Concurrent replica boots serialize on the advisory lock; CRDB retries 40001. |
| Concurrent `Consume` of one code/token | Single-statement `DELETE ... RETURNING` is atomic; exactly one winner, the rest see `Err*NotFound`. Verified by ported `-count=10 -race` concurrency tests. |
| Expired row presented | Deleted by the consume statement, reported as `Err*NotFound` — indistinguishable from unknown/consumed. |
| `RecordRotation` store error | `(0, false, err)` — the handler logs and proceeds (fail-open, per oauthspi). |
| Reaper failure | Background deletes are best-effort like SQLite; lazy consume-time deletion bounds growth regardless. |
| Clock skew | `expires_at` compared against server wall clock at consume time; a skewed replica may delete early/late but never leaks a different error class — same contract as SQLite. |
| Pool exhaustion / pgbouncer tx-mode | Inherits the shared-pool config and the `default_query_exec_mode=simple_protocol` caveat already documented in `pool.go`. |

### What could break the design

- **`?` → `$N` placeholder drift** in the translated statements — every
  statement must be re-checked against the SQLite original; the conformance
  tests are the backstop.
- **Missing transaction on the ledger mirror** — the one place where a
  "translation" that drops the `runTx` wrapper would silently degrade reuse
  detection instead of failing. Treat as fail-closed by construction.
- **Multi-statement DDL in migrations** — pgx rejects it; the baseline must
  be authored in `splitStatements`-compatible single statements.
- **CockroachDB divergence** — `DELETE ... RETURNING` works, but the
  rotation RMW and the ledger mirror need the serializable+retry path;
  skipping it turns a contended cluster into 40001 500s.
- **Budgets**: 4 new non-test files is the fan-out allowance; opaque-lookup
  helpers must live inside `auth_code.go` (SQLite precedent). File/function
  budgets force the same extract-scan/decode-helper structure the SQLite
  peers use.
- **New upward imports** — importing `interfaces/sso` (as `session.go`
  does) would require a forbidden `layerExemptions` entry. The new files
  import `oauthspi` only.
- **Test-DB availability in CI** — the ported conformance tests must use the
  same postgres test-DB harness as the existing `postgres_test.go` files, or
  `make ci` silently skips the only real verification of this decision.

---

## Decision 2: Optional-SPI and opaque-lookup parity

### API surface

The postgres `RefreshTokenStore` implements the full optional surface the
SQLite and Redis peers carry (`sqlite/refresh_tokens.go` + `refresh_tokens_rotation.go`,
assertions at `redis/refresh_token.go:493-496`), with compile-time assertions
at the bottom of `refresh_token.go`:

- `oauth.RefreshTokenInspector` — `Inspect` (non-destructive SELECT, expired
  rows deleted opportunistically) and `Delete` (idempotent, RFC 7009 §2.2).
- `oauth.RefreshTokenSubjectIndex` — `DeleteAllForSubject(userID, clientID)`,
  the GDPR account-erasure path (`build_app_oauth.go:245-247`).
- `oauth.RefreshTokenSubjectCounter` — `CountForSubject`, the erasure
  dry-run blast-radius preview.
- `oauth.RefreshTokenClientPurger` — `DeleteAllForClient(clientID)`, the
  tenant-suspension proactive purge (`interfaces/sso/server_tenant.go:169`).
  Empty clientID MUST be a no-op, not a wildcard.
- `oauth.RefreshTokenFamilyTracker` — `DeleteFamily(familyID)` returning the
  count of active tokens killed; deletes ledger rows too.
- `oauth.RefreshTokenRotationLimiter` — `RecordRotation` (Decision 1).
- `oauth.RefreshTokenExpiryLister` — `ListExpiring(before, limit)`, the
  governance expiry calendar (`interfaces/sso/sso.go:375`).

All four stores implement `SetLookupHMACKeys(...[]byte)` with the same
domain-separated kinds — `"auth_code"`, `"refresh_token"`, `"device_code"`,
`"par"` — and the same helper trio (`opaqueLookupKey`, `opaqueLookupCandidates`,
`cloneLookupKeys`) ported into `auth_code.go`. Read candidates: current key,
then previous key, then legacy plaintext — a no-logout key rotation works
identically on postgres.

Config surface mirrors `OAuthRedisConfig` (`config/config_oauth2.go:100-113`):

```go
type OAuthPostgresConfig struct {
    LookupHMACKeyFile         string `yaml:"lookup_hmac_key_file"`
    LookupHMACPreviousKeyFile string `yaml:"lookup_hmac_previous_key_file"`
}
// OAuthConfig gains: Postgres OAuthPostgresConfig `yaml:"postgres"`
```

`serverbuildstore` gains `ResolveOAuthPostgresLookupHMACKeys(cfg) ([][]byte, error)`
reusing the existing shared `resolveOAuthLookupHMACKeys` core (current-key-
required, previous-requires-current, 32-byte minimum — `build_oauth_stores.go:112-180`).

No behavioral change in `interfaces/sso`; the existing type assertions stop
being no-ops. A guard test in `infrastructure/postgres` asserts the **full
optional assertion set in one place** so a future edit that drops an
interface fails the build/test loudly instead of silently degrading a
shipped feature.

### Storage model

- `DeleteAllForSubject` / `CountForSubject`: index on `refresh_tokens(user_id, client_id)`
  (spec name `idx_refresh_tokens_subject_client`); both paths also delete the
  matching `refresh_token_families` rows so a revoked subject leaves no reuse
  ghosts.
- `DeleteAllForClient`: `(client_id)` index; empty clientID returns `(0, nil)`
  before touching SQL.
- `DeleteFamily`: delete active rows by `(family_id)` index, count them,
  then delete ledger rows for the family; unknown family → `(0, nil)`.
- `ListExpiring`: `expires_at` range scan (`>= now AND <= before`, ASC,
  optional `LIMIT`). **Parity detail**: the SQLite peer computes
  `Thumbprint` from the *stored* lookup value (`RefreshTokenThumbprint(token)`
  over the `h1:` column, `refresh_tokens.go:356-386`) — the raw token is
  never persisted. The postgres store must do exactly the same so governance
  output is byte-identical across backends.
- Opaque lookup: stored code/token = `h1:` + base64url(HMAC-SHA256(key,
  kind ‖ 0x00 ‖ raw)); `nil` keys fall back to raw (identical to SQLite —
  operators must set key files in production). The grace cache (Decision 3)
  stores only `sha256(raw)` — a one-way hash, not the secret.

### Failure modes

| Failure | Behavior |
|---|---|
| Store drops an optional interface | Compile-time assertion + guard test fail loudly. This is the failure mode the decision exists to prevent — silent degradation of tenant purge, revoke-all, GDPR erasure, reuse detection, rotation cap. |
| `RecordRotation` error | Fail-open `(0, false, err)` — never blocks a legitimate refresh. |
| Ledger rows orphaned by `DeleteAllForSubject`/`DeleteFamily` | Reuse detection sees ghosts → spurious `ErrRefreshTokenReused` family kills. Mitigated by deleting ledger rows in the same statement/transaction as the active rows. |
| Lookup-key files unset | Raw plaintext storage (nil-key fallback) — same as SQLite/Redis; config docs must say "required in production". |
| Previous key dropped too early | In-flight grants become unreadable → mass `invalid_grant`. The current→previous→legacy candidate order and the TTL-eldest-artifact documentation rule apply unchanged. |
| HMAC key rotation mid-flight | Old rows readable via previous-key candidate; new rows written with current key — no logout needed, same as peers. |

### What could break the design

- **Thumbprint semantics drift**: if a reviewer "fixes" `ListExpiring` to
  thumbprint the raw token, it must store raw values to do so — that would
  break the opaque-lookup invariant. The parity contract is: thumbprint over
  the stored lookup value, matching SQLite byte-for-byte.
- **Subject-index consumers assume per-store behavior**: the three call
  sites (`server_tenant.go:169`, `sso.go:375`, `build_app_oauth.go:245-247`)
  are type assertions that silently no-op. The guard test is the only thing
  standing between a refactor and silent degradation — it must be a hard
  test failure, not a skip.
- **Sentinels drift in scan/decode** (`'[]'` vs `''` vs `0`): a wrong
  sentinel changes wire-visible claims (empty scopes vs nil, epoch auth_time
  vs omitted). Ported tests must assert round-trip equality on every
  JSON/timestamp column, including the zero cases.
- **`DeleteAllForClient` wildcard footgun**: the empty-clientID no-op guard
  is an oauthspi hard requirement (`refresh_token.go:290-293`); the ported
  test must include the empty-ID case.
- **Config-key scope creep**: `oauth.postgres.*` must not accidentally
  shadow the shared `postgres:` block (identity). The `postgres:` block
  remains the single DSN source; `oauth.postgres` carries lookup keys only.

---

## Decision 3: Stock-binary surface closure — `oauth.backend=postgres` end to end

### API surface

`cmd/sso-server/serverbuildstore/build_oauth_stores.go` — all four
dispatchers gain `case "postgres":` and thread the shared pool:

```go
func BuildAuthCodeStore(cfg config.OAuthConfig, rdb goredis.Cmdable,
    pgDB *sql.DB, pgDialect postgresbackend.Dialect) (oauth.AuthCodeStore, error)
// ... same for BuildRefreshTokenStore / BuildDeviceCodeStore / BuildPARStore
```

Postgres branch: `pgDB == nil` → `errPostgresNotConfigured("oauth")`
(the shared error from `build_identity_stores.go:29-33`); otherwise resolve
`oauth.postgres` lookup keys, construct via `New*StoreWithDB`, set
`SetLookupHMACKeys`, `MaxEntries`, `StartReaper`. The `default:` error enum
becomes `(supported: memory, sqlite, redis, postgres)`.

`cmd/sso-server/build_app_oauth.go` — three wiring points:

1. **Schema boot gate**: `wireOAuthGrantStores` / `wireRefreshToken` /
   `wireDeviceCodePAR` currently run `serverbuildsign.CheckSQLiteSchema`
   unconditionally (`build_app_oauth.go:201-238`), which would query the
   SQLite version-table format against a postgres pool and falsely fail boot
   (`build_readiness.go:44-54`). Branch on the resolved backend, following
   the `checkIdentityLinkSchema` precedent (`build_stores.go:403-410`):
   sqlite → `CheckSQLiteSchema`, postgres →
   `postgresbackend.CheckSchema(b.schemaCtx, b.pgDB, "auth_codes",
   postgresbackend.AuthCodesMaxVersion())` (and the other three namespaces).
2. **Ready-check/health names**: switch `sqlite-oauth-auth-codes` etc. to
   backend-accurate names (`postgres-oauth-*`), and append the postgres
   per-store Ping entries via `AppendStorageHealthSource`; the shared pool
   `/readyz` check already exists from `wirePostgres`
   (`build_bootstrap.go:289-320`).
3. **Rotation grace**: `wireRefreshRotationGrace` gains
   `case "postgres":` (`build_app_oauth.go:257-300`), constructing a new
   `postgresbackend.NewRefreshGraceStoreWithDB(b.pgDB, b.pgDialect, w, 0)`
   plus ready check and prune-lifecycle wiring, mirroring the sqlite branch
   (`NewRefreshGraceStoreWithDSN`, line 285). The `default:` error lists
   postgres.

Config and docs (same change): `config.OAuthConfig.Postgres` + doc comments
(`config/config_oauth2.go:5-17`); `docs/config-reference.md` lines 100-105 —
`oauth.backend` enum gains `postgres`, lookup-key scope becomes
`oauth.{sqlite,redis,postgres}.{lookup_hmac_*}`,
expiry-cleanup row mentions postgres reaper, rotation-grace row gains
`postgres`; feature-matrix OAuth rows list `memory · sqlite · redis ·
postgres`.

Tests (`cmd/sso-server/oauth_stores_test.go` + `build_stores.go` HA wiring):

- postgres build cases (no DSN needed beyond the shared block; sqlite-DSN
  error and unknown-backend error stay, message now lists postgres).
- negative: `oauth.backend: postgres` with no `postgres:` block fails boot
  with the `errPostgresNotConfigured`-style message.
- HA lock: `perPodBackend` flags only `""`/`memory`
  (`build_stores.go:132`), so `oauth.backend=postgres` is automatically
  valid in `TopologyModeMulti` without `AllowPerPodState` — assert this
  explicitly so it stays true.

### Storage model

- Refresh grace cache: new namespace `refresh_grace` with
  `refresh_grace_cache (consumed_token_hash TEXT PRIMARY KEY,
  successor_response BYTEA, expires_at BIGINT)` + `expires_at` index —
  the SQLite shape (`refresh_grace.go:19-34`) with `BLOB`→`BYTEA`.
  `Lookup` is non-destructive and returns `false` on ANY uncertainty
  (miss/expiry/error) so the caller fails closed to family-reuse detection —
  the `tokengrant.RefreshGraceStore` contract
  (`internal/handler/tokengrant/refresh_grace.go:90`)
  is never weakened.
- No new DSN: all four stores + the grace cache share `b.pgDB`, built once
  by `wirePostgres`. `oauth.backend=postgres` reuses the `postgres:` block
  exactly as `identity.session_backend=postgres` does.
- Per-namespace `CheckSchema` boot gates keyed off the exported
  `*MaxVersion()` helpers, so a forward-migrated DB against an old binary
  fails boot with `ErrSchemaTooNew` (the documented degraded-key-state
  503-style guard, adapted).

### Failure modes

| Failure | Behavior |
|---|---|
| `CheckSQLiteSchema` run against a postgres pool (pre-fix) | False boot failure. Fixed by backend-branched schema gate. |
| `oauth.backend: postgres` without `postgres:` block | Loud boot error (`errPostgresNotConfigured("oauth")`) — same shape as the sqlite-DSN error; never a silent memory fallback. |
| Unknown backend value | `default:` error now lists postgres in the supported enum. |
| Forward-migrated DB + old binary | `CheckSchema` → `ErrSchemaTooNew` boot failure, per namespace. |
| Grace-store DB error at `Lookup` | Returns `false` (fail closed) — rotation falls back to family-reuse detection; BCP §4.13 never weakened. `Remember` failures are logged, fail-open (the grace window is a resilience layer, not a security gate). |
| Grace-store table growth | Background prune at `expires_at` (sqlite peer's `CleanupStop`/`CleanupDone` lifecycle mirrored). |
| Multi-replica boot race on new namespaces | Advisory lock per namespace serializes migrations; CRDB retries. |

### What could break the design

- **Namespace/version-table drift**: `CheckSchema`'s `binaryMax` comes from
  the same package as the migrations, but only if the max-version helpers
  stay colocated and are actually used by `wireOAuthGrantStores` — a
  hardcoded constant would rot. Guard: `make ci` config/doc check plus the
  boot-gate tests.
- **Ready-check name collisions**: `sqlite-oauth-*` vs `postgres-oauth-*`
  names are operator-visible in `/readyz`; the branch must produce exactly
  one name per backend, and the storage-health dedup must not drop the
  postgres entries.
- **Rolling upgrade asymmetry**: an old binary rejects `oauth.backend:
  postgres` loudly (it must — the enum didn't exist); a new binary against a
  DB migrated by an even-newer binary fails `CheckSchema`. Both are
  acceptable and loud; the design must not introduce a silent third state
  (e.g. skipping the schema check).
- **HA-coherence regression**: if a future `perPodBackend` change flags
  postgres as per-pod state, multi-replica deployments would be rejected —
  the new test locks the current (correct) behavior.
- **Docs drift**: `docs/config-reference.md` lines 100-105 and the
  feature-matrix rows are checked by the config gate (`python cli.py`
  config check); the enum/scope/cleanup/grace rows must change in the same
  commit as the code or `make ci` fails.
- **E2E byte-parity**: `test/` runs the four flows with `oauth.backend:
  postgres` and must assert byte-identical wire responses to the sqlite run —
  any drift (e.g. a different error body, a missing `Cache-Control: no-store`
  header) fails the gate.

---

## Verification summary per decision

| Decision | Key gates |
|---|---|
| 1 | build/vet; maintainability/architecture; ported conformance tests (`-race -count=10`, incl. concurrent-consume single-winner and reuse detection); E2E four flows on postgres |
| 2 | compile-time assertions; guard test (full optional set, hard fail); optional-interface tests (revoke-all, client purge + empty-ID no-op, family kill, rotation cap, `ListExpiring`, lookup-key rotation); E2E revoke-all/suspension/erase parity |
| 3 | boot tests (postgres block present/absent, unknown backend enum), schema-gate branch, readiness names, rotation-grace postgres, HA-coherence lock, `python cli.py` config check, `make ci` |

Dependency order is strict: 1 unblocks 2 (the optional surface sits on the
same tables/statements), 2 unblocks 3 (a stock binary advertising postgres
must not silently drop purge/erasure/reuse features). Each lands with its
own gates; a failure in a later decision never relaxes an earlier one.
