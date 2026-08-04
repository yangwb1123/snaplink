# Requirements Specification: interfaces/sso — Direction 2

Postgres becomes a first-class backend for the OAuth hot stores
(auth_code / refresh_token / device_code / PAR).

Source: `docs/auto/interfaces-sso-analysis.md`, 方向二.
Module: `interfaces/sso` (SPI boundary — **frozen, no new files**, package is
at its 60-file ceiling), `infrastructure/postgres` (new store
implementations), `cmd/sso-server/serverbuildstore` + `cmd/sso-server`
(wiring), `config` (enum + knobs), `docs/config-reference.md` +
`docs/feature-matrix.md` (contract docs).
Out of scope (separate directions): SDK option/config-surface registry
(方向一), `interfaces/sso` thin-delegation slimming (方向三), flow-level
observability (`flow_id`).

Background facts established by inspection (all verified in current code):

- `docs/config-reference.md` line 100: `oauth.backend` accepts only
  `memory · sqlite · redis`, while line 99 `identity.session_backend` already
  accepts `memory · sqlite · redis · postgres` — the asymmetry named by the
  direction.
- `infrastructure/postgres/` (36 files) contains zero OAuth protocol stores;
  `infrastructure/redis/` has `auth_code.go`, `device_code.go`, `par.go`,
  `refresh_token.go`, `refresh_token_rotation.go`; `infrastructure/defaultimpl/
  sqlite/` has `auth_codes.go`, `device_codes.go`, `par.go`,
  `refresh_tokens*.go` — the SQLite reference implementation is complete and
  tested (`auth_codes_test.go`, `device_codes_test.go`, `par_test.go`,
  `refresh_tokens_*_test.go`).
- `cmd/sso-server/serverbuildstore/build_oauth_stores.go`:
  `BuildAuthCodeStore` / `BuildRefreshTokenStore` / `BuildDeviceCodeStore` /
  `BuildPARStore` each switch `case "", "memory" | "sqlite" | "redis"` and end
  with `default: ... unknown oauth.backend %q (supported: memory, sqlite,
  redis)` — a `backend: postgres` YAML value fails loud at boot today.
- SQLite stores implement atomic single-use consumption with
  `DELETE ... RETURNING` (`sqlite/auth_codes.go:303-320`,
  `refresh_tokens.go:137-156`, `device_codes.go:253-272`, `par.go:164-180`),
  a consumed-token family ledger for OAuth Security BCP §4.13 reuse detection
  (`refresh_tokens_schema.go:60` `refresh_token_families`), and a rotation
  velocity window (`refresh_tokens_schema.go:83` `refresh_rotation_windows`).
  Postgres supports `DELETE ... RETURNING` natively, so the semantics
  translate without protocol risk.
- Postgres already hosts one hot store: `infrastructure/postgres/session.go`
  `NewSessionManagerWithDB(db, dialect, ttl)` runs per-namespace migrations
  via `Run(ctx, db, "sessions", sessionMigrations, dialect)` and is wired as
  `identity.session_backend=postgres` through
  `serverbuildstore.BuildSessionManager` (`build_identity_stores.go:267-300`)
  reusing the single shared pool `b.pgDB` built by `wirePostgres`
  (`build_bootstrap.go:291`). `infrastructure/postgres/migrate.go` provides
  the namespace runner (`Run`) and the boot gate
  `CheckSchema(ctx, db, namespace, binaryMax)` (line 224).
- `interfaces/sso` consumes the OAuth stores only through the SPI types in
  `protocols/oauth/oauthspi/` (`AuthCodeStore`, `RefreshTokenStore`,
  `DeviceCodeStore`, `PARStore` + optional extension interfaces) and via
  type assertions for the optional surface: `server_tenant.go:169`
  (`oauth.RefreshTokenClientPurger` for tenant-suspension purge),
  `sso.go:375` (`RefreshTokenExpiryLister` governance), and
  `cmd/sso-server/build_app_oauth.go:245-247` (`RefreshTokenSubjectIndex`
  for GDPR account erasure). A backend that omits an optional interface
  silently degrades those features — parity is therefore an
  `interfaces/sso`-visible behavior contract, not a cosmetic one.

Dependency order: 1 → 2 → 3 (stores first, parity second, stock-binary
surface closure last). Each improvement lands with the mandatory gates
(`go build ./... && go vet ./...`, `go test -run
'TestMaintainability_|TestArchitecture_' .`) and, before handoff,
`go test ./... -race` and `make ci`.

## Decision 1: Postgres implementations of the four OAuth hot-store SPIs

**Name**: `infrastructure/postgres` gains `auth_code`, `refresh_token`,
`device_code`, and `par` stores satisfying the existing `oauthspi` interfaces
via the shared-pool constructor pattern.

**Problem**: a Postgres-standardized deployment cannot run the
authorization-code, refresh, device, or PAR flows without standing up a
second stateful service (Redis) or a shared SQLite file. The most
enterprise-grade backend is the weakest on the OAuth core path, and the
analysis doc's limitation A ("Postgres → 仅持久化 identity store，无 OAuth
ephemeral stores ❌", `docs/architecture/architect-analysis-expansion-v10-
directions.md` lines 35-40) is still true in current code. This is a pure
translation gap: the SQLite peers already implement every required semantic
(atomic consume via `DELETE ... RETURNING`, TTL expiry, family ledger) and
Postgres supports the same DML, so the risk is DDL/transaction adaptation,
not protocol design.

**Evidence**:
- `infrastructure/postgres/` file listing — no `auth_code.go`,
  `refresh_token.go`, `device_code.go`, `par.go` (while `infrastructure/
  redis/` and `infrastructure/defaultimpl/sqlite/` have all four).
- `infrastructure/defaultimpl/sqlite/auth_codes.go:303-320` —
  `DELETE FROM auth_codes WHERE code = ? RETURNING ...` atomic consume;
  `sqlite/refresh_tokens.go:137-156`, `sqlite/device_codes.go:253-272`,
  `sqlite/par.go:164-180` — same pattern for the other three; the exact
  column sets the Postgres DDL must carry (incl. `confirmation_jkt`, `sid`,
  `requested_claims`, `authorization_details`, `amr`, `acr`, `resources`).
- `infrastructure/postgres/session.go:93-105` —
  `NewSessionManagerWithDB` + `Run(ctx, db, "sessions", sessionMigrations,
  dialect)` — the established shared-pool + per-namespace-migration template
  for hot stores on Postgres (used by `identity.session_backend=postgres`).
- `protocols/oauth/oauthspi/auth_code.go` (`AuthCodeStore`), `refresh_token.go`
  (`RefreshTokenStore`, line 183), `device_code.go:54`, `par.go:80` — the
  interfaces to satisfy; `interfaces/sso` needs no change
  (`options.go:359` `WithAuthCodeStore(store oauth.AuthCodeStore, ttl)` etc.
  already accept any implementation).

**Proposed behavior**:
- Add `infrastructure/postgres/auth_code.go`, `refresh_token.go`,
  `device_code.go`, `par.go` (+ `_test.go`) with constructors
  `NewAuthCodeStoreWithDB(db, dialect)`, `NewRefreshTokenStoreWithDB(...)`,
  `NewDeviceCodeStoreWithDB(...)`, `NewPARStoreWithDB(...)`, each running its
  own migration namespace (`auth_codes`, `refresh_tokens`, `device_codes`,
  `par`) through `postgres.Run` and exposing `DB() *sql.DB` / `Ping` like the
  session store, so readiness plumbing works unchanged.
- Translate the SQLite DDL verbatim (same column names, JSON-encoded
  `scopes`/`attributes`/`amr`/`resources`/`authorization_details`/
  `requested_claims`, `unix_nano` timestamps, `expires_at` index) and keep
  the exact consume semantics: single-statement `DELETE ... RETURNING`,
  expired rows collapsed to the same `Err*NotFound` (oracle-safe), and the
  refresh family ledger (`refresh_token_families`) + reuse detection that
  returns `ErrRefreshTokenReused`.
- Reuse `runTx`/`serializable` (`infrastructure/postgres/tx.go`) for the
  read-modify-write paths (rotation + ledger + grace) so CockroachDB 40001
  retry semantics match the rest of the package; the `DELETE ... RETURNING`
  consume itself stays single-statement (no transaction needed).
- TTL expiry: mirror the sqlite `StartReaper` contract with an
  `expires_at`-indexed background `DELETE`; when `ReapInterval` is 0, lazy
  consume-time deletion still bounds growth for the one-shot stores exactly
  as SQLite behaves.

**Acceptance check**:
- `go build ./... && go vet ./...` and the maintainability/architecture gates
  pass; `infrastructure/postgres` gains no more than 4 new non-test files
  (10-file fan-out budget respected).
- Ported conformance tests (port `sqlite/auth_codes_test.go`,
  `device_codes_test.go`, `par_test.go`, `refresh_tokens_rotation_test.go`
  shapes against a Postgres test DB) pass with `-count=10` under
  `-race`, including concurrent-Consume single-use tests (only one winner
  per code/token) and family-reuse detection.
- `go test ./test/ -run TestE2E -v` passes with `oauth.backend: postgres`
  in the test harness config (auth-code, refresh, device, PAR flows
  byte-identical to the sqlite run).
- `python cli.py`-reachable check or `make ci` confirms no contract doc
  drift (see Decision 3).

## Decision 2: Optional-SPI and opaque-lookup parity with the sqlite/redis peers

**Name**: postgres stores implement the full optional extension surface
(`SetLookupHMACKeys`, `RefreshTokenSubjectIndex`/`Counter`/`ClientPurger`/
`FamilyTracker`/`RotationLimiter`/`ExpiryLister`) so no `interfaces/sso`
feature silently degrades when the backend is postgres.

**Problem**: the optional interfaces are consumed by `interfaces/sso`
itself through type assertions — `server_tenant.go:169` (`RefreshToken
ClientPurger` for tenant-suspension purge), `sso.go:375`
(`RefreshTokenExpiryLister` governance data), and
`cmd/sso-server/build_app_oauth.go:245-247` (`RefreshTokenSubjectIndex` for
GDPR self-service erasure). A postgres refresh store that implements only
`Issue`/`Consume` would silently turn off tenant suspension purge,
revoke-all, family reuse detection, and the rotation velocity cap — the
worst possible failure mode for a "first-class" backend. The lookup-HMAC
protection (`SetLookupHMACKeys`, domain-separated opaque keys) is likewise a
mandatory production behavior for all three existing backends
(`docs/config-reference.md` line 101) and must not be missing on the fourth.

**Evidence**:
- `infrastructure/defaultimpl/sqlite/refresh_tokens.go:471-475` and
  `infrastructure/redis/refresh_token.go:493-496` — compile-time assertions
  `_ oauth.RefreshTokenSubjectIndex = (*RefreshTokenStore)(nil)` etc. — the
  parity target list.
- `interfaces/sso/server_tenant.go:169` — `purger, ok :=
  s.refreshTokenStore.(oauth.RefreshTokenClientPurger)` (tenant-suspension
  proactive purge); `interfaces/sso/sso.go:375` — `RefreshTokenExpiryLister`
  read-through for governance; `cmd/sso-server/build_app_oauth.go:225-228` —
  `oauth.RefreshTokenSubjectIndex` assertion for the account eraser.
- `protocols/oauth/oauthspi/refresh_token.go:233-370` — the optional
  interface contracts (`DeleteAllForSubject`, `CountForSubject`,
  `DeleteAllForClient` with the empty-clientID-no-op footgun guard,
  `DeleteFamily`, `RecordRotation`, `ListExpiring`).
- `cmd/sso-server/serverbuildstore/build_oauth_stores.go:180-188` —
  `lookupHMACStore` interface + `configureRedisLookup`; `ResolveOAuthLookup
  HMACKeys` (line 112) — current/previous/legacy key rotation; the sqlite
  stores apply it in `auth_codes.go:196-199` (`SetLookupHMACKeys`,
  `opaqueLookupKey(firstLookupKey(...), "auth_code", code)`); config surface
  `OAuthSQLiteConfig.LookupHMACKeyFile` / `OAuthRedisConfig`
  (`config/config_oauth2.go:100-113`); test `cmd/sso-server/serverbuildstore/
  oauth_lookup_key_test.go`.
- `infrastructure/defaultimpl/sqlite/refresh_tokens_rotation.go:11` —
  `RecordRotation` implements `RefreshTokenRotationLimiter` atomically (the
  per-family velocity cap wired from `MaxRotationsPerWindow`/`RotationWindow`).

**Proposed behavior**:
- Postgres `RefreshTokenStore` implements every optional interface: subject
  index/counter via `idx_refresh_tokens_subject_client`-style indexes,
  client purge (empty clientID is a no-op), family tracker via the
  `refresh_token_families` ledger, rotation limiter via a windowed count in
  `refresh_rotation_windows` (both tables already exist in the sqlite DDL
  to translate), expiry lister via `expires_at` scan. Add the same
  compile-time assertions at the bottom of `refresh_token.go`.
- All four postgres stores implement `SetLookupHMACKeys` with the same
  domain-separated HMAC lookup keys (`auth_code` / `refresh_token` /
  `device_code` / `par`) and current/previous/legacy read candidates, so a
  no-logout key rotation works identically on postgres.
- Wire the key files through a new `config.OAuthPostgresConfig`
  (`lookup_hmac_key_file`, `lookup_hmac_previous_key_file`) mirroring
  `OAuthRedisConfig`, resolved by an extended `ResolveOAuth*LookupHMACKeys`
  (or a shared resolver) in `serverbuildstore`.
- No behavioral change in `interfaces/sso`: the assertions already in place
  simply stop being no-ops for the postgres backend.

**Acceptance check**:
- Compile-time interface assertions pass; ported tests cover: revoke-all
  (`DeleteAllForSubject`) count correctness, tenant-suspension purge
  (`DeleteAllForClient`, empty clientID no-op), family reuse → `DeleteFamily`
  + `ErrRefreshTokenReused`, rotation velocity cap (windowed
  `RecordRotation`), `ListExpiring`, and lookup-key rotation
  (current→previous→legacy read, new-key writes) — all run against a
  postgres test DB with `-race -count=10`.
- E2E: `/token/revoke-all`, admin tenant suspension, and GDPR
  `/me/account/erase` behave identically with `oauth.backend: postgres` and
  `oauth.backend: sqlite` (asserted in `test/`).
- A guard test fails (not silently skips) if any future postgres store drops
  an optional interface the sqlite peer implements — e.g. by asserting the
  full assertion set in one place.

## Decision 3: Stock-binary surface closure — `oauth.backend=postgres` end to end

**Name**: the operator-visible surface (config enum, store dispatch,
schema boot gate, readiness, rotation-grace option, docs, tests) treats
postgres as a first-class `oauth.backend` value, not an SDK-only curiosity.

**Problem**: even with Decisions 1-2 landed, four wiring/doc points would
still reject or mis-serve a postgres deployment: (a) all four
`serverbuildstore.Build*Store` switches and their error messages enumerate
only `memory, sqlite, redis`; (b) `wireOAuthGrantStores` runs
`serverbuildsign.CheckSQLiteSchema` unconditionally on the OAuth stores —
`CheckSQLiteSchema` acts on any store exposing `DB() *sql.DB`
(`build_readiness.go:44-54`) and runs the sqlite version-table query, so on a
postgres store it would produce a false schema error at boot; (c)
`oauth.refresh_token.rotation_grace_backend` rejects postgres
(`build_app_oauth.go:257-300` default branch), so a postgres-only deployment
still cannot get a cluster-shared rotation-grace window without adding
Redis/SQLite; (d) `docs/config-reference.md` lines 100-104 still document
the old enum, the `oauth.{sqlite,redis}.{lookup_hmac_*}` scope, and
"cleanup ... for memory and SQLite stores" — the feature-matrix "postgres
仅持久层" narrative persists.

**Evidence**:
- `cmd/sso-server/serverbuildstore/build_oauth_stores.go:34-68`
  (`BuildAuthCodeStore` switch + `default: ... supported: memory, sqlite,
  redis`) and the identical shapes at lines 71-115, 117-153, 154-195.
- `cmd/sso-server/build_app_oauth.go:201-238` (`wireOAuthGrantStores`):
  unconditional `serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store,
  "auth_codes", sqlitestores.AuthCodesMaxVersion())` plus hardcoded
  ready-check names `sqlite-oauth-auth-codes` / `sqlite-oauth-refresh-tokens`
  / `sqlite-oauth-device-codes` / `sqlite-oauth-par`.
- `cmd/sso-server/build_app_oauth.go:257-300` (`wireRefreshRotationGrace`):
  `case "sqlite": ... case "redis": ... default: ... unknown
  oauth.refresh_token.rotation_grace_backend %q (supported: memory, sqlite,
  redis)`.
- Branching precedent: `cmd/sso-server/build_stores.go:403-410`
  `checkIdentityLinkSchema` — `case "sqlite": CheckSQLiteSchema(...)` /
  `case "postgres": postgresbackend.CheckSchema(b.schemaCtx, b.pgDB,
  "identity_links", ...)`; `infrastructure/postgres/migrate.go:224`
  `CheckSchema`.
- `docs/config-reference.md` lines 100-105 (enum + lookup scope + expiry
  cleanup + rotation grace rows); `config/config_oauth2.go:5-17`
  (`OAuthConfig` has `Backend`/`SQLite`/`Redis` sections — a postgres branch
  reuses the shared `postgres:` block, no new DSN, mirroring
  `identity.session_backend=postgres`).
- `cmd/sso-server/oauth_stores_test.go` (`TestBuildApp_AllOAuthStoresEnabled_
  BuildsCleanly`, `...SQLiteNeedsDSN`, `...UnknownBackendErrors`) — the test
  matrix to extend; `cmd/sso-server/build_stores.go:150-165`
  (`haCoherenceIssues` already lists `oauth.backend`; `perPodBackend` flags
  only `""`/`memory`, so a postgres value is automatically HA-valid — this
  must be locked by a test, not left implicit).

**Proposed behavior**:
- Add `case "postgres":` to all four `Build*Store` dispatchers (requiring
  `pgDB != nil` with the same `errPostgresNotConfigured`-style error the
  identity builder uses, `build_identity_stores.go:255`) and update the
  `default` error enums; thread `pgDB`/`pgDialect` through the four builder
  signatures.
- Branch the schema gate in `wireOAuthGrantStores` on the resolved backend
  (`CheckSQLiteSchema` for sqlite, `postgresbackend.CheckSchema` for
  postgres) and switch the ready-check/health-source names to be
  backend-accurate, following `checkIdentityLinkSchema` +
  `appendIdentityLinkHealth` (`build_stores.go:403-419`); the shared
  `postgres` pool `/readyz` check already exists (`wirePostgres`,
  `build_bootstrap.go:291-320`).
- Add `case "postgres"` to `wireRefreshRotationGrace` using a new
  `infrastructure/postgres` refresh-grace store (same grace-window contract
  as `sqlitestores.NewRefreshGraceStoreWithDSN`, `build_app_oauth.go:285`),
  and extend the `docs/config-reference.md` rotation-grace row.
- Update contract docs in the same change: `oauth.backend` enum (line 100),
  lookup-key scope line 101 (`oauth.{sqlite,redis,postgres}.{lookup_hmac_*}`),
  expiry-cleanup row, `config/config_oauth2.go` doc comments, and the
  feature-matrix OAuth store rows; extend `oauth_stores_test.go` with
  postgres build cases (postgres needs no DSN beyond the shared block,
  sqlite-DSN error stays, unknown-backend error stays).
- Extend `haCoherenceIssues` coverage with a test asserting
  `oauth.backend=postgres` is accepted in `TopologyModeMulti` without
  `AllowPerPodState`.

**Acceptance check**:
- A YAML config with `oauth.backend: postgres` (and no `redis:` block) boots,
  passes `/readyz` (postgres pool check), and runs the four flows; a
  `postgres:` block is required — missing block fails boot with the
  `errPostgresNotConfigured`-style message (loud, matching the sqlite-DSN
  precedent).
- `oauth.refresh_token.rotation_grace_backend: postgres` is accepted and
  shares grace state across replicas; the `default` error now lists postgres.
- `docs/config-reference.md` no longer contains the asymmetric rows
  (verified by the doc-check gate, `python cli.py` config check); the
  feature-matrix OAuth rows list `memory · sqlite · redis · postgres`.
- `go test ./cmd/sso-server/ -run 'TestBuildApp_AllOAuthStoresEnabled' -v`
  passes with a postgres backend; new negative tests assert the loud-fail
  paths (no postgres block; unknown backend message includes postgres in the
  supported list); `make ci` green.
