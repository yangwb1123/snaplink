# Database-Architect Review: Token-Policy Governance Lifecycle (writable admin API + sqlite store + cross-replica invalidation)

Review basis: `ai-dev/prompts/README.md`, `ai-dev/prompts/database_architect.md`,
`docs/auto/domains-tokenpolicy-design.md` (the reviewed artifact), current
executable code, `docs/config-reference.md`, `docs/error-codes.md`, and the
sibling design/review corpus (`domains-tokenexchange-database-review.md`,
`domains-threataction-*`).

The feature is **Proposed** (design only — no implementation landed; Verified:
`domains/tokenpolicy/` contains no `sqlite` package, and
`domains/tokenpolicy/tokenpolicy.go`'s `Store` still exposes `Policies()` only).
**Checks that ran:** source reads and targeted greps of every cited path, the
store-wiring import census below, and a namespace-collision scan of every
`migrate.Run` call site. No build of the feature exists to run; no files were
modified (advisory review).

Every claim about current code is **Verified** (code read) unless labeled;
design claims are **Proposed** (from the design doc) or **Missing** (absent
from the design).

---

## 1. Store inventory: purpose, durability, implementation, stock wiring, consistency

| # | Store / table | Purpose | Durability | Implementation | Stock binary wiring | Consistency requirement |
|---|---|---|---|---|---|---|
| S1 | token-policy engine (`memory.Store`) | active governance rule set for `Evaluate` (TTL clamp, scope-combo/refresh-depth/session denies) | **Hot / volatile** (per-process, config-seeded) | `domains/tokenpolicy/memory/store.go` — slice COW under `RWMutex`; `Replace` has zero non-test callers (grep-verified) | **Verified wired.** `serverbuildplatform.BuildTokenPolicyStore` (`cmd/sso-server/serverbuildplatform/build_governance.go:197`), `wireTokenPolicy` (`cmd/sso-server/build_app_security.go:280-290`) → `sso.WithTokenPolicy` | Snapshot read on the issuance hot path (`ClampingIssuer.Issue`, `server_helpers.go:67`; `enforceTokenPolicy`, `:89`; `sso_protocol.go:481`); fail-open on store error |
| S2 | **Proposed** `token_policies` (sqlite) | durable single source of truth for admin-authored rules; multi-replica shared file | **Durable** (file DSN; journal/synchronous settings inherited from DSN pragmas per the cookbook, `infrastructure/defaultimpl/sqlite/users.go:71-73`) | design 决策 9/10: single table `(name TEXT PK, policy_json TEXT)`, migrate v1 baseline, in-memory snapshot + `Refresh` | **None yet** — `BuildTokenPolicyStore` sqlite branch is the first stock wiring of any durable token-policy backend | Whole-list snapshot; `Policies()` never touches disk; per-row upsert/delete atomic; seed only when table empty |
| S3 | **Proposed** `schema_migrations_token_policies` | per-namespace schema version | Durable | `platform/migrate` (Verified: per-namespace version table, single `BEGIN IMMEDIATE` tx, forward-only, `CheckSchema` boot gate) | via S2's constructor + `TokenPolicyMaxVersion()` + `CheckSQLiteSchema` (design 决策 9) | v1 baseline; `ErrSchemaTooNew` when live DB is ahead of the binary |
| S4 | cluster invalidation bus | cross-replica convergence of the token-policy snapshot | per-backend (etcd/memory) | `platform/cluster/bus.go`; kinds are an open set; `KindControlPlaneRestore` reseeds via `flushInvalidationCaches` (`interfaces/sso/server_invalidation.go:48,365`) | Opt-in `WithInvalidationBus` | Best-effort, no ordering guarantee; fail-open receive arms (`server_invalidation.go:336-370`) |
| S5 | sibling: `threat_policies` (sqlite) | durable threat-policy rule set | Durable | `domains/threataction/sqlite/policy_store.go`, migrate v1 | **NOT wired.** `BuildThreatAction` uses `threatactionmemory.NewThreatPolicyStore()` (`build_governance.go:323`); zero production imports of `domains/threataction/sqlite` (grep census) | name-sorted `List` on both memory (`domains/threataction/memory/policy_store.go:37` sorts by name) and sqlite |
| S6 | sibling: `tokenexchange_chain_hops` (sqlite) | RFC 8693 hop observability | Durable | `domains/tokenexchange/sqlite/chain_store.go` | **NOT wired** (zero production importers; SDK accessor only) | per-row upsert atomic; fail-open recording |
| S7 | governance precedent: `config_history` (sqlite) | config-audit history | Durable | `platform/configaudit/sqlite/store.go` | **Verified wired.** `BuildConfigAuditStore` (`build_governance.go:155`), `config_audit.backend=sqlite` | one row per admin mutation; optional retention |
| S8 | hot-path durable family: `auth_codes`, `refresh_tokens(+families, rotation windows)`, `jti_replays`, `sessions`, `clients`, `par_requests`, `device_codes`, ... | OAuth/OIDC credential state | Durable | `infrastructure/defaultimpl/sqlite/*` (18 files import it in `cmd/sso-server`), `SharedDB` pool (`shareddb.go:29`), process-wide `busy_timeout` hook (`busy_timeout.go` `init`) | **Verified wired** | atomic consume (`DELETE ... RETURNING`), atomic rotation (BEGIN IMMEDIATE RMW), replay idempotency (`ON CONFLICT IGNORE`) |
| S9 | durable domain family: `connections`, `identity_links`, `permissions`, `tenants`, `audit` sink, `metering` (tenant-usage aggregator only), rate-limit sqlite | domain state / audit / telemetry | Durable | per-domain `*/sqlite` packages | **Verified wired** (connections/identitylink/tenant/permissions/audit/metering/ratelimit import census in §3) | per-domain invariants; audit is append-only with retention |

**Hot vs durable and does the stock binary wire it — bottom line for this design:**

- The token-policy **hot path is memory-snapshot by design** (Proposed, sound): `Policies()` serves a mutexed snapshot; the sqlite file is touched at boot (load/seed), on admin writes, on `Refresh`, and by health probes. The snapshot is the availability unit: a wedged DB degrades the admin surface, never issuance (fail-open, matches S1's existing contract).
- The **durable backend does not exist yet and its wiring is the first durable wiring for this domain** — unlike configaudit (S7), the design cannot lean on an existing stock-wired sibling; the builder branch, the boot schema check, the storage-health source, and the shutdown `Close()` must land together or the sqlite backend is unreachable in `sso-server`.
- **The sibling sqlite stores the design cites as precedent (S5, S6) are NOT stock-wired.** Verified by import census: `domains/threataction/sqlite` and `domains/tokenexchange/sqlite` have zero non-test importers anywhere; `cmd/sso-server` uses only the memory threat store. The design's storage model therefore inherits no production-proven wiring path — only package-level precedents.

---

## 2. Findings (sorted by severity)

### F-DB-1 (High — silent permanent divergence in a supported topology): admin writes never converge on peer replicas when the memory backend is wired, and the HA-coherence gate does not cover the token-policy store

- **Evidence (Verified):** `cmd/sso-server/build_stores.go:95-131` `haCoherenceIssues()` checks `oauth.backend`, `identity.session_backend`, `jti_replay.backend`, `ciba.backend`, `identity.backend`, `mfa.challenge.backend`, `identity_link.backend`, `pairwise_subjects.backend` — **no token-policy entry**. `perPodBackend()` (`:132`) treats `""`/`memory` as per-pod. The design (决策 7/8) mounts PUT/DELETE routes and publishes `KindTokenPolicyChange` for **both** backends, but the receive arm type-asserts `interface{ Refresh(context.Context) error }` (`interfaces/sso/server_invalidation.go:336-370` pattern) — the memory store implements no `Refresh` (design 决策 6 keeps only `Replace`), so on a memory-backed fleet: PUT on replica A succeeds and updates only A; B's arm silently no-ops; divergence is **permanent until restart**, with no boot warning (the design's own risk #5 accepts only the *bounded* stale window of the sqlite model, not this unbounded one). The connection-change precedent (`KindConnectionChange`) is weaker than this: that arm has no per-replica cache to invalidate, while the token-policy arm has a real snapshot cache.
- **Impact:** an operator running `topology.mode: multi` with `token_policies` from File/Policies (the only way to get policies today) gets a write API that half-works; rules added on one replica are enforced only there. Governance divergence of this kind is silent because the admin read on B also serves B's stale snapshot.
- **Recommendation (required):** add the token-policy store to `haCoherenceIssues` (e.g. `{multi, "token_policies.backend", ...}` — memory ⇒ flagged per-pod), or refuse to mount the write routes for a memory-backed store, or make the receive arm log loudly when the wired store cannot refresh. The two-server integration test must cover the memory-backend case explicitly (assert non-convergence is at least surfaced, or routes are unmounted), not only the sqlite case.
- **Validation step:** boot two servers in `topology.mode: multi` with File-seeded memory stores, PUT a policy on A, assert B's `GET /api/v1/admin/token-policies` and B's enforcement reflect either convergence or a loud, documented failure — per the chosen option.

### F-DB-2 (Medium — non-atomic seed): the first-boot seed is a check-then-seed sequence, not one transaction

- **Evidence:** design 决策 11 seeds "if the table is empty" via the store's `Put` (per-rule upsert) after a count check. `migrate.Run` proves the repo knows how to do atomic boot-time writes (`BEGIN IMMEDIATE`, pinned conn — `platform/migrate/migrate.go`); the design does not place the seed inside the migration transaction or a single `BEGIN IMMEDIATE`.
- **Impact:** two replicas booting together against one empty file can both observe empty and both seed (content-idempotent only when configs are identical — true in a fleet, but the second seed re-writes rows and re-refreshes snapshots). More material: a concurrent admin PUT in the tiny boot window can be overwritten by the config seed's upsert (config wins over an admin write, violating the design's own "config/seed never silently overrides admin-authored state" rule, which is otherwise enforced only after first boot). Window is boot-only and small, hence Medium.
- **Recommendation:** run the seed inside the store constructor under one `BEGIN IMMEDIATE` (pinned conn, per `beginImmediateRMW` pattern): `SELECT COUNT(*)` and the inserts share the write lock, so no interleaving with admin PUTs and no double-seed. If the seed lives outside the store, have `BuildTokenPolicyStore` perform it before the server starts accepting traffic.
- **Validation step:** a test that opens two stores concurrently on one fresh file with a goroutine issuing an admin PUT mid-seed; assert the seeded set is exactly config ∪ PUT or that the PUT is ordered after the seed (never lost).

### F-DB-3 (Medium — unspecified read surface): the design does not state whether sqlite `Get`/`Policies` serve the snapshot or the DB, so the admin view and the enforcement view can diverge on peers

- **Evidence:** 决策 9 defines `Get`/`Put`/`Delete` and 决策 10 defines the snapshot, but the `Get` read path is **Missing** from the design. Two readings: (a) `Get` hits the DB → an admin GET on replica B shows a just-created policy that B's evaluator still denies on (or vice versa: shows a deleted policy B still enforces); (b) `Get` serves the snapshot → admin view == enforcement view on every replica, with the documented bounded staleness. Threat-policy sqlite precedent (`policy_store.go` `Get` queries the DB) has no snapshot, so it does not settle this.
- **Impact:** a governance operator using the admin API as ground truth can act on a view that does not match what the replica enforces; with (a) the divergence is silent and per-request.
- **Recommendation:** serve `Get` (and the admin list) from the same snapshot that `Policies()` serves, and document that the admin surface reflects the replica's *enforcement* view, not the DB's committed state. This keeps one consistency story (snapshot) for both surfaces.
- **Validation step:** two-server test: PUT on A; before the bus event lands, assert B's admin GET and B's enforcement agree with each other (both stale), and both flip after the event.

### F-DB-4 (Medium — no DR/restore path for admin-authored policies): the policy table is outside every backup/restore artifact, and the seed contract cannot restore into a non-empty table

- **Evidence (Verified):** the snapshotter/restorer resource set is fixed at `Clients, Users, Permissions, NetPolicy, Tenants, Connections, Pairwise` (`cmd/sso-server/build_stores.go:142-156`) — no threat or token policies. `WithBackupSource` (`interfaces/sso/options_httpstack.go:196`) has **zero** call sites in `cmd/` (grep-verified), so `POST /api/v1/admin/backup` is unmounted in the stock binary (`server_resource.go:381` gates on `len(s.backupSources) > 0`). The design's seed is empty-table-only (决策 11), so after first boot the only ways to rebuild a lost policy set are manual PUTs or a DB-file restore.
- **Impact:** admin-authored governance state (the entire point of 方向一) has no export/restore story: an operator who loses the DB file loses the rules with no recovery path, and config edits cannot re-seed (by design, loudly). For a governance surface this is a recoverability gap, not a data-loss path for credentials.
- **Recommendation:** (1) extend the snapshotter/restorer resource set with the token-policy store (it implements `Policies()`; restore = `Replace`/`Put` + `InvalidateTokenPolicies`), or (2) add a documented `sso-ctl` export/import for the table, or (3) explicitly document "DB-file backup is the sole recovery unit" in `docs/config-reference.md` next to the `sqlite` knob. Option (1) is consistent with the design's own `KindControlPlaneRestore` reseed story.
- **Validation step:** snapshot → wipe the table → restore → assert `Policies()` equals the artifact's set on every replica.

### F-DB-5 (Low — config-shape drift): `TokenPolicyConfig.Sqlite string yaml:"sqlite"` deviates from the repo's `.sqlite.dsn` sub-struct convention

- **Evidence (Verified):** every existing sqlite DSN knob is a sub-struct: `config_audit.sqlite.dsn` (`config/config_audit.go:326-339`), `notifications.sqlite.dsn` (`docs/config-reference.md:260`), `identity_link.sqlite.dsn` (`:173`), audit's `audit.sqlite.dsn`. The design proposes a bare `sqlite: <dsn>` string.
- **Impact:** operator confusion (two adjacent config files with different shapes), and `EffectiveConfigSnapshot`/redaction round-trips treat them differently.
- **Recommendation:** use `Sqlite SqliteDSNConfig { DSN string yaml:"dsn" }` — the `SqliteDSNConfig` type already exists for exactly this.
- **Validation step:** `config` load/round-trip test for the new section.

### F-DB-6 (Low — connection-handling parity): `New(dsn)` mirrors the threat store's plain `sql.Open` with no `SetMaxOpenConns(1)` and no pragmas of its own

- **Evidence (Verified):** `domains/threataction/sqlite/policy_store.go` `New` and the design's mirror open a raw `*sql.DB`; the defaultimpl stores all call `db.SetMaxOpenConns(1)` with the comment "WAL: one writer at a time prevents lock convoy" (`auth_codes.go:214`, `clients.go:125`, ...), and `SharedDB` (`shareddb.go:29`) additionally sets `journal_mode=WAL`, `synchronous=NORMAL`, `busy_timeout=5000`. The domain stores rely on (a) the process-wide busy_timeout hook registered by `infrastructure/defaultimpl/sqlite`'s `init` (`busy_timeout.go` — present in the stock binary, absent for SDK embedders who do not import that package) and (b) the DSN cookbook (`users.go:71-73`: `file:/var/lib/sso/sso.db?_journal=WAL&_pragma=busy_timeout(5000)`).
- **Impact:** with default pool settings a concurrent admin write and a `Refresh` read can hit different connections; in rollback-journal mode (fresh file, no WAL DSN) that is `SQLITE_BUSY` (mitigated by the 5s hook when present). Low probability on this store's write rate, but it is the one new write path on possibly-shared files.
- **Recommendation:** follow the defaultimpl pattern: `SetMaxOpenConns(1)` in `New(dsn)`; state the DSN requirement (`_journal=WAL&_pragma=busy_timeout(5000)`) in the config-reference entry; and use `SharedDB`/`NewWithDB` when the DSN matches the deployment's shared file.
- **Validation step:** concurrency test (`-race -count=10+`) with two stores on one file in rollback-journal mode asserting no `SQLITE_BUSY` under concurrent PUT+Refresh.

### F-DB-7 (Info — convention claim imprecision): "dot notation per the existing convention" is only half true

- **Evidence (Verified):** `platform/cluster/bus.go` kinds are mixed: `tenant_suspension`, `signing_key_rotation`, `token_revoked`, `session_suspended`, `config_digest`, `discovery_reload` (snake) vs `tenant.residency`, `client.change`, `connection.change`, `control_plane.restore` (dot). `token_policy.change` follows the newer subset. The `bus_test.go` kind-set test must be updated in the same change (design already lists it).
- **Impact:** none functional; the doc sentence should say "the newer dotted subset" to avoid a future contributor standardizing on snake.

### F-DB-8 (Info — ordering divergence is deliberate and safe, but departs from the sibling precedent)

- **Evidence (Verified):** `domains/threataction/memory/policy_store.go:37` sorts `List` by name — threataction memory and sqlite agree. The design's 决策 6 keeps insertion order in tokenpolicy memory vs `ORDER BY name` in sqlite. The rationale (deny-reason label stability for config-seeded deployments) is sound and the outcome/wire are order-independent, but this is a *new* cross-backend divergence where the sibling precedent chose parity.
- **Recommendation:** keep the design as written, but add a regression test asserting the *deny outcome* (not reason) is identical across both stores for the same overlapping-rule set, so the divergence can never grow into a behavioral one.
- **Validation step:** property test: random policy sets, `Evaluate` outcome equality between memory-order and name-order evaluations.

### Verified-correct design decisions (no action)

- **Fail-open snapshot model** (`Policies()` never touches disk; DB outage degrades admin surface only) matches the S1 contract and the sibling stores — **Verified sound**.
- **Migration namespace `token_policies` is collision-free**: full census of every `migrate.Run` namespace (`auth_codes`, `ciba_requests`, `clients`, `connections`, `consent`, `device_codes`, `identity_links`, `providers`, `rate_limit`, `rebac_tuples`, `refresh_tokens`, `revocations`, `sessions`, `threat_policies`, `tokenexchange_chain_hops`, `webauthn_sessions`, `webauthn_users`) shows no overlap; `schema_migrations_token_policies` is unique.
- **TTL-plumbing single source (design risk #1) is structurally real**: `config_load.go:82-83` defaults `Server.TokenTTL` to `sso.DefaultTokenTTL` (= `core.DefaultTokenTTL`, `shared/core/consts_oauth.go:134`), and `build_signing_issuers.go:44,68` feed the same `srv.TokenTTL` into the issuers. The design's `WithTokenPolicyDefaultTTL` wired from the same field keeps one source; the invariant test is mandatory.
- **Single-statement upsert/delete** (`ON CONFLICT(name) DO UPDATE`, `DELETE ... WHERE name=?` + `RowsAffected`) needs no multi-row transaction — atomic per statement.

---

## 3. Query/index and transaction analysis for demonstrated hot or atomic paths

### Demonstrated atomic paths in the repo (Verified, all stock-wired)

| Path | Pattern | Evidence | Why it is correct |
|---|---|---|---|
| Auth-code consume | `DELETE ... RETURNING` single statement | `infrastructure/defaultimpl/sqlite/auth_codes.go` `Consume`/`consume` | Read+delete atomic; concurrent consumes cannot both return the code; expired rows indistinguishable from missing (oracle-safe) |
| Refresh-token rotation window | `BEGIN IMMEDIATE` on pinned conn, then SELECT+upsert, explicit COMMIT | `refresh_tokens_rotation.go` `RecordRotation`/`bumpRotationWindow` | Plain `db.BeginTx` isolation hints are ignored by modernc; pinned-conn immediate write lock closes the lost-update race |
| Refresh reuse detection | `DELETE ... RETURNING` + `refresh_token_families` lookup; reuse → family wipe | `refresh_tokens.go:137-173, 324+` | Consumed-token replay detection is retained through the validity window, then reaped |
| JTI replay | `INSERT ... ON CONFLICT IGNORE` on PK `jti` | `jti_replay.go:16-25, 99-130` | PK-conflict is the atomicity primitive; no SELECT-then-INSERT race |
| Schema migration | `BEGIN IMMEDIATE` pinned conn, per-namespace version table, forward-only | `platform/migrate/migrate.go` `run`/`beginImmediate` | Concurrent replicas serialize on the write lock; mid-batch failure rolls back; `CheckSchema` fails an old binary against a forward-migrated DB at boot |
| SQLite connection discipline | `SetMaxOpenConns(1)` per store; `SharedDB` adds WAL + `synchronous=NORMAL` + `busy_timeout=5000` | `auth_codes.go:214`, `shareddb.go:29` | Single writer avoids lock convoy; WAL keeps reads concurrent |

### The proposed `token_policies` store against the same lens

- **Schema/keys:** `name TEXT PRIMARY KEY` covers `Get`/`Delete` (point lookups) and `Put` (upsert conflict target). `Policies()`/`Refresh` are full scans with `ORDER BY name` — the only feasible plan for a single-table whole-list read; there is no WHERE to index, so **no additional index is justified** (same conclusion as `threataction/sqlite`'s documented rationale).
- **Transactions:** `Put` and `Delete` are single statements — atomic, no transaction needed. The **seed is the only multi-write sequence and needs one `BEGIN IMMEDIATE`** (F-DB-2). `Refresh` is a read-only full scan; no transaction needed.
- **Isolation:** snapshot mutex gives readers COW isolation from concurrent `Put`/`Delete`/`Refresh`; DB-level isolation is irrelevant to `Policies()` because it never reads the DB.
- **Concurrency:** two replicas on one file: WAL allows concurrent readers + one writer; admin write rate is human-scale. The `ORDER BY name` snapshot keeps cross-replica determinism (divergence from memory insertion order is audit-label-only, F-DB-8).
- **Retention/eviction:** no TTL column, no reaper — correct: governance rules must not self-expire. Configaudit's retention precedent (S7) does not apply to a policy table.
- **Backfill:** none needed at v1 (fresh table); any future column must follow the Func-migration check-then-add pattern (`auth_codes.go` v2-v4) because SQLite lacks `ADD COLUMN IF NOT EXISTS`.

---

## 4. Safe migration sequence

The proposed change ships **one baseline migration only** (`{Version: 1, Name: "baseline"}`), which makes the sequence short but the wiring surface wide.

### Sequence

1. **Land the domain change first, sqlite package inert** — `Store` + `Get`/`Put`/`Delete` + `ErrPolicyNotFound`, memory-store rework, `ParseYAML` strictness, `Validate`/`AdvisoryWarnings`, `NewClampingIssuer` signature, admin handlers, bus kind, docs. No config knob yet: `TokenPolicyConfig` unchanged, `BuildTokenPolicyStore` still memory-only → zero production behavior change; the interface break is contained to in-repo implementers (Verified: only `memory` + test fakes; the server holds the store as `tokenpolicy.Store`, `sso_protocol.go:50`).
2. **Add the `sqlite` knob and store, behind config** — `TokenPolicyConfig.Sqlite` (shape per F-DB-5), `domains/tokenpolicy/sqlite` (migrate v1, `MaxVersion`), builder branch. Deployments that never set the knob are byte-identical; those that do get the new table **created at first boot** (`CREATE TABLE IF NOT EXISTS` + `schema_migrations_token_policies` stamped v1 inside the migrate transaction).
3. **Boot schema gate** — `CheckSQLiteSchema(..., "token_policies", TokenPolicyMaxVersion())` alongside the existing per-store checks (`build_app_security.go:63` pattern); storage-health source; shutdown `Close()`.

### Compatibility window

| Deployment | Old binary + new DB | New binary + old DB | Mixed fleet |
|---|---|---|---|
| Behavior | Old binary has no token-policy sqlite code: it never reads/writes `token_policies` or `schema_migrations_token_policies` — tables are inert, **safe** | `CREATE TABLE IF NOT EXISTS` + migrate stamps v1; seed-if-empty — **safe** | New binary's `CheckSQLiteSchema` fails boot only when the live DB is **ahead** of the binary's max (future v2); at v1 everywhere, mixed-version is safe; unknown bus kinds from newer peers hit the `default` arm (`server_invalidation.go:322-333`) |

### Validation queries (first boot and after any restore)

```sql
-- schema state
SELECT version, name, applied_at FROM schema_migrations_token_policies;
-- seed correctness: counts match the config bundle, names are exactly the config set
SELECT COUNT(*), group_concat(name, ',') FROM token_policies;
-- row integrity: every blob must be valid JSON and round-trip through Policy
SELECT name FROM token_policies WHERE json_valid(policy_json) = 0;   -- must be empty
-- whole-file integrity
PRAGMA integrity_check;                                               -- must be 'ok'
-- cross-surface check: sqlite Policies() must equal the DB rows in ORDER BY name
```

### Rollback / roll-forward

- **Rollback (schema):** forward-only by policy (`migrate.go` doc: rollback is restore-from-snapshot). At v1 the practical rollback is simpler: deploy the old binary — it ignores both tables (see compatibility window), and the data remains for a later re-deploy of the new binary.
- **Rollback (data):** restore the DB file from backup; then the seed contract applies only if the table is empty, so a restore that brings back a populated table keeps the restored rows (correct — no config override).
- **Roll-forward:** v2+ must be `Func` migrations (column-add with existence check, per `auth_codes.go` v2-v4 precedent) or SQL DDL; `MaxVersion` must be bumped in the same change; the boot gate then protects canary rollbacks (`ErrSchemaTooNew`).

### Data-integrity checks to ship in the change

- Seed idempotency test: double `New` on the same file → identical rows, version stays v1.
- Reopen-persistence test: PUT → close → reopen → `Policies()` equals DB order.
- Cross-backend outcome-equality test (F-DB-8).
- Round-trip: `Put` → `Get` → `Policies()` equality; `Delete` unknown → `ErrPolicyNotFound` and no row change.

---

## 5. Unknown volume, retention, and recovery assumptions

- **Volume (Unknown — no in-repo workload evidence):** governance rule counts are assumed small (tens to low hundreds); each `Refresh` is a full scan + JSON decode of every row, and each admin PUT triggers one on the writer plus one per converged peer. No measurement exists anywhere in the repo (there is no durable token-policy deployment to measure). **Measurements required before this can be called scale-safe:** rule-set size at which `Refresh` latency breaches the bus subscriber budget (a slow `Refresh` stalls `applyInvalidation`'s synchronous arm — `applyInvalidation` is synchronous per `server_invalidation.go` docs), and PUT/Delete rate ceilings under one WAL file with concurrent issuance traffic. If rule counts ever reach ~10k or admin writes exceed ~tens/sec, the whole-list snapshot model needs delta events or a versioned table read.
- **Retention (assumed):** `token_policies` rows live forever by design (governance config must not expire); growth is bounded by rule-set size, not request volume. The audit stream remains the retention-controlled history (bounded-cardinality event types per `auditreport`).
- **Recovery (assumed, with a known gap):** the DB file is the recovery unit (F-DB-4); the design assumes a crashed publish (PUT committed, event lost) heals on the peer's next token-policy event (keyless whole-list refresh means *any* later event converges all peers) or on restart (`New` reloads). That assumption is sound **only if** the peer eventually gets another event or restarts; a peer that never restarts and never sees another write can stay stale indefinitely — the design accepts this (fail-open governance), and F-DB-1 is the memory-backend case where even that healing path does not exist.
- **Backup (Unknown in stock binary):** zero `WithBackupSource` registrations in `cmd/sso-server` (Verified) — the stock binary's only backup surface is the snapshot/DR artifact, which excludes policies (F-DB-4). File-level backup (e.g. `VACUUM INTO`, volume snapshots, `sso-ctl` export) is entirely operator-side today.
- **Multi-replica write concurrency (assumed):** single-writer WAL semantics bound concurrent writers; admin-write rates are human-scale, so no lock-convoy risk is expected — but no test in the repo exercises two *processes* (not goroutines) writing one file, and `modernc.org/sqlite` multi-process behavior under the shared-pool `MaxOpenConns(1)` is exercised only through the existing `test/` suite. The two-server/one-DB integration test in the design's acceptance list is the right place to close this.
- **Clocks:** none of the proposed schema is time-dependent (no TTL, no expiry index) — no clock-skew coupling, unlike the credential stores. This is a small but real operational simplification worth keeping.

---

### Review scope note

This review covers persistence correctness and production readiness only. The
oracle-safety, wire-contract, and audit aspects are covered by the sibling
security/protocol reviews; the `defaultTTL` plumbing invariant (design risk #1)
is verified structurally here (§2 verified-correct list) and flagged as
requiring its dedicated rootcov test, but its behavioral verification belongs
to the implementer's acceptance run.
