# Database-Architect Review: Token-Exchange Hop-Policy Operational Loop (admin API + sqlite store + matching dimensions)

Review basis: `ai-dev/prompts/README.md`, `docs/auto/domains-tokenexchange-design.md`,
current executable code, `docs/config-reference.md`, and the sibling reviews
(`docs/auto/domains-tokenexchange-review.md`, `-qa-review.md`, and the
security-engineer review). The feature is **Proposed** (design only — no
implementation landed). **Checks that ran:** source reads and greps of every
cited path, `wc -l` measurements, and `go test -run 'TestMaintainability_|TestArchitecture_' .`
which **PASSED at HEAD `9606997b`** (no build of the feature exists to run).
This is advisory analysis; no files were modified.

Every claim about current code is **Verified** (code read or gate run) unless
labeled; design claims are **Proposed** (from the design doc) or **Missing**
(absent from the design).

---

## 1. Store inventory: purpose, durability, implementation, stock wiring, consistency

| # | Store / table | Purpose | Durability | Implementation | Stock binary wiring | Consistency requirement |
|---|---|---|---|---|---|---|
| S1 | `tokenexchange_chain_hops` (sqlite) | RFC 8693 hop observability | **Durable** (file DSN) | `domains/tokenexchange/sqlite/chain_store.go`, migrate v1 | **None.** Zero imports of `domains/tokenexchange/sqlite` outside the package and its tests (grep-verified); `WithTokenExchangeChainStore` call sites are `test/` only and use the **memory** store | Per-row upsert atomic; fail-open recording |
| S2 | `tokenexchange` hop policy (memory) | optional hop-authorization gate | **Volatile** | `domains/tokenexchange/memory/store.go` (RWMutex + copy-on-write, `Replace`/`Rules` zero production callers — only `store_test.go:33`) | **None.** `WithTokenExchangePolicy` (Verified `interfaces/sso/options_grants.go:191`) has **zero** callers in `cmd/` or `test/` outside the policy harness | Snapshot read on hot path; atomic swap |
| S3 | **Proposed** `tokenexchange_policy_rules` (sqlite) | durable hop-policy rule set, admin-mutable | **Durable** (file DSN; durability inherits the operator's `oauth.sqlite.dsn` journal/synchronous settings) | design Decision 4 (`policy_store.go`, snapshot + copy-on-write) | **None yet** — `BuildTokenExchangePolicyStore` + `wireTokenExchangePolicy` would be the FIRST stock wiring of any tokenexchange store; the builder + wire must land together or the sqlite backend is unreachable in `sso-server` | Atomic full-replace; disk and snapshot must never diverge; boot load loud |
| S4 | **Proposed** `schema_migrations_tokenexchange_policy_rules` | version tracking (migrate runner) | Durable | `platform/migrate` (Verified: per-namespace table, single `BEGIN IMMEDIATE` tx, forward-only) | via S3's constructor | v1 baseline; `PolicyStoreMaxVersion` + `CheckSQLiteSchema` boot gate |
| S5 | cluster invalidation bus | cross-replica propagation | etcd/memory per backend | `platform/cluster/bus.go`; `KindAuthzPolicyChange` exists (Verified `bus.go:42-48`) and is published for client role-definition changes (`server_discovery.go:123-138`) | Opt-in (`WithInvalidationBus`) | Best-effort, no ordering guarantee (bus contract) |

**Bottom line on "hot vs durable and does the stock binary wire it":**

- **Hot path is memory-only by design** (Proposed, sound): `Allow` reads the
  in-memory snapshot under `RLock`; zero SQL on the exchange path. The sqlite
  file is touched only at boot (load), on `Replace` (write), and by
  `Ping`/schema health. This makes the snapshot the availability unit — a
  wedged DB file degrades the admin PUT surface, never `/token`.
- **Durable backend is not stock-wired today for ANY tokenexchange store.**
  Verified: `domains/tokenexchange/sqlite` has no production importers and
  `WithTokenExchangePolicy` has no production callers. The design's own
  persistence precedent (the sqlite chain store) is package-level truth, not
  stock-binary truth — so Decision 5's builder + wire function is not an
  incremental wiring change; it is the first. This raises the bar on the
  builder test matrix (absent/inline/strict-file/conflict/sqlite-without-DSN/
  redis-inherited — mirror `TestBuildTokenPolicyStore_*`) since `test/` never
  boots `appBuilder` (Verified: zero references in `test/`).
- **Config doc drift:** `docs/config-reference.md:19` currently states the
  hop-policy SPI is "Option-wired, not YAML-driven" — the design changes that
  and its contract-update list already includes `docs/config-reference.md`
  (good; must land in the same change or docs lie at release).

---

## 2. Findings (sorted by severity)

### F-DB-1 (Critical — verified hard-gate violation, blocks the whole change incl. the sqlite store): the design's "`interfaces/admin` has no ceiling" is false; a new `interfaces/admin/tokenexchange_policies.go` fails `TestArchitecture_DirectoryFileFanout`

- **Evidence (Verified):** `directory_fanout_test.go:34` sets
  `maxGoFilesPerDir = 10`; `dirFileCountExemptions` (`:51-63`) lists
  `interfaces/sso: 60`, `cmd/sso-server: 24`, `config: 26`, etc. —
  **`interfaces/admin` is not exempt** and holds exactly **10** non-test files
  (`break_glass.go, break_glass_impersonate.go, connections.go, deps.go,
  governance.go, lifecycle.go, middleware.go, tenants.go, token_portfolio.go,
  users.go` — verified by `ls`). A new file → 11 > 10 → gate fails; the
  exemption header ("SHRINK THESE; never grow them") and AGENTS.md §2 forbid
  adding an exemption. No existing admin file has the needed headroom
  (largest: `users.go` at 464 lines, `middleware.go` at 482 — the two handlers
  + audit need ~110-150 lines). Gate run at HEAD passes only because the file
  doesn't exist yet.
- **Impact:** `make ci` fails → release blocker; the sqlite store and every
  other decision cannot land as designed.
- **Recommendation:** follow the repo's own precedent the design mis-cites:
  `domains/tokenpolicy/admin.go` hosts `HandleAdminPolicies` in the **domain
  package**. Put both handlers + `ValidateRules` in a new
  `domains/tokenexchange/admin.go` (that directory has 2 non-test files today;
  +2 → 4 ≤ 10 — legal), with the thin `accessors_threat.go` wrapper (already
  imports `interfaces/admin` for the chain handler) passing actor/IP from
  `admin.ActorFromContext` (`middleware.go:482`, Verified) + `audit.ClientIP`.
  This also matches AGENTS.md §5's "domain free function + thin Server
  wrapper" pattern. Regression gate: `make ci` itself.

### F-DB-2 (High — Proposed concurrency defect): `Replace`'s "commit, then swap under the write lock" makes commit order (SQLite file lock) and swap order (Go mutex) independent serialization points; concurrent PUTs can permanently diverge disk vs snapshot

- **Evidence (Proposed):** Decision 4: "one transaction — DELETE all, INSERT
  each ... — commit, then swap the snapshot under the write lock." Interleaving
  with two concurrent PUTs: A's tx commits (disk=A) → B's tx commits (disk=B)
  → B swaps (memory=B) → A swaps (memory=A) → **disk=B, memory=A, permanently**
  (until restart). This violates the design's own "never a partial set on
  either side" invariant — worse, it is a *divergent* set that survives
  indefinitely, and the admin API can then enforce rules that are not durable
  (a deny rule invisible to the disk is lost on failover) or fail to enforce
  rules that are (a restored deny is not enforced). A second, smaller window:
  between commit and swap on the same replica, a concurrent `GET`/`Rules()`
  shows the OLD set while the PUT response already echoed the new one.
- **Impact:** correctness of a security control under the one operation that
  exists for incident response (concurrent PUTs are plausible exactly when two
  operators react to the same incident).
- **Recommendation:** hold a single per-store write mutex across the whole
  tx+swap (one critical section → commit order == swap order; the memory store
  already serializes `Replace` the same way). Additionally, use
  `BEGIN IMMEDIATE` (repo precedent: `beginImmediateRMW`,
  `infrastructure/defaultimpl/sqlite/busy_timeout.go:39-47`; `migrate.run`
  does the same) instead of a deferred `database/sql` tx, so a concurrent
  writer produces `SQLITE_BUSY_SNAPSHOT` at BEGIN rather than a spurious
  mid-tx upgrade failure — either way the error path must roll back and
  propagate (500, fail-closed), which the design already specifies.
- **Validation:** concurrent-`Replace` regression test at the store level with
  `-race -count=10`, asserting disk and snapshot agree after every interleaving
  (read back via a fresh store instance opened on the same DSN).

### F-DB-3 (High — Proposed): boot load bypasses `ValidateRules`; shape-valid but inert rows (out-of-band writes, restored/copied DBs) silently widen allow

- **Evidence (Proposed + Verified):** Decision 4 validates JSON *syntax* at
  boot ("corrupt JSON → loud boot error") but not rule *shape*; the hot path
  deliberately does no defensive re-check ("validation at ingest ... so the
  hot path needs no defensive re-check"). A row written outside the package
  (restored DB, manual edit) with `scopes='["*x"]'` or an empty `name` loads
  cleanly and the matcher treats `"*x"` as a literal exact-match string that
  never fires — **an inert deny rule silently stops denying**. SQLite enforces
  nothing here: no CHECK constraints on the JSON columns or on `deny IN (0,1)`
  (Proposed schema has `deny INTEGER NOT NULL DEFAULT 0` with no CHECK). The
  package's own chain store defends against out-of-package writes
  (`maxChainWalk` guard, `chain_store.go:55-57`); a security-control table
  must do the same.
- **Impact:** a poisoned row is a widened-allow path, the exact class AGENTS.md
  §3 calls a security hole, and it is *silent* (no boot error, no log).
- **Recommendation:** run the shared `ValidateRules` over every loaded row at
  boot and refuse to start on violation (same loudness as corrupt JSON);
  optionally add `CHECK (deny IN (0,1))` and `CHECK (position > 0)` in v1
  while it is free. Document "direct DB writes are unsupported and detected at
  boot". Validation test: hand-write `scopes='["*x"]'` and an empty-name row
  into a temp DSN; `New()` must error.
- **Memory/sqlite parity suite** (Proposed, from the sibling reviews): the two
  backends share `Evaluate`; a parity table over the same rule sets pins that
  a rule that loads in sqlite behaves identically in memory — this is also the
  cheapest way to prove the boot-load decode (`null`→`[]`, ordering) is
  faithful.

### F-DB-4 (High — Proposed): multi-replica staleness of a *security control* has no reload path, and the same gap makes a snapshot restore on a live replica leave stale policy in force

- **Evidence (Verified + Proposed):** AGENTS.md §3: "Cross-replica
  invalidation covers ... **client/authz-policy changes** ...". The mechanism
  exists: `KindAuthzPolicyChange` (`platform/cluster/bus.go:42-48`),
  publish precedent (`server_discovery.go:123-138`), and a `default:` arm in
  `applyInvalidation` (`server_invalidation.go:333-337`) that makes a new kind
  mixed-version safe. Decision 4 explicitly defers the hook ("out of scope").
  Additionally, `KindControlPlaneRestore` (`bus.go:76-79`) exists and
  `applyControlPlaneInvalidation` flushes caches on it — a portable-snapshot
  restore that changes `tokenexchange_policy_rules` leaves every running
  replica's snapshot stale until restart, with no signal at all.
- **Impact:** the design's own primary use case — an incident-response deny
  rule — is not enforced on peer replicas (or the failover target) until a
  restart; `GET` on a peer shows the old set with no staleness marker.
- **Recommendation:** wire the bus: new `EventKind` (e.g.
  `KindTokenExchangePolicyChange`, key = namespace or empty), publish after
  `Replace` commit, subscriber arm calls `store.Reload()` (re-read disk under
  the write lock, fail-open on reload error but keep the old snapshot — never
  an empty set on reload failure). `Reload` is cheap and safe: WAL readers do
  not block writers, and the swap takes `RLock`-compatible locking. If truly
  out of scope, the acceptance must be explicit: `GET` envelope carries an
  `as_of` snapshot timestamp, and the ops runbook says "rolling restart after
  every PUT" — the design has neither today.

### F-DB-5 (Medium — Proposed): `backend: sqlite` + configured `policies`/`policies_file` is undefined → rules silently ignored → fresh-DB allow-all (fail-open misconfiguration)

- **Evidence (Proposed + Verified):** Decision 4's sqlite store loads only
  from disk; Decision 5 adds `policies`/`policies_file` but defines no
  interaction with `backend: sqlite`; Decision 6's failure table has no row
  for it. The natural operator move — sqlite backend + a deny-heavy bundle —
  boots cleanly with an empty table and serves every hop (`default_allow:
  true`), exactly the "silently-widened deny rule" class AGENTS.md §3 forbids.
- **Recommendation:** fail loud in `BuildTokenExchangePolicyStore`:
  `backend: sqlite` + non-empty inline/bundle policies → boot error ("rules
  are admin-API-managed on the sqlite backend"), mirroring the existing
  file+inline mutual-exclusion precedent (`build_governance.go`). Regression:
  boot against a fresh temp DSN must error, never silently serve.
  Config-reference update in the same change.

### F-DB-6 (Medium — Proposed): no version/etag; concurrent PUTs are silent lost-updates and a replayed old body reverts newer denies; per-replica `default_allow` divergence is undetectable

- **Evidence (Proposed):** full-replace PUT with no version column and no
  `If-Match`; a captured old body replayed with a still-valid credential
  reverts the rule set to a weaker one, audited as a normal update (no
  before/after hashes, per the design's counts-only audit meta).
- **Recommendation:** this is the one schema decision that is cheap to make in
  v1 and mildly annoying later: a `policy_meta` row (or a `version INTEGER`
  column) that `Replace` rewrites in the same tx, echoed by GET, optionally
  gated by `If-Match`/`base_version`. Because the table is full-replace, a
  later v2 migration is still trivial (`Replace` rewrites everything), so
  deferring is acceptable **provided the decision is recorded** (the sibling
  reviews' "no versioning" residual risk is otherwise re-litigated at
  implementation). At minimum, add `before_hash`/`after_hash` to the audit
  event (bounded by the rule cap + string caps).

### F-DB-7 (Medium — Proposed): the new store's runtime connections get no guaranteed `busy_timeout` when the package is used standalone

- **Evidence (Verified):** the process-wide `PRAGMA busy_timeout=5000`
  connection hook lives in `infrastructure/defaultimpl/sqlite/busy_timeout.go`
  `init()`; `domains/tokenexchange/sqlite` does not import it. `migrate.run`
  sets `busy_timeout` only on its pinned migration connection. In the stock
  binary the hook applies (cmd imports `infrastructure/defaultimpl/sqlite` for
  the OAuth stores), so this bites only standalone SDK embeddings and
  multi-connection unit tests — where a contended `Replace` then fails fast
  with `SQLITE_BUSY` → 500. Fail-closed, but noisy and surprising.
- **Recommendation:** either set `PRAGMA busy_timeout` on the store's own
  connections (mirror the hook's DSN-pragma-respecting behavior) or document
  the dependency. Also relevant to the E2E restart test (sibling review F6):
  a file temp DSN in `test/` inherits the hook automatically because `test/`
  imports the package, but a cmd-level test harness would need it too.

### F-DB-8 (Low — Proposed): `Rules()` returns the live slice header; caller mutation corrupts the active set

- **Evidence (Verified + Proposed):** `memory.Store.Rules()` returns `s.rules`
  directly (convention "read-only for the caller", `store.go:57-60`); the
  sqlite store is specified to "mirror memory.Store". The admin GET path
  serializes it, but any future in-tree caller could mutate it.
- **Recommendation:** the sqlite store returns a copy (≤1000 rules — free);
  keep the memory store as-is or document the contract on the interface.

### F-DB-9 (Low — Proposed): `NewWithDB` shared-pool constructor missing; `:memory:` DSN trap unguarded

- **Evidence (Verified):** every other sqlite store offers `NewWithDB` for
  shared-pool deployments (`connections/sqlite/store.go:80-81`,
  `permissions/sqlite/sqlite.go:93`, `identitylink/sqlite/store.go:51-60`,
  `metering/sqlite/aggregator.go:41-43`); the chain store has it
  (`chain_store.go:53-58`). The design's `New(dsn, defaultAllow)` skips it.
  Separately, `oauth.sqlite.dsn` is operator-supplied; a bare `:memory:` DSN
  (no `cache=shared`) gives each pool connection a *separate* database — the
  "durable" policy store silently becomes volatile and per-connection
  inconsistent. Pre-existing class for every sqlite store, but this feature
  makes it a security-control integrity question.
- **Recommendation:** mirror `NewWithDB`; in the builder, reject bare
  `:memory:`/`mode=memory` without `cache=shared` (or document that in-memory
  DSNs are dev-only), consistent with the `memDSN` precedent
  (`test/storage_health_test.go:23-25`).

### F-DB-10 (Info — Verified): hot-path latency is unbounded by rule/string size; no workload evidence

See security review F-4: no per-string length caps and no body limit on PUT
(the server default `WithBodyLimit` is 0 = unlimited, Verified
`options_httpstack.go:57-63`), so prefix scans in `scopeMatches`/
`resourceMatches` run over multi-MB strings on every exchange hop. DB-side:
JSON columns grow unboundedly and every boot reload re-decodes them. Cap
strings (e.g. ≤256 bytes) in the shared `ValidateRules` and wrap the PUT body
with `http.MaxBytesReader`. Also see §5 unknowns — no measurements exist yet
for maximal rule sets.

---

## 3. Query/index and transaction analysis for demonstrated hot or atomic paths

**Hot path (`/token` exchange, `Allow`):** zero SQL by design (Proposed).
Verified shape: `memory.Store.Allow` takes `RLock`, copies the slice header,
runs the pure `Evaluate` (`tokenexchange.go:60-78`), releases. The sqlite
store's `Allow` is specified identically. No index, no query, no clock — the
sqlite file is not on the hot path. This is the correct call for an
admin-sized rule set (≤1000) and the availability analysis in Decision 6
("store outage → snapshot still serves") holds.

**Boot load (one-time):** `SELECT ... ORDER BY position` full scan over the
whole table (≤1000 rows). Correct and sufficient: the table is never queried
by column at runtime (full-replace semantics), so the JSON-in-columns choice
is justified — normalizing `scopes`/`resources` would buy nothing (no
WHERE on them) and cost row mapping. No additional index needed; the
`position INTEGER PRIMARY KEY` (rowid alias) both enforces uniqueness and
carries evaluation order. Recommendation from F-DB-3 stands: run
`ValidateRules` over loaded rows in the same pass.

**`Replace` (the only write path):** single tx = `DELETE` all + `INSERT` per
rule with explicit `position`. Correctness properties, as designed:
- Atomicity: WAL gives readers (boot load of a peer, `Reload`) a
  pre- or post-commit snapshot, never a partial set; a mid-tx failure rolls
  back and the error propagates (500).
- **F-DB-2 defect:** the disk commit (SQLite file lock serialization) and the
  in-memory swap (Go mutex serialization) are two independent critical
  sections; concurrent PUTs can interleave to disk=new/memory=old *durably*.
  Fix: one mutex across tx+swap; `BEGIN IMMEDIATE` to take the write lock up
  front (precedent `beginImmediateRMW`).
- Locking under load: SQLite serializes writers; with WAL + `busy_timeout`
  (F-DB-7) concurrent PUTs queue rather than error. WAL readers never block.
- Durability: a single committed PUT survives process crash (journal/WAL
  durability follows the operator's DSN settings — standard for the repo; the
  default journal mode is already crash-safe, WAL adds concurrency).

**Health/schema gates (boot + `/readyz`):** `DB()` + `Ping` +
`CheckSQLiteSchema` (Verified pattern, `serverbuildsign/build_readiness.go`)
and `AppendStorageHealthSource` (schema versions via `migrate.Status`). The
design specifies both — consistent with every wired sqlite store.

**No other queries exist** in the design: no pagination (full envelope, ≤1000
rows), no TTL/reaper (full-replace, admin-managed), no join surface. Retention
of the audit event falls under existing audit retention config; the rule table
is self-bounding by the 1000-rule cap + full-replace.

---

## 4. Safe migration sequence (v1 baseline only)

The schema is a **new, additive namespace** (`tokenexchange_policy_rules` +
`schema_migrations_tokenexchange_policy_rules`); it touches no existing table
and no existing namespace (`tokenexchange_chain_hops` is separate — Verified
`maxversions.go`). Compatible with both fresh DBs (create) and existing
deployments (no-op baseline + stamp v1).

| Step | Action | Compatibility window / risk |
|---|---|---|
| 1 | Land code + schema + `PolicyStoreMaxVersion()` + `CheckSQLiteSchema` gate in the builder | Additive; old binaries never reference the namespace, so a mixed fleet is safe both ways. The gate only fires when an OLD binary checks a namespace the DB has moved past — with v1 there is nothing to fire; it becomes load-bearing at v2+ |
| 2 | Deploy new binary; opt-in via `oauth.token_exchange.backend: sqlite` (absent section = no store = byte-identical) | Rolling deploy safe; first boot with the section creates the table inside migrate's single `BEGIN IMMEDIATE` tx — mid-failure rolls back cleanly |
| 3 | Validate after first boot (see queries below) | Catch ordering/decoding defects before traffic |
| 4 | Rollback | `migrate` is forward-only (Verified doc): rollback = redeploy old binary (it ignores the table) or restore-from-snapshot. No data to backfill; the table is rebuildable from config or admin PUT |
| 5 | Future v2+ | Any later migration must keep `PolicyStoreMaxVersion` bumped in the same change, or an old binary boots against a forward-migrated DB with only a *boot-time* failure from the gate (canary-rollback protection, `ErrSchemaTooNew`, Verified `migrate.go`) |

**Validation queries** (after first boot, and in the E2E restart test):
1. `SELECT version, name FROM schema_migrations_tokenexchange_policy_rules` → exactly `(1, baseline)`.
2. `SELECT COUNT(*), MAX(position) FROM tokenexchange_policy_rules` → matches the GET envelope `total` and `len(rules)`.
3. `SELECT name FROM tokenexchange_policy_rules ORDER BY position` → equals the GET `rules[].name` order (evaluation-order parity, the admin API's core contract).
4. Hand-written poison rows (`scopes='["*x"]'`, empty `name`, `deny=2`) → `New()` must error (F-DB-3).
5. Restart test (per sibling reviews): open → PUT deny rule → close (release WAL) → reopen same temp DSN → rule still enforced; `-race -count=10` concurrent-Replace (F-DB-2) asserting disk==snapshot after every interleaving.

---

## 5. Unknown volume, retention, and recovery assumptions

- **PUT frequency:** no workload evidence. The design assumes low-churn
  incident-response/admin cadence. If PUTs ever approach per-second rates,
  measure: SQLite write serialization + snapshot swap under one mutex is the
  ceiling; the 1000-rule full-replace tx is the cost unit. No benchmark exists
  in-tree; the validation plan should add one only if this cadence is real.
- **Rule-set size and string lengths:** cap = 1000 rules (Verified as design
  constant), but per-string lengths are unbounded (F-DB-10). Until caps land,
  boot-load decode cost, JSON column size, and hot-path prefix-scan cost are
  all unbounded. Measurements required: hot-path latency at max rules × max
  strings, and boot time at max table size.
- **Multi-replica topology:** the design supports N replicas sharing one DSN
  file (with the F-DB-4 staleness caveat). **Per-replica DSNs are an
  unsupported topology** that silently gives each replica its own rule set —
  this must be stated in `docs/config-reference.md`, or an operator will
  discover divergent deny sets mid-incident.
- **Journal/durability settings:** inherited from `oauth.sqlite.dsn`
  (production example in `config/config_oauth2.go:95-98`: WAL +
  `busy_timeout(5000)`). The store adds no synchronous/journal guarantees of
  its own. A single PUT's durability is bounded by the DSN's settings — same
  trust model as every sqlite store in the repo.
- **Backup/restore:** standard sqlite file backup; restore-from-snapshot is
  the documented rollback (migrate is forward-only). No in-tree tooling
  specific to this table; the table is small and rebuildable. The
  `KindControlPlaneRestore` gap (F-DB-4) means a restore on a live replica
  leaves the in-memory snapshot stale until restart — fold the Reload path
  into the same fix.
- **Retention:** none needed for the rules table (full-replace, ≤1000 rows).
  The `token_exchange_policy_updated` audit events fall under existing audit
  retention; cardinality is bounded by the rule cap (and would be better
  bounded by the missing string caps).

---

## Cross-reference with sibling reviews

- F-DB-1 == security F-1 / QA F1 (verified placement violation) — agreed; the
  domain-package handler relocation is the fix.
- F-DB-2 == distributed F2 (lock scope) — agreed, with the SQL-level
  refinement (`BEGIN IMMEDIATE` precedent).
- F-DB-3 == security F-5 / QA F3(b) (boot-load validation) — agreed.
- F-DB-4 == distributed F1 / security F-3 (bus hook or explicit acceptance +
  `as_of`) — agreed; adds the snapshot-restore staleness angle.
- F-DB-5 == security F-2 (sqlite + config rules) — agreed.
- F-DB-6 == distributed F4 (version/etag) — agreed; v1-vs-defer decision
  should be recorded explicitly.
- F-DB-7/8/9/10 == distributed F6/F5 + security F-4 (busy_timeout, slice
  copy, body/string caps) — agreed.

**Bottom line:** the persistence architecture is sound — memory-snapshot hot
path, single-tx atomic full-replace, additive migration with a boot gate,
loud boot failures, and a store that is genuinely durable when wired. Three
things must change before implementation: F-DB-1 (placement, verified gate
violation), F-DB-2 (commit/swap serialization — one mutex across tx+swap +
`BEGIN IMMEDIATE`), and F-DB-3 (boot-load `ValidateRules`). F-DB-4 must be
resolved as either the ~20-line bus hook (preferred, AGENTS.md §3) or an
explicit acceptance with `as_of` + runbook. F-DB-5 is a cheap fail-loud
guard. Everything else is hardening that fits in the same change.
