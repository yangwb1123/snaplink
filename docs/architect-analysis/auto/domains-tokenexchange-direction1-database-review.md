# Database-Architect Review: `domains/tokenexchange` Direction 1 (ChainStore → revocation control plane)

Review basis: `ai-dev/prompts/README.md`, `docs/auto/domains-tokenexchange-direction1-design.md`,
`docs/auto/domains-tokenexchange-direction1-spec.md`, current executable code,
`docs/config-reference.md`, and the two sibling reviews
(`-distributed-systems.md`, `-security-review.md`). The feature is **Proposed**
(design + spec only). **Checks that ran:** source reads and greps only —
store constructors, migration runner, query paths, builders, wiring call
sites, `wc -l`; no build/test execution and no file modifications. This is
advisory analysis. Every claim about current code is **Verified** (code
read) unless labeled otherwise; design claims are **Proposed**.

---

## 1. Store inventory: purpose, durability, implementation, stock wiring, consistency

| # | Store / table | Purpose | Durability | Implementation | Stock binary wiring | Consistency requirement |
|---|---|---|---|---|---|---|
| S1 | `tokenexchange_chain_hops` (sqlite) | RFC 8693 hop observability; the cascade's parent index | **Durable** (sqlite file, DSN-supplied journal) | `domains/tokenexchange/sqlite`, migrate v1 (`chainSchema`, `idx_..._parent`) | **None.** `cmd/` imports nothing from `domains/tokenexchange` (grep of `cmd/` — zero hits); the only `WithTokenExchangeChainStore(` call site is `test/token_exchange_chain_store_test.go:21,101`, which wires the **memory** store | Per-row upsert atomic (single statement); no cross-row transactions today; hop recording must never block the exchange (fail-open) |
| S2 | `tokenexchange_chain_hops` (memory) | test / single-replica | **Volatile** (process) | `domains/tokenexchange/memory` (RWMutex + maps) | None (tests only) | Same as S1; map writes under `mu` |
| S3 | Issuer in-process token deny-set (`j.revoked[token]`) | RFC 9068 validation authority | **Volatile**, always armed | `infrastructure/defaultimpl/revocation_set.go` (exp-bounded, prune-not-early, `revokedMu`) | **Yes** — every JWT issuer (RSA/Ed25519/ECDSA) in the stock binary | O(1) lookup on `Validate`; set-insert marks; must never be consulted as a store (map only) |
| S4 | `revocations` table (sqlite) | Durable backing for S3 (restart/late-join re-seed) | **Durable** | `infrastructure/defaultimpl/sqlite/revocations.go`, migrate v1, lazy prune on `Load` | **Yes** — `keys.signing.revocation_backend: sqlite` (+ `revocation_dsn`), `serverbuildsign/build_signing.go:84-106`; `memory` is the default | Idempotent upsert (`ON CONFLICT DO UPDATE`); prune-not-early |
| S5 | `MemoryRevocationStore` | default durable seam for S3 | **Volatile** | `defaultimpl.NewMemoryRevocationStore` | Yes (default) | mutex + lazy prune |
| S6 | cluster invalidation bus | cross-replica propagation (`KindTokenRevoked`) | etcd-backed: durable; memory-backed: volatile | `platform/cluster/etcd`, `platform/cluster/memory` | Opt-in (`WithCrossReplicaRevocation`) | Best-effort, no ordering, no delivery guarantee (bus.go contract) |
| S7 | `AgentSessionStore` | agent session state | **Volatile** — only `MemoryAgentSessionStore` exists in-tree (`domains/tokenexchange/agentidentity/memory_session.go`); no durable backend shipped | memory | None (zero production callers of `RevokeSession`/`RevokeAllForHuman`, grep-verified) | Store-side revoke is a map delete under mutex |
| S8 | Introspection cache | `/token/introspect` fast path | **Volatile**, TTL-bounded (documented: "A revoked token might be served from cache for up to TTL seconds", `introspect_cache.go:29-35`) | optional backend | Opt-in | TTL < token remaining lifetime; point-eviction by full token string only |
| S9 | **Proposed** per-issuer `jtiRevoked` maps | jti deny authority (keystone, Decision 2) | Volatile, always armed (mirrors S3) | design | would be Yes (issuers are stock-wired) | O(1) lookup in `Validate`; set-insert marks under existing `revokedMu` |
| S10 | **Proposed** `jti_revocations` table | durable backing for S9 (re-seed) | Durable | design (`JTIRevocationStore`, mirrors S4) | **None planned** — design explicitly adds no config knob ("wiring-only") | Idempotent upsert; lazy prune |
| S11 | **Proposed** `KindTokenRevokedJTI` bus event | cross-replica jti adoption | inherits S6 | design | inherits S6 (opt-in) | best-effort; local-only adoption (no broadcast loop) |

**Bottom line on "hot vs durable and does the stock binary wire it":**

- **Hot (always-on) stores:** S3 deny-set — stock-wired in all three issuers.
- **Durable stores:** S1/S4 — S4 is stock-wired (config knob exists); **S1 is
  NOT wired anywhere in the stock binary** — it is SDK-option-only, and every
  integration test uses the memory store, so the sqlite backend's production
  durability is exercised by unit tests only (`chain_store_test.go`
  `PersistsAcrossReopen`).
- **The direction's durable spine (S10, S11) inherits S1's wiring gap:** the
  design's Decision-8 restart/cross-replica parity claims ("the sqlite
  `JTIRevocationStore` backs the re-seed", "parity with the existing
  revocation architecture") describe reachable behavior only for SDK
  embeddings that wire `WithTokenExchangeChainStore` + the new store
  manually. A stock `sso-server` deployment cannot enable any of this — no
  builder, no config knob (see F-DB-2).

---

## 2. Findings (sorted by severity)

### F-DB-1 (High, Proposed — design defect): `HopsBySession`'s `LIMIT ?` silently truncates, reintroducing the exact silent-partial-revocation Decision 1 forbids

- **Evidence:** D1 pins "walk truncation at `maxChainWalk` becomes
  `ErrChainWalkTruncated` — never silent partial revocation," but D1's own
  `HopsBySession` contract says only "newest-recorded first, bounded," and
  D6's sqlite sketch is `WHERE session_id = ? ORDER BY recorded_at DESC
  LIMIT ?` — a silent cap; the memory sketch ("bounded by the same 1000
  cap") has the same shape. D6's failure table lists `HopsBySession`
  *errors* but no truncation row. Children per parent are unbounded today
  (`MaxActChainDepth` caps depth, not breadth), so a session or human cohort
  with >1000 recorded mints is not hypothetical.
- **Impact:** `RevokeSession`/`RevokeAllForHuman` kill only the newest 1000
  hops and report success; the **oldest** hops escape — and old hops are the
  ones most likely still unexpired within a long-lived delegation. This is
  the "partial revocation silently dropped" class the design eliminates
  everywhere else, on the most security-sensitive surface (human account
  compromise).
- **Recommendation:** return a `truncated bool` (or use the
  `LIMIT maxChainWalk+1` sentinel — one extra row costs nothing and needs no
  second query), and treat truncation as fail-closed in both
  `RevokeSession` and `RevokeAllForHuman`: audit the partial list and flip
  the event outcome, mirroring `ErrChainWalkTruncated`.
- **Validation step:** unit test seeding 1001 hops on one session, asserting
  the cascade returns an error + partial list, not success. (Also flagged by
  the DS and security reviews as F-1 / finding 3; this is the query-level
  confirmation.)

### F-DB-2 (High, current code fact + Proposed scope gap): the stock binary wires none of this — the durable ChainStore has zero production wiring, and the design adds no path to enable it

- **Evidence:** `grep -rn "domains/tokenexchange" cmd/ --include='*.go'` →
  zero hits; `WithTokenExchangeChainStore(` call sites exist only in
  `test/token_exchange_chain_store_test.go:21,101` (memory store);
  `serverbuildsign/build_signing.go:106` enumerates stock revocation backends
  as `memory, sqlite` for the **token** deny-set only; the design's own
  "No new config knobs — the feature is wiring-only" (implementation order,
  docs discipline) confirms no stock enablement path is planned.
- **Impact:** the spec's "Surface: stock `sso-server` admin API" and D8's
  restart-survival/cross-replica-parity claims are unreachable in the shipped
  binary. A stock deployment gets no descendants view, no admin cascade, no
  `/token/revoke` side-effect; and the keystone's durable story (S10) would
  never be opened by the stock binary, so a jti denial made through any
  SDK-wired path dies on restart in exactly the deployment the direction
  targets. The e2e acceptance suite exercises only the memory backend, so
  the sqlite durability path (migration v2, re-seed, shared-file) has no
  integration coverage.
- **Recommendation:** either (a) add a stock builder + config knob for the
  chain store (contradicts the design's "wiring-only" choice — that choice
  needs explicit re-justification), or (b) re-scope D8/D10.9 and the spec's
  surface claim to SDK embeddings and add a stock-binary test asserting the
  admin route is not mounted and `/token/revoke` is byte-identical when
  unwired. This is a decision the design must make; currently it claims
  both "stock surface" and "no config knob," which cannot both hold.
- **Validation step:** `grep -rn "WithTokenExchangeChainStore(" cmd/` (must
  be non-empty after (a)); or a stock-built-server e2e asserting route
  absence after (b).

### F-DB-3 (High, Proposed — design defect): the cascade's N+1 BFS has no snapshot isolation and costs up to 1000 sequential queries in-band

- **Evidence:** `sqlite/chain_store.go` `GetDescendants` issues one
  `getChildren` SELECT per visited node (bounded by `maxChainWalk` = 1000);
  `RevokeDescendants` reuses the same walk (D1). Each statement sees its own
  SQLite snapshot (WAL), so a concurrent `RecordHop` (a mint) can insert a
  child of an already-visited parent **after** its `getChildren` ran — that
  descendant escapes the cascade. The walk is read-only; nothing pins a
  snapshot across statements. On `/token/revoke`, `revokeAccess`
  (`handle_revoke.go:152`) runs **before** `ctx.JSON(200)` is written
  (verified: `HandleRevoke` calls `revokeAccess` at lines 97/99, then
  `InvalidateIntrospectionCache` at 109, then the 200 at 111), so the full cascade cost — up to 1000 SELECTs + up to 1000 durable
  INSERTs + 3×1000 map marks + 1000 bus publishes — is in-band and widens
  the valid-vs-unknown-token timing channel by ~2 orders of magnitude on a
  public credential endpoint. (Security review finding 2 concurs; protocol
  review F3 concurs.)
- **Impact:** (1) revoke-during-mint race — a token minted mid-cascade can
  be missed and stay valid (also security review finding 6); (2) request
  latency amplification; (3) no atomicity between "what the walk saw" and
  "what the durable legs recorded."
- **Recommendation:** replace the N+1 walk with a single
  `WITH RECURSIVE` query over `idx_tokenexchange_chain_hops_parent` (one
  statement = one snapshot = a consistent view + one round trip), retaining
  the visited cap and the `truncated` flag. This single change fixes the
  race, the latency, and makes the durable batch (F-DB-4) atomic with the
  walk's snapshot. Keep the memory-store walk as-is (already consistent
  under its RWMutex).
- **Validation step:** `EXPLAIN QUERY PLAN` on the recursive CTE shows the
  parent index; a `-race -count=10+` test with a concurrent `RecordHop`
  inserting a child mid-walk asserts the child is either included or the
  walk errors (never silently missed).

### F-DB-4 (Medium, Proposed — design gap): crash mid-cascade leaves a partial durable deny-set; the admin root kill's durable leg is its *only* durable record

- **Evidence:** D2's `expire` closure persists best-effort per hop
  ("an error logged + metric, does NOT fail the mark"), and no transaction
  spans the cascade; re-seed (`SeedJTIRevocations`, D8) restores exactly
  what was persisted. The token path's parity claim ("the same gap the token
  deny-set had before `RevocationStore`") is **not** the same: on
  `/token/revoke` the root's full token string is durably persisted by the
  existing S4 path and a retry re-persists it; the admin surface holds only
  a jti (D4), so if the process dies between hop i and hop i+1, marks i+1..n
  are gone permanently (bus is best-effort; the memory bus loses them
  outright). The root itself has no token-string record anywhere.
- **Impact:** a crash mid-cascade silently converts a "revoked" admin
  response into a partial revocation that no re-seed can repair; the root
  kill is in-process-only until its durable write lands.
- **Recommendation:** (1) colocate `jti_revocations` in the **same sqlite
  file** as `tokenexchange_chain_hops` (the design leaves the DSN open) and
  batch the cascade's durable leg into one write transaction (≤1000 upserts
  — fast, atomic, and atomic with the F-DB-3 snapshot if the walk is one
  statement); (2) for the admin root, treat the root's durable persist as a
  required leg (the admin surface is a control plane, not an oracle — a 500
  "not durably recorded" is honest) or at minimum audit "root deny not
  durably persisted" distinctly from descendant best-effort marks.
- **Validation step:** unit test with an injected durable-store failure at
  hop 500 asserting the audit carries the persisted/unpersisted split;
  restart re-seed honors only the persisted subset, and that subset is
  exactly the audit's.

### F-DB-5 (Medium, current code fact): `domains/tokenexchange/sqlite` connections get no `busy_timeout` when used standalone — SDK-embedding hazard the design's shared-file story amplifies

- **Evidence:** the process-wide `PRAGMA busy_timeout=5000` hook is
  registered in `infrastructure/defaultimpl/sqlite`'s `init()`
  (`busy_timeout.go`); `domains/tokenexchange/sqlite/chain_store.go` imports
  only `modernc.org/sqlite` + `platform/migrate` — no defaultimpl import. The
  migration runner sets `busy_timeout(10000)` only on its pinned migration
  connection (`migrate.go beginImmediate`); runtime pool connections in a
  standalone embedding get the driver default (0 → immediate `SQLITE_BUSY`
  under write contention). The stock binary is safe only because it happens
  to import the defaultimpl sqlite package. D8's "shared sqlite file,
  multi-replica" model makes contention a first-class scenario.
- **Impact:** SDK embedders wiring only the chain store (the direction's
  own deployment story) get spurious busy errors on concurrent
  `RecordHop`/cascade writes; no error is fail-open (the hop is dropped, the
  cascade aborts) — silent observability loss and fail-closed cascade aborts
  caused by a missing PRAGMA.
- **Recommendation:** register the busy_timeout hook (or set
  `_pragma=busy_timeout(5000)` guidance) inside
  `domains/tokenexchange/sqlite` itself, and document that WAL
  (`_journal=WAL` in the DSN) is required for multi-connection use — the
  store sets no journal pragma today (tests pass plain `file:` DSNs).
- **Validation step:** two-connection concurrent-write test with no hook →
  busy errors observed; with the hook → serialized success.

### F-DB-6 (Medium, Proposed — operational consequence): pre-v2 rows permanently poison cascades, and nothing can backfill them

- **Evidence:** v2 `ALTER TABLE ... ADD COLUMN expires_at INTEGER NOT NULL
  DEFAULT 0` (D3) makes every pre-upgrade row read `expires_at = 0`; the
  pinned `ErrHopMissingExpiry` aborts any cascade touching such a row; rows
  are append-only and never pruned, so the landmine never ages out; the
  admin surface holds only a jti, so a pre-v2 root is **permanently
  un-revokable** from admin, and any legacy hop inside a subtree 500s every
  cascade through it forever. No backfill is possible — the minted token's
  `exp` is not derivable from any stored column (the hop records
  `recorded_at`, not `exp`; the token itself is the only carrier and is
  gone).
- **Impact:** upgraded deployments with chain history silently lose the
  cascade capability on exactly the oldest (most interesting) chains,
  discovered at incident time as a 500.
- **Recommendation:** the never-deny-for-zero pin is right; add an explicit
  upgrade note to the endpoint contract + the `ErrHopMissingExpiry`
  error-code entry ("cascade surface applies to post-v2 mints only"), and
  emit a metric/audit when a cascade aborts on a legacy row so operators
  learn the history predates the control plane. Consider a `Func` migration
  (migrate supports it, `migrate.go`) that counts/annotates legacy rows —
  not to backfill a TTL (impossible), but to make the population visible at
  upgrade time.
- **Validation step:** v1-seeded DB → apply v2 → assert legacy rows read
  `expires_at = 0`, `GetChain`/`GetDescendants` still work on them, and a
  cascade through one aborts with `ErrHopMissingExpiry`.

### F-DB-7 (Medium, Proposed — operability): `tokenexchange_chain_hops` grows unboundedly with no retention policy; the new session index adds per-mint write amplification

- **Evidence:** the table is never pruned (by design — observability
  history); children per parent are unbounded (breadth is not capped by
  `MaxActChainDepth`); D3 adds `idx_tokenexchange_chain_hops_session` — a
  second index maintained on every `RecordHop`. Contrast S4/S10, which prune
  lazily on `Load` (bounded by TTL). No volume, growth, or retention
  evidence exists anywhere in the tree (see §5).
- **Impact:** unbounded disk + index growth over a long-lived deployment;
  the admin descendants surface's 100-row default hides the underlying
  table size; the cascade's worst case (1000) is a floor that grows with
  table size only via the index, but write cost per mint grows with index
  count.
- **Recommendation:** decide a retention policy (archival to cold storage,
  or partitioned pruning with an audit trail) or explicitly declare
  append-only-forever as the contract; add a size metric and a documented
  operational query. Measure before shipping.
- **Validation step:** none required beyond the policy decision; a size
  gauge on `COUNT(*)`/`page_count` per store would support it.

### F-DB-8 (Medium, Proposed — deployment constraint): the multi-replica "shared sqlite file" model is fragile and the jti store inherits it

- **Evidence:** S4's own doc claims "On a SHARED database it is a
  multi-replica durable deny-set"; stock config examples use
  `file:...?_journal=WAL&_pragma=busy_timeout(5000)`; D8 builds the jti
  re-seed on the same model. SQLite over NFS-style filesystems is unsafe
  (locking), and WAL checkpointing across replicas on one file serializes
  writers on the 5s busy timeout (also DS review's shared-file hazard).
- **Impact:** the durability story for S10 is only as sound as the
  filesystem; misconfigured shared files produce busy failures (see F-DB-5)
  or corruption-class behavior.
- **Recommendation:** document local-disk-or-SAN-only for shared-file
  deployments; keep the etcd bus as the live path and the shared file purely
  as the restart/re-seed path (which D8 already does); consider per-replica
  files + bus + periodic re-seed for WAN topologies.
- **Validation step:** an ops note + a test opening two stores on one WAL
  file and asserting serialize-or-timeout behavior.

### F-DB-9 (Low, Proposed — query plan): `HopsBySession` sorts on `recorded_at` over a session_id-only index

- **Evidence:** D3's `idx_tokenexchange_chain_hops_session` is on
  `session_id` alone; D6's query is `WHERE session_id = ? ORDER BY
  recorded_at DESC LIMIT ?` — SQLite must collect and sort every matching
  row before applying the LIMIT. `recorded_at` is stored as UnixNano
  (integer), so a composite index is trivially expressible.
- **Impact:** bounded (per-session rows), but the sort is pure waste on a
  path that also needs the truncation sentinel (F-DB-1); the LIMIT cannot be
  a true range scan.
- **Recommendation:** `CREATE INDEX ... (session_id, recorded_at DESC)` in
  migration v2 (same migration, one statement). Also add a column-level
  comment: `recorded_at` is UnixNano, `expires_at` is unix seconds — mixed
  units in one table; a future "still-alive hops" query must not compare
  across units.
- **Validation step:** `EXPLAIN QUERY PLAN` shows the composite index
  serving both the WHERE and the ORDER BY (no temp B-tree).

### F-DB-10 (Low, current code fact): `ChainStoreMaxVersion` has no production caller; the chain namespace is outside the stock boot schema guard

- **Evidence:** `domains/tokenexchange/sqlite/maxversions.go` defines
  `ChainStoreMaxVersion()`; grep shows no non-test caller. The stock boot
  guard (`serverbuildsign.CheckSQLiteSchema` + `cmd/sso-server/
  schema_guard_test.go`) covers only stock-wired namespaces. Because the
  stock binary never opens the chain DB, a canary rollback against a
  v2-migrated chain DB would not fail loud — it would just be invisible.
- **Impact:** zero today; becomes a rollback foot-gun the moment any
  builder wires the store (see F-DB-2).
- **Recommendation:** when wiring lands, add the chain namespace to the boot
  guard; update `TestChainStoreMaxVersion_MatchesLiveSchema` for v2 in the
  same change.
- **Validation step:** the existing `TestCheckSQLiteSchema_RefusesAheadDB`
  pattern applied to the chain namespace.

### F-DB-11 (Low, current code fact): introspection-cache staleness for jti-killed tokens is TTL-bounded and unavoidable without the rejected index

- **Evidence:** `introspect_cache.go:29-35` documents the bound ("A revoked
  token might be served from cache for up to TTL seconds"); `handle_revoke.go`
  point-evicts only the presented token string; D2 explicitly rejects the
  jti→token index. A jti kill (admin root or cascade descendant) cannot be
  point-evicted.
- **Impact:** `/token/introspect` can answer `active:true` for a
  cascade-killed descendant for up to TTL — bounded and cache-contract-
  consistent, but a declared residual window the endpoint contract should
  state (protocol review F2 concurs). No store change can fix it; this is a
  documentation fix.
- **Recommendation:** document the window in the endpoint contract +
  OpenAPI description; mark jti-keyed eviction an explicit non-goal.
- **Validation step:** a regression test asserting stale `active:true`
  within TTL after a jti kill (documented behavior, not a fix).

### Cross-checked and confirmed (not re-listed as findings)

- Migration runner is atomic: `migrate.run` wraps all pending migrations in
  one `BEGIN IMMEDIATE` transaction with a rollback defer (`migrate.go`) —
  a crash mid-v2 leaves v1 fully intact. Verified.
- `revokeAccess` runs before the 200 is **written** (`handle_revoke.go`
  lines ~106-118); the cascade is in-band. The design's "after the 200 is
  decided" phrasing is salvageable but "written before/independent" is
  false — folded into F-DB-3 (protocol review F6 concurs).
- All file budgets, `maxChainWalk`, deny-set keying, and `HopsBySession`
  breadth claims from the design were re-verified against source (sibling
  reviews' ledgers; no contradictions found in the storage layer).

---

## 3. Query/index and transaction analysis (demonstrated hot + atomic paths)

**Hot path — RFC 9068 `Validate` (per validation):** today one O(1) map
lookup against the token deny-set after claims decode, plus the signature
check; no I/O. The proposed jti lookup adds one more O(1) map lookup —
negligible, in-process only, fail-closed by construction (D2's seam). This
path must never touch the durable store (the design correctly keeps the
in-process map authoritative).

**Mint/exchange path — `RecordHop`:** one indexed upsert
(`ON CONFLICT(jti) DO UPDATE`, autocommit under WAL), atomic and idempotent;
caller is fail-open (`RecordHopFailOpen`). Cost grows with the two indexes
(parent, and session once v2 lands). A slow write delays the exchange
response (documented in the interface doc) but cannot fail it.

**Cascade path — the one true hot/atomic problem:** the N+1 BFS
(`getChildren` per visited node, ≤1000 statements) with per-statement
snapshots (F-DB-3) feeding per-hop durable writes and bus publishes with no
spanning transaction (F-DB-4). Every other store in this review has a
single-statement atomic core; the cascade is the first multi-row operation
in the revocation architecture, and it is designed as an uncoordinated
sequence. The single recursive-CTE + single-batch-transaction shape fixes
snapshot consistency, latency, and crash atomicity at once.

**Atomic-consume/rotation semantics:** not applicable here — no
read-then-delete stores on this path (refresh-family atomicity lives in the
refresh store, untouched by this direction). The deny marks are set-inserts;
idempotency is a property of the marks, correctly so (D1).

**Locking:** memory store RWMutex; deny maps under the existing `revokedMu`
(no new lock, no lock-ordering surface — verified); sqlite relies on WAL +
busy_timeout; migration boot serializes via `BEGIN IMMEDIATE` +
`busy_timeout(10000)`.

---

## 4. Safe migration sequence (v2), compatibility, rollback, validation

**Migration v2** (D3 — append to `chainMigrations`):

```sql
ALTER TABLE tokenexchange_chain_hops ADD COLUMN session_id TEXT NOT NULL DEFAULT '';
ALTER TABLE tokenexchange_chain_hops ADD COLUMN expires_at INTEGER NOT NULL DEFAULT 0;
CREATE INDEX IF NOT EXISTS idx_tokenexchange_chain_hops_session
    ON tokenexchange_chain_hops(session_id);
-- recommended add (F-DB-9):
CREATE INDEX IF NOT EXISTS idx_tokenexchange_chain_hops_session_rec
    ON tokenexchange_chain_hops(session_id, recorded_at DESC);
```

**Safety properties (Verified against `platform/migrate`):**

1. **Atomic:** all three statements run inside one `BEGIN IMMEDIATE`
   transaction on a pinned connection; any failure rolls back — a crash
   mid-v2 leaves the DB at v1, fully intact. Concurrent replicas booting
   together serialize on the write lock (loser waits on the 10s migration
   busy_timeout, then no-ops).
2. **No table rewrite:** `ADD COLUMN` with a constant `NOT NULL DEFAULT` is a
   metadata-only change in SQLite (no copy of existing rows) — safe on any
   table size. (Documented SQLite behavior; modernc.org/sqlite is current.)
3. **Compatibility window (forward-only):**
   - New binary + v1 DB: migrates at open (`New`/`NewWithDB`), stamps v2.
   - Old binary + v2 DB: `migrate.run` applies nothing (recorded 2 ≥ max 1)
     and returns success; old code never references the new columns, and
     both have defaults, so reads/writes are unaffected — **silent but
     safe** (this is why F-DB-10 matters for stock wiring: nothing fails
     loud).
   - Canary rollback: restore-from-snapshot (migrate's documented contract;
     no down migration exists). The `ErrSchemaTooNew` guard exists
     (`migrate.go`) but is not wired for the chain namespace (F-DB-10).
4. **Data-integrity checks to run in the migration's own test + at upgrade:**
   - `SELECT version, name FROM schema_migrations_tokenexchange_chain_hops`
     → `(2, ...)` after upgrade.
   - `PRAGMA table_info(tokenexchange_chain_hops)` → both new columns
     present; `PRAGMA index_list(tokenexchange_chain_hops)` → session
     index(es) present.
   - `PRAGMA integrity_check` → `ok`.
   - `SELECT COUNT(*) FROM tokenexchange_chain_hops WHERE expires_at = 0`
     → equals the pre-v2 row count (every legacy row, and only legacy rows,
     unless a buggy new recorder wrote a zero TTL).
   - `SELECT COUNT(*) FROM tokenexchange_chain_hops WHERE session_id <> ''`
     → 0 immediately post-migration (only the agent mint path sets it,
     D3/D6); any non-zero count means a recorder wrote outside its contract.
   - Upsert idempotency re-check: re-recording the same jti after v2 keeps
     `scanHop`'s 9-column projection consistent (single scan path — verified
     design claim).
   - Legacy-row read path: `GetChain`/`GetDescendants` over pre-v2 rows
     return `expires_at = 0`, and the cascade aborts with
     `ErrHopMissingExpiry` (never denies-for-zero) — the F-DB-6 acceptance
     test.
5. **Roll-forward plan:** v2 is the only new step; if the direction ships in
   steps, ship D3's schema + fields in step 1 (implementation order) so
   later steps never re-touch the schema. If the composite index (F-DB-9) is
   decided late, it lands as a separate v3 (`CREATE INDEX IF NOT EXISTS` —
   additive, safe, no data migration).

---

## 5. Unknown volume, retention, and recovery assumptions

No workload evidence exists in the tree for any of these; each is a
measurement the design should demand before production rollout:

1. **Volume:** exchange rate, hops per chain (distribution — depth is capped
   at 10 by `MaxActChainDepth`, breadth is unbounded), hops per session,
   cascade-size percentiles (the 1000 cap's headroom), table growth rate.
   Required before the admin descendants surface and the `/token/revoke`
   side-effect can claim latency bounds (F-DB-3).
2. **Retention:** `tokenexchange_chain_hops` is append-only forever with no
   archival path (F-DB-7). Whether that is acceptable is a product decision
   with a disk-cost curve the design does not address.
3. **Recovery:** no documented backup/restore for the chain DB (sqlite file
   copy; WAL checkpoint cadence unknown; no RTO/RPO stated). The boot
   re-seed's semantics are verified, but recovery *of the file* is
   undetermined. Shared-file deployments additionally assume a
   local-disk/SAN filesystem (F-DB-8).
4. **Topology:** per-replica files vs one shared file; replica count; WAL
   settings (DSN-supplied, per-store); bus backend (etcd vs memory) per
   deployment — the memory bus makes cross-replica jti adoption
   best-effort-with-loss, which D8's "parity" claim should be read against.
5. **Introspection cache TTLs** per deployment bound the F-DB-11 staleness
   window; no global default is documented here.
6. **Agent session durability:** `AgentSessionStore` is memory-only (S7);
   session revocation state itself does not survive restart — the direction
   inherits this for the session cascade, and it should be stated alongside
   D8's restart-survival claims.

---

## 6. Priority validation tests (database-specific)

1. F-DB-1: 1001-hop session → `HopsBySession` truncation surfaced, cascade
   fails closed with partial list + failure audit.
2. F-DB-3: recursive-CTE walk uses `idx_tokenexchange_chain_hops_parent`
   (`EXPLAIN QUERY PLAN`); concurrent-mint-during-walk race test
   (`-race -count=10+`) asserts no silent miss.
3. F-DB-4: injected durable-store failure at hop 500 → audit carries the
   persisted/unpersisted split; restart re-seed honors exactly the persisted
   subset; admin root durable persist is a required leg.
4. F-DB-5: standalone `domains/tokenexchange/sqlite` two-connection
   concurrent write test (busy timeout hook present after fix).
5. F-DB-6: v1-seeded DB → v2 → legacy rows read `expires_at=0`; read paths
   intact; cascade aborts `ErrHopMissingExpiry`.
6. Migration: atomicity (injected mid-v2 failure leaves v1), version stamp,
   `PRAGMA integrity_check`, index presence, zero non-empty `session_id`
   post-migration.
7. Existing RFC 7009 oracle suite passes unchanged (byte-identical when
   unwired); stock-binary route-absence test per F-DB-2.

**Declared unsupported / non-goals (current code; the design does not
change them):** jti→token index (D2 rejection) — which also makes
jti-keyed introspection-cache eviction impossible (F-DB-11); backfill of
pre-v2 hop TTLs (nothing to backfill from, F-DB-6); durable AgentSession
state (S7); any multi-row transaction on the token revocation path today
(the cascade's batch is the design's first, F-DB-4).
