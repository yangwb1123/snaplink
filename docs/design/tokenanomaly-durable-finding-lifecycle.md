# Design: tokenanomaly — Durable FindingStore, Triage Lifecycle, Paginated/Tenant Query Surface

Design for the three verified expansion directions on `domains/tokenanomaly`. All
file/line references were verified against executable code before writing. Scope
is exactly the three decisions below; the detector-side observation sharing gap
(`Detector.obs` is process-local, so geo cardinality dilutes across replicas) is
explicitly out of scope — this design fixes the persist/surface half of the
chain only.

One correction to the decision text: `domains/tokenanomaly/sqlite` does **not**
need a `layerName()` edit in `architecture_layer_test.go`. Under the v2 layered
tree the first path segment IS the layer (`layerName` switch, `case "shared",
"platform", "domains", ...`), so `domains/tokenanomaly/sqlite` classifies as
`domains` automatically — exactly like the existing peer
`domains/threataction/sqlite`. The "classified as infrastructure" wording in the
decision is inaccurate but harmless: the same-layer import
`sqlite → tokenanomaly` is legal, no `layerExemptions` entry is involved, and
the mandatory outcome (gate passes without exemptions) is unchanged. The same
holds for the new `domains/tokenanomaly/tokenanomalytest` conformance package.

The three decisions share one schema, one conformance suite, and one config
section, and they touch the same interface (`FindingStore`) — they should land
as **one change**, shipping a single baseline migration v1 with the final
schema. Landing them separately means migration v2 = `ALTER TABLE ADD COLUMN`
(SQLite supports it), but there is no production reason to split.

Data flow after the change:

```text
usage events → Recorder drain → Detector.Record (observation{TenantID} captured)
  → periodic Detector.Analyze sweep (per replica)
      1. detectGeoVelocity/detectRateSpike → Finding{TenantID}
      2. findings.Add (UPSERT, reopen-on-resolved)        # shared sqlite or memory
      3. ResolveStale(now-window, now-retention)          # auto-close + retention prune
  → admin GET /api/v1/admin/tokens/suspicious (tenant filter, keyset cursor)
  → admin PATCH /api/v1/admin/tokens/suspicious/{key} (open/acknowledged/resolved, audited)
```

---

## Decision 1: Durable FindingStore with a config-selectable sqlite backend

**Name:** `token_anomaly.backend` = `memory | sqlite`.

**Problem (verified):** `domains/tokenanomaly/memory/store.go` is the sole
`FindingStore` implementation — a 1024-row FIFO-capped, process-local table that
loses every finding on restart and fragments findings across replicas (each
replica's `Analyze` sweep writes only to its own store, so the admin API on
replica A never sees replica B's findings). `BuildTokenAnomaly`
(`cmd/sso-server/serverbuildplatform/build_governance.go`) hardcodes
`tokenanomalymemory.NewFindingStore`, and `TokenAnomalyConfig`
(`config/config_snapshot.go`) has no backend/DSN fields. The missing pattern
exists in-tree: `domains/threataction/sqlite` (schema + `migrate.Run` +
`NewWithDB`/`Close`/`Ping`/`DB`) and `BuildConfigAuditStore`'s
`config_audit.backend` switch.

### API surface

- `FindingStore` (interface, `domains/tokenanomaly/tokenanomaly.go`) is
  unchanged by this decision alone — `Add`/`List` stay, the `DedupKey` UPSERT
  contract stays (a cross-replica re-run of the same finding must be
  idempotent). Decisions 2/3 extend the interface; all three land together, so
  the interface changes once.
- New package `domains/tokenanomaly/sqlite` exposing, mirroring
  `threataction/sqlite`:
  - `New(dsn string) (*FindingStore, error)` — `sql.Open("sqlite", dsn)`,
    `PingContext`, `migrate.Run(ctx, db, "token_anomaly_findings", migrations)`,
    fail loud on any step (wrapped, prefixed errors).
  - `NewWithDB(db *sql.DB) (*FindingStore, error)` — shared-pool deployments;
    caller owns the connection lifecycle.
  - `Close() error` (idempotent), `Ping(ctx) error` (for `sso.WithReadyCheck` /
    storage-health readiness, the `threataction/sqlite` peer pattern), `DB()`
    (storage-health schema reporter).
  - `var _ tokenanomaly.FindingStore = (*FindingStore)(nil)` compile guard.
- The composition root closes a returned `io.Closer` at shutdown, exactly like
  `BuildConfigAuditStore`'s callers. `BuildTokenAnomaly` returns
  `(rec, detector, err)`; the sqlite store is reachable via
  `detector.Findings()` for the closer — the cmd wiring pattern for
  configaudit's closer is copied (see Failure modes for ordering).
- Config (`TokenAnomalyConfig` gains):
  - `Backend string` — `memory` (default, empty ⇒ memory) | `sqlite`.
  - `Sqlite struct{ DSN string }` — required when `backend=sqlite`, boot error
    otherwise (`"token_anomaly.sqlite.dsn required when token_anomaly.backend=sqlite"`),
    same loud contract as `config_audit`.
  - Unknown backend value → boot error listing supported values (mirror
    `BuildConfigAuditStore`'s default branch).
  - `MaxFindings` becomes a **memory-only** knob: the sqlite backend drops FIFO
    cap-eviction (an audit record must not silently vanish); boundedness moves
    to Decision 2's retention. Accepted-but-ignored under sqlite (configs that
    set it keep booting); documented in `docs/config-reference.md` as a
    divergence.

### Storage model

Single table, migration v1 (final shape — includes the Decision 2 status
columns and Decision 3 tenant column so the baseline is the last migration):

```sql
CREATE TABLE token_anomaly_findings (
    dedup_key       TEXT PRIMARY KEY,            -- Type + "\x00" + (thumbprint|client_id)
    type            TEXT NOT NULL,
    severity        TEXT NOT NULL,               -- warn | critical
    status          TEXT NOT NULL DEFAULT 'open',-- open | acknowledged | resolved (D2)
    tenant_id       TEXT NOT NULL DEFAULT '',    -- '' = unknown/tenant-less (D3)
    thumbprint      TEXT NOT NULL DEFAULT '',
    client_id       TEXT NOT NULL DEFAULT '',
    subject_id      TEXT NOT NULL DEFAULT '',
    geos            TEXT NOT NULL DEFAULT '[]',  -- JSON array; slice-shaped → JSON column
    detail          TEXT NOT NULL DEFAULT '',
    count           INTEGER NOT NULL DEFAULT 0,
    first_seen_ns   INTEGER NOT NULL,            -- unix nanos, lossless time.Time round-trip
    last_seen_ns    INTEGER NOT NULL,
    resolved_at_ns  INTEGER,                     -- NULL = unresolved (D2)
    resolved_reason TEXT NOT NULL DEFAULT ''     -- (D2)
);
CREATE INDEX idx_findings_tenant_lastseen ON token_anomaly_findings(tenant_id, last_seen_ns DESC);
CREATE INDEX idx_findings_lastseen        ON token_anomaly_findings(last_seen_ns DESC);
```

Schema rationale:

- **Columns, not a JSON blob** (deliberate divergence from
  `threataction/sqlite`'s blob-by-name): Decision 3 queries by
  `(tenant_id, last_seen)` and filters on `type/severity/status` — the
  sibling-store precedent (`connections/sqlite`, `permissions/sqlite`) pushes
  only *never-WHERE-queried* slice/map fields into JSON. Here only `geos` is
  slice-shaped; everything else is a filter key or a scalar.
- **Times as unix-nanos INTEGER.** `time.Time` comparisons and ordering must be
  lossless; SQLite's `TEXT` RFC3339 comparison is not, and second-granularity
  INTEGER would collapse the `LastSeen` tie-break that Decision 3's cursor
  depends on. Nanos fit int64 until 2262.
- **`dedup_key` TEXT PRIMARY KEY.** The key contains a NUL byte; SQLite TEXT
  stores it fine and BINARY collation compares byte-wise — identical to Go's
  `<` on strings, which is what the memory store's `List` tie-break uses.
- **`tenant_id` merge**: `COALESCE(NULLIF(excluded.tenant_id,''),
  token_anomaly_findings.tenant_id)` — a re-detection with an empty tenant must
  not blank a stored tenant (see parity trap below).

The UPSERT merge — `ON CONFLICT(dedup_key) DO UPDATE` — mirrors
`memory.mergeFinding` exactly (earliest `FirstSeen`, latest `LastSeen`,
severity escalates only, fresher `Count`/`Geos`/`Detail` replace, and the D2
reopen rule):

```sql
first_seen_ns   = CASE WHEN token_anomaly_findings.first_seen_ns = 0
                       THEN excluded.first_seen_ns
                       ELSE MIN(token_anomaly_findings.first_seen_ns, excluded.first_seen_ns) END,
last_seen_ns    = MAX(token_anomaly_findings.last_seen_ns, excluded.last_seen_ns),
severity        = CASE WHEN token_anomaly_findings.severity = 'critical'
                            OR excluded.severity = 'critical'
                       THEN 'critical' ELSE 'warn' END,
count = excluded.count, geos = excluded.geos, detail = excluded.detail,
thumbprint = excluded.thumbprint, client_id = excluded.client_id, subject_id = excluded.subject_id,
tenant_id = COALESCE(NULLIF(excluded.tenant_id, ''), token_anomaly_findings.tenant_id),
status = CASE WHEN token_anomaly_findings.status = 'resolved' THEN 'open'
              ELSE token_anomaly_findings.status END,
resolved_at_ns = CASE WHEN token_anomaly_findings.status = 'resolved' THEN NULL
                      ELSE token_anomaly_findings.resolved_at_ns END,
resolved_reason = CASE WHEN token_anomaly_findings.status = 'resolved' THEN ''
                       ELSE token_anomaly_findings.resolved_reason END
```

The `first_seen_ns = 0` guard is a parity trap the naive `MIN()` form gets
wrong: Go's `mergeFinding` keeps `next.FirstSeen` when `prev.FirstSeen` is
zero, but `MIN(0, x) = 0` would pin the row to epoch. This is exactly what the
conformance suite must catch (see Decision 3 for the shared suite).

### Failure modes

- **Boot:** DSN empty, `sql.Open`/`Ping`/`migrate.Run` failure, or unknown
  backend → `BuildTokenAnomaly` returns an error, server does not boot. This is
  the configaudit contract: a misconfigured durable store is an operator error,
  not a silent degradation.
- **Runtime store error (detection side):** unchanged fail-open behavior —
  `Detector.Analyze` collects the first `Add` error and keeps sweeping the
  remaining findings; the sweep goroutine never dies on a store error
  (`RunTokenAnomalyDetection` already logs and continues). A sqlite outage
  means findings are *skipped*, not buffered — a bounded, documented loss
  window, identical in spirit to the memory store's eviction.
- **Runtime store error (admin side):** `List` failure → `500 internal_error`
  (existing handler path). `Ping` failure → storage-health readiness flips,
  `/readyz` reflects it via the same wiring `threataction/sqlite` uses.
- **Shutdown ordering:** the sqlite store must be `Close`d only after the
  recorder drain goroutine has stopped AND the sweep goroutine has joined
  (`ctx` cancel + wait, mirroring how configaudit's closer is sequenced in
  `cmd/sso-server`). Closing under a live sweep yields `sql: database is
  closed` errors that the fail-open path would silently log — benign but
  avoidable; the cmd wiring owns the order.
- **Multi-process sqlite:** one writer at a time; concurrent upserts from
  replica sweeps contend on the write lock. The store sets
  `PRAGMA busy_timeout` (a few seconds — sweep upserts are single-row,
  sub-ms) and uses `journal_mode=WAL` for read/write concurrency. Deployment
  contract to document: the shared file must sit on a filesystem with real
  POSIX locking (local disk, shared block device); **network filesystems
  without proper locking (plain NFS) corrupt sqlite databases** — this is the
  classic durable-store foot-gun and must appear in `docs/config-reference.md`
  next to `token_anomaly.sqlite.dsn`.
- **Two-detector convergence:** two `Detector`s (simulated replicas) sharing
  one sqlite store, each analyzing disjoint observations: `dedup_key` PK +
  `ON CONFLICT` upsert guarantees no duplicate rows and no lost upsert; the
  union of both replicas' findings is present. The `Add`-then-merge is
  single-statement, so no read-modify-write race exists.

### What could break the design

- **Merge-semantics drift** between Go (`memory.mergeFinding`) and SQL is the
  top risk: zero-`FirstSeen` handling, severity escalation, reopen-on-resolved
  (D2), and empty-tenant preservation are four distinct traps. The parity
  conformance suite (same scripted sweep sequence through both stores, byte
  comparisons of `Add`/`List` results) is the guard — it must be written
  *first*, before the sqlite implementation, and must include a zero-`FirstSeen`
  row and an empty-tenant re-detection.
- **`layerName()` misclassification**: none needed (see header note), but the
  new packages must be added to the walk's expectations if the test requires
  explicit registration — verify by running
  `go test -run 'TestArchitecture_' .` rather than assuming.
- **Budget drift:** `sqlite/store.go` with schema + CRUD + upsert SQL will
  approach the 500-line file budget; plan to split schema/migrations into a
  `schema.go` sibling from the start. `tokenanomaly/` (4 non-test files today)
  gains at most one file (lifecycle/state logic); stay ≤10 files/dir.
- **`max_findings` becomes a lie under sqlite** — operators who set it for the
  memory store will silently get an unbounded (until retention) table. Mitigate
  with the config-reference divergence note; do NOT fail loud on it (existing
  configs must keep booting).
- **`time.Time` zero vs NULL**: a `Finding` with zero `FirstSeen` must round-trip
  as 0 nanos and back to zero `time.Time` — the memory store compares
  `prev.FirstSeen.IsZero()`, so sqlite must store 0, not NULL, for `first_seen_ns`
  (NULL would make `MIN()` behave differently). `resolved_at_ns` is the only
  nullable column, and it is only ever written via `UpdateStatus`/`ResolveStale`.

---

## Decision 2: Triage lifecycle state machine with auto-resolution and retention

**Name:** `open → acknowledged → resolved`, auto-close on signal loss,
retention purge.

**Problem (verified):** `Finding` has no status field, `memory.mergeFinding`
only escalates severity and refreshes `LastSeen`, and `Detector.Analyze` is
add-only — a token that was revoked or went quiet keeps its row until capacity
eviction (permanent noise), and there is no way to record "handled".
`detectGeoVelocity`'s freshness gate (`o.last.Before(cutoff)` skip) proves
signal-absence is observable yet unused for closing rows.

### API surface

- `Finding` gains:
  - `Status` — bounded wire strings `open | acknowledged | resolved`
    (`const` values, metric-label discipline). Normalized on write AND on read
    (empty ⇒ `open`), so the wire always carries a valid enum; JSON field
    `status` (no omitempty — a normalized enum is always present).
  - `ResolvedAt time.Time` (`json:"resolved_at,omitempty"`) and
    `ResolvedReason string` (`json:"resolved_reason,omitempty"`). `ResolvedReason`
    is a bounded vocabulary (`signal_stale` from the sweep, free-text from an
    admin PATCH, capped length).
  - `FindingQuery.Status` filter (empty = all).
- `FindingStore` gains two methods (both backends):
  - `UpdateStatus(ctx, dedupKey string, status Status, reason string) error` —
    dumb executor: sets status/resolved fields, returns a new
    `ErrFindingNotFound` sentinel for a missing key. Transition validation
    lives in the domain handler, not the store (the store cannot know intent).
  - `ResolveStale(ctx, signalCutoff, retentionCutoff time.Time, reason string)
    (resolved, pruned int64, err error)` — one pass, two phases, single
    transaction on sqlite:
    1. `UPDATE … SET status='resolved', resolved_at_ns=?, resolved_reason=?
       WHERE status IN ('open','acknowledged') AND last_seen_ns < signalCutoff`
    2. `DELETE FROM … WHERE status='resolved' AND resolved_at_ns < retentionCutoff`
  - Retention cutoff semantics: `resolved_at < now - retention`; `retention <= 0`
    ⇒ phase 2 is a no-op (keep forever). `open` rows are never pruned by
    retention (acceptance contract).
- **Transition table (admin PATCH, domain-validated):**

  | From | open | acknowledged | resolved |
  |---|---|---|---|
  | open | — | ✓ | ✓ |
  | acknowledged | ✓ | — | ✓ |
  | resolved | ✗ (400, reopen requires re-detection) | ✗ (400) | — |

  Unknown status string → 400. Both rejections are `400 invalid_request` with a
  documented `error_description`. `resolved` is admin-terminal: the only reopen
  path is a detector re-detection (`Add` on a resolved row reopens to `open`,
  clears `ResolvedAt`/`ResolvedReason`; an `acknowledged` row stays
  `acknowledged` — the admin's acknowledgement is the only state a re-detection
  preserves).
- **Detector sweep becomes a lifecycle:** `Analyze` runs emit-first, resolve-
  second: (1) detect + `Add` all findings (refreshing `LastSeen` for live
  signals), (2) `ResolveStale(now - window, now - retention, "signal_stale")`.
  The ordering makes the "not re-detected this sweep" condition fall out for
  free: a finding re-detected this sweep has `LastSeen >= now-window` (both
  detectors only emit observations/buckets inside the window), so the bulk pass
  skips it; a finding whose signal went quiet has an old `LastSeen` and
  resolves. No emitted-key set needs to be threaded through. The detector gains
  a `WithRetention` option (zero/negative = never prune) fed from config;
  resolution counts are logged (`logger.Info`) and optionally exposed on the
  existing findings metric family — no auth decision ever reads this state.
- **Admin API:** `PATCH /api/v1/admin/tokens/suspicious/{key}` with body
  `{"status": "…", "reason": "…"}` (reason optional, capped). See Decision 3
  for the `{key}` encoding (the dedup key contains a NUL byte — not
  URL-path-safe raw). Gated `admin:write`; `GET` gains `status` filter.
- **Audit:** every admin transition records a new event type (classified in
  `platform/audit/auditreport/control_areas.go` in the same change — two gate
  tests enforce exactly-one-claim / no-unclaimed). Metadata via `audit.SetMeta`:
  dedup key, old status, new status, reason, actor. Auto-resolution by the
  sweep is logged/counted, not audited (it is a system action with
  sweep-interval-bounded cardinality; flooding the audit trail every 15 minutes
  for every stale row would violate the bounded-cardinality rule). Governance
  mutation only — never an auth decision, consistent with the detection-only
  contract.
- Config: `token_anomaly.retention` (`time.Duration`, default 30d, `<=0` =
  keep forever).

### Storage model

Three columns (`status`, `resolved_at_ns`, `resolved_reason`) already in the
Decision 1 baseline schema; the UPSERT's `CASE` expressions implement the
reopen rule atomically, so a re-detection racing an admin PATCH cannot clobber
triage state: the admin's `UpdateStatus` and the sweep's `Add` are both
single-statement, last-write-wins, and neither read-modify-writes. Memory
`mergeFinding` gains the same status/reopen rules (a resolved row reopens, an
acknowledged row stays), keeping both backends on the same state machine.
Memory keeps its FIFO cap (it remains a rolling operational view); sqlite is
bounded by retention instead. Conformance tests stay under the memory cap so
the divergence never surfaces in parity runs.

### Failure modes

- **`ResolveStale` store error:** fail-open, same as `Add` — the sweep logs and
  continues; the consequence is stale rows lingering (noise returns, no outage,
  no crash). Retention pruning failing is likewise fail-open; the table grows
  past retention until the next successful sweep.
- **Clock behavior:** resolution uses the detector clock; per AGENTS.md,
  production clocks slew but do not step backward. A forward step resolves rows
  up to `window` early (benign — they were near-stale anyway); a backward step
  delays resolution (benign). No step produces a security-relevant outcome
  because this state never gates anything.
- **Concurrent admin PATCH vs sweep reopen:** last-write-wins with the atomic
  statements above. A PATCH racing a prune can 404 on a row the admin just saw
  — benign, and the admin re-lists. A PATCH racing a reopen can land on an
  `open` row (reopen won) — the admin's transition still applies from `open`;
  no state is lost, only the ordering of two legitimate mutations.
- **Sweep disabled / subsystem off:** no sweeps → no auto-resolution and no
  pruning. `open` rows persist indefinitely (retention only ever touches
  `resolved` rows). Documented: retention is a sweep-driven lifecycle, not a
  background janitor; re-enabling the subsystem resumes both.

### What could break the design

- **The reopen rule is load-bearing for multi-replica.** With per-replica
  `Detector.obs`, replica A resolves a finding whose signal only replica B
  still sees; B's next sweep re-detects and reopens. Rows flap
  resolved→open at sweep-interval granularity and converge to `open` while ANY
  replica sees the signal, `resolved` when none do. Flapping is invisible to
  the audit trail (auto-resolution is not audited) and is the correct eventual
  state — but it must be documented, or operators will file bugs about rows
  "reopening themselves". The alternative (only resolve findings this replica
  previously emitted) is worse: it requires replicas to own rows, which breaks
  the shared-store model. This is the strongest argument for direction 1
  (shared observations) as follow-up work.
- **`resolved → acknowledged` rejection vs operational reality:** an admin who
  fat-fingers `resolved` cannot un-resolve without waiting for re-detection.
  This is per spec (reopen is re-detection-only) and is the right default —
  but the 400 `error_description` must say so explicitly, and the openapi.yaml
  transition matrix must be visible, or the endpoint reads as buggy.
- **Interface growth ripples:** `UpdateStatus`/`ResolveStale` on the interface
  force both stores AND the detector's test doubles to implement them.
  `Detector.Analyze`'s new resolve phase must not push the function over the
  50-line/complexity budgets — extract `resolveStalePass` as a separate method.
- **Retention-vs-cap interaction in memory:** with both FIFO cap and retention,
  a resolved row can be cap-evicted before retention ever sees it — fine, but
  the parity suite must not assert prune counts on the memory backend for
  datasets near the cap.
- **Audit classification gates:** `TestControlAreaDefs_NoEventTypeClaimedTwice`
  and `TestEveryKnownEventTypeIsClaimedOrExplicitlyUncategorized` fail hard on
  an unclassified new event type — the `auditreport/control_areas.go` edit is
  part of this change, not a follow-up.

---

## Decision 3: Cursor pagination and tenant dimension on the query surface

**Name:** tenant-scoped, cursor-paginated finding query surface.

**Problem (verified):** `HandleAdminSuspicious` supports only
`type`/`severity`/`limit`, `FindingQuery` has no tenant/cursor, and
`memory.List` is a full scan sorted in memory with `limit` applied last — once
Decision 1 makes the store durable, a single response is unbounded.
`metering.Event.TenantID` exists upstream but `recordObservation` drops it, so
every tenant's findings pool into one unpartitioned list — a governance and
privacy problem (tenant A subject IDs appear in an unfiltered admin read) and a
blocker for per-tenant detection-volume accounting.

### API surface

- `FindingQuery` gains `TenantID string` (exact match; empty = unbounded) and
  `Cursor string` (opaque continuation token). `Finding` gains
  `TenantID string` (`json:"tenant_id,omitempty"` — empty when unknown, the
  same omission semantics as `SubjectID`).
- `FindingStore.List` changes signature to
  `List(ctx, q FindingQuery) ([]Finding, nextCursor string, err error)` —
  keyset pagination over `(last_seen DESC, dedup_key ASC)`, the ordering the
  memory store already produces. `nextCursor` is empty when the page is
  exhausted.
- **Cursor encoding:** `base64url(JSON{"l": last_seen_unix_nanos,
  "k": dedup_key})` — a tiny fixed-field-order JSON payload. Rationale: the
  dedup key contains a NUL byte and may contain colons, so delimiter-joined
  encodings are ambiguous; JSON is unambiguous, deterministic, and cheap.
  Decoding is strict: malformed base64url, non-JSON, wrong field types, or a
  missing field → `400 invalid_request` with a documented `error_description`.
- **Keyset predicate** (both backends, matching memory's sort exactly):
  `last_seen < cursor.l OR (last_seen = cursor.l AND dedup_key > cursor.k)`,
  `ORDER BY last_seen DESC, dedup_key ASC LIMIT n+1`. The `n+1` fetch yields
  `has_more`. Equal `LastSeen` rows are tie-broken by `dedup_key`, so page
  boundaries are exact and no row straddles a boundary ambiguously.
- **Handler (`domains/tokenanomaly/admin.go`):**
  - `GET /api/v1/admin/tokens/suspicious` gains `tenant_id` and `cursor` params
    and a `status` filter (D2); response gains `next_cursor` (omitted when
    exhausted) and `has_more`; `total` becomes the **match count** for the
    filter (computed with the same predicates), not the page size — a
    deliberate, documented semantic change; the key stays present so existing
    consumers don't break structurally.
  - `limit`: absent/malformed ⇒ a bounded default page size (const
    `defaultPageSize = 100` in `consts.go`); values above a hard cap
    (`maxPageSize = 1000`) are clamped. The old "`<=0` = all" contract is gone
    — unbounded responses are the bug this decision fixes; documented in
    openapi.yaml.
  - `PATCH /api/v1/admin/tokens/suspicious/{key}` where `key` =
    `base64url(dedup_key)` (no padding). The NUL byte in `DedupKey()` is not
    path-safe, so the raw key is never a path segment. `GET` rows expose the
    raw `dedup_key` (new additive field) so clients can construct the PATCH
    path deterministically rather than reconstructing
    `type + "\x00" + (thumbprint|client_id)` themselves.
  - `404 finding_not_found` (new `Err*` sentinel, documented in
    `docs/error-codes.md`) for PATCH on an unknown key; 400s per the D2
    transition table.
- **Tenant semantics:** findings for a tenant are queryable only with that
  tenant's filter; empty-tenant findings (`rate_spike` with unknown tenant)
  are returned only when no `tenant_id` filter is set. The admin endpoint stays
  admin-scoped — `tenant_id` is a query dimension, not an authz boundary
  (`admin:read` gating unchanged), consistent with the existing per-tenant
  usage read API. `DedupKey` is unchanged: thumbprints are SHA-256 of globally
  unique jtis and client ids are globally unique, so dedup identity needs no
  tenant scoping — every row merely *records* its tenant.
- **Wiring:** no new `interfaces/sso` files (60-file ceiling — currently
  exactly 60 non-test files). The PATCH route registers in the existing
  `server_routes_admin.go` block; thin `Server` wrappers
  (`handleAdminTokenSuspiciousPatch`, accessor for `UpdateStatus`) go in the
  existing `sso.go`/`options_misc.go` files, following
  `handleAdminTokenSuspicious`'s shape.

### Storage model

- Columns `tenant_id` + indexes `(tenant_id, last_seen_ns DESC)` and
  `(last_seen_ns DESC)` are already in the D1 baseline; the keyset predicate
  plus filters is index-covered on sqlite (the `COUNT` for `total` uses the
  same index; on memory it is a scan, as today).
- Tenant capture: `observation` gains `tenantID`; `recordObservation` sets it
  from `ev.TenantID` (empty stays empty); `geoFinding`/`spikeForClient`
  populate `Finding.TenantID`. The observation table's eviction and merge
  behavior are unchanged.
- Memory `List` implements identical cursor semantics: filter → sort
  `(LastSeen desc, DedupKey asc)` → binary-search the cursor position →
  slice `n+1`. Both backends run the same conformance suite.
- **Conformance suite:** new package `domains/tokenanomaly/tokenanomalytest`
  with `ConformanceSuite(t, store)` (the `permissionstest.ConformanceSuite`
  precedent), covering D1 merge parity, D2 lifecycle, and D3 pagination/tenant
  composition. `memory` and `sqlite` tests both run it; no other `FindingStore`
  implementations exist to update (verified).

### Failure modes

- **Malformed/stale cursor:** malformed → 400 (strict decode). A cursor from a
  superseded snapshot (rows pruned by retention or resolved/updated between
  pages) never 500s: keyset continuation simply skips absent rows — the walk
  continues at the next key after `(l, k)`, no duplicates, no stuck loop.
- **Concurrent upserts mid-walk:** keyset has no offset drift, but a row whose
  `LastSeen` is refreshed to a *newer* value than the current cursor moves
  ahead of the walk and is skipped by THIS walk (it reappears at the front of
  the next walk — no permanent loss). The acceptance test's "no misses" claim
  therefore holds for rows stable during the walk, or for upserts that do not
  move a row past the cursor; the test must upsert concurrently with
  last_seen values *older than the walk's current position* to assert strict
  union, or must assert union across a re-walk. This is a documented keyset
  property, not a bug — the alternative (offset pagination) trades it for
  duplicate/missed rows under drift, which is worse.
- **Tenant data exposure:** the unfiltered admin read still sees all tenants —
  unchanged from today, by design (admin:read is the authz boundary). The
  filter gives SOCs scoping; it does not and must not be presented as a
  tenant-isolation boundary in docs (openapi/feature-matrix wording must be
  careful).
- **Store error during paginated read:** unchanged 500 path; a sqlite read
  failure mid-walk returns no partial page (single `QueryContext`).

### What could break the design

- **Interface signature change ripples** (`List` returns cursor): every caller
  and test double — `admin.go`, `sso.go` wrapper, memory store, detector tests,
  admin tests — changes in one commit. Grep for `FindingStore` implementers and
  `store.List(` callers before starting; the user's verification says memory is
  sole, but the detector's `Findings()` accessor and the two admin test files
  (`admin_test.go` ×2) all touch it.
- **Cursor/ordering parity between Go and SQLite:** the memory sort is
  `LastSeen desc, DedupKey asc` with Go byte-wise string comparison; sqlite is
  `last_seen_ns DESC, dedup_key ASC` with BINARY collation. These match (both
  byte-wise, nanos preserve `time.Time` ordering) but ONLY if times are stored
  as nanos and never truncated — a second-granularity storage would silently
  break page stability. The conformance suite's 250-row mixed-tenant walk is
  the guard; include rows with identical `LastSeen` (the tie-break is the
  subtle part).
- **`total` semantics change** (page size → match count) is observable drift
  for existing consumers even though the key stays. OpenAPI + changelog notes
  must call it out; the alternative (drop `total`) breaks consumers harder.
- **`limit` semantics change** (`<=0` = all → absent = default page): an
  existing client passing `limit=0` expecting "everything" now gets 100 rows.
  Additive-only this is not; document in openapi.yaml with the default and cap
  values.
- **PATCH key encoding friction:** requiring `base64url(dedup_key)` in the URL
  is an extra client step; exposing the raw `dedup_key` in GET rows makes it
  mechanical. Do not attempt to raw-encode the NUL (percent-encoding is legal
  per RFC 3986 but rejected by enough routers/proxies to be a support trap),
  and do not redefine `DedupKey()` itself — it is already a stored/ordered
  identity in both backends.
- **Budget drift:** the handler grows (cursor decode/validate, transition
  validation, default/clamp logic) — extract `parseCursor`/`validateTransition`
  helpers to keep `admin.go` functions under 50 lines / complexity 15; the
  package stays at ≤10 non-test files.

---

## Sequencing, contracts, and gates

One change, three coordinated parts; the conformance suite is written first and
is the definition of done for backend parity:

1. Interface + types: `Finding.Status/ResolvedAt/ResolvedReason/TenantID`,
   `FindingQuery.Status/TenantID/Cursor`, `List` signature, `UpdateStatus`,
   `ResolveStale`, `ErrFindingNotFound` (→ `docs/error-codes.md`).
2. `domains/tokenanomaly/tokenanomalytest` conformance suite (D1 merge parity +
   restart retention + two-detector convergence, D2 lifecycle + sweep + retention,
   D3 pagination + tenant + wire shape).
3. `memory` store updates (merge rules, lifecycle, cursor, tenant), then
   `domains/tokenanomaly/sqlite` (`schema.go` + `store.go`, migration v1,
   `New`/`NewWithDB`/`Close`/`Ping`/`DB`, `busy_timeout`/WAL pragmas).
4. Config (`backend`, `sqlite.dsn`, `retention`) + `BuildTokenAnomaly` switch +
   cmd shutdown wiring (closer after goroutine joins, readiness via `Ping`).
5. `Detector.Analyze` lifecycle pass (`WithRetention`, emit-then-resolve).
6. Admin handler + thin `Server` wrappers in existing `interfaces/sso` files;
   route registration in the existing admin routes file.
7. Contracts in the same change: `docs/openapi.yaml` (GET params/response,
   PATCH endpoint, transition matrix, cursor/limit semantics),
   `docs/config-reference.md` (`backend`/`sqlite.dsn`/`retention`, memory-only
   `max_findings`, multi-process sqlite deployment constraints, sweep-driven
   retention), `docs/feature-matrix.md`, `docs/error-codes.md`
   (`finding_not_found`, PATCH 400 descriptions), new audit event type claimed
   in `auditreport/control_areas.go`.

Gates: `go build ./... && go vet ./...` and
`go test -run 'TestMaintainability_|TestArchitecture_' .` after every `.go`
edit; `go test ./... -race`, `go test ./test/ -run TestE2E -v`, `make ci` at
handoff. The architecture gate needs no `layerName()` edit and no
`layerExemptions` entry (see header note).

**Explicitly out of scope** (owned elsewhere, must not creep in): shared
cross-replica observations (direction 1) — until it lands, geo-cardinality
dilution across replicas and the D2 resolution flap it causes are accepted,
documented behavior; any change to the detection-only contract (a finding never
feeds an auth decision); FIFO-eviction preservation on the durable backend
(dropped by design); per-tenant authz on the admin endpoint (query dimension
only).

---

# Distributed-systems review (role gate)

Advisory analysis for the design above, written from the assumption of
replicas, retries, partial failure, partitions, failover, and clock anomalies.
All grounding claims below were re-verified against executable code in this
revision (see the verification log at the end); design decisions themselves
are **Proposed** until implemented. No gate commands were run for this review
(read-only verification only).

## 1. State map

| Dimension | Value |
|---|---|
| **Owner** | Sweep (write): any replica's `Detector.Analyze`; triage (write): admin PATCH; reads: any replica's admin handler. No single owner — with sqlite the shared file IS the state, so ownership is "whoever writes last per row" (single-statement, last-write-wins). With memory, each process owns a private fragment |
| **Store** | `tokenanomaly.FindingStore`: memory (default, FIFO-capped 1024, insertion-order eviction) or new `domains/tokenanomaly/sqlite` (single table `token_anomaly_findings`, PK `dedup_key`, two last_seen indexes) |
| **Durability** | Memory: none (process-local, lost on restart). Sqlite: rows durable from sweep-commit onward. The detection pipeline itself (`Detector.obs`, the wrapped tokenusage buckets) is **ephemeral**: a crash loses up to one sweep interval of un-emitted findings and the observation state that would re-derive them. Recorder queue is drop-on-full, no retry (Verified: `metering.Recorder`, `token_anomaly.queue_size`) |
| **Consistency** | Per-row atomic UPSERT (single statement; no read-modify-write anywhere — `Add`/`UpdateStatus`/`ResolveStale` are each one statement/transaction). Cross-row: no transactions span rows except `ResolveStale`'s two phases (single tx on sqlite). Convergence between replicas is eventual at sweep granularity via the shared file |
| **Ordering** | Keyset `(last_seen DESC, dedup_key ASC)`; per-row `LastSeen` is monotonic (MAX merge). Memory sort and sqlite BINARY collation both byte-wise on the NUL-bearing key (Verified: `memory.List` tie-break `DedupKey() <`, sqlite TEXT BINARY default) |
| **Replication** | None in the store. Multi-replica = shared sqlite file; WAL + `busy_timeout` serialize writers. Detection inputs are per-replica (Verified: `Detector.obs` is a process-local map), so replicas converge only at the finding-row level, never at the observation level |
| **Failover** | Stateless replicas; any replica serves reads; a crashed replica's sweep state is rebuilt as its recorder drains new events. Readiness: `Ping(ctx) error` → `serverbuildsign.AppendReadyCheck` → `/readyz` (Verified pattern: `build_readiness.go` only registers stores exposing `Ping`) |

## 2. Findings

Sorted by severity. Severity is for the design as written (nothing ships yet),
not for live code.

### F1 — High: the design's own UPSERT SQL breaks merge parity for a zero-`FirstSeen` re-detection

- **Evidence (Verified):** Go `mergeFinding` (`domains/tokenanomaly/memory/store.go`):
  `if !prev.FirstSeen.IsZero() && (next.FirstSeen.IsZero() || prev.FirstSeen.Before(next.FirstSeen)) { merged.FirstSeen = prev.FirstSeen }` — when the *stored* row is non-zero and the *incoming* row is zero, Go keeps the stored value. The design's SQL is `CASE WHEN prev = 0 THEN excluded ELSE MIN(prev, excluded) END`, which yields **0** in exactly that case. The design's stated trap ("naive `MIN()` pins to epoch") describes only the prev=0 direction; the next=0 direction is a second, distinct trap.
- **Triggering failure:** any `Add` of a finding with zero `FirstSeen` onto a non-zero row (direct `Add` callers, tests, future emission paths). The current detector cannot produce zero `FirstSeen` (`recordObservation` falls back to `d.clock()`; `spikeForClient` uses `time.Unix`), so this is a latent parity/contract defect, not today's data path.
- **User impact:** if the parity suite inserts its zero-`FirstSeen` row *first* (both stores agree on the prev=0 branch), the divergence ships green; a later zero-second `Add` pins `first_seen` to epoch on sqlite while memory keeps the true value — byte parity, and with it the D3 page-stability story, silently breaks.
- **Recovery / corrective pattern:** symmetric CASE — add a `WHEN excluded.first_seen_ns = 0 THEN token_anomaly_findings.first_seen_ns` branch, and make the conformance suite script *both* orderings (`Add(nonzero)` then `Add(zero)`). The suite scenario list must say "zero-`FirstSeen` re-detection", matching the empty-tenant wording, not "a zero-`FirstSeen` row".

### F2 — Medium: no schema-version boot check in the sqlite package spec or cmd wiring

- **Evidence (Verified):** the peer pattern is richer than the design mirrors: `domains/threataction/sqlite/maxversions.go` exposes `ThreatPolicyMaxVersion()`, and every durable sqlite store in `cmd/` gets `serverbuildsign.CheckSQLiteSchema(b.schemaCtx, store, "<ns>", <Pkg>MaxVersion())` at boot (`build_app_oauth.go`, `build_app_security.go`, `build_app_selfservice.go`, `build_stores.go`, …), which calls `migrate.CheckSchema(ctx, db, namespace, binaryMax)` (`platform/migrate/migrate.go:357`). The design's `New/NewWithDB/Close/Ping/DB` list omits this.
- **Triggering failure:** a future migration v2 + binary rollback (the standard failed-deploy recovery): the older binary boots against the forward-migrated DB and writes rows into a schema it does not understand.
- **User impact:** silent misbehavior (500s or corrupt rows) instead of the loud boot failure every sibling store ships.
- **Corrective pattern:** add `TokenAnomalyMaxVersion()` (maxversions.go sibling) and a `CheckSQLiteSchema` call in the `BuildTokenAnomaly` wiring; note it in the sequencing list.

### F3 — Medium: PATCH retry semantics for the transition table's "—" cells are unspecified

- **Evidence:** the design's table marks same-state transitions (open→open, acknowledged→acknowledged, resolved→resolved) as "—" without a wire behavior; only `resolved`→{open,acknowledged} and unknown strings are specified (400).
- **Triggering failure:** an admin client times out after its PATCH commits and retransmits. If "—" cells are implemented as 400, the retry fails a transition that already succeeded — non-idempotent PATCH, the classic retry trap.
- **User impact:** spurious 400s on retry; operators learn to distrust the endpoint.
- **Corrective pattern:** same-state = `200` no-op (idempotent), other invalid transitions = 400 with the documented `error_description`. State this explicitly in the transition table and openapi.yaml. `404 finding_not_found` on a concurrent prune is already retry-safe (the retry 404s again — deterministic).

### F4 — Low: `detector.Findings()` cannot close the sqlite store

- **Evidence (Verified):** `Findings()` (`domains/tokenanomaly/detector.go`) returns the `tokenanomaly.FindingStore` interface, which has no `Close`. The design says the closer is "reachable via `detector.Findings()`".
- **Triggering failure:** implementation time — the cmd wiring cannot `Close` what the accessor returns.
- **Corrective pattern:** keep the concrete `*sqlite.FindingStore` in the `app` struct and close via the existing `closeAppStores` `io.Closer` type-assert (exact configaudit precedent, `main_shutdown.go:80`), or return an extended interface from a new accessor. Do not add `Close` to `FindingStore` (it would break the compile guard on the memory store and the detector's test doubles).

### F5 — Low: the emit-then-resolve ordering argument is false for `rate_spike` at the window boundary

- **Evidence (Verified):** `spikeForClient` sets `LastSeen = time.Unix(latest minute)`, and the tokenusage store's Query includes buckets with `minute >= floor(since)` (`domains/metering/memory/token_store.go:141`). So a spike whose last event sits in the boundary minute has `LastSeen < now - window` (minute truncation) and is resolved by `ResolveStale` **in the same sweep that re-detected it**. The design's invariant ("re-detected this sweep ⇒ LastSeen ≥ cutoff ⇒ skipped") holds only for geo findings, whose `LastSeen` is the exact sighting time.
- **Triggering failure / impact:** a spike that ended exactly at the window boundary resolves up to ~59 s early. A *continuing* spike always has a newer minute ≥ cutoff, so it never flaps — convergence is correct, the window edge truncates staleness judgment by at most one minute. Not audited, invisible.
- **Corrective pattern:** document the true invariant (minute-truncated `LastSeen` for `rate_spike`; boundary resolution may be up to one minute early), and pick the conformance suite's staleness clock so boundary-minute rows are covered deliberately.

### F6 — Info: "no lost upsert" holds only inside `busy_timeout`

- **Evidence:** the design's two-detector convergence claim assumes every upsert lands. Under WAL, a writer whose `busy_timeout` expires gets `SQLITE_BUSY`, which the fail-open sweep path skips and logs.
- **Impact:** bounded skip windows under sustained write contention (many replicas, slow shared storage) — convergence is eventual *modulo skip windows*, and rows skipped are re-detected on a later sweep only while the signal is still live. Recommend stating this and keeping `busy_timeout` a few seconds (single-row upserts are sub-ms; the design's choice is right).

## 3. Scenario table

| Scenario | Behavior | Outcome | Recovery |
|---|---|---|---|
| **Partition: replica cannot reach the shared sqlite file** (storage outage, not network) | Sweep `Add` errors → fail-open skip + log (`Analyze` collects firstErr; `RunTokenAnomalyDetection` logs and keeps ticking — Verified); admin reads 500; `Ping` fails → `/readyz` flips | No new findings for the outage window; no crash; no partial pages (single `QueryContext`) | File returns → next sweep re-detects live signals; findings whose signal aged out during the outage are lost (bounded, documented); retention backlog pruned on the first successful `ResolveStale` |
| **Partition: replicas split but both reach the file** (two sites, shared backend) | No quorum is involved — the file is the single source of truth; WAL + busy_timeout serialize writers | Both replicas keep writing; convergence unaffected; admin reads see all rows (read-after-write holds: readers see last committed WAL state) | None needed. The NFS-without-locking warning is the real partition hazard (F-corruption), not split-brain |
| **Crash: replica dies between detection and `Add`** | Findings computed in `Analyze` but not persisted; obs + buckets were process-local | Loss of up to one sweep interval of findings for the signals only that replica saw | Surviving replicas re-detect their own signals; dead replica's observations rebuild as its recorder drains new events. Acceptable for a detection-only surface; must be stated as the durability boundary |
| **Crash: replica dies after `Add`, before `ResolveStale`** | Rows persist; stale-resolution delayed one sweep | No data loss; stale rows linger one extra sweep | Next sweep's `ResolveStale` catches up |
| **Retry: two replicas sweep the same window** (duplicate delivery) | Idempotent UPSERT on `dedup_key`; per-row merge is a fold (earliest first, latest last, escalate-only) | No duplicate rows, no lost update; `Count`/`Geos`/`Detail` reflect the last writer, not a sum — recomputed cumulatively by the detector, so this is correct | None |
| **Retry: admin PATCH retransmitted after timeout** | Same-state transitions must be 200 no-ops (F3) | Idempotent; no spurious 400 | None |
| **Retry: recorder redelivers an event** | Not expected (drop-on-full, no retry); if it happens, observation `count` inflates | Finding `Count` marginally inflated; benign, fail-open telemetry | None |
| **Clock rollback (one replica steps back)** | Detection cutoff `now - window` shifts back → more observations qualify → extra findings; `ResolveStale`/retention delayed; rows with "future" `LastSeen` (written pre-rollback) sort first in pages | No auth impact (state never gates anything); cosmetic ordering; resolution lags until the clock recovers. AGENTS.md assumes slew, not backward steps — the design's stated assumption holds | None; converges when the clock returns |
| **Clock skew forward, > analysis window (replica A ahead by > 15 m)** | A's `ResolveStale` uses `A.now - window`; rows B just refreshed (`LastSeen = B.now`) fall below A's cutoff → A resolves them → B reopens next sweep | Continuous resolved↔open flapping at sweep cadence for as long as skew > window; invisible to audit, but operators see "self-reopening" rows | Bound the deployment assumption: cross-replica skew must stay well under `token_anomaly.window` (NTP). The design's flap documentation should state this bound explicitly |
| **Clock skew forward, < window** | Resolution up to `skew` early for near-stale rows | Benign, matches the design's stated behavior | None |
| **Stale cache** | No cache in this design — admin reads hit the store directly; no invalidation-bus dependency (the shared file needs no cross-replica invalidation, unlike Redis-backed stores). The only snapshot surface is WAL reader visibility (last committed) and the memory store's lock-protected read | No stale-read path | n/a |
| **Dependency outage: sqlite file unreadable during admin read** | `List` error → 500 `internal_error` (existing handler path); no partial page | Read fails whole; detection side unaffected (fail-open) | Restore file; readiness recovers via `Ping` |
| **Recovery sequencing after a multi-replica outage** | All replicas' sweeps resume on their own cadence; `ResolveStale` idempotent; rows resolved during the outage that are still live get reopened by any replica that re-detects (D2 load-bearing rule) | Converges to `open` iff any replica sees the signal, `resolved` iff none do | Documented flap; correct eventual state |

## 4. Stated guarantees, unsupported topologies, validation, residual risks

### Guarantees the design may claim (after F1–F4 are folded in)

1. **No duplicate rows** for a `DedupKey`, across replicas and sweeps (PK + single-statement `ON CONFLICT`; no read-modify-write anywhere).
2. **Per-row merge is a commutative-ish fold**: earliest `first_seen`, latest `last_seen`, severity escalate-only, freshest `count/geos/detail`, reopen-on-resolved, empty-tenant preservation — byte-identical across backends (the parity suite is the proof).
3. **Triage safety**: `resolved` is admin-terminal; only re-detection reopens; a re-detection never clobbers `acknowledged`; admin `UpdateStatus` and sweep `Add` are both single-statement last-write-wins, so no interleaving loses state.
4. **Retention safety**: only `resolved` rows are ever pruned; `open` rows survive forever; `retention <= 0` keeps resolved rows.
5. **Keyset pagination**: exact page boundaries (equal-`LastSeen` tie-break), no offset drift, stale cursors never 500; a row refreshed past the cursor is skipped this walk and found next walk (documented property, not a bug).
6. **Fail-open/fail-closed boundary preserved**: detection-side store errors skip + log and never kill the sweep or gate anything; boot-time config/schema errors fail loud; admin-side errors 500; readiness via `Ping`.
7. **Convergence**: with a shared sqlite file, replicas converge to the union of their findings at sweep granularity, with transient resolved→open flapping while any replica sees the signal.
8. **Read-after-write** for admin PATCH→GET across replicas (single file, WAL readers see last committed).

### Unsupported topologies / non-goals

- **Per-replica sqlite files** (each replica its own DSN): findings fragment exactly like memory today; no convergence. The shared-file contract must be documented on the config knob.
- **Network filesystems without real POSIX locking** (plain NFS): sqlite corruption — the design's foot-gun warning is mandatory, and it is the single most likely production failure this feature introduces.
- **Memory backend across processes**: process-local by construction; the admin API on replica A never sees replica B's findings (unchanged from today).
- **Sustained write contention beyond `busy_timeout`**: skip windows are accepted; "no lost upsert" is bounded, not absolute (F6).
- **Clock skew ≥ window**: continuous flapping (scenario table) — an operational bound, not a guarantee.
- **Tenant filter as an isolation boundary**: explicitly a query dimension under `admin:read`; docs must not imply otherwise.
- **The store as an audit log**: retention prunes resolved rows; bounded-cardinality rule keeps auto-resolution out of the audit trail by design.

### Validation tests (the conformance suite must cover, in addition to the design's list)

1. **F1's trap both directions**: `Add(nonzero)` then `Add(zero)` and the reverse; assert byte-identical `FirstSeen` on both backends.
2. **F5's boundary minute**: rate-spike row whose last event sits exactly at `floor(now - window)`; assert both backends resolve it on the same sweep and that a continuing spike never resolves.
3. **Tie-break rows**: multiple rows with identical `LastSeen` walking the cursor across pages; assert no row is skipped or duplicated and the walk is stable across a re-walk.
4. **Reopen-vs-acknowledged**: resolved row re-detected → open, `ResolvedAt`/`ResolvedReason` cleared; acknowledged row re-detected → stays acknowledged; both via `Add`, not `UpdateStatus`.
5. **Two-detector convergence** on one sqlite store (disjoint observations, disjoint and overlapping keys); assert union, no dups, and no lost upsert within `busy_timeout`.
6. **Mid-walk upsert honesty**: concurrent `Add` with `LastSeen` *older* than the walk's cursor position (strict union), or assert union across a re-walk — per the design's keyset note.
7. **PATCH idempotency**: same-state transition twice → both 200 no-op (F3).
8. **Restart durability**: sqlite store reopened → rows and statuses survive; memory store → empty (the accepted divergence).
9. **Retention**: resolved rows pruned after cutoff; open rows never pruned; `retention <= 0` no-op.
10. **Race**: `go test ./... -race` with concurrent `Add` + `List` + `UpdateStatus` + `ResolveStale` on both backends, `-count=10+`.

### Residual risks (accepted, documented, or requiring a follow-up)

- **NFS/multi-process sqlite corruption** — the top production risk; mitigated by documentation and `busy_timeout`/WAL, not by code.
- **Crash-loss window** of up to one sweep interval of findings plus the process-local observation state — inherent to the sweep architecture; the shared-observation follow-up (direction 1, out of scope) is the only structural fix, and the design already says so.
- **F1 shipping green** if the suite scripts the zero-`FirstSeen` row in the wrong order — closed by the corrected suite scenario.
- **Skew-vs-window flapping** — an operational bound; no code guard exists or is proposed.
- **`total` under concurrency** is a point-in-time match count, approximate under concurrent upserts; clients must not treat it as exact.
- **`limit`/`total` contract drift** (`<=0` = all → default page; page size → match count) is observable for existing consumers; openapi.yaml must call both out, as the design already commits to.

### Verification log (this review)

Read-only verification; no gates executed. **Verified:** sole `FindingStore` impl is `domains/tokenanomaly/memory/store.go` (grep for implementers); `mergeFinding` rules incl. the zero-`prev` guard; 1024 FIFO cap + insertion-order eviction; `List` filter→sort→limit order with `DedupKey()` tie-break; `FindingStore` = `Add`+`List` only, no `Close`; `Detector.obs` process-local; `Analyze` firstErr-collect + `processFindingSafe` recover; `RunTokenAnomalyDetection` log-and-continue + ctx-exit contract (`interfaces/sso/sso.go:411`); `Findings()` accessor; `HandleAdminSuspicious` params and `total = len(findings)`; `parseLimit` (≤0 = all); `BuildTokenAnomaly` hardcodes `tokenanomalymemory.NewFindingStore`; `TokenAnomalyConfig` has no backend/DSN fields; `BuildConfigAuditStore` backend switch + DSN-required + unknown-backend errors (same file, `build_governance.go:156-169`); `threataction/sqlite` `New/NewWithDB/Close/Ping/DB` + `migrate.Run(ctx, db, ns, migrations)` signature + `maxversions.go`; `migrate.CheckSchema` + per-store boot checks in cmd; `layerName()` first-segment rule (architecture_layer_test.go:49-56) — no edit or exemption needed, as the header correction states; `interfaces/sso` exactly 60 non-test files; auditreport `control_areas.go` + the two drift gates (`drift_test.go:82,95`); `audit.SetMeta` exists; `metering.Event.TenantID` exists and `recordObservation` drops it; tokenusage Query boundary `minute >= floor(since)`; shutdown ordering `shutdownSchedulers` (sweep cancel+done) → recorder drain → deferred `closeAppStores` io.Closer asserts; WAL/`busy_timeout`/`synchronous=NORMAL` precedent at `infrastructure/defaultimpl/sqlite/shareddb.go:48-50`; `AppendReadyCheck` registers only stores exposing `Ping(ctx)`. **Partial:** nothing material. **Missing/Unknown:** actual sqlite contention behavior under multi-replica load (no benchmark exists in-tree); operator NFS deployment practice (no in-tree evidence).
