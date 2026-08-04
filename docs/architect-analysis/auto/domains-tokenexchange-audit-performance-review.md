# Performance Review — Token-Exchange Audit Observability Design

**Revision reviewed:** `docs/auto/domains-tokenexchange-audit-design.md` + spec
against tree HEAD `64b08185`. Docs-only review; no files modified.

**Checks that actually ran this revision:** direct source verification of every
performance-relevant claim (file reads + greps): `internal/handler/tokengrant/
token_exchange.go`, `platform/audit/{recorder.go,memory_sink.go,async_sink.go,
handler_helpers.go,auditspi/query.go,sqlite/sink.go}`, `domains/tokenexchange/
{chainstore.go,sqlite/chain_store.go,memory/chain_store.go}`, `interfaces/admin/
lifecycle.go`, `cmd/sso-server/{config.yaml,build_app_core.go,serverbuildauthn/
build_audit_secrets.go}`, `docs/config-reference.md`. No Go gates run (nothing
to build); no benchmark exists anywhere in the touched packages (`grep -rn
"func Benchmark" platform/audit/ domains/tokenexchange/ internal/handler/
tokengrant/` = 0 hits), so every magnitude below is a **mechanism-based
estimate**, not a measurement, and is labeled as such.

## 1. Workload assumptions and evidence quality

**Verified facts that frame the review:**

| Fact | Evidence | Implication |
|---|---|---|
| Stock binary: `audit.enabled: true`, `backend: memory` (10k ring), `hash_chain: false`, `pii_redaction: false`, `audit.async` **absent from config → opt-in** | `cmd/sso-server/config.yaml` audit block; `composeAuditSinks` wraps async only `if cfg.Audit.Async.Enabled` (`build_app_core.go:255-268`) | In stock, audit `Record` runs **synchronously on the request goroutine**; cost = `EventFromRequest` + `Recorder.Record` (stamp + sink) |
| `WithTokenExchangePolicy` and `WithTokenExchangeChainStore` have **zero `cmd/` call sites** | greps (DB-architect F5, re-confirmed) | Deny events and chain-hop writes are SDK-embedder-only surfaces; stock footprint of the design = exactly +1 audit event per successful exchange |
| `audit.Query` exposes no `TokenID`/`SessionID`/`Reason` filter; SQLite indexes cover only `ts_unix_ns, type, actor_id, client_id, request_id, trace_id, tenant_id` — **no `token_id`/`session_id` index** | `platform/audit/auditspi/query.go:14-27`; `platform/audit/sqlite/sink.go` schema | The design's §3.2 join story ("jti → issued row via `token_id`") is executable only as offline SQL against an **unindexed** column of a **monotonic** table |
| Audit retention scheduler exists but defaults **off** (`retention.enabled: false`, `max_age: 720h`) | `config.yaml:290-293` | Audit table grows without bound under defaults; every unindexed lookup degrades O(N) over deployment lifetime |
| Chain store (`sqlite` + `memory`) has **no retention/eviction anywhere** | grep of `domains/tokenexchange/sqlite/chain_store.go`, `memory/chain_store.go` (DB-architect F3, re-confirmed) | Memory `hops`/`children` maps grow monotonically; long-lived single-replica SDK embedder eventually OOMs |
| Both SQLite sinks open **bare pools**: no WAL pragma application, no `MaxOpenConns(1)`; documented DSN `?_journal=WAL&_pragma=busy_timeout(5000)` — `_journal` is not a handled modernc parameter | `platform/audit/sqlite/sink.go:131-143`; `domains/tokenexchange/sqlite/chain_store.go:52-73`; `config.yaml:212` | The documented production configuration actually runs **DELETE-journal + synchronous=FULL**: every commit is an exclusive-lock, full-fsync write (DB-architect F2 — this review's H2 is the latency consequence of that fact) |
| `tokExRecordChainHop` runs synchronously **before** refresh/id_token issuance and before the response (`token_exchange.go:147`) | source | Chain write + new audit write both sit on the request critical path whenever wired |
| Rate limiter bounds `/token` (default 60 req/min/burst 60 per bucket, memory backend) | `config.yaml:709-718` | Deny-path event amplification is bounded by the limiter, not by the design |

**Workload assumptions (all **Unknown** — no in-tree evidence):** exchange QPS
and its share of total `/token` traffic; audit row rate; chain-table growth;
admin/SIEM query frequency; disk type (local SSD vs network FS) for the SQLite
sinks. No SLOs exist for any of these. The design itself contains no
performance requirement — acceptable for an audit-only change, which means the
**baseline must be designed, not assumed** (section 4).

## 2. Findings

| # | Sev | Path / symbol | Mechanism (predicted unless measured) | Impact | Recommendation | Experiment |
|---|---|---|---|---|---|---|
| H1 | **High** | `audit.Query` (`auditspi/query.go:14-27`), `sink.go` schema (no `token_id` index); design §3.2 join story | The design's acceptance story — resolve a suspicious bearer jti to the `token_exchange_issued` row via `token_id`, then to chain hops — has **no in-product API path** (no Query filter) and, done as offline SQL, is a **full table scan** on a monotonic table with retention **off by default** | Lookup cost grows linearly with table size; at 1M+ rows a single correlation lookup is seconds. This is the design's *core deliverable* (token↔session reverse lookup) made unscalable by construction | (a) In the same change, add `TokenID`/`SessionID` filters to `Query`+`buildWhere`+`parseQuery`+`MemorySink.Match` + **audit migration v4** `CREATE INDEX idx_audit_events_token_id`, `..._session_id` (2 extra index updates per INSERT, amortized by the existing `RecordBatch` path), **or** (b) declare the join offline-SQL-only and delete the "queryable without JSON scans" claim. Also fix the design's false "already indexed" wording (§1.2/§3.2) — `reason`'s bounded-cardinality argument works precisely because it is **not** indexed | `EXPLAIN QUERY PLAN SELECT ... WHERE token_id=?` + timing on a 1M-row audit DB (index scan vs full scan); HTTP `GET /api/v1/audit/events?token_id=<jti>` once filters exist |
| H2 | **High** (pre-existing — report per AGENTS.md §5, do not silently absorb) | `platform/audit/sqlite/sink.go:131` `New`, `domains/tokenexchange/sqlite/chain_store.go:52` `New`; documented DSN `config.yaml:212` | `_journal=WAL` is silently ignored by modernc.org/sqlite (only `_pragma` is handled); neither pool sets pragmas or `MaxOpenConns(1)`. Actual mode: DELETE journal + `synchronous=FULL` → **every commit = exclusive file lock + fsync** | Chain-hop write (one per exchange, **on the request hot path** when a store is wired) and each sync audit INSERT pay a full fsync; on network FS (the documented "cluster-shared" posture) this is ~ms-scale and `SQLITE_BUSY`-prone. The design doubles the row rate into the audit store and leans on "durable" for its core promise | Same change as the feature: apply `_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)&_pragma=busy_timeout(5000)` inside both `New` functions (single source of truth like `SharedDB`) + `SetMaxOpenConns(1)`; fix the documented DSN | `PRAGMA journal_mode` on a sink opened with the documented DSN (today: `delete`; after: `wal`); 2-process write hammer with `audit.backend=sqlite` → zero `SQLITE_BUSY` drops |
| M1 | **Medium** | `tokExRecordChainHop` (design §3.1); `RecordTokenIssued` at `token_exchange_stages.go:376` | The design doubles the exchange grant's success-path audit row rate (1→2 ordinary, 2→3 cross-tenant), each event = `EventFromRequest` (4 header reads + traceparent parse + 3-6 `SetMeta` map writes) + sink write. **Stock (memory ring):** ~µs, negligible vs. token signing. **`backend: sqlite` without `audit.async`:** +1 synchronous INSERT (7 index updates + PK + `metadata_json` marshal + fsync per H2) on the request path. **With async+batch:** bounded (1024 queue, drop-on-full, 64/batch tx — existing, works) | The design's §3.4 "one extra row — bounded" is a per-event bound, not a volume bound; the volume multiplier (2x) × exchange QPS (Unknown) is what hits the sink. Without async, this is the largest request-path delta the design introduces | Make the SIEM note state the row-rate multiplier and the async+batch requirement for `backend=sqlite` at any sustained exchange QPS; measure rather than assume (section 4, plan 2) | Micro-bench `EventFromRequest`+`Record`×2 vs ×1; load matrix (a)-(d) in section 4 |
| M2 | **Low** | `GetDescendants` (`sqlite/chain_store.go:185-210`): BFS, one `getChildren` query per visited node, up to `maxChainWalk`=1000 **before** truncating to `limit` | N+1 query pattern: a `limit=10` admin/SDK call can issue up to 1000 child queries. **No production caller today** (admin endpoint uses `GetChain` only, `lifecycle.go:119`) — SPI + the design's own acceptance tests only | Bounded today; becomes the dominant cost of the design's §2 acceptance story once the chain table is large. The design's §2.4 correctly leaves the walk untouched | No change now; record as a measurement item (section 5) and as a documented SPI cost — if a descendants admin surface is ever added, batch the child queries (one `WHERE parent_jti IN (...)`) | Benchmark `GetDescendants(limit=10)` on 10/100/1000-node tables; report query count per call |
| L1 | **Low** | Design §3.1: `RecordTokenExchangeIssued` computes `JTIFromJWTUnsafe(st.token.AccessToken)` while `RecordExchangeHopFailOpen` (same assembly point, `token_exchange.go:147`) parses the **same token** again | Duplicate base64 decode + JSON unmarshal of the just-minted JWT per exchange (~µs, 2 allocations) | Noise on a path dominated by signature verification — but free to remove: derive the jti once in `tokExRecordChainHop` and pass it to both helpers (also pins the "same jti" invariant structurally instead of by convention) | Fold the jti into the design's helper signatures | None needed; compiler-guarded by the signature change already planned |
| L2 | **Info** | `tokExEnforcePolicy` deny path + `RecordTokenExchangeDenied` | New synchronous audit write on an error path that previously wrote zero events; bounded by the `/token` rate limiter (default 60/min/bucket) | A credential-stuffing run at the limiter ceiling adds ≤ bucket-rate event INSERTs; with `backend=sqlite`+async this is invisible, with sync it adds fsync latency to denied requests | Document that `token_exchange_denied` volume is rate-limiter-bounded (design's §3.4 SIEM note); no code change | Deny-path load at limiter ceiling; assert audit row rate ≈ deny rate and p99 error-path latency flat |
| L3 | **Info** | Memory sink capacity 10k (default) + retention off | At 2 events/exchange, the stock ring holds the last ~5k exchanges | The design's "three stores, one identifier" join is only as durable as the sink: with defaults, correlation evidence evaporates after ~5k exchanges, and the ring's `Query` is a full 10k-slot sweep per lookup (no token_id filter, H1) | State in the design's SIEM note that the join's audit leg is bounded by sink capacity/retention, and that the chain store has **no** retention counterpart (asymmetric join degradation after `Prune`) | None |

**Verified strengths (no action):** the design adds **no index** to either
store (audit write amplification unchanged — `token_id`/`session_id`/`reason`
columns already exist; chain table gains 4 columns but no index); migration v2
is 4× `ADD COLUMN NOT NULL DEFAULT ''` (constant default → metadata-only in
SQLite, no table rewrite, no index rebuild, one-time at construction); the
space-join encoding is two `strings.Join` calls per exchange (negligible); the
`DenyReasoner` second `RLock` snapshot runs only on the deny path with
`MatchRule` O(rules) over operator-sized rule sets (negligible); the memory
ring insert under a single mutex is not a contention surface at any realistic
QPS; the async+batch machinery (queue 1024, drop-on-full with counters, batch
64/tx) already provides the correct backpressure model for the new events —
**the design introduces no new unbounded queue, no new goroutine, and no new
lock** on any path.

## 3. Critical-path table — `/token` exchange grant

Baseline: **none exists** (no benchmarks, no SLOs in-tree). Target: none
supplied — the acceptance rule is *regression* (delta within measurement noise
on the stock path), with the wired-surface costs documented as measurements.

| Step (in order, `token_exchange.go:130-160`) | Cost today (mechanism) | After design | Bottleneck | Profiling method |
|---|---|---|---|---|
| Token validation + signature | Dominant (crypto: EdDSA/RS256/PS256) | unchanged | CPU | `pprof` cpu |
| `tokExResolveActorAndAuthorize` incl. `Policy.Allow` | Small; nil-policy no-op in stock | `+MatchRule`/`DenyReason` only on deny path | CPU | `pprof` |
| Mint + sign | Dominant | unchanged | CPU | `pprof` |
| Chain hop write (`tokExRecordChainHop:147`; wired only) | 1 autocommit INSERT (7 cols) | 1 INSERT (11 cols) + 2× `strings.Join` | **fsync** (DELETE journal, `synchronous=FULL` — H2) | `trace`; `EXPLAIN`; disk iostat |
| Audit events | 1 (`token_issued`) | **2** (+`token_exchange_issued`); 3 cross-tenant | memory: ring mutex (~µs); sqlite-sync: INSERT+7 idx+fsync; async: channel send | micro-bench; `pprof` alloc |
| Refresh / id_token issue | Small | unchanged (note: chain+audit writes already happened — protocol F6 wrinkle, not perf) | — | — |
| Response JSON | Small | unchanged | — | — |

## 4. Prioritized benchmark/load plan

No baseline exists; every item below creates one. **Dataset/concurrency/
duration/acceptance** stated per item; regression comparison = run the same
suite pre- and post-change on the same machine/disk.

1. **Micro-benchmarks (new, in-tree, `go test -bench`)** — the cheapest
   baseline and the only numbers the change itself must ship:
   - `BenchmarkRecorderRecord` — `EventFromRequest` + `Record` → MemorySink
     (1 vs 2 events per exchange). Acceptance: the delta is published; stock
     per-exchange audit cost stays <1% of measured grant latency.
   - `BenchmarkAuditSinkRecord` vs `BenchmarkAuditSinkRecordBatch(64)` —
     SQLite sink, 10k rows. Acceptance: batch ≥10x single-INSERT throughput
     (validates the async+batch recommendation; decides whether M1 needs
     anything beyond documentation).
   - `BenchmarkChainStoreRecordHop` (7-col vs 11-col), `GetChain` (10-deep),
     `GetDescendants(limit=10)` on 10/100/1000-node tables (M2).
   - Dataset: 10k/1M-row audit table; 1k/100k-row chain table. Duration:
     `-benchtime=2s -count=5`.
2. **`token_id` lookup experiment (H1 decision gate)** — `EXPLAIN QUERY PLAN`
   + wall time for `WHERE token_id=?` on the 1M-row audit table, before any
   code: proves scan-vs-index cost. Acceptance: if lookup >100ms at 1M rows
   (expected: seconds), the design must adopt option (a) or (b) of H1.
3. **Load matrix (E2E, `test/` harness or external load tool)** — the
   exchange grant at ramp concurrency 1/10/50, 60s each, four configs:
   (a) stock defaults (memory sink), (b) `audit.backend=sqlite` +
   `audit.async.enabled` + `batch_size=64`, (c) sqlite **without** async,
   (d) (b) + chain store wired. Metrics: p50/p99 latency, audit drop counters
   (`sso_audit_async_*`), SQLite `busy` errors. Acceptance: (b) within noise
   of (a); (c) and (d) documented as measured, not as regressions to fix.
4. **Migration timing** — v1→v2 on a 1M-row chain table (expect metadata-only,
   ms-scale; verify the "no table rewrite" claim). Dataset: 1M rows with
   pre-existing v1 data. Acceptance: <1s, row count unchanged.
5. **Deny-path load (L2)** — policy-deny hammer at the `/token` rate-limiter
   ceiling, 60s. Acceptance: audit row rate ≈ deny rate (no amplification),
   error-path p99 flat, wire byte-identical.

## 5. Optimization risks and measurements still needed

**Optimization risks (what NOT to do):**
- Do **not** add caching of audit events or chain hops anywhere — append-only
  observability data, read at admin/SIEM rates; caches add invalidation
  complexity for zero benefit.
- Do **not** wrap the memory backend in `AsyncSink` to "improve" the stock
  path — the extra goroutine hop costs more than the ring insert saves
  (`async_sink.go` doc states this explicitly). The async wrap is an
  operator knob for slow inner sinks; the design correctly does not touch it.
- Do **not** add a `token_id` index (H1 option a) without the query workload
  that justifies it — +1 index update per INSERT on the audit sink's hot
  write path; the batch path amortizes it, but the decision must ride on the
  H1 experiment, not on the join story alone.
- Do **not** move emission after `tokExIssueIDToken` to fix the protocol-F6
  wrinkle without considering that the chain write already has the same
  semantic; moving audit after the fail-closed path would reorder audit vs
  wire causality the design explicitly preserves (§1.1 "audit before
  response").
- Space-join encoding, `MatchRule`, and the migration carry no measurable
  performance risk; no action.

**Measurements still needed (owner/operator inputs, in priority order):**
1. **Exchange QPS and share of `/token`** — the single most important unknown:
   it converts the design's per-event bounds (M1, L3) into volume and sink
   sizing. No evidence exists in-tree.
2. **Disk type / filesystem for the SQLite sinks** (local SSD vs NFS/EFS) —
   decides the actual fsync cost behind H2 and the chain-store hot-path
   write; also governs the DB-architect F4 "cluster-shared" safety claim.
3. **Audit table size trajectory with retention off** — the growth rate that
   H1's scan cost and L3's ring-eviction window both depend on.
4. **Chain-table growth + memory-backend lifetime** in long-running SDK
   embedders (no retention anywhere — DB-architect F3; the memory maps are
   the OOM risk, and `GetDescendants` cost grows with the table — M2).
5. **SIEM lookup pattern for the jti join** (per-request vs batch/offline) —
   determines whether H1 needs in-product Query filters at all, or whether
   the offline-SQL contract suffices.

**Bottom line.** The design's performance posture is sound: it adds no index,
no goroutine, no queue, no lock, and no unbounded buffer; every new write goes
through existing bounded machinery; the stock-binary hot-path delta is one
~µs event construction per exchange (negligible against signature
verification). Two things make it materially heavier than the design states:
the join story's unindexed, unfiltered `token_id` lookup on an unbounded table
(H1 — the design's own acceptance promise is O(N) by construction), and the
pre-existing no-WAL/no-fsync-control configuration of both SQLite sinks (H2),
which the design's doubled row rate now leans on. Neither blocks the
architecture, but both must land in the same change — H1 as an index+filter
or an explicit offline contract, H2 as a reported pre-existing defect with a
measured baseline. No benchmark exists for any of this today; section 4 is the
baseline that makes those two decisions evidence-based.
