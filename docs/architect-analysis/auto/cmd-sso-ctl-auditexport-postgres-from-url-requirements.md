# Requirements: postgres `--dsn` + `--from-url` export paths for offline-verifiable audit evidence (cmd/sso-ctl/auditexport)

Requirements specification for the selected direction "Add a postgres / `--from-url`
export path so B4-5's 'memory→sqlite/postgres + hash_chain' evidence chain is
offline-verifiable for every stock backend" (analysis
`docs/architect-analysis/auto/analyses/cmd-sso-ctl-auditexport-037d2986.json`,
direction 1). Doc-only artifact; no `.go` edits, so no build gates are triggered
by this file.

Module: `cmd/sso-ctl/auditexport` (composition layer; dispatch entry
`"audit-export": auditexport.Run`, `cmd/sso-ctl/main.go:49`). Every citation in
the source analysis was re-checked against the working tree; the supplied
acceptance is preserved in section 3 and made testable. One substantive error in
the source analysis was found and is called out in §1.7: **the postgres backend
already implements `Query`** — the missing piece is CLI wiring, not a pager.

## 1. Verification outcome — citations checked against the repository

### 1.1 `cmd/sso-ctl/auditexport/main.go:26,186` — planned `--from-url`; sqlite-only open

**Verified.** The package doc states at main.go:26-27: "v1 supports the direct
`--dsn` mode only; a `--from-url` mode against the live `/api/v1/audit/events`
API is a planned follow-up." `run()` hardcodes the sqlite open at main.go:186:
`sink, err := auditsqlite.OpenReadOnly(o.dsn)` — the only store import in the
file is `auditsqlite "github.com/yangwb1123/snaplink/platform/audit/sqlite"`
(main.go:68). `dispatch` (main.go:128-143) has exactly two modes: `--verify
<bundle>` or `--dsn`; no URL flag, no backend/dialect flag exists. The read-only
discipline is documented at main.go:16-21 ("The export is strictly READ-ONLY:
the store is opened via auditsqlite.OpenReadOnly, which NEVER migrates the
schema") and re-stated at main.go:182-184. `--dsn` help text (main.go:145) says
"SQLite DSN to export from (required for export; opened read-only, append
?mode=ro for a live DB)". File is 442 lines (under the 500-line budget).

### 1.2 `platform/audit/auditexport/auditexport.go:64-70,123` — QueryPager seam, BuildExportBundle

**Verified.** The `QueryPager` interface is at auditexport.go:68-70:

```go
type QueryPager interface {
	Query(ctx context.Context, q audit.Query) ([]*audit.Event, error)
}
```

with the doc at 65-66 explicitly anticipating a remote adapter: "Every audit
sink (MemorySink, sqlite.Sink) satisfies it structurally, and a remote
HTTP-backed adapter can implement just this one method." `BuildExportBundle`
(auditexport.go:123) pages through `pageAll` (auditexport.go:173-197) honoring
`q.Offset`/`q.Limit`, and reverses newest-first pages into chain order
(`reverse(collected)`, line 195). A postgres or HTTP source therefore needs
**zero changes in the export core**.

### 1.3 `infrastructure/postgres/audit_sink.go:189,207,234,252` — "no Query" (file-level) and its refutation

**File-level claim verified, conclusion refuted.** `audit_sink.go` itself
implements only `Record` (189), `RecordBatch` (207), `Prune` (234), `LastHash`
(252), plus `Close`/`DB`/`Ping` (129/139/142) — no `Query` in that file. The
analysis's conclusion "the QueryPager seam … is NOT satisfiable by the postgres
backend" is **false**: `infrastructure/postgres/audit_query.go:79-108` implements

```go
func (s *AuditSink) Query(ctx context.Context, q audit.Query) ([]*audit.Event, error)
```

with the same semantics as the sqlite peer — `buildAuditWhere` (audit_query.go:46-74,
identical filter mapping), `ORDER BY ts_unix_ns DESC` newest-first, `LIMIT
q.NormalizedLimit()` + `OFFSET q.Offset` (lines 85-88) — exactly what `pageAll`
needs. The compile-time assertion `_ audit.Sink = (*AuditSink)(nil)`
(audit_sink.go:280) proves it: `audit.Sink` aliases `auditspi.Sink`
(`platform/audit/aliases_spi.go:17-24`), which **requires** `Query`
(`platform/audit/auditspi/sink.go:14-19`). `go build ./...` exits 0 on the
current tree. **Correction:** the work is not "port a postgres pager"; it is
wire the existing `*postgres.AuditSink` (which already satisfies `QueryPager`
structurally) into the CLI, plus the `--from-url` mode.

### 1.4 `platform/audit/sqlite/query.go:75`; `platform/audit/memory_sink.go:67` — QueryPager satisfied by the sqlite/memory sinks

**Verified.** `platform/audit/sqlite/query.go:75` — `func (s *Sink) Query(ctx
context.Context, q audit.Query) ([]*audit.Event, error)`, newest-first with
Limit/Offset (lines 82-85). `platform/audit/memory_sink.go:67` — `func (m
*MemorySink) Query(...)`. Both satisfy `auditexport.QueryPager`.

### 1.5 `cmd/sso-ctl/auditverify/main.go:104,144,394-403` — proven `--from-url` pager + bearer enforcement

**Verified.** Line 104 binds `--bearer` ("admin bearer token for the
/api/v1/audit/events API (required with --from-url)"); lines 143-144 enforce it
in `loadEvents`: `if o.bearer == "" { usageErr("--bearer is required with
--from-url") }` — CLI misuse, exit 2. `readFromURL` (doc at 394-402, func at
403-444) pages `/api/v1/audit/events` newest-first with `limit`/`offset`, stops
on a short page or the `--limit` cap (with a probe page for exact fills), and
reverses into chain order (`reverseEvents`, 482-487). `fetchEventPage`
(450-477) sets `Authorization: Bearer <token>` + `Accept: application/json`,
checks `2xx`, and errors with the offset on failure. `parseEventList` (378-392)
accepts both a raw JSON array and the `{"events":[...]}` envelope. The pager is
tested via `httptest` in `cmd/sso-ctl/auditverify/main_test.go:95-160`
(multi-page newest-first, 401 on wrong bearer, `--limit` cap). `pageSize` caps at
`audit.MaxQueryLimit` = 1000 (`auditspi/query.go:15`).

### 1.6 `cmd/sso-server/serverbuildauthn/build_audit_secrets.go:37-65` — stock backend wiring

**Verified.** `BuildPrimaryAuditSink` (build_audit_secrets.go:34-59) switches
`audit.backend` over `""|memory` (36), `sqlite` (39-46), `postgres` (49-57,
`postgresbackend.NewAuditSinkWithDB(pg, dialect)`), and rejects anything else
("audit.backend must be one of memory|sqlite|postgres"). Stock wiring:
`cmd/sso-server/build_app_core.go:203` calls it; the hash chain is enabled by
`cfg.Audit.HashChain` via `audit.WithHashChain()` (build_app_core.go:385).
Postgres is a first-class stock backend; the campaign gate
(`docs/campaigns/implementation-gate.md:15`) requires "stock audit.backend
memory→sqlite/postgres + hash_chain".

### 1.7 New finding — the endpoint the URL mode needs is advertised and admin-gated

- `cmd/sso-server/log_endpoints.go:23-25`: when `cfg.Audit.Enabled &&
  cfg.Audit.APIEnabled`, the banner advertises `PathAPIPrefix + PathAuditEvents`
  (= `/api/v1/audit/events`, `shared/core/consts.go:36`, `interfaces/sso/aliases.go:371`)
  and `/api/v1/audit/events/{id}`. Exact cited lines 24-25.
- The route is mounted at `interfaces/sso/server_routes_admin.go:71`
  (`api.GET(PathAuditEvents, s.handleAuditEvents)`, handler at
  server_discovery.go:381 → `audit.HandleEvents`) on the `PathAPIPrefix` group
  wrapped in `core.NewGatedRouter(..., s.adminAPIGateOn)` (server_routes_admin.go:49)
  — gated by the live `feature_gates.admin_api` (`server_routes.go:222`).
- Credential enforcement is the admin middleware (`interfaces/admin/middleware.go:108`
  `NewMiddleware`; `admin:read` for GET via `defaultMethodScopes`); the OpenAPI
  contract documents the endpoint at `docs/openapi.yaml:4391` with
  `security: bearerAuth` and "the admin middleware enforces `admin:read`".
  So on a stock server with audit + admin APIs on: no bearer → 401 (not 404),
  valid `admin:read` bearer → 200. The 404 case only occurs when the admin gate
  is off, which also removes the route from the advertised banner — the T-2
  sweep invariant (advertised endpoints never 404) already holds and is asserted,
  not changed, by this direction.
- Query-param vocabulary for the HTTP pager: `platform/audit/handlers.go:15-26`
  (`type`, `outcome`, `actor_id`, `client_id`, `tenant_id`, `provider`,
  `request_id`, `trace_id`, `since`, `until`, `limit`, `offset`); `parseQuery`
  (handlers.go:145-186) accepts RFC3339 or unix seconds for `since`/`until`.
  The audit-export filter flags already mirror these names (bindFlags, main.go:144-167).

### 1.8 New finding — postgres open migrates; a read-only open must not reuse `NewAuditSink*`

`NewAuditSink` (audit_sink.go:107-110) "opens cfg.DSN, **migrates the schema**";
`NewAuditSinkWithDB` (121-128) runs `Run(ctx, db, "audit", auditMigrations,
dialect)` — DDL (`CREATE TABLE IF NOT EXISTS`, `ALTER TABLE ... ADD COLUMN IF
NOT EXISTS`). `Run` is `infrastructure/postgres/migrate.go:75`; the version
table for the audit namespace is `schema_migrations_audit` (migrate.go:35-39);
`CurrentVersion` (migrate.go:198) reads it with plain SELECTs. The sqlite peer
solves this with `OpenReadOnly` (platform/audit/sqlite/sink.go:156-169) which
runs **no** migrations and fails closed on a schema-version mismatch via
`checkSchemaCurrent` (sink.go:191-198). A postgres export path needs the
postgres equivalent: `postgres.Open` (pool.go:53 — dial + pool sizing + ping,
no DDL) + schema-version check + the existing `*AuditSink` (whose `Query`/`Get`
are SELECT-only, audit_query.go:27,79).

### 1.9 Coordination — sibling requirements doc

`docs/architect-analysis/auto/cmd-sso-ctl-audit-dsn-requirements.md` (sibling
direction, audit-verify `--dsn` + aggregation) already specifies the same
postgres non-migrating opener (its REQ-5) and a shared reader home
(`cmd/sso-ctl/auditstore`), and its REQ-3 covers `audit-export --dsn <postgres>`
as a consumer. This direction is the `auditexport`-owned leg of the same
evidence surface. To avoid divergence, REQ-1 below depends on that shared
opener when it has landed and defines the identical contract if it has not
(see REQ-5 in the sibling doc; the two specs must not ship two openers with
different semantics).

## 2. Core invariants

1. **Read-only, never-migrate export discipline preserved.** The tool's
   documented contract (main.go:16-21, 182-184) extends to every new source: a
   postgres `--dsn` uses a non-migrating opener with a fail-closed
   schema-version check (sqlite: existing `OpenReadOnly`); `--from-url` issues
   GETs only. A schema whose version does not match the binary is reported,
   never migrated, never guessed.
2. **One export core, three sources.** sqlite, postgres, and HTTP all satisfy
   `auditexport.QueryPager` (auditexport.go:68-70); `BuildExportBundle` /
   `pageAll` (auditexport.go:123, 173-197) are unchanged. The HTTP adapter
   returns **one newest-first page per `Query` call** and does NOT reverse —
   `pageAll` already reverses; pre-reversing would break pagination.
3. **Newest-first everywhere.** Both sinks and the API return newest-first with
   identical filter/`Limit`/`Offset` semantics (`sqlite/query.go:75`,
   `postgres/audit_query.go:79`, `platform/audit/handlers.go:145-186`); the
   pager drives offsets and lets `pageAll` do the rest.
4. **Bearer discipline, CLI and server.** `--from-url` without `--bearer` is
   exit-2 misuse (mirroring auditverify/main.go:143-144); the server already
   returns 401 for missing/weak bearers on `/api/v1/audit/events` (admin
   middleware, `admin:read`). This direction asserts both, changes neither.
5. **Exit-code contract unchanged** (main.go doc, line 40): 0 wrote/verified
   a clean bundle (including an empty window), 1 load/verify/store/HTTP error
   (incl. tamper), 2 CLI misuse.
6. **T-9 byte-identity regression.** Existing sqlite `--dsn` and `--verify`
   behavior is byte-identical when the new flags are absent; the full existing
   `cmd/sso-ctl/auditexport/main_test.go` suite (TestRun_* / TestRunVerify_*,
   45-1070) passes unmodified.
7. **Bundle semantics are source-independent.** `Contiguous`, `BoundaryPrevHash`,
   `HeadHash`, `--anchor` enforcement, and offline `--verify` behave identically
   for all sources; a URL export over a pure time-window is contiguous and
   chain-verifiable exactly like a DSN export.

## 3. Requirements

Acceptance (supplied, preserved verbatim):

> **A — postgres leg:** ssotest e2e: stock server with `audit.backend=postgres`
> issues a token; `sso-ctl audit-export` over the postgres pager yields a bundle
> whose `HeadHash` equals the store chain head and `--verify` exits 0;
> byte-tamper exits 1.
>
> **B — `--from-url` leg:** `GET /api/v1/audit/events` advertised in
> `log_endpoints.go:24-25` must never 404 (T-2 sweep style); no/weak bearer →
> 401 (T-9 credential-enforcement style, mirroring `auditverify/main.go:144`).

| # | Acceptance sentence | Requirement(s) |
|---|---|---|
| A1 | stock postgres-backed server issues a token; export over the postgres pager yields a bundle | REQ-1, REQ-3, REQ-4 |
| A2 | bundle `HeadHash` equals the store chain head | REQ-1, REQ-4 (criterion 1) |
| A3 | `--verify` exits 0 on the exported bundle; byte-tamper exits 1 | REQ-4 (criteria 2-3); existing `--verify` path unchanged |
| B1 | advertised `/api/v1/audit/events` never 404 (T-2 sweep style) | REQ-4 (criterion 4) |
| B2 | no/weak bearer → 401 (server), mirroring `auditverify/main.go:144` (CLI: `--from-url` without `--bearer` → exit 2) | REQ-2, REQ-4 (criterion 5) |

### REQ-1 — Non-migrating postgres read-only opener (shared contract)

The postgres `Query` already exists (audit_query.go:79) and satisfies
`QueryPager`; the opener is the only missing store-side piece.

- New exported constructor in `infrastructure/postgres` (root module, allowed):
  wraps `postgres.Open` (pool.go:53 — dial/pool/ping only), runs **no**
  migration (`Run`, migrate.go:75, is NOT invoked), performs the fail-closed
  schema-version check against `schema_migrations_audit` via
  `migrate.CurrentVersion` (migrate.go:198) vs the binary's expected audit
  migration version, and returns the existing `*AuditSink` (`Query`/`Get` are
  SELECT-only, audit_query.go:27,79).
- Doc comment states the never-migrate contract and the read-only-role
  recommendation (no `?mode=ro` equivalent exists for postgres), mirroring
  `OpenReadOnly`'s contract comment (platform/audit/sqlite/sink.go:156-169).
- **Coordination:** if the sibling direction's REQ-5
  (`cmd-sso-ctl-audit-dsn-requirements.md`) has landed, reuse that constructor
  and its shared reader (`cmd/sso-ctl/auditstore`) verbatim; this direction adds
  no duplicate opener. If it has not landed, this direction creates it with the
  contract above and the sibling reuses it. Either way exactly one opener
  exists.
- Failure modes: open error and schema-version mismatch are exit-1 diagnostics
  naming the store (mirror sqlite's `checkSchemaCurrent` wording, sink.go:198);
  no DDL is ever executed.

Testable criteria:

1. Given `SSO_TEST_POSTGRES_DSN` (repo skip convention,
   infrastructure/postgres/postgres_test.go:13-19) and a store at the current
   schema version, when the opener runs, then it returns a `QueryPager` whose
   `Query` pages newest-first with `Limit`/`Offset` identical to the live store
   rows.
2. Given a store whose `schema_migrations_audit` version is behind the binary,
   then the opener fails with a found-vs-expected version diagnostic and zero
   DDL executed (asserted via a `CREATE TABLE`-free trace or a read-only role).
3. Without `SSO_TEST_POSTGRES_DSN`, the opener's integration tests skip; all
   non-DB tests (classifier, misuse) run everywhere.

### REQ-2 — `sso-ctl audit-export --from-url <base> --bearer <token>` (HTTP source)

The mode documented as "planned follow-up" at main.go:26-27. The HTTP reader is
a `QueryPager` adapter over the proven pager shape in auditverify
(main.go:394-477, tested at main_test.go:95-160) — one page per `Query` call so
`BuildExportBundle`'s `pageAll` drives offsets, limits, and the final reversal
unchanged.

- **Flags** (new): `--from-url <base URL>`; `--bearer <admin token>` (required
  with `--from-url`; missing → exit 2 + usage, mirroring
  auditverify/main.go:143-144); `--timeout-sec` (default 30, HTTP client
  timeout, mirroring auditverify/main.go:107).
- **Exclusivity.** Exactly one of `--dsn | --from-url | --verify` per run;
  pairwise combinations are exit-2 misuse with the existing
  `usageErrorf`/`dispatch` style (main.go:128-143, 440).
- **Adapter semantics.** `Query(ctx, q)` performs
  `GET {base}/api/v1/audit/events?limit=<q.Limit>&offset=<q.Offset>` plus the
  populated filter params mapped from `q` — `type`, `outcome`, `actor_id`,
  `client_id`, `tenant_id`, `provider`, `request_id`, `trace_id`, `since`,
  `until` (RFC3339 UTC) — matching the API vocabulary
  (platform/audit/handlers.go:15-26, 145-186). `q.Limit` is always
  `exportPageSize` (= `audit.MaxQueryLimit` = 1000, auditexport.go:50,
  auditspi/query.go:15) when driven by `pageAll`, so the adapter forwards it
  verbatim; `q.Offset` advances per page. Headers: `Authorization: Bearer
  <token>`, `Accept: application/json`. Non-2xx → error naming the offset
  (port `fetchEventPage`'s diagnostic, auditverify/main.go:468-476). Body parse
  accepts a raw JSON array or the `{"events":[...]}` envelope (port
  `parseEventList`, auditverify/main.go:378-392). Adapter does NOT reverse.
- **Client lifecycle.** One `http.Client{Timeout: timeoutSec}` per run, closed
  via the existing `sink.Close()` defer path (add a `Closer` alongside the
  pager).
- **Bundle semantics.** Unchanged: empty window → exit 0 with genesis boundary
  anchor; attribute filters → `Contiguous == false`; `--anchor` loads and
  signature-checks before the source opens (fail-fast ordering preserved,
  main.go:182-184); `--limit` caps via `q.Limit` through `pageAll` (the API's
  `limit` param is the page size, the CLI's `--limit` is the total cap — no
  conflict).

Testable criteria:

1. Given an httptest server serving `/api/v1/audit/events` newest-first with
   `offset`/`limit` paging (shape of auditverify/main_test.go:95-160), when
   `Run(["--from-url", base, "--bearer", "t", "--out", bundle])` executes, then
   exit is 0, the bundle's `EventCount` equals the served event count,
   `Contiguous` is true, `BoundaryPrevHash` is the oldest event's `PrevHash`,
   and `Run(["--verify", bundle])` exits 0.
2. Given the same server with 7 events paged at 3/page, then the adapter issues
   offset 0, 3, 6 (+ probe only when the CLI `--limit` exactly fills) and the
   bundle contains all 7 in chain order.
3. Given a server that 401s without the exact bearer (or any non-2xx), then
   exit is 1 and stderr names the failing offset.
4. Given `--from-url` without `--bearer`, `--from-url` with `--dsn`, or
   `--from-url` with `--verify`, then exit is 2 with a misuse diagnostic.
5. Given an empty event window (server returns 0 events), then exit is 0 with an
   empty bundle and the existing summary line (contract at main.go:40).

### REQ-3 — `sso-ctl audit-export --dsn <postgres-dsn>` (store source, postgres)

`run()`'s hardcoded `auditsqlite.OpenReadOnly(o.dsn)` (main.go:186) routes
through a classifier so postgres DSNs reach the REQ-1 opener; the export core
is untouched.

- **Classifier.** A DSN is postgres iff it begins `postgres://` or
  `postgresql://` (case-insensitive); otherwise it is a sqlite DSN (path or
  `file:` URI). Postgres connection strings always carry a scheme in this repo
  (`postgres.Open` consumers, importcmd examples); sqlite DSNs never do —
  total, unambiguous, no second state flag. (Shared with the sibling direction's
  classifier when it lands.)
- **Open ordering unchanged:** `buildQuery` → `warnUnknownType` → `--anchor`
  load + signature check → source open → `BuildExportBundle` → `enforceAnchorHead`
  → write (run(), main.go:169-202). Only the open call branches on the classifier.
- **`--dsn` help text** gains the postgres case ("postgres:// or
  postgresql:// DSNs supported; opened read-only, never migrated; use a
  read-only role — there is no ?mode=ro equivalent for postgres").
- **Package doc** updated: the "planned follow-up" sentence (main.go:26-27)
  becomes the shipped `--from-url` usage line, and the usage banner gains the
  new flags (usage(), main.go:395-410).

Testable criteria:

1. Given the existing sqlite export tests (main_test.go:45-1070), then all pass
   unmodified (T-9; sqlite path byte-identical, `TestRun_ExportModeROSucceeds`
   and `TestRun_ExportDoesNotModifyStore` still prove read-only/no-mutation).
2. Given `SSO_TEST_POSTGRES_DSN` and a store written by the stock postgres
   backend with a hash chain, when `Run(["--dsn", dsn, "--out", bundle])`
   executes, then exit is 0 and `Run(["--verify", bundle])` exits 0; the bundle
   `HeadHash` equals `LastHash` over the same store (`ChainTip`,
   audit_sink.go:252-268).
3. Given a postgres DSN with one flipped `hash` row, then `--dsn` export exits 1
   (BuildExportBundle's fail-closed self-verify, auditexport.go:141-142) and no
   bundle file is left behind.
4. Given a `postgresql://`-prefixed DSN (or a schema-version-mismatched store),
   then the classifier routes to the postgres opener and the mismatch is exit 1
   with the version diagnostic; sqlite DSNs never reach the postgres opener.

### REQ-4 — e2e acceptance (ssotest)

Both legs live in `test/` (package `ssotest`), on the existing in-process
harness patterns (test/e2e_test.go boots a full server via `sso.NewServer` +
`httptest`; test/audit_handler_test.go:26-46 shows the audit-API harness shape;
test/admin_* tests show the admin-gated surface with an admin bearer).

- **Postgres leg (A1-A3), `SSO_TEST_POSTGRES_DSN`-gated** (skip convention,
  postgres_test.go:13-19). Stock-shaped server: `sso.NewServer(sso.WithAuditRecorder(rec),
  sso.WithAuditAPI(), ...)` where `rec` is `audit.New(postgres sink,
  audit.WithHashChain())` — the same shape as `BuildPrimaryAuditSink`
  (build_audit_secrets.go:34-59) + `build_app_core.go:385`. The server issues a
  token through a real issuance path (client-credentials or password grant,
  per the e2e harness), emitting `token_issued` events into the chained
  postgres store. Then, in-process: `auditexport.Run(["--dsn", dsn, "--out",
  bundle])` → exit 0, bundle `HeadHash` == postgres sink `LastHash`; `--verify`
  → exit 0; byte-tamper (flip one event's `reason`/`hash` in the bundle JSON) →
  `--verify` exit 1 with `bundle FAILED verification` on stderr.
- **URL leg (B1-B2), no DB required.** Boot the stock-shaped server with the
  audit API enabled and a hash-chained sink; `Run(["--from-url", base,
  "--bearer", tok, "--out", bundle])` over the real HTTP wire; `--verify` exits
  0. Assert the exported rows equal the sink's rows in chain order.
- **T-2 sweep (B1).** On the audit-API-enabled server, `GET
  /api/v1/audit/events` — the exact path advertised at log_endpoints.go:24-25 —
  returns 401 (no bearer) and never 404; with a valid `admin:read` bearer it
  returns 200. (The 404-only-when-gate-off behavior is asserted as: the banner's
  advertised set is exactly the served set under the same config flags —
  audit enabled + API enabled + admin gate on.)
- **T-9 credential enforcement (B2).** Server: no bearer → 401; garbage/weak
  bearer → 401. CLI: `--from-url` without `--bearer` → exit 2 + usage
  (mirroring auditverify/main.go:143-144). Both asserted in the same e2e.

Testable criteria:

1. A1: given `SSO_TEST_POSTGRES_DSN` and the stock-shaped postgres server that
   issued ≥ 1 token, `Run(["--dsn", dsn, "--out", b])` exits 0 and
   `bundle.HeadHash == sink.LastHash(ctx)`.
2. A2: `Run(["--verify", b])` exits 0.
3. A3: after flipping one event's `hash` in `b`, `Run(["--verify", b])` exits 1
   with `bundle FAILED verification` on stderr.
4. B1: on the audit+admin-enabled server, `GET /api/v1/audit/events` is 401
   without bearer (never 404); 200 with a valid `admin:read` bearer.
5. B2: garbage bearer → 401; `--from-url` without `--bearer` → exit 2.

### REQ-5 — Regression and contract updates

- T-9: every existing flag and output line of audit-export (`--dsn` sqlite,
  `--verify`, filters, `--anchor`, exit codes, stderr summaries, stdout purity)
  is unchanged when the new flags are absent; the existing main_test.go suite
  passes unmodified.
- Usage banner and `--dsn`/`--from-url`/`--bearer`/`--timeout-sec` help updated;
  package doc (main.go:1-38) reflects the shipped `--from-url` mode.
- No `docs/openapi.yaml`, `docs/error-codes.md`, or `docs/config-reference.md`
  changes: CLI-only surfaces, no new server endpoints, errors, or config keys.
  The B4-5 evidence chain itself (backend selection, hash chain) is untouched.

Testable criterion:

1. Given the full pre-change `cmd/sso-ctl/auditexport` test suite, then all
   tests pass with the new code in place.

### REQ-6 — Unit tests beside the code

- `url_pager_test.go`: httptest-driven adapter tests ported from
  auditverify/main_test.go:95-160 — multi-page newest-first with offset
  progression, `--limit` cap + probe page, 401/404/non-2xx diagnostics naming
  the offset, both body shapes (array and envelope), filter-param forwarding
  (assert the querystring carries `type`/`since`/`until`/…), and
  no-reversal (pageAll owns reversal).
- Misuse table: `--from-url` without `--bearer`, `--from-url`+`--dsn`,
  `--from-url`+`--verify` → exit 2.
- Classifier table: `postgres://…`, `postgresql://…` (case-insensitive),
  `/path/store.db`, `file:…?mode=ro`.
- Postgres opener tests under `SSO_TEST_POSTGRES_DSN` (REQ-1 criteria);
  sqlite cases run everywhere.

## 4. Budgets and design constraints (checked before editing)

- `cmd/sso-ctl/auditexport/main.go` is 442 lines. The delta — 3 flags, dispatch
  exclusivity, classifier routing in `run()`, usage/doc text — must stay under
  58 net lines; if it would cross 500, move the opener routing into the new
  adapter file (main.go then holds flags + dispatch only).
- New functions ≤ 50 lines, complexity ≤ 15, `if` nesting ≤ 3 (the adapter
  mirrors `fetchEventPage`'s shape, auditverify/main.go:450-477, ~28 lines).
- `platform/audit/auditexport/auditexport.go` (252 lines) is NOT modified: the
  seam (auditexport.go:65-66) already documents the remote-adapter case.
- `interfaces/sso` is at its 60-file ceiling and is NOT touched; no server
  route, middleware, or auth change (the 401/never-404 acceptance asserts
  existing behavior).
- `infrastructure/postgres` is a root-module package; one additive file
  (`audit_readonly.go`) is allowed. No `layerExemptions` entry; `cmd/` and
  `infrastructure/` are already classified.
- Import flow: `cmd/sso-ctl/auditexport` → `platform/audit/auditexport` +
  `platform/audit` + `infrastructure/postgres`; no upward imports, no
  `protocols/*` involvement.
- File/directory ceilings re-checked before editing per AGENTS.md budgets.

## 5. Files

### Create

```text
cmd/sso-ctl/auditexport/url_pager.go          — HTTP QueryPager adapter: one newest-first page per
                                                Query call, bearer header, filter-param mapping,
                                                {events:[...]}/array parse, non-2xx diagnostics;
                                                Closer for the http.Client
cmd/sso-ctl/auditexport/url_pager_test.go     — REQ-2 + REQ-6 criteria (httptest; no live DB)
infrastructure/postgres/audit_readonly.go     — REQ-1 opener: postgres.Open + schema-version
                                                fail-closed check + *AuditSink; NO Run(); doc comment
                                                mirrors sqlite OpenReadOnly (created only if the
                                                sibling direction's REQ-5 opener has not landed)
infrastructure/postgres/audit_readonly_test.go — REQ-1 criteria under SSO_TEST_POSTGRES_DSN
test/auditexport_evidence_test.go             — REQ-4 e2e: postgres leg (SSO_TEST_POSTGRES_DSN-
                                                gated), URL leg, T-2 sweep, T-9 bearer assertions
```

### Modify

```text
cmd/sso-ctl/auditexport/main.go — --from-url/--bearer/--timeout-sec flags; dispatch exclusivity
                                 (exactly one of --dsn|--from-url|--verify); classifier routing in
                                 run(); usage banner; --dsn help postgres case; package doc
                                 (planned follow-up → shipped). Keep ≤ 500 lines.
```

### Do not modify

```text
platform/audit/auditexport/auditexport.go — QueryPager/BuildExportBundle/pageAll, reused as-is
platform/audit/sqlite/*                   — OpenReadOnly/Query, reused as-is
infrastructure/postgres/audit_sink.go     — Record/RecordBatch/Prune/LastHash, untouched
infrastructure/postgres/audit_query.go    — Query/Facets already exist (audit_query.go:79); untouched
cmd/sso-ctl/auditverify/*                 — sibling direction; readFromURL is ported, not moved
interfaces/sso/*, cmd/sso-server/*        — no server-side changes
docs/openapi.yaml, docs/error-codes.md, docs/config-reference.md — CLI-only surface
```

Confirm file/function/directory/fan-out ceilings before implementation (per
AGENTS.md budgets: 500-line files, 50-line functions, complexity 15, if-nesting
3, non-test files/dir 10, subdirs 15).

## 6. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/auditexport/... -race
go test ./platform/audit/... ./infrastructure/postgres/ -race
SSO_TEST_POSTGRES_DSN=postgres://user@localhost:5432/sso_test?sslmode=disable \
  go test ./cmd/sso-ctl/... ./infrastructure/postgres/ ./test/ -run 'AuditExport|ReadOnly|Evidence' -v
go test ./test/ -run TestE2E -v
make ci
```

Targeted tests beside the code: REQ-1 criteria 1-3 (postgres opener,
`SSO_TEST_POSTGRES_DSN`, skips otherwise per repo convention
postgres_test.go:13-19); REQ-2 criteria 1-5 (httptest pager + misuse, no DB);
REQ-3 criteria 1-4 (sqlite T-9 regression + postgres bundle verify + flipped
hash); REQ-4 criteria 1-5 (e2e: token issuance, HeadHash == LastHash, --verify
0, tamper 1, never-404, bearer 401s); REQ-5 criterion 1 (full existing
auditexport suite unchanged).

## 7. Explicit non-goals (scope guard)

- No server-side changes: no new endpoints, no `interfaces/sso` edits, no
  auth/middleware changes (the 401 and never-404 acceptance asserts existing
  behavior), no discovery/config/OpenAPI changes.
- No changes to `auditverify` (`--dsn`, `--from-url`, `--checkpoint` there are
  the sibling direction's surface).
- No aggregation / `audit-agg` / `auth.token.issue` vocabulary work (analysis
  direction 3 — not selected), no relay/outbox/governance connector (analysis
  direction 2 — not selected).
- No changes to `platform/audit/auditexport/auditexport.go`, `chainer.go`,
  recorder, or the sqlite/postgres sinks; no migration tooling (a
  version-mismatched store is reported, exit 1, never migrated).
- No postgres-side read-only enforcement code (operators use a read-only role;
  documented in the usage banner, matching the sibling REQ-5 contract).
