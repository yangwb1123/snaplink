All citations verified against the tree. The requirements specification is complete at `docs/architect-analysis/auto/cmd-sso-ctl-auditexport-postgres-from-url-requirements.md`.

## Verification summary

**Every cited symbol checked** — 9 of 10 citations confirmed exactly:

| Citation | Verdict |
|---|---|
| `auditexport/main.go:26-27` planned `--from-url`; `:186` hardcoded `auditsqlite.OpenReadOnly(o.dsn)` | Verified |
| `auditexport.go:64-70` QueryPager, `:123` BuildExportBundle (doc at 65-66 explicitly anticipates a remote HTTP adapter) | Verified |
| `postgres/audit_sink.go:189/207/234/252` — Record/RecordBatch/Prune/LastHash, no Query in that file | Verified (file-level) |
| `sqlite/query.go:75`, `memory_sink.go:67` Query | Verified |
| `auditverify/main.go:104,143-144,394-403` — bearer flag, required-bearer misuse (exit 2), readFromURL pager; httptest-tested at main_test.go:95-160 | Verified |
| `build_audit_secrets.go:34-59` memory\|sqlite\|postgres stock switch; `build_app_core.go:203,385` wiring + `WithHashChain` | Verified |
| `log_endpoints.go:24-25` advertised `/api/v1/audit/events`; route at `server_routes_admin.go:71`, admin middleware 401, OpenAPI `bearerAuth`/`admin:read` | Verified (new) |

**One substantive error in the source analysis, documented in §1.3:** the claim that the QueryPager seam is "NOT satisfiable by the postgres backend" is **refuted** — `infrastructure/postgres/audit_query.go:79-108` implements `Query` with identical newest-first/Limit/Offset semantics, and the compile-time assertion `_ audit.Sink = (*AuditSink)(nil)` (audit_sink.go:280, `go build ./...` exit 0) proves it since `auditspi.Sink` requires `Query`. The real gap is CLI wiring only: no postgres `--dsn` (plus the postgres constructors migrate, requiring a non-migrating opener) and no `--from-url`. Effort drops accordingly; the spec reframes the work as wiring + a port of the proven pager as a `QueryPager` adapter.

**Acceptance preserved and made testable** — the two supplied checks map to A1-A5 → REQ-1..REQ-6 with given/when/then criteria: postgres e2e (HeadHash == `LastHash` ChainTip, `--verify` 0, byte-tamper 1) under the `SSO_TEST_POSTGRES_DSN` skip convention; never-404 sweep and no/weak-bearer → 401 asserted against the existing admin middleware, with CLI-side `--bearer` misuse exit 2 mirroring `auditverify/main.go:143-144`.

**Scope kept tight**: no server changes, no `auditexport.go`/sinks/chainer modifications, no auditverify changes (sibling direction), no aggregation/relay work (unselected directions 2-3); coordination with the sibling `cmd-sso-ctl-audit-dsn-requirements.md` REQ-5 opener is specified to avoid two divergent constructors.
