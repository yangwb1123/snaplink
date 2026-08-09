Done. Deliverable: `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-failure-pins.md` (216 lines, sole change — the pre-existing worktree modifications from other campaigns were left untouched).

## What the audit found

Every row of the §3.3 input table (9) and §4 failure-mode table (7) was mapped to a §7 test, with the named gaps first **re-probed empirically** against `modernc.org/sqlite v1.50.1` (the pinned version, go.mod:35) so the pins assert real driver behavior:

| Probe finding | Pin consequence |
|---|---|
| `chmod 0400` opens **read-only** (Ping nil) — only `0200`/`0000` yield `unable to open database file (14)` | write-permission pin uses `0200` + root guard; a naive `0400` test would silently pass |
| `BEGIN EXCLUSIVE` (mid-migration shape) → `database is locked (5)` at Ping, **even with `?mode=ro` and `busy_timeout`** | busy pin survives the documented live-DB form |
| Corrupt version table (text `version` row) → deterministic `MAX(version)` scan error; **empty** existing table → `(0, nil)` | corrupt → stderr `migrate(audit): read current version`, empty stdout, exit 1; empty → report `got 0`, exit 1 — the split pins the row's "after application" wording |
| Missing file + `?mode=ro`, missing dir → `unable to open (14)`; `:memory:`/`/dev/null`/zero-byte all reach floors identically | missing-file/dir pin, empty-DB table extension |

**Pins added (minimal set, 6 tests + 2 extensions):** N-E1 `TestVerify_FailClosed_EmptyDB` → `:memory:` + `/dev/null` + zero-byte; N-E2 `TestVerify_FailClosed_MissingFileDir` (both sub-cases); N-E3 `TestVerify_FailClosed_WritePermission`; N-E4 `TestVerify_FailClosed_CorruptVersionTable`; N-E5 `TestVerify_FailClosed_BusyDB`; N-E6 `TestVerify_JSON_DriverError` (Postgres DSN + busy, `--json`, stdout provably empty); N-E7 `TestVerify_ReadOnlyDSN` failure branch (`?mode=ro` + floor unmet → 1).

**Written justifications (3 rows):** §4 "deploy tree forgot bump" (undetectable by construction — enforcement is the absent-namespace predicate + R6, both pinned elsewhere); §4 "driver changes Ping error text" (fallback outcome identical to the N-E2/N-E3/N-E5/postgres pins — classification hit via garbage test, degradation via fallback set); §3.3 garbage row (already has its dedicated test + `TestVerify_ProbeFailure`).

**Stream/exit discipline:** every pin fixes all three channels (exact exit 0/1/2, stdout empty-or-report-fragment, stderr empty-or-mandated-prefix), streams mutually exclusive per row; stderr/stdout-empty assertions are specified as additions to the previously unasserted halves of the existing pass/fail/usage tests. §7 grows 16 → 21 named functions, all in `verify_test.go`; zero API/design-contract deltas.
