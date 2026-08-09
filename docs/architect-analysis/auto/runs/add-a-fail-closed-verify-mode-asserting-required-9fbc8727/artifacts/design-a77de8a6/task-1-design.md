Design written to `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-design.md`. Summary:

## Evidence verification (all 12 claims re-checked)

**Confirmed** (with line drift): status-only dispatch/Run at 41; empty-DB green at 116–117; `Status` `nil,nil` non-SQLite (302); audit ns = `"audit"` v1–v3 (file is `platform/audit/sqlite/sink.go`, not `audit/...`); sso-ctl registration at 53, banner at 99; `CurrentVersion` exported/0-for-absent/read-only; `seedDB` pattern; devops_engineer.md gap quote.

**Refuted — two claims materially affect the design:**

1. **"Zero auditgovernance refs in cmd/" is false** — `cmd/snaplink-audit-provisioner`, `cmd/snaplink-billing`, `cmd/sso-ctl/auditexport` all import it. The *functional* half holds (no sso-server wiring, no governance namespace).
2. **A2's garbage-file model is wrong empirically** (I ran probe programs against `modernc.org/sqlite`): a garbage file fails at **`Ping`** (`file is not a database (26)`), *never* at the probe; `/dev/null` and zero-byte files open as valid empty DBs; Postgres-shaped DSNs fail Ping generically; `?mode=ro` on existing DBs works.
3. **"9 namespaces" is not an inventory** — defaultimpl/sqlite also migrates users, sessions, refresh_tokens, revocations, ip_failure_counter, recent_login, device_codes (+ saml/auditoutbox). Immaterial: verify stays declarative.
4. **`status -h`/`--bogus`/missing-DSN all exit 1 today** (empirically), so verify's "usage → exit 2" is a deliberate new contract, not a shared one.

## Design highlights

- **API**: `sso-ctl migrate verify --dsn <dsn> --expect ns=min [--expect …] [--json]`; repeatable `flag.Var`; charset `^[a-z][a-z0-9_]*$` duplicated from `versionTable` with cross-reference; floors via `migrate.CurrentVersion` (`pass iff actual >= min`); exit 0/1/2 taxonomy with a documented divergence table; `--json` emits the report on stdout even on failure.
- **Non-SQLite diagnosis**: Ping-error classification (`file is not a database` prefix → `not a SQLite database: …`), plus the spec'd `sqlite_master` probe as insurance; everything else fails closed with the generic `open:` message — tests pin outcomes, not internal stages.
- **Compat**: `status` byte-compatible (zero test edits, A5), `platform/migrate` untouched, no new dirs (16/16 ceiling), no deps, no OpenAPI/config/error-code changes; only banner + usage text change.
- **Failure modes**: full input→exit/output table (garbage, empty, `/dev/null`, missing, Postgres URI, ro live DB, mid-migration, typos); fail-closed invariant stated.
- **Migration steps**: 5-step implementation order with gate commands; deployment is binary-only (no schema migration); B4-5 bump rule (`--expect` raised per namespace growth, new namespace absence → 1) wired to the T-9 predicate.
- **Acceptance mapping**: A1–A6 → 16 concrete test functions in `verify_test.go` with seeds mirroring `seedDB`, including the two empirically-driven pins (garbage-file at Ping, `status -h` legacy quirk).
