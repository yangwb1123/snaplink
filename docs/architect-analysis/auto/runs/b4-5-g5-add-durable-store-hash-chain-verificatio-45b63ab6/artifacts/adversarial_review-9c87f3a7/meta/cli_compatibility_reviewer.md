Review complete. Written to `docs/architect-analysis/auto/runs/b4-5-g5-add-durable-store-hash-chain-verificatio-45b63ab6/artifacts/adversarial_review-9c87f3a7/meta/cli_contract_reviewer.md`. Every claim re-verified against the tree; no `.go` edits.

## Verdict: compatible with two rejections and three gaps

**Safe as designed (no silent change):**
- **`--dsn` triple** — new flag, exit-2 misuse preserved (`usageErr`, `main.go:73-79`); `auditexport.dispatch` is the in-repo mode-router precedent. Keep today's laxity (`--bearer` with `--from-file` is silently ignored today — `--page-size`/`--timeout-sec`/`--bearer` with `--dsn` must be too).
- **Exit 3 in `audit-verify --dsn` only** — new mode, no existing users; ladder 0/1/2/3 is coherent, no `os.Exit(3)` precedent in `cmd/`.
- **L1 line** — hard-branch required; `TestRun_VerifyHappyPath` only asserts `Contains("chain verified")` today, so the byte-identical pin needs exact-match tightening. L1 must come from the same-snapshot `Facets` count, stdout, after clean verify only.
- **`audit-export --type token_issued` + EventCount** — works **today** (`EventTokenIssued = "token_issued"`, `event_types.go:15`); zero code/bundle change, pure doc pin. Caveats: Type filter ⇒ `Contiguous=false` ⇒ integrity-only verify; parity holds only on a quiescent store (separate snapshots per run).

**Two silent behavior changes to reject:**
1. **Changing the global `--limit` default to 0** — file mode would stop truncating at 10k (whole-file memory), URL mode would page to exhaustion (unbounded HTTP/runtime), and count lines change on every >10k run. Required choice: keep the FlagSet default at 10000, detect explicit `--limit` via `fs.Visit` (new pattern, flag it), and give `--dsn` mode 0 = whole chain (matches audit-export's existing "0 = all matching" vocabulary). A reached cap → exit 3 with a distinct "limit reached" message, never `chain verified`.
2. **Extending exit 3 to `audit-export`** — its store-open error is pinned to exit 1 by `TestRun_OpenErrorExitsOne` (`main_test.go:137-142`) and the package doc; changing it breaks existing `audit-export --dsn` scripts. Keep 0/1/2 and document the asymmetry.

**Three gaps:**
1. **FM-5 pg sniffing is underspecified** — only URL-form DSNs (`postgres://`) would be caught; a libpq keyword DSN (`host=... dbname=...`) falls through to `file:` normalization and — given modernc's READWRITE|CREATE open — **creates an empty file named after the DSN in the CWD** before failing: a write from the read-only tool. Reject both shapes (plus `cockroach://`) before any open; pin both in the test.
2. **Docscheck constraint on error-codes.md** — `TestErrorCodesDocumented` scans only `Code`-headed tables and demands matching `Err<Name>` constants; the exit-code table must be `Exit`-headed or prose, else the gate fails.
3. **The prefix false-pass exists in file/URL mode today** (10k default truncation verifies cleanly, count visible in the verdict line). The design correctly leaves it (byte-identical pin) but must say so in the help text.

**§5.6 obligations (same change):** no new `Err*` (existing chain errors reused), no endpoint (`openapi.yaml` N/A), no config knob (`config-reference.md` N/A). Required: exit-code section in `docs/error-codes.md` (`Exit`-headed), L1/`--dsn`/single-writer-assumption in `docs/observability.md` Audit section (`:76`), README example (`:249`), and the executable docs — `auditverify` package doc ("1 on a break / error" becomes mode-dependent), `usage()` banner, `--limit` help string, and the `?mode=ro` plain-path drift in auditexport's help (delta 4 makes it internal).
