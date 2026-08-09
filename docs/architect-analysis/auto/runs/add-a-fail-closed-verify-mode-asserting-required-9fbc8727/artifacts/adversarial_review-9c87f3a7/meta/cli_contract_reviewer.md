All fixes are in and the document is self-consistent. Final state of the review:

## Review verdict: 3 findings, all fixed in the design doc

I verified each contract claim against HEAD and empirically against `modernc`-irrelevant stdlib `flag`/`json` semantics (probe in `/tmp/flagsprobe`), plus the repo's own precedent.

### F1 — `-h`/`--help` → exit 0: FlagSet mode was unstated; only `ContinueOnError` is viable
The doc claimed exit 0 for help and exit 2 for parse errors without choosing the FlagSet mode. Determined:
- **`ExitOnError` is impossible in this design** — it calls `os.Exit` inside error handling, and §7's acceptance tests drive `runVerify`/`Run` in-process; every usage-error row (`--bogus`, `-expect audit=-1`) would kill the *test binary*, not fail a test.
- Required pattern (probe-confirmed): `flag.ContinueOnError` + `fs.Usage = usage` + `errors.Is(err, flag.ErrHelp) → 0`. The flag package prints the usage **once** on `-h`/`-help`/`--help` and returns `ErrHelp` — the handler must print nothing further (no double help, no `flag: help requested` wrap). `-help` (single dash) hits the same path.
- The tree precedent exists — `apiclient/check.go:123-125` is already "the deliberate first case" of help→0; verify is the *second instance* of an established convention, not a novel divergence. The doc now cites it.

### 2 — Set-time vs post-parse: two-stage validation pinned, with one stage-invariant
`flag.Var.Set` sees one value at a time, so duplicates and sorting *cannot* be Set-time; the split is now explicit:
- **Set-stage** (`parseExpectValue`): charset + `Atoi` + `min ≥ 1`; failures emerge via the flag package's wrapper — `invalid value "audit=0" for flag -expect: …` + usage — "names the offending value" for free (probe-confirmed).
- **Post-parse (`finalizeExpects`)**: duplicates, zero-count, sort; printed as `sso-ctl migrate: <reason>` + `usage()`.
- **Stage-invariant** (pinned by `TestVerify_UsageErrors` on every row): exit 2, usage block on stderr, stdout empty. Both stages also now emit the `sso-ctl migrate: <err>` wrap on parse failures, preserving byte-parity with the `status` grep surface; ErrHelp is the sole stage that omits it.

### 3 — Byte-determinism: one factual error fixed, tests now actually pin bytes
- The JSON paragraph claimed "`json.MarshalIndent` + `Enc.SetIndent` identical to `renderStatus`" — two *different* mechanisms, and `renderStatus` (migratecmd/main.go:106-108) *indents*, contradicting the doc's own compact example. Pinned: `json.NewEncoder(os.Stdout).Encode(&report)` without `SetIndent` — compact one line + one trailing `\n`, struct field order, never a map.
- The A6/A3 automation tests asserted only `json.Unmarshal` field presence — which proves nothing about byte-diffability. Now `TestVerify_JSON` does **golden-bytes equality**, and `TestVerify_SortedOrder` asserts repeat-invocation byte-identity.
- Fixed doc drift: the human-mode example `expected >=3` vs the format string `expected >= %d` (and added explicit newline-termination / no-trailing-whitespace statements).

### Residual caveats (documented, not bugs)
- Parse stops at the first failing flag, so *which* Set-time message surfaces is argv-order-dependent; §3.5 now scopes the CI promise correctly: per-invocation byte-stability, exit-code/stdout stability under reordering, stderr message precedence not guaranteed.
- `status` silently ignores extra positional args; `verify` refuses with exit 2 — recorded as a deliberate deviation.

**Edited**: `docs/architect-analysis/cmd-sso-ctl-migratecmd-verify-design.md` — §3.1 API table (`-h`/unknown/extra-args rows), report-shape section (examples + JSON mechanics), testing-seams table (`parseExpects` → `parseExpectValue`/`finalizeExpects`; `runVerify` int-return), Run-wiring comment, new §3.2 stderr-stage table, §3.5 determinism, and four §7 acceptance rows. No Go files touched; nothing to run in-tree.
