All checks complete. Here is the review report.

---

# Review: Run refactor, exit-decision equivalence, B4-5 follow-up

**Scope note:** The "Run refactor" is the proposed N-2 change in the design (`cmd/sso-ctl/auditexport/main.go`); the worktree has zero `cmd/sso-ctl` edits — design stage is doc-only, as claimed. The authoritative deliverable is the full design at `runs/validate-type-outcome-against-the-registered-eve-4a69096f/artifacts/design-a77de8a6/` (the `e1aed759` dir is a condensed report of the same verification; pipeline.yaml points at `4a69096f`).

## 1. Run refactor vs external consumers — no regression

Complete caller census of `auditexport.Run`:

| Caller | Impact |
|---|---|
| `cmd/sso-ctl/main.go:48` (`subcommands` map → `main.go:72 os.Exit(run(args))`) | Signature `Run(args []string) int` unchanged; return codes flow through unchanged |
| `cmd/sso-ctl/soc2report/pipeline_test.go:36` — `auditexport.Run(["--dsn", dsn, "--out", bundlePath])`, asserts exit 0 | Invocation has no `--type`/`--outcome` → `validateOutcome("")`=nil, `warnUnknownType("")`=no-op → exit 0, bundle written. `captureQuiet` discards both streams; only the code is asserted. **Green** (verified: `go test ./cmd/sso-ctl/soc2report/`) |

No other Go consumers anywhere: nothing outside `cmd/sso-ctl` imports the subcommand packages (checked `test/`, nested modules `cmd/sso-mcp`/`cmd/sso-operator`, examples); no scripts reference `audit-export` (only generated static HTML docs); `cmd/sso-ctl/auditexport` exports only `Run`. `dispatch_test.go` covers only the subcommands map — unaffected. The refactor touches no other subcommand, and the `main.go:24-27` package doc ("or a direct os.Exit from a flag/usage error") stays accurate — `flag.ExitOnError` parse errors still exit 2 directly, unchanged.

## 2. Observational equivalence of the exit-decision refactor — holds, with one ambiguity

`main.go:72` is confirmed `os.Exit(run(args))`. I built the current binary and captured baselines; the refactored design matches them class-by-class:

| Path | Today (verified) | Refactored | Equivalent |
|---|---|---|---|
| Usage error (`--dsn` missing / mutually exclusive) | `usageErr` (284-288): msg + banner, exit 2 | `dispatch` → `(2, err)`; `Run` prints msg + banner, returns 2 | ✅ exit code and stderr identical — message strings in the design's `dispatch` match today's `usageErr` format strings verbatim |
| Runtime error | `errorf` (291-294): msg, exit 1, no banner | `(1, err)` → msg, return 1, no banner | ✅ identical |
| Success | 0 | 0 | ✅ identical |
| `flag.ExitOnError` parse error | exit 2 | unchanged | ✅ |

AC-1's in-process test is now satisfiable: `--outcome bogus` parses as a plain string value (no `flag.ExitOnError`), so `dispatch` returns `(2, err)` before any store open — no `os.Exit` inside `Run`.

**Defect (must fix in the design):** the `Run` snippet prints `fmt.Fprintf(os.Stderr, "%s: %v\n", progName, err)` while the text defines `usageErrorf` as "`fmt.Errorf(progName+": "+format, ...)`-shaped". If both apply, usage-error output becomes `sso-ctl audit-export: sso-ctl audit-export: --dsn ...` — **not** observationally identical to today. The prefix must be applied exactly once (recommend: `usageErrorf` without prefix, matching the snippet; or `Run` prints `%v` verbatim). Exit codes are unaffected either way.

**Minor corner (document it):** `validateOutcome` precedes the mutually-exclusive check, so `--verify a --dsn b --outcome bogus` now yields the outcome diagnostic instead of "mutually exclusive" — same exit 2 + banner, different message text for a double-misuse corner. Deliberate per design ("validation precedes every mode branch") but missing from the §6 failure-mode table.

## 3. B4-5 conditional follow-up — zero CLI change, no contract drift ✅

The follow-up (design §7.3, AC-3 conditional) is: register `auth.token.issue` in `auditspi` + extend `TestRun_TokenTypeFilterExportsAndVerifies` with the new constant.

- **Zero CLI change:** the warning path is a runtime `auditspi.KnownEventTypes` map lookup (R-3); the CLI consults, never hardcodes. Registration is a library-data addition plus a test-file edit — no flag, help text, exit code, or CLI source change. Verified `audit.EventType` is a **type alias** of `auditspi.EventType` (`aliases_spi.go:17`), so the design's `auditspi.EventType(typ)` lookup is type-identical to the filter value. N-3 confirmed: `auditspi` is a stdlib-only leaf (`go list -deps` shows nothing beyond stdlib).
- **No contract drift:** `docs/error-codes.md` (SDK section for `platform/audit/auditexport` — no new `Err*`), `openapi.yaml`, `config-reference.md`, `feature-matrix.md` all have no audit-export CLI entry and are correctly untouched; the new help text "unrecognized values warn; custom types allowed" remains truthful after registration.
- Caveat (B4-5's own work, not CLI): adding a const requires the auditsink CEF/OCSF tables; the conformance test is log-only on drift, so it stays green regardless.

## 4. Correction required: N-1 is factually wrong

The design's central new finding — "`EventAdminRecoveryCodesReset` and `EventRecoveryCodesRegenerated` are absent from `auditspi.KnownEventTypes`" — **does not hold**. Verified three ways:

- Both consts **are** registered: map lines 254 (`EventRecoveryCodesRegenerated: {}`, value `mfa_recovery_codes_regenerated` per line 106) and 286 (`EventAdminRecoveryCodesReset: {}`).
- Full census: 172 `EventType` consts across `event_types{,_admin,_system}.go` = exactly 172 `KnownEventTypes` keys (`comm` both directions empty — the registry is **complete**).
- The `auditsink/conformance_test.go:161-171` comment is stale and direction-reversed: runtime counts are `allKnownEventTypes=129 KnownEventTypes=172` (drift log fires every run) — the *snapshot list*, not the registry, is short (43 entries), and the "+2" attribution to the MFA recovery-code feature no longer matches anything.

Consequences for the design: §2 N-1, §5 "Known limitation (N-1)", the §6 failure-mode row "registry-gap spurious warning", and §10's "gap owned by the MFA feature" are all based on a false premise — `--type mfa_recovery_codes_regenerated` / `admin_recovery_codes_reset` would **not** spuriously warn. The warn-only stance survives on independent, verified grounds (webhook precedent at `build_audit_webhook.go:125-135` + "custom types are allowed" docs), so **R-2's conclusion is unchanged**, but N-1 should be replaced with the actual finding (auditsink snapshot staleness, out of CLI scope).

## 5. Minor drifts

- Design §7.2 says "7 call sites" for `seedStore`; actual is **8** (`main_test.go:44,69,92,114,154,182,200,217`). Mechanical.
- All line-number claims otherwise verified exact: `buildQuery` at 183 (casts 185-186), `bindFlags` 116-131, `usageErr` 284-288 / `errorf` 291-294, exit-code doc at 29-30, `TestRun_EmptyWindowExitsZero` at 88, `TestRun_TenantAndTypeFilter` at 110-135, `event_types.go:15,195-196`, `auditspi/event.go:9-13`, `query.go:36-42` literal-match, zero `auth.token.issue` in `.go`, `recorder_events.go:18-58`.

## Verdict

1. **Run refactor: no regression** — `pipeline_test.go:36` and the only other caller (`main.go:48/72`) are unaffected; both affected test packages are green; no `.go` edits were made by this review.
2. **Observational equivalence: confirmed** for exit codes in every class and stderr text modulo the usageErrorf prefix ambiguity (one line to disambiguate) and the documented double-misuse precedence corner.
3. **B4-5 follow-up: zero CLI change and no contract drift confirmed**; registry-driven mechanism verified end-to-end.
4. **Design fix needed:** replace the false N-1 registry-gap finding with the actual stale-snapshot observation; correct the seedStore count; pin the single-prefix rule for usage-error messages.
