I've now read all 16 subcommands' dispatch, flag parsing, exit paths, output streams, and env usage. Here's the comparison.

## Verdict

The surface is ~80% a good citizen: kebab-case `--flag` long names, `Run(args []string) int` signature, one map entry, 0/1/2 exit codes, stderr usage banners, and `SSO_ADMIN_ADDR` reuse all match the tree. But four items are genuine inconsistencies — one of them (**exit 0 on credential-less skip**) directly contradicts the tree's exit-contract and honesty conventions, and one (**`-h` exit 0 under `ContinueOnError`**) contradicts the design's own implementation note.

## Dimension-by-dimension comparison

| Dimension | Tree convention (evidence) | Design | Verdict |
|---|---|---|---|
| Flag parse | Split: `ContinueOnError` majority (clientscmd:84, configcmd:87/22/64, entitiescmd ×8, snapshotcmd ×3, sessionscmd:82, tokenscmd:111, migratecmd:81, hashcmd:33, legacysync:49) vs `ExitOnError` minority (auditverify:99, importcmd:122, soc2report:67, auditexport:106, generate:56) | `ContinueOnError` (§5 row 24) | ✓ majority |
| Flag names | Single kebab-case nouns (`--from-file`, `--notary-key`, `--anchor-hash`, `--page-size`, `--passphrase-file`); no `--addr` anywhere (URL flags are `--from-url`) | `--addr`, `--client-id`, `--expect-*` | ~ (see F-4) |
| Repeatable flags | Precedent exists: `attrFlag` (entitiescmd/users.go:24), `stringMapFlag` (legacysync/config.go:24) via `flag.Var` | `--resource` repeatable | ✓ |
| Exit codes | 0/1/2 only, documented verbatim (soc2report:32-34, auditexport:40-42, auditverify:29-33); nothing returns 3+ | 0/1/2 | ✓ |
| Missing required input | Always exit 2 + usage (configcmd `--file`:91-95, importcmd `--format`/`--dsn`:134-144, legacysync env pw:31-35, auditverify `--bearer`, clientscmd `get` id, hashcmd empty pw) | **No creds → exit 0 + skip** (row 25) | ✗ **F-1** |
| Partial verification | auditverify truncation → exit 1 ("prefix verified … not the full chain", :259-263); never 0 | skipped groups are "never failures" | ✗ **F-1** |
| `-h` at flag level | Exit 0 only in the `ExitOnError` group (flag pkg exits 0 on `ErrHelp`); all `ContinueOnError` users return 2 on `-h` (no `ErrHelp` special-case anywhere — grep confirmed) | `-h, --help → exit 0` + `ContinueOnError` | ✗ **F-2** (self-contradiction) |
| URL-parse failure | auditverify: `url.Parse` error → **exit 1** runtime (`readFromURL` → `errorf`) | bad `--addr` → **exit 2** misuse (§2.1) | ~ **F-3** |
| stdout | Human-readable result lines: `config OK: <file>` (configcmd), `chain verified: N event(s), head=…` (auditverify); data via `apiclient.WriteJSON/WriteTable` | one line per group + `check OK`/`check FAIL` | ✓ |
| stderr | All diagnostics + all usage() → stderr (every subcommand, incl. exit-0 help in main.go); bare verdict prefixes have precedent (`chain BROKEN:`, `notice:`) | stderr-only diagnostics, bare `discovery:`/`mint:` prefixes | ✓ |
| Env vars | `SSO_ADMIN_ADDR`/`SSO_ADMIN_TOKEN` (apiclient.go:16-20), `SNAPLINK_LEGACY_DB_PASSWORD` (legacysync/config.go:12); env-wins ordering in `apiclient.New` (:58-61) is exactly as the design claims | `SSO_ADMIN_ADDR` honored, env wins | ✓ |
| Failure style | Every subcommand is fail-fast (clientscmd `if !ok { return 1 }`, auditverify checkpoint-before-events) | collect-all-failures, no mid-sweep abort (§5) | ~ **F-5** |

## Findings

**F-1 (contradicts the exit contract) — credential-less run exits 0 with `check OK` on stdout.** Two tree conventions collide with row 25 / A8:
- *Missing-required-input = exit 2 misuse* is universal (configcmd `--file`, importcmd `--format`, legacysync env password, auditverify `--bearer`).
- *Incomplete verification = exit 1* is the auditverify truncation rule: a run that didn't verify the whole chain exits 1 and says so ("…not the full chain"), never 0.

A bare `sso-ctl check` (or a CI job with a typo'd credential env) prints `check OK` after silently skipping 2 of 4 probe groups — the exact "assert the prefix is the full chain" false-green auditverify refuses to emit. The design's own "exit 0 = all **executed** checks passed" phrasing is self-consistent but deploys as a deploy-gate footgun with no precedent anywhere in the tree. Fix: no credentials → exit 2 (tree convention), or exit 1 with an explicit "incomplete" verdict — and `check OK` must not be printed when any group was skipped.

**F-2 (self-contradiction) — `-h` exit 0 is unreachable with the design's stated implementation.** With `flag.ContinueOnError`, `-h`/`--help` makes `fs.Parse` return `flag.ErrHelp`; every `ContinueOnError` user in the tree (`clients list -h`, `config validate -h`, …) exits 2 because none special-cases `ErrHelp` (grep: zero hits). Exit-0 help exists only in the `ExitOnError` group (auditverify, importcmd, soc2report, auditexport, generate), where the flag package does it implicitly. The design must either special-case `errors.Is(err, flag.ErrHelp) → return 0` (making `check` the first subcommand to do so, with the help banner on stderr per tree convention) or drop the "exit 0" claim. Note `sso-ctl check -h` never reaches main.go's help case — it dispatches straight to `CheckRun`, so this path is mandatory, not optional.

**F-3 — §2.1's fail-fast `--addr` validation is half-implemented and misclassified.** Two problems:
- *Misclassification:* the closest precedent (auditverify `--from-url` → `url.Parse` failure → exit 1, "parse base URL: %w") treats unparseable URLs as runtime errors, not misuse. Exit-2-for-bad-URL is a deliberate deviation (design says so) but §5 row 24 should say it deviates.
- *Incomplete fail-fast:* validation runs on the flag value only, but `apiclient.New` applies `SSO_ADMIN_ADDR` **after** `WithAddr` (apiclient.go:58-61, env wins). So (a) a bad env value bypasses preflight and produces exactly the five confusing per-row transport failures §2.1 claims to eliminate, and (b) a bad `--addr` flag exits 2 even when a valid env value would have overridden it. The preflight must also validate the env-sourced value (read `apiclient.EnvAddr` in `CheckRun`) or the design's own rationale is only half-honored.

**F-4 (minor) — `--addr` is a new vocabulary word.** No existing flag is named `--addr`; URL-bearing flags are `--from-url`/`--file`/`--dsn`. It is, however, consistent with the apiclient module's own vocabulary (`DefaultAddr`, `WithAddr`, `EnvAddr`), so this is defensible — but flag help should mention the env override (already planned) and the design should keep it as the only divergence. The `--expect-*`/`--client-*` prefix style is likewise new but unobjectionable.

**F-5 (minor, deliberate) — collect-all-failures is the tree's first non-fail-fast subcommand.** Every existing Run returns at the first error (clientscmd `fetchList`, auditverify's checkpoint-before-events fail-fast). The design's "all executed probes run; every failure collected" is justified for a sweep, but it's a new observable semantic — worth one sentence in the doc so a reviewer doesn't flag it as a bug.

## What is genuinely consistent (no change needed)

- **Exit codes 0/1/2**: exactly the documented contract of soc2report/auditexport/auditverify; 8 flags is within bounds (auditverify has 9).
- **Env naming**: `SSO_ADMIN_ADDR` reuse is exact, including the env-wins precedence; `SSO_` prefix matches apiclient (only legacysync uses the `SNAPLINK_` prefix, for a different concern).
- **Byte-determinism**: no tree convention forbids it, and the design's pins are sound — random probe scope off stdout, fixed probe order, stable final line, variable content (URLs, bodies, truncated JSON) confined to stderr. The one determinism-adjacent problem is F-1's `check OK` on a skip-run, which is a semantics problem, not a bytes problem.
- **Stdout/stderr split**: result lines on stdout + diagnostics on stderr matches configcmd/auditverify; usage banners must go to stderr even on the exit-0 `-h` path, as all 16 do today.
- **Registration**: one map entry + one usage line + one doc line is precisely the documented pattern (main.go:40-44); the `dispatch_test.go` nil-Run guard (EveryEntryHasARunFunc) will exercise the new entry for free.

The two must-fix items before implementation are **F-1** (skip-run exit semantics) and **F-2** (ErrHelp handling); F-3's env-side validation should be decided in the design doc, not left to the implementer.
