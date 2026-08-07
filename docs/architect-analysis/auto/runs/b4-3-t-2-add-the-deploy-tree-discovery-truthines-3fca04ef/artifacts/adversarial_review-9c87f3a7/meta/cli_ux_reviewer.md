# Review: `config check-discovery` + `validate --issuer-allowlist` vs sso-ctl command conventions

All five dimensions checked against executable code (not just the design doc). The design's factual bases hold up under independent re-verification; I found no T-9 break, one real byte-stability hazard in the new command's own output, and two contract ambiguities that must be pinned before implementation. Full details below, then a severity list.

**Verified as sound (spot-checked, not just cited):** `StdRouter.ServeHTTP` (shared/core/router.go) skips method-mismatched routes and falls through to `http.NotFound` → the C1/C1a 404-then-POST correction is correct, and the spec's 405-based case 7 mechanism was indeed wrong; `config/config.go:13` already imports `interfaces/sso` (no new dependency edge); `importcmd/importer.go:11`/`generate/templates.go:12` import precedents real; `cmd/sso-ctl/` has exactly 16 subdirs vs `maxSubdirsPerDir = 16` at `directory_fanout_test.go:35`; `usageErr` exits 2 at `auditverify/main.go:230`.

## 1. Flag naming/parsing style — conforms, two gaps

- Matches: kebab-case flags, `flag.NewFlagSet(name, flag.ContinueOnError)`, parse error → `return 2` (configcmd's variant; auditverify's `usageErr` is the os.Exit twin — same 2-vs-1 taxonomy, the design correctly follows the package-local return-int style). `--issuer-allowlist` empty-value/empty-entry → 2 mirrors `--file`-required handling exactly.
- **Gap (must pin):** `--timeout` ≤ 0 (flag.Duration accepts `0s`/`-1s`) is undefined. With `context.WithTimeout` it manifests as every probe failing → exit 1 "timed out" — a confusing runtime failure for an operator typo. Reject `<= 0` at parse → exit 2, consistent with the design's own "bad flag value = usage" split.
- **Note (advisory):** the module's only HTTP-timeout precedent is `auditverify --timeout-sec` (int seconds). `--timeout` (duration) is more expressive and defensible, but the divergence should be a conscious choice, not silent; also pin the missing-`--url` message shape to the `--file` pattern (`sso-ctl config: --url is required` + `usage()`, exit 2) — the design only says "exit 2".

## 2. usage()/help text — one convention divergence to decide

- Design correctly updates the configcmd banner + package-doc `Subcommands:` block and leaves `cmd/sso-ctl/main.go` usage untouched (T-9 for the top-level help).
- **Divergence (advisory):** every other sso-ctl FlagSet wires `fs.Usage = usage` (auditverify:66, hashcmd:36, importcmd:130); configcmd's three existing FlagSets do **not** (parse errors and `-h` print only flag defaults, no banner). If the new `check-discovery` FlagSet wires the banner, it follows the module convention but diverges within the package; if it doesn't, it inherits configcmd's quirk. Either is defensible — but decide and note it. Whatever the choice, `check-discovery -h` → exit 2 matches the pre-existing `validate -h` quirk, so no new inconsistency is introduced.

## 3. Exit-code taxonomy — conforms; one split needs help-text documentation

- 2 = usage (parse error, missing/`-h`, unparseable `--url`/`--timeout`, empty allowlist), 1 = runtime (fetch failure, violations, load failure, allowlist mismatch), 0 = success. Clean and consistent with both `usageErr` (2) and `errorf` (1) precedents.
- The trailing-slash/`--url`-path → **1** vs malformed-`--url` → **2** split is defensible (legal URL, contract violation vs invalid input) but must be visible in the flag help string (e.g. "base URL http(s)://host[:port], no trailing slash or path") — currently the design doesn't specify the help text carries it.

## 4. The 13-field table as *output* — not specified; byte-stability hazard in what IS specified

This is the largest finding. The design's §2.1 table is a **spec-internal field table, not CLI output**. The only pinned output is per-violation stderr lines; success-path stdout is unspecified (acceptance case 1 pins "no stderr" only, and the module convention is a stdout status line — `config OK`, `chain verified`, `no events to verify`). If the campaign intends the sweep to emit a 13-field table (the review premise), the design lacks the entire output spec: stream, alignment, success shape. The module table convention to follow if added: **stdout, fixed-width `%-Ns` columns with two-space separators, header row** (snapshotcmd/main.go:109, migratecmd/main.go:119). Resolve this premise before implementation; a stdout table would not violate case 1 (which pins stderr), but silence-on-success is also fine if pinned.

Regardless of table-vs-lines, two byte-stability requirements are missing and must be added:

- **Violation ordering must be canonical.** `checkDiscoveryDoc(doc map[string]any, ...) []violation` — iterating the decoded map directly randomizes order per run (Go map iteration), making multi-violation stderr nondeterministic. Mandate iteration over the fixed 13-field table in table order; probes sequential (or results sorted) with dedup preserving first-seen order. Add a test asserting **exact stderr bytes** for a doc with multiple simultaneous violations (case 3 currently tests one mismatch per doc and cannot catch ordering drift).
- **Fetch URL construction:** build the fetch URL from the *trimmed* base. Raw `--url` with trailing slash → `//.well-known/...` → ServeMux 301-clean hop; harmless but adds a redirect the design's diagnostics don't account for. Minor, one line.

## 5. T-9 byte-identical on untouched commands — structurally sound, one ambiguity

- Verified airtight: main.go untouched; `runValidate` changes gated on flag presence; no `config.Config`/schema change (so `schema`/`--print` output stable); existing 12 tests are the lock; `check-discovery` is one additive switch case with no interaction with existing paths.
- **Ambiguity (must pin):** design §2.2 says the allowlist check runs "before `--print` rendering; on failure nothing is printed to stdout" — but `runValidate` prints `config OK: %s` **before** `--print`. If the check is placed after that print, the mismatch path emits `config OK` on stdout with exit 1, contradicting the design's own "nothing printed to stdout". Pin: check immediately after `config.Load`, before the `config OK` print. Success-path output is unaffected either way.
- Also pin the exact stderr format (`sso-ctl config: check-discovery: <field>: <detail>\n`; the nested `check-discovery:` segment is new relative to `validate`'s flat prefix — fine, but byte-stability requires it be exact).

## Severity list

| # | Severity | Item | Resolution |
|---|---|---|---|
| 1 | **Must-pin** | Violation ordering from map iteration = nondeterministic stderr; no multi-violation exact-bytes test | Fixed-list iteration in table order; sequential probes; add multi-violation stderr test |
| 2 | **Must-pin** | Allowlist check placement vs `config OK` stdout contradicts "nothing printed to stdout" on failure | Check immediately after `config.Load`, before the print |
| 3 | **Must-pin** | `--timeout <= 0` undefined (would surface as exit 1) | Reject as usage error, exit 2 |
| 4 | **Spec gap (conditional)** | 13-field table as CLI output doesn't exist in the design; success stdout unpinned | If table required: stdout, `%-Ns` + 2-space separators, header, canonical order; else pin silent success |
| 5 | Advisory | `--timeout` vs auditverify's `--timeout-sec`; `fs.Usage` wiring decision; missing-`--url`/help-text message shapes | Decide explicitly, document in design |

**No regression on untouched commands** (T-9 holds by structure), no exit-taxonomy violation, no flag-style violation, and the C1/C2 router corrections are confirmed correct against the actual `StdRouter` code. The three must-pins are all implementable in the design before step 1 of the migration order; item 4 needs a campaign-side answer if the premise is a table output.
