# Verification report — revision resolves every finding

**Important status note first:** no revised design existed in the workspace — the artifact at `e4b01429/artifacts/design-a77de8a6/task-1-design.md` was still the original (it contained the `!passwordNamed` pin, the `echo -n '<password>'` remediation, and the vendoring claim; the `47b68d40` run's design file is only the orchestrator summary). I applied the frozen revision requirements (P0/P1/P2) to that artifact (504 lines, revision 2, supersession notes in the header) and verified the result. Every finding below is checked against the revised artifact **and** re-confirmed against HEAD `078eb6d7` code, go.mod/go.sum, and the x/term v0.2.2 module-cache source.

## P0 — named-but-empty on a TTY takes the no-echo prompt path ✅

- `secret()` now keys on the flag **value** only: `flagVal != ""` wins; else `if isTTY()` → `promptPassword` — `passwordNamed`/`fs.Visit` deleted from `run` and `secret`. The sole echoing TTY path is gone; §2 and §5's fail-closed note now say "no TTY path echoes" **accurately**.
- **AC-6 rewritten** as `TestRun_FlagNamedEmptyPromptsOnTTY` (TTY case: noEcho invoked exactly once, `in` never read, `Password: ` + `empty password`, exit 2; companion non-TTY case pins the legacy pipe path with noEcho NOT invoked — the test-strategy reviewer's "AC-6's `in` unspecified" nit is also fixed by specifying the EOF-empty reader).
- **F6 rewritten consistently**: `TestRun_EmptyPasswordIsUsageError` passes `--password ""`, so it now *does* get the prompt — the "friendlier + empty Enter passes" claim is now true, and the old F6↔AC-6 self-contradiction (security-engineer 2b, terminal-reviewer #2/#6) is resolved; F6's AC column corrected to AC-7.
- **F7 rewritten**: `--password ''` + TTY → prompt path (exit 2 on empty, no warning); non-TTY → legacy path unchanged.
- **R3 stderr sentence rewritten** (§4.1): scoped to stdout/exit-codes-identical for *every* shape; stderr identical for the enumerated non-TTY shapes minus four named intended deltas (warning, prompt, R4 usage text, and the declared TTY-empty message asymmetry `read password: EOF` vs `empty password`). R2's "flag wins even on a TTY" is explicitly scoped to non-empty values.

## P1 — warning remediation ✅

- `argvExposureWarning` no longer shows `echo -n '<secret>'` (grep-clean); it points interactive users at the bare no-echo prompt and mentions piping for scripts, without a secret-bearing command.
- Vectors enumerated: `ps`/`/proc/<pid>/cmdline`, shell history, **auditd execve records, systemd unit argv logging, process accounting (acct)**.
- §2 threat model now states plainly that the argv control is zero-effect and the TTY prompt is the security deliverable (finding 1a).

## P2 — F-table and semantics ✅

- **F9 oversized input**: `maxPasswordBytes = 1024` via `io.LimitReader` at the legacy call site + `len(plain)` check in `run` → `password exceeds 1024 bytes`, exit 2; ≤cap but >72 bytes → bcrypt → **exit 1** (re-verified empirically at HEAD: 72 bytes exit 0, 73 bytes exit 1 with `...bcrypt: password length exceeds 72 bytes`). AC-11 pins both.
- **F4 full signal class**: SIGINT/SIGTSTP/SIGTERM/SIGHUP, unix-only; SIGTSTP invisible-typing hazard; `stty echo`/`reset` recovery in docs; "dies by signal, shell reports 128+N" (never "exit 130"); Windows no-residual (per-handle modes); the discarded `//nolint:errcheck` restore noted; vendoring claim replaced with the correct statement (x/sys/unix at go.mod:132, `IoctlGetTermios`/`IoctlSetTermios` — feasible, out of scope).
- **F5 stderr-merging**: `out=$(sso-ctl hash --password x 2>&1)` caveat + `2>/dev/null` mitigation, no longer "no breakage".
- **F10 class-B pipe consumption + first-line-only** as an explicit accepted-failure row (AC-2's stderr-EMPTY pin preserved — the tradeoff is named, not hidden). **F11** documents ALL-trailing-`\r\n` trimming and the TTY/pipe interior-`\r`/`\b` divergence, correcting the false pipe-identical claim. Both empirically confirmed at HEAD ("first\nsecond\n" → hash of "first"; "s3cret\r\n\n" → hash of "s3cret"; NUL bytes round-trip through bcrypt).
- **F8 pinned**: `TestRun_BinaryPipeInput` (AC-10); F8's wording corrected ("trailing `\r\n` trimmed, not passed through").
- Bonus reviewer items also folded in: Windows `ReadConsole`→`DuplicateHandle`+`ReadFile` citation fix, `ICANON|ISIG|ICRNL` forced-on (`|=`), msys2/mintty native-console qualifier, stderr-redirected-prompt edge, F2 unix-scoping (Windows Ctrl-D = literal 0x04), pre-existing red gates noted in §6.

## Corrected factual claims — confirmed

| Claim | Verdict |
|---|---|
| "Signal-safe restore requires vendoring" is false | Confirmed false: `x/sys v0.44.0` indirect at go.mod:132; x/term uses `unix.IoctlGetTermios`/`IoctlSetTermios` (term_unix.go:56-77) — a ~15-line `signal.Notify` restore needs no new dep. Design now says feasible-but-out-of-scope |
| "No TTY path echoes" | Now **true** post-P0: empty-flag TTY reads all go through `readNoEcho`; non-empty flag returns without reading stdin |
| Pipe-identical semantics | Corrected: identical for well-formed single-line input; divergences documented (F11) |
| go.sum zero-diff | Confirmed: `go.sum:41-42` holds both x/term v0.2.2 hashes; promotion is the one-line go.mod move |

## Invariants survive the revision — confirmed

- **stdout bytes**: print statements byte-for-byte current; prompt/warning/cap never touch stdout. **Exit codes**: 0/1/2 map unchanged for all existing shapes; the cap error is a read-side error → 2, consistent with the frozen contract. **Dispatcher**: `"hash": hashcmd.Run` at main.go:57, `Run(args []string) int` preserved, `readPassword` body untouched (cap applied by caller).
- **go.mod promotion** zero-diff; **budgets**: main.go 93→~160 < 500, `run` ~44 < 50, complexity ~7 < 15, nesting ≤2, fan-out frozen at 16, 0 new exported symbols; **tests**: 9 new, all in-memory readers/canned closures, non-parallel; existing 5 untouched (`git diff` additions-only).
- **Acceptance**: warn-only exit 0 preserved; no refusal, no `--allow-argv`, no `--format`/`--cost`, no server changes. Baseline `go test ./cmd/sso-ctl/hashcmd/` green at HEAD; go.sum clean.

**Pre-existing, unrelated** (report per AGENTS.md §5, now recorded in design §6): `TestMaintainability_FileSizeBudget` and `TestArchitecture_DirectoryDepth/Fanout` are red at HEAD; the revision adds no violations.

Verdict: **PASS** — all three reviews' findings (P0, both P1s, all P2s, the 7-item terminal-reviewer edit list, and the test-strategy reviewer's four bottom-line items) are resolved in the revised artifact with every supporting claim re-verified.
