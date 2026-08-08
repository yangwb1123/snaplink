Review complete. Artifact: `docs/architect-analysis/auto/runs/seeding-path-secrecy-...-e4b01429/artifacts/review-c3d9a7b1/task-1-review.md`. Every claim was verified against the actual x/term v0.2.2 source in the module cache and the Go 1.26 runtime, not just the design's citations.

**Verdict: no design-blocking defects, but 3 factual errors and 2 undocumented residuals.**

The six requested angles, with the key findings:

1. **Windows vs unix semantics** — The design's "Ctrl-D on empty input → io.EOF" (F2) is **unix-only**. Windows `readPassword` clears `ENABLE_LINE_INPUT`, so Ctrl-D arrives as a literal `0x04` byte that gets silently hashed into the password (exit 0), and Ctrl+Z is `0x1A`. Windows exit paths are Enter (`\r` ends the line) and Ctrl+C (`CTRL_C_EVENT`, runtime `os_windows.go:1014`). Also, the design cites "ReadConsole" — the code actually uses `DuplicateHandle` + byte-oriented `ReadFile`. And the unix impl *forces* `ICANON|ISIG|ICRNL` on (`|=`), not merely "keeps" them.

2. **stdin shapes** — All non-TTY shapes with `--password` absent are safe and unchanged: pipe, empty-pipe, `/dev/null`, closed fd 0 (fail-closed exit 2), directory fd. No hangs, no echoing fallback. One asymmetry to declare: TTY Ctrl-D-empty → `read password: EOF`, pipe EOF-empty → `empty password` (both exit 2).

3. **io.EOF → exit codes** — Unix trace confirmed end-to-end: empty Ctrl-D → `([]byte(nil), io.EOF)` → `read password: EOF`, exit 2; non-empty Ctrl-D hashes normally. On Windows `io.EOF` is effectively unreachable from the console read.

4. **Signals** — F4's residual is correct on unix but incomplete: SIGTSTP/SIGTERM/SIGHUP have the same no-defer, echo-left-off class (F4 lists only Ctrl-C), and on Windows there is **no** residual (console modes are per-handle). Pedantry: the process never exits 130 — it dies by signal; the shell reports 130.

5. **Seam faithfulness** — The pairing is coherent (both seams key off fd 0, same ioctl basis, no TOCTOU — confirmed). Two gaps: (a) prompt goes to `errOut` while the read keys off fd 0, so `sso-ctl hash 2>log` with TTY stdin shows no prompt and blocks; (b) "Windows gets true no-echo" holds only for native console hosts — Git Bash/msys2 ptys fail `GetConsoleMode`, silently landing on the **echoing** pipe path.

6. **`TestRun_EmptyPasswordIsUsageError`** — This is where the design contradicts itself (High): the test passes `--password ""`, which AC-6/F7 pin to the legacy no-prompt path. So F6's "the prompt makes empty-Enter pass cleanly" and §4.8's "with the change it prompts" are **wrong for this invocation** — behavior after the change is byte-identical to HEAD: a blocking, *echoing* read with no prompt. CI passes via the exit-code-only assertion (EOF-empty or error path), already true today.

The artifact ends with a minimal 7-item edit list for the design (F2 unix-scoping, F6/§4.8 rewrite, F4 broadening, citation fix, msys caveat, stderr-prompt edge, message asymmetry) plus two optional smoke tests (Windows non-ASCII, pty wiring). No `.go` edits were made, so no gates were required.
