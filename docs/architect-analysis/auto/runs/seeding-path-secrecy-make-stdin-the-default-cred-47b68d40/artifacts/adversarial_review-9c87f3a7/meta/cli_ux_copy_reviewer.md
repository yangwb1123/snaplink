All source verification is complete. Here is my review.

---

# Review: user-facing copy (warning, prompt, R4 usage text) — `cli_ux_copy_reviewer`

**Verdict: FAIL as-is — and a precondition is unmet.** The "revised user-facing copy" the orchestrator's iteration-2 prompt assumes does not exist: `docs/architect-analysis/auto/runs/...e4b01429/artifacts/design-a77de8a6/task-1-design.md` is byte-unchanged since 14:29:27 (mtime verified; iteration-1 reviews ran 14:34–14:35), and design §3.4 contains only intent bullets ("reorder examples… document the no-echo prompt and the argv warning") — **no concrete R4 copy was ever written**. I therefore reviewed the copy as it currently stands in the design and supply the exact corrected copy below so the revision (and the parallel `design_revision_verifier`) has a verbatim target.

## Verification basis (source-checked, not citations)

| Claim | Evidence |
|---|---|
| unix `readPassword`: clears `ECHO`, forces `ICANON\|ISIG\|ICRNL`, defer-restores | `term_unix.go:49-63` (module cache, v0.2.2) |
| `readPasswordLine` drops `\r` and pops on `\b`; returns `(nil, io.EOF)` on empty-EOF; data+EOF returns data | `util.go:13-46` |
| Windows `readPassword`: `GetConsoleMode` failure → **error return**; clears `ECHO_INPUT\|LINE_INPUT`, sets `PROCESSED`; Enter = `\r`; Ctrl-D/Ctrl-Z = literal 0x04/0x1A | `term_windows.go:59-83` |
| msys2/mintty: `GetConsoleMode` fails → `IsTerminal=false` → `secret()` takes the **legacy echoing `bufio` read** (exit 0), no-echo path never entered | `term_windows.go:60-62` + design `secret()` gating |
| bcrypt rejects >72 bytes (`ErrPasswordTooLong`), wrapped → exit 1 | `x/crypto@v0.51.0/bcrypt.go:96-98`, `password_hash.go:92-98` |
| `acct` records command name only (`ac_comm`), not argv | kernel acct(2) semantics |

## Findings by surface

**S1 — Blocking: the R4 copy does not exist.** §3.4 describes a rewrite but contains no text. The three required residual behaviors (first line only; all trailing CR/LF trimmed; 72-byte bcrypt rejection) appear **nowhere** in the design, and `stty echo` recovery / unix-only Ctrl-D appear only in the F-table (design prose), never in user-facing copy. Requirement 3 (document residuals in the text) is entirely unmet.

**S2 — Blocking: the warning remediation recreates the leak it names.** Current const: `…prefer piping the password on stdin: echo -n '<password>' | sso-ctl hash`. This instructs an interactive operator to type the secret into a **new** command line — landing in shell history, the exact vector the warning names. Violates requirement 1. For interactive users the design's own R2 no-echo prompt is the remediation; the pipe form belongs to scripts (secret from a variable/secret store). §6.4's release-note guidance (`echo -n '<secret>' | sso-ctl hash`) and the HEAD usage example (`echo -n 'change-me' | …`) carry the same defect and must change in the same revision.

**S3 — Blocking: vector claims are incomplete and one would be false.** Current copy names ps//proc/cmdline + shell history (both accurate; ps reads `/proc/<pid>/cmdline` on Linux, `KERN_PROCARGS` on BSD/macOS). Missing, per requirement 2: kernel **auditd** execve-argv records, **systemd** unit/ExecStart and `systemd-run` arguments (persistent unit files; `systemd-coredump` also stores cmdline). **`acct` must not be named as a plaintext vector**: process accounting records only the command name (`ac_comm`, 16 bytes) — the secret never appears there. The revision should state that exclusion explicitly rather than list acct as a capture point.

**S4 — Blocking: three design claims that would leak into copy are contradicted by x/term v0.2.2.**
1. §2 "TTY prompt must be byte-identical in *result* semantics to the pipe path: one line, `\r\n`-trimmed" — false: TTY path drops interior `\r` and processes `\b` (util.go), and forced `ICRNL` makes a pasted CR *terminate the line early*; the pipe path keeps interior `\r`. Copy may say "one line; trailing CR/LF removed" but **never "identical to the pipe path"**.
2. §2 "empty ⇒ exit 2 with the existing `empty password` message" — false for empty Ctrl-D on unix TTY: `readPasswordLine` returns `io.EOF` → `read password: EOF` (still exit 2). Messages differ by shape: pipe EOF → `empty password`; TTY bare Enter → `empty password`; TTY empty Ctrl-D → `read password: EOF`. No copy may promise a single empty-input message.
3. §4.7/F2 "never an echoing fallback (fail-closed)" — false at the **isatty gate**: under Git Bash/msys2, `GetConsoleMode` fails → `IsTerminal=false` → the no-echo path is never entered and the secret is read with echo **on** (exit 0). The echo-off promise is per-read, not per-invocation. Any "no-echo" claim in help/warning must be scoped: unix terminals + native Windows consoles; msys2 ptys fall back to the echoing read.

**S5 — Medium: consistency.** Warning says "prefer piping" while R2/R4 make stdin-with-prompt the default channel — the warning must point interactive users at `Password: ` and reserve the pipe for scripts, and usage/flag-help must match. The `--password` flag description string is dead text today (custom `fs.Usage` never prints it) — R4 should still keep it consistent, but the real surfaces are `usage()`, the package doc, and the warning. The prompt label must be quoted identically in warning, usage, and package doc ("`Password: `").

## Corrected copy (verbatim-ready)

**Warning const** (keeps pinned test substrings `--password`, `argument list`, `stdin`; no interpolation — still leak-proof):

```
sso-ctl hash: warning: --password puts the plaintext in the process argument
list (visible via ps or /proc/<pid>/cmdline) and may persist in shell history;
kernel audit (auditd) execve records, systemd unit arguments, and core dumps
can capture it too. Interactive use: run 'sso-ctl hash' without --password and
type the secret at the no-echo 'Password: ' prompt. Scripts: pipe the secret on
stdin from a variable or secret store (printf '%s' "$SECRET" | sso-ctl hash);
never type the secret into a shell command.
```

**Prompt**: unchanged — `Password: ` on stderr, newline after the read. No claims attached; correct on both platforms. (Optionally append "(Ctrl-C to cancel)" — accurate on unix via `ISIG` and on Windows via `CTRL_C_EVENT`→SIGINT.)

**usage()** (stdin-first; documents every required residual):

```
sso-ctl hash — produce a server-compatible password hash.

Usage:
  sso-ctl hash                           # type the secret at the no-echo 'Password: ' prompt
  printf '%s' "$SECRET" | sso-ctl hash   # pipe for scripts (secret from a variable or store)
  sso-ctl hash --password '...' [--quiet]   # discouraged: prints a warning; plaintext is visible in process argv

Flags:
  --password   The plaintext to hash (omit to read from stdin). Warning: the value is
               visible in the process argument list (ps, /proc/<pid>/cmdline, shell
               history, auditd/systemd records).
  --quiet      Print only the hash, no "format:/hash:" labels.

Notes:
  - Only the first line of stdin is read; the remainder is not consumed (on a terminal,
    a multi-line paste can spill into the shell after this command exits).
  - All trailing CR/LF bytes are removed; a secret cannot end with a newline. On a
    terminal, CR ends the line.
  - Echo is disabled only on unix terminals and native Windows consoles; Git Bash/msys2
    terminals cannot disable echo and fall back to an echoing read — pipe the secret there.
  - Empty input is an error (exit 2). On unix, Ctrl-D on an empty line also ends input
    (exit 2); on Windows Ctrl-D is not a control character and would be hashed into the
    secret — press Enter on an empty line, or Ctrl-C to cancel.
  - On unix, Ctrl-C or Ctrl-Z during the prompt can leave echo disabled in the terminal;
    restore with 'stty echo'.
  - Secrets longer than 72 bytes are rejected (exit 1), never truncated; bcrypt's limit
    counts bytes, not characters.
```

**Package doc**: replace the concession with the scoped claim: "On a terminal the password is read with echo disabled (unix terminals and native Windows consoles; Git Bash/msys2 ptys fall back to an echoing read — pipe there)." Keep the shared-shell caution on `--password`; keep the `printf '%s' "$SECRET" |` pipe example; AC-8's `grep "no echo on a TTY"` still passes.

**Design-text corrections for the same revision** (feeds `design_revision_verifier`): §2 identity claim, §2 empty-message claim, §4.7/F2 msys2 gate, §6.4 `echo -n '<secret>'` guidance, and an explicit "acct records command name only" note.

**Verified-good as written**: constant has no interpolation (no secret can enter it); prompt is stderr-only and never touches stdout; `Password: ` label is conventional; the pipe form is preserved for scripts (requirement 1's second half). No `.go` edits were made, so no gates were run (doc-level review, matching the other reviewers).

**Bottom line**: the premise "revised copy" is unsatisfied — the design was never revised. The copy that exists fails requirements 1 (echo remediation), 2 (incomplete vectors; acct would be false), and 3 (no residuals documented), and three design sentences it would inherit are contradicted by x/term v0.2.2. The corrected copy above is the minimal complete replacement; until it is applied and verified against S1–S5, this deliverable cannot pass.
