All three challenge areas verified against code, x/term v0.2.2 source, and x/crypto v0.51.0. Findings below; each claim is tied to evidence.

---

# Adversarial review: credential-handling decisions

## 1. Warn-only (exit 0) and warning-text leakage

**Verdict: acceptance-faithful, but the design overstates both the control's effect and its own compat claims.**

**1a. Warn-only is information-only; the leak surface is unchanged.** The design's threat model (§2) names argv observation — and argv exposure is *all* that remains: `ps`/`/proc/<pid>/cmdline` (transient, sub-second), shell history (persistent), plus vectors the design never enumerates: kernel `auditd` execve argv records, systemd unit argv logging, process accounting (`acct`). Warn + exit 0 does nothing to any of these; a `--password` invocation behaves exactly as at HEAD, plus one stderr line. That is defensible *because the direction's acceptance froze exit 0* (requirements §"Explicit non-goals: no refusal/`--allow-argv`") — but §2's framing "the no-echo prompt is the enforced part (fail-closed)" quietly shifts the goal: the enforced part only covers the no-flag TTY shape. The design should say plainly that the argv control is zero-effect and the actual security deliverable is the TTY prompt.

**1b. The warning text itself cannot leak (verified), but its advice recreates the leak it warns about.** `argvExposureWarning` is a constant with no interpolation — no secret can enter it; tests assert substrings only. However, the remediation line `echo -n '<password>' | sso-ctl hash` instructs the operator to type the secret into a *new* command — which lands in the exact vector the warning names ("may persist in shell history"). It swaps argv for history, and for an interactive human it is strictly worse advice than the no-echo prompt that the same binary already provides with the same invocation (`sso-ctl hash`, no flags). The advice is only an improvement for scripts — where the pipe is already the correct form. Fix: point interactive users at the prompt, keep the pipe for scripting.

**1c. F5's "no breakage" is overstated.** `out=$(sso-ctl hash --password x 2>&1)` — command substitution with merged stderr, a common pattern — now captures the warning into the variable and corrupts hash extraction/CSV seeding. F5's "stdout and exit unchanged — no breakage" is only true for scripts that keep stderr separate. This belongs in the compat list with the `2>/dev/null` mitigation, not in a "no breakage" row.

## 2. F1–F8 fail-closed verification — two internal contradictions, one under-scoped residual

Verified each row against code. F1 ✓, F2 ✓ (error → exit 2; x/term's `defer` restores termios on the error path, so no fallback to the echoing `bufio` read), F3 ✓, F5 ✓ (modulo 1c), F7 ✓ as written, F8 partial (below). Two rows are false as written:

**2a. The design's core fail-closed invariant is false (the big catch).** §5 claims: *"there is no path where a TTY stdin read echoes the plaintext."* There is exactly one: `--password ''` + TTY. `secret()` sends named-but-empty flags to `readPassword("", in)` — the legacy `bufio` read from fd 0 with **ECHO on**. This is a plausible human invocation: the flag help says "omit to read from stdin", so an operator typing `sso-ctl hash --password ''` as a "I'll type it interactively" placeholder gets an echoing read — the precise hazard the feature exists to eliminate — and AC-6's own new test **locks it in** (`TestRun_FlagNamedEmptyStillReadsStdin` asserts noEcho NOT invoked with `isTTY=true`). The fix is one condition (`prompt when isTTY && flagVal == ""`, ignoring `passwordNamed`), and the R3 objection doesn't survive scrutiny: constraint #1 claims "stderr bytes identical to HEAD for every existing invocation shape" — which is *already false* for the no-flag TTY shape, where the prompt itself adds two stderr lines. R3 as written is internally inconsistent; the `--password ''`+TTY shape deserves the same prompt treatment, not exemption.

**2b. F6's claim is false under the design's own channel rules.** F6 says the change "makes it friendlier (prompt + empty Enter passes)" for the interactive-`go test` interaction. But `TestRun_EmptyPasswordIsUsageError` passes `--password ""` — which per AC-6 stays on the legacy pipe path, **no prompt**. The change does nothing for that test; it still blocks on a bare, echoing stdin read. The F6 row and the AC-6 row contradict each other. Same fix as 2a resolves both.

**2c. The Ctrl-C residual is under-scoped in three ways.** Source-verified in x/term v0.2.2 `term_unix.go:49-63`: clears only `ECHO`, keeps `ICANON|ISIG`, restores via `defer` — which does not run on signal death. But:
- *"A signal-safe restore would require vendoring"* is **factually wrong**. `golang.org/x/sys/unix` is already in the graph (go.mod:132); `IoctlGetTermios`/`IoctlSetTermios` are the exact primitives x/term uses. A `signal.Notify` handler that restores the saved termios and re-raises is ~15 lines, no new dependency. Out-of-scope is a legitimate call; the stated reason is not.
- **Ctrl-Z (SIGTSTP) is worse than Ctrl-C and unmentioned.** With ISIG kept, Ctrl-Z suspends the process with ECHO off; the shell prompt resumes with the operator's typing **invisible** — they may type a password into the wrong command, a new leak vector the design never names. SIGQUIT/SIGHUP/SIGTERM have the same no-restore class. The residual should enumerate the signal class, not just Ctrl-C.
- x/term's deferred restore error is discarded (`//nolint:errcheck`, `term_unix.go:60`) — a failed restore on the *normal* path silently leaves ECHO off. Exotic, but it means even the "recovery is `stty echo`" note in F4 is the only net; it should move into the prompt docs.

**2d. F8 misdescribes the behavior and omits size.** Empirically confirmed through the repo's own `authenticators.HashPassword`: 72 bytes succeeds, 73 bytes → `ErrPasswordTooLong` → **exit 1** (not 2) with the cryptic `password_hash: bcrypt generate: bcrypt: password length exceeds 72 bytes`. Fail-safe (no silent truncation — good), but the unbounded `bufio` read happens *first*: a newline-less stream (`cat /dev/urandom | sso-ctl hash`) grows memory without limit before the 72-byte check. And F8's wording "bytes pass through TrimRight" is wrong — trailing `\r\n` bytes are **trimmed**, not passed through. The F-table has no row for size at all.

## 3. Stdin-as-default risks

Frame first: the pipe path is byte-identical to HEAD, so these are pre-existing behaviors the design now *endorses* as the default channel without new mitigations.

**3a. Oversized input.** Unbounded `bufio.ReadString` growth (OOM on newline-less input) then a confusing exit-1 bcrypt error past 72 bytes. Cheap hardening: a read cap (1–4 KiB is generous for a password) with a clear message, or at minimum a usage note on the 72-byte limit.

**3b. Trailing-newline handling.** `TrimRight` strips **all** trailing `\r\n`, not one — `"s3cret\n\n"` → `"s3cret"`, and a secret legitimately ending in LF/CR cannot be seeded via stdin at all (must use `--password`, which now warns). Worse, the design's "result semantics identical to the pipe path — one line, `\r\n`-trimmed" (AC-2/3 rationale) is testably false: the TTY path sets `ICRNL` and x/term's `readPasswordLine` *drops interior `\r` and interprets `\b`* (`util.go:13-46`), while the pipe path keeps interior `\r`. A CRLF paste behaves differently per channel. Edge case, but the equivalence claim used to justify the semantics is wrong.

**3c. Accidental consumption of piped data.** Two classes: (A) empty/EOF stdin (`</dev/null` in CI) → exit 2 — safe. (B) stdin is a pipe with *unrelated* data (build-log streams, `xargs`, mis-wired pipelines) → the first line **silently becomes the password**, exit 0, zero feedback. Under `--password`-required semantics this class was impossible; it is now the default channel. The isTTY gate only protects interactive misuse, and no R3-preserving mitigation exists — AC-2 itself pins `stderr EMPTY` on the pipe path, so even a hint line is precluded by the design's own test. This is the acceptance's inherent tradeoff (stdin-default + byte-identical stderr are jointly incompatible with a pipe hint); the design should name it as an explicit accepted failure row instead of leaving it implicit. Related: only the first line is consumed — a multi-line paste silently uses line 1 and discards the rest.

**3d. Survival into error output and exit paths — verified clean.** Every error string checked: fd/termios-level errors (`inappropriate ioctl for device`, `io.EOF`), the constant `empty password`, bcrypt errors (no input echo — confirmed in x/crypto source), and Go `flag` parse errors (string values can't be echoed; `stringValue.Set` never fails). Stdout carries only the hash. Residual, same as HEAD: the secret lives unzeroed in heap (bufio buffer + `plain` string; the TTY path appends byte-by-byte) until process exit — acceptable for a short-lived seeding tool, but worth one sentence in the threat model rather than silence.

---

## Verdict and prioritized recommendations

The design is structurally sound (seams-as-parameters, frozen public surface, zero-diff go.sum) and faithful to the acceptance. The credential-handling decisions have one genuine hole and several false supporting claims:

| Priority | Item |
|---|---|
| **P0** | `--password ''` + TTY is the one path that echoes a secret on a TTY — contradicting the design's own fail-closed note and pinned by its own AC-6 test. Prompt when `isTTY && flagVal == ""`; also fixes F6's false friendliness claim. |
| **P1** | Replace the warning's `echo -n '<secret>'` remediation with the no-echo prompt for humans (the echo advice recreates the history leak); enumerate the argv vectors the tool cannot fix (auditd/systemd/acct) instead of only ps. |
| **P1** | Correct three factual claims: "signal-safe restore requires vendoring" (x/sys/unix is already a dep), "no path where a TTY read echoes", "result semantics identical to pipe". |
| **P2** | Extend the F-table: oversized input (cap + 72-byte note, exit 1 ≠ 2), the full signal class including SIGTSTP (invisible-typing hazard) with `stty echo` recovery in docs, stderr-merging scripts under F5, and the silent class-B pipe consumption. |
| **P2** | Document "all trailing \r\n trimmed (not one)" and "first line only" in usage text. |

None of these require changing the acceptance's warn+exit-0 decision — the P0 fix is a one-condition change that strengthens the enforced (no-echo) half of the design while leaving every stdout byte and exit code untouched.
