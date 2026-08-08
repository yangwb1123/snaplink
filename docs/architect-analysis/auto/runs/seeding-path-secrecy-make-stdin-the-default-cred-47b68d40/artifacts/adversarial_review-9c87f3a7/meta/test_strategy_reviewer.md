All verification complete. Here is the verdict.

# Verification report: design acceptance mapping (task-1-design.md)

**Verdict: complete and executable, with 3 small gaps, 1 overstated sentence, and 1 pre-existing gate condition the design doesn't call out.** Every claim below was re-checked against HEAD (`078eb6d7`).

## 1. AC-1..AC-9 executability — PASS (2 minor under-specifications)

All 9 rows are Given/When/Then with the seam-injected `run(...)`; stdout assertions are round-trip-built (never hardcoded — correct, since bcrypt is salted), stderr uses substring/prefix. Verified against `authenticators` signatures (`HashPassword(plaintext) (PasswordHash, error)`, `VerifyHash(ctx, h, plaintext)` — design's assertions compile). Two nits:
- **AC-6's `in` is unspecified**: the named-but-empty path *does* read `in` (legacy pipe path), so `in` must be an EOF-empty reader, not the poisoned reader used in AC-2. Implicit, but a test author could mis-wire it.
- AC-8's "stdin example leads" is a manual review item, not a test — acceptable for a doc AC.

## 2. F↔AC coverage for all 8 rows — 7/8 mapped; F8 is the deliberate gap

F1→AC-1/5, F2→AC-4, F3→AC-3, F5→AC-1, F6→AC-7, F7→AC-6 — all correct. Two issues:
- **F8 (binary/UTF-8 pipe input) has no AC and no test at all** — neither new nor pre-existing. The claim "unchanged from HEAD" is *provably* true (the `readPassword` body is untouched), so this is defensible, but if the requirement is coverage for all 8 rows, this is the one hole. A ~5-line pinning test (binary bytes → exit 0, stdout shape) would close it. The design's own "All 7 F rows map" sentence is accurate only in that 7-of-8 sense.
- **F6's AC column is inconsistent**: the F-table says `AC-6`, the F↔AC table says `AC-7`. The F↔AC table is correct (AC-7 = existing tests green is the row that covers interactive `go test`; AC-6 is the named-but-empty test).

## 3. Terminal-API failure fault-injectability — F2/F3 yes, F4 NO (honestly labeled)

- **F2 (ioctl failure / `io.EOF`)**: fully injectable through the `readNoEcho` seam — AC-4 pins exactly this (canned `io.EOF` → exit 2, `read password:`). Verified in the module cache: x/term's unix `readPassword` returns the ioctl error from `IoctlGetTermios`/`IoctlSetTermios`, and `readPasswordLine` returns `io.EOF` on empty-EOF. The fail-closed structure (error before any read; no echoing fallback exists in the code) is also structurally testable.
- **F3 (bare Enter)**: injectable via canned `""` — AC-3.
- **F4 (Ctrl-C → 130, echo-left-off residual)**: **not fault-injectable through the seams.** The seam replaces `term.ReadPassword` entirely — SIGINT delivery, ISIG, and the deferred termios restore live in x/term's real implementation that seam tests never invoke. Also, "130" is the shell's 128+SIGINT for a signal-killed process; `Run` never returns it, so no unit test can assert it. The design correctly labels F4 manual with the upstream limitation (verified: `defer unix.IoctlSetTermios` restore at `term_unix.go:93` — design cites "49-63", minor line drift, substance right). A PTY subprocess test would be the only automation, and none exists in the repo. So: the user's question "is F-rows fault-injectable" answers *F2/F3 yes, F4 no, and the design says so* — that's honest, not a defect.

## 4. Hermeticity of the 6 new tests — PASS

All six use in-memory `io.Reader`/`io.Writer` + canned closures; zero `os.*`, env, PTY, or files. Deterministic regardless of the developer's terminal (the F6 claim). **Non-parallel justification**: the requirements doc (R2) explicitly mandates "Seam-mutating tests must not use `t.Parallel`"; the design complies and honestly admits no shared state exists (seams are parameters), so serial is spec fidelity + cheap, not a technical necessity. No hazard either way: Go runs serial tests before the package's parallel tests, so the six complete before `TestRun_EmptyPasswordIsUsageError` (the one real-stdin test) blocks. I confirmed the F6 "pre-existing stdin interaction" claim by running it — the test genuinely reads `os.Stdin` today (printed `sso-ctl hash: empty password` in my non-interactive shell).

## 5. Byte-identical claim — PASS for stdout/exit codes on ALL shapes; stderr scope is narrower than the R3 sentence

- **stdout**: byte-identical for *every* existing shape, including TTY (prompt/warning never touch stdout; `fmt.Println`/`fmt.Printf` bodies preserved verbatim).
- **exit codes**: 0/1/2 identical everywhere — parse error→2, `-h` (ErrHelp)→2, empty→2, read error→2, hash error→1; `fs.SetOutput(errOut)` + `fs.Usage = func(){usage(errOut)}` reproduce today's parse-error stderr in production (os.Stderr).
- **dispatcher contract**: `"hash": hashcmd.Run` at `main.go:57` confirmed; `Run(args []string) int` signature preserved; `main()` does `os.Exit(run(args))` so the code flows through. No other production caller exists.
- **stderr caveat**: the R3 sentence "stderr bytes … identical for every existing invocation shape" is **overstated**. It holds for the enumerated shapes (pipe, EOF, empty, quiet/non-quiet) minus three *intended* deltas: (a) the advisory warning on non-empty `--password` (R1), (b) the `Password: ` prompt on TTY (R2), (c) the **rewritten usage text (R4), which changes stderr for `hash -h`/`hash -x`** — usage-printing shapes are outside the parenthetical scope. Intent is clear; the sentence's broad reading conflicts with R4. On the TTY path, Ctrl-D also changes message (`read password: EOF` vs today's `empty password`) — same exit 2, documented in F2.

## 6. -race and the mandatory gate suite — PASS, with one pre-existing red gate to report

- `make ci` includes the `race` target = `go test -race -count=1 ./...` (root module → covers `cmd/sso-ctl/hashcmd`); AGENTS.md's `go test ./... -race` handoff gate likewise. All 11 tests (5 existing + 6 new) run under -race. Design's own `-count=10` flake pass on the six new tests omits `-race` (minor — `-race -count=10` would be strictly stronger).
- **Pre-existing gate failures (unrelated, must be reported separately per AGENTS.md §5)**: `go test -run 'TestMaintainability_|TestArchitecture_' .` is **red at HEAD today** — `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539 lines) and `TestArchitecture_DirectoryDepth`/`DirectorySubdirFanout` (the harness's own `docs/architect-analysis/auto/` run dirs; root fanout 24 > frozen 21). None cite hashcmd, and the change adds no new violations (no new packages/dirs; `main.go` 93→~150 < 500; fan-out frozen at 16 — confirmed `cmd/sso-ctl` has exactly 16 subdirs). The design lists the gate without noting it is currently red; an implementer following the design verbatim would see this unrelated failure.
- Supporting claims all verified: x/term v0.2.2 indirect at `go.mod:60`, both hashes at `go.sum:41-42` (promotion = zero go.sum diff), `x/sys v0.44.0` already indirect, no production Go file imports x/term today, `go 1.26.1` (so `t.Context()` is fine), T-9 gate row at implementation-gate.md:14, no other doc surface cites the usage text, and the analysis JSON's acceptance matches the design word-for-word.

**Bottom line**: ship-ready as a design, provided the implementer (a) pins F8 or explicitly accepts it as an untested residual, (b) fixes the F6 AC-column typo (`AC-7`), (c) tightens the R3 stderr sentence to the enumerated shapes, and (d) records the three pre-existing red gates in the change notes rather than being surprised by them at `make ci`.
