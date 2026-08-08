Design artifact delivered: `docs/architect-analysis/auto/runs/seeding-path-secrecy-make-stdin-the-default-credential-channel-and-warn-or-refuse-on--password-whose-plaintext-is-visible-in-process-argv-e4b01429/artifacts/design-a77de8a6/task-1-design.md` (394 lines).

## Evidence verification — all claims confirmed

Every citation in the requirements artifact was re-checked against HEAD `078eb6d7`:

- **Code citations** — all substantively true with small line drifts (warnings at main.go:7-8 vs cited 8-9; flag at 32 vs 33-35; call site 39 / def 65-75 vs cited 40-49; usage 77-91 vs 75-81; FlagWins test 10-16 vs 14-21). The requirements doc had already declared these drifts.
- **Terminal API** — `charmbracelet/x/term v0.2.2` at go.mod:60 (indirect), both hashes in go.sum:41-42, `IsTerminal`/`ReadPassword` verified in the module cache; `x/sys v0.44.0` already indirect. Promotion = one-line go.mod move, **zero go.sum diff**. Bonus finding: the unix `ReadPassword` clears only `ECHO` (keeps ICANON/ISIG), returns `io.EOF` on empty Ctrl-D.
- **T-9 decoding** — confirmed ("T-9（introspect 无凭据 → 401，回归保留）" at implementation-gate.md rows 14/77).
- **No prior implementation, no other doc surface, dispatcher contract** (`"hash": hashcmd.Run` at main.go:57) — all confirmed. Baseline `go test ./cmd/sso-ctl/hashcmd/` green.
- **One new constraint surfaced** (not in the evidence): `TestRun_EmptyPasswordIsUsageError` *already* blocks on a real stdin read today, so interactive `go test` is a pre-existing interaction — the change makes it friendlier, not worse (documented as F6).

## Design decisions (from the artifact)

- **Public surface frozen**: `Run(args []string) int` becomes a 3-line wrapper over internal `run(args, in, out, errOut, isTTY, noEcho)` — seams as parameters (race-free by construction, no globals), `readPassword` signature/body untouched, stdout bytes and exit codes byte-identical for every existing invocation shape.
- **`fs.Visit` nuance**: the TTY prompt fires only when `--password` is *entirely absent*; a named-but-empty `--password ''` stays on the legacy pipe path (preserves today's semantics; new test AC-6 pins it).
- **Warn-only** (per acceptance): stderr advisory naming `--password`/`argument list`/stdin, exit 0; no refusal, no `--allow-argv`, no `--format`/`--cost`, no server changes.
- **Failure modes**: 8 rows (F1-F8) — fail-closed on terminal-API failure (exit 2, never an echoing fallback), documented residual for Ctrl-C leaving the terminal no-echo (upstream x/term defer-restore limitation).
- **Acceptance mapping**: AC-1..AC-9 with Given/When/Then, plus F↔AC coverage; 6 new non-parallel tests (5 required + 1 pinning the named-but-empty semantics); existing 5 tests zero-edit.
- **Budgets**: `Run` → 3 lines, `run` ~40, complexity ~6, main.go 91→~150, fan-out untouched.
