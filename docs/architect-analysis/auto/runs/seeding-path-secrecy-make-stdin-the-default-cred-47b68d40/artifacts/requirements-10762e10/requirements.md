Requirements specification produced and evidence-verified.

**Deliverable:** `docs/architect-analysis/auto/runs/seeding-path-secrecy-make-stdin-the-default-credential-channel-and-warn-or-refuse-on--password-whose-plaintext-is-visible-in-process-argv-e4b01429/artifacts/requirements-e4b01429/requirements.md`

**Evidence verification (all 5 citations re-checked against HEAD `078eb6d7`):**

| Citation | Verdict |
|---|---|
| `main.go:8-9` (warnings) | Exact — "avoid in shared shells", "no echo on a TTY is NOT guaranteed" |
| `main.go:33-35` (`--password` flag) | Exact — flag at line 34 |
| `main.go:40-49` (readPassword flag-wins, bufio) | Call site at 41; definition at 67-77 (`bufio.ReadString` at 72) — drift 18-27, substance true |
| `main.go:75-81` (usage text) | `usage()` at 79-91 — near-exact |
| `main_test.go:14-21` (FlagWins pins semantics) | Test at 10-16 — true, drift 4-5 |

**Supplementary findings:**
- **No prior implementation** — the earlier campaign `add-a-no-echo-tty-password-prompt-and-argv-leak--964b68fb` failed at requirements stage (agent exit 1, no artifact); zero `IsTerminal`/`ReadPassword` consumers in `cmd/` today.
- **Terminal API verified available** — `charmbracelet/x/term v0.2.2` (go.mod:60, indirect) exports `IsTerminal` + no-echo `ReadPassword`; promotion needs no go.sum change.
- **"T-9-style" decoded** — `docs/campaigns/implementation-gate.md` row 4: T-9 is the B4 campaign's regression pattern (guard + preserved behavior both pinned).
- **No other contract surface** — grep confirms zero docs outside `architect-analysis/` cite the tool's usage text; so R4's doc update is confined to the package doc + `usage()`.

**Spec contents (acceptance preserved, made testable):** R1 stderr warning on `--password` naming argv exposure (tests `TestRun_ArgvPasswordWarnsOnStderr` / `TestRun_StdinPathSilent`); R2 no-echo TTY prompt via injectable isatty/no-echo seams (tests `TestRun_TTYPromptPath` / `TestRun_TTYPromptEmpty` / `TestRun_TTYFlagWins`, serial to avoid seam races); R3 zero edits to the five existing tests (baseline confirmed green); R4 doc/usage update. Explicit non-goals: no refusal/`--allow-argv` (prior campaign's broader scope), no `--format`/`--cost`, no server changes. Budget and gate constraints included (`Run` ≤50 lines via extracted helpers, `go build`/`vet`/`-race`/`make ci`).
