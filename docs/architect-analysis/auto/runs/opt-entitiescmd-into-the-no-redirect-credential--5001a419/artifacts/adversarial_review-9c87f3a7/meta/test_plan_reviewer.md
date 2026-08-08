The extended design artifact is complete and verified against the code. Summary of what was delivered:

## Deliverable

**`docs/architect-analysis/auto/runs/opt-entitiescmd-into-the-no-redirect-credential--5001a419/artifacts/design-a77de8a6/task-1-design.md`** — rewritten from the 25-line tenants/users summary into the full 11-site design with acceptance mapping extended from A1–A6 to A1–A8.

## Acceptance mapping (every row has exact test names, entry points, and pre/post-fix expectations)

- **A1 — pre-fix repro per newly pinned surface** (S4–S11): table with test name, real subcommand vector, method/path/body, and the expected FAIL observation — exit 0, target counter > 0, `Authorization: Bearer` (and replayed body for the 5 write surfaces) at the target, via the 307 two-server rig.
- **A2 — post-fix tests**: exit 1 + target counter 0 per surface, with two honest documented deviations: tui asserts error-return (bubbletea renders data errors in the status line, not exit codes), auditverify pins at `readFromURL` (`errorf` → `os.Exit(1)` is pre-existing, byte-identity contract R4).
- **A3 — stderr message-pin**: pinned §3 template (`<prog>: <verb> failed (HTTP <code> redirect to <redactURL(Location)>): <hint>; body: <echo>`) with a golden apiclient test (userinfo-redacted Location, no-Location clause, 200-byte truncation, sensitive-field redaction, empty body) plus per-surface stderr-capture assertions (redirect wording, per-surface hint, truncation marker, bearer never in stderr, stdout empty).
- **A4 — byte-identical non-3xx regression**: exact per-package commands with test counts (16/6/3/2/3/3), `TestStatusMessage_Non3xxByteIdentical`, and tui's first-ever non-3xx baselines.
- **A5 — F3 boundary pin**: all tests enter through exported `Run` entry points; tui via extracted `newClient()` (shared construction path, UI not unit-testable — stated explicitly).
- **A6 — F4 verification**: 307-only mandate with the 302-reasoning (POST→GET body drop can't pin the F1 vector) and a zero-hit grep command.
- **A7 — auditverify raw-client mirror**: `TestReadFromURL_NoRedirect`/`TestReadFromURL_RedirectMessage` must exercise the main.go:414 construction itself, never a hand-built client; pre-fix 3 target hits / post-fix counter 0.
- **A8 — gates**: build/vet/maintainability/race/`make ci`, plus config-reference env-var row.

All cited line numbers were re-verified against the tree (tenants.go:254/275/298, clients.go:132/158, tokens.go:74/133, sessions.go:132/158, tui/run.go:38, auditverify/main.go:414/450, apiclient.go:60-61/86/92, check.go:63, sweep.go:218/234); two citations were corrected during verification. No `.go` files were modified, so no build gates apply to this change.
