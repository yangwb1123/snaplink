All checks pass. The work is complete:

## Validation result: PASS — full design body reconstructed and committed

**Commit `4f32592a`** replaces the 26-line summary at `docs/architect-analysis/auto/runs/encode-b4-token-claims-and-scope-registry-invari-dddba3e2/artifacts/design-a77de8a6/task-1-design.md` with the full 598-line design body (D1–D6, FM-1..FM-8 table, 6 migration steps + rollback, acceptance mapping, exact note text, complete helper code, simulation record). Unrelated worktree changes preserved; only the artifact was committed.

**Every hardening is incorporated and mechanically pinned:**

| Hardening | Where |
|---|---|
| Window-scoped markers ("Standard pattern:" → "After filling in your logic") | `assertGrantContract` §5; probe 13/13b prove outside-window prose can neither satisfy (FP-1) nor interfere (FP-2) |
| Composite `core.ErrorBody(core.ErrInvalidScope)` marker | A1 error-shape assertion; probe 6 catches the `errorBody(ctx,…)` trace-wrapped regression |
| `count(issuer.Issue(` == 1 guard | A1 issuance assertion; probes 7/10 (note quoting the literal, second issuance) |
| `RejectUnregistered` presence marker | `once("registry note function", …)` — plus the `rejectUnregisteredScopes` seam marker (both pinned); probe 9 |
| "Two gates" teaching beat | Note opens "Two gates protect scopes on a custom grant, and this branch is the one the server cannot do for you" — registry registration vs per-client `AllowedScopes` allowlist |
| F7 roles-surface deferral | Step-3 comment: handoff pinned when B4-1 lands; `Subject.Claims` is `map[string]string` → `ext`, not the T-8(a) `roles` claim |
| Note after branch, no `issuer.Issue(` literal | Placement check (error-shape @854 < note @1076) + count guard; note wording audited |

**Marker simulation re-run against the final template text** (scratch module, `go1.26.5`): the committed template is byte-identical to the simulated input — all 8 window markers occur exactly once with correct ordering (split 754 < issue 2911; roles 2001 < issue 2911; issue 2911 < `}, grantedScopes)` 3087), zero backticks, template parses/renders, 13 negative probes all yield the designed verdicts (11 named failures, 2 documented FP-3 tolerances), and the unmodified template fails the gate (red proof — the gate is load-bearing).

One correction found and fixed during reconstruction: my first template extraction dropped the `package {{.Package}}` line (line 139 shares the `const` prefix) — caught by review, rebuilt, re-simulated, and re-verified byte-exact in the committed blob.
