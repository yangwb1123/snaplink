Verification complete. Report: `docs/architect-analysis/auto/runs/emit-form-urlencoded-bodies-on-the-credential-en-85cbe797/artifacts/gap-closure-verification-29f4c0b1/report.md`

## Headline finding: the design was never revised after the G1–G6 review

Design doc mtime is **22:10**; the three reviewers ran **22:15–22:18**. No post-review revision exists (nothing newer in-tree outside the run's own DECISIONS.md; `git diff HEAD` on the design is empty). Every closure claim was therefore checked against the same text the reviewers rejected.

## Per-gap result: 0 of 6 closed

| Gap | Status | Evidence |
|---|---|---|
| **G1** — presence-based guard + `params: {}` golden | **OPEN** | §2.4 still emits `if (body.params && Object.keys(body.params).length > 0)` — the exact predicate G1 flagged; C1 narrative still says "non-empty `params`". Sibling pins `PostForm.Has("params")` (decisions doc line 96) = presence, any value. `params: {}` would pass the guard, emit `params=%7B%7D`, and 400 `mfa_invalid` post-sibling. The `params: {}` golden appears **nowhere** in design or requirements — only in the reviewer artifacts |
| **G2** — C5 emission pins, both runtimes | PARTIAL | TS closed (AC2(b) ordering assert + AC1 `form: true`/no-`JSON.stringify`). Python half-pinned: `form=True` asserted only on `post_mfa_complete`; the `post_token` pin was weakened to "unchanged signature" (requirements had "urlencode + form header for post_token"; the design restatement dropped it); body-creds retention never asserted |
| **G3** — exec-based goldens, no `t.Skip` | **OPEN** | No execution harness specified — goldens would be pure-Go string assertions (verified: current `emit_test.go` has zero exec tests; string presence can't prove coercion). No `t.Skip` prohibition. F10 `[""]`→`key=` and TS-side bool golden absent from AC rows; exact header string pinned only in the mjs E2E arm. `bun run build` broken in clean checkout (no devDependencies/tsc — only `bunx tsc` works) and `make ci` (Makefile:268) has no bun/tsc step |
| **G4** — mechanical F1 interlock | **OPEN** | §4 F1 detection is still "Code review of merge order"; no ordering constraint in either campaign file; no blocked/enabled-on-F1 E2E arm; the `§6.5` reference is still dangling (no §6.5 exists) |
| **G5** — full-file drift test in `emit_test.go` | **OPEN** | AC4 still defers: "once the T-9 drift gate (sibling direction) is in place — **no new gate added here**". F8's claimed detection ("`make ci` regeneration check") does not exist — verified Makefile:268 and cli.py: no gensdk artifact diff anywhere |
| **G6** — golden-set additions | PARTIAL | F10 empty-element and TS bool golden absent; exact header string only in the mjs arm; `body !== undefined` form-branch mirror not stated |

## Confirmations

- **`params: {}` in the golden set: NO** — absent from both docs.
- **No gap defers to undocumented manual steps: NO** — G4 defers to merge-order code review; G5 defers to a nonexistent T-9 gate; F8's detection mechanism is fictional, leaving AC1's "git diff clean" as an unwired manual check.
- Outside G1–G6: sibling Drift A is still live (sibling design step 4 plans its own 4-op SDK emission at the same `gen_ts_runtime.go`/`gen_py.go` lines and same artifacts this design owns at 7-op scope — unresolvable merge collision, same doc-gated class as G4).

The C1–C7 corrections and the schema-driven 7-op mechanism themselves remain sound against the code — the failure is entirely in the test-gate layer, which is the whole point of the G-list.

VERDICT: FAIL — the revised design closes 0 of 6 binder-conformance gaps (G1, G3, G4, G5 open; G2, G6 partial): the C1 guard is still non-empty-based with no `params: {}` golden, no exec-based serializer goldens exist, the F1 interlock remains code-review-only with no campaign ordering, and AC4 still defers drift detection to a nonexistent T-9 gate — the design was last modified before the G1–G6 review ran, so none of the six findings is addressed in any revision.
