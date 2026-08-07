The probe is complete. Report written to `docs/architect-analysis/auto/runs/encode-b4-token-claims-and-scope-registry-invari-dddba3e2/artifacts/adversarial_review-9c87f3a7/meta/hardened_marker_probe.md` (alongside the other reviewer artifacts; the harness commits per stage, so I left the tree untouched otherwise).

## Results (26 probes × 4 helper variants, all expectations matched — actual run, not simulation)

Harness at `/tmp/markerprobe/probe.go` (rerun: `GO111MODULE=off go run probe.go <repo-root>`); it extracts the committed `grantTemplate` live, splices the design's reconstructed 4-step window (gate → roles → issuance passing `grantedScopes`), and runs the helper as designed (h1: window-scoped, composite M1/M2, presence+order, `count==1`), two strengthenings (h2: +status-inclusive M2', +M8 note marker; h3: +word-boundary `Roles(`), and the pre-hardening naive helper for contrast.

**The six requested mutations — all caught by the as-designed helper**, with the catching markers:
1. **Branch deleted, prose-only mention** → caught (M1+M2 composites; the bare-vocabulary prose can't reproduce the contiguous composites)
2. **Doc comment `issuer.Issue(` above the gate** → caught inside the window (M7 count→2); the *same* comment outside the window passes all hardened variants — window-scoping kills the first-occurrence interference class (naive fails it spuriously)
3. **Symbol swap** → `RolesForUser(` caught (M5); **`ResolveRoles(` evades h1/h2** — `Roles(` is a substring — only the word-boundary regex (h3) catches it
4. **Second `issuer.Issue(`** → caught (M7); naive is blind to it (P)
5. **Reordered markers** → issuance-before-gate and issuance-before-roles caught (M3 order); roles/gate step swap passes by design (only "before issuance" is an invariant)
6. **Raw `req.Scope` issuance** → caught (M6); the ungated-alias variant (`grantedScopes := oauth.SplitScope(...)`) keeps M6 alive but fails M1+M2 — layered defense confirmed

**Remaining classes**: FN-1 full-branch prose quote (irreducible for comment-gated text; h2 shrinks it to a single full-line quote); FN-2 `ResolveRoles` (closed by h3); FN-3 registry note dropped and FN-4 status 400→500 (both closed by h2); FP-A identifier rename → spurious fail (deliberate vocabulary pinning); FP-B in-window `issuer.Issue(` prose (M7's inherent cost, per F4/F5); FP-C window-anchor rewording → fail-closed.

**Drift immunity**: confirmed empirically — helper code has zero line-number references; 40-line shift and full reflow both pass; the only sensitivities (marker-internal whitespace, anchor wording) fail closed.

**Recommendations**: land M2' (status-inclusive composite), M5' (`(^|[^A-Za-z])Roles\(`), and M8 (`rejectUnregisteredScopes` presence) — three one-line changes that close FN-2/3/4 — and document FN-1/FP-A/FP-B in the helper's doc comment.
