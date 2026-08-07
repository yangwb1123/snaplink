All four verification targets are confirmed. Final state of the worktree is byte-identical to baseline.

## Verification report — migration steps vs. dirty worktree

### 1. `go mod tidy` (step 3) — **CONFIRMED**, one cosmetic precision note

Experiment: stand-in `zz_tidy_verify_test.go` in `apiv1alpha1/` importing `gopkg.in/yaml.v3` (faithful proxy for the CRD-parity test's import — nothing in the module imports yaml today, so the promotion is genuinely caused by the new tests), then `go mod tidy` with go1.26.5 (= Makefile `GO ?= go`).

- **go.mod delta vs baseline = exactly the yaml.v3 move**: `gopkg.in/yaml.v3 v3.0.1 // indirect` removed from the indirect block (line 58) and added as `require gopkg.in/yaml.v3 v3.0.1` — same version, zero other line changes (diff-of-diffs shows only hunk-header shifts).
- **Precision note**: tidy emits the promoted require as a *standalone stanza after the first require block* (new line 15), not merged into the existing direct block — Go 1.26's minimal-churn block preservation. The design's "one-line block move" holds in substance (one line out, one in), but "moves to the direct block" is slightly imprecise about placement.
- **Sibling path-parity edits preserved verbatim**: the `replace github.com/yangwb1123/snaplink => ../../` directive, the `// test-only parity import of shared/core` require (comment included), and all version bumps (cbor 2.9.2, x/net 0.53.0, x/sync/sys/term/text/time, x/mod 0.35.0) — byte-identical in the post-tidy diff. `go.yaml.in/yaml/*` fork and `sigs.k8s.io/yaml` stay indirect.
- **`go.sum` byte-unchanged**: sha256 `2df2b355…` before and after; the 36-line sibling diff is untouched.
- **Untracked `controller/adminpaths_parity_test.go` untouched**: sha256 `61412a35…` before and after; still untracked.
- Worktree fully restored afterward (all three baseline sha256s verify).

### 2. ci-modules (Makefile:263) is the true detection boundary — **CONFIRMED**

- Line 263 is exactly `cd cmd/sso-operator && $(GO) build ./... && $(GO) test -race -count=1 ./...` inside `ci-modules` (target at 250); `ci:` (265) includes `ci-modules`, so `make ci` reaches the operator module only through this gate.
- Root `go list ./...` returns **0** sso-operator packages — `go build/vet ./...` and the `TestMaintainability_|TestArchitecture_` root gates physically cannot descend into the nested module.
- The full gate command passes on the current tree (controller 1.455s, including the untracked parity test).

### 3. One-line rollback — **CONFIRMED**, tripwire fails as designed

- HEAD `types.go:147–148` still aliases (`out.BearerSecretRef = in.BearerSecretRef`), byte-identical to HEAD (sha256 `c2b7c6ef…`).
- My first tripwire attempt passed spuriously (pointer *replacement* via `&flipped` instead of mutation *through* the shared pointer); corrected to `*out…Optional = !*out…Optional` — then it **fails on HEAD** ("D1 aliasing: mutating the copy's *Optional leaked into the source"), reproducing D1.
- After D1a: tripwire passes, `go build/vet` green, diff is exactly the one pinned line.
- After reverting the line: `git diff` empty, sha256 equals HEAD exactly, and the tripwire **fails again** — the designed tripwire semantics hold in both directions.

### 4. Spot-checks of design citations

- E4 correction confirmed verbatim: comment 38–39, `newScheme` 40, `corev1.AddToScheme` 43, `drift.AddToScheme(s)` 46.
- E8 mostly confirmed: yaml.v3 v3.0.1 indirect at go.mod:58; go.sum lines are actually 145–147 (design said 146–147 — includes the `v3.0.0-20200313…/go.mod` hash line; cosmetic).
- Case-14's "tests fail as designed" is verified via the throwaway tripwire (the real test files are the deliverable's next step; `apiv1alpha1/` is back to its single original file, suite `[no test files]`).

Worktree state now: exactly `M go.mod, M go.sum, ?? controller/adminpaths_parity_test.go` — the pre-existing sibling state, untouched. Migration steps 1, 2, 3, and 6 of the design are all executable as written; only the tidy-stanza placement wording in §3.2/step 3 deserves a cosmetic touch-up.
