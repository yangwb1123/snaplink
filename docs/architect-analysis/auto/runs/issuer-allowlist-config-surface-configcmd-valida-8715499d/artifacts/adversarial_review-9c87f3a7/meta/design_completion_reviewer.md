All eight checklist items verified and incorporated. Summary of the design-gate pass:

**Artifacts updated (were NOT incorporated before this pass — the mapping doc still listed F-1..F-6 as open flags):**

1. **Row (a) G1→G2** — design artifact's acceptance bullet now pins (a) to **G2** (flag on, no issuer); G1 stays the flag-off sentinel case under (c). Mapping §5 marks F-1 resolved.
2. **C7 omission arm added** — C7 is now three-armed: both keys → exit 0, unknown key → exit 1, `issuer_allowlist` set + `require_configured` omitted → `validate-schema` exit 0. FM-7 closed both ways (C6 types + C7(iii) pins the Required-heuristic's actual claim).
3. **C4 empty-allowlist arm added** — flag on, valid issuer, no `issuer_allowlist` key → exit 1 with stderr naming `server.issuer_allowlist`; FM-3's operator-facing diagnostic now pinned end to end.
4. **FM-5 pinned explicitly** — new **G16** (flag on, mismatched `base_url` → OK) *and* the one-line fixture comment on C4 ("base_url deliberately mismatched — dead-key coherence check must not exist").
5. **G11 added to FM-2's pin list** — design artifact FM-2 bullet now reads G4/G8–G12/G15/C4 with port folding named; verdict table consistent.
6. **FM-9 reporting contract (mapping §8.1, binding)** — pre/post gate diff must be empty; the three failures cited verbatim, re-reproduced live at HEAD `15b488e4` in this pass: `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go` 539 lines), `TestArchitecture_DirectoryDepth` (auto/runs tree), `TestArchitecture_DirectorySubdirFanout` (`docs` 18, `auto/runs` 288, root `.` 24 > 21).

**Confirmations:**
7. **No uncovered failure modes** — post-fix verdict table pins all 9 FMs (FM-3, FM-5, FM-7, FM-9 no longer gaps); exit-1 (a)/(b)/(c) pinned at configcmd + config layers, (c) also at binary.
8. **W1 both-states sentinel** — W1 is now three-armed: (i) flag-on non-member rejection, (ii) sentinel + `require_configured: true` → "must not equal", (iii) sentinel flag-off → same error. W1(ii) catches an implementer who moves the check inside the gate while default-off configs still pass; existing `TestConfigRejectsSDKSentinel` (flag-free) and `TestConfigAcceptsRealURLIssuer` (reverse direction) remain as anchors.

Gate verdict written to `artifacts/design_gate-6a76b0dd/task-1-design-gate.md` (no Go edits, so no build gates triggered; the maintainability/architecture tests were re-run only for FM-9 evidence):

**VERDICT: PASS** — all six coverage flags (F-1..F-6) are incorporated in the design and mapping artifacts (row (a) pins G2, C7 omission arm, C4 empty-allowlist arm, G16 + fixture comment, G11 in FM-2's pin list, FM-9 reporting contract citing the three pre-existing failures verbatim), W1 asserts sentinel rejection under both require_configured states, and the re-verified tree facts leave no failure mode uncovered.
