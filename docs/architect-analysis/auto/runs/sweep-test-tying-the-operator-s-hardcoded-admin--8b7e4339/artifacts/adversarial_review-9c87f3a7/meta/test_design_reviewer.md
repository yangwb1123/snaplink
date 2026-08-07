All verification is complete. Here is the adversarial review.

---

# Adversarial review: `TestAdminPathsMatchOpenAPIDocumentation` design

**Verdict: the design's core mechanics are sound and the acceptance mapping is 8/8 functional — but it contains one material factual overclaim (the "only tripwire" claim), one false gate justification (row 11), three evidence-drift errors (E12 count, CRD "precedent", gate-boundary claim), and one uncovered failure mode (operator-side method flip).**

## 0. What I independently re-verified (all confirmed)

- Consts at `ssoconfigdrift_controller.go:40-41` (E1 correction right; spec's 48–51 wrong); consumption at `http.go:50,58,67` (GET) and `:88,97,106` (POST); root consts at `consts.go:463,467`; openapi keys at `:5340`/`:5607`; `Makefile:263`; `go.mod:58` `gopkg.in/yaml.v3 v3.0.1 // indirect` with both go.sum hashes already present (lines 146–147), root `go.mod` has **no** `gopkg.in/yaml.v3` (uses `goccy/go-yaml`), and `shared/core` imports only stdlib → the tidy claim (promote only, zero go.sum additions, no MVS bump) is exactly right.
- **E15 path fix is correct**: from the package dir, `../../docs` = `cmd/docs` (nonexistent); `../../../docs/openapi.yaml` is right.
- Decode strategy: the real 18,219-line doc parses; `paths` is a 275-entry mapping; both keys carry exactly `get`/`post`; **no duplicate keys** (relevant because yaml.v3 errors on dupes — a latent parse-failure mode the design never considers; currently clean).
- R2 (untracked file, header self-reference confirmed) and R3 (`config_audit_test.go:88`, const-derived, default gate state, three phases via `fghrAssertIdentical`/`fghrNeverMountedBaseline` in `feature_gate_hotreload_test.go`) — mechanics exactly as claimed.
- Baseline green (`go test -count=1 ./controller/` → ok, 0.128s); operator production files import only within the module (binary stays root-free).

## 1. The coordinated-rename claim — **overclaimed (finding F1, material)**

§5 row 1's "the only tripwire that sees it" and the task evidence's "only catchable via the openapi anchor" are **factually false in the current worktree**, because the root suite already contains **committed** literal copies of both full paths:

- `TestConfigAuditAPI_SnapshotsWiredServesRedactedRunningAppliedDiff` (`config_audit_test.go:144,179` — verified present at `HEAD`, the worktree diff adds zero literal lines) GETs literal `/api/v1/admin/config/running` and POSTs literal `/api/v1/admin/config/cluster-diff` against a wired server expecting 200.

Under the design's own scenario (both Go consts renamed, doc untouched), the server re-mounts at the *new* const-derived paths → those literal requests 404 → **that existing test fails**. So the drift class is visible to `go test ./...` today, with no anchor. R2 passes by construction (true), R3 passes (true), but "only catchable via the anchor" is wrong.

The requirements spec's phrasing ("the one failure mode the *consts-only parity* cannot see") is defensible; the design's "only tripwire" escalation is not. The design conclusion still stands — the literal catch is *incidental*: the sibling R3's own comment boasts "const-derived paths (no literals)", i.e. the direction's philosophy is to delete exactly those literals, which would restore the blind spot; and this design explicitly forbids touching that file. Fix: reword to "the only **deliberate, refactor-proof** tripwire; incidentally visible today via committed literal copies in `config_audit_test.go` that the design neither relies on nor removes" — or, stronger, note that the design *should* (in a follow-up) de-literalize those root tests, since they are the same hardcoded-path class the direction exists to eliminate, in the one module where the consts are importable.

## 2. The 12-row table — actually 11 rows; row 11 is false; row 7 imprecise

- **Count**: the §5 table has 11 rows (coordinated rename, single-side drift, method flip, path removed/doc deleted/moved, `paths` restructured, yaml bump, server route renamed, gate flip, R2 regress, wrong-path-implemented, 50-line budget). The "12-row" premise is off by one.
- **Row 11 is false (F2)**: both maintainability gates explicitly skip `_test.go` (`maintainability_budget_test.go:71`, `maintainability_complexity_test.go:142`). No committed gate measures test-function length. The two-helper split is structurally fine (`loadOpenAPIDoc` + `assertDocPath` with `t.Helper()` is a good shape and makes the self-explaining failure messages achievable) — but its stated justification ("keeps functions under the 50-line budget", repeated in §1/§3.4/row 11) corresponds to no gate. Re-justify as readability/assertion-clarity, not budget compliance.
- **Row 7 conflation (F7)**: "Server route renamed (root consts renamed, mount changed…) → R3 fails" — if the root consts are renamed *and* the mount follows them (mechanical), R3 passes (const-derived); that variant belongs to row 1. R3 fails only when the mount drifts from the consts. The parenthetical should be "mount changed without the consts".
- Rows 2–6 and 8–10 are accurate. Row 8 (gate-default flip) is verified in source: `NewServer` is built with no `WithFeatureGates`, so phase 1 runs on the default state. Row 5's "loud by design" on a `paths` restructure is an accepted, stated trade-off — fine for a committed, reviewed doc.

## 3. §7 acceptance mapping — 8/8 named tests, but two mechanics caveats

| Case | Named test | Mechanics verdict |
|---|---|---|
| 1 | `TestAdminPathsMatchOpenAPIDocumentation` (net-new) | ✓ verified: doc parses, keys/methods present, equality with both const sides holds today |
| 2 | same, presence | ✓ `paths[opPath]` lookup misses on operator-const rename |
| 3 | same | ✓ test fails under coordinated rename — **but for the wrong stated reason (F5)**: under the stated assertion order (presence keyed by the *operator const*), the presence lookup misses *first*; the "doc-vs-root-consts mismatch" the mechanics column names only fires if assertion 3 is implemented as an independent composition-keyed lookup. As specified, assertion 3 is logically identical to R2. Specify the lookup key per assertion, or reword the column. Also: "fails even though R2 passes" is true, but the unstated "only tripwire" framing is F1-false |
| 4 | same, method/presence | ✓ `op["post"]` miss or path miss |
| 5 | same, `loadOpenAPIDoc` | ✓ `os.ReadFile` fatal; file is tracked (verified) |
| 6 | `TestAdminPathConstsMatchRootOwnedConstants` | ✓ unchanged, mechanics verified |
| 7 | `TestConfigAudit_OperatorPaths_GateAwareTruthiness` | ✓ three-phase mechanics verified line-by-line; helpers exist; default gate state confirmed |
| 8 | whole `./...` suite | ✓ gate command matches `Makefile:263`; E12's "(10 package-wide)" parenthetical is stale — the truthiness file holds **six** `TestReconcile_*` (14 package-wide), though case 8's own wording is unaffected (F4) |

**Residual gap (F6)**: the method-fidelity leg pins only the *doc* side. Nothing pins `http.go`'s method usage — the operator's mock servers enforce only Authorization and body, never the method (verified); R1's hardcoded `get`/`post` goes silently stale if `http.go` flips; R2/R3 are method-agnostic. A GET→POST flip on `runningConfigPath` breaks production (405s) with every test green — the mirror image of row 3. The design should either declare this an explicit residual gap or bind the method via a production const (out of current scope); as written, it claims method-fidelity coverage it doesn't fully deliver.

## 4. Smaller accuracy items

- **F3**: "CWD assumption precedented by the CRD-parity test" (§3.4/§4) — **no CRD-parity test exists**: repo-wide, no `.go` file references `crd-ssoconfigdrift` (the sibling design's own E9 admits it; the yaml is tracked but test-less). The precedent is a *planned* sibling design, not a landed test. The CWD claim itself is documented Go behavior and needs no precedent — cite that instead.
- **F8**: §4's "root gates do not descend into nested modules" is not universally true: the maintainability walk's `skipDirs` is name-based and lists only infra module dirs (`kms`, `saml`, …) — it **does** descend into `cmd/sso-operator` non-test files today (all within budget, so invisible). Immaterial to this design (the new test file is exempt either way), but the blanket claim is wrong.

## 5. Required fixes before implementation

1. Reword the coordinated-rename claim (§5 row 1, §1 verdict, §7 case 3): "deliberate tripwire; not the *only* one — committed literal copies in `config_audit_test.go:144,179` catch it today, and would stop doing so under the direction's own no-literals refactor; the anchor makes the catch durable."
2. Fix row 11 (drop the maintenance-gate justification; re-justify the split stylistically) and correct the row count if it must be stated.
3. Specify `assertDocPath`'s lookup keys/order so case 3's mechanics column is literal; state assertion 3's redundancy with R2 or give it an independent composition-keyed lookup.
4. Correct E12 (14 `TestReconcile_*` package-wide, not 10) and the CRD-parity "precedent" reference.
5. Add an explicit row/caveat for operator-side method flips (unpinned), and fix row 7's parenthetical.

None of these invalidate the change: the anchor test, the E15 path fix, the tidy mechanics, and the R2/R3 pins are all correct as designed and the acceptance mapping fails correctly under every drift scenario in its table — it just doesn't uniquely own the coordinated-rename catch, and its evidence table carries four stale claims that should not ship into a committed test's rationale.
