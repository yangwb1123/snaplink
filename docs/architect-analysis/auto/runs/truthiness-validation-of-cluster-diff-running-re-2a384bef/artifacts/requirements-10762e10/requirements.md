Done. Requirements specification written to `docs/architect-analysis/cmd-sso-operator-controller-b4-3-truthiness-requirements.md` (208 lines, house format matching the sibling apiv1alpha1 CRD-parity spec).

## Evidence verification results

Every cited file/symbol checked against HEAD:

| Citation | Measured | Verdict |
|---|---|---|
| `postClusterDiff` http.go:69-95 | http.go:82–118; zero structural validation at 108–117 | Confirmed (range offset ~13 lines, behavior exact) |
| `fetchRunningConfig` http.go:34-67 | http.go:49–80; only `Running == nil` check | Confirmed (offset, exact) |
| `runCheck` ssoconfigdrift_controller.go:118-150 | :130–164; `driftDetected: len(patch) > 0` at :158 | Confirmed (offset ~12 lines) |
| diff.go:20-27 emit set; ops at 59,61,79 | "Only add/replace/remove" at :27; add/remove/replace at 59/61/79 | Exact |
| 8 tests, no invalid-shape case | 8 `TestReconcile_*` at lines 139–327, hand-rolled fakes only | Exact |
| k8s-only deps, no go.work | k8s.io/* + controller-runtime only; root import is test-only (`adminpaths_parity_test.go`, via `replace`); no go.work | Confirmed, with nuance noted in spec |

**New findings surfaced**: (1) `HandleClusterDiff` rejects `len(snapshot)==0` with 400 (handlers.go:105) — this anchors acceptance (b): an empty running snapshot makes a 200 empty patch unverifiable by the server's own contract; (2) `RedactOps` preserves op/path structure, so the emit set is observable at the wire; (3) `applyResult` already keeps `DriftDetected` on failure — the "never reset to false" acceptance needs no status-code change, only the new failure path.

## Spec shape (bounded to the direction)

- **R1/R2**: two stdlib-only free functions in new `validate.go` — `validatePatch` (op ∈ {add,remove,replace}; `/`-rooted, strict RFC 6901 paths resolving into the snapshot with object-only intermediates, per-op add-parent/remove-replace-target rules mirroring the server's `diffMaps` recursion) and `validateRunningSnapshot` (non-empty object).
- **R3**: two call sites in `runCheck`, existing failure semantics (failed=true, token-free Message, `shortRequeueInterval`, status preserved).
- **12 machine-checked Given/When/Then cases** mapping 1:1 to acceptance (a)/(b)/(c) plus the 8-test regression, with the sharp "pre-seeded `DriftDetected=true` stays true" variant.
- **Deliberate non-requirements** (D2): no add-at-existing-key rejection, no `patch:null` distinction, no value-shape checks, no op-order checks — each documented with rationale to keep scope tight.
- Gate: `ci-modules` (Makefile:263); baseline verified green at spec time (controller 0.090s); new tests fail on HEAD by design.
