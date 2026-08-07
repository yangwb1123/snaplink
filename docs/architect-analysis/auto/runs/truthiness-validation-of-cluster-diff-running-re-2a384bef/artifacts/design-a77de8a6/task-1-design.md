Verification complete. All evidence claims check out against HEAD; the design is written to `docs/architect-analysis/cmd-sso-operator-controller-b4-3-truthiness-design.md` (sibling house format).

## Evidence verification (all 12 claims)

| Claim | Verdict |
|---|---|
| `postClusterDiff` http.go:82–118, zero structural validation | Confirmed (unmarshal/return block at 108–113, no op/path/resolution check) |
| `fetchRunningConfig` http.go:49–80, only `Running == nil` | Confirmed; `{"running": {}}` passes today |
| `runCheck` :130–164, `driftDetected: len(patch) > 0` at :158 | Confirmed, exact |
| `applyResult` :177–186 writes status only when `!failed` | Confirmed — "never reset to false" needs no change |
| diff.go emit set: doc :27, add/remove/replace at 59/61/79, escaping 86–92 | Confirmed, exact |
| `HandleClusterDiff` 400s empty snapshot (handlers.go:105) | Confirmed — anchors acceptance (b) |
| `RedactOps` redact.go:33–45, non-nil `[]` on the wire | Confirmed |
| 8 `TestReconcile_*` at 139/168/188/211/232/287/305/327, hand-rolled fakes | Confirmed, exact; fixtures match the spec's claims |
| k8s-only deps, test-only root import via `replace`, no go.work | Confirmed |
| `Makefile:263` = sso-operator `ci-modules` command | Confirmed, exact |
| B4-3 campaign mapping, budgets (2→3 non-test / 4→6 files) | Confirmed |

**One sharpening found (E5a):** the server emits the path `"/"` for an empty-string snapshot key (`childPath = path + "/" + key`), so validation must resolve `"/"` by key lookup rather than rejecting short paths — the spec's rules already permit this; the design makes it explicit.

## Design highlights

- **API changes**: none to wire/CRD/config/status. Two unexported stdlib-only functions (`validatePatch`, `validateRunningSnapshot`) in new `validate.go`, plus two guards in `runCheck` (~43 lines, inside budget). `validatePatch` is a strict superset of the server's documented emit set — sound by construction (no false rejects on legitimate data), which is the correct direction for truthiness.
- **Concrete algorithm**: strict left-to-right RFC 6901 unescape (`~0`/`~1` only, injective on emitted segments), split-before-unescape, map-only traversal with object-only intermediates, leaf existence by key (any type incl. `null`/maps — type-change `replace` is legitimate), `add` parent = root for single-segment paths.
- **Compatibility**: 8 existing tests byte-identical; new wording only on shapes the server cannot emit; root-free module posture and go.mod untouched.
- **Failure modes**: 8-item table — panic-safety (ok-checked assertions), token-leak impossibility (validators never see tokens), bounded 30s requeue, empty-snapshot+empty-patch pair caught before the POST, plus pre-existing out-of-scope items (unbounded `io.ReadAll`, float64 precision) documented.
- **Migration**: 8 ordered steps with rollback = 2-line revert that trips the new tests.
- **Acceptance mapping**: 12/12 spec cases + 6 design-extras (X1–X6 covering the empty-key path, escaped-key round-trip, `-` segment, null/map leaves, adversarial paths), each mapped to a named Go test and a,b,c acceptance.

No files were modified other than the new design document; the worktree is otherwise untouched.
