All citations check out exactly (`http.go:50,58,67` GET running, `:88,97,106` POST cluster-diff, 8 `TestReconcile_*` tests). Spec complete.

## Summary

**Deliverable:** `docs/architect-analysis/cmd-sso-operator-controller-b4-3-adminpaths-sweep-requirements.md` — evidence-verified requirements spec for the selected direction (entry 3 of `cmd-sso-operator-controller-6371f05a.json`), in the house format used by the sibling specs.

**Evidence verification outcomes** (all primary citations confirmed):

| Citation | Result |
|---|---|
| `ssoconfigdrift_controller.go:47-51` hardcoded paths | Confirmed (consts at 48–51; consumed at http.go:50,58,67 / 88,97,106) |
| `shared/core/consts.go:34,463,467` (`PathAPIPrefix` + group-relative consts) | Confirmed exact |
| `docs/openapi.yaml:5340` (running, `get`, 200/401/501) and `:5607` (cluster-diff, `post`, 200/400/401/501) | Confirmed exact; `paths:` at 143, `openapi: 3.0.3` |
| `Makefile:263` (`ci-modules` operator gate) | Confirmed exact |
| `cmd/sso-operator/go.mod` "no root dependency" | **Stale** — worktree already carries test-only `require`+`replace => ../../` (sibling direction landed); production binary stays root-free |
| "no test asserts the concatenation" | **Stale** — `adminpaths_parity_test.go` + `TestConfigAudit_OperatorPaths_GateAwareTruthiness` already exist uncommitted in the worktree |

**Key finding:** two of the direction's three acceptance legs are already implemented in the worktree (consts parity; server-side gate-aware sweep answering 200 when wired — stronger than the acceptance's non-404/non-501). The **net-new leg is the openapi.yaml anchor**: nothing in `cmd/sso-operator` parses the OpenAPI document today, and it is the only tripwire that catches a *coordinated* rename of both Go consts leaving the documented contract behind.

**Spec structure:** 9 testable Given/When/Then acceptance cases (graded 9/9 machine-checked under `make ci` → `ci-modules`), a single-file change surface (extend `adminpaths_parity_test.go`, ~60–70 lines, `gopkg.in/yaml.v3` already in the module graph), no production edits, no go.work, no new module paths, and the two landed legs pinned as regressions rather than re-implemented.
