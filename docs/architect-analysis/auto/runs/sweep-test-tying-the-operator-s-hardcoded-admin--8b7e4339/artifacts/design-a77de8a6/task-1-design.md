Design delivered. Verification summary:

## Evidence verification results

**Confirmed exact (13/16):**
- `http.go:50,58,67` (GET `baseURL+runningConfigPath`) and `:88,97,106` (POST `baseURL+clusterDiffPath`) — all six consumption points
- `shared/core/consts.go:34` `PathAPIPrefix`, `:463` `PathAdminConfigRunning`, `:467` `PathAdminConfigClusterDiff`; composition matches the operator consts byte-for-byte
- `docs/openapi.yaml`: `openapi: 3.0.3` at :32, `paths:` at :143, running `get` (200/401/501) at :5340, cluster-diff `post` (200/400/401/501) at :5607
- `Makefile:263` — operator line inside `ci-modules` (target at :250)
- `cmd/sso-operator/go.mod` — test-only root `require`+`replace => ../../`, no go.work
- Baseline green (`go test -count=1 ./controller/` → ok, 0.098s)

**Three corrections found:**

1. **Consts line drift (cosmetic):** the evidence/spec claims `ssoconfigdrift_controller.go:47-51`; actual is 39–42 (`runningConfigPath` :40, `clusterDiffPath` :41) — ~8 lines stale from sibling worktree edits.
2. **Naming conflation:** the landed parity leg is `TestAdminPathConstsMatchRootOwnedConstants` in `adminpaths_parity_test.go` (untracked); the quoted `TestConfigAudit_OperatorPaths_GateAwareTruthiness` lives in `interfaces/sso/config_audit_test.go:88` (root module, modified). Both exist — the evidence's "stale" verdicts are accurate.
3. **Real bug in the spec's R1:** `../../docs/openapi.yaml` from `cmd/sso-operator/controller` resolves to `cmd/docs/...` — **does not exist**. Correct path is `../../../docs/openapi.yaml` (verified with `ls`). The design corrects this; the spec's version would fail with a misleading file-missing error.

## Deliverable

`docs/architect-analysis/cmd-sso-operator-controller-b4-3-adminpaths-sweep-design.md` (companion to the existing requirements spec), in the house format of the sibling CRD-parity design:

- **§3 API changes** — no production API; the only delta is yaml.v3 promoted indirect→direct (v3.0.1, zero go.sum additions) plus the new `TestAdminPathsMatchOpenAPIDocumentation` with a two-helper split (keeps functions under the 50-line budget); presence-only assertions so legitimate doc growth never false-positives
- **§4 Compatibility** — openapi.yaml as immutable anchor, root-free binary preserved, CWD assumption precedented by the CRD-parity test, gate boundary at `ci-modules`
- **§5 Failure modes** — 12-row table; the coordinated-rename case (both Go consts renamed, doc untouched) is the one failure only the openapi anchor sees, since R2's consts-vs-consts parity passes by construction
- **§6 Migration** — 6 ordered steps: extend parity file → tidy (verify only the yaml.v3 line moved, sibling hunks untouched) → focused run (passes immediately; no red-to-green exists since all copies agree today) → full gates → commit → additive rollback
- **§7 Acceptance mapping** — all 8 Given/When/Then cases (graded 9/9 machine-checked) mapped to named tests with assertion mechanics; case 7 under the root suite
- **§8 Verification commands** — the exact `Makefile:263` gate command plus root gates and `make ci`
