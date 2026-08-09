All verifications pass. The document is now implementation-ready with zero unresolved reviewer findings.

# Verification report: design doc final-state audit

**Audited:** `docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-design.md` (342 lines, now with a "Review findings incorporated (N1–N3, P4, accepted gaps)" block in §1)

## Findings incorporated (verified in document text)

| Finding | Status | Where |
|---|---|---|
| **N1** — SystemExit(2) phrasing | ✅ | §7 acceptance row 6: `pytest.raises(SystemExit)` from `run(["bogus"])` with code 2; §1 rationale |
| **N2** — registry row placement | ✅ **fixed this review** | §3 registry row now reads "after `self_test.py` (end of the checks block, :28)"; §6 step 7 and §8 also updated. Previously still said "after `sdk_surface.py` (:31)" in all three places |
| **N3** — `##` help comment | ✅ **fixed this review** | §3: `sdk-drift-check: ## <help text>`; §6 step 6; §1 cites `checks/make_help.py:27-29` (verified: parses `##`) |
| **P4** — ClientMetadata → AdminClient | ✅ **fixed this review** | §3 changed-surfaces row now: "`AdminClient` is `TypedDict(total=False)` (client.py:64)" — verified against the file (:64 = `AdminClient`, :299 = `ClientMetadata` which already carries the fields); §1 documents the correction, conclusion unchanged |
| **F1–F11 coverage matrix** | ✅ | §5 "Coverage test" column present on all 11 rows; §7 matrix has header + F1–F11 (verified 12 pipe-rows) |
| **run_git seam** | ✅ | §3 API table (`run_git(args, cwd)`, monkeypatch target for F8), F8 row, §8 manifest |
| **Git-in-fixture** | ✅ | §7 fixture mechanics: `git init`/`add`/`-c user.name` commit, verified commands, F8 the only seam stub |
| **GOPROXY=off** | ✅ | §7 case 8 (`monkeypatch.setenv("GOPROXY", "off")`), §6 step 2, §8 |
| **P1–P3** | ✅ | §1; P3 now **explicitly reconciles R5's "only 0/1"** (requirements :111) — verdict contract is 0/1, exit 2 is the documented usage-error deviation, matched against live `sdk-surface` behavior (0/2/1 measured). No contradiction remains: §3 CLI row states "verdict contract stays 0/1, P3" |
| **Accepted gap: committed dist/ stale after R3 + npm package** | ✅ **fixed this review** | §1 "Accepted gap" bullet: dist `AdminClient` lacks the 3 optional fields until `npm run build` + commit; `@snaplink/sso-client` ships without them until then — additive-optional only, no break, deliberately outside the gate. §6 step 9 commit body now records it so the dist exclusion isn't "fixed" away |

## Stale-citation sweep

- Fixed `help block entry (~:39)` → `(:40)` (verified: `cli.py:40` = `sdk-surface` help line).
- Re-verified all other citations against HEAD: `cli.py:275-278/356/388`, `Makefile:16/125-126/268`, `CHECKS_REGISTRY.md:28/31/45`, `client.py:64/299`, requirements `:51/:111`, `make_help.py:27-29` — all exact.
- No residual wrong-class citation: the only remaining `ClientMetadata` mention is the P4 correction note itself.

## Consistency & integrity

- Exit-code contract 0/1/2 uniform across §1, §3, §6, §7; dist/ exclusion uniform (P2, D3, F6, §7, §8); registry placement now identical in all three references.
- Markdown tables intact (uniform 3/4/5-column counts per table; no broken rows); section structure 1–9 preserved; §9 gate posture unchanged.
- No Go edits (doc-only change), so no `go build`/`make ci` required per AGENTS.md.

**Deliverable:** the design document is the single source of truth, is implementation-ready, and carries no unresolved reviewer findings — all of N1–N3, P4, P1–P3, the F1–F11 amendments, and both accepted gaps are explicitly documented and internally consistent.
