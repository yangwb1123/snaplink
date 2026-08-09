All line references verified. The design document is complete and every citation in it was independently measured.

## Summary

**Evidence verification — all 6 citations + 2 corrections confirmed by direct execution, 3 precision notes (P1–P3) added:**

| Claim | Measured |
|---|---|
| Deploy `client.ts` 2857-line diff | ✅ `diff \| wc -l` = 2857 (3494 vs 832) |
| Deploy `openapi.yaml` 5686-line diff | ✅ 18236 vs 13052 |
| Deploy `client.py` 2268-line drift | ✅ 2772 vs 616 |
| Deploy `static/` tree untracked | ✅ `?? static/`, check-ignore exit 1 — **P1**: scoped to `static/`; `conf.d/` is tracked (17 files) |
| `Makefile:268` `ci:` — no drift check | ✅ ends at `sdk-surface-check`; no target references the deploy tree |
| `cli.py:275` registry-only check; `generate` unwired | ✅ `sdk_surface.py:129-137` check, `146-151` generate |
| gensdk defaults + determinism | ✅ defaults at main.go:99-105; double-run byte-identical |
| Discovery truthfulness | ✅ `server_discovery_config.go:146`, `consts.go:21`; `TestOIDCDiscovery*` 0 Go hits |
| Committed `docs/sdks/*` stale | ✅ TS +8 lines/2 hunks, PY +5 lines/2 hunks (`client_secret_expires_at`, `grant_types`, `tenant_id`) — **P2** refines the R1 git-status check to exclude `dist/` |
| Dispatch points, registry rows, check pattern | ✅ cli.py:40/275/356/388; CHECKS_REGISTRY.md:31/:45; `run() -> int` precedent |

**Deliverable:** `docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-design.md` — concrete design with:

- **API changes**: `python cli.py sdk-drift check` (exit 0/1/2), `checks/sdk_drift.py` (`run`, pure `check_regen`/`check_deploy`), Make target `sdk-drift-check` in `.PHONY`/`ci:`, registry rows; additive only — no Go, no wire, no `sdk-surface` changes
- **Compatibility constraints**: fresh checkout passes (deploy leg SKIPs), determinism pinned, backward-compatible SDK refresh (`TypedDict total=False`, `?`-optional TS fields)
- **Failure modes**: 11 enumerated (F1–F11), each with gate behavior and design response
- **Migration steps**: 9 ordered steps incl. R3 remediation, sibling-direction coordination (D6), rollback path
- **Testable acceptance mapping**: all 9 GWT cases → concrete pytest tests with assertions, fixture strategy via monkeypatched `ROOT`/`REGEN_CMD`

Notable design decisions: temp-dir regeneration (non-destructive failures), `dist/`-excluded cleanliness scan, `servers:`-independent ordering vs. the sibling direction (verified 0 hits in the generator).
