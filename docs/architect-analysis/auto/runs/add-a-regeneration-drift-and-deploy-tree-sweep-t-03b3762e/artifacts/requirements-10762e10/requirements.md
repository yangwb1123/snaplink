The requirements specification is complete. Summary of the work:

## Deliverables

1. **Full spec**: `docs/architect-analysis/cmd-gensdk-regeneration-drift-deploy-sweep-requirements.md` (191 lines)
2. **Run artifact** (pipeline output): `docs/architect-analysis/auto/runs/add-a-regeneration-drift-and-deploy-tree-sweep-t-03b3762e/artifacts/requirements-10762e10/requirements.md` (summary + pointer, per the sibling-run convention)

## Evidence verification — all 6 citations confirmed, 2 corrections

| Citation | Verdict |
|---|---|
| Deploy `client.ts` 2857-line diff | ✅ `diff \| wc -l` = 2857 (832 vs 3494 lines) — **correction**: the entire `ops/deploy/openresty/fullstack/static/` tree is *untracked* (0 `git ls-files`, not gitignored, external pipeline output), so it's a working-tree diff, not `git diff` |
| Deploy `openapi.yaml` 5686-line diff | ✅ (13052 vs 18236 lines); discovery blocks byte-identical between copies |
| `Makefile:268` `ci` — no drift check | ✅ prereqs end at `sdk-surface-check`; no target references the deploy tree |
| `cli.py:275` `sdk-surface check` registry-only | ✅ `check` validates registry vs OpenAPI/capabilities only; `generate` exists (sdk_surface.py:146-151) but isn't wired into `ci` |
| `cmd/gensdk/main.go` outputs | ✅ `--out-ts/--out-py` defaults; deterministic (double-run byte-identical) |
| Discovery truthfulness | ✅ `TokenEndpoint: base + PathToken` (server_discovery_config.go:146), `PathToken = "/token"` (consts.go:21); Go-tree sweeps exist; `TestOIDCDiscovery*`/`/authenticate`/`8080:0` zero hits |

**New findings folded into the spec**: (a) the *committed* `docs/sdks/*` are also stale at HEAD (missing `client_secret_expires_at`/`grant_types`/`tenant_id` — 4 hunks), so R3 includes regenerating them; (b) deploy `client.py` drift = 2268 lines; (c) the deploy tree being untracked requires skip-when-absent sweep semantics for CI.

## Spec structure (R1–R5 + 9 GWT acceptance cases)

- **R1** regeneration-drift leg: `checks/sdk_drift.py` regenerates to a temp dir and byte-compares against committed `docs/sdks/*` (non-destructive on failure)
- **R2** deploy-tree sweep: 3 byte-identity pairs, SKIP-when-absent
- **R3** one-time drift remediation (regenerate committed SDKs + refresh deploy copies)
- **R4** wiring: cli.py (help, `cmd_sdk_drift`, COMMANDS :323-359, tuple :388), Makefile (`.PHONY` :16, target beside :125, `ci:` :268), CHECKS_REGISTRY.md (:31, :45)
- **R5** pytest tests + determinism pin

The supplied acceptance is preserved verbatim as the contract, then made testable with 9 Given/When/Then cases covering clean-tree pass, seeded-stale fail for each of the five files, absent-tree skip, future-drift blocking, wiring inspection, and determinism. Scope is bounded to the gate + remediation — no Go changes, no generator changes, no `sdk-surface check` semantic changes, no legacy-literal scanner (byte-identity achieves that transitively).
