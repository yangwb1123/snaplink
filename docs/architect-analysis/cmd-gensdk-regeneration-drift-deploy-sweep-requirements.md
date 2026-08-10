# Requirements Spec: regeneration-drift and deploy-tree sweep/truthiness gate for the shipped SDK artifacts (T-9)

- Direction: "Add a regeneration-drift and deploy-tree sweep/truthiness gate so B4 discovery/endpoint truthiness cannot regress in the shipped tree" (source: `docs/architect-analysis/auto/analyses/cmd-gensdk-4ffda121.json`, entry 2)
- Analysis module: `cmd/gensdk`; change surface: `checks/sdk_drift.py` (new gate), `cli.py` + `Makefile` (wiring), `docs/agent-os/CHECKS_REGISTRY.md` (registration), plus one-time drift remediation of the committed SDK outputs and the deploy-tree static copies. No production Go changes anywhere.
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `ops/deploy/openresty/fullstack/static/docs/sdks/client.ts` differs from canonical `docs/sdks/typescript/client.ts` by 2857 lines | `diff docs/sdks/typescript/client.ts ops/deploy/openresty/fullstack/static/docs/sdks/client.ts \| wc -l` → **2857**. Sizes: 3494 vs 832 lines. One correction: this is a plain working-tree file diff, not `git diff` — the entire `ops/deploy/openresty/fullstack/static/` tree is **untracked** (`git status` → `??`, zero `git ls-files` entries, `git check-ignore` exit 1, no `.gitignore` pattern; prior audit runs confirm it is external docs-site pipeline output, "ln v1.6.4" in the HTML meta) | Confirmed (method corrected: untracked tree, so `git diff` cannot show it) |
| `ops/deploy/openresty/fullstack/static/docs/openapi.yaml` differs from `docs/openapi.yaml` by 5686 lines | `diff docs/openapi.yaml ops/deploy/openresty/fullstack/static/docs/openapi.yaml \| wc -l` → **5686**. Sizes: 18236 vs 13052 lines (canonical is newer). The `getOpenIDConfiguration` blocks are byte-identical between the two files — the drift is in newer schemas/endpoints (SCIM enterprise, etc.), not in the discovery section | Confirmed |
| Deploy-tree `sdks/client.py` (acceptance's third sweep target) | `diff docs/sdks/python/client.py ops/deploy/openresty/fullstack/static/docs/sdks/client.py \| wc -l` → **2268** (2772 vs 616 lines) — same stale-copy class as client.ts | New fact, folded into R2 |
| `Makefile:268` `ci` target — no gensdk regenerate-diff or deploy-sweep check | Line 268: `ci: fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract proto-openapi-parity capabilities-check sdk-surface-check profiles-evidence adapters-check`. `sdk-surface-check` (line 125-126) runs `$(CLI) sdk-surface check` only. No target regenerates or diffs committed SDK output; no target references `ops/deploy/openresty/fullstack/static` | Confirmed |
| `cli.py:275` `sdk-surface check` validates registry only; never regenerates/diffs committed SDKs | `cmd_sdk_surface` (cli.py:275-278) → `ops/scripts/sdk_surface.py run`. `check` action (sdk_surface.py:129-137) validates the registry against OpenAPI operationIds + capabilities + output-file existence only. `generate` action (sdk_surface.py:146-151) runs `go run ./cmd/gensdk --lang=all` but is **not** wired into `make ci` — nothing in CI detects stale generated output | Confirmed |
| `cmd/gensdk/main.go` committed outputs `docs/sdks/{typescript/client.ts,python/client.py}` | `parseFlags` defaults (main.go:99-105): `--out-ts=docs/sdks/typescript/client.ts`, `--out-py=docs/sdks/python/client.py`; `--lang=all` writes both (main.go:67-74). Output is deterministic — two consecutive regenerations to temp dirs diff byte-identical; no `time.Now`/`rand` in the generator | Confirmed |
| `docs/openapi.yaml` discovery section already truthful | `getOpenIDConfiguration` at docs/openapi.yaml:3523 → `OpenIDConfiguration` schema (:17630) with `token_endpoint` required `format: uri`. Server truth anchor: `interfaces/sso/server_discovery_config.go:146` `TokenEndpoint: base + PathToken`, with `shared/core/consts.go:21` `PathToken = "/token"`. The Go-tree sweep/truthiness coverage the campaign's T-2 requires already exists (`test/oidc_discovery_test.go` — 13 `TestDiscovery_*` incl. `token_endpoint` assertions at :214; `rootcov_discovery_test.go`, `rootcov2_discovery_test.go`) | Confirmed — the remaining B4(3) exposure is exactly the artifact chain |
| Legacy defect tests absent | `grep -rn "TestOIDCDiscovery" --include="*.go" .` → 0 hits (only campaign docs mention the names as deletion instructions). `/authenticate` appears only as a negative guard at `cmd/sso-ctl/generate/scaffold_contract_test.go:136`; `8080:0` only as a negative shape assertion (:132, :146). Zero hits for `/authenticate` and `8080:0` in `ops/deploy/` | Confirmed |

Additional facts verified to make the acceptance testable (not in the direction, required to pin its assertions):

| New fact | Measured reality |
|---|---|
| The **committed** SDK outputs are themselves stale at HEAD | Regenerating today produces a client.ts/client.py that differ from the committed copies: the committed `Client` schema lacks `client_secret_expires_at`, `grant_types`, and `tenant_id` (both TS and Python; 4 hunks). The acceptance's "after fixing the existing drift" leg covers this — the change must regenerate the committed SDKs, not only add the gate |
| Deploy tree is untracked external-pipeline output; nothing in-tree syncs it | Zero references to `fullstack/static` in any in-tree script, Makefile target, or nginx conf (grep over `ops/`, `Makefile`, `cli.py`); the tree is produced by an external docs-site generator. The sweep must **skip** (exit 0, note) when the tree is absent — CI checkouts will not have it — and fail when present-but-stale |
| Gate-module precedent for the new check | `checks/route_contract.py` (`run() -> int`) ← `cmd_check_routes` (cli.py:171-173) ← COMMANDS dict (cli.py:323-359) ← Makefile target (`route-contract`, Makefile:191-192) ← `.PHONY` (Makefile:16) ← `docs/agent-os/CHECKS_REGISTRY.md` (table row ~:31, "Specific checks" group :45). checks/ unit tests run via `python cli.py check-test` (pytest on `checks/`, cli.py:200-204; `test_*.py` files live beside the modules) |
| cli.py dispatch points | Help text block ~:24-40; `cmd_sdk_surface` :275-278; COMMANDS dict :323-359 (`"sdk-surface"` :356); arg-passthrough tuple :388 (`("skill", "configure", "modules", "capabilities", "sdk-surface", "profiles")`) |
| Determinism | `go run ./cmd/gensdk --lang=all` run twice to separate temp dirs → byte-identical outputs (TS and Python). A regeneration-based gate cannot flap from generator nondeterminism |
| Discovery metadata is server-state-derived | `buildBaseMetadata` (server_discovery_config.go:142-149) emits `base + PathToken` etc.; both spec copies' discovery blocks are byte-identical — the "truthfulness" side of B4(3) is done; this direction only guards the artifacts |

Net: all direction claims hold, with two scope-relevant corrections — (1) the deploy tree is untracked (diff method was a working-tree file diff; sweep needs skip-when-absent semantics), and (2) the committed `docs/sdks/*` outputs are also stale at HEAD, so the drift fix includes regenerating them.

## 2. Goal and user outcome

B4(3)/T-9 requires that the shipped artifact chain — the committed SDKs under `docs/sdks/` and the deploy tree's static copies under `ops/deploy/openresty/fullstack/static/docs/` — never regress against the canonical generated output. Today nothing checks either surface: `make ci` (Makefile:268) runs `sdk-surface check` (registry validation only), and the deploy-tree copies are pre-registry hand-scoped generations (2857/5686/2268 diff lines vs canonical). The Go tree's discovery truthiness (verified: `token_endpoint = base + PathToken`, no legacy `/authenticate`/`8080:0` artifacts, `TestOIDCDiscovery*` gone) is already correct and sweep-tested; the unguarded exposure is precisely the artifact chain.

Completion marker: a new check, wired into `make ci` and cli.py, regenerates with `go run ./cmd/gensdk --lang=all` and fails on any diff of `docs/sdks/*`; a second sweep asserts the three deploy-tree copies are byte-identical to the canonical `docs/` outputs; after fixing the existing drift, both checks pass on a clean tree and fail on a seeded stale copy.

## 3. Product boundary

- Surface: engineering tooling (`checks/sdk_drift.py`, cli.py command, Makefile target, CHECKS_REGISTRY.md) + one-time artifact refresh. No server, protocol, config, or OpenAPI-content changes; no generator changes.
- Default: the new check is unconditional inside `make ci` (new prerequisite) and available standalone via `python cli.py sdk-drift check`.
- Explicit non-goals (do not implement):
  - No changes to `cmd/gensdk/*.go` — the generator's output format, schema picker, and CLI are untouched; this direction gates what is already generated.
  - No changes to `sdk-surface check` semantics — `ops/scripts/sdk_surface.py` registry validation stays exactly as-is (its contract is CHECKS_REGISTRY.md:31); the new drift check is a separate command.
  - No content changes to `docs/openapi.yaml` — the `servers:` `http://localhost:8080` "Local dev" entry purge is the sibling direction's scope (`cmd-gensdk-b4-3-discovery-truthiness-requirements.md`); byte-identity to the canonical spec is the sweep's contract, whatever the canonical spec contains.
  - No legacy-literal scanner over the deploy tree: byte-identity to canonical `docs/` outputs transitively guarantees absence of the legacy defect artifacts (canonical outputs verified clean of `/authenticate`/`8080:0`). A separate literal scan would duplicate the sibling direction and is not requested.
  - No tracking/committing of `ops/deploy/openresty/fullstack/static/` — it is external-pipeline output by design; the gate asserts on the working tree when present, skips when absent.
  - No `docs/sdks/typescript/dist/` staleness check — `dist/` is built by a separate TS toolchain, not by gensdk; the regeneration leg covers exactly what the generator writes (client.ts, client.py).
  - No Go code changes, no new `Err*` codes, no config keys, no route/discovery changes.

## 4. Module classification

- [x] Infrastructure/config/deployment (engineering gate + artifact refresh)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `checks/` + `cli.py` + `Makefile` (engineering tooling, composition layer). No import-graph change: no Go package is added or modified.

## 5. Requirements

### R1 — Regeneration-drift check (T-9 leg 1)

New gate module `checks/sdk_drift.py` exposing `run(args: list[str]) -> int` (pattern: `checks/route_contract.py`), invoked as `python cli.py sdk-drift check`. The regeneration leg:

- Runs `go run ./cmd/gensdk --lang=all` with the default surface registry (`ops/build/sdk-surface.json`) and the embedded spec, writing to a **temporary directory** via `--out-ts=<tmp>/client.ts --out-py=<tmp>/client.py` (non-destructive: a failing gate never leaves the working tree dirty).
- Byte-compares (`cmp`) each regenerated output against the committed file:
  - `<tmp>/client.ts` ≡ `docs/sdks/typescript/client.ts`
  - `<tmp>/client.py` ≡ `docs/sdks/python/client.py`
- Fails on any diff of `docs/sdks/*`: a mismatch on either file, or any modified/new file under `docs/sdks/` after regeneration (`git status --porcelain docs/sdks/` non-empty), exits non-zero with a per-file report naming the drifted path and a diff sample.
- Exits 0 when regeneration reproduces the committed outputs byte-for-byte and `docs/sdks/` is clean.

Rationale for temp-dir regeneration: semantically identical to regenerate-in-place-then-`git diff` (the acceptance's "regenerates with `go run ./cmd/gensdk --lang=all` and fails on any diff of docs/sdks/*"), but leaves the tree untouched on failure, which keeps `make ci` failure states clean and reproducible.

### R2 — Deploy-tree sweep (T-9 leg 2)

Same `sdk-drift check` invocation, second leg, byte-identical (`cmp`) assertions:

| Deploy-tree copy | Canonical source |
|---|---|
| `ops/deploy/openresty/fullstack/static/docs/openapi.yaml` | `docs/openapi.yaml` |
| `ops/deploy/openresty/fullstack/static/docs/sdks/client.ts` | `docs/sdks/typescript/client.ts` |
| `ops/deploy/openresty/fullstack/static/docs/sdks/client.py` | `docs/sdks/python/client.py` |

- If `ops/deploy/openresty/fullstack/static/` does **not** exist → SKIP the leg (print note, exit 0): the tree is untracked external-pipeline output and is absent from CI checkouts. This is required for `make ci` to pass in a fresh checkout.
- If the tree exists but a sweep target is missing → FAIL (a partial tree is drift).
- Any byte mismatch → FAIL naming the pair.

The sweep's "never legacy defect artifacts" property is achieved transitively: the canonical outputs are verified free of `/authenticate` and `8080:0` (section 1), so byte-identity forbids reintroduction in the shipped copies.

### R3 — Drift remediation (one-time, part of this change)

The acceptance requires both checks to pass on a clean tree, so the change ships the artifact refresh, not just the gate:

- Regenerate the committed SDKs: `go run ./cmd/gensdk --lang=all` in place, committing the refreshed `docs/sdks/typescript/client.ts` and `docs/sdks/python/client.py`. This fixes the verified staleness at HEAD (committed `Client` schema missing `client_secret_expires_at`, `grant_types`, `tenant_id`).
- Refresh the deploy-tree copies so the sweep passes when the tree is present: copy the canonical files to `ops/deploy/openresty/fullstack/static/docs/{openapi.yaml,sdks/client.ts,sdks/client.py}`. (If the external pipeline regenerates the tree, the sweep then guards it on every run.)
- The refreshed deploy copies replace the pre-registry hand-scoped generations (2857/5686/2268 diff lines today).

### R4 — Wiring

- `cli.py`: register the new command — help-text entry (block ~:24-40), `cmd_sdk_drift` delegating to `checks.sdk_drift.run` (pattern `cmd_check_routes` :171-173), COMMANDS dict entry (:323-359), and add `"sdk-drift"` to the arg-passthrough tuple (:388).
- `Makefile`: new target `sdk-drift-check:` → `$(CLI) sdk-drift check` (placed beside `sdk-surface-check`, :125-126), added to `.PHONY` (:16) and to the `ci:` prerequisite list (:268).
- `docs/agent-os/CHECKS_REGISTRY.md`: add the `checks/sdk_drift.py` row to the checks table (~:31) and `sdk-drift check` to the "Specific checks" command group (:45).

### R5 — Tests and determinism pin

- New `checks/test_sdk_drift.py` (pytest, run by `python cli.py check-test`): unit tests exercising both legs with temp dirs and path injection (no network, no `go run` — the regeneration leg is tested by comparing pre-generated fixture bytes against a fake "regenerated" payload, plus one integration-style subprocess test tagged to run when the Go toolchain is present):
  - regeneration equality → 0; seeded stale committed copy → non-zero naming the file;
  - deploy leg: absent tree → 0 (SKIP note); byte-identical → 0; seeded stale copy and missing target → non-zero;
  - exit-code contract: only 0/1; failure output names the offending path pair.
- Determinism pin: assert two regenerations of the same input produce byte-identical output (guards the gate against generator nondeterminism flapping `make ci`).

### Testable acceptance (Given/When/Then)

The direction's supplied acceptance, made testable:

> "T-9: a new check (wired into `make ci` and cli.py) regenerates with `go run ./cmd/gensdk --lang=all` and fails on any diff of docs/sdks/*; a second sweep asserts ops/deploy/openresty/fullstack/static/docs/{openapi.yaml,sdks/client.ts,sdks/client.py} are byte-identical to the canonical docs/ outputs; after fixing the existing drift, both checks pass on a clean tree and fail on a seeded stale copy."

1. Given a clean tree after R3 remediation, when `python cli.py sdk-drift check` runs, then exit 0 (both legs pass; deploy leg passes because the refreshed copies are byte-identical).
2. Given a seeded stale committed copy (one line deleted from `docs/sdks/typescript/client.ts`), when the check runs, then exit ≠ 0, failure output names `docs/sdks/typescript/client.ts`; after restore, exit 0. Same for `docs/sdks/python/client.py`.
3. Given a seeded stale deploy copy (one-line edit to `ops/deploy/openresty/fullstack/static/docs/openapi.yaml`), when the check runs, then exit ≠ 0 naming the pair; after restore, exit 0. Same for `sdks/client.ts` and `sdks/client.py`.
4. Given `ops/deploy/openresty/fullstack/static/` absent (fresh CI checkout), when the check runs, then exit 0 with a SKIP note for the deploy leg (no false failure).
5. Given a future spec/surface change that alters generated output (`docs/openapi.yaml` or `ops/build/sdk-surface.json` edited without regenerating), when `make ci` runs, then `sdk-drift-check` fails, blocking the stale commit; after `go run ./cmd/gensdk --lang=all` + commit of the refreshed SDKs, it passes. (This is the "cannot regress" property the direction exists for.)
6. Given `make sdk-drift-check` / `make -n ci`, when inspected, then the new target exists, is in `.PHONY`, and appears in the `ci:` prerequisites; `python cli.py sdk-drift` is listed in help and dispatches (unknown action → usage error, exit ≠ 0).
7. Given the new unit tests, when `python cli.py check-test` runs, then `checks/test_sdk_drift.py` is green (exit 0).
8. Given two consecutive regenerations, when diffed, then outputs are byte-identical (determinism pin, R5).
9. Given the pre-change behavior set — `sdk-surface check` still validates the registry and passes; committed SDKs are up to date with regeneration — when the change lands, then all still hold (no behavior change to the existing check).

Mapping: R1/R2 are T-9's shipped-tree sweep; the Go-tree sweep/truthiness (T-2) is already delivered (`test/oidc_discovery_test.go` `TestDiscovery_*` incl. `token_endpoint == "/token"` at :214; `rootcov_discovery_test.go`, `rootcov2_discovery_test.go`; `buildBaseMetadata` const-derived endpoints) — this direction closes the remaining artifact-chain gap.

## 6. Engineering-gate constraints (verified)

- **No Go changes**: budgets, `interfaces/sso` 60-file ceiling, import direction, and the architecture gates are untouched. Mandatory post-edit verification (`go build ./... && go vet ./...`, maintainability/architecture tests) still applies and is unaffected.
- **Directory/fan-out**: `checks/` already holds gate modules; `sdk_drift.py` and `test_sdk_drift.py` join the flat directory — no new directories, no fan-out change.
- **Makefile**: `ci:` (line 268) gains one prerequisite token; `.PHONY` (line 16) gains one name; new target placed beside `sdk-surface-check` (line 125-126).
- **cli.py**: three small additions (help block, `cmd_sdk_drift`, COMMANDS entry + tuple) — no structural change.
- **Wire/security contracts untouched**: no routes, no handlers, no credential-endpoint semantics, no oracle surfaces. The gate only compares artifacts.
- **Reproducibility**: regeneration is deterministic (verified; R5 pins it); the gate uses temp-dir output so failure leaves the tree clean.
- Baseline at HEAD: `go run ./cmd/gensdk --lang=all` succeeds and is deterministic; `sdk-surface check` passes; `make ci` passes (the new prerequisite must stay green after R3).

## 7. Files

### Create

```text
checks/sdk_drift.py — gate module: regeneration leg (gensdk to temp dir +
    cmp against docs/sdks/{typescript/client.ts,python/client.py} + git
    status cleanliness on docs/sdks/) and deploy-tree sweep leg
    (byte-identity of the three deploy copies; SKIP when the tree is
    absent); run(args) -> int; per-file failure messages.
checks/test_sdk_drift.py — pytest unit tests (temp-dir fixtures, path
    injection, exit-code and message contract; determinism pin; optional
    subprocess integration test tagged for a present Go toolchain).
```

### Modify

```text
cli.py — help-text entry for sdk-drift; cmd_sdk_drift → checks.sdk_drift.run;
    COMMANDS entry (:323-359); arg-passthrough tuple (:388).
Makefile — .PHONY (:16); sdk-drift-check target beside sdk-surface-check
    (:125-126); ci: prerequisites (:268).
docs/agent-os/CHECKS_REGISTRY.md — checks-table row for sdk_drift.py (~:31);
    "Specific checks" group entry (:45).
docs/sdks/typescript/client.ts — regenerated (R3; fixes missing
    client_secret_expires_at/grant_types/tenant_id on Client).
docs/sdks/python/client.py — regenerated (R3).
ops/deploy/openresty/fullstack/static/docs/{openapi.yaml,sdks/client.ts,
    sdks/client.py} — refreshed to byte-identical canonical copies (R3;
    untracked external-pipeline output — refreshed in the working tree).
```

### Do not modify

```text
cmd/gensdk/*.go — generator untouched; the gate guards its output.
ops/scripts/sdk_surface.py — sdk-surface check semantics unchanged.
docs/openapi.yaml — spec content is the sibling direction's scope; the
    sweep compares against it as-is.
interfaces/sso/*, shared/core/* — no server or constant changes.
```

## 8. Dependencies and compatibility

- New/changed SPI: none (engineering tooling only).
- New CLI surface: `python cli.py sdk-drift check` (exit 0/1; SKIP note for absent deploy tree).
- New Make target: `sdk-drift-check` (prerequisite of `ci`).
- Storage/HTTP/proto/config compatibility: none affected.
- Rollout/rollback: the gate is additive; rollback = revert the wiring + artifact refresh. The refreshed committed SDKs are forward-only (regeneration is deterministic; the previous committed outputs were stale by verified 4-hunk drift).
- Interaction with the sibling direction (`cmd-gensdk-b4-3-discovery-truthiness`): if that direction's spec purge (removing the `servers:` `http://localhost:8080` entry) lands first, this direction's R3 must regenerate the committed SDKs again after it (output is currently byte-identical with/without `servers:` handling — the generator does not consume the `servers:` list — so in practice the order does not matter; stated for completeness).
