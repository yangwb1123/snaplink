Design complete and verified. Summary of what I did:

## Verification of the evidence (all claims re-checked against the tree)

**Confirmed (10/11):** `ServerConfig.Issuer` at `config/config_server.go:18`; `resolveIssuer` Host fallback at `server_discovery.go:251-255`; `WithIssuer` at `options.go:350`; tracing/CAEP wiring (`main_wiring.go:203`, `build_app_oidc.go:137` — CAEP-only); sentinel rejection at `config_load.go:176-185` + `issuer_test.go` guards; configcmd `runValidate`→`config.Load`/`--print`/A1-P4-A4 fixtures; zero Go hits for the new keys; `ServerOptions()`→`sso.WithIssuer`→`build_app_core.go:154`→`sso.NewServer` (`build_app.go:257`); both "falsified" items hold (the premise is stale at HEAD; `issuer_wiring_test.go` untracked WIP pins it end to end); all three pre-existing gate failures reproduced by actually running the gates.

**Two facts the evidence missed, now load-bearing in the design:**
- **F1:** `config/` fan-out is frozen at 26 non-test files (`directory_fanout_test.go` exemption map) — the validator must live in `config/config_server.go`, not a new file (and not `config_load.go`, which is at 498/500).
- **F2:** `issuer_allowlist` **already exists in deploy manifests** (`ops/deploy/kustomize/{base,overlays/prod}/config.yaml`, `ops/deploy/k8s-distributed/config.yaml`, `bin/k8s-rendered/*`) — currently unknown keys (boot warning, `validate-schema` violation); the new surface converts them to recognized-but-inert.

## Deliverable

`docs/architect-analysis/auto/runs/issuer-allowlist-config-surface-configcmd-valida-8715499d/artifacts/design-a77de8a6/task-1-design.md`, containing:

- **API changes** — `server.issuer_allowlist []string` + `server.require_configured bool` on `ServerConfig`; `applyDefaults` fallback skip (net 0 lines); `validateIssuerPolicy()` with the sentinel check moved verbatim (unconditional) plus five gated checks (issuer set → absolute URL → allowlist non-empty → entries valid → membership with exactly-one-trailing-slash normalization, literal ports, case-significant); configcmd zero production change; two `docs/config-reference.md` rows.
- **Compatibility** — default-off byte-compat; the one relocation trap (sentinel must stay outside the flag gate); schema growth + intended `validate-schema` loosening for existing manifests; CI (`make config-validate-all`) unaffected; all budgets checked (config/ stays at 26 files, `config_load.go` ≈489, `config_server.go` ≈235, `_test.go` exempt from size budget); untracked `issuer_wiring_test.go` committed.
- **Failure modes** — 9 enumerated (FM-1 conditional-sentinel regression, FM-2 normalization drift, FM-3 silent always-fail, FM-4 `url.Parse` leniency/userinfo, FM-5 `base_url` check rejected with evidence — it validates a dead key, FM-6 rotation fail-closed, FM-7 schema `Required` heuristic, FM-8 manifest churn, FM-9 pre-existing gate failures).
- **Migration** — 6 steps, fleet-segment toggle per the B4-1 proposal, rotation playbook, corrected per-file values (`bin/config.yaml` → `http://localhost:28898`).
- **Acceptance mapping** — every campaign acceptance (T-8(a), T-2, the three exit-1 conditions, schema/validate-schema pins, byte-compat exit 0) mapped to 15 config-level `G*` cases, 7 configcmd `C*` fixtures, and `W1` in `issuer_test.go`.
