All review evidence is in. Here is the complete review.

# Review: cmd-sso-ctl-b4-3-t2 design

## 1. The 16 acceptance mappings with corrected C1/C2 semantics — CONFIRMED, with 2 minor corrections

I verified the probe semantics empirically: a temporary probe test in `test/` (deleted after) built a stock server exactly per `newDiscoveryServer` (`test/oidc_discovery_test.go:21-39`) and exercised the C1a GET-then-POST-on-404 mechanism field-by-field.

**Stock-server field inventory and probe outcomes:**

| Field | Emitted on stock | GET | POST-on-404 | Probe |
|---|---|---|---|---|
| `issuer` | yes (`https://sso.test` via `WithIssuer`) | — | — | excluded (C1b) — **required**: issuer ≠ base |
| `authorization_endpoint` | yes | 200 | — | pass |
| `token_endpoint` | yes | 404 | 400 | pass |
| `jwks_uri` | yes (`/.well-known/jwks.json`) | 200 | — | pass |
| `revocation_endpoint` / `introspection_endpoint` | yes | 404 | 400 | pass |
| `userinfo_endpoint` | yes | 500 | — | pass |
| `end_session_endpoint` | yes | 204 | — | pass |
| `check_session_iframe` | **absent** (session-mgmt is opt-in, `sso_wiring.go:253-259`) | — | — | pass (when-present) |
| `registration_endpoint` / `pushed_authorization_request_endpoint` / `backchannel_authentication_endpoint` | **absent** (DCR/PAR/CIBA opt-in) | — | — | pass |
| `device_authorization_endpoint` | **absent** (C4 confirmed: only hit is `cmd/sso-minimal/surface.go`) | — | — | pass |

**C1 confirmed**: GET-only probing fails on a healthy stock server (GET `/`→404, `/token`→404, `/introspect`→404, `/revoke`→404; ServeMux answers method mismatch with 404, not 405). **C2 confirmed**: the corrected GET-404→POST-non-404 mechanism is the real one; case 7's pinned handler (GET 404 / POST 200) passes. **Case 1 passes end-to-end under the corrected semantics** — every emitted URL field is non-404 on GET or non-404 on empty-body POST, and all equality/issuer-exclusion rules hold for `srv.URL`.

**Correction 1 (factual, non-blocking):** the design's §1 C1a status evidence is wrong — empty-body POST `/token`, `/introspect`, `/revoke`, `/auth/login` all return **400**, not the claimed 401/415 (only `/par` and `/device/code` return the claimed 501). The load-bearing claims (non-404, fails validation before any store write) hold; the probe semantics are unaffected. Update the evidence record.

**Determinism/non-flakiness — confirmed:** all 16 tests are httptest-local (no external network, no sleeps, no wall-clock deps); the `--timeout` shared context never enters test assertions; cases 2/3 fire exactly one violation per run so stderr assertions aren't order-sensitive (important since `checkDiscoveryDoc` iterates a map); case 9 asserts body identity (not exit 0 — the recording handler 404s probes, so the sweep exits 1 there; worth stating explicitly in the test comment). `-count=10 -race` is sound.

## 2. Checker factorization budgets — CONFIRMED

- configcmd non-test files: `main.go` + `schema.go` = 2 → 3 of the 10 cap. ✓
- File lines: 120 (+~30 → ~150 < 500), 96, discovery_check.go ≤300. ✓ All planned functions ≤50 lines / complexity ≤15 / nesting ≤3.
- No new subdir (`cmd/sso-ctl` = exactly 16 = cap, counted), no new `subcommands` map entry (16 entries, counted at `main.go:46-63`). ✓
- Import edge `configcmd → interfaces/sso`: `cmd` is composition (rank 6, may import downward); precedent exists in siblings (`importcmd/importer.go:11`, `generate/templates.go:12`); `interfaces/sso` is already in configcmd's transitive deps via `config` (which imports it for `sso.DefaultIssuer`); no cycle — `go build ./... && go vet ./...` clean. ✓

## 3. Migration steps — CONFIRMED green at every stage, one inventory gap

- **Step 1** (checker core, no wiring): additive files only; `Run` untouched → all 12 existing configcmd tests pass unchanged (verified with `-race`); build/vet clean; maintainability gates unaffected (no new subdir, sizes under budget).
- **Step 2** (+1 switch case): existing dispatch/configcmd tests untouched and passing (verified). Case-1 e2e test uses a local `newDiscoveryServer` replica — correct call, since the real helper is unexported.
- **Step 3** (allowlist flag): registered on the existing FlagSet but parsed only when passed → T-9 byte-identity holds; `config.Load` defaulting to `"sso-server"` then failing any allowlist confirmed against `config/config_load.go:60,70-71` (only the sentinel is rejected by the loader, at 183-184).
- **Step 4** (`make ci`): change touches only vet/race/build/fmt surface; no config keys added, so `config-validate-all` (server YAML files, Makefile:400) is unaffected.

**Pre-existing failures verified today** (correctly quarantined by the design, and provably unaffected by the change):
- `TestArchitecture_DirectorySubdirFanout`: docs 18>16, `docs/architect-analysis/auto/runs` 80>16, root exempt regression 24>21 — exactly C3.
- Python `directory_fanout.py`: `cmd/sso-ctl` 16>15 plus dist/, docs/, auto/runs/, platform/ — exactly E10. The change adds no subdir, so `cmd/sso-ctl` stays 16; no new violation.
- **Correction 2 (inventory gap, non-blocking):** `TestArchitecture_DirectoryDepth` **also fails today** (depth-5 dirs under `docs/architect-analysis/auto/runs`) — the design's C3 report only lists the fan-out failures. The change cannot affect it (no new directories, nothing under `auto/runs`), but §5's "report separately" list should include it.

## Verdict

The design is implementable as written: case 1 demonstrably passes against a stock server under the corrected C1a/C1b semantics (and would fail under the spec's GET-only rule), cases 2–16 are deterministic, local, and correctly mapped; the factorization respects all budgets and the legal composition-layer import; the 4 migration steps keep the tree green modulo pre-existing failures that are properly quarantined. Two minor corrections for the evidence record: the C1a status codes are 400 (not 401/415), and the pre-existing-failure inventory should add `TestArchitecture_DirectoryDepth`. Neither affects any acceptance-case outcome or gate math.
