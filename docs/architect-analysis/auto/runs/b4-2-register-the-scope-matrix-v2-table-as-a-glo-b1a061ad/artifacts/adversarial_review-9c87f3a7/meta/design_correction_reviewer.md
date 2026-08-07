Re-audit complete — report written to `docs/architect-analysis/auto/runs/b4-2-register-the-scope-matrix-v2-table-as-a-glo-b1a061ad/artifacts/design_gate-6a76b0dd/task-1-design-gate.md`.

**Key finding: there is no revised artifact.** The design file on disk is byte-identical to the version the reviewers rejected (committed at `faf05452`, no working-tree diff, no `task-1b` amendment file in the run). Every fact was re-verified against the tree:

**Gate checks**
1. **Split-first plan #2 — NOT FIXED.** Artifact still says "extract `wireSessionTrustDecay` → `build_app_trust.go`". Verified: the file does not exist; `cmd/sso-server` = exactly 24 non-test files vs the frozen ceiling 24 (`directory_fanout_test.go:52`), so creating it → 25 > 24 → fan-out regression. `build_app_security.go:310` (the source) is exactly 500 lines. Valid existing targets verified: `build_stores.go` (477, already wires `WithMaxScopeCount` at :293), `main_wiring.go` (239).
2. **Config host file — NOT FIXED.** Knobs are named but no host file; `config/` = exactly 26 non-test files vs frozen 26 (`directory_fanout_test.go:53`). Existing candidates (`config_oauth2.go`, `config_permissions.go`) are unmentioned.

**Security blockers**
3. Per-branch effective-scope checks at the 8 post-resolution/pre-issuance points — **NOT FIXED**. Verified the seam's blindness: authcode mints code-bound `info.Scopes` (token_authcode.go:114, SA4009), refresh family scopes (:136/:153), device `dc.Scopes` (:199), CIBA `r.Scopes` (:282), exchange `st.scopes` (:298), SAML2 via `customGrantHandlers` (server_setup.go:271).
4. /token re-scoping — **NOT FIXED**; direct mints (server_finish_login, webauthn.go:87/:146) unnamed.
5. Seam ordering before `denyTokenScopeCombo` (:128) — **NOT FIXED** (no pin; tokenpolicy emits trace-shape body).
6. `extra_scopes` validation (reject bare `*`, startup-fail) — **NOT FIXED** (billing/config.go:360 precedent exists but unprescribed).
7. A-1b byte-identical-body pin — **PRESENT** (already in the original correction #1: emit `core.ErrorBody`, 400).

**Carried findings**: OIDC-standard-scope bypass still unbacked (only `openid`/`device_sso` are bypass constants — scope.go:100/:117; `offline_access` webauthn mints unnamed); the 8 migration steps and 9 failure modes exist only as counts.

**VERDICT: FAIL** — the artifact was never revised; 1 of the 5 blockers is present, the rest are unincorporated, and both gate constraints remain violated as written.
