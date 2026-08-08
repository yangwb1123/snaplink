The design is complete. Here's the summary of what I did and found.

## Deliverable

`docs/architect-analysis/auto/cmd-sso-ctl-entitiescmd-design.md` — a concrete design with API changes, compatibility constraints, failure modes, migration steps, and a testable acceptance mapping (A1–A13 + new baseline prerequisites B1–B3).

## Verification outcome: evidence largely confirmed, one material discrepancy

**Confirmed (substance exact, minor line drift):** all 15 citations and the new evidence. The interpolation pattern (`len(args) < 1 || args[0] == ""` then splice) exists at all **seven** sites (tenants get/update/delete/set-status, users get/update/delete); the custom-verb collision (`{id}` catches `{id}:set-status`, pinned by admin_gateway_routing_test.go:141); zero admin-endpoint probes in the sweep; the full suspension chain introspect → `validateAnyToken` (:400) → `{active:false}` (introspect_cache.go:130-131); `tenant_id` read-only on the admin client API and stamped on cc mints (`token_client_credentials.go:52`), which validates probe (b)'s approach; the admin flip synchronously invalidates the suspension cache (build_http.go:456), so A11 won't be masked by the 30s TTL; OpenAPI set-status entry genuinely lacks the 404 row. Undisclosed path drifts I found: `scoperegistry` lives under `protocols/oauth/`, and `config_load.go` under `config/`.

**Material discrepancy — the evidence understates the red baseline:** the apiclient suite has **13 failing tests in 6 classes**, not the disclosed 1. The load-bearing one: `newLiveServer` (check_test.go:79-93) never sets `WithEd25519Issuer(addr)`, so every minted token carries `iss "snaplink-sso"` ≠ the discovery issuer — breaking `TestSweep_GreenPath`, `TestStdoutDeterministic`, and 8 more. This matters because REQ-2's A9 ("golden runs pass unchanged") is unevaluable while those are red. I also found `TestMint_ResponseFail/status-400` is a mislabeled test (sends HTTP 200, not 400 — the sweep's status check is correct and pinned by the passing redirect-302 case).

## Design decisions

- **Two commits:** (1) a mandatory test-only prerequisite repairing the fixture (1 line) plus the disclosed expectation bugs, restoring the evaluable compatibility baseline; (2) the feature: `validEntityID` guarding 7 sites (exit 2, no request), opt-in `--admin-entities` T-8f group (no-flag byte-identity preserved), composed-gateway e2e (A10/A11), and the OpenAPI 404 row. No server wire changes, no config knob, no `Err*`.
- Failure modes are pinned to verified server behavior: 400 `tenant store not configured` = skip (documented unmounted signal); anything else = fail. Probe (b) flips only the operator's own tenant, warns before the flip, never introspects pre-suspend (cache masking), and skips when the token carries no `tenant_id`.
- Root gates (`TestArchitecture_*`, `TestMaintainability_*`) are red for pre-existing unrelated reasons (campaign doc artifacts; `ed25519_jwt_issuer.go` at 539 lines) — reported separately per AGENTS.md, not absorbed.
