Design delivered to `docs/architect-analysis/auto/runs/enforce-content-type-form-urlencoded-on-credenti-b63aeb29/artifacts/design-a77de8a6/task-1-design.md` (the pipeline-configured output path for the design stage, hash confirmed deterministic via `sha256("design")[:8]`).

## Verification outcome (evidence was largely truthful, two inaccuracies found)

All 4 direction citations and every requirements-stage claim re-checked against the working tree at `0aab82b5`, with gates re-run:

- **Confirmed exact**: `bind.go:28-49` JSON-default seam (with load-bearing REGRESSION BOUNDARY comment); `BindParamsFormOnly`/`ErrFormOnly` (`bind_strict.go`); constant-time compare (`client_secret.go:19-32`); config `server.require_form_content_type` (`config_server.go:72`) + `WithCredentialFormOnly` (`options.go:107-113`); 27 tests (8 + 19) green; the R7 gap (`assertQuotaTokenRequest`:149 / `assertRetentionTokenRequest`:94 assert `PostForm` but never the CT header; no strict-mode e2e drives the three billing mints).
- **Confirmed with drift**: introspect bind now at `bindCredentialRequest`:154, PAR :73, revoke :82; CIBA :87 exact dual-mode (out of scope); oracle-safe plain-envelope discipline relocated to `rejectUnregisteredScopes` (`server_token.go:202`).
- **Pre-existing failures reproduced**: DirectoryDepth, DirectorySubdirFanout (root 24 > 21), FileSizeBudget (`ed25519_jwt_issuer.go` 539), `TestSdkForm_PARClaimsThreaded` documented-red interlock.
- **Evidence inaccuracies**: (1) "Two synced files (396 lines)" is false — the pipeline artifact is a 32-line stub containing the completion message; the 396-line named doc is the only spec (design deliberately emits one authoritative artifact). (2) The deploy flip is already `true` in `ops/deploy/compose/config.yaml:21`, so R7.2 proves a shipped deployment mode, not hypothetical hardening.

## Design core (the delta is test-only R7)

- **API changes**: none to production — the strict-wire surface (config key, SDK option, `ErrFormOnly` internal sentinel, 415 plain `{"error":"invalid_request"}` envelope on the four endpoints) is ratified as landed. Test-only: CT-header assertions in the two billing relay helpers; new `test/billing_form_e2e_test.go` driving the real `NewOAuthTokenSource` (audit `snaplink-relay`, quota `billing-quota-relay`) and `NewPlatformTokenSource` (retention `billing-retention-relay`) mints against a strict server, with a JSON control arm that must 415.
- **Compatibility**: default-off byte-identical; compose already strict with a single pinned flip point; CIBA/device/MFA dual-mode out of scope; zero billing production changes; budget ceilings respected.
- **Failure modes F1–F9** with detection (vacuous-pass control arm, token-cache-masked mints → fresh source per identity, header drift, strict-mode regression, deploy-tree drift, sibling interlock, flake, readyz 503 as the ops symptom).
- **Migration**: no production migration in this stage; operator steps restated (verify consumers → flip boot-time key → observe readyz → rollback by key removal).
- **Acceptance mapping**: T-1..T-6 → concrete existing test pins plus the two new R7 tests, and a 7-step verification plan ending at `make ci`.
