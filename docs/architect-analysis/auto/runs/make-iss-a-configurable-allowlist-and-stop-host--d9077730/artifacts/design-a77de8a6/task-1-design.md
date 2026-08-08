Design complete. Wrote the deliverable to the pipeline output path: `docs/architect-analysis/auto/runs/make-iss-a-configurable-allowlist-and-stop-host--d9077730/artifacts/design-a77de8a6/task-1-design.md`. No production code touched.

## Verification outcome (every evidence claim re-checked against the tree at HEAD `81d42e12`)

**Confirmed**: `resolveIssuer` Host fallback (`server_discovery.go:251-255`, fallback untested); `d.ResolveIssuer` (`accessors_handlers.go:330`); `issue_payload.go:26-47` tenant_id/roles emission; billing `--allow-insecure-loopback` + `127.0.0.1:8080` dev flow; `oidc_discovery_test.go:80-86` covers only the configured case.

**Refuted as stated**: the "caep-only WithIssuer" claim — `config/config_load.go:308` already wires `sso.WithIssuer(c.Server.Issuer)`, pinned by `issuer_wiring_test.go`. Residual gap is exactly what the summary says: allowlist shape, strict mode, untested fallback.

**Material omissions found**: (1) `ops/deploy/*` configs already carry `issuer_allowlist` (warn-and-ignored today); (2) `handleMFAComplete` (`server_mfa.go:181` → `resumeLoginAfterMFA` → `wrapAuthorizationResponse`) is a second authorization-response entry — a gate on `handleLogin` alone is insufficient; (3) all line budgets, the 60-file ceiling, and `security_test.go` 1/2/4 pins measured as cited, including in-flight diffs.

## Design summary

- **API**: `server.issuer_allowlist` + `server.require_configured_issuer` (key shared with the unlanded configcmd sibling); `sso.WithIssuerAllowlist` / `sso.WithRequireConfiguredIssuer` in `sso_wiring.go` (not `options.go`, 490 lines); `core.ErrIssuerNotConfigured`; pure `core.NormalizeIssuer`/`IsAbsoluteIssuerURL`/`ValidateIssuerConfig` in `shared/core` so boot check and sibling validate gate agree by construction.
- **Boot fail-closed**: `s.validateIssuerConfig()` after the option loop (`sso.go` 499→500) — panics on empty/invalid allowlist or non-member issuer; cmd-path unset issuer panics (default `"sso-server"` can't be a member); SDK-only unconfigured path 503s at runtime.
- **Request gates**: one `denyUnconfiguredIssuer` helper + four one-line gates (G1 discovery before the body-cache lookup, G2 login, G3 MFA continuation — the missed entry, G4 token), covering all 8 RFC 9207 sites with no edits to the do-not-touch `server_finish_login.go`; credential 503s carry no-store structurally.
- **R5**: loopback dev expressibility is by allowlist-entry validity (`http://127.0.0.1:8080` is a legal entry) — no new server-side insecure flag.
- **Migration**: land switch-off → preflight via sibling `config validate` (landing-order dependency) → canary → fleet rollout → key-removal rollback, no binary rollback.
- **Acceptance mapping**: A-1..A-9 from the spec (T-2 → A-3/A-4/A-5, T-8(a) → A-1/A-2/A-7, billing dev leg → A-8) plus A-9a (MFA gate), A-10..A-16 (panics, normalization, byte-identity, option pins, `make ci`) with owner/test-file homes; every file's budget impact tabulated.

The one hard constraint to respect at implementation time: `sso.go` lands at exactly 500 lines — re-verify before touching if any in-flight diff reaches it.
