The requirements specification is complete at `docs/architect-analysis/auto/runs/make-iss-a-configurable-allowlist-and-stop-host--d9077730/artifacts/requirements-10762e10/requirements.md` (the pipeline-configured output path).

## Verification summary (HEAD `a1fafed7`)

Every cited file/symbol was re-checked against the tree:

| Citation | Verdict |
|---|---|
| `interfaces/sso/server_discovery.go:251-255` — `resolveIssuer` Host fallback | Confirmed (fallback branch untested) |
| `interfaces/sso/accessors_handlers.go:330` — `d.ResolveIssuer` | Confirmed |
| `cmd/sso-server/build_app_oidc.go:137` — "caep-only WithIssuer, never the server option" | **Refuted as stated** — `config/config_load.go:308` (`ServerOptions()` → `build_app_core.go:154` → `build_app.go:257`) already wires `sso.WithIssuer`, pinned by `cmd/sso-server/issuer_wiring_test.go`. The residual gap is the allowlist shape, the require-configured mode, and the untested unconfigured fallback |
| `infrastructure/defaultimpl/issue_payload.go:26-47` — tenant_id/roles/claimsWithoutEmittedKeys | Confirmed |
| `cmd/snaplink-billing/config.go` + README — mandatory trust boundary, `127.0.0.1:8080` dev flow, `--allow-insecure-loopback` (already exists — the "escape hatch analog" is needed on the *server-side allowlist*: loopback entries must be expressible) | Confirmed |
| `test/oidc_discovery_test.go:80-86` — only the configured case covered | Confirmed |

## Spec contents

- **§1-2**: evidence table + corrections (stale wiring claim; JWT `iss` is the signer's constructor value, so minted-token enforcement is boot-time; prior same-direction spec `bbdb82eb` re-verified — its shape is still unlanded and is adopted as the proposed mechanism).
- **§5 R1-R7**: requirements — `server.issuer_allowlist` + `server.require_configured_issuer` (key shared with the configcmd sibling), `WithIssuerAllowlist`/`WithRequireConfiguredIssuer`, boot fail-closed panics, 503 `issuer_not_configured` gates at discovery/login/token, loopback-dev expressibility (R5), mode-off byte-identity, and the billing-owned legs (R7).
- **§6**: the supplied checks preserved verbatim and decomposed into 9 deterministic Given/When/Then acceptances (A-1..A-9) with owner and test-file mapping: T-2 (A-3/A-4/A-5) and T-8(a) (A-1/A-2/A-7), including the billing `--allow-insecure-loopback` dev leg (A-8).
- **§7-10**: engineering gates re-measured at HEAD (60-file ceiling, 500-line budgets incl. the `sso.go:499` cap and do-not-touch files), dependencies, contract doc updates, verification commands, G1 handoff.

No production code was changed; the deliverable is documentation-only, and the dirty worktree files (e.g. `cmd/snaplink-billing/auth_test.go` B4-2 sibling test) are flagged for preservation.
