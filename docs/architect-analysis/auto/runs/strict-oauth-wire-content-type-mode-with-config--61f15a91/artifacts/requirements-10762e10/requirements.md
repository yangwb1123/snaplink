The requirements specification is written. Here's a summary of the deliverable and the verification work:

## Deliverable

`docs/architect-analysis/auto/runs/strict-oauth-wire-content-type-mode-with-config--61f15a91/artifacts/requirements-10762e10/requirements.md` — the evidence-backed spec for the B4-4 strict-wire direction, written to the pipeline's expected artifact path.

## Verification results (every cited file/symbol checked against HEAD)

| Citation | Result |
|---|---|
| `oauthwire/bind.go:28-51` JSON default for missing/unknown CT | ✅ Verified (:28-48; `default:` :43-46 → `decodeSingleJSON`) |
| `config_oauth2.go:85-91` `OAuthConfig`, no strict-wire field | ✅ Verified with line drift (now :68-101; `validateScopeRegistry` added at top) |
| `config_oauth2.go:94-130` `ScopeRegistryConfig` default-off precedent | ✅ Verified (now :123-137; "Default-off" doc :106-110; called from `config_load.go:220`) |
| `main_test.go` `TestRun_Schema_ScopeRegistryMatrix` (A4) + `TestRun_Validate_ScopeRegistry_*` | ✅ Verified (:180-235 and A1-P4 fixtures) |
| `server_token.go:17` | ⚠️ Line-drifted (imports end); operative facts at :22 (no-store) and :30 (`bindOAuthParams`) |
| `bind.go:39-42` form path | ✅ Verified (:38-42) |
| All four endpoints bind via `BindParams` | ✅ Verified (introspect :120, revoke :75, par :66, aliases :97) |
| No strict knob anywhere; JSON acceptance live-tested (`handle_token_test.go:59,87`) | ✅ Verified |
| Loader unknown-key pass is warn-only | ✅ Verified (`source.go:257-275`) — this drives the C3 design |

## Key decisions (recorded in the spec)

- **Knob**: `oauth.strict_wire_content_type` on `OAuthConfig`, default-off byte-compat — per the direction's `oauth.*` mandate; lineage's `security.strict_credential_content_type` (0a8df02f) recorded as rejected/dead-key.
- **C3 posture assertion pinned**: the ambiguous supplied check ("validate exits 1 for strict=on with no form-urlencoded route fallback documented") is pinned to a fail-closed rule: `validate` scans raw YAML for the strict-wire key family; any hit that does **not** resolve to `true` in the resolved config exits 1 — the only semantics consistent with a shippable strict=on config, and exactly the "typo ships a JSON-accepting token endpoint" hole the direction targets. Alternatives (acknowledgment field, docs-content gate) recorded as rejected.
- **400 vs 415**: pinned to `400 invalid_request` (byte-identity with today's bind failures, no new error surface), per the lineage's R5.
- **RFC quibble**: direction cites RFC 8628 §3.1 for `/par`; corrected to RFC 9126 §2.1.
- All six supplied acceptance checks preserved and made testable with named test homes (configcmd exit-code fixtures, `test/` ssotest table, `shared/security` timing test, permissive-binder pins), including the strict-off byte-compat lock (`handle_token_test.go:59,87` pass unmodified) and the PAR RAR/claims caveat.
