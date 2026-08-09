The design document is complete: `docs/architect-analysis/cmd-sso-ctl-legacysync-scope-registry-preflight-design.md` (474 lines, 8 sections).

## Verification verdict

Every claim in the evidence was re-checked against HEAD. **All substantive claims verified** — including the spec's own location corrections (the merged tenant-binding gate), with exact line numbers confirmed for `loadTargetClients` (target.go:173-174), `buildReport`/`validateMappedClientBindings` (:194-249), the plan.go fabrications (:186/:196/:200-204), the `/token` dispatch seam (server_token.go:132 → reject.go:31-43), the nine-scope Matrix (consts.go:25-36), the YAML-only config gate (:49/:58), the schema (clients.go:42), the server construction site (build_stores.go:306), and the U7 column-order pin (target_test.go:182).

Two findings, both handled in the design:

- **D1 (non-material)**: the spec's "non-test files go 7 → 8" is wrong — the package has 6 today; correct statement is 6 → 7, still ≤ 10.
- **D2 (material test defect)**: REQ-6's negative leg as written (client with `AllowedScopes: ["admin:read"]` requesting `legacy:menu:1:view`) would 400 via the *allowlist* gate (`GrantedScopes` rule 1), masking the registry seam it claims to pin. The design seeds the dirty allowlist (`["admin:read","legacy:menu:1:view"]`) so the rejection comes from exactly the predicate the pre-flight mirrors — acceptance text unchanged, mechanism made faithful.

## Design summary

- **API changes**: two CLI flags (`--scope-registry` bool, `--scope-registry-extra` comma-separated) with exit-2 fail-closed validation at parse time via a `parseScopeRegistryFlags` helper (keeps `parseFlags` at 48 ≤ 50); package-internal `commandConfig.ScopeRegistry`, `syncPlan.ScopeRegistry`, `targetSnapshot.ClientScopes` fields; new `buildScopeRegistry` + `validateScopeRegistration` in `scope_gate.go`; `buildReport` gains one call after the tenant gate. No server/protocol/discovery/config changes (T-2).
- **Compatibility**: unwired nil-registry short-circuit = byte-identical (T-9); `tenant_id` stays before `allowed_scopes` in the SELECT (U7 pin); `buildReport` signature unchanged so all existing tests compile untouched; 12 failure modes enumerated (F1-F12) with exit codes and containment.
- **Migration**: no storage/config migration (column exists since v1; flags additive); three-phase rollout (dry-run enumerate → reconcile extras → `--apply`); rollback = drop the flags.
- **Acceptance mapping**: T-8d neg/pos, T-2, T-9 each mapped to concrete unit tests (REQ-5), the `/token` integration harness with the D2 repair (REQ-6), and the mandatory/targeted/handoff gate commands.
