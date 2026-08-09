The requirements specification is complete and written to `docs/architect-analysis/cmd-sso-ctl-legacysync-scope-registry-preflight-requirements.md`.

## Verification summary

Every cited symbol was checked against HEAD; the analysis's citations were **accurate in substance but stale in location** because the sibling tenant-binding direction (B4-1) has since landed. Corrections recorded in the spec's evidence table:

| Claim | Result |
|---|---|
| `loadTargetClients` never reads `allowed_scopes` | **Verified** — now `SELECT id,COALESCE(tenant_id,'') FROM clients WHERE active=1` (target.go:173-174); the tenant column is the merged sibling gate, `allowed_scopes` still absent |
| `buildReport` has no scope check | **Verified** — existence/active/tenant gate only (target.go:194-214, 216-249); no registry consultation |
| `plan.go` fabrications (`legacyRoleCode`:186, `menuPermission`:196, `overridePermission`:200-204) and `planGrants` roleMap (118-141) | **Verified**, exact lines |
| Registry seam → plain `400 invalid_scope` before grant branches | **Verified** — `dispatchTokenGrant` seam at server_token.go:132, `rejectUnregisteredScopes` 189-207, `scoperegistry/reject.go:31-43` |
| Nine-scope `Matrix` | **Verified** — `scopecontract/consts.go:25-36` |
| Config gate is YAML-only | **Verified** — membership check at config_oauth2.go:56-64 only when `Enabled` (:49), iterating `c.Clients` (:58) |
| Enablement order in docs/config-reference.md:20 | **Verified** |

Supplementary evidence the analysis lacked but the spec now grounds on: real schema `allowed_scopes TEXT NOT NULL DEFAULT '[]'` (sqlite/clients.go:42, incl. the `'null'` case from `json.Marshal(nil)`), the `GrantedScopes` default-to-allowlist rule that makes dirty `allowed_scopes` mint by default, `build_stores.go:306` registry construction (the predicate the pre-flight must mirror), `WithScopeRegistry`, and the `test/handle_token_test.go` / `legacy_sync_tenant_claim_test.go` harnesses for the integration leg.

## Spec design (bounded to the direction)

- **Opt-in wiring**: `--scope-registry` + `--scope-registry-extra` flags mirroring `oauth.scope_registry.{enabled,extra_scopes}`; nil registry = byte-identical no-op (T-9). This is the only reading consistent with T-8d ("exits 1") *and* T-9 ("no wiring → byte-identical").
- **Uniform predicate**: `scoperegistry.NewMemory(scopecontract.Matrix(), extras)` — construction-identical to the server, so the pre-flight can never disagree with `/token`.
- **Three checked sets**: mapped clients' `allowed_scopes` (S1), imported role permissions incl. menu/override fabrications (S2), and role codes (S3, named in the direction's problem).
- **Minimal churn**: new `syncPlan.ScopeRegistry` field + parallel `ClientScopes` map keep every existing test compiling untouched; lazy JSON parsing keeps unwired runs byte-identical; SELECT column order preserves the pinned missing-`tenant_id` error.
- All four supplied acceptance checks preserved and mapped to testable forms (REQ-5 unit tests, REQ-6 `/token` 200/400 integration, T-2 file-scope pin, T-9 golden + no-op tests), with budget checks (target.go 435→~445, `parseFlags` needs a helper extraction to stay ≤50) and the verification plan.
