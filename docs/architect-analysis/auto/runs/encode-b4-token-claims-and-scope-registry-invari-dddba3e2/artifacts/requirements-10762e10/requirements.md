Requirements specification complete: `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-2-grant-scaffold-requirements.md`

## Verification results

Every cited symbol was checked against HEAD. **All core claims confirmed** with exact lines, plus two evidence corrections the spec records explicitly:

| Claim | Verdict |
|---|---|
| `grantTemplate` Handle example (templates_handler.go:174-215) forwards unvalidated `scopes` to `issuer.Issue`, no invalid_scope path | **Confirmed** — `TenantID: client.TenantID` is already present (pre-built binding) |
| `dispatchCustomGrant` (server_token.go:345) no scope check | **Confirmed with drift** — now at line 383; premise partially outdated: the B4-2 registry seam (`rejectUnregisteredScopes`, lines 189-204) now runs *before* custom grants, so the remaining gap is the per-client `GrantedScopes` gate + claims |
| `buildAccessPayload` (issue_payload.go:26) / `ed25519Payload` (ed25519_types.go:15) emit no tenant_id/roles | **Confirmed** — verified field-by-field gap |
| `Subject.TenantID` (types_token.go:231) | **Confirmed** — doc self-states "NOT a token claim" |
| handle_ciba.go:296-308 400 invalid_scope precedent | **Confirmed** — exact pattern (`GrantedScopes(SplitScope(...))` → `core.ErrInvalidScope`) |
| "scope registry symbols: not found (verified absent)" | **Rejected as stated** — B4-2 has landed: `protocols/oauth/scoperegistry` + `interfaces/scopecontract` + `WithScopeRegistry` + dispatch seam + `docs/error-codes.md:298` |
| `TestGeneratedScaffoldsCompile` compile-only gate | **Confirmed** — bare `go build ./...`, grant case `device-code` → `device-code_grant.go` (generate.go:82) |
| T-8(a)/T-8(d) mapping (implementation-gate.md rows 1-2) | **Confirmed** |

Also caught: the template's doc comment cites `interfaces/sso/options_saml2_bearer.go`, which does not exist (real handler: `server_setup.go:283`) — the spec includes the stale-citation fix.

## Spec shape (bounded to this direction)

- **R1** — template encodes `oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)` → `400 core.ErrInvalidScope` before any `issuer.Issue`, plus a note teaching the landed registry seam (`RejectUnregistered` on effective scopes)
- **R2** — pins `TenantID: client.TenantID` and the roles source (`permissions.Provider.Roles`, the repo's real roles path) into the Subject construction
- **R3** — `TestGeneratedScaffoldsCompile` grant subtest gains three artifact-level assertions (invalid_scope branch ordered before `issuer.Issue`; tenant binding; `Roles(` before issuance) with the compile gate unchanged
- **R4** — re-run after B4-1 lands, with contract-sync duty per AGENTS.md §5.6

Non-goals wall off B4-1 server work (defaultimpl/shared/core), landed B4-2 surfaces, and entry 2's `verify.go` raising. Acceptance checks preserved 1:1, made testable as Given/When/Then with named per-marker assertions.
