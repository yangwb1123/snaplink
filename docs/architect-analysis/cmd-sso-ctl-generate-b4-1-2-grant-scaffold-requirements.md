# Requirements Spec: encode B4 token-claims + scope-registry invariants into the grant scaffold

- Direction: entry 1 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-generate-3176af89.json` (selected)
- Module: `cmd/sso-ctl/generate` (`grantTemplate` in `templates_handler.go`, `TestGeneratedScaffoldsCompile` in `scaffold_build_test.go`)
- Status: requirements (evidence-verified against HEAD)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/generate/templates_handler.go:174-215` — grantTemplate `Handle` example forwards `req.Scope` unvalidated to `issuer.Issue`, no registry gate, no invalid_scope path | `grantTemplate` const starts at line 139; the `Handle` example block is lines 174–215. It teaches: step 1 validates only grant-specific params (e.g. `req.Assertion`); step 2 calls `issuer.Issue(ctx.Request().Context(), &core.Subject{ID: ..., ClientID: client.ID, TenantID: client.TenantID}, scopes)` where `scopes` is derived from `req.Scope` with NO `GrantedScopes`/allowlist branch and NO `core.ErrInvalidScope` path. `TenantID: client.TenantID` IS already present (tenant binding pre-built at Subject level). No roles reference anywhere in the template | Confirmed (exact lines; `scopes` source is the step-1 comment "req.Scope/req.Resource otherwise") |
| `interfaces/sso/server_token.go:345` — `dispatchCustomGrant` performs no scope check for custom handlers | Function actually at line 383 (drift 38): registry lookup on `req.GrantType`, then `handler.Handle(ctx, client, req, dpopJKT, mtlsX5T)`. No scope check inside | Confirmed with drift; premise partially OUTDATED: `dispatchTokenGrant` (lines 119–146) now runs `rejectUnregisteredScopes` (lines 189–204 → `scoperegistry.RejectUnregistered`) BEFORE `dispatchCustomGrant` (call at line 144), so request-borne scopes ARE registry-gated for custom grants when a registry is wired. The per-client `AllowedScopes` gate (`oauth.GrantedScopes`) is still NOT applied to custom grants — only the registry seam is |
| `infrastructure/defaultimpl/issue_payload.go:26` — `buildAccessPayload` emits neither tenant_id nor roles | Function at line 26 (exact). Emits `iss/sub/exp/nbf/iat/scope/ext/client_id/jti/acr/sid/serving_region` + optional (`cnf`, `auth_time`, `amr`, `authorization_details`, `act`, `_claims_`, `aud`). No `tenant_id`, no `roles` | Confirmed (verified gap) |
| `infrastructure/defaultimpl/ed25519_types.go:15` — `ed25519Payload` has no tenant_id/roles fields | Struct at line 15 (exact). Fields: `Iss/Sub/Aud/Exp/Nbf/Iat/Scope/GrantedResources/Extra/ClientID/JTI/AuthTime/ACR/AMR/SID/CNF/ServingRegion/AuthorizationDetails/Act/RequestedClaims`. No `tenant_id`, no `roles` | Confirmed (verified gap) |
| `shared/core/types_token.go:231` — `Subject.TenantID` exists as the claim source | Field at line 231 (exact), doc: "Policy-input ONLY: the ClampingIssuer scopes max_ttl rules with it. NOT a token claim — issuers emit only fields they enumerate in buildAccessPayload." `Subject` is aliased `sso.Subject = core.Subject` (interfaces/sso/aliases.go:132); `core.TokenIssuer.Issue(ctx, *Subject, []string)` at shared/core/spi.go:245-249 | Confirmed; the doc self-documents the claim gap (tenant_id/roles claims are B4-1 work, not yet landed) |
| `protocols/oauth/handle_ciba.go:296-308` — existing 400 invalid_scope precedent | `persistCIBARequest` lines 296–308 (exact): comment 296–299 + `grantedScopes, err := GrantedScopes(SplitScope(req.Scope), client)`; on error `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))` at line 308. Same pattern at `handle_par.go:198` and `internal/handler/tokengrant/token_client_credentials.go:38-40` | Confirmed (this is the canonical pattern to encode) |
| "scope registry symbols: not found (verified absent — proposed)" | OUTDATED — B4-2 has LANDED since the analysis snapshot: `protocols/oauth/scoperegistry` exists (`registry.go`, `reject.go`; `RejectUnregistered` at reject.go:31-40, `FilterRegistered` at 48-53); wired via `WithScopeRegistry` (interfaces/sso/options_misc.go:482-495), accessor `ScopeRegistry()` (interfaces/sso/accessors_handlers.go:163-166), dispatch seam `rejectUnregisteredScopes` (interfaces/sso/server_token.go:189-204); matrix `interfaces/scopecontract/consts.go` (scope-matrix-v2, "campaign B4-2"); config `oauth.scope_registry.{enabled,matrix,extra_scopes}` (docs/config-reference.md:20); error surface docs/error-codes.md:298. The scaffold's registry obligation is therefore to TEACH the landed seam, not to create a registry | Rejected as stated — premise corrected; direction intent (scaffold must not bypass the gate) still holds |
| `TestGeneratedScaffoldsCompile` (scaffold_build_test.go) — compile-only gate | Verified: builds each kind into an isolated temp module (`newBuildableModule`) and runs bare `go build ./...` (no vet, no content assertions). Grant case: `{"grant", "protocols/grants", "device-code"}`, output `gen/protocols/grants/device-code_grant.go` (filename per generate.go:82 `"%s_grant.go"` with raw `s.Name`). A template regression that keeps compiling passes the gate | Confirmed |
| `verifyGeneratedBuild` (verify.go) — bare `go build` | Verified (`go build target` only). Out of this direction's scope (entry 2's territory); noted as boundary | Confirmed (not modified here) |
| T-8(a) / T-8(d) mapping | docs/campaigns/implementation-gate.md row 1: T-8(a) = `POST /token` → 200 + kid + claims `{iss/aud/scope/client_id/tenant_id/roles}`; row 2: T-8(d) = scope registry registers scope-matrix-v2 full table; unregistered scope → 400 `invalid_scope`. G5 gate row 2 (B4-2) is registry-server work already landed | Confirmed (generated-code inspection is a proxy for both; wire-level tests are server-side) |
| Roles source for the scaffold to reference | Real roles source: `domains/permissions/provider.go` `Provider.Roles(ctx, userID, clientID) ([]permissions.Role, error)`; used at interfaces/sso/accessors_handlers.go:103 (`s.permissions.Roles`), mesh_authz.go:326. The B4-1 `roles` claim's exact plumbing into `buildAccessPayload` is not yet defined in code | Confirmed (repo's existing roles source is the reference point; handoff shape pinned when B4-1 lands) |
| GrantHandler extension point + real example | `oauth.GrantHandler` at protocols/oauth/grant_handler.go:14 (verified); `saml2BearerHandler` registered at interfaces/sso/server_setup.go:271, `Handle` at 283. NOTE: the template doc comment cites "interfaces/sso/options_saml2_bearer.go" — that file does not exist (stale reference). The real production grant paths apply the exact pattern this spec encodes: `token_saml2_bearer.go:53,108-109` (`authorizeSAML2Scopes` → `oauth.GrantedScopes` → 400 invalid_scope) and `token_client_credentials.go:38-40` | Confirmed with a stale-citation fix included in §7 |
| `core.ErrInvalidScope` / `oauth.GrantedScopes` / `oauth.SplitScope` | `ErrInvalidScope = "invalid_scope"` at shared/core/errors.go:170; `GrantedScopes`/`SplitScope` exported from `protocols/oauth` via aliases.go:119-120 (oauthvalidate/scope.go:27,80); `GrantedScopes` semantics: allowlist gate (rules 1–4), `ErrScopeNotAllowed`, caller maps to 400 invalid_scope, oracle-safe | Confirmed |

Net: the direction's core claims hold (scaffold teaches the bypass pattern; claims gap is real; compile-only gate). Two corrections: (1) the scope registry EXISTS at HEAD, so the scaffold change teaches the landed seam instead of proposing a new one; (2) `dispatchCustomGrant` line drifted 345→383 and the dispatch-level registry seam now precedes it, so "every scaffolded grant ships the violating pattern" is exact only for the per-client `AllowedScopes` gate (`GrantedScopes`) and the claims side — which is precisely what this spec encodes.

## 2. Goal and user outcome

`sso-ctl generate grant` is the codebase's only generator for the `oauth.GrantHandler` extension point — the exact surface B4-1 (tenant_id/roles claims) and B4-2 (scope registry → 400 invalid_scope) regulate. Today the scaffold's `Handle` example teaches the violating pattern: request scopes flow into `issuer.Issue` with no `GrantedScopes`/invalid_scope branch and no roles resolution, so every generated custom grant ships a grant that (a) never applies the per-client allowlist gate at issuance, (b) never resolves or carries the roles claim source, and (c) depends on the dispatch seam alone for registry enforcement.

Completion marker: a developer who runs `sso-ctl generate grant --name x --package protocols/grants` gets a `Handle` example that contains, before any `issuer.Issue` call, the same `oauth.GrantedScopes` → 400 `core.ErrInvalidScope` branch every built-in grant path uses, the `TenantID: client.TenantID` binding, and a roles-source reference — and `TestGeneratedScaffoldsCompile` fails if any of the three regresses.

## 3. Product boundary

- Surface: `cmd/sso-ctl/generate` (scaffold generator + its regression test). No server, protocol, or config changes.
- Default: template text change is the default output of the existing `grant` kind; test assertions run in the existing test suite.
- Explicit non-goals (do not implement):
  - No changes to `infrastructure/defaultimpl/issue_payload.go`, `ed25519_types.go`, or `shared/core/types_token.go` — emitting `tenant_id`/`roles` claims is B4-1 server work, its own module.
  - No changes to `protocols/oauth/scoperegistry`, `interfaces/scopecontract`, `interfaces/sso/server_token.go`, `options_misc.go`, or `docs/config-reference.md` — B4-2 registry already landed; the scaffold only teaches it.
  - No new CLI flags, subcommands, or generated file kinds; no change to `verify.go` (bare-`go build` raising is entry 2's scope).
  - No change to the other three scaffold kinds (`authenticator`/`store`/`handler`) — their templates are untouched.
  - No change to the template mechanism (comment-block example + fail-closed `invalid_grant` default body stays the design; the example is the teaching artifact the test inspects).

## 4. Module classification

- [x] Infrastructure/config/deployment (scaffolding tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/generate` (composition layer, owns templates + their regression gate). Dependency direction: the test already imports nothing new beyond the stdlib + `os/exec`; the template's example text references `protocols/oauth` symbols (`GrantedScopes`, `SplitScope`) already imported by the generated scaffold (`oauth` import exists at templates_handler.go:145). No import-graph change.

## 5. Requirements

### R1 — grantTemplate encodes the scope gate before issuance

The `Handle` example block (templates_handler.go:174-215) must teach, before any `issuer.Issue` call:

```go
grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
if err != nil {
	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
	return
}
```

matching `persistCIBARequest` (handle_ciba.go:306-308) and `token_client_credentials.go:38-40` byte-for-byte in semantics: plain `core.ErrorBody` body (no trace_id), 400, oracle-safe. The issuance example must pass `grantedScopes` (the validated set), never raw `req.Scope`. The example must also carry a note that the dispatch-level registry seam (`rejectUnregisteredScopes` → `scoperegistry.RejectUnregistered`, wired via `WithScopeRegistry`/`oauth.scope_registry.enabled`) already rejects unregistered request-borne scopes before custom handlers run, and that scopes a handler mints internally must pass the same registry check on the EFFECTIVE set before issuance (per scoperegistry/reject.go's contract).

### R2 — grantTemplate encodes the tenant binding and the roles source

The example must keep `TenantID: client.TenantID` in the `core.Subject` literal (B4-1's `tenant_id` claim source is the client binding; the template already carries it — now pinned by test) and must resolve roles from the roles source — a deps accessor mirroring `permissions.Provider.Roles(ctx, userID, clientID)` (domains/permissions/provider.go; used at accessors_handlers.go:103) — and hand them into the Subject (via `Subject.Claims` or the dedicated Subject field B4-1 defines; the exact handoff is pinned when B4-1 lands — contract-sync duty per AGENTS.md §5.6).

### R3 — TestGeneratedScaffoldsCompile gains contract assertions on generated grant output

In the `grant` subtest, after `scaffold.Generate(outputDir)`, read the generated file `filepath.Join(outputDir, "device-code_grant.go")` (filename rule generate.go:82, raw `s.Name` + `_grant.go`) and assert, before the existing `go build ./...` gate:

1. **A1 (scope gate, maps T-8(d))**: the file contains `GrantedScopes(`, `SplitScope(`, and `core.ErrInvalidScope`, and `strings.Index(core.ErrInvalidScope) < strings.Index("issuer.Issue(")` — the invalid_scope branch precedes any issuance.
2. **A2 (tenant binding, maps T-8(a))**: the file contains `TenantID: client.TenantID`.
3. **A3 (roles source, maps T-8(a))**: the file contains `Roles(` — the roles-source call — and its position precedes `issuer.Issue(`.

Assertions run on the generated artifact (which includes the template's comment text verbatim), not on the template source, so a template regression fails the gate exactly as the direction requires. The compile gate stays: the isolated-module `go build ./...` proves the generated package still builds.

### R4 — Re-run against the completed B4-1 issuer path

B4-2 has landed; B4-1 has not. When B4-1 lands (`buildAccessPayload` gains `tenant_id`/`roles`), re-run this module's gates (`go test ./cmd/sso-ctl/generate/...`) so (a) the compile gate proves the scaffold still builds against the completed issuer path, and (b) if B4-1 changes the `Subject`/issuer surface, the template example and R3 markers are updated in the same change (contract-sync, AGENTS.md §5.6). Until then, A3's marker is the repo's existing `permissions.Roles` symbol, which exists today.

### Testable acceptance (Given/When/Then)

1. Given `sso-ctl generate grant --name device-code --package protocols/grants` (the existing test path), when the generated file is inspected, then it contains the `GrantedScopes(`/`SplitScope(`/`core.ErrInvalidScope` branch textually before the `issuer.Issue(` call (A1).
2. Given the same generated file, when inspected, then it contains `TenantID: client.TenantID` (A2) and a `Roles(` roles-source reference before issuance (A3).
3. Given any future template edit that removes the invalid_scope branch, reorders it after `issuer.Issue(`, drops the tenant binding, or drops the roles reference, when `TestGeneratedScaffoldsCompile` runs, then the grant subtest fails with a named assertion (each marker asserted separately so the failure names the violated invariant).
4. Given the generated grant package, when the isolated-module `go build ./...` runs, then it succeeds (existing compile gate unchanged; fail-closed `invalid_grant` default body untouched).
5. Given the B4-1 landing change, when `go test ./cmd/sso-ctl/generate/...` runs against it, then the compile gate passes against the completed issuer path, and any required marker update lands in the same change (R4).

## 6. Engineering-gate constraints (verified)

- Budgets: `templates_handler.go` is 215 lines / 500 cap (the example block grows ~25 comment lines); `scaffold_build_test.go` is 122 lines / 500 cap (grant subtest grows ~15 lines). Function lengths: `TestGeneratedScaffoldsCompile` stays under 50 lines (assertions factored into a small helper if needed); the template is data, not code. No directory/fan-out changes (no new files in `cmd/sso-ctl/generate` beyond tests, if a helper file is preferred — currently one modified test file is enough).
- `interfaces/sso` 60-file ceiling untouched (no edits there).
- No `Err*` additions, no OpenAPI/config/error-code changes (R1's `invalid_scope` is `core.ErrInvalidScope`, already registered at docs/error-codes.md:298).

## 7. Files

### Create

```text
(none — both changes are modifications)
```

### Modify

```text
cmd/sso-ctl/generate/templates_handler.go — grantTemplate Handle example block
    (lines ~174-215): insert the GrantedScopes → 400 core.ErrInvalidScope branch
    and the registry-seam note (R1); keep TenantID: client.TenantID and add the
    roles-source resolution step into the Subject construction (R2); fix the
    stale template doc citation "interfaces/sso/options_saml2_bearer.go" →
    "interfaces/sso/server_setup.go (saml2BearerHandler)" (verified: the file
    does not exist).
cmd/sso-ctl/generate/scaffold_build_test.go — grant subtest: after Generate,
    read device-code_grant.go and assert A1 (invalid_scope branch present and
    ordered before issuer.Issue), A2 (TenantID: client.TenantID), A3 (Roles(
    before issuer.Issue), then the existing go build ./... gate (R3).
```

### Do not modify

```text
protocols/oauth/{scoperegistry,handle_ciba.go,oauthvalidate} — landed B4-2 +
    the precedent pattern; server-side.
interfaces/sso/server_token.go, options_misc.go, accessors_handlers.go —
    dispatch seam + wiring; landed B4-2.
infrastructure/defaultimpl/issue_payload.go, ed25519_types.go,
shared/core/types_token.go — B4-1 claim work, its own module.
cmd/sso-ctl/generate/verify.go — bare go build raising is entry 2's scope.
docs/error-codes.md, docs/config-reference.md, docs/openapi.yaml — no new
    surface (core.ErrInvalidScope already registered).
```

## 8. Dependencies and compatibility

- New/changed SPI: none (template text only; generated output is a starting point, not a shipped API).
- New option/store wiring: none.
- New YAML/env keys: none.
- Storage migration: none.
- HTTP/proto compatibility: none.
- Rollout/rollback: pure generator + test change; `sso-ctl generate grant` output text changes for new scaffolds only — already-generated files are unaffected. Reverting the template restores prior output exactly.

## 9. Documentation

- [ ] `docs/openapi.yaml` — not applicable (no server endpoint).
- [ ] `docs/error-codes.md` — not applicable (`invalid_scope` already registered at line 298; the scaffold now emits the registered code instead of teaching its absence).
- [ ] `docs/config-reference.md` — not applicable (no config knob; the registry seam is documented at line 20).
- [x] Campaign traceability: this advances implementation-gate.md rows 1 (T-8(a) claim sources) and 2 (T-8(d) registry) on the scaffold-compliance axis; wire-level T-8(a)/T-8(d) tests remain the B4-1/B4-2 server deliverables.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v
go test ./cmd/sso-ctl/... -race
make ci
```

Follow-up (post-B4-1 landing, per R4): re-run the above and confirm the scaffold compiles against the completed issuer path; update R3's markers in the same change if B4-1 alters the Subject/issuer surface.
