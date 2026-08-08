All citations are now verified with exact line numbers. Here is the evidence-backed requirements specification.

---

# Requirements Spec: encode the B4-2 per-client scope gate + B4-1 claim sources into `grantTemplate` with A1–A3 contract assertions

- **Direction**: entry 1 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-generate-3176af89.json` (selected, value 9 / risk 8 / effort 4 / confidence 10)
- **Module**: `cmd/sso-ctl/generate` (`grantTemplate` in `templates_handler.go`; `TestGeneratedScaffoldsCompile` in `scaffold_build_test.go` + `scaffold_contract_test.go` helpers)
- **Baseline**: committed spec `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-2-grant-scaffold-requirements.md` (R1–R3), unlanded at HEAD. Worktree carries the verify-gate spec uncommitted (`cmd.go`, `verify.go`, `scaffold_build_test.go`, `templates_handler.go` modified; `scaffold_contract_test.go` untracked); the grant-scaffold B4-1/2 change is not among them.

## 1. Evidence verification (re-checked against the repository at HEAD)

| Direction citation | Measured reality | Verdict |
|---|---|---|
| `templates_handler.go` grantTemplate `Handle` example forwards raw `req.Scope`-derived scopes to `issuer.Issue`; `TenantID: client.TenantID` present; zero `GrantedScopes`/`SplitScope`/`ErrInvalidScope`/`Roles` | `const grantTemplate` at :150 (doc comment :139–149); `Handle` at :185; step 1 (:189–201) validates only grant params (`req.Assertion` :192); `issuer.Issue(ctx..., &core.Subject{...})` at :204 with `TenantID: client.TenantID` at :207 and `}, scopes)` at :208. `grep -n 'GrantedScopes\|SplitScope\|ErrInvalidScope\|Roles' templates_handler.go` → exit 1, zero matches | **Confirmed** (example block is :185–215, not 174–215; the direction's 174–215 range includes the struct/GrantType doc — cosmetic drift) |
| `interfaces/sso/server_token.go:189-204` `rejectUnregisteredScopes` — dispatch seam precedes custom grants (:132/144) | Seam comment :189–202, func at :203, call at :136 (before `denyTokenScopeCombo` at :142 and `dispatchCustomGrant` call at :144); `dispatchCustomGrant` at :383. It gates only the registry, not per-client `AllowedScopes` | **Confirmed** (spec's drift correction 345→383 holds; the per-client allowlist gap for custom grants is real) |
| `protocols/oauth/handle_ciba.go:296-308` + `internal/handler/tokengrant/token_client_credentials.go:38-40` — canonical invalid_scope pattern | `persistCIBARequest` comment :296–304, `grantedScopes, err := GrantedScopes(SplitScope(req.Scope), client)` :306, `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))` :308. CC grant: `oauth.GrantedScopes(scopes, client)` :38, 400 branch :40, followed by `scoperegistry.RejectUnregistered` on the resolved set :46 | **Confirmed** — both branches byte-match the plain-body oracle-safe shape; CC grant additionally shows the effective-scope registry check R1 must teach |
| `oauth.SplitScope`/`GrantedScopes` aliases | `protocols/oauth/aliases.go:119-120` (`SplitScope` :119, `GrantedScopes` :120); implementations `oauthvalidate/scope.go:27` (`SplitScope`, nil-for-empty) and :80 (`GrantedScopes`, allowlist gate rules 2/4, `ErrScopeNotAllowed`, oracle-safe) | **Confirmed** |
| `core.ErrInvalidScope` | `shared/core/errors.go:170` (`= "invalid_scope"`); registered at `docs/error-codes.md:298` (400, per-client allowlist + registry semantics, oracle-safe) | **Confirmed** |
| `scoperegistry` landed | `protocols/oauth/scoperegistry/{registry.go,reject.go}`; `RejectUnregistered` reject.go:31–40 (plain invalid_scope body, nil-registry no-op, "effective scopes" contract in its doc), `FilterRegistered` :48–53 | **Confirmed** — scaffold must TEACH the landed seam, not create one |
| "The server side is landed at HEAD: buildAccessPayload emits TenantID (:46) and Roles (:86–87)" | `infrastructure/defaultimpl/issue_payload.go`: `buildAccessPayload` at :27; `TenantID: subject.TenantID` at :46 (unconditional literal, `omitempty`); `payload.Roles = append(...)` at :86–87 under `len(subject.Roles) > 0` (AMR guard+copy discipline); `ed25519Payload` carries `tenant_id,omitempty` and `roles,omitempty` (ed25519_types.go); `Subject.TenantID` (types_token.go:236) and `Subject.Roles []string` (:249) documented as claims emitted by `buildAccessPayload`; `claimsWithoutEmittedKeys` strips `ext` copies (`KeyTenantID`/`KeyRoles` at consts_wire.go:169/277) | **Confirmed — direction correct; the committed spec's §1 rows on issue_payload.go / ed25519_types.go / types_token.go are STALE** ("emits neither…verified gap" is false at HEAD; the `Subject.TenantID` doc quote "NOT a token claim" is the pre-B4-1 wording). **B4-1 has landed** |
| Roles source | `permissions.Provider.Roles(ctx, userID, clientID) ([]Role, error)` at `domains/permissions/provider.go:38`; `Role` struct at types.go:16; call site at `interfaces/sso/accessors_handlers.go:104` (direction cites :103 — off-by-one) | **Confirmed** (role codes are `[]string`-shaped for `Subject.Roles`) |
| `TestGeneratedScaffoldsCompile` — compile-only gate | Grant case `{"grant", "protocols/grants", "device-code"}`; reads `generatedFile(...)` = `device-code_grant.go` (rule at `generate.go:79` `%s_grant.go`, mirrored in `generatedFile` helper); gate = content assertions → `go build ./...` → `go vet ./...` (vet added by the worktree verify-gate change) | **Confirmed** — content assertions exist for error codes/paths/Content-Type, but none for the grant scope gate or claims |
| `GrantHandler` extension point | `protocols/oauth/grant_handler.go:14` exactly; `TokenRequest.Scope` at `oauthwire/token_request.go:15` | **Confirmed** |
| T-8(a)/T-8(d) mapping | `docs/campaigns/implementation-gate.md` row 1: T-8(a) = `POST /token` → 200 + kid + `{iss/aud/scope/client_id/tenant_id/roles}`; row 2: T-8(d) = registry matrix-v2, unregistered → 400 `invalid_scope` | **Confirmed** — generated-code inspection is the proxy; wire-level tests are server-side, out of scope |
| T-9 `TestRunExitCodes` | Lives in `scaffold_contract_test.go`; exercises only the handler kind + exit codes 2/1/0; no CLI surface touched by this change | **Confirmed** |

**Net**: the direction's claims hold at HEAD with two material updates. (1) **B4-1 claim emission is landed** — the committed spec's "verified gap" rows are stale, and R4's deferred contract-sync is now due in this change: the roles handoff is pinned to `Subject.Roles` (`Roles: roles`), not `Subject.Claims`. (2) `GrantedScopes` remains the only missing per-client gate for custom grants; the scaffold currently teaches exactly that bypass.

## 2. Goal and user outcome

`sso-ctl generate grant` is the only generator for the `oauth.GrantHandler` extension point — the surface B4-1 (tenant_id/roles claims) and B4-2 (per-client scope gate) regulate. The scaffold's `Handle` example ships the violating pattern: request scopes flow into `issuer.Issue` with no `GrantedScopes`/invalid_scope branch and no roles source.

Completion marker: `sso-ctl generate grant --name x --package protocols/grants` yields a `Handle` example containing, textually before any `issuer.Issue(`: the `oauth.GrantedScopes` → 400 `core.ErrInvalidScope` branch (issuance passing the validated `grantedScopes`), `TenantID: client.TenantID`, and a `Roles(` source reference — and `TestGeneratedScaffoldsCompile`'s grant subtest fails with a named assertion per invariant if any regresses.

## 3. Product boundary

- **Surface**: `cmd/sso-ctl/generate` — `grantTemplate` text + test assertions. No server, protocol, config, or docs changes.
- **Default**: template text change is the default output of the existing `grant` kind; assertions run in the existing suite.
- **Explicit non-goals (do not implement)**:
  - No changes to `infrastructure/defaultimpl/`, `shared/core/types_token.go` — claim emission already landed; the scaffold only teaches it.
  - No changes to `protocols/oauth/scoperegistry`, `interfaces/scopecontract`, `interfaces/sso/server_token.go`, `options_misc.go`, `docs/config-reference.md` — B4-2 registry landed; the scaffold teaches the seam (R1 note), including the CC-grant precedent of a post-resolution `RejectUnregistered` on internally-minted scopes.
  - No CLI flags, subcommands, kinds, or exit-code changes (`cmd.go`, `verify.go` untouched) — T-9.
  - No changes to the `authenticator`/`store`/`handler` templates.
  - **Entry-2 items excluded** (iss-allowlist teaching, stale citation `interfaces/sso/options_saml2_bearer.go` — verified absent; real example `saml2BearerHandler` at `server_setup.go:271` registration, `:275` struct, `:279` GrantType): the citation fix belongs to direction entry 2's acceptance; do not fold it in here.
  - **Entry-3 items excluded** (store audit-governance teaching).

## 4. Module classification

- [x] Infrastructure/config/deployment (scaffolding tooling) — composition layer owning templates + regression gate.
- No import-graph change: the generated file already imports `protocols/oauth` and `shared/core`; all new text is inside the template's comment example, so the generated package compiles unchanged in shape.

## 5. Requirements

### R1 — `grantTemplate` encodes the per-client scope gate before issuance (B4-2, maps T-8(d))

The `Handle` example (templates_handler.go:185–215) must insert, as its own step **before** the `issuer.Issue(` step:

```go
//    grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
//    if err != nil {
//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
//    	return
//    }
```

Semantically byte-matching `persistCIBARequest` (handle_ciba.go:306–308) and `token_client_credentials.go:38–40`: plain `core.ErrorBody` (no trace_id), 400, oracle-safe. The issuance step must pass `grantedScopes`, never raw `req.Scope`-derived `scopes`. The step must carry a note (comment text) that the dispatch-level registry seam (`rejectUnregisteredScopes` → `scoperegistry.RejectUnregistered`, wired via `WithScopeRegistry`/`oauth.scope_registry.enabled`) already rejected unregistered **request-borne** scopes before this handler ran, and that scopes a handler mints **internally** must pass the same `RejectUnregistered` check on the effective set before issuance (reject.go contract; CC-grant precedent at token_client_credentials.go:46).

### R2 — `grantTemplate` encodes the tenant binding and the roles source (B4-1, maps T-8(a))

- Keep `TenantID: client.TenantID` in the `core.Subject` literal (the B4-1 `tenant_id` claim source; emitted unconditionally by `buildAccessPayload`, issue_payload.go:46) — now pinned by test.
- **Contract-sync update (R4 triggered — B4-1 is landed at HEAD)**: resolve roles before issuance from an accessor mirroring `permissions.Provider.Roles(ctx, userID, clientID)` (provider.go:38; accessors_handlers.go:104) and hand them into the **dedicated field `Roles: roles`** (`Subject.Roles []string`, types_token.go:249; emitted as top-level `roles` claim at issue_payload.go:86–87, AMR guard). The committed spec's "via Subject.Claims or the dedicated Subject field B4-1 defines" ambiguity is resolved: the field exists — use it. The example's roles call must contain the literal `Roles(` (e.g. `roles, err := h.Roles(ctx.Request().Context(), resourceOwnerID, client.ID)`, with the struct TODO comment naming the accessor and citing `permissions.Provider.Roles`).
- No text in the new steps may trip the existing contract helpers: no `"/..."` path literals, no `/authenticate`, no `8080`, no unregistered `ErrorBody` codes (the new `core.ErrInvalidScope` is registered at error-codes.md:298; `assertRegisteredErrorCodes` validates it automatically).

### R3 — Grant subtest gains named content assertions on the generated artifact

In `TestGeneratedScaffoldsCompile`, for `kind == "grant"`, after the existing reads/assertions (assertRegisteredErrorCodes, assertNoLegacyPathPort, assertNoPathLiterals) and **before** the `go build`/`go vet` loop, run a new named helper (in `scaffold_contract_test.go`, matching the existing helper style) asserting on the generated `device-code_grant.go` text (the template's comment text is embedded verbatim):

1. **A1 (T-8(d) proxy)**: contains `GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, and `grantedScopes)` (issuance passes the validated set — R1's "never raw req.Scope"); each marker's index < index of `issuer.Issue(` (the invalid_scope branch is ordered before issuance).
2. **A2 (T-8(a) proxy)**: contains `TenantID: client.TenantID` (presence only — the literal sits inside the `issuer.Issue(` argument list textually).
3. **A3 (T-8(a) proxy)**: contains `Roles(` at an index < index of `issuer.Issue(` (roles resolved before issuance).
4. Every check fails with its own `t.Errorf` naming the violated invariant (each marker asserted separately, so a regression names exactly what was dropped/reordered). If `issuer.Issue(` is absent, fail with a named error and return (no silent pass of ordering checks).
5. The compile gate stays: isolated-module `go build ./...` + `go vet ./...` (hermetic: `GOFLAGS=-mod=mod`, `GOPROXY=off`, local `replace` to the repo root) must pass.

### R4 — Gate against the completed B4-1 issuer path (already satisfied, verified)

B4-1 is landed at HEAD (evidence §1), so the committed spec's R4 conditional is triggered in this change, not a future one: (a) the compile gate proves the scaffold builds against the completed issuer path now; (b) the R2 handoff uses `Roles: roles` from day one; (c) the stale §1 rows of the committed spec (issue_payload.go, ed25519_types.go, types_token.go) are superseded by this document's corrected evidence. No follow-up re-run dependency remains for this direction.

### Testable acceptance (Given/When/Then) — preserves the direction's T-8(d)/T-8(a)/T-9 checks

1. Given `sso-ctl generate grant --name device-code --package protocols/grants` (the existing test path), when the generated `device-code_grant.go` is inspected, then it contains `GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, and `grantedScopes)` with all four textually before `issuer.Issue(` (A1, T-8(d) proxy).
2. Given the same artifact, when inspected, then it contains `TenantID: client.TenantID` (A2) and a `Roles(` reference before `issuer.Issue(` (A3, T-8(a) proxies).
3. Given any template edit that drops/reorders any marker, when `TestGeneratedScaffoldsCompile` runs, then the grant subtest fails with a named assertion identifying the violated invariant.
4. Given the generated grant package, when the isolated-module `go build ./...` and `go vet ./...` run, then both succeed (existing gate unchanged; fail-closed `invalid_grant` default body untouched).
5. Given the unchanged CLI surface, when `TestRunExitCodes` runs, then it stays green (exit codes 2/1/0 — no flag/exit-code change; T-9).

## 6. Files

**Modify** (no new files, no deletions):
- `cmd/sso-ctl/generate/templates_handler.go` — `grantTemplate` only: struct TODO gains the Roles-accessor note; `Handle` example gains the GrantedScopes step (with registry-seam note) and the roles step; issuance passes `grantedScopes` and `Roles: roles`. `handlerTemplate` untouched. Budget: file ~215 → ~250 lines (< 500); template is data, not code.
- `cmd/sso-ctl/generate/scaffold_contract_test.go` — new named helper (e.g. `assertGrantScopeGateClaims(t, kind string, content []byte)`) with the A1/A2/A3 assertions (§5 R3). Budget: file well under 500.
- `cmd/sso-ctl/generate/scaffold_build_test.go` — grant subtest calls the helper (one line) before the build/vet loop. `TestGeneratedScaffoldsCompile` stays under 50 lines (helper factored out).

**Do not modify**: `cmd.go`, `verify.go` (T-9; entry 2 boundary), all server/registry/issuer packages, `docs/error-codes.md` (`invalid_scope` already at :298), `docs/openapi.yaml`, `docs/config-reference.md`, the other three templates.

**Worktree dependency**: the R3 assertions live in `scaffold_contract_test.go` and rely on `generatedFile` + the existing helper style introduced by the (uncommitted) verify-gate change — land both changes together or note the dependency in the commit.

## 7. Engineering-gate constraints (verified)

- Budgets: function lengths fine (helper ~45 lines, subtest grows 1 line); no directory/fan-out changes; `interfaces/sso` 60-file ceiling untouched.
- No new `Err*`, no OpenAPI/config/error-code surface.
- Security invariants preserved: the template teaches the oracle-safe plain-body `invalid_scope` shape (`core.ErrorBody`, no trace_id) — matching reject.go's and every grant branch's byte-compat baseline; nothing here changes runtime server behavior.

## 8. Dependencies and compatibility

- No SPI, option, config, storage, HTTP/proto, or rollout changes. Pure generator + test change; `sso-ctl generate grant` output text changes for new scaffolds only — already-generated files are unaffected; reverting the template restores prior output exactly.

## 9. Documentation

- `docs/openapi.yaml` / `docs/error-codes.md` / `docs/config-reference.md`: not applicable (no new surface; `invalid_scope` already registered).
- Campaign traceability: advances implementation-gate.md rows 1 (T-8(a) claim sources) and 2 (T-8(d) registry) on the scaffold-compliance axis; wire-level T-8(a)/T-8(d) tests remain server deliverables.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run 'TestGeneratedScaffoldsCompile|TestRunExitCodes' -v
go test ./cmd/sso-ctl/... -race
make ci
```

Pre-condition sanity check before implementation: the grant subtest must FAIL against the current template once the helper lands (proving the assertions bite), then pass after the template edit — both verified by the gate itself.
