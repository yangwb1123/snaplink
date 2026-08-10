# Requirements Spec: B4-1 tenant-claim contract — entitiescmd CLI e2e + per-grant claim matrix

- Direction: B4-1 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-entitiescmd-631f0c1d.json`, entry 1)
- Module: `cmd/sso-ctl/entitiescmd`
- Status: requirements (evidence-verified against HEAD; joint gate G1 = B4-1 + B1-1 + B1-7, T-8(a)/T-1.2 per `docs/campaigns/implementation-gate.md`)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `infrastructure/defaultimpl/issue_payload.go:26` — `buildAccessPayload` emits no `tenant_id`/`roles` | `func buildAccessPayload` at :26. Payload literal sets only `Iss/Sub/Exp/Nbf/Iat/Scope/Extra/ClientID/JTI/ACR/SID/ServingRegion` (:28-40) + `applyOptionalClaims` (RFC 9068/9396/8693 set, `:42`, defined :90-124). No tenant/roles projection anywhere in the file | Confirmed |
| `infrastructure/defaultimpl/ed25519_types.go` — payload struct lacks `tenant_id`/`roles` | `type ed25519Payload struct` at :15; fields: `iss/sub/aud/exp/nbf/iat/scope/_resources/ext/client_id/jti/auth_time/acr/amr/sid/cnf/serving_region/authorization_details/act/_claims_` — no tenant or roles field. `ed25519IDPayload` (:90) likewise | Confirmed |
| `ed25519_issue.go:43` / `ecdsa_issue.go:37` / `rsa_issue.go:29` — shared `buildAccessPayload` call | All three call `buildAccessPayload(j.issuer, subject, scopes, jti, now, expiresAt)` at exactly :43/:37/:29; each issuer signs via the shared `signCompactJWS`. Claim set is byte-identical across signers by design | Confirmed |
| `shared/core/types_token.go:226-231` — `Subject.TenantID` | Field at :231, doc :226-230: "TenantID is the OAuth client's tenant binding at mint time … **NOT a token claim — issuers emit only fields they enumerate in buildAccessPayload**." This comment is direct confirmation of the direction's problem statement | Confirmed |
| `shared/core/spi.go:171` — `SessionMeta.TenantID` | Field at :171 (doc :165-170); `DeleteByTenant`/`ListByTenant` tenant-scoping semantics at :227-239. Distinct concept from `Subject.TenantID` (session-level); both are the same tenant identity string | Confirmed |
| Grant-path `TenantID` stamps (8 sites) | All present, every one `TenantID: client.TenantID`: token_authcode.go:136, token_refresh.go:291, token_client_credentials.go:52, token_device.go:99, token_ciba.go:124, token_jwt_bearer.go:112, token_saml2_bearer.go:123, token_exchange_stages.go:399. Direction cited 125/278/42/89/107/102/110/395 — drift 10-17 lines, symbol and behavior exact | Confirmed (line drift) |
| `ed25519_issue.go:33` — header `{Alg,Typ,Kid}`, kid present | `header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTypAT, Kid: kid}` at exactly :33 (ID-token :90, generic :150, logout :210). Header struct `ed25519Header{Alg,Typ,Kid}` at ed25519_types.go:7-11. **Do not re-add kid** | Confirmed |
| `interfaces/sso/server_discovery.go:251-259` — `resolveIssuer` Host fallback | `func (s *Server) resolveIssuer` at :251; returns `s.issuer` only when `!= "" && != DefaultIssuer` (:252-254), else `requestBaseURL(ctx.Request())` (:255, fn ends :258). Default `s.issuer = DefaultIssuer` at sso.go:67; `DefaultIssuer = "snaplink-sso"` (shared/core/consts_oauth.go:139, aliased interfaces/sso/aliases.go:179). Consumers: `authzErrorBody` :268, form-post :343. Discovery doc `Issuer` has the same unset/sentinel fallback (server_discovery_config.go:144 seeded `base`, :264-265 overridden by `s.issuer`) | Confirmed |
| `interfaces/sso/mesh_authz.go:326` — request-time roles only | `roles, rerr := s.permissions.Roles(ctx, lookupSub, claims.ClientID)` at exactly :326; `X-Auth-Roles` header emission at :422-423 (`HeaderAuthRoles`, aliases.go:276). Request-time only — the token itself never carries roles | Confirmed |
| `interfaces/sso/accessors_handlers.go:102` — `/roles/me` lookup | `roles, err := s.permissions.Roles(ctx, userID, clientID)` at :103 (drift 1); handler serves `/roles/me` (accessors.go route family) | Confirmed (line drift 1) |
| `cmd/sso-ctl/entitiescmd/tenants.go` — tenant lifecycle surface | `RunTenants` create/set-status at documented paths: `runTenantCreate` (:148) POSTs the flat `Tenant{ID,Slug,Name,Status,...}` to `/api/v1/admin/tenants` (:167); `runTenantSetStatus` (:223) POSTs `{status}` to `/api/v1/admin/tenants/:id:set-status`; `Tenant.ID` is operator-chosen (`--id`, required, :158). Wire contract verified against `proto/admin/v1/tenants.proto`: `CreateTenant` has `body: "tenant"` (flat body = the Tenant message, so the CLI's flat POST is correct); `CreateTenantResponse{Tenant tenant=1}` and `ListTenantsResponse{tenants}` envelope the CLI's `printEntity`/`runTenantList` expectations | Confirmed |
| Admin wire protocol has no `Client.TenantID` | `proto/admin/v1/clients.proto` has no `tenant_id` field; `interfaces/grpcserver/grpcadmin/admin_clients.go:59` states "TenantID is intentionally absent from the admin wire protocol". So the CLI e2e binds the CLI-created tenant to a client at the **store** level (`Client.TenantID`, shared/core/types.go:40), never via the admin API | Confirmed — shapes the acceptance harness |
| `Subject` has no Roles field; tokengrant has no permissions provider | `core.Subject` (types_token.go) fields: ID/ClientID/TenantID/ServingRegion/Confirmation*/AuthTime/AMR/ACR/SID/TTL/Claims/RequestedClaims/Resources/AuthorizationDetails/Actor — no Roles. `internal/handler/tokengrant/` imports no `domains/permissions` | Confirmed — roles is PROPOSED, as the direction states |
| `sso.WithIssuer` wired at boot under the cmd config path | `config.ServerOptions()` emits `sso.WithIssuer(c.Server.Issuer)` (config/config_load.go:308), appended by `cmd/sso-server/build_app_core.go:154`; JWT `iss` is the same `cfg.Server.Issuer` via `WithEd25519Issuer(srv.Issuer)` etc. (cmd/sso-server/serverbuildsign/build_signing_issuers.go:43,67,95) | Confirmed — cmd-path tokens are never Host-derived today; see §2 correction |
| Tenant admin service + memory store are directly constructible for a test harness | `NewTenantAdminService(store tenant.Store, recorder *audit.Recorder, invalidateCache, invalidateResidency func(string), revokeTokens func(...))` (interfaces/grpcserver/grpcadmin/admin_tenants.go:50); recorder nil-safe (`recordAdmin` guards nil, admin_paginate.go:215-217); `tenant.Store` interface at domains/tenant/tenant.go:85; real `domains/tenant/memory.New()` exists | Confirmed — enables a CLI e2e with the real service + store, no cmd→cmd imports |
| Per-grant e2e drivers exist in `test/` | authcode (auth_code_test.go), cc (dpop/fapi tests use `grant_type=client_credentials`), refresh (refresh_token_test.go), device (handle_device_test.go, 15 tests), ciba (handle_ciba_test.go), jwt-bearer (jwt_client_assertion_test.go family), exchange (handle_token_exchange_test.go, 19 tests). Claim-decode helper `decodeJWTPayload` (test/oidc_test.go:33) and per-claim-contract precedent `test/region_token_contract_test.go` (serving_region asserted per grant) | Confirmed |

## 2. Corrections to the direction's problem framing

1. **"iss never Host-derived" is reachable only for SDK embedders, not the cmd path.** `WithIssuer(cfg.Server.Issuer)` is wired at boot (config/config_load.go:308), so under `cmd/sso-server` the JWT `iss` and the discovery `issuer` are always the configured value — never the request Host. The Host-derived `requestBaseURL` fallback in `resolveIssuer` (server_discovery.go:255) fires only when `WithIssuer` is unset or set to the `snaplink-sso` sentinel (SDK embedders / mis-wired compositions). The T-1.2 joint acceptance in this spec therefore asserts the **minted-token side** (token `iss` == discovery `issuer` == configured `WithIssuer` != request Host) in the e2e; the boot-time rejection / fallback removal is server+config work owned by the B4-1 server module and the sibling configcmd spec (`docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md`), out of this module's code surface.
2. **Roles are genuinely PROPOSED, and the acceptance must stay conditional.** Verified: zero role resolution exists at mint time, and `core.Subject` has no Roles carrier. The mint-time lookup needs (a) a new `Subject.Roles []string` field (shared/core), (b) a permissions-provider dependency in the issuance path (tokengrant handlers are `interfaces` layer — `internal/handler/tokengrant` — and may import `domains/permissions` downward), and (c) a `roles` projection in `buildAccessPayload`. Per AGENTS.md: roles are advisory — fail-open (lookup error must not alter issuance outcome; detail only in audit), and the claim must never gate issuance. Until a roles source is wired, the claim must not be emitted at all (byte-identical tokens).
3. **Grant-path line drift (10-17 lines)**: all eight `TenantID: client.TenantID` stamps exist; only the cited line numbers are stale. No content correction.
4. **Observed, out of scope**: the CLI's `Tenant` struct tags `home_region/allowed_regions/enforce_writes` are snake_case, but the grpc-gateway marshals responses with protojson camelCase (`runtime.NewServeMux()` defaults, cmd/sso-server/build_http.go:228 — same class of drift the clientscmd comment documents). Requests are unaffected (protojson accepts original field names on unmarshal). B4-1's binding uses `id` only, so this does not block the acceptance; fixing it would be unrelated cleanup and is excluded.

## 3. Goal and user outcome

B4-1 requires the access-token claim set to carry the client's tenant binding (`tenant_id`) and, where a roles source is wired, `roles`; and requires the issuer identity to be operator-configured, never Host-derived. The claim projection itself is server work (`buildAccessPayload` + `Subject` + a roles source) owned by the B4-1 server module. This direction delivers the **entitiescmd half**: proof, through the `sso-ctl tenants` CLI surface, that an operator-created tenant is the binding identity that lands in the token — plus the per-grant claim matrix and issuer-coherence assertions that make T-8(a)/T-1.2 testable.

Completion marker: a test boots a real token-issuing server whose client store binds a tenant created via `sso-ctl tenants create --id=… --status=active`; every grant path (`authorization_code`, `client_credentials`, `refresh_token`, `device_code`, CIBA, JWT-bearer, token-exchange) mints a 200 token whose decoded JWT has header `{alg,typ,kid}` and claims `{iss, aud, scope, client_id, tenant_id}` with `tenant_id` == the CLI-created tenant ID; `iss` equals the configured issuer and never the request Host; and a wired roles source adds `roles` without ever failing issuance.

## 4. Product boundary

- Surface: `cmd/sso-ctl/entitiescmd` (tenants subcommands) + `test/` (package `ssotest`) acceptance harness.
- Default: no production-code change in `cmd/sso-ctl` — the CLI surface already satisfies the contract (see §1 wire verification); the deliverable is the acceptance harness and the contract pins. If the enabling server work (R0) is absent, the new tests are expected to fail on the `tenant_id` assertion only — they are the joint gate's verification half.
- Explicit non-goals (do not implement):
  - No changes to `buildAccessPayload`, `ed25519Payload`, `core.Subject`, `resolveIssuer`, discovery, or tokengrant handlers — B4-1 server work, separate module (enabling dependency R0 below; the sibling configcmd spec owns the config-side issuer gate).
  - No new `sso-ctl` subcommand, no new package under `cmd/sso-ctl/` (fan-out ceiling, §6), no new flags on `tenants`/`users`, no `clientscmd` changes.
  - No CLI client↔tenant binding command: the admin wire protocol intentionally omits `Client.TenantID` (grpcadmin/admin_clients.go:59); binding is a store/config concern. The e2e binds at the store level, which is exactly what the direction's "bind a CLI-created tenant to a client" requires.
  - No change to the CLI `Tenant` JSON tags (the camelCase display drift in §2.4 stays).
  - No new audit event types, no OpenAPI/`Err*`/config-key changes.

## 5. Requirements

### R0 — Enabling dependency (other module; precondition for green acceptance)

The B4-1 server module must land, in the same joint gate (G1):

1. `ed25519Payload.TenantID string json:"tenant_id,omitempty"` (+ ECDSA/RSA share the same payload type — one change covers all three signers) projected in `buildAccessPayload` from `subject.TenantID`. Empty stays omitted (`omitempty`), so single-tenant deployments emit byte-identical tokens.
2. `resolveIssuer`'s Host-derived fallback removed/replaced by the operator-configured issuer (boot-time rejection or sentinel handling), keeping token `iss` == discovery `issuer` == authorization-response `iss` (RFC 9207 §2 invariant, server_discovery.go:242-249).
3. Roles carrier only if a roles source is wired: `Subject.Roles []string` + a fail-open mint-time lookup (error ⇒ issuance unchanged, roles omitted, detail only in audit) — per §2.2 semantics.

This spec's tests are written so the `tenant_id`/`iss`/`roles` assertions fail loudly while every other assertion (kid, status codes, existing contracts) stays green when R0 is absent — the joint gate's intended split.

### R1 — Tenant lifecycle surface is the tenant-binding entry point (contract pin, no code change)

`sso-ctl tenants create --id=<id> --status=active` must persist exactly the operator-chosen `<id>` through the admin gateway contract, and `sso-ctl tenants set-status <id> active|suspended` must round-trip, so `<id>` is usable verbatim as `Client.TenantID` (shared/core/types.go:40). The CLI's flat POST body and `{"tenant": …}`/`{"tenants": […]}` response handling must remain byte-identical (T-9): no flag, subcommand, output, or exit-code changes.

### R2 — CLI e2e harness: real tenant service + real store + real token issuance

New test file `cmd/sso-ctl/entitiescmd/tenant_claims_e2e_test.go` (package `entitiescmd`, no cmd→cmd imports):

- Admin half: `httptest` server whose `/api/v1/admin/tenants` routes call the **real** `grpcadmin.NewTenantAdminService(domains/tenant/memory.New(), nil, …)` over the gateway wire contract (request: protojson of the flat Tenant message per `body: "tenant"`; response: protojson of `CreateTenantResponse`/`ListTenantsResponse`/`SetTenantStatusResponse`). This exercises the real service logic (id-required, status validation, check-then-put, audit via nil-safe recorder) with only the HTTP envelope mimicked.
- Token half: the **real** `sso.Server` (issuer `defaultimpl.NewEd25519JWTIssuer` + `sso.WithIssuer("https://sso.test")` + `MemoryClientStore` seeded with a client whose `TenantID` is the CLI-created ID) under the same httptest server, so `POST /token` mints real JWS.
- Drive the CLI with `t.Setenv(apiclient.EnvAddr, srv.URL)` (apiclient.go:27) + `t.Setenv(apiclient.EnvToken, …)` (apiclient.go:30), calling `RunTenants([]string{"create", "--id=…", "--status=active"})` — the same entry point the binary dispatches (cmd/sso-ctl/main.go).

### R3 — Per-grant claim matrix (test/, package ssotest)

New `test/tenant_claim_contract_test.go` following the `region_token_contract_test.go` pattern: an SDK-level server with clients carrying `TenantID` seeds (precedent: test/cross_tenant_collaboration_test.go:56,62) and the real Ed25519 issuer. Drives all seven grants from the acceptance — authorization_code, client_credentials, refresh_token, device_code, CIBA, JWT-bearer, token-exchange — and asserts the same claim contract on each minted access token.

### R4 — Issuer coherence (T-1.2 joint, minted-token side)

In both harnesses, the server is built with `sso.WithIssuer("https://sso.test")`. Assert token `iss` == discovery `issuer` == `resolveIssuer` output == the configured value, and != the request Host — including when the test client sends a different `Host` header (Host-derivation regression lock; the fix itself is R0.2/server-side).

### R5 — Roles claim (proposed, conditional)

- When no roles source is wired: the token must not carry a `roles` claim (byte-identical to today).
- When a roles source is wired (test harness wires `domains/permissions` memory provider + `AssignRoles`): the token carries `roles` = the assigned role codes for the subject+client.
- Oracle-safe fail-open (mandatory semantics): a role-lookup error must not change the issuance outcome — the token still mints 200 with `roles` omitted and the failure recorded only in audit (AGENTS.md: advisory signals fail open; no claim ever gates issuance). Test: a provider that returns an error yields a token indistinguishable from the no-roles case except for the audit record.

### Testable acceptance (Given/When/Then)

CLI e2e — `cmd/sso-ctl/entitiescmd/tenant_claims_e2e_test.go`:

1. Given the §R2 harness, when `RunTenants(["create", "--id=cli-tenant", "--status=active", "--name=…"])` runs, then exit 0, the admin service's store contains tenant `cli-tenant` with status `active`, and `RunTenants(["get", "cli-tenant"])` exit 0 prints `id == "cli-tenant"`.
2. Given a client seeded with `TenantID: "cli-tenant"` (the §R2-created ID), when `POST /token` with `grant_type=client_credentials` runs, then 200 and the decoded JWT header is `{"alg":"EdDSA","typ":"at+jwt","kid":<present>}` and claims contain `iss/aud/scope/client_id/tenant_id` with `tenant_id == "cli-tenant"` (T-8(a)).
3. Given the same server with `sso.WithIssuer("https://sso.test")` and a request carrying `Host: attacker.example`, when the token from case 2 is decoded, then `iss == "https://sso.test"` and `iss != "attacker.example"` (T-1.2 joint).
4. Given `RunTenants(["set-status", "cli-tenant", "suspended"])` then `RunTenants(["set-status", "cli-tenant", "active"])`, when the admin service's store is read, then the status round-trips `suspended` → `active` (surface usable for the binding lifecycle).
5. Given an unbound client (`TenantID: ""`), when `POST /token` runs, then 200 and the decoded claims contain **no** `tenant_id` key (single-tenant byte-compat; `omitempty`).
6. Given `--id=""` (missing) or `--status=garbage`, when `RunTenants(["create", …])` runs, then exit 2 in both cases (CLI-side usage validation, tenants.go:158-163) — existing validation unchanged (T-9); a server-side rejection of an already-existing tenant ID surfaces as exit 1 via `doWrite`.

Per-grant matrix — `test/tenant_claim_contract_test.go`:

7. Given a server whose clients carry `TenantID: "t-acme"`, when each of authorization_code / client_credentials / refresh_token / device_code / CIBA / JWT-bearer / token-exchange mints an access token, then every token returns 200, has the `kid` header, and decodes with `tenant_id == "t-acme"` alongside `iss/aud/scope/client_id` (T-8(a) per grant).
8. Given a token from each grant, when introspection runs, then the same `tenant_id` claim is echoed (RFC 9068 validator parity; optional extension of case 7 — implement only if the introspection projection is part of the server module's R0 change).
9. Given a server wired with a memory permissions provider whose subject+client have roles `["admin","auditor"]` assigned, when `POST /token` runs, then 200 and the decoded claims contain `roles == ["admin","auditor"]`; the same subject with no assignment yields **no** `roles` key (R5).
10. Given a roles provider that returns an error for the subject, when `POST /token` runs, then the response is byte-identical in status and claim set to the no-roles case of case 9 (fail-open; `roles` omitted) — the issuance outcome is unchanged by the lookup failure (R5).
11. Given `sso.WithIssuer("https://sso.test")` and discovery fetched, when token `iss`, discovery `issuer`, and `resolveIssuer` output are compared, then all three are equal and none equals the request Host (T-1.2 joint).

Regression (T-9):

12. Given the existing `cmd/sso-ctl/entitiescmd/tenants_test.go` and `users_test.go` suites (mock-admin cases), when run against the unchanged CLI code, then all pass byte-identically; `sso-ctl tenants` usage/exit-code conventions (0/1/2) are unchanged.

## 6. Engineering-gate constraints (verified)

- **Fan-out ceiling**: `cmd/sso-ctl/` has 16 immediate subdirectories; the committed Go gate `TestArchitecture_DirectorySubdirFanout` (ceiling 16) has no exemption — **no new package**. All new code is test files inside `entitiescmd` (new test file `tenant_claims_e2e_test.go`; `_test.go` files do not count against the 10-file non-test cap). The Python mirror (`checks/directory_fanout.py`, max 15) already flags `cmd/sso-ctl/` — pre-existing, must not worsen.
- **Budgets**: `entitiescmd` holds 4 non-test files (tenants.go 332, users.go 228, plus two test files) — new test file fits; no production function changes, so no function/complexity/nesting risk. `interfaces/sso` is at its 60-file ceiling — this spec touches nothing there (test/ harness builds `sso.Server` via existing options).
- **Import direction**: `entitiescmd` tests (composition) importing `domains/tenant`, `domains/permissions`, `infrastructure/defaultimpl`, `interfaces/sso`, `interfaces/grpcserver/grpcadmin`, `gen/proto/admin/v1` (interfaces), `platform/audit` (platform) — all downward; no cmd→cmd edge, no `cmd/` import by a library package.
- **Wire/contract invariants untouched**: no routes, no `Err*`, no config keys, no OpenAPI surface; the CLI's HTTP behavior is not modified (the mock gateway in R2 is test-only).
- **Worktree state**: `config/config_load.go` may carry an unrelated in-progress B4-2 diff — this spec modifies nothing under `config/`.

## 7. Files

### Create

```text
cmd/sso-ctl/entitiescmd/tenant_claims_e2e_test.go — R2 harness + acceptance cases 1-6:
    httptest server exposing /api/v1/admin/tenants (+ :set-status) over the real
    grpcadmin.TenantAdminService + domains/tenant/memory store, and /token over a real
    sso.Server; drives RunTenants + apiclient; decodes JWT segments and asserts
    kid/iss/aud/scope/client_id/tenant_id/roles.
test/tenant_claim_contract_test.go — R3/R5/R4 acceptance cases 7-11 (package ssotest):
    per-grant tenant_id claim matrix (authcode/cc/refresh/device/ciba/jwt-bearer/
    exchange), roles claim semantics (wired / unwired / lookup-error), issuer
    coherence vs discovery + Host. Follows region_token_contract_test.go structure;
    reuses decodeJWTPayload (test/oidc_test.go:33) and the existing per-grant drivers.
```

### Modify

```text
(none in cmd/sso-ctl — the CLI surface already satisfies R1; T-9 forbids touching it)
```

### Do not modify

```text
cmd/sso-ctl/entitiescmd/tenants.go, users.go — wire contract + output byte-identity (T-9)
cmd/sso-ctl/main.go, cmd/sso-ctl/clientscmd — fan-out ceiling; no new surface, no
    client-tenant binding command (admin wire protocol omits Client.TenantID by design)
infrastructure/defaultimpl/{issue_payload.go,ed25519_types.go,*_issue.go},
shared/core/types_token.go, internal/handler/tokengrant/*,
interfaces/sso/server_discovery.go — B4-1 server work (R0), separate module
config/* — issuer allowlist gate owned by the sibling configcmd spec
docs/openapi.yaml, docs/error-codes.md — no new endpoint/error surface
```

## 8. Dependencies and compatibility

- New/changed SPI: none from this module. Enabling dependency: R0 server changes (Subject.TenantID projection, resolveIssuer fallback removal, optional Subject.Roles + fail-open lookup) — joint gate G1.
- New option/store wiring: none (test harnesses construct existing stores/options).
- New YAML/env keys: none.
- Storage migration: none. HTTP/proto compatibility: none (CLI requests byte-identical).
- Rollout/rollback: no production change; removing the test files restores the pre-change tree exactly.

## 9. Documentation

- [ ] `docs/config-reference.md` — not applicable (no config knob from this module; the issuer-allowlist row is the sibling configcmd spec's).
- [ ] `docs/openapi.yaml` — not applicable (no endpoint).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`; exit codes follow the existing 0/1/2 convention).
- [x] Feature/deferred-backlog note: joint-gate G1 (implementation-gate.md:73) — T-8(a)/T-1.2 green requires this spec's harness + the R0 server changes together; the campaign row already tracks that coupling.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .        # fan-out gate must stay green
go test ./cmd/sso-ctl/entitiescmd/... -v -race                # CLI e2e + existing suites (T-9)
go test ./test/ -run 'TestTenantClaimContract|TestRegionTokenContract' -v   # per-grant matrix
go test ./test/ -run TestE2E -v
make ci
```

Pre-existing failures to report separately: `checks/directory_fanout.py` already fails for `cmd/sso-ctl/` (16 > 15) and other dirs; the committed Go gate passes today and must remain passing. When R0 (server module) is not yet landed, `tenant_id`/`iss`-derivation/`roles` assertions fail while status/kid/scope/client_id assertions stay green — report that split explicitly rather than as a blanket failure.
