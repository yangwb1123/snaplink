# Design: B4-1 tenant-claim contract — entitiescmd acceptance harness + contract pins

- Direction: B4-1 (source: `docs/architect-analysis/auto/analyses/cmd-sso-ctl-entitiescmd-631f0c1d.json`, entry 1)
- Module: `cmd/sso-ctl/entitiescmd`; joint gate G1 = B4-1 + B1-1 + B1-7 (T-8(a)/T-1.2 per `docs/campaigns/implementation-gate.md`)
- Requirements baseline: `docs/architect-analysis/cmd-sso-ctl-entitiescmd-b4-1-tenant-claims-requirements.md` (verified accurate, one material gap corrected below)
- Status: design (evidence re-verified against HEAD; `go build ./... && go vet ./...` clean at design time)

## 1. Verification verdict (untrusted claims → measured reality)

Every citation in the requirements spec was re-checked against the working tree. All confirmed; one material gap in the harness-precondition claims is corrected in §2.

| Evidence claim | Measured reality | Verdict |
|---|---|---|
| `infrastructure/defaultimpl/issue_payload.go:26` — `buildAccessPayload` emits no `tenant_id`/`roles` | Payload literal at :28-40 sets only `Iss/Sub/Exp/Nbf/Iat/Scope/Extra/ClientID/JTI/ACR/SID/ServingRegion`; `applyOptionalClaims` (:42, defined :90-124) covers the RFC 9068/9396/8693 set. No tenant/roles projection in the file | **Confirmed** |
| `ed25519Payload` (ed25519_types.go:15) lacks `tenant_id`/`roles` | Fields: `iss…cnf/serving_region/authorization_details/act/_claims_`; no tenant or roles field; `ed25519IDPayload` (:90) likewise | **Confirmed** |
| Shared `buildAccessPayload` calls at ed25519_issue.go:43 / ecdsa_issue.go:37 / rsa_issue.go:29 | All three call `buildAccessPayload(j.issuer, subject, scopes, jti, now, expiresAt)` at exactly :43/:37/:29; claim set signer-independent by design (comment at issue_payload.go:20-23) | **Confirmed** |
| `ed25519_issue.go:33` kid header | `header := ed25519Header{Alg: jwtAlgEdDSA, Typ: jwtTypAT, Kid: kid}` exactly at :33. Do not re-add | **Confirmed** |
| `shared/core/types_token.go:231` `Subject.TenantID` doc "NOT a token claim" | Field at :231; doc :226-230 verbatim: "NOT a token claim — issuers emit only fields they enumerate in buildAccessPayload". Direct confirmation of the problem statement | **Confirmed** |
| 8 grant-path `TenantID: client.TenantID` stamps | authcode:136, refresh:291, cc:52, device:99, ciba:124, jwt-bearer:112, saml2:123, exchange:399 (token_exchange_stages.go). Content exact; drift 10-17 lines | **Confirmed (line drift)** |
| `resolveIssuer` Host fallback (server_discovery.go:251-258) | `resolveIssuer` at :251; returns `s.issuer` only when `!= "" && != DefaultIssuer` (:252-254), else `requestBaseURL(ctx.Request())` (:255-257). RFC 9207 invariant comment :242-249 | **Confirmed** |
| `mesh_authz.go:326` request-time roles only | `roles, rerr := s.permissions.Roles(ctx, lookupSub, claims.ClientID)` at exactly :326; `X-Auth-Roles` emission :422-423. Tokens never carry roles | **Confirmed** |
| `accessors_handlers.go:103` `/roles/me` lookup | `roles, err := s.permissions.Roles(ctx, userID, clientID)` at :103 (drift 1) | **Confirmed (drift 1)** |
| `entitiescmd/tenants.go` surface | `RunTenants` :36; `runTenantCreate` :148 (POST flat `Tenant{ID,Slug,Name,Status,…}` to `/api/v1/admin/tenants` :167; `--id` required → exit 2 :158-161; `validateTenantStatus` → exit 2 :163-165); `runTenantSetStatus` :223; `printEntity`/`runTenantList` handle `{"tenant":…}`/`{"tenants":[…]}` envelopes | **Confirmed** |
| `config_load.go:308` — `WithIssuer` wired at boot | `opts := []sso.Option{sso.WithIssuer(c.Server.Issuer)}` at exactly :308; `WithIssuer` at interfaces/sso/options.go:350. cmd-path tokens are never Host-derived today | **Confirmed** |
| Admin wire protocol has no `Client.TenantID` | `proto/admin/v1/clients.proto`: zero `tenant_id` references; `grpcadmin/admin_clients.go:59` comment "TenantID is intentionally absent from the admin wire protocol" | **Confirmed** |
| `tenants.proto` flat body | `body: "tenant"` at tenants.proto:31 and :37 — flat POST matches `RunTenants` exactly | **Confirmed** |
| `Subject` has no Roles; tokengrant has no permissions provider | `core.Subject` (types_token.go) has no Roles field (zero grep hits); `internal/handler/tokengrant/` has zero `domains/permissions` imports | **Confirmed** |
| Tenant admin service + memory store constructible | `NewTenantAdminService(store, recorder, invalidateCache, invalidateResidency, revokeTokens)` at admin_tenants.go:50; all callbacks nil-safe; `domains/tenant/memory.New()` exists; `sso.WithPermissionProvider` (options_misc.go:21) + `permissions.NewMemoryProvider()` (memory.go:45) + `AssignRoles` (memory.go:128) exist | **Confirmed** |
| Per-grant drivers exist in `test/` | authcode (auth_code_test.go), cc (dpop/fapi `grant_type=client_credentials`), refresh (refresh_token_test.go), device (handle_device_test.go `urn:…:device_code`), ciba (handle_ciba_test.go `/backchannel-authentication` + poll with `oauth.GrantCIBA`), exchange (handle_token_exchange_test.go `urn:…:token-exchange` + `subject_token`). `decodeJWTPayload` at test/oidc_test.go:33; `region_token_contract_test.go` per-claim precedent incl. introspection echo (`/token/introspect`, :218-247); tenant seeds precedent `cross_tenant_collaboration_test.go:56,62`; `defaultimpl.NewMemoryClientStore` alias (aliases_memory.go:62) | **Confirmed** — except jwt-bearer, see §2 |
| Engineering ceilings | `cmd/sso-ctl/` = 16 immediate subdirectories (Go gate ceiling 16, no exemption); `interfaces/sso` = 60 non-test files (ceiling); `entitiescmd` = 4 non-test files | **Confirmed** |
| Python fan-out failure pre-existing | `checks/directory_fanout.py` flags `cmd/sso-ctl/` (16 > 15) and others; committed Go gate passes | **Confirmed** |

## 2. Material correction to the evidence (applied to this design)

**The JWT-bearer grant (RFC 7523 §2.1) has NO existing e2e driver and NO concrete validator implementation in the repository.** The requirements spec's claim "jwt-bearer (jwt_client_assertion_test.go family)" is overstated:

- `test/jwt_client_assertion_test.go` drives `grant_type=client_credentials` with `client_assertion_type=jwt-bearer` — that is **private_key_jwt client authentication**, not the RFC 7523 JWT-bearer *grant* (`oauth.GrantJWTBearer`, consts_oauth.go:25).
- `tokengrant.JWTAssertionValidator` (token_jwt_bearer.go:30-36) has **zero concrete implementations** outside the interface (the only `ValidateAssertion` in the repo is `infrastructure/saml`'s, which implements the different SAML2 seam).
- No `_test.go` anywhere drives `GrantJWTBearer`.

Consequence for the design: the per-grant matrix's jwt-bearer row must **implement a real in-test validator** (Ed25519-signed assertions verified against a pinned key) wired via the existing `sso.WithJWTBearerGrant(tokengrant.JWTAssertionValidator)` option (options_grants.go:98) — the seam's documented extension point, mirroring how `infrastructure/saml` implements the SAML2 seam. This is a real implementation of a documented seam (signature verification with real crypto), not a mock; storage concerns remain real (`memorystoreidentity`). It adds ~40 lines to the matrix fixture versus the other six grants.

Minor precision (no design impact): `MemoryClientStore` lives in `infrastructure/defaultimpl/memorystoreidentity` and is re-exported as `defaultimpl.NewMemoryClientStore` (aliases_memory.go:62).

## 3. Design

### 3.1 API changes

**Production API: none in this module.** `cmd/sso-ctl` is byte-identical after this change (T-9 regression pin): no new subcommand, flag, output, exit code, `Err*`, config key, OpenAPI surface, proto field, or route. The CLI already satisfies the tenant-binding contract (§1 wire verification).

**Test-surface additions (the deliverable):**

| File | Package | Content |
|---|---|---|
| `cmd/sso-ctl/entitiescmd/tenant_claims_e2e_test.go` | `entitiescmd` (same package as `RunTenants` — direct call, no cmd→cmd import) | R2 harness + acceptance cases 1-6 |
| `test/tenant_claim_contract_test.go` | `ssotest` | R3/R4/R5 per-grant matrix + issuer coherence (cases 7-11) |

**Enabling dependency (R0, sibling B4-1 server module — the contract this harness pins, never compiled against):** the tests assert on **decoded claim maps**, never on R0 struct fields, so the harness compiles and stays green-minus-the-new-claims when R0 is absent. R0's surface is pinned here so the joint gate has one definition:

1. `ed25519Payload.TenantID string json:"tenant_id,omitempty"` — one field covers all three signers (shared payload type). Projected by **unconditional literal assignment** `TenantID: subject.TenantID` beside `ServingRegion` (the SID discipline comment at issue_payload.go:38-40: `omitempty` performs the omission, no wire-visible guard). Empty ⇒ omitted ⇒ single-tenant deployments byte-identical.
2. `ed25519Payload.Roles []string json:"roles,omitempty"` — **nil-when-absent discipline**: `omitempty` omits only nil slices, not empty non-nil ones; the fail-open path must assign `nil`, never `[]string{}`, or a spurious `roles: []` claim leaks. Mint-time lookup is fail-open (error ⇒ issuance unchanged, roles nil, detail only in audit) and never gates issuance (AGENTS.md advisory-signal semantics). Unwired ⇒ nil ⇒ byte-identical tokens.
3. `resolveIssuer` Host-fallback removal (token `iss` == discovery `issuer` == operator-configured issuer; boot-time gate owned by the sibling configcmd spec).

### 3.2 Harness architecture

**CLI e2e** (`tenant_claims_e2e_test.go`): one `httptest` server, two route families sharing a `sso.Server` instance:

- Admin family — `/api/v1/admin/tenants` (POST create, GET list), `/api/v1/admin/tenants/{id}` (GET), `/api/v1/admin/tenants/{id}:set-status` (POST): protojson envelope handlers that decode into `adminv1.CreateTenantRequest`/`GetTenantRequest`/`SetTenantStatusRequest` (flat `tenant` body per `body: "tenant"`), call the **real** `grpcadmin.TenantAdminService` methods (`CreateTenant` :194, `GetTenant` :177, `SetTenantStatus` :315, `ListTenants` :77) over the **real** `domains/tenant/memory` store, and re-encode `*Response` as protojson. Recorder and callbacks nil (all nil-safe per admin_tenants.go:50-65). Only the HTTP envelope is mimicked; service logic is real (id-required, status validation, check-then-put, suspend revocation via nil no-op).
- Token family — `/token`: the **real** `sso.Server` (Ed25519 issuer via `defaultimpl.NewEd25519JWTIssuer`, `sso.WithIssuer("https://sso.test")`, `sso.WithClientStore(defaultimpl.NewMemoryClientStore())` seeded with a client whose `TenantID` is the CLI-created ID, `WithDefaultTokenStrategy("jwt")`). Case 2 drives `grant_type=client_credentials` only; the per-grant breadth lives in `test/`.
- CLI driving: `t.Setenv(apiclient.EnvAddr, srv.URL)` + `t.Setenv(apiclient.EnvToken, "test-token")` (apiclient.go:27,30), then call `RunTenants([]string{...})` — the same entry point `cmd/sso-ctl/main.go` dispatches. No `t.Parallel` (env is process-global).

**Per-grant matrix** (`test/tenant_claim_contract_test.go`): fixture modeled on `newRegionTokenServer` (region_token_contract_test.go:24-77) — real user provider, password authenticator, Ed25519 issuer, authcode/refresh stores — plus `sso.WithIssuer("https://sso.test")`, clients seeded `TenantID: "t-acme"` (one extra client with `TenantID: ""` for the negative case), `sso.WithPermissionProvider(permissions.NewMemoryProvider())` (roles cases), and `sso.WithJWTBearerGrant(testJWTBearerValidator)` (new in-test validator: Ed25519 keypair; assertion `{iss,sub,aud,exp,iat}` signed per the jwt_client_assertion_test.go sign-helper pattern :95-99; validator verifies signature against the pinned public key and returns issuer+subject — real verification). Grant drivers reuse the existing test/ helpers where present (device poll, ciba poll, exchange form, introspect form) or the direct `/token` POST otherwise. Every minted access token is decoded with `decodeJWTPayload` (oidc_test.go:33) and asserted against the same claim contract.

### 3.3 Compatibility constraints

- **Wire byte-identity (T-9)**: `tenants.go`/`users.go` untouched; usage text, exit codes 0/1/2, output shapes, request bodies byte-identical. The existing mock-admin suites (`tenants_test.go`, `users_test.go`) must pass unchanged.
- **No new package**: `cmd/sso-ctl/` stays at 16 subdirectories (Go gate ceiling 16, no exemption); `_test.go` files do not count against the 10-file non-test cap, and `entitiescmd` stays at 4 non-test files. `interfaces/sso` stays at 60 non-test files (the `test/` harness constructs `sso.Server` via existing options only).
- **Import direction**: `entitiescmd` test (composition layer) → `interfaces/grpcserver/grpcadmin`, `interfaces/sso`, `gen/proto/admin/v1`, `infrastructure/defaultimpl`, `domains/tenant`, `domains/permissions`, `platform/audit` — all downward, no cmd→cmd edge, no `cmd/` import by a library package. `test/` (ssotest) imports the same set downward.
- **Env hygiene**: `t.Setenv` for `SSO_ADMIN_ADDR`/`SSO_ADMIN_TOKEN` isolates the CLI e2e from ambient environment; no `t.Parallel`.
- **No R0 compile coupling**: claim-map assertions (`claims["tenant_id"]`), never R0-added struct fields — this is what makes the pre-R0 red-split (§3.4) possible.
- **No config/storage/proto migration**; `docs/openapi.yaml`/`docs/error-codes.md`/`docs/config-reference.md` untouched (no new endpoint, error, or knob from this module).

### 3.4 Failure modes

| # | Failure mode | Symptom | Detection | Handling |
|---|---|---|---|---|
| F1 | R0 not landed (enabling dependency absent) | `tenant_id`/`roles`/`iss`-derivation assertions red; status/kid/scope/client_id assertions green | Case-by-case assertion split | Expected — report the split explicitly, not as blanket failure; joint gate G1 lands R0 in the same window |
| F2 | Roles lookup error at mint time | Provider returns error | Case 10 | Fail-open: 200, `roles` omitted (nil), claim set byte-identical to the no-roles case; detail only in audit. Claim never gates issuance |
| F3 | Roles provider unwired | No roles claim | Case 9 negative | Assert byte-identical token (no `roles` key); R0 must emit nil, never `[]string{}` (omitempty does not drop empty slices) |
| F4 | JWT-bearer validator unwired in fixture | `/token` errors on the jwt-bearer row | Matrix row fails | Fixture must wire `sso.WithJWTBearerGrant` (test bug, not product); pinned in §3.2 |
| F5 | Host-derivation regression | `iss` == request Host | Case 3/11 with `Host: attacker.example` | Assert `iss == "https://sso.test"` != Host; the fix itself is R0.2 |
| F6 | Ambient `SSO_ADMIN_*` env contamination | CLI e2e hits the wrong base URL/token | Flaky cross-environment | `t.Setenv` in every CLI e2e test; no `t.Parallel` |
| F7 | Gateway envelope drift (protojson camelCase display vs snake_case request) | `get`/`list` display drift; create unaffected | Existing `Tenant` tags (tenants.go:29-31) | Out of scope (documented §2.4 of requirements); requests use `id` only |
| F8 | Device/CIBA poll timing | Poll returns `authorization_pending` flake | Matrix rows | Use the existing tests' short-interval poll pattern (handle_device_test.go pollToken; ciba 1ms interval) |
| F9 | Pre-existing Python fan-out failure | `checks/directory_fanout.py` fails for `cmd/sso-ctl/` (16>15) and others | CI / local run | Pre-existing; must not worsen (no new subdirectory); report separately |
| F10 | CLI usage validation regression | Exit codes drift | Case 6 | Assert exit 2 for missing `--id` and invalid `--status`; exit 1 surfaces server-side rejection via `doWrite` (T-9) |

### 3.5 Migration steps

1. **This module** (no ordering constraint): add the two test files (§3.1). They compile against the current surface and stay green except the R0-dependent claim assertions — run `go test ./cmd/sso-ctl/entitiescmd/... -race` and `go test ./test/ -run 'TestTenantClaimContract'` and record the red-split as the expected pre-R0 state.
2. **Joint gate G1**: land R0 (sibling B4-1 server module: `Subject.TenantID` projection + optional `Subject.Roles` fail-open lookup in `buildAccessPayload`, `resolveIssuer` fallback removal; plus the sibling configcmd issuer gate) in the same gate window. No source coupling — the harness flips green purely via behavior.
3. **Full gates**: `go build ./... && go vet ./...`; `go test -run 'TestMaintainability_|TestArchitecture_' .` (fan-out must stay green); `go test ./... -race`; `go test ./test/ -run TestE2E -v`; `make ci`. Report `checks/directory_fanout.py` pre-existing failure separately.
4. **Rollback**: delete the two test files — the tree is restored exactly (no production code shipped by this module; nothing to migrate, no rollout step).

### 3.6 Testable acceptance mapping

All 12 requirements cases map to named tests; each row states its file, R0-dependency, and T-8(a)/T-1.2 mapping. `RED-pre-R0` = assertion fails until the R0 server module lands; `GREEN` = green today.

| Case (requirements §5) | Test function (file) | Given/When/Then essence | R0 dep |
|---|---|---|---|
| 1 | `TestTenantClaimsE2E_CreateAndMint` (entitiescmd) | `RunTenants(["create","--id=cli-tenant","--status=active","--name=…"])` → exit 0; store contains `cli-tenant` active; `get` prints `id == "cli-tenant"` | GREEN |
| 2 | same test (continuation) | Client seeded `TenantID:"cli-tenant"`; `POST /token` cc → 200; header `{alg:EdDSA, typ:at+jwt, kid:≠""}`; claims `iss/aud/scope/client_id/tenant_id` with `tenant_id == "cli-tenant"` | `tenant_id` RED-pre-R0, rest GREEN |
| 3 | `TestTenantClaimsE2E_IssuerCoherence` (entitiescmd) | Same server, request `Host: attacker.example` → token `iss == "https://sso.test"` != Host (T-1.2 minted-token side) | RED-pre-R0 only if fallback removal is the mechanism; assert as written (with `WithIssuer` set, `resolveIssuer` already returns the configured value today) |
| 4 | `TestTenantClaimsE2E_StatusRoundTrip` (entitiescmd) | `set-status cli-tenant suspended` then `active` → store status round-trips | GREEN |
| 5 | `TestTenantClaimsE2E_UnboundClientOmitsTenantID` (entitiescmd) | Client `TenantID:""` → 200; decoded claims have **no** `tenant_id` key (single-tenant byte-compat) | GREEN (asserts absence — passes pre-R0, is the regression guard that keeps R0's `omitempty` honest) |
| 6 | `TestTenantClaimsE2E_UsageValidation` (entitiescmd) | `--id=""` → exit 2; `--status=garbage` → exit 2; duplicate ID server rejection → exit 1 | GREEN |
| 7 | `TestTenantClaimContract_PerGrantMatrix` (test/, table-driven) | 7 grants × client `TenantID:"t-acme"` → 200, `kid` header, claims `iss/aud/scope/client_id/tenant_id == "t-acme"` (T-8(a) per grant) | `tenant_id` RED-pre-R0 |
| 8 | `TestTenantClaimContract_IntrospectionEchoes` (test/, conditional) | `POST /token/introspect` → `tenant_id` echoed (RFC 9068 validator parity; implement only if R0 projects it) | RED-pre-R0 |
| 9 | `TestTenantClaimContract_RolesClaim` (test/) | Memory provider + `AssignRoles(subject, client, ["admin","auditor"])` → 200, `roles == ["admin","auditor"]`; same subject unassigned → **no** `roles` key | RED-pre-R0 (both halves) |
| 10 | `TestTenantClaimContract_RolesLookupErrorFailOpen` (test/) | Provider returns error → 200, claim set byte-identical to case 9-negative (`roles` omitted); issuance outcome unchanged (fail-open) | RED-pre-R0 |
| 11 | `TestTenantClaimContract_IssuerCoherence` (test/) | Token `iss` == discovery `issuer` == `resolveIssuer` output == `"https://sso.test"` != request Host (T-1.2 joint) | GREEN today under `WithIssuer`; pins the invariant for R0 |
| 12 | existing `tenants_test.go` + `users_test.go` (regression) | Mock-admin suites pass byte-identically; 0/1/2 exit conventions unchanged (T-9) | GREEN |

## 4. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .            # fan-out gate stays green
go test ./cmd/sso-ctl/entitiescmd/... -v -race                    # CLI e2e + existing suites (T-9)
go test ./test/ -run 'TestTenantClaimContract|TestRegionTokenContract' -v
go test ./test/ -run TestE2E -v
make ci
```

Pre-existing failure reported separately: `checks/directory_fanout.py` fails for `cmd/sso-ctl/` (16 > 15) and other directories today; the committed Go gate passes and must remain passing. Pre-R0, the `tenant_id`/`roles` assertions are expected red while status/kid/scope/client_id/iss assertions stay green — report that split explicitly.
