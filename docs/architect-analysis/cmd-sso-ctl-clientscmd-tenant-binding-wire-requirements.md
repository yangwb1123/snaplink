# Requirements Spec: admin-wire client tenant binding (tenant_id + grant_types) surfacing — clientscmd

- Direction: entry 1 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-clientscmd-5066b2a0.json`
  ("Surface the client's tenant binding (tenant_id + grant_types) on the admin wire and in
  clientscmd output")
- Module: `cmd/sso-ctl/clientscmd` + `proto/admin/v1/clients.proto` + `interfaces/grpcserver/grpcadmin`
- Status: requirements (every citation re-verified against HEAD; acceptance preserved from the
  direction and made testable)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/clientscmd/clients.go:21-38` — `clientListItem`, documented tenant_id/grant_types gap | Struct comment at :65-72, `type clientListItem struct` at :73-81 (fields ID..Active, :74-80). The gap comment is verbatim at :70-72: "There is also no tenant_id/grant_types field on the Client message at all (see proto/admin/v1/clients.proto) — the closest equivalent the server exposes is token_strategy." `printClients` (table) at :107-118, header `{ID, Name, TokenStrategy, RedirectURIs, Active}` :112. `runGet` (:146-181) dumps the raw gateway JSON — it will render the new fields with zero code change | Confirmed (content exact; cited lines stale by ~44 — the package-doc/import block shifted) |
| `proto/admin/v1/clients.proto:41-89` — Client message, no tenant field | `message Client` at :70-84; fields 1-10 = id, secret, name, redirect_uris, allowed_scopes, allowed_authenticators, token_strategy, active, client_secret_expires_at, login_page_uri. No `tenant_id`/`grant_types`, no `reserved` ranges → field numbers 11+ free per ADR-0008 Rule 1 | Confirmed (content; cited range stale — message is now at :70-84) |
| `interfaces/sso/server_login_client.go:329` — `TenantID: client.TenantID` | Exactly at :329, inside `buildTrustSignals` — the **trust-signal** projection, not the token claim path (see §2 correction 2) | Confirmed exact (attribution corrected) |
| `infrastructure/defaultimpl/issue_payload.go:46` — `TenantID: subject.TenantID` | Exactly at :46 in `buildAccessPayload` (:27). ECDSA/RSA issuers share this one function. Strip coupling at :117-129 (`claimsWithoutEmittedKeys` removes the same-named `ext` key when the literal is emitted) | Confirmed exact |
| `infrastructure/defaultimpl/ed25519_types.go:47-52` — wire tag `json:"tenant_id,omitempty"` | `TenantID string` at :50 with tag `json:"tenant_id,omitempty"`; doc comment :43-49 ("mint-time client-binding tenant claim … projected from Subject.TenantID by buildAccessPayload") | Confirmed (tag at :50, inside cited range) |
| `cmd/sso-ctl/clientscmd/clients_test.go:34-73` — camelCase-shape pin test to extend | `TestRunList_DecodesGatewayCamelCaseShape` at :45-95: camelCase gateway fixture (:55-61, includes `"tokenStrategy":"jwt"`), decode struct :65-74, asserts TokenStrategy/RedirectURIs/Active decode. `TestRunList_TableFormat` at :97-123 asserts substrings only ("opaque", joined redirect URIs) — safe to extend, nothing asserts the header row | Confirmed (content; cited range stale — test is at :45-95) |
| `cmd/sso-ctl/apiclient/token.go:215-225` — `check --expect-tenant-id` sweep leg | :215-216 `if ck.expectTenantID != ""` → `ck.verifyTenantID(...)`; `verifyTenantID` :222-234 (absent → `claims: tenant_id absent`; mismatch → names observed vs declared). Flag declared at check.go:118 ("declare the minted token MUST carry this tenant_id"), usage text check.go:193. Claim read from decoded JWT payload (`decodeJWT` :107-145) | Confirmed |

Additional verifications required to bound the change (beyond the direction's citations):

| Check | Measured reality |
|---|---|
| `sso.Client` binding fields | `TenantID string json:"tenant_id,omitempty"` at shared/core/types.go:39-47 ("binds this client to one tenant…"); `GrantTypes []string json:"grant_types,omitempty"` at types.go:298-304 (DCR-settable; enforced at /token, server_token.go:107-111) |
| Token-claim binding sources (the real chain) | `TenantID: client.TenantID` into `Subject` at interfaces/sso/server_login.go:119 and internal/handler/tokengrant/{token_authcode.go:136, token_client_credentials.go:52, token_device.go:99, token_ciba.go:124}; `Subject.TenantID` doc at shared/core/types_token.go:226-236 ("the OAuth client's tenant binding at mint time") → `buildAccessPayload` → `tenant_id` claim. Single binding source: `client.TenantID` |
| Admin mapper | `clientToProto(c, includeSecret)` at interfaces/grpcserver/grpcadmin/admin_clients.go:394-415 is the **single** response mapper (used by List :94, Get :198, Create :215, Update :238, Approve :337); it copies 10 fields and omits `TenantID` + `GrantTypes`. Design comment at :73-75: "whose TenantID is intentionally absent from the admin wire protocol" |
| Write-side mappers | `protoToClient` :417-435 and `applyProtoToExistingClient` :443-460. Update overlays proto-exposed fields onto the STORED record (:443-459), so a proto field the mapper does not consume can never wipe the binding; the "Update wiped TenantID" regression test `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` (admin_clients_test.go:394-421) pins exactly this invariant |
| Gateway wire shape | cmd/sso-server/build_http.go:228 `runtime.NewServeMux()`; grpc-gateway v2.28.0 default JSONPb = protojson `{EmitUnpopulated: true, UseProtoNames: false}` (runtime/marshaler_registry.go:22-23) → camelCase `tenantId`/`grantTypes`, unpopulated values emitted as `""`/`[]`; gateway registered via `RegisterClientAdminServiceHandlerServer` (build_http.go:426); admin-gated via `newAdminOuterMux` (:238-260) |
| ADR-0008 additive-field rule | docs/adr/ADR-0008-proto-versioning.md, Rule 1: "Adding a field to v1 — always allowed. This is backward-compatible per proto3 semantics. New fields must use field numbers outside the reserved range." Client message has no reserved range → fields 11/12 free |
| OpenAPI contract mirror | `AdminClient` schema at docs/openapi.yaml:15971-16021 mirrors the proto (snake_case properties); `docs-validate` (kin-openapi) runs in `make ci` → the schema must gain the two fields in the same change |
| Codegen | `make proto-gen` = `cd proto && buf generate` (Makefile:181-183); gen files are committed; `gen/proto/admin/v1/clients.pb.go` currently has no `TenantId`/`GrantTypes` (grep empty). `make ci` includes `proto-lint` (buf lint) but not `proto-gen` → regeneration is part of this change |
| No existing test pins field absence | grep across interfaces/grpcserver/grpcadmin tests, test/, cmd/sso-ctl for `tenantId`/`grantTypes`/`TenantId`/`GrantTypes`: only discovery grant-types tests (unrelated) and the clients_test.go comments about the gap; nothing asserts the admin Client wire does NOT carry the fields |
| e2e placement constraint | test/ (package ssotest) cannot import `cmd/` (AGENTS.md architecture rule; confirmed by test/auditoutbox_governance_test.go:10 comment "test/ cannot import cmd/"); no test/ file spawns the sso-ctl binary (no `exec.Command` in test/*_test.go). The CLI-driving e2e must live inside `cmd/sso-ctl/clientscmd` (which may import apiclient + interfaces + gen downward) |
| Real-server sweep precedent | check_test.go `newLiveServer` (:71) proves a real `sso.Server` (MemoryClientStore + Ed25519 issuer + `WithIssuer(addr)`) passes all four probe groups green (goldenGreenStdout :32: "discovery: OK / mint: OK / invalid_scope: OK / introspect: OK / check OK"); EnvToken set only emits a stderr warning (check.go:64-67), non-fatal |
| Admin-gate test precedent | admin_middleware_test.go: stub `TokenValidator` + `permissions` provider with `admin:*` (adminProvider :28-41) wired via `sso.NewAdminMiddleware` (interfaces/sso/aliases.go:72 → interfaces/admin/middleware.go:108 `NewMiddleware(v TokenValidator, prov permissions.Provider)`) |

## 2. Corrections to the direction's problem framing

1. **Line drift on three citations, content intact.** `clients.go:21-38` is actually :65-81 (gap comment :70-72); `clients.proto:41-89` is actually :70-84; `clients_test.go:34-73` is actually :45-95. Symbols and behavior are exactly as cited.
2. **`server_login_client.go:329` is the trust-signal projection, not the token claim path.** `buildTrustSignals` feeds `trust.TrustSignals.TenantID`, not `Subject.TenantID`. The token-claim chain is `client.TenantID` → `Subject.TenantID` at server_login.go:119 + the four tokengrant stamps → `buildAccessPayload` (issue_payload.go:46) → `tenant_id` claim (ed25519_types.go:50). Net conclusion of the direction is unchanged — `client.TenantID` is the single binding source and the claim is emitted at mint — only the intermediate citation is mis-attributed.
3. **"TenantID intentionally absent from the admin wire protocol" is a deliberate design decision** (admin_clients.go:73-75). This change reverses it for the **read path only**: `tenant_id`/`grant_types` become read-only wire fields. The write-side mappers (`protoToClient`, `applyProtoToExistingClient`) must NOT consume them, so Create/Update gain no new mutation capability, no audit surface changes, and the Update overlay keeps preserving the binding (pinned by `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto`, admin_clients_test.go:394-421). The read-only semantics are documented in the .proto and OpenAPI so no future consumer assumes a round-trip.
4. **Wire emission detail that shapes the tests:** the gateway's default marshaler emits unpopulated values, so an unbound client appears on the wire as `"tenantId":""` / `"grantTypes":[]`. The clientscmd struct uses `omitempty` so CLI JSON output stays clean (no empty fields) for unbound clients — this is the intended split, not a bug.
5. **e2e placement:** the direction's "proposed new test in test/" cannot drive the real CLI there (test/ cannot import cmd/; no binary-spawn precedent). The acceptance is preserved in two halves: (a) a wire-level equality cross-check in `test/` (package ssotest) asserting the two facts the CLI commands render, and (b) the faithful CLI-driving e2e in `cmd/sso-ctl/clientscmd` running the real `runGet` and the real `apiclient.CheckRun` against a real assembled server + gateway.

## 3. Goal and user outcome

B4-1 requires tokens to carry `tenant_id` from the client binding — the claim path exists and is verified (§1). The operator-facing gap is that the admin wire and `sso-ctl clients` cannot show which tenant a registered client is bound to (or which grants it may use), so the deploy sweep's `check --expect-tenant-id` cannot be cross-referenced against registry state and a mis-bound client is invisible until runtime.

Completion marker: `sso-ctl clients list` and `sso-ctl clients get <id>` render the client's `tenantId` and `grantTypes`; a test proves the admin-wire `tenant_id` equals the `tenant_id` claim the `check --expect-tenant-id` sweep asserts on a minted token for the same client; and the sweep fails with a named-claims diagnostic when the operator's expectation disagrees with the registry state the admin wire reveals.

## 4. Product boundary

- Surface: admin gRPC wire (`proto/admin/v1/clients.proto` + the gateway mapper) and `cmd/sso-ctl/clientscmd` output (JSON default + table columns).
- Default: additive, always-on. Proto3 additive fields are non-breaking under ADR-0008; unbound clients stay byte-identical on the wire except for the new unpopulated-empty values the default marshaler already emits for every field.
- Explicit non-goals (do not implement):
  - No mutation capability: `tenant_id`/`grant_types` are **read-only** over the admin API. Create/Update do not consume them; binding remains registration-time (YAML/DCR/federation/store seed). No new admin capability, no audit events, no `admin:write` semantics change.
  - No change to the token claim path (`issue_payload.go`, `ed25519_types.go`, `Subject`, tokengrant handlers), to `resolveIssuer`/discovery, to the check sweep's flags or behavior (`apiclient/check.go`, `token.go`, `sweep.go` unchanged).
  - No new CLI subcommand, no new flags, no new package under `cmd/sso-ctl/` (fan-out ceiling), no `runGet` change (it already dumps the raw gateway JSON).
  - The other two direction entries in the analysis JSON (scope-matrix-v2 conformance view; `--expect-issuer` allowlist) are out of scope.
  - No fix to the table's existing omission of `AllowedScopes` (pre-existing partial surfacing; unrelated).

## 5. Requirements

### R1 — Proto: additive read-only fields 11/12 on `admin.v1.Client`

In `proto/admin/v1/clients.proto`, `message Client` (:70-84) gains:

```proto
// Read-only over the admin API: surfaced for operator verification of the
// client's tenant binding and grant-type allowlist. Mutations never consume
// these fields — binding is established at registration time (YAML/DCR/
// federation); GrantTypes is enforced at /token (unauthorized_client).
string tenant_id = 11;
repeated string grant_types = 12;
```

Field numbers 11/12 are free (no `reserved` ranges; ADR-0008 Rule 1). Regenerate and commit:
`cd proto && buf generate` (Makefile:181-183) → `gen/proto/admin/v1/clients.pb.go`
(and `.gw.go` if touched). The gateway marshaler then emits `tenantId`/`grantTypes`
(camelCase; grpc-gateway v2.28.0 default JSONPb). No other proto package changes.

### R2 — Mapper read path: `clientToProto` surfaces both fields

`interfaces/grpcserver/grpcadmin/admin_clients.go:394-415` — the single response mapper
(List/Get/Create/Update/Approve) — gains:

```go
TenantId:    c.TenantID,
GrantTypes:  append([]string(nil), c.GrantTypes...),
```

This is the only server-code change. `onClientDeleted`'s comment (:73-75) is updated to
read "intentionally not writable via the admin wire protocol" (the read path now surfaces it;
the mutation path remains closed).

### R3 — Mapper write path unchanged (read-only discipline)

`protoToClient` (:417-435) and `applyProtoToExistingClient` (:443-460) must NOT consume
`TenantId`/`GrantTypes`. The Update overlay then continues to preserve the stored binding
exactly as today; the existing regression test `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto`
(admin_clients_test.go:394-421) must keep passing unmodified. Add a one-line comment on
`protoToClient` stating the new fields are read-only by design (see R1).

### R4 — clientscmd: decode and render both fields

`cmd/sso-ctl/clientscmd/clients.go`:
- `clientListItem` (:73-81) gains `TenantID string json:"tenantId,omitempty"` and
  `GrantTypes []string json:"grantTypes,omitempty"` (camelCase per the pinned gateway shape;
  `omitempty` keeps unbound clients clean despite the gateway's EmitUnpopulated `""`/`[]`).
- Rewrite the stale gap comment (:70-72): the fields now exist on the wire; the comment
  documents that names must stay camelCase and that `tenantId`/`grantTypes` are read-only.
- `printClients` table (:107-118, header :112) gains `TenantID` and `GrantTypes` (comma-joined) columns.

`runGet` is unchanged (raw gateway JSON already carries the fields once R1+R2 land).

### R5 — T-8a: extend the wire-shape pin test

`cmd/sso-ctl/clientscmd/clients_test.go` `TestRunList_DecodesGatewayCamelCaseShape` (:45-95):
- Fixture (:55-61) gains `"tenantId":"tenant-acme","grantTypes":["authorization_code","refresh_token"]`.
- Decode struct (:65-74) gains the two fields; assert `TenantID == "tenant-acme"` and the
  grant array decodes exactly.
- Assert **render**: the captured stdout JSON contains `"tenantId":"tenant-acme"` and
  `"grantTypes":["authorization_code","refresh_token"]` (the fields survive the round trip).
- `TestRunList_TableFormat` (:97-123) additionally asserts the table contains `tenant-acme`
  and the comma-joined grant types (R4 table columns).

### R6 — Wire-level equality cross-check (test/, package ssotest)

New `test/client_tenant_binding_contract_test.go`. One deployment on one httptest server:
- real `sso.Server`: `WithIssuer(addr)`, `WithClientStore` (MemoryClientStore seeded with
  `client-1` bound to `TenantID: "tenant-acme"`, `GrantTypes: ["authorization_code","client_credentials"]`,
  `AllowedScopes: ["read","write"]`), Ed25519 issuer (`defaultimpl.NewEd25519JWTIssuer`) —
  the check_test.go `newLiveServer` shape;
- real admin gateway: `runtime.ServeMux` + `adminv1.RegisterClientAdminServiceHandlerServer`
  + `grpcadmin.NewClientAdminService(store, nil, nil, nil)` over the SAME store, admin-gated
  with the stub-validator + `admin:*` provider pattern of admin_middleware_test.go.

Assertions (the two facts the direction's acceptance names, at the wire level):
- `GET /api/v1/admin/clients/client-1` → 200; decoded `client.tenantId == "tenant-acme"` and
  `client.grantTypes` contains `authorization_code` (this is exactly what `sso-ctl clients get`
  renders).
- `POST /token` (grant_type=client_credentials, Basic client-1) → 200; decoded JWT payload
  `tenant_id == "tenant-acme"` (this is exactly what `sso-ctl check --expect-tenant-id tenant-acme`
  asserts; reuse the `decodeJWTPayload` precedent, test/oidc_test.go:33).
- Equality: admin-wire value == minted-claim value.
- Mis-bound visibility (the named harm): a second seeded client bound to `tenant-other` — the
  admin wire for it shows `tenant-other`, i.e. a sweep expectation of `tenant-acme` fails
  consistently on both surfaces; the mismatch is visible pre-runtime instead of only at token
  inspection time.
- Unbound control: a client with `TenantID: ""` renders `"tenantId":""` on the wire (EmitUnpopulated)
  and its minted token carries no `tenant_id` claim (`omitempty`; single-tenant byte-compat).

### R7 — CLI-driving e2e (cmd/sso-ctl/clientscmd, package clientscmd)

New `cmd/sso-ctl/clientscmd/tenant_binding_e2e_test.go` — same deployment assembly as R6,
but drives the REAL CLI code paths (no cmd→cmd import issue: clientscmd already imports
apiclient, and may import interfaces/grpcserver/grpcadmin + gen + grpc-gateway runtime downward):

- `t.Setenv(apiclient.EnvAddr, srv.URL)`, `t.Setenv(apiclient.EnvToken, "good")` (the stub
  validator's accepted token; the sweep only warns, never fails, on EnvToken).
- `runGet([]string{"client-1"})` via the existing `captureStdout` helper → exit 0; rendered
  JSON `tenantId == "tenant-acme"` (the `sso-ctl clients get <id>` leg).
- `apiclient.CheckRun([]string{"--addr", srv.URL, "--client-id", "client-1",
  "--client-secret", "s", "--expect-tenant-id", "tenant-acme"})` → exit 0; stdout contains
  `mint: OK` and `check OK` (the `sso-ctl check --expect-tenant-id` leg, real sweep code).
- Equality: the value the sweep declares and passes == the value runGet rendered.
- Anti-drift: `CheckRun` with `--expect-tenant-id tenant-other` → exit 1; stderr contains the
  `claims: tenant_id` named-mismatch diagnostic (token.go:222-234) — the sweep fails exactly
  when the registry binding the admin wire shows differs from the operator's declaration.

### Testable acceptance (Given/When/Then) — direction checks preserved

T-8a (extended pin test):

1. Given the gateway `ListClientsResponse` fixture carrying `"tenantId":"tenant-acme"` and
   `"grantTypes":["authorization_code","refresh_token"]` in camelCase, when `runList(nil)`
   runs, then exit 0 and the stdout JSON decodes with `TenantID == "tenant-acme"` and
   `GrantTypes == ["authorization_code","refresh_token"]`, and the raw output contains both
   field names with those values (decode AND render).
2. Given the same fixture, when `runList(["--format=table"])` runs, then exit 0 and the table
   contains `tenant-acme` and `authorization_code,refresh_token`.

e2e (cross-check + real CLI):

3. Given one deployment with `client-1` bound to `tenant-acme`, when
   `GET /api/v1/admin/clients/client-1` and a client_credentials mint both run, then the
   admin wire's `client.tenantId` equals the minted JWT's `tenant_id` claim (both
   `tenant-acme`).
4. Given the same deployment, when `runGet(["client-1"])` runs, then exit 0 and the rendered
   JSON `tenantId == "tenant-acme"`; when `CheckRun` runs with `--expect-tenant-id tenant-acme`,
   then exit 0 and stdout contains `check OK` — the two operator-visible facts agree.
5. Given the same deployment, when `CheckRun` runs with `--expect-tenant-id tenant-other`,
   then exit 1 and stderr names both values in a `claims: tenant_id` diagnostic — the sweep
   fails exactly when the binding the admin wire reveals differs from the declaration.
6. Given a client with `TenantID: ""` (and the gateway's EmitUnpopulated wire), when
   `runList` runs, then the CLI JSON omits `tenantId`/`grantTypes` (omitempty), and when a
   cc mint runs, then the token carries no `tenant_id` claim — single-tenant byte-compat on
   both surfaces.

Regression:

7. Given the unchanged write-side mappers, when the grpcadmin suite runs, then
   `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` (admin_clients_test.go:394-421)
   still passes — Update cannot wipe the binding and gains no new capability.
8. Given the existing clientscmd and apiclient suites, when they run against the modified
   files, then all pass: `TestRunList_DecodesGatewayCamelCaseShape` (extended), table test
   (extended), and the check sweep tests (check_test.go green/negative rows) are unchanged.

## 6. Engineering-gate constraints (verified)

- **Budgets**: `cmd/sso-ctl/clientscmd/clients.go` is 181 lines today; R4 adds ~10 — far
  under 500/file. No function exceeds 50 lines or complexity 15 (two struct fields + two
  table columns; `printClients` grows by 2 cells). `clients_test.go` stays under 500.
- **Fan-out**: no new package; `cmd/sso-ctl/` subdirectory count unchanged; clientscmd keeps
  1 non-test file. New test files are `_test.go` (exempt from the non-test file ceiling).
- **`interfaces/sso` 60-file ceiling**: untouched. All server-side work is in
  `interfaces/grpcserver/grpcadmin` (mapper) — no new files there either.
- **Import direction**: clientscmd tests (composition) importing `interfaces/grpcserver/grpcadmin`,
  `gen/proto/admin/v1` (interfaces), `infrastructure/defaultimpl`, `domains/permissions`,
  `grpc-gateway runtime` — all downward; no `cmd/` import by a library package; test/
  harness imports only library packages (no cmd/).
- **Wire/contract invariants**: additive proto fields per ADR-0008 Rule 1; no routes, no
  `Err*`, no config keys, no audit events, no token-claim change. `make ci` gates that run
  against this change: `proto-lint` (buf lint on the edited .proto), `docs-validate`
  (kin-openapi on the edited openapi.yaml), `route-contract` (gateway path set unchanged).
- **Pre-existing, unchanged**: `checks/directory_fanout.py` thresholds are not touched
  (no new directories). Any pre-existing failures observed at run time must be reported
  separately.

## 7. Files

### Create

```text
cmd/sso-ctl/clientscmd/tenant_binding_e2e_test.go — R7: real sso.Server + real admin gateway
    (runtime.ServeMux + RegisterClientAdminServiceHandlerServer + grpcadmin.NewClientAdminService
    over the same MemoryClientStore, admin-gated via stub validator + admin:* provider); drives
    runGet + apiclient.CheckRun (--expect-tenant-id, pass and mismatch legs); JWT decode helper
    (decodeJWTPayload pattern).
test/client_tenant_binding_contract_test.go — R6 (package ssotest): wire-level equality
    cross-check (admin-wire tenantId == minted tenant_id claim), mis-bound visibility row,
    unbound control row.
```

### Modify

```text
proto/admin/v1/clients.proto — R1: fields 11 (tenant_id) + 12 (grant_types), read-only docs.
gen/proto/admin/v1/clients.pb.go (+ clients.pb.gw.go if regen touches it) — regenerated via
    `cd proto && buf generate` (Makefile:181-183), committed.
interfaces/grpcserver/grpcadmin/admin_clients.go — R2: clientToProto maps TenantId + GrantTypes;
    R3: write-side mappers untouched + read-only comment; :73-75 comment updated to
    "not writable via the admin wire protocol".
cmd/sso-ctl/clientscmd/clients.go — R4: clientListItem fields, gap-comment rewrite, table columns.
cmd/sso-ctl/clientscmd/clients_test.go — R5: T-8a fixture + decode/render assertions; table assertion.
docs/openapi.yaml — AdminClient schema (:15971-16021) gains tenant_id + grant_types (snake_case,
    matching the proto; read-only description).
```

### Do not modify

```text
infrastructure/defaultimpl/{issue_payload.go,ed25519_types.go}, shared/core/types_token.go,
internal/handler/tokengrant/*, interfaces/sso/server_login*.go — the claim path is complete and
    verified; no token-side change.
cmd/sso-ctl/apiclient/{check.go,token.go,sweep.go} — the sweep already asserts tenant_id; no flag
    or behavior change.
interfaces/grpcserver/grpcadmin/{protoToClient,applyProtoToExistingClient} — read-only discipline (R3).
docs/error-codes.md, docs/config-reference.md — no new Err*, no config knob.
```

## 8. Dependencies and compatibility

- New/changed SPI: none. Additive proto fields only.
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: additive v1 fields per ADR-0008; old CLI clients ignore the new
  JSON keys; old servers (before this change) simply omit them, so a new CLI against an old
  server renders clients without tenant info (empty) rather than failing — acceptable
  cross-version behavior; ship server + CLI together for the operator value.
- Rollout/rollback: reverting removes the fields from proto/gen/mapper/CLI; the Update
  overlay invariant is preserved in both directions (no migration).
- The check sweep's `--expect-tenant-id` leg, the trust-signal path, and the grant-type
  enforcement at /token are all pre-existing and unchanged; this spec only makes their
  inputs observable on the admin wire.

## 9. Documentation

- [x] `docs/openapi.yaml` — AdminClient schema gains `tenant_id` + `grant_types` (R-section).
- [ ] `docs/error-codes.md` — not applicable (no new `Err*`).
- [ ] `docs/config-reference.md` — not applicable (no config knob).
- [ ] `docs/feature-matrix.md` — the B4-1 `tenant_id` claim row (:119) already documents the
  token side; no matrix change needed for the admin-wire surfacing.

## 10. Verification plan

```bash
cd proto && buf generate                    # regenerate gen/; commit with the .proto change
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/clientscmd/... -v -race    # T-8a extension + table + R7 e2e (real CLI)
go test ./interfaces/grpcserver/grpcadmin/... -v # mapper + Update-wipe regression (R3)
go test ./test/ -run 'TestClientTenantBinding' -v  # R6 wire-level cross-check
go test ./test/ -run TestE2E -v
make proto-lint && make docs-validate       # buf lint + kin-openapi on the edited files
make ci
```

Pre-existing failures to report separately: none known in the touched gates; if
`checks/directory_fanout.py` or any other pre-existing check fails at run time, report it
independently of this change (no new directories are introduced, so this spec cannot worsen it).
