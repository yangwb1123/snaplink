Verification complete. All evidence claims check out against HEAD, with a handful of minor drifts in the spec's own citations. Here is the design deliverable.

---

# Design: admin-wire client tenant binding (`tenant_id` + `grant_types`) surfacing — `clientscmd`

## 0. Evidence audit verdict

**Every cited symbol verified against the repository. All content claims hold.** The verification summary's core claims are confirmed; I found four additional drifts *in the spec's own citations* (not the direction's):

| Spec claim | Measured | Verdict |
|---|---|---|
| `clients.go` gap comment verbatim at :70-72, struct :73-81, table header :112, `runGet` :146-181 | Exact match | Confirmed |
| `clients.proto` `message Client` :70-84, fields 1-10, no `reserved` | Exact; numbers 11/12 free | Confirmed |
| `server_login_client.go:329` is trust-signal projection, not claim path | `TenantID: client.TenantID` inside `buildTrustSignals`; claim chain is `client.TenantID` → `Subject.TenantID` (`server_login.go:119`; **8** grant stamps — authcode :136, cc :52, device :99, ciba :124, jwt_bearer :112, saml2_bearer :123, exchange :399, refresh :292 — not 4) → `issue_payload.go:46` → tag `ed25519_types.go:50` | Confirmed; correction is itself corrected (chain is broader than cited) |
| `issue_payload.go:46`, `ed25519_types.go:47-52` | Exact | Confirmed |
| `clients_test.go` shape pin :45-95, table test :97-123 | Exact | Confirmed |
| `token.go:215-216` + `verifyTenantID`; flag `check.go:118` | Confirmed; `verifyTenantID` at :227-235 (spec said :222-234) | Confirmed, trivial drift |
| `clientToProto` :394-415 single read mapper; `protoToClient` :417-435, `applyProtoToExistingClient` :443-460 don't consume binding; `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` :394-421 pins the overlay | Exact | Confirmed |
| core `TenantID` (types.go:45-47), `GrantTypes` (types.go:298-304, enforced at `server_token.go:107-111` `rejectDisallowedGrantType`) | Exact | Confirmed |
| grpc-gateway v2.28.0 default marshaler `{EmitUnpopulated:true}`, camelCase | `marshaler_registry.go:22-23`; `UseProtoNames` unset → false | Confirmed |
| ADR-0008 Rule 1 (additive v1 fields, no reserved range) | ADR-0008:59 | Confirmed |
| `make ci` includes `docs-validate` (kin-openapi) | **FALSE.** `ci` = fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract capabilities-check sdk-surface-check profiles-evidence adapters-check. `docs-validate` is standalone (Makefile:188) | **Spec §6 error — see §4 failure mode F3** |
| Admin-gate precedent `admin_middleware_test.go` | Lives in **`test/`** (package ssotest), not `interfaces/sso/` — `stubValidator` :13-24, `adminProvider` :27-38. Better than cited: R6 lands in the same package | Location drift |
| "intentionally absent" comment | `admin_clients.go:59` (on `onClientDeleted` field), not :73-75 | Line drift |
| `test/` cannot import `cmd/`; no binary-spawn precedent | `test/auditoutbox_governance_test.go:10` | Confirmed |
| `newLiveServer` (check_test.go:71) real-server sweep precedent; `goldenGreenStdout` :32 | Exact; EnvToken emits only a stderr warning (check.go:81-85, non-fatal) | Confirmed |
| No test pins field absence; `gen/proto/admin/v1/clients.pb.go` has no `TenantId`/`GrantTypes` | Grep empty; only unrelated `admin_domains.go`/`admin_tenants.go` `TenantId` uses (different messages — supports the camelCase `tenantId` naming) | Confirmed |
| Direction entry 1 acceptance | Direction JSON is a text+json hybrid; entry 1's acceptance text matches the spec's R5/R6/R7 split exactly | Confirmed |

**New design-relevant facts found during audit** (not in the spec):
- **Sweep mint leg uses `grant_type=client_credentials`** (token.go:61). Therefore the e2e seed's `GrantTypes` **must include `"client_credentials"`**, or `rejectDisallowedGrantType` (server_token.go:107-111) returns `400 unauthorized_client` and the mint leg fails. The spec's R6 seed already has it; promote to an invariant (see §5, T-C).
- **buf lint is MINIMAL** (proto/buf.yaml) — no field-comment enforcement; the R1 doc comments are hygiene, not gate-driven.
- **`docs-validate`/`route-contract` check paths, not proto↔OpenAPI field parity** — the `AdminClient` schema update is enforced by nothing automated; needs an explicit verification step.
- Wire byte-delta: with `EmitUnpopulated`, *every* admin client response (bound or not) gains `"tenantId":""`/`"grantTypes":[]` keys. Old CLIs ignore them (`encoding/json`); strict snapshot consumers of the admin API observe new keys — the only true observable wire delta.

## 1. API changes

**R1 — proto (additive, read-only).** `proto/admin/v1/clients.proto`, `message Client` (:70-84):
```proto
// Read-only over the admin API: surfaced for operator verification of the
// client's tenant binding and grant-type allowlist. Mutations never consume
// these fields — binding is established at registration time (YAML/DCR/
// federation); GrantTypes is enforced at /token (unauthorized_client).
string tenant_id = 11;
repeated string grant_types = 12;
```
Numbers 11/12 free (no `reserved`; ADR-0008 Rule 1). Regenerate via `cd proto && buf generate` (Makefile:181-183); commit `gen/proto/admin/v1/clients.pb.go` (+ `.gw.go` if touched). Wire shape: camelCase `tenantId`/`grantTypes` via the gateway's default JSONPb.

**R2 — server read path (single mapper).** `interfaces/grpcserver/grpcadmin/admin_clients.go`, `clientToProto` (:394-415) gains:
```go
TenantId:   c.TenantID,
GrantTypes: append([]string(nil), c.GrantTypes...),
```
This is the only production server change (List/Get/Create/Update/Approve all route through it). Update the :59 comment to "intentionally not writable via the admin wire protocol".

**R3 — write path closed.** `protoToClient` (:417-435) and `applyProtoToExistingClient` (:443-460) unchanged; the Update overlay continues to preserve the stored binding (`TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` must pass unmodified). Add a one-line read-only-by-design comment on `protoToClient`.

**R4 — CLI.** `cmd/sso-ctl/clientscmd/clients.go`:
- `clientListItem` (:73-81) gains `TenantID string \`json:"tenantId,omitempty"\`` and `GrantTypes []string \`json:"grantTypes,omitempty"\`` (camelCase per pinned gateway shape; `omitempty` keeps unbound-client JSON clean against EmitUnpopulated `""`/`[]`).
- Rewrite the :70-72 gap comment to document the read-only semantics and the camelCase-pin constraint.
- `printClients` header (:112) gains `TenantID`, `GrantTypes`; rows gain the values (grants comma-joined).
- `runGet` unchanged (raw `map[string]any` JSON already carries the fields once R1+R2 land).

**R5 — contract mirror.** `docs/openapi.yaml` `AdminClient` schema (:15971-16000) gains `tenant_id` (string) and `grant_types` (array of string) with the read-only description, snake_case matching the proto.

## 2. Compatibility constraints

- **Proto3 additive fields (ADR-0008 Rule 1):** no wire break; old gRPC peers ignore/omit the fields. `buf breaking` (FILE policy) passes.
- **Cross-version CLI/server matrix:** new CLI + old server → `tenantId`/`grantTypes` absent → CLI decodes `""`/`nil`, JSON omits (omitempty), table shows blank — degrades, never fails. Old CLI + new server → unknown keys ignored. Ship server + CLI together for the operator value.
- **Read-only semantics:** no Create/Update consumption, no new audit events, no `admin:*` change, no routes, no `Err*`, no config keys. Binding sources (YAML/DCR/federation/store seed) unchanged; claim path (`issue_payload.go`, `ed25519_types.go`, `Subject`, all 8 tokengrant stamps) untouched.
- **Single-tenant byte-compat:** unbound clients emit `"tenantId":""`/`"grantTypes":[]` on the wire (EmitUnpopulated, same as every other unpopulated field today) and carry **no** `tenant_id` claim in tokens (`omitempty`) — token bytes unchanged.
- **Budget gates:** clients.go grows ~10 lines (181 → ~191); no new packages/dirs; `interfaces/sso` 60-file ceiling untouched; all test additions are `_test.go` (exempt).
- **Import direction:** clientscmd tests (composition) import `interfaces/grpcserver/grpcadmin`, `gen/proto/admin/v1`, `infrastructure/defaultimpl`, `domains/permissions`, grpc-gateway runtime — all downward. `test/` (ssotest) imports only library packages.

## 3. Failure modes

| # | Mode | Detection | Behavior |
|---|---|---|---|
| F1 | Regen omitted (proto edited, gen/ stale) | `go build ./...` fails — `adminv1.Client` lacks the fields | Hard fail at the mandatory gate; the mapper edit cannot compile |
| F2 | Marshaler drift (future grpc-gateway upgrade changing EmitUnpopulated/case) | Extended T-8a pin test (R5) | Test fails; CLI silently mis-decodes otherwise |
| F3 | OpenAPI mirror forgotten | **Not gated**: `docs-validate` (kin-openapi) and `route-contract` check document validity and paths, not proto↔schema field parity; `docs-validate` is not in `make ci` (spec §6 error) | Silent contract drift; mitigated by explicit grep step in §6 and same-change discipline |
| F4 | E2E seed omits `client_credentials` from `GrantTypes` | Sweep mint leg gets `400 unauthorized_client` (`server_token.go:107-111`) | R7 e2e fails confusingly; prevented by seed invariant T-C |
| F5 | Write-side mapper accidentally consumes fields (future edit) | `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` + a new mirror assertion (no-op Update round-trips binding) | Data-loss regression caught by the existing pin |
| F6 | Strict admin-API JSON snapshots | New empty keys on every client response | Additive; documented, not breaking (proto3 contract); old consumers ignore |
| F7 | Table header/width assertions | None exist (table test asserts substrings only) | No regression surface |

## 4. Migration steps

1. Edit `proto/admin/v1/clients.proto` (R1) → `cd proto && buf generate` → commit gen files in the same change.
2. Edit `clientToProto` (R2) + comment updates (R3) in `admin_clients.go`.
3. Edit `cmd/sso-ctl/clientscmd/clients.go` (R4).
4. Extend `clients_test.go` (R5) and add the two test files (R6/R7, §5).
5. Update `docs/openapi.yaml` `AdminClient` (R5) in the same change.
6. Run mandatory gates + §6 verification; `make ci` for handoff.
7. Rollout: server + CLI shipped together; rollback = revert the same commit set (fields removed from proto/gen/mapper/CLI; Update overlay invariant preserved in both directions — no migration, no storage change).

## 5. Testable acceptance mapping

Direction acceptance preserved: *T-8a* (decode+render of a tenant/grant-bearing fixture) and *e2e* (`clients get` JSON tenant_id == what `check --expect-tenant-id` asserts on the minted token). Split per the `test/` cannot-import-`cmd/` constraint: wire-level equality in `test/` (ssotest), faithful CLI-driving in `cmd/sso-ctl/clientscmd`.

| ID | Given | When | Then |
|---|---|---|---|
| T-8a.1 | Gateway `ListClientsResponse` fixture with `"tenantId":"tenant-acme"`, `"grantTypes":["authorization_code","refresh_token"]` (camelCase) | `runList(nil)` (extended `TestRunList_DecodesGatewayCamelCaseShape`) | Exit 0; stdout JSON decodes `TenantID=="tenant-acme"`, `GrantTypes` exact; raw output contains both field names + values (decode AND render) |
| T-8a.2 | Same fixture | `runList(["--format=table"])` | Exit 0; table contains `tenant-acme` and `authorization_code,refresh_token` |
| T-C (invariant) | Seed client `GrantTypes` excludes `client_credentials` | Sweep mint leg (`token.go:61`) | `400 unauthorized_client` — seed **must** include `client_credentials`; documented in both test files |
| E-1 | One deployment: real `sso.Server` (MemoryClientStore, `client-1` bound `tenant-acme`, Ed25519 issuer, `WithIssuer(addr)`) + real admin gateway (`runtime.ServeMux` + `RegisterClientAdminServiceHandlerServer` + `grpcadmin.NewClientAdminService` over the **same** store, admin-gated via `sso.NewAdminMiddleware` + stub validator + `admin:*` provider — `test/admin_middleware_test.go` pattern, same package) | `GET /api/v1/admin/clients/client-1` and `POST /token` (cc, Basic client-1) | 200/200; decoded `client.tenantId == tenant-acme` **==** decoded JWT `tenant_id` claim `tenant-acme` (wire-level equality, `decodeJWTPayload` precedent `test/oidc_test.go:33`) |
| E-2 | Same deployment; second client bound `tenant-other` | Read its admin wire | Wire shows `tenant-other` → a `--expect-tenant-id tenant-acme` sweep fails consistently on both surfaces; mismatch visible pre-runtime (named harm) |
| E-3 | Client with `TenantID: ""` | `runList` + cc mint | CLI JSON omits both keys (omitempty vs EmitUnpopulated `""`/`[]`); minted token has no `tenant_id` claim (single-tenant byte-compat) |
| E-4 | Same deployment as E-1 | `runGet(["client-1"])` (real `runGet`, `captureStdout`) | Exit 0; rendered JSON `tenantId == "tenant-acme"` |
| E-5 | Same deployment | `apiclient.CheckRun(["--addr", srv.URL, "--client-id","client-1","--client-secret","s","--expect-tenant-id","tenant-acme"])` (real sweep) | Exit 0; stdout contains `mint: OK` and `check OK`; declared value == E-4's rendered value |
| E-6 | Same deployment | `CheckRun` with `--expect-tenant-id tenant-other` | Exit 1; stderr contains the `claims: tenant_id` named-mismatch diagnostic (`verifyTenantID` :227-235) — sweep fails exactly when declaration disagrees with registry state |
| R-1 | Unchanged write mappers | grpcadmin suite | `TestClientAdminService_UpdatePreservesFieldsNotInAdminProto` passes unmodified; add a no-op-Update binding round-trip assertion |
| R-2 | Existing clientscmd + apiclient suites | Run against modified files | T-8a (extended), table (extended), check green/negative rows all pass unchanged |

## 6. Verification plan

```bash
cd proto && buf generate && git add gen/proto/admin/v1   # F1 fail-fast
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/clientscmd/... -race -v              # T-8a + table + E-4..E-6
go test ./interfaces/grpcserver/grpcadmin/... -v           # R-1
go test ./test/ -run 'TestClientTenantBinding' -v          # E-1..E-3
go test ./test/ -run TestE2E -v
make proto-lint && make route-contract && make docs-validate   # docs-validate is NOT in make ci (spec §6 error)
grep -A20 '^    AdminClient:' docs/openapi.yaml | grep -c 'tenant_id\|grant_types'   # F3 manual parity check
make ci
```

**Pre-existing worktree note:** the tree carries unrelated uncommitted modifications (stripe-adapter, auditverify, etc.). The change set here touches only the 8 files in the spec §7; unrelated worktree changes are preserved untouched.
