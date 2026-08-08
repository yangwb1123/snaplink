All evidence gathered. Here is the review.

---

# Review: R1–R5 against the repository

## Verdict summary

| Review item | Verdict |
|---|---|
| R1: proto3 additive fields 11/12 pass `buf breaking` FILE + ADR-0008 Rule 1 | **Confirmed, empirically** (ran the real tool) |
| Wire shape: grpc-gateway JSONPb `EmitUnpopulated:true` + camelCase | **Confirmed** against v2.28.0 source and by executing the actual marshal path; citation is to the *module* file, not a repo file |
| Byte-delta `"tenantId":""`/`"grantTypes":[]` on every admin client response | **Confirmed empirically** with regenerated types |
| Cross-version CLI/server matrix | **Confirmed** (decode/re-encode mechanics verified) |
| F3: no enforceable proto↔OpenAPI field parity check; `docs-validate` not in `make ci` | **Confirmed** — and a pre-existing parity gap found: OpenAPI `AdminClient` lacks proto field 9 `client_secret_expires_at`; the parity check must close it or it fails on first run |

## 1. R1 — proto additive fields: CONFIRMED (empirically)

- `proto/admin/v1/clients.proto` `message Client` (:70–84) uses fields 1–10; **no `reserved` statement anywhere in the file**. ADR-0008 Rule 1 ("always allowed… must use field numbers outside the reserved range") is satisfied by construction.
- I applied the R1 edit to a scratch copy of `proto/`, regenerated with the repo's pinned toolchain (`buf` 1.59.0 + `protoc-gen-go`/`-go-grpc`/`-grpc-gateway` from `~/go/bin`), and ran the real gates:
  - `buf lint` (MINIMAL policy): **exit 0**
  - `buf breaking --against <old>` (FILE policy): **exit 0** (fields 11/12 added)
  - Negative control (deleted field 10 in a third copy): **exit 100**, `Previously present field "10" with name "login_page_uri" on message "Client" was deleted` — proves the gate is meaningful, not vacuous.
- Nuance: `make proto-breaking` compares against `git main`; proto files are unmodified in this worktree, so the baseline is the unchanged HEAD tree. The target is not in `make ci` (Makefile:265) — consistent with ADR-0008's compliance section, which explicitly says so.

## 2. R2/R3 — mapper claims: CONFIRMED

- `clientToProto` at `interfaces/grpcserver/grpcadmin/admin_clients.go:394–415` is the single read mapper; **all six** Client-bearing RPCs route through it (List :120, Get :212, Create :235, Update :270, Approve :358, and **ListExpiring** in `admin_paginate.go:68–72`). The design enumerates five — it omits ListExpiring; no design impact since R2's two-line addition covers it automatically.
- `protoToClient` :417–435 and `applyProtoToExistingClient` :443–460 consume nothing beyond their current fields; the overlay doc comment already names `TenantID` among the fields that must survive Update.
- `rejectDisallowedGrantType` verified at `interfaces/sso/server_token.go:107–111` — the F4/T-C invariant (seed must include `client_credentials` in `GrantTypes`) holds.
- Citation drift: the design's evidence table says core types live at `interfaces/sso/types.go:45-47,298-304` — that file does not exist. Actual: `shared/core/types.go:47` (`TenantID`), `:304` (`GrantTypes`).

## 3. Wire shape / marshaler: CONFIRMED, with a citation correction

- `marshaler_registry.go` is **not a repo file** — it is grpc-gateway v2.28.0's `runtime/marshaler_registry.go`. The evidence's `:22-23` citation matches the module file exactly: lines 19–26 define
  `defaultMarshaler = &HTTPBodyMarshaler{&JSONPb{MarshalOptions: protojson.MarshalOptions{EmitUnpopulated: true}, UnmarshalOptions: {DiscardUnknown: true}}}`.
  In v2.28.0, `JSONPb` embeds `protojson.MarshalOptions` directly (no OrigName forcing as in older versions), so `UseProtoNames` unset → false → **camelCase**. Both halves of the claim hold.
- The repo's gateway uses this default: `buildAdminRESTMux` (`cmd/sso-server/build_http.go`) calls `runtime.NewServeMux()` with no options, and the generated `clients.pb.gw.go:404+` uses `runtime.MarshalerForRequest`.
- **Byte-delta confirmed by execution.** Using the regenerated types under `protojson.MarshalOptions{EmitUnpopulated:true}`:
  - bound: `"tenantId":"tenant-acme","grantTypes":["authorization_code","refresh_token"]`
  - unbound: `"tenantId":"","grantTypes":[]` — every response gains both keys with empty values, exactly as claimed.
  - Incidental finding (pre-existing, not R1–R5): protojson emits int64 as JSON *strings* — today's wire already has `"clientSecretExpiresAt":"0"`. The CLI's `encoding/json` decode is unaffected.

## 4. R4 + cross-version matrix: CONFIRMED

- `clients.go:70-72` gap comment, `clientListItem` :73–81, table header :112, raw-map `runGet` :146–181 — all match. `runGet` passthrough means `clients get` renders the new keys without CLI changes.
- Matrix mechanics verified: `encoding/json` ignores unknown keys (old CLI + new server); absent keys decode to zero values and the proposed `omitempty` tags drop them on re-encode (new CLI + old server); table shows blank cells. "Degrades, never fails" holds. `WriteJSON` (`apiclient.go:161`) is plain `json.Encoder` — tag-driven, so the R4 tags fully control output.
- Minor: the existing test fixture comment ("This is the real shape produced by protojson…") overstates — the fixture omits `clientSecretExpiresAt`/`loginPageUri`; harmless for decoding, worth a one-word fix if T-8a is being extended anyway.

## 5. F3 — gap confirmed; enforceable check specified below

- `make ci` (Makefile:265) = `fmt vet race build examples proto-lint ci-modules config-validate-all modules-check modules-smoke route-contract capabilities-check sdk-surface-check profiles-evidence adapters-check`. **No `docs-validate`, no `proto-breaking`.** The design's §6 correction is right.
- `docs-validate` (Makefile:188) = `route-contract capabilities-check` + kin-openapi `validate` — document validity and route presence only. `route_contract.py` compares routes↔operations. Neither touches proto↔schema **field** parity. No existing check parses `.proto` at all (verified across `checks/`).
- **New finding:** OpenAPI `AdminClient` (`docs/openapi.yaml:15971–16000`) already drifts: it has 9 properties (proto fields 1–8 and 10) and **omits `client_secret_expires_at` (proto field 9)**, which the gateway emits on every response. A total 1:1 parity check fails today on exactly this field. So R5 as written (only `tenant_id` + `grant_types`) is insufficient: the check either ships with an allowlist (weak, drift-tolerant — the thing F3 exists to prevent) or R5 also adds `client_secret_expires_at` (integer, `format: int64`, same convention as `RotateSecretResponse` at :16060). Recommend the latter — it closes real drift with a one-property change.

### Enforceable F3 check — spec

Follow the `route_contract.py` pattern (module + `run() -> int` + cli.py registration + Make target + pytest) so it is committed tooling, not a grep footnote:

1. **`checks/proto_openapi_parity.py`** — `run() -> int`:
   - Parse `proto/admin/v1/clients.proto` `message Client { … }` block; collect top-level field names via `re` (`^\s*(repeated\s+)?[\w.]+\s+(\w+)\s*=\s*\d+;`), mirroring `route_contract.py`'s regex style. Oneofs/nested messages: none in `Client`; reject if one appears (fail loudly rather than mis-parse).
   - Load `docs/openapi.yaml` (PyYAML, as `route_contract.py` does); read `components.schemas.AdminClient.properties` keys.
   - Errors: (a) proto field absent from `AdminClient`; (b) `AdminClient` property without a proto field (symmetric; currently none). Print one line per drift, `FAIL:`/`PASS:` summary with counts, exit 1 on any error.
   - Data-driven pairs dict `MESSAGE_TO_SCHEMA = {"Client": "AdminClient"}` so future messages (e.g. `TokenAdmin`→schema) extend the check without new code.
2. **Registration:** `cli.py` — `cmd_check_proto_openapi_parity()` + entry in the command map (next to `check-routes`, :334); `Makefile` — `proto-openapi-parity: $(CLI) check-proto-openapi-parity`, and **add `proto-openapi-parity` to the `make ci` dependency list** (Makefile:265). Do **not** fold it into `docs-validate`: that target floats `kin-openapi@latest` (a concern `adapters_check.py:37` already documents) and is not in ci; the parity check must be deterministic and gated.
3. **Tests:** `checks/test_proto_openapi_parity.py` with `tmp_path`-based fixtures (proto + openapi written to a scratch root, matching `test_route_contract.py`'s style): missing-field case fails, extra-property case fails, exact-parity case passes.
4. **Registry:** one row in `docs/agent-os/CHECKS_REGISTRY.md` Python-modules table + `check-proto-openapi-parity` in the command-group list, and `make_help.py` picks the target up via `.PHONY`.
5. **Same-change discipline (the design's R5):** this change must (a) add `tenant_id`/`grant_types` **and** `client_secret_expires_at` to `AdminClient`, (b) add the check, (c) run `python cli.py check-proto-openapi-parity` + `python cli.py check-test` before handoff. Add both to the design's §6 verification list.

## 6. Residual notes

- The design's evidence table citation drift (`interfaces/sso/types.go` → `shared/core/types.go`) and the `test/`-vs-`interfaces/sso` location of `admin_middleware_test.go` (E-1 correctly targets `test/`, package `ssotest`) are cosmetic; no acceptance criterion depends on them.
- `make docs-validate` remains useful as a standalone; the F3 fix is about closing the parity gap *inside* ci, which the new target does without pulling the floating kin-openapi dependency into the gate.
- Nothing in R1–R5 touches the `interfaces/sso` 60-file ceiling, adds `Err*`, config keys, routes, or audit events; budget claims hold.

**Bottom line:** R1–R4 verified against code and by execution; the only substantive change needed is in the F3/R5 area — the parity check must be a committed, ci-gated check module, and R5 must also add `client_secret_expires_at` to the `AdminClient` schema or the check fails on first run.
