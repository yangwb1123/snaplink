All verifications complete. Summary of what was validated and delivered:

## F3 parity check — committed and gated

**New files**
- `checks/proto_openapi_parity.py` — follows `route_contract.py` conventions exactly: shebang + module docstring, `from __future__ import annotations`, `ROOT = Path(__file__).resolve().parents[1]`, relative `Path` constants, regex constants with rationale comments, root-parameterized helpers (`proto_fields`, `schema_properties`, `contract_errors(root) -> tuple[list[str], int, int]`), `run() -> int` with try/except + `FAIL:`/`PASS:` summary output, and the `sys.exit(run())` main guard. Data-driven `MESSAGE_TO_SCHEMA = {"Client": "AdminClient"}` so future messages extend it without new code. Oneof/nested-message/reserved blocks fail loudly rather than mis-parse (per the wire reviewer's spec).
- `checks/test_proto_openapi_parity.py` — 8 tests in `test_route_contract.py`'s `tmp_path` style (minimal `proto/admin/v1/clients.proto` + `docs/openapi.yaml` trees), plus a repository-level parity pin mirroring `test_repository_runtime_routes_are_documented`.

**Wiring (all verified in-tree)**
- `cli.py` — `cmd_check_proto_openapi_parity()` + `"check-proto-openapi-parity"` in the `COMMANDS` map directly after `"check-routes"` (now :341, spec said ~:334 — same block) + docstring help line; `python cli.py help` lists it.
- `Makefile` — `proto-openapi-parity` target (uses `$(CLI)` like `route-contract`), added to `.PHONY` (:16) and to the `make ci` dependency list (:268); `make proto-openapi-parity` exits 0 and `make help` surfaces it via `make_help.py`.
- `CHECKS_REGISTRY.md` — module row in the Python-modules table + `check-proto-openapi-parity` in the "Specific checks" command group.
- Full `python cli.py check-test` suite: **203 passed** (includes the 8 new tests).

**First-run pass (with the pre-existing gap closed)**
- `docs/openapi.yaml` `AdminClient` gained `client_secret_expires_at` (integer/int64 — closes the pre-existing field-9 gap the wire reviewer found, without which a 1:1 check fails on first run), plus `tenant_id` and `grant_types` with read-only semantics matching R5.
- `proto/admin/v1/clients.proto` gained `tenant_id = 11` / `grant_types = 12` (hand-written R1 edit; no `buf` in-tree per B2, and nothing compiles against the fields yet, so `go build` is unaffected — regeneration belongs to the R1/R2 implementation task).
- Result: **`PASS: proto/OpenAPI field parity (12 proto fields, 12 schema properties)`** on first run, exit 0. Negative controls on scratch trees prove both directions detect drift: proto-drop → `AdminClient tenant_id: schema property without a Client proto field`; schema-drop → `Client.tenant_id: proto field absent from AdminClient schema`.

**B3 fix**
- The broken `grep -A20 '^    AdminClient:' ... | grep -c ...` line in the design's §6 verification plan is replaced with `python cli.py check-proto-openapi-parity && python cli.py check-test` (the committed check + its unit tests), and the trailing `make ci` line now annotates that ci gates F3 via `proto-openapi-parity`.

**Regression check** — `python cli.py check-routes` still PASS (241 routes / 348 operations) and kin-openapi validates the edited `docs/openapi.yaml` (exit 0). No `.go` edits were made, so the Go mandatory gates are not triggered; `gen/` is untouched. Pre-existing worktree modifications (stripe-adapter, auditverify, `servers:` localhost removal in openapi.yaml, adapters_check.py) were preserved untouched.

One residual note for the implementation task: B2 stands — `buf generate` requires installing buf + pinned protoc plugins (protoc-gen-go v1.34.1, protoc-gen-go-grpc v1.5.1, grpc-gateway v2.28.0) before the R1/R2 mapper work can land.
