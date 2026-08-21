# CHECKS_REGISTRY.md — Agent engineering checks

Catalog of the Python engineering helpers. Committed Go gates are specified in
[`HARNESS.md`](HARNESS.md); broader repository automation is listed by
`make help` and `.github/workflows/`.

## Python modules

| Module | Purpose | Command |
|---|---|---|
| `acceptance.py` | Supplementary U1–U9 report | `accept` |
| `adapters_check.py` | Adapters delivery contract enforcement: conformance-suite inventory, router-backend matrix, embed examples, line budgets, kin-openapi validation of nested `cmd/*/openapi.yaml`, exported wire-code ↔ error-codes.md Stripe-row pairing; behaviorally runs suite + matrix | `adapters`, `make adapters-check` |
| `adr_compliance.py` | Project ADR checks | `adr-compliance` |
| `architecture.py` | Python dependency-direction check | `architecture` |
| `build.py` | Configured binary build | `build` |
| `complexity.py` | Optional cyclomatic/cognitive diagnostics | `complexity` |
| `coverage.py` | Package coverage regression gate | `coverage`, `evaluate` |
| `directory_fanout.py` | Configured subdirectory fan-out | via `adr-compliance` |
| `exemptions.py` | Declarative exemption synchronization | `check-exemptions` |
| `filesize.py` | Configured file-size check | `check-filesize` |
| `health_report.py` | Aggregate engineering health | `health-report` |
| `invariants.py` | Presence-only security marker scan | `check-invariants` |
| `route_contract.py` | Compiles registered route constants and requires matching OpenAPI operations + unique operation IDs | `check-routes`, `make route-contract` |
| `proto_openapi_parity.py` | Proto message field ↔ OpenAPI schema property parity (admin `Client` ↔ `AdminClient`); symmetric drift detection, rejects oneof/nested/reserved blocks it cannot represent | `check-proto-openapi-parity`, `make proto-openapi-parity` |
| `review_feature.py` | Feature-spec/checklist runner | `review [spec]` |
| `root_business_code.py` | Root business-file policy | via `accept`, `check-root` |
| `root_files.py` | Root file-count diagnostic | via `accept` |
| `self_test.py` | Deliberately bad harness probes | `self-test` |
| `ops/scripts/module_catalog.py` | Strict module/profile validation and capability planning | `modules check`, `modules list`, `modules plan`, `modules graph`, `modules why` |
| `ops/scripts/capability_registry.py` | Validates product availability against runtime gates/module capabilities and detects generated feature-matrix drift | `capabilities check`, `capabilities generate`, `capabilities list` |
| `ops/scripts/sdk_surface.py` | Validates the generated-SDK operation registry against OpenAPI + capabilities and re-emits every language | `sdk-surface check`, `sdk-surface generate`, `sdk-surface list` |
| `ops/scripts/profile_evidence.py` | Builds profile binaries and asserts the declared package-isolation boundaries (durable/admin graph must stay out of the small editions), archiving per-binary package/module/symbol/size evidence | `profiles evidence [--skip-build]` |
| `ops/scripts/configure_modules.py` | Atomic alternate modfile/overlay/lock materialization and profile builds | `configure --profile <id> [--version vX.Y.Z] [--build]` |

`config.py` loads `engineering.yaml`; `make_help.py` formats Make target help.
Run `python cli.py check-test` for check-module tests and
`python cli.py skill-test` for skill tests.

## Command groups

| Group | Commands |
|---|---|
| Fast loop | `check`, `check-filesize` |
| Composite reports | `harness`, `accept`, `evaluate` |
| Specific checks | `complexity`, `architecture`, `coverage`, `check-invariants`, `check-routes`, `check-proto-openapi-parity`, `adapters`, `capabilities check`, `sdk-surface check`, `profiles evidence`, `check-root`, `check-exemptions`, `adr-compliance` |
| Scaffolding | `generate` |
| Diagnostics | `diagnose`, `trend`, `health-report`, `self-test` |
| Test execution | `test`, `race`, `bench`, `check-test`, `skill-test` |
| Review | `review [spec]` |
| Module builds | `modules <action>`, `capabilities <action>`, `sdk-surface <action>`, `profiles evidence`, `configure --profile <id> [--version vX.Y.Z] [--build]`; `modules smoke` builds every supported profile plus each currently buildable preview |

`python cli.py --help` is the executable command index.

## Scope and limitations

- `make ci` is the core local gate; hosted CI additionally runs lint,
  security, contract, container, and infrastructure validation.
- `route_contract.py` covers statically registered stock-server routes plus
  the out-of-router liveness/readiness probes. Embedder-owned dynamic routes
  added through `Server.Handle` require their own OpenAPI contract.
- `adapters_check.py` static scans cover existence-level contract facts AND
  two wire-contract assertions: every `cmd/*/openapi.yaml` passes pinned
  kin-openapi validation, and every exported wire-code const in
  `cmd/snaplink-stripe-adapter/model.go` appears as a `| code |` row in the
  error-codes.md Stripe section (one-directional: consts ⊆ rows); behavior is covered
  by the Go tests it invokes (conformance suite + matrix), which run without
  `-race` — race coverage lives in `make ci`'s `race` target and
  `make test-e2e`.
- `capability_registry.py` describes product-level capability domains, not
  every protocol row or every profile's resolved dependency closure.
- `invariants.py` confirms selected markers exist somewhere; it does not prove
  per-endpoint behavior.
- Coverage fails closed when the test subprocess fails, a package target cannot
  be resolved, or a coverage row is missing. Optional complexity remains a
  diagnostic unless invoked through a blocking project gate.
- Python and Go fan-out use the same 15-subdirectory ceiling and skip scope;
  the committed Go exemption maps remain the ratcheted authority.

Exact open debt belongs in [`TODO.md`](TODO.md) and acceptance caveats in
[`EVALUATION.md`](EVALUATION.md).

## Adding a check

Prefer a committed root Go test for a build-blocking structural rule. Use a
Python module for orchestration or cross-cutting diagnostics, add its unit
test, expose it through `cli.py`, and document whether it blocks or only
reports. Project-specific OAuth/ADR scans must not be presented as generic
policy.
