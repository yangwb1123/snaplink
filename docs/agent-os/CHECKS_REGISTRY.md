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
| `ops/scripts/sdk_surface.py` | Orchestrates generated-SDK registry validation, explicit-baseline operation/schema diffing, and regeneration | `sdk-surface check`, `sdk-surface diff --baseline-ref <ref>`, `sdk-surface generate`, `sdk-surface list` |
| `ops/scripts/sdk_versions.py` | Reads the four fixed SDK manifests, validates SemVer 2.0.0, checks the TypeScript lock root, and compares package versions | `sdk-surface versions`; also runs inside `sdk-surface check` |
| `ops/scripts/sdk_toml.py` | Stdlib TOML loader with a fixed-format fallback for older repository tooling | Called by `sdk_versions.py` |
| `ops/scripts/sdk_schema.py` | Bounded `components.schemas` structural compatibility comparison using PyYAML; conservative for composition/unsupported keyword changes | Called by `sdk-surface diff` |
| `ops/scripts/sdk_baseline.py` | Reads registry + OpenAPI from one local git ref without fetch/shell, or reports a closed baseline error | Called by `sdk-surface diff` |
| `ops/scripts/sdk_report.py` | Stable operation-surface and schema breaking/additive report formatting | Called by `sdk-surface diff` |
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
| Specific checks | `complexity`, `architecture`, `coverage`, `check-invariants`, `check-routes`, `check-proto-openapi-parity`, `adapters`, `capabilities check`, `sdk-surface versions`, `sdk-surface check`, `sdk-surface diff --baseline-ref <ref>`, `profiles evidence`, `check-root`, `check-exemptions`, `adr-compliance` |
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
- `sdk-surface versions` is a read-only, non-networked gate over four audited
  paths: the TypeScript `package.json` and `package-lock.json`, Python
  `pyproject.toml`, Rust `Cargo.toml`, and PHP `composer.json`. It rejects
  missing or malformed manifests, missing/non-string/invalid SemVer versions,
  package-version drift, and a TypeScript lock-root mismatch. It reads only
  package-root metadata, never dependency versions, and does not publish or
  change any file. `sdk-surface check` and `make ci` run the same gate;
  versioned package publication remains an external release boundary.
- `sdk-surface diff` compares the committed registry's group/operation data and,
  when available, a bounded structural subset of OpenAPI `components.schemas`.
  It requires exactly one explicit local baseline (`--baseline-ref` or
  `--baseline-file`); a ref reads both files from that same local commit without
  fetching, while `--baseline-file` is registry-only unless explicitly paired
  with `--baseline-openapi-file`. It never reads generated SDK source, changes
  versions, or exposes a breaking-change bypass. Removed/renamed operationIds,
  group relocations, schema/property removals, required additions, `$ref`/type/
  format changes, `additionalProperties` tightening, enum removals, and nested
  or array breaking changes fail; optional properties, required removals, and
  enum additions are additive. Description/title/examples/default metadata is
  ignored. `oneOf`/`anyOf`/`allOf` and other unsupported schema keyword changes
  use a conservative breaking policy; this is not a complete vendor-level OAS
  diff. The opt-in `make sdk-surface-diff` target requires
  `SDK_SURFACE_BASELINE_REF`; it is intentionally not a `make ci` prerequisite, so
  a shallow or parentless local checkout cannot create a false baseline result.
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
