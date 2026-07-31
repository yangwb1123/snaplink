# CHECKS_REGISTRY.md — Agent engineering checks

Catalog of the Python engineering helpers. Committed Go gates are specified in
[`HARNESS.md`](HARNESS.md); broader repository automation is listed by
`make help` and `.github/workflows/`.

## Python modules

| Module | Purpose | Command |
|---|---|---|
| `acceptance.py` | Supplementary U1–U9 report | `accept` |
| `adr_compliance.py` | Project ADR checks | `adr-compliance` |
| `architecture.py` | Python dependency-direction check | `architecture` |
| `build.py` | Configured binary build | `build` |
| `complexity.py` | Optional cyclomatic/cognitive diagnostics | `complexity` |
| `coverage.py` | Package coverage diagnostic | `coverage`, `evaluate` |
| `directory_fanout.py` | Configured subdirectory fan-out | via `adr-compliance` |
| `exemptions.py` | Declarative exemption synchronization | `check-exemptions` |
| `filesize.py` | Configured file-size check | `check-filesize` |
| `health_report.py` | Aggregate engineering health | `health-report` |
| `invariants.py` | Presence-only security marker scan | `check-invariants` |
| `route_contract.py` | Compiles registered route constants and requires matching OpenAPI operations + unique operation IDs | `check-routes`, `make route-contract` |
| `review_feature.py` | Feature-spec/checklist runner | `review [spec]` |
| `root_business_code.py` | Root business-file policy | via `accept`, `check-root` |
| `root_files.py` | Root file-count diagnostic | via `accept` |
| `self_test.py` | Deliberately bad harness probes | `self-test` |
| `ops/scripts/module_catalog.py` | Strict module/profile validation and capability planning | `modules check`, `modules list`, `modules plan`, `modules graph`, `modules why` |
| `ops/scripts/capability_registry.py` | Validates product availability against runtime gates/module capabilities and detects generated feature-matrix drift | `capabilities check`, `capabilities generate`, `capabilities list` |
| `ops/scripts/configure_modules.py` | Atomic alternate modfile/overlay/lock materialization and profile builds | `configure --profile <id> [--version vX.Y.Z] [--build]` |

`config.py` loads `engineering.yaml`; `make_help.py` formats Make target help.
Run `python cli.py check-test` for check-module tests and
`python cli.py skill-test` for skill tests.

## Command groups

| Group | Commands |
|---|---|
| Fast loop | `check`, `check-filesize` |
| Composite reports | `harness`, `accept`, `evaluate` |
| Specific checks | `complexity`, `architecture`, `coverage`, `check-invariants`, `check-routes`, `capabilities check`, `check-root`, `check-exemptions`, `adr-compliance` |
| Scaffolding | `generate` |
| Diagnostics | `diagnose`, `trend`, `health-report`, `self-test` |
| Test execution | `test`, `race`, `bench`, `check-test`, `skill-test` |
| Review | `review [spec]` |
| Module builds | `modules <action>`, `capabilities <action>`, `configure --profile <id> [--version vX.Y.Z] [--build]`; `modules smoke` builds every supported profile plus each currently buildable preview |

`python cli.py --help` is the executable command index.

## Scope and limitations

- `make ci` is the core local gate; hosted CI additionally runs lint,
  security, contract, container, and infrastructure validation.
- `route_contract.py` covers statically registered stock-server routes plus
  the out-of-router liveness/readiness probes. Embedder-owned dynamic routes
  added through `Server.Handle` require their own OpenAPI contract.
- `capability_registry.py` describes product-level capability domains, not
  every protocol row or every profile's resolved dependency closure.
- `invariants.py` confirms selected markers exist somewhere; it does not prove
  per-endpoint behavior.
- Coverage and optional complexity diagnostics have known false-green paths.
- Python/Go fan-out thresholds and declarative exemptions are not fully
  synchronized.

Exact open debt belongs in [`TODO.md`](TODO.md) and acceptance caveats in
[`EVALUATION.md`](EVALUATION.md).

## Adding a check

Prefer a committed root Go test for a build-blocking structural rule. Use a
Python module for orchestration or cross-cutting diagnostics, add its unit
test, expose it through `cli.py`, and document whether it blocks or only
reports. Project-specific OAuth/ADR scans must not be presented as generic
policy.
