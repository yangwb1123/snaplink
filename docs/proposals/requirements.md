Requirements specification written to `docs/auto/interfaces-apidocs-spec.md`. It derives from the analysis doc's "全局扫描结论" and contains exactly 3 decision headings, each with the requested name/problem/evidence/proposed behavior/acceptance check structure:

**## Decision 1 — Deployment-aware OpenAPI projection**
- **Problem**: `WithAPIDocsUI` claims "full live endpoint + schema inventory" but serves a static, deployment-blind document: `handleSpec` outputs the embedded spec verbatim, no option-state filtering, while `check-routes` reports **241 runtime routes vs 322 documented operations** (~81 return 404), and `servers:`/`info.version` are hardcoded placeholders (`docs/openapi.yaml` lines 52–60, 32).
- **Evidence**: `interfaces/apidocs/apidocs.go` (`New`/`handleSpec`), `interfaces/sso/server_routes.go` (`mountAPIDocsUI`, `WithAPIDocsUI` comment), `platform/buildinfo/buildinfo.go` (`ResolveProfile`), `python cli.py check-routes` output.
- **Proposal**: projection inputs (mounted-route allowlist, resolved issuer, buildinfo version) computed in `interfaces/sso` and passed down — keeping the no-cyclic-import rule; strip unmounted paths, rewrite `servers`/`info.version`.

**## Decision 2 — Render security and error contracts**
- **Problem**: `template.go`'s renderer has zero branches for `security`/`securitySchemes`/`servers`/`examples`; `ErrorResponse` renders as a plain object, hiding the per-endpoint auth family (bearer/DPoP/mTLS/Basic) and the oracle-safe error codes — the product's most distinctive contract.
- **Evidence**: `template.go` (`operationBody`, `paramsTable`, `renderSchema`), `docs/openapi.yaml` (line 11843 securitySchemes, 276 `security:` lines, line 14277 `ErrorResponse`), `docs/error-codes.md`, AGENTS.md oracle-safe table.
- **Proposal**: per-op "Authentication" line, "Errors" block keyed to operationId, security-schemes section, base-URL list; pure viewer change, dependency-free, no server-contract touch.

**## Decision 3 — Bidirectional lockstep + operationId changelog**
- **Problem**: `docs-validate`/`route-contract` only check spec syntax and "runtime ⊆ docs" — never the reverse; `go:embed` swallows byte drift; `sdk-surface.json` mandates CHANGELOG entries for operationId changes that no tool generates.
- **Evidence**: `Makefile` lines 178–181, `checks/route_contract.py` docstring, `docs/openapi_embed.go`, `ops/build/sdk-surface.json` policy text, `docs/deferred-backlog.md` ("not yet published as versioned packages").
- **Proposal**: reverse route-contract (documented-but-unmounted fails or must be triaged in an exception list), embed-consistency hash check, operationId-level semantic diff reusing kin-openapi/gensdk parsing → `make sdk-changelog`.

Each decision includes acceptance checks tied to existing gates (`go build/vet`, `TestMaintainability_|TestArchitecture_`, `make docs-validate`, `make ci`) and the module stays within its budgets (516 lines / 3 files; Decision 2 flagged as the only near-500-line file). The analysis doc's priority ordering (1 → 2 → 3) and the no-gate-relaxation constraint are preserved.
