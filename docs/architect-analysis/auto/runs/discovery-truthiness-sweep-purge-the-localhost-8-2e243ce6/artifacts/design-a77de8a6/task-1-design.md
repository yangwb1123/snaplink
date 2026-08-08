Design delivered: `docs/architect-analysis/cmd-gensdk-b4-3-discovery-truthiness-design.md` (companion to the requirements spec, in the sibling design-doc house style).

## Verification verdict

Every claim in the evidence checked out against HEAD — all 11 direction citations and all 8 additional facts confirmed, including the two the spec flags itself (the single `"/authenticate"` hit in `cmd/` is the legitimate `_test.go` scaffold guard at `scaffold_contract_test.go:136`; discovery is request-derived via `requestBaseURL` at `server_discovery_config.go:62`, making the port assertion testable). Baselines re-executed green: `go test ./cmd/sso-minimal/ ./cmd/gensdk/` and `go test ./test/ -run 'TestDiscovery_'`.

Three non-material corrections (C1–C3) folded into the design:

- **C1** — `edition_test.go` does *not* import `shared/core` today (imports `sso` + `shared/spi`); the sweep test adds it. No new edge (`op_session.go:16` already imports it).
- **C2** — minimal/standard docs also carry `check_session_iframe` (session manager wired unconditionally, `app.go:82`); design asserts `userinfo`/`end_session` for OIDC-on rows but deliberately skips `check_session_iframe` (wiring-dependent, not edition-gated).
- **C3** — R3's `:\d+` regex has a `{port}`-variable hole; design closes the drift class (`8080` literal, `{port}` variable, loopback `variables.host` default), stricter than the letter of R3 while satisfying all 12 acceptance cases.

## Design at a glance

- **API changes**: none in production code. One informational `servers:` edit in `docs/openapi.yaml` (verified consumed by no generator or gate); three new test functions.
- **Compatibility**: byte-identical SDK regeneration (generator never reads `servers:`), embed self-tracking via `parseSpec(docs.OpenAPISpec)`, edition behavior locked by existing prototype 404 test, hermetic httptest port assertions, budgets untouched (7/10 gensdk non-test files, 10/10 sso-minimal, `interfaces/sso` ceiling untouched).
- **Failure modes**: 14-row table covering suffix drift, `/authenticate` reintroduction, `8080`/`8080:0` shapes, alias-gating regression, walk root misresolution, `servers:` restructure — plus one documented accepted limitation (concatenation-based reintroduction passes R2 by design; R1 catches it behaviorally).
- **Migration**: 6 ordered steps, tree green after each, from spec purge → R3 test → R1 sweep → R2 guard → regeneration stability → full gates + `make ci`.
- **Acceptance mapping**: 12/12 preserved; cases 1–5, 7–11 fail under named gates, case 6 is the documented `_test.go`-exclusion invariant, case 12 is review-time absence.

No `.go` edits were made (docs-only change), so no mandatory gates were triggered; the one-line citation fix (`assertNoLegacyPathPort` span 134–147) was applied after verification.
