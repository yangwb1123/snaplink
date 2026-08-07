Design document written to `docs/architect-analysis/auto/runs/add-a-global-scope-matrix-v2-registry-and-reject-a084fac6/artifacts/design-a77de8a6/task-1-design.md`.

## Verification outcome

Every evidence claim was re-checked against the tree — all verified, with two refinements to its "stale" findings confirmed:

- **Registry surface exists** (uncommitted): `protocols/oauth/scoperegistry/` (frozen `Memory`, fail-closed pattern grammar, `RejectUnregistered`/`FilterRegistered`), `interfaces/scopecontract.Matrix()` (8 scopes), `WithScopeRegistry`, 9 per-branch effective-scope call sites across all 8 grants, `oauth.scope_registry.{enabled,extra_scopes}` with always-on validation, docs rows.
- **Seam ordering**: `rejectUnregisteredScopes` runs at `server_token.go:132`, before `denyTokenScopeCombo`; discovery snapshots are pre-filtered at `server_discovery_cache.go:170`.
- **Tests**: `go test ./test/ -run TestScopeRegistry -v` → 9/9 PASS (re-ran, cached-green); package suites pass.

## Design content

- **API changes**: two new packages (`scoperegistry`, `scopecontract`), `WithScopeRegistry` + `ScopeRegistry()` accessor + `RefreshGrantDeps.ScopeRegistry()`, config block, 5 new `shared/core` scope constants; **zero HTTP wire changes** — no new endpoints, `Err*`, or audit events.
- **Compatibility constraints**: default-off nil-registry byte-compat, plain `{"error":"invalid_scope"}` no-trace body (never `errorBody`), post-auth + pre-token-policy ordering pins, rule-2 preservation, per-rotation fail-closed drain, discovery-never-over-advertises, frozen build-once registry, all budgets verified compliant.
- **Failure modes**: 9 rows (FM-1..FM-9) each with trigger, mitigation, and named verification pin, including the AC-2 deviation risk.
- **Migration**: ship-inert → pre-provision `extra_scopes` with `enabled:false` → fleet-wide flip → canary → drain → rollback-by-flip (no data migration).
- **Acceptance mapping**: AC-1/3/4/5 → named passing tests; **AC-2 confirmed as a deviation (D-1)** with four evidence points (login is a request surface, fail-closed downstream, RFC 9207 body already exists at login for allowlist violations, consistency with other direct mints) — plus the bounded ~10-line delta if the gate rejects it.

## Pre-existing failure reported separately

`go test -run 'TestMaintainability_|TestArchitecture_' .` FAILs on `TestArchitecture_DirectoryDepth` and `TestArchitecture_DirectorySubdirFanout` — 131 violations, **all** under `docs/architect-analysis/auto/**` (the pipeline's own artifact tree, depth 4-8). The registry code itself passes every other gate (import boundaries, layers, file size, complexity, fan-out, exemptions). Environmental, not caused by this work; flagged in the design so the implement stage reports it distinctly.
