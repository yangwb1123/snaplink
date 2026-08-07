Design complete. Summary of the work:

## Evidence verification (all claims re-checked against HEAD `fc8ec2c7`)

Every citation in the requirements spec was independently verified. **All core claims confirmed**, including the two corrections the spec itself records:
- **B4-2 landed**: `protocols/oauth/scoperegistry` (`RejectUnregistered` at reject.go:31-40), `WithScopeRegistry` (options_misc.go:494), `ScopeRegistry()` accessor (accessors_handlers.go:166), dispatch seam `rejectUnregisteredScopes` (server_token.go:189-204) running *before* `dispatchCustomGrant` (drifted :345→:383) — so the scaffold's job is to teach the seam + the per-client `GrantedScopes` gate the seam does **not** apply to custom grants
- **Stale citation**: `interfaces/sso/options_saml2_bearer.go` confirmed nonexistent (only reference is the template itself); real handler at server_setup.go:271/283
- Two line-level nits found: `handle_par.go` invalid_scope branch spans 197-200 (not :198); the design cites ranges, not lines

## Design delivered

Written to `docs/architect-analysis/auto/runs/encode-b4-token-claims-and-scope-registry-invari-dddba3e2/artifacts/design-a77de8a6/task-1-design.md` (the pipeline's design-stage output path), containing:

- **6 design decisions** (D1-D6): comment-block teaching artifact kept (ALT-1 real-code rejected), example restructured into 4 ordered steps (gate → roles → issuance passing `grantedScopes`), registry-seam note text, named-marker test helper, one strict strengthening over R3 (`}, grantedScopes)` marker for R1's "never raw req.Scope"), stale-citation fix
- **API changes**: none public; only new-scaffold generated text changes
- **Compatibility constraints**: server wire-compat untouched, budgets with verified headroom, `interfaces/sso` ceiling untouched, no go.mod/go.sum change
- **8 failure modes** (FM-1..FM-8) with detection and mitigation, incl. the B4-1 contract-sync residual risk (R4)
- **6 migration steps** ending in `make ci`, plus rollback
- **Acceptance mapping**: R1-R4 → A1/A2/A3 → concrete Given/When/Then

## Mechanical validation performed

- Marker simulation against the proposed template text: `core.ErrInvalidScope` (idx 1310) and `Roles(` (1695) both precede `issuer.Issue(` (2450) ✓; `TenantID`/`}, grantedScopes)` correctly appear inside the Subject literal (presence-only assertions) ✓
- Zero backticks in the proposed raw-string block (raw-string safety) ✓
- The `assertGrantContract` helper extracted to a scratch module: `gofmt` clean, `go vet` clean ✓
- Corrected one budget figure (helper cyclomatic ≈10, not 6) after counting
