Verification complete. Report written to `docs/architect-analysis/auto/runs/issuer-allowlist-with-require-configured-switch--8e66686e/artifacts/adversarial_review-9c87f3a7/acceptance-suite-verification.md`.

## Summary

I re-verified every cited line against working tree HEAD `32596d23` (the design body is unrevised on disk — the newer run's copy is a summary pointer), then mapped all 10 review findings to test homes and observables.

**Mapped and correct (5):**
- **G3/A9a** — `handleMFAComplete` (server_mfa.go:181, 487 lines), slot between `tokenNoStoreHeaders` (:195) and the `mfaProvider` check (:196); A9a's home is feasible (`auth_pipeline_test.go:90-91` wiring precedent). Needs 3 assertion deltas: no-store on the MFA 503, challenge-not-consumed witness, byte-uniformity vs G2.
- **C4 no-store split** — G2/G3/G4 structural via header-first stamps; G1 discovery 503 deliberately carries no cache headers (quota.go:205 pattern) — suite must assert header-absence for G1, no-store for credential endpoints.
- **Oracle-safety placements** — all four gates precede every row-dependent step; needs one table test (valid/garbage creds, existing/nonexistent codes, valid/bogus challenge IDs → byte-identical bodies mod `trace_id`).
- **Sentinel split** — cmd 503 unreachable by construction (`"sso-server"` ≠ sentinel `"snaplink-sso"`).
- **A13/A14** — the only real proof of byte-identical boot.

**Gaps — design must be amended before implement:**
- **G5 signed introspection** — `handle_introspect.go:184` emits Host-derived `iss` in a signed artifact, uncovered. 2-line gate in the adapter (`handlers.go:35`, 488+3=491 fits) → new acceptance A17 with mode-off control pinning the signed JWT.
- **Federation entity-config** — `server_federation.go:387` → `handler.go:84` `ResolveIssuer` into a signed JWS; 1-line gate (441+1=442) → new A18.
- **A12** — fix the assertion, don't canonicalize: stamped `iss == "https://sso.test/"` (raw preserved); canonicalization would break token/discovery parity on the cmd path (signer reads raw `cfg.Server.Issuer`).
- **A15a** — must be fixture-based slog-capture (pattern exists at `config/source_test.go:236`), scoped to *no `issuer_allowlist` unknown-key warning* (version/hosted_login warnings pre-exist), +1 option-count pin; note `make config-validate-all` never loads the three deploy files.
- **Retry-After** — unpinned; recommend adopting on G2-G4 (+G5) with `Retry-After: 1` (quota.go:402 precedent), bare on public-metadata surfaces.
- **Blocking budget arithmetic** — `sso_wiring.go` 456+45=**501** and `config_load.go` 498+8=**506** both cross the 500-line gate; fix verified: `normalizeIssuer`+entry validation → `shared/core` (also closes F4's garbage-entry hole, → new A19), conditional appends → `config_server.go` method (195 lines, room). All other rows fit.
- **F3 sibling** — configcmd gate unimplemented (main.go:120, `config.Load` only); design must declare landing order and mark migration step 2 dependent.

**Verdict: FAIL** — 5 findings unmapped/incorrect as written; amendments are mechanical and fully specified in the report for the design-gate pass.
