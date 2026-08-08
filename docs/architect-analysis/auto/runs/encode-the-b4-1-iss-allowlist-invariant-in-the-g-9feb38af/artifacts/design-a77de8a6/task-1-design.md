Design complete. Summary of the work:

## Evidence verification (all claims re-checked at HEAD `53e8d715`)

**All substantive claims confirmed**, with three cosmetic drifts:
- E1–E2: ghost citation at `templates_handler.go:144` confirmed (file absent; citation lives in the source doc comment, *outside* the raw-string const, so it never reaches artifacts — R2's body-carry is required); zero `iss` teaching; `issuerForClient(client)` at 250, `issuer.Issue(` at 255 exact
- E3: `resolveIssuer` at `server_discovery.go:251-263` with RFC 9207 comment; discovery parity at `server_discovery_config.go:262-264`
- E4: `saml2BearerHandler` at `server_setup.go:275/279/283` (4-line drift from cited 271 — the design cites symbols, never line numbers)
- E5–E7: `WithIssuer` at `options.go:349-350` (0 hits in `options_misc.go` — the spec's correction of the direction holds), `ResolveIssuer` at `accessors.go:375`, `DefaultIssuer = "snaplink-sso"` at `consts_oauth.go:139`
- E8 (new, design-critical): the `iss` claim value is wire-verified as the TokenIssuer's constructor-configured name (`buildAccessPayload` → `Iss:` at `issue_payload.go:29`; `WithEd25519Issuer(srv.Issuer)` at `build_signing_issuers.go:61`) — the teaching text is technically accurate
- E9–E12: assertion surface (`assertGrantScopeGateClaims`:209, dispatch:250, `TestRunExitCodes`:310-356, single call site at `scaffold_build_test.go:131`), budgets 278/356 exact, `7884230e` left line 144 unfixed, baseline gates green (generate pkg passes; the two `TestMaintainability_` failures are pre-existing and measured)

## Design (`docs/architect-analysis/cmd-sso-ctl-generate-b4-1-iss-allowlist-grant-scaffold-design.md`)

- **API changes**: none public; two unexported test helpers + `root` param threaded through `assertKindInvariants` (one call site); generated-artifact teaching text changes only
- **Concrete text**: line-144 path swap; citation carried into the template body preamble (artifact-visible); step-4 teaching block with exact marker audit
- **Key trap resolved (F1)**: R3's banned markers (`requestBaseURL(`, `Request().Host`, `X-Forwarded-Host`) cannot appear as literals *anywhere* in template text — not even in "don't do this" examples — so the teaching describes them in prose; `ResolveIssuer(` must stay on one line or the contains-check silently misses it (F2)
- **Failure modes**: 8 enumerated (self-trigger, wrapped marker, backtick/`{{` hazard, ordering drift, line-number rot, false positives, red-premise miscount, T-9 coupling), each with mitigation
- **Migration**: two commits, red-first. Empirically measured red premise: **10 named failures** against today's template (5 source: 4 required-missing + `options_saml2_bearer` banned; 5 artifact: all required missing, 0 banned) — corrected from my initial 9 after the marker sweep
- **Acceptance mapping**: all 5 Given/When/Then cases mapped to concrete loops/assertions with red→green transitions; verification plan includes the measured pre-existing gate failures
