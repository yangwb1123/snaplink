All verification complete. Summary of my independent check at HEAD `fef39c18`:

**Confirmed (every load-bearing claim):**
- E1: ghost citation `options_saml2_bearer.go` live at `templates_handler.go:144`; file absent; unique in Go code. E2: zero `iss`/issuer teaching; `issuerForClient(client)` at 250, `issuer.Issue(` at 255 exact.
- E3: `resolveIssuer` at `server_discovery.go:251-263` (WithIssuer-wins/sentinel-fallback), RFC 9207 comment at 224, discovery parity at `server_discovery_config.go:264`.
- E4: `saml2BearerHandler` struct/GrantType/Handle at `server_setup.go:275/279/283`; E5: `WithIssuer` at `options.go:349-350`, zero hits in `options_misc.go`; E6: `ResolveIssuer` at `accessors.go:375`; E7: `DefaultIssuer` at `consts_oauth.go:139` + alias at `aliases.go:179`.
- E8 substance: `Iss:` stamped at `issue_payload.go:29`; `WithEd25519Issuer(srv.Issuer)` present (line 43, not 61 — cosmetic drift, no impact since generated text cites symbols only).
- E9: assertion surface exact (`assertGrantScopeGateClaims`:209, dispatch:250, `TestRunExitCodes`:310-356, `assertNoLegacyPathPort`:134); single call site `scaffold_build_test.go:131` with `root := repoRoot(t)` in scope; grant case at 108; E10 budgets 278/356 exact; E11 `7884230e` landed scope gate, line 144 untouched.
- F7 red premise: empirically 10 named failures (source: 4 required-missing + `options_saml2_bearer` banned; artifact: 5 required-missing, 0 banned). F6: no false positives. F1: proposed template text describes banned shapes in prose only; `ResolveIssuer(` on one line; no backtick/`{{` hazards; insertion sits between `h.Roles(` (240) and `issuer.Issue(` (255), preserving `assertGrantScopeGateClaims` ordering; required imports (`os`, `path/filepath`, `strings`) already present.
- Gates: `go build ./... && go vet ./...` PASS; `TestGeneratedScaffoldsCompile` (all 4 kinds) and `TestRunExitCodes` PASS; the two `TestMaintainability_|TestArchitecture_` failures (ed25519_jwt_issuer.go 539 lines, root fan-out 24>21) are pre-existing, correctly characterized in design §9, and untouched by this change.
- No API/CLI/config/wire changes; confined to `cmd/sso-ctl/generate`; R4/T-9 preserved.

Non-blocking drifts found: E8's line citation (61→43) and the requirement doc's `server_setup.go` line numbers (271/275 vs actual 275/279) — both cosmetic, already corrected by the design (E4), and the design's symbols-not-line-numbers rule for generated text is sound.

VERDICT: PASS - all blocking review findings are resolved with verified evidence: the ghost-citation fix, configured-issuer teaching, named-marker assertion design, and red-first migration are all grounded in exact, re-checked tree state, with the banned-literal self-trigger trap (F1) explicitly designed around and baseline gates measured green.
