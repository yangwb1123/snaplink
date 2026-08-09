All verification complete. Summary of my independent findings:

**Blocking findings — all resolved or verified non-blocking:**

1. **Status-code split** (plain `core.ErrorBody` 415 vs trace-aware 400): Resolved — Rev 3 §3.3 pins and justifies the plain envelope, D1 test-pins exact bytes; hardening artifact documents it. The asymmetry is deliberate, deterministic, and non-oracle.
2. **415-vs-401 on introspect/par**: Resolved by retention-with-justification — parse-before-auth is explicitly pinned in §3.3; T-9 gate preserved via unmodified `TestIntrospect_RejectsMissingCreds/WrongSecret/AcceptsBasicAuth`.
3. **Device-grant scoping misread**: Resolved — §3.1 enumerates device/CIBA exchanges inside the flip; §3.4 names the four dedicated endpoints as NOT flipped.
4. **Config hot-reload precision** (migration reviewer): Resolved — I verified the landed `docs/config-reference.md:42` row states "Boot-time only, no hot-reload; rollback = drop the key or set false".
5. **Docs contract items**: All 5 landed and validated — openapi 415 description notes on all four paths (no response blocks added), config-reference row, error-codes 415 note, CHANGELOG bullet; `make docs-validate` passes (check-routes + capabilities PASS).

**The one carried-forward item** — "44 dual-mode sites" phrasing (§3.4): My precise enumeration: 46 total dual-mode sites (40 direct `BindParams` + 6 `bindOAuthParams`), 42 outside the four. The number is numerically loose, but the substantive claim (nothing outside the four sites changes) is fully verified: the Modify list touches exactly `server_token.go:30`, `handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`, and `bind.go`'s JSON default is untouched. Both raising reviewers classified it non-blocking/zero-risk; it does not affect design correctness.

**Key facts I re-verified directly**: bind.go:28-46 dispatch (form :38-42, JSON default :43-46); four bind sites with no-store stamped before parse (:22/:113/:69/:55); PKCE constant-time compares :83/:85; Deps interfaces at :29/:18/:16 with compile-time-asserted fakes at test lines :78/:38/:58; interfaces/sso exactly 60 non-test files, oauthwire 6→7; zero strict-mode symbols in Go repo-wide (mechanism unlanded); provisioner `platform_token.go:151-162` form + CT at :162; entry 3 of analysis JSON with opt-in wording; T-8(a-e) verbatim + 20 cases in requirements Rev 2 matching design §3.7; `go build ./...` clean.

VERDICT: PASS - All blocking findings are resolved with evidence (oracle-safe 415 envelope pinned by D1-D6, docs landed and validated, 20/20 acceptance mapping intact, migration/rollback verified against real trees); the only unaddressed item is the numerically loose "44 sites" phrase, which every reviewer independently classified as non-blocking and substance-correct.
