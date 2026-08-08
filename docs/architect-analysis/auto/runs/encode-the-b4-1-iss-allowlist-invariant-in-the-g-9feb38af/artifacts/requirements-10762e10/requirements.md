Specification complete: `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-iss-allowlist-grant-scaffold-requirements.md`

## Evidence verification results (all direction citations re-checked against HEAD `65e06ebd`)

**Confirmed:**
- `templates_handler.go:144` — ghost citation `interfaces/sso/options_saml2_bearer.go` live; file verified absent (`ls` exit 2, no `*saml*` file in `interfaces/sso/`)
- `grantTemplate` `Handle` example — zero `iss`/issuer-allowlist teaching; only `h.issuerForClient(client)` (line 250, drift from cited 199 — resolves the strategy *name* + `TokenIssuer` per `server_helpers.go:37`, never the `iss` claim value) and `issuer.Issue(` (255)
- `server_discovery.go:242-263` — RFC 9207 comment + `resolveIssuer` (WithIssuer wins, `DefaultIssuer` sentinel → `requestBaseURL`); discovery parity at `server_discovery_config.go:260-266`
- `server_setup.go:271,275,283` — `saml2BearerHandler` struct/`GrantType`/`Handle`, the real production grant example
- T-8(a)/T-2/T-9 mapping, B4-1 allowlist contract (`implementation-gate.md` rows 1/3, `config-reference.md:48`), and the landed R3 assertion surface (`assertGrantScopeGateClaims` at `scaffold_contract_test.go:209`, wired from `TestGeneratedScaffoldsCompile` grant case)

**Corrections found (reported in §1):**
- `WithIssuer` lives at `interfaces/sso/options.go:349-350`, **not** `options_misc.go`
- Added the concrete "WithIssuer-backed accessor": `(*sso.Server).ResolveIssuer` at `accessors.go:374-375` — makes the acceptance testable
- The ghost citation sits in the template's **Go doc comment**, not the template body, so it never reaches generated artifacts — the corrected citation must be carried into the body (lines 158-162) to be artifact-verifiable and operator-visible (this is also the fix the committed B4-1-2 spec §7 listed but commit `7884230e` left unlanded — no overlap)

## Spec contents

- **R1** — issuer-discipline teaching in step 4: required markers `WithIssuer` / `ResolveIssuer(` / `DefaultIssuer`; banned Host-derivation shapes `requestBaseURL(` / `Request().Host` / `X-Forwarded-Host`
- **R2** — citation fix at line 144 + carried into the template body
- **R3** — named artifact assertions (T-2-mirror style) + a template-source read for the doc-comment citation, each marker a separate named failure
- **R4** — T-9 untouched
- Preserved the supplied acceptance checks verbatim as Given/When/Then (T-8(a) proxy, T-2 mirror, T-9), with budget headroom verified (278/500 and 356/500), zero server/config/CLI changes, and the full verification plan
