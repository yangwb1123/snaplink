# Requirements Spec: encode the B4-1 iss allowlist invariant into the grant scaffold

- Direction: entry 2 of `docs/architect-analysis/auto/analyses/cmd-sso-ctl-generate-3176af89.json` (selected)
- Module: `cmd/sso-ctl/generate` (`grantTemplate` in `templates_handler.go`, contract assertions in `scaffold_contract_test.go`)
- Status: requirements (evidence-verified against HEAD `65e06ebd`)

## 1. Evidence verification

Every citation in the direction was re-checked against the repository. Verdicts:

| Citation | Measured reality | Verdict |
|---|---|---|
| `cmd/sso-ctl/generate/templates_handler.go:144` — stale citation "interfaces/sso/options_saml2_bearer.go" | Line 144 (inside the `grantTemplate` doc comment, lines 139–149, above the const at 150): "registered via sso.WithCustomGrant. See interfaces/sso/options_saml2_bearer.go's saml2BearerHandler for the simplest real (production) example this template mirrors." `ls interfaces/sso/options_saml2_bearer.go` fails (exit 2); no `*saml*` file exists in `interfaces/sso/`. Repo-wide grep: the ghost path appears nowhere else in production code (only this line + two docs) | Confirmed (ghost file verified absent; citation is in the template's Go doc comment, NOT embedded in generated artifacts — the corrected citation must be carried into the template body to reach operators) |
| grantTemplate `Handle` example: no iss/issuer-allowlist teaching; `issuerForClient` accessor example is client-scoped only | The only issuer references in the template body are (a) the deps comment at lines 163–175 suggesting "a func(client *core.Client) (string, core.TokenIssuer, error) accessor to mint tokens", (b) step 4 at lines 246–258: `strategy, issuer, err := h.issuerForClient(client)` (line 250) then `issuer.Issue(...)` (line 255). Zero occurrences of `WithIssuer`, `DefaultIssuer`, `ResolveIssuer`, `resolveIssuer`, or any `iss` claim teaching. `issuerForClient` (interfaces/sso/server_helpers.go:37) resolves the strategy NAME + TokenIssuer (tenant mapping → client strategy → default), not the `iss` claim value — client-scoped only, as claimed. Line drift: direction said line 199; current tree has it at 250 (template grew when the B4-2/B4-1 scope-gate spec landed) | Confirmed (with drift: 199 → 250) |
| `interfaces/sso/server_discovery.go:242-263` — `resolveIssuer` (configured WithIssuer wins, DefaultIssuer sentinel falls back to request base URL) | Comment lines 242–250 (RFC 9207 §2 parity with `oidc.ProviderMetadata.Issuer`); `func (s *Server) resolveIssuer` at 251–263: `if s.issuer != "" && s.issuer != DefaultIssuer { return s.issuer }; return requestBaseURL(ctx.Request())`. Discovery-metadata parity at `server_discovery_config.go:260-266` (same sentinel test before `cfg.Issuer = s.issuer`). Used by every authorization response (`authzErrorBody`, `server_finish_login.go:191`, `server_oauth.go:468/481`) and bearer challenges | Confirmed (exact lines) |
| `interfaces/sso/server_setup.go:271,275,283` — `saml2BearerHandler` (real production grant example) | `type saml2BearerHandler struct` at 271; `GrantType()` at 275; `Handle(...)` at 283. Registered as an `oauth.GrantHandler` via `WithSAML2BearerGrant` (lines 260–269), which delegates to `tokengrant.HandleSAML2BearerGrant` — the real production custom-grant example the scaffold should cite | Confirmed (exact lines) |
| `interfaces/sso/options_misc.go` — `WithIssuer` option | **Correction**: `WithIssuer` is at `interfaces/sso/options.go:349-350` ("WithIssuer sets the token issuer name"), NOT `options_misc.go` — grep of `options_misc.go` finds no `WithIssuer` (the file's issuer-adjacent content is `WithScopeRegistry` and tenant-bucket allowlists, unrelated). The `DefaultIssuer` sentinel is `"snaplink-sso"` at `shared/core/consts_oauth.go:139`, aliased at `interfaces/sso/aliases.go:179` | Citation corrected (options.go:349-350) |
| Canonical accessor for the configured-issuer path | **Added** (the direction implied it; it makes the acceptance testable): `(*sso.Server).ResolveIssuer(ctx core.HandlerContext) string` at `interfaces/sso/accessors.go:374-375` — the exported wrapper over `resolveIssuer`, i.e. the WithIssuer-backed accessor a custom grant's deps can mirror. Also `(*sso.Server).Issuer()` at accessors.go:130 (raw configured value, may be the sentinel) | Confirmed (this is the "WithIssuer-backed accessor" the acceptance requires) |
| B4-1 iss allowlist contract ("iss must come from the configured allowlist, never Host-derived") | `docs/campaigns/implementation-gate.md` rows 1 and 3: "iss 配置化（allowlist，禁 Host 派生；resolveIssuer server_discovery.go:251 + WithIssuer 覆盖）"; `docs/config-reference.md:48`: "server.issuer — MUST differ from sso.DefaultIssuer; stamped into JWT iss, discovery issuer, every RFC 9207 iss" | Confirmed (campaign contract, server-side enforcement already landed) |
| T-8(a) / T-2 / T-9 mapping | T-8(a) = `POST /token` → 200 + claims `{iss/aud/scope/client_id/tenant_id/roles}` (implementation-gate.md row 1) — generated-code inspection is the scaffold-compliance proxy. T-2 = discovery truthiness sweep; the module already applies the same blunt named-contains style to `/authenticate` and `8080` shapes via `assertNoLegacyPathPort` (scaffold_contract_test.go:134-157) — the model for banning Host-derived issuer shapes. T-9 = `TestRunExitCodes` (scaffold_contract_test.go:310-356) | Confirmed |
| Assertion surface for the new gate | Direction #1 landed at commit `7884230e` (scope gate + claims teaching): `assertGrantScopeGateClaims` (scaffold_contract_test.go:209-247) is the R3 block, dispatched from `assertKindInvariants` (250-259) inside `TestGeneratedScaffoldsCompile` (scaffold_build_test.go:97-141; grant case `{"grant", "protocols/grants", "device-code"}` at line 108). Assertions run on the generated artifact, which embeds the template body verbatim | Confirmed (the new assertion hooks in beside it) |
| The committed spec's stale-citation fix was never applied | `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-2-grant-scaffold-requirements.md` §7 already listed "fix the stale template doc citation ... → interfaces/sso/server_setup.go (saml2BearerHandler)", but the landed commit `7884230e` did not touch line 144 — the ghost citation is still live at HEAD. This direction is precisely that leftover plus the iss teaching | Confirmed (no overlap with landed work) |

Net: the direction's core claims all hold. One citation correction (`WithIssuer` lives at `options.go:349-350`, not `options_misc.go`) and one precision fix (`ResolveIssuer` at `accessors.go:374-375` is the concrete WithIssuer-backed accessor the generated artifact can reference; the ghost citation sits in the template's Go doc comment, so the corrected citation must be carried into the template body to be artifact-verifiable and operator-visible).

## 2. Goal and user outcome

`sso-ctl generate grant` produces the only scaffold for the `oauth.GrantHandler` extension point. Its `Handle` example now teaches the per-client scope gate and roles source (landed), but says nothing about where `iss` comes from: the only issuer guidance is a client-scoped `issuerForClient` accessor that resolves the minting *strategy*, never the `iss` claim value. A developer wiring the scaffolded accessor to a request-Host-derived issuer would ship a grant whose `iss` violates the B4-1 allowlist contract (`iss` must come from the operator-configured `WithIssuer` value, `DefaultIssuer` sentinel fallback, never Host-derived) and breaks RFC 9207 issuer-identification parity with the discovery document. The scaffold also still cites `interfaces/sso/options_saml2_bearer.go` — a file that does not exist in the tree — instead of the real production example `saml2BearerHandler` at `interfaces/sso/server_setup.go:271,283`.

Completion marker: a developer who runs `sso-ctl generate grant --name x --package protocols/grants` gets a `Handle` example whose accessor resolves the issuer through the configured-issuer path — the `(*sso.Server).ResolveIssuer` discipline (operator `WithIssuer` wins, `DefaultIssuer` sentinel falls back to the request base URL, per `interfaces/sso/server_discovery.go:242-263`) — with no Host-derived issuer expression anywhere in the artifact, and a doc comment pointing at the real `saml2BearerHandler` in `server_setup.go`. `TestGeneratedScaffoldsCompile` fails with a named assertion if any of that regresses, and `TestRunExitCodes` stays green.

## 3. Product boundary

- Surface: `cmd/sso-ctl/generate` (grant template text + contract assertions). No server, protocol, config, or CLI changes.
- Default: template text change alters the output of the existing `grant` kind; test assertions run in the existing suite.
- Explicit non-goals (do not implement):
  - No change to `interfaces/sso/server_discovery.go`, `server_discovery_config.go`, `options.go`, `options_misc.go`, or `accessors.go` — `resolveIssuer`/`ResolveIssuer`/`WithIssuer`/`DefaultIssuer` are landed server surface; the scaffold only teaches them. (`options_misc.go` is named here precisely because the direction's evidence mislocated `WithIssuer` there — no edit is made to either options file.)
  - No change to the issuer-allowlist server enforcement (campaign B4-1 server work is landed; this is the scaffold-compliance axis only).
  - No new CLI flags, subcommands, generated file kinds, or exit-code changes (`TestRunExitCodes` untouched).
  - No change to the other scaffold kinds (`authenticator`/`store`/`handler`) or to `templates.go`.
  - No change to the template mechanism (comment-block example + fail-closed `invalid_grant` default body stays the design).
  - The B4-2 scope gate / roles teaching already landed at commit `7884230e` is not re-touched except where this direction's issuer teaching extends the same step-4 comment block.

## 4. Module classification

- [x] Infrastructure/config/deployment (scaffolding tooling)
- [ ] OAuth/OIDC protocol flow · [ ] Store · [ ] Admin endpoint · [ ] Authenticator · [ ] Audit · [ ] Authorization · [ ] Cold module · [ ] Refactoring only

Owning layer/package: `cmd/sso-ctl/generate` (composition layer, owns templates + their regression gate). No import-graph change: the template's example text references `(*sso.Server).ResolveIssuer`, `WithIssuer`, and `DefaultIssuer` in comments only (the generated scaffold's own imports are unchanged); the test reads `templates_handler.go` as a source file, the same pattern `resolveErrCode`/`pathConsts` already use for `shared/core`.

## 5. Requirements

### R1 — grantTemplate teaches issuer resolution through the configured-issuer path (never request-Host derivation)

The `Handle` example's accessor teaching (step 4, currently lines 246–258 of `templates_handler.go`) must explain where the `iss` claim value comes from, mirroring `resolveIssuer` (`interfaces/sso/server_discovery.go:251-263`):

- The minting accessor's job is to resolve the strategy AND the issuer identifier through the configured-issuer path: the operator-configured `WithIssuer` value wins when set and not the `DefaultIssuer` sentinel; only the sentinel falls back to the request base URL.
- The accessor example must mirror `(*sso.Server).ResolveIssuer(ctx)` (`interfaces/sso/accessors.go:374-375`) — the exported WithIssuer-backed accessor — and reference `WithIssuer` (`interfaces/sso/options.go:349-350`) and the `DefaultIssuer` sentinel (`shared/core/consts_oauth.go:139`, aliased at `interfaces/sso/aliases.go:179`) by name.
- The example must state, in the same breath, that the `iss` value is never derived from the request Host / `X-Forwarded-Host` / `requestBaseURL` — the B4-1 allowlist contract (docs/campaigns/implementation-gate.md rows 1/3; docs/config-reference.md:48).

Placement freedom: the teaching may extend the step-4 comment block and/or the deps-interface comment (lines 163–175); the gate is the markers below, not the exact wording.

### R2 — stale saml2-bearer citation replaced with the real symbol, operator-visible

- The ghost citation at `templates_handler.go:144` (`interfaces/sso/options_saml2_bearer.go`) must be replaced with the real production example: `saml2BearerHandler` at `interfaces/sso/server_setup.go` (struct at 271, `Handle` at 283).
- Because line 144 sits in the template's Go doc comment and is NOT embedded in generated artifacts, the corrected citation must also be carried into the template body's doc comment (the `{{.Name}}GrantHandler` preamble at lines 158–162, immediately above the struct at 163) so every generated grant names the live reference — this is what makes the fix artifact-verifiable and operator-visible, matching the module's artifact-assertion philosophy.
- The string `options_saml2_bearer` must not appear anywhere in `templates_handler.go` (source) or in the generated grant artifact.

### R3 — named contract assertions lock the discipline in the grant subtest

In `scaffold_contract_test.go`, add a new grant-kind assertion helper (sibling of `assertGrantScopeGateClaims` at line 209) and dispatch it from the grant branch of `assertKindInvariants` (line 250). Style: exactly like the existing R3 block — each marker asserted separately with a named `t.Errorf` so a regression names the violated invariant; blunt contains-checks on the generated artifact, mirroring the discovery-truthiness sweep `assertNoLegacyPathPort` applies to `/authenticate` and `8080` shapes (T-2 mirror).

Required markers (each separately named):

1. `WithIssuer` — the operator-configured option the discipline is anchored on.
2. `ResolveIssuer(` — the WithIssuer-backed accessor call shape (interfaces/sso/accessors.go:374), as it appears in the accessor example.
3. `DefaultIssuer` — the sentinel that must be named for the fallback rule to be complete.
4. `server_setup.go` — the corrected citation target.
5. `saml2BearerHandler` — the real production grant example symbol.

Banned markers (each separately named; T-8(a) proxy for "no Host-derived issuer"):

1. `requestBaseURL(` — the Host-derived fallback call shape; a grant that constructs its issuer from it violates the allowlist contract. (Prose like "request base URL" with spaces is allowed — the ban is the code shape, so the sentinel-fallback explanation stays expressible.)
2. `Request().Host` — the request-Host derivation expression on `core.HandlerContext`.
3. `X-Forwarded-Host` — the proxy-header derivation carrier.
4. `options_saml2_bearer` — the ghost citation, in any form (with or without `.go`).

A template-source assertion (same style, reading `cmd/sso-ctl/generate/templates_handler.go`) additionally enforces the same required/banned pairs on the source, so the doc-comment citation at line 144 is gated even though it never reaches artifacts.

Assertions run on the generated artifact (`generatedFile("grant", "device-code", outputDir)` → `device-code_grant.go`, as already wired in `TestGeneratedScaffoldsCompile`), which embeds the template body verbatim — a regression in teaching content is a regression in what operators receive. The compile gate (`go build ./...` + `go vet ./...` in the isolated module) stays.

### R4 — no CLI/exit-code surface change

No flags, subcommands, or exit codes change. `TestRunExitCodes` (scaffold_contract_test.go:310-356) stays green — T-9.

### Testable acceptance (Given/When/Then)

1. Given `sso-ctl generate grant --name device-code --package protocols/grants` (the existing test path), when the generated artifact is inspected, then it contains `WithIssuer`, `ResolveIssuer(`, and `DefaultIssuer` — the configured-issuer path teaching (T-8(a) proxy: the scaffold teaches the same `iss` source the wire-level T-8(a) `iss` claim asserts).
2. Given the same artifact, when inspected for Host-derived issuer expressions, then it contains none of `requestBaseURL(`, `Request().Host`, `X-Forwarded-Host` — each banned shape a separate named assertion, in the style of the `/authenticate` + `8080` sweep (T-2 mirror).
3. Given the corrected citation, when the generated artifact AND `templates_handler.go` are inspected, then neither contains `options_saml2_bearer`, and both contain `server_setup.go` and `saml2BearerHandler` (the real symbol at server_setup.go:271/283).
4. Given any future template edit that drops a required marker, reintroduces a banned shape, or restores the ghost citation, when `TestGeneratedScaffoldsCompile` runs, then the grant subtest fails with a named assertion identifying the exact invariant (each marker asserted separately).
5. Given the unchanged CLI surface, when `TestRunExitCodes` runs, then all cases stay green (T-9: no flag/exit-code change).

## 6. Engineering-gate constraints (verified)

- Budgets: `templates_handler.go` is 278 lines / 500 cap (the step-4 block grows ~15-20 comment lines; the struct preamble gains one citation line) — safe. `scaffold_contract_test.go` is 356 lines / 500 cap (new helper ~35 lines + one dispatch line) — safe. The new helper must stay ≤50 lines (factor per-marker checks as a small loop over named pairs, as `assertGrantScopeGateClaims` already does). `TestRunExitCodes` is 47 lines and untouched. No new files in the module, no directory/fan-out change.
- `interfaces/sso` 60-file ceiling untouched (no edits there).
- No `Err*` additions, no OpenAPI/config/error-code changes (`iss` is not an error code; `resolveIssuer`/`WithIssuer`/`DefaultIssuer` are referenced, not redefined).

## 7. Files

### Create

```text
(none — both changes are modifications; this spec document itself is the only addition)
```

### Modify

```text
cmd/sso-ctl/generate/templates_handler.go
    — line 144: replace "interfaces/sso/options_saml2_bearer.go" with
      "interfaces/sso/server_setup.go" (saml2BearerHandler, the real
      production example at server_setup.go:271/283) (R2);
    — template body {{.Name}}GrantHandler doc comment (lines 158-162):
      carry the corrected citation so generated artifacts name the live
      reference (R2);
    — Handle example step 4 / deps comment (lines 163-175, 246-258):
      add the issuer-discipline teaching — WithIssuer wins, DefaultIssuer
      sentinel falls back to the request base URL, mirror the
      (*sso.Server).ResolveIssuer accessor (accessors.go:374-375), never
      derive iss from request Host / X-Forwarded-Host / requestBaseURL (R1).
cmd/sso-ctl/generate/scaffold_contract_test.go
    — new grant-kind helper next to assertGrantScopeGateClaims (line 209),
      dispatched from assertKindInvariants' grant branch (line 250):
      required markers WithIssuer / ResolveIssuer( / DefaultIssuer /
      server_setup.go / saml2BearerHandler; banned markers requestBaseURL( /
      Request().Host / X-Forwarded-Host / options_saml2_bearer; plus the
      template-source read of templates_handler.go for the same pairs (R3).
```

### Do not modify

```text
interfaces/sso/server_discovery.go, server_discovery_config.go,
accessors.go, options.go, options_misc.go — landed server surface the
scaffold teaches (resolveIssuer at server_discovery.go:251-263, ResolveIssuer
at accessors.go:374-375, WithIssuer at options.go:349-350).
interfaces/sso/server_setup.go — the cited example lives here; it is not
edited.
protocols/oauth/*, infrastructure/defaultimpl/*, shared/core/* — untouched.
cmd/sso-ctl/generate/verify.go, templates.go, cmd.go, generate.go — untouched.
docs/error-codes.md, docs/config-reference.md, docs/openapi.yaml — no new
surface.
```

## 8. Dependencies and compatibility

- New/changed SPI: none (template + test only; the referenced symbols `WithIssuer`, `ResolveIssuer`, `DefaultIssuer` already exist and are exported).
- New option/store wiring: none. New YAML/env keys: none. Storage migration: none.
- HTTP/proto compatibility: none (no server change; `iss` enforcement at the wire is already landed server-side).
- Rollout/rollback: pure generator + test change; `sso-ctl generate grant` output text changes for new scaffolds only — already-generated files are unaffected. Reverting the template restores prior output exactly; the test then fails (the gate's job).

## 9. Documentation

- [ ] `docs/openapi.yaml` — not applicable (no server endpoint).
- [ ] `docs/error-codes.md` — not applicable (no new error; `invalid_grant`/`invalid_scope` already registered).
- [ ] `docs/config-reference.md` — not applicable (no config knob; `server.issuer` already documented at line 48).
- [x] Campaign traceability: this advances implementation-gate.md row 1 (T-8(a) `iss` claim) on the scaffold-compliance axis — the generated grant teaches the configured-issuer source that wire-level T-8(a) asserts; the stale-citation fix closes the dead-reference gap the B4-1-2 spec §7 left unlanded at commit `7884230e`.

## 10. Verification plan

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v
go test ./cmd/sso-ctl/... -race
make ci
```

Pre-change expectation: `TestGeneratedScaffoldsCompile` grant subtest currently passes (no iss markers asserted yet); after this change it must still pass with the new markers satisfied, and the three pre-existing assertion families (`assertRegisteredErrorCodes`, `assertNoLegacyPathPort`, `assertNoPathLiterals`, `assertGrantScopeGateClaims`) must remain green — the new assertions are additive, not substitutive.
