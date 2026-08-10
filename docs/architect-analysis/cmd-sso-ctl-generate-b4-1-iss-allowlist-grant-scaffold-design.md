# Design: encode the B4-1 iss allowlist invariant into the grant scaffold

Companion to `docs/architect-analysis/cmd-sso-ctl-generate-b4-1-iss-allowlist-grant-scaffold-requirements.md`.
This document treats that spec (and the direction it cites) as untrusted
evidence, records what was independently verified against the tree at HEAD
(`53e8d715`; the spec's evidence was taken at `65e06ebd` — only a pi-batch
stage commit differs), and turns the requirements into a concrete, ordered
design with API changes, compatibility constraints, failure modes, migration
steps, and testable acceptance mapping.

## 1. Evidence verification verdict

Every load-bearing citation was re-checked against the working tree. All
substantive claims hold; three cosmetic drifts are recorded. One design trap
the spec leaves open (banned markers are un-teachable as literals) is resolved
in §3.3 and §6.

| # | Claim | Verified at | Verdict |
|---|---|---|---|
| E1 | Ghost citation `interfaces/sso/options_saml2_bearer.go` live at `templates_handler.go:144`; file absent | Line 144 (Go doc comment above the `grantTemplate` const at 150): "registered via sso.WithCustomGrant. See interfaces/sso/options_saml2_bearer.go's saml2BearerHandler...". `ls interfaces/sso/` → no `*saml*` file; repo-wide grep: ghost path appears nowhere else in production code | Confirmed. The citation is in the *source* doc comment, outside the raw-string const, so it never reaches generated artifacts — R2's body-carry is required for operator visibility |
| E2 | `grantTemplate` Handle example has zero iss/issuer-allowlist teaching; `issuerForClient(client)` at 250, `issuer.Issue(` at 255 | grep of `templates_handler.go`: `WithIssuer`/`DefaultIssuer`/`ResolveIssuer`/`resolveIssuer` → 0 hits; `issuerForClient(client)` at 250, `issuer.Issue(` at 255. `issuerForClient` (`interfaces/sso/server_helpers.go:37`) resolves strategy name + `TokenIssuer`, not the `iss` claim value | Confirmed. The TokenIssuer is a *minting* seam; the `iss` claim value is the issuer's configured name (see E8) |
| E3 | `server_discovery.go:242-263` — RFC 9207 comment + `resolveIssuer`; discovery parity at `server_discovery_config.go:260-266` | RFC 9207 block at 224–234; `resolveIssuer` at 251–263 (`WithIssuer`-set-and-not-sentinel wins, else `requestBaseURL(ctx.Request())`); same sentinel test at `server_discovery_config.go:262-264` before `cfg.Issuer = s.issuer` | Confirmed |
| E4 | `server_setup.go:271,275,283` — `saml2BearerHandler` struct/GrantType/Handle | `type saml2BearerHandler struct` at 275, `GrantType()` at 279, `Handle(` at 283; registration via `WithSAML2BearerGrant` at 262 | Confirmed, drift: struct at 275 not 271 (4-line shift; `Handle` at 283 exact). The design therefore cites the symbol, never line numbers, in generated text |
| E5 | `WithIssuer` at `interfaces/sso/options.go:349-350`, NOT `options_misc.go` | `options.go:349-350` "WithIssuer sets the token issuer name"; `options_misc.go` contains 0 occurrences of `WithIssuer` | Confirmed — the spec's correction of the direction is itself correct |
| E6 | `(*sso.Server).ResolveIssuer` at `accessors.go:374-375` | `func (s *Server) ResolveIssuer(ctx core.HandlerContext) string { return s.resolveIssuer(ctx) }` at line 375 | Confirmed — the concrete WithIssuer-backed accessor the teaching mirrors |
| E7 | `DefaultIssuer` sentinel `"snaplink-sso"` at `shared/core/consts_oauth.go:139`, aliased at `interfaces/sso/aliases.go:179` | Exact lines verified | Confirmed |
| E8 | `iss` claim value is the operator-configured issuer, not Host-derived | `buildAccessPayload(issuer, ...)` sets `Iss:` at `infrastructure/defaultimpl/issue_payload.go:29`; each JWT issuer stamps its constructor-configured name (`WithEd25519Issuer(srv.Issuer)` at `cmd/sso-server/serverbuildsign/build_signing_issuers.go:61`, same for ECDSA/RSA) | Confirmed — the teaching's claim "the TokenIssuer stamps the operator-configured issuer into `iss`" is wire-accurate |
| E9 | R3 assertion surface: `assertGrantScopeGateClaims` at `scaffold_contract_test.go:209`, dispatch at `assertKindInvariants` 250, `TestRunExitCodes` at 310–356 (47 lines), `assertNoLegacyPathPort` 134–157 | All exact. `assertKindInvariants` has a single call site: `scaffold_build_test.go:131`; grant case `{"grant","protocols/grants","device-code"}` at `scaffold_build_test.go:108`; artifact naming `%s_grant.go` via `generatedFile` | Confirmed. Single call site makes the `root` param addition (§4) a one-line change |
| E10 | Budget headroom 278/500 and 356/500 | `wc -l`: `templates_handler.go` = 278, `scaffold_contract_test.go` = 356 (both exactly as claimed) | Confirmed; post-change estimates in §7 stay under both caps |
| E11 | Commit `7884230e` landed the scope gate but not the stale-citation fix | `git log`: `7884230e feat(sso-ctl): encode the B4-2 per-client scope gate...`; line 144 unchanged at HEAD | Confirmed — this direction is the leftover plus the iss teaching, no overlap |
| E12 | Baseline gates green | `go build ./... && go vet ./...` PASS; `go test ./cmd/sso-ctl/generate/ -run TestRunExitCodes` PASS at HEAD | Confirmed |

Net verdict: the spec's facts are accurate (three cosmetic line drifts, no
semantic defects). The one open trap — R3's banned markers cannot appear as
literals anywhere in template source or artifact, which the spec's own R1
wording ("never Host-derived", "request Host") already respects by accident —
is made an explicit design rule in §6 F1.

## 2. Design overview

`sso-ctl generate grant` is the only generator for the `oauth.GrantHandler`
extension point. Its `Handle` example today teaches the scope gate and roles
source but is silent on `iss`: the only issuer guidance is the client-scoped
`issuerForClient` accessor, which resolves the minting *strategy* and
`TokenIssuer` — never the `iss` claim value. A developer who assumes that
`issuer` is the `iss` source, or wires a Host-derived identifier, ships a
grant that violates the B4-1 allowlist contract (`iss` must be the
operator-configured identifier, never Host-derived; RFC 9207 §2 parity with
the discovery document). The scaffold also still cites a file that does not
exist (`interfaces/sso/options_saml2_bearer.go`).

The design makes three text changes to the template (one source-doc-comment
swap, one citation carried into the template body, one teaching block in the
step-4 example) and adds two test helpers with a `root` parameter threaded
through the existing dispatcher. No server, protocol, config, CLI, or
generator-mechanism change; the assertions are additive and red-first against
today's template.

## 3. Concrete changes

All three edits are in `cmd/sso-ctl/generate/templates_handler.go`. The
template is a Go raw-string const executed by `text/template`
(`generate.go:125-136`), so the added text must contain no backticks and no
`{{`/`}}` sequences, and must not trip the artifact assertions (§6).

### 3.1 Source doc comment (line 144) — R2, source half

Replace the ghost path, same surrounding prose:

```go
// sso.WithCustomGrant. See interfaces/sso/server_setup.go's
// saml2BearerHandler for the simplest real (production) example this
// template mirrors. This is deliberately NOT the built-in grant switch
```

Bare path swap: `options_saml2_bearer.go` → `server_setup.go`. Both R2 markers
(`server_setup.go`, `saml2BearerHandler`) now appear in the source; the banned
`options_saml2_bearer` is gone from the source.

### 3.2 Template body preamble (after line 161) — R2, artifact half

Carry the corrected citation into the raw string so every generated grant
names the live reference (this is what makes R2 artifact-verifiable — line 144
never reaches artifacts):

```go
// {{.Name}}GrantHandler implements oauth.GrantHandler for the
// {{.Description}} grant type. Register it once at boot:
//
//	sso.WithCustomGrant(&{{.Package}}.{{.Name}}GrantHandler{ /* deps */ })
//
// The production example this template mirrors is saml2BearerHandler at
// interfaces/sso/server_setup.go, the grant the server registers via
// sso.WithSAML2BearerGrant.
type {{.Name}}GrantHandler struct {
```

Adds the two R2 markers to the artifact; no `{{`-action hazard (the two
existing `{{...}}` actions are untouched).

### 3.3 Handle example step 4 (before `strategy, issuer, err := ...`) — R1

Insert the issuer-discipline teaching as a lead paragraph of step 4, so it
sits between the roles step (whose `h.Roles(` marker must precede
`issuer.Issue(`) and the minting example (which must keep preceding
`issuer.Issue(` — ordering constraints of `assertGrantScopeGateClaims` are
preserved; the new text contains none of its markers):

```go
// 4. Mint a token via the same path every built-in grant uses, passing
//    the VALIDATED grantedScopes (never the raw request scope string)
//    and the resolved roles. The issuerForClient accessor resolves the
//    minting strategy and the TokenIssuer; that TokenIssuer stamps the
//    operator-configured issuer into the token's iss claim (the server
//    wires it from server.issuer via sso.WithIssuer, interfaces/sso/
//    options.go) — never a request-derived value. If the grant needs the
//    issuer identifier itself (RFC 9207 iss parity with the discovery
//    document), mirror the exported accessor (*sso.Server).ResolveIssuer(ctx)
//    (interfaces/sso/accessors.go, wrapping resolveIssuer at interfaces/
//    sso/server_discovery.go): the configured WithIssuer value wins when
//    set and not the DefaultIssuer sentinel (shared/core/consts_oauth.go);
//    only the sentinel falls back to the request base URL. The B4-1
//    allowlist contract forbids Host-derived issuer values: never take
//    the iss claim from the request Host header, a proxy-forwarded Host
//    header, or the request base URL helper — iss must equal the
//    identifier the server publishes via discovery (RFC 9207 §2
//    mix-up detection).
//
//    strategy, issuer, err := h.issuerForClient(client)
```

Marker audit (each is a separate named assertion, §4):
- Required present: `WithIssuer` (twice), `ResolveIssuer(` (one line, not
  wrapped — a line break inside `ResolveIssuer(` would silently fail the
  contains-check), `DefaultIssuer`, plus `server_setup.go` /
  `saml2BearerHandler` from §3.2.
- Banned absent: `requestBaseURL(` (prose "request base URL helper" with
  spaces), `Request().Host` (prose "request Host header"), `X-Forwarded-Host`
  (prose "proxy-forwarded Host header"), `options_saml2_bearer`.

### 3.4 Test changes — R3

`cmd/sso-ctl/generate/scaffold_contract_test.go`, two new helpers beside
`assertGrantScopeGateClaims` (line 209), dispatched from the grant branch of
`assertKindInvariants` (line 250):

```go
// assertGrantIssuerDiscipline (grant kind only) pins the B4-1
// issuer-allowlist teaching in the generated artifact: the example must
// teach the configured-issuer path (WithIssuer wins, DefaultIssuer
// sentinel falls back to the request base URL, mirrored from
// (*sso.Server).ResolveIssuer) and must contain no Host-derived issuer
// expression. Each marker is asserted separately so a regression names
// the exact violated invariant (T-2-mirror style, the same blunt
// contains-checks assertNoLegacyPathPort applies to /authenticate and
// 8080 shapes).
func assertGrantIssuerDiscipline(t *testing.T, kind string, content []byte) {
	t.Helper()
	text := string(content)
	for _, m := range []struct{ name, marker string }{
		{"WithIssuer option", "WithIssuer"},
		{"ResolveIssuer accessor", "ResolveIssuer("},
		{"DefaultIssuer sentinel", "DefaultIssuer"},
		{"corrected citation target", "server_setup.go"},
		{"real production example", "saml2BearerHandler"},
	} {
		if !strings.Contains(text, m.marker) {
			t.Errorf("%s scaffold: missing %s marker %q — the B4-1 issuer-allowlist teaching was dropped", kind, m.name, m.marker)
		}
	}
	for _, m := range []struct{ name, marker string }{
		{"requestBaseURL call shape", "requestBaseURL("},
		{"request-Host derivation", "Request().Host"},
		{"proxy-forwarded Host carrier", "X-Forwarded-Host"},
		{"ghost saml2-bearer citation", "options_saml2_bearer"},
	} {
		if strings.Contains(text, m.marker) {
			t.Errorf("%s scaffold: banned %s marker %q — iss must come from the configured-issuer path, never Host-derived", kind, m.name, m.marker)
		}
	}
}

// assertGrantTemplateIssuerDiscipline applies the same required/banned
// pairs to the template SOURCE (templates_handler.go): the ghost-citation
// fix at line 144 lives in the Go doc comment above the raw-string const
// and never reaches generated artifacts, so the source read is what gates
// it. Same read pattern as pathConsts/resolveErrCode already use for
// shared/core.
func assertGrantTemplateIssuerDiscipline(t *testing.T, root string) {
	t.Helper()
	src, err := os.ReadFile(filepath.Join(root, "cmd", "sso-ctl", "generate", "templates_handler.go"))
	if err != nil {
		t.Fatalf("read templates_handler.go: %v", err)
	}
	assertGrantIssuerDiscipline(t, "template source", src)
}
```

Dispatch — `assertKindInvariants` gains a `root` parameter (single call site,
`scaffold_build_test.go:131`):

```go
func assertKindInvariants(t *testing.T, kind string, content []byte, root string) {
	t.Helper()
	switch kind {
	case "handler":
		assertFormContentTypeGuard(t, kind, content)
	case "grant":
		assertGrantScopeGateClaims(t, kind, content)
		assertGrantIssuerDiscipline(t, kind, content)
		assertGrantTemplateIssuerDiscipline(t, root)
	}
}
```

and the call site becomes `assertKindInvariants(t, tc.kind, generated, root)`
(`root` is already in scope there). The source read runs once per grant
subtest (the grant case runs once per test run), concurrently safe.

## 4. API changes

| Surface | Change |
|---|---|
| Public Go API | **None.** `WithIssuer` (options.go:349), `ResolveIssuer` (accessors.go:375), `DefaultIssuer` (consts_oauth.go:139) are referenced by the teaching text, never redefined; no new exports |
| CLI surface | **None.** No flags/subcommands; `TestRunExitCodes` untouched (R4/T-9) |
| Config / wire / storage | **None.** `server.issuer` already documented (config-reference.md:48); server-side allowlist enforcement already landed; no `Err*`, no OpenAPI rows |
| Generated-artifact surface | The scaffold's `Handle` example now teaches the `iss` source and the corrected citation. Only *newly generated* files change; already-generated files are unaffected (one-shot generator) |
| Test-internal API | `assertKindInvariants` signature gains `root string` (one call site). Two new unexported helpers in `scaffold_contract_test.go` |

## 5. Compatibility constraints

- Template mechanism unchanged: still a raw-string const + `text/template`
  execution; comment-block example + fail-closed `invalid_grant` default body
  stays the design.
- The `assertGrantScopeGateClaims` ordering invariants must survive:
  `GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, `h.Roles(` before
  `issuer.Issue(`; `grantedScopes)` present; `}, scopes)` absent;
  `Roles:\s+roles` projection intact. The step-4 insertion sits after
  `h.Roles(` and before `issuer.Issue(` and contains none of those markers
  (§3.3 marker audit), so all existing checks stay green.
- The generated artifact must still pass `go build` + `go vet` in the hermetic
  module (`GOPROXY=off`, `-mod=mod`): all additions are comment text inside
  the raw string — no compile impact.
- `interfaces/sso` 60-file ceiling, package fan-out, and directory depth
  untouched (no edits outside `cmd/sso-ctl/generate`).
- The three pre-existing assertion families (`assertRegisteredErrorCodes`,
  `assertNoLegacyPathPort`, `assertNoPathLiterals`, `assertGrantScopeGateClaims`)
  are additive-compatible: no existing marker text changes, only insertions.
- No module/profile interaction: cold-build configs and `snaplink.module.json`
  manifests are unaffected (no code compiled into or out of any server
  binary).

## 6. Failure modes

| # | Failure mode | Effect | Mitigation |
|---|---|---|---|
| F1 | **Banned-marker self-trigger**: the teaching text itself contains `requestBaseURL(`, `Request().Host`, or `X-Forwarded-Host` as literals (e.g. a "never call X" example) | The new artifact/source assertions fail on the very commit meant to fix the template — red with a self-inflicted violation, and the spec's own R3 bans make the "don't do this" literal un-teachable | Design rule: banned shapes are described in prose only ("request base URL helper", "request Host header", "proxy-forwarded Host header"). The `t.Errorf` messages may name the literals; template text may not. This is the same no-echo discipline the `}, scopes)` ban already established |
| F2 | **Wrapped marker**: `ResolveIssuer(` broken across a line in the teaching text | Silent green-pass for a marker the operator text then fails to teach verbatim (contains-check misses the split token) | §3.3 keeps `(*sso.Server).ResolveIssuer(ctx)` on one line; the design review checks the artifact byte-for-byte |
| F3 | **Backtick or `{{` injection** in added text | Raw-string const terminates early (compile break) or text/template swallows an action (silent text loss) | Added text contains neither; grep-verify ` for backticks and `{{` in the diff before commit |
| F4 | **Ordering drift**: a future edit moves the issuer teaching after `issuer.Issue(` or adds a scope-gate marker to it | `assertGrantScopeGateClaims` fires its ordering failures (named) | Existing ordering assertions already cover this; the new helpers add no ordering constraints (presence/absence only, per R3) |
| F5 | **Line-number rot in citations**: §3.1/§3.2 pin `server_setup.go` and `saml2BearerHandler` symbols, not line numbers | None — symbols are stable; line numbers drift (E4: 271→275 already) | Generated text cites symbols only; this design doc records numbers as of HEAD for verification only |
| F6 | **False positive on existing text**: some current template line contains a banned marker | New assertions would fail red against unchanged text | Pre-verified: today's template contains none of the four banned markers in the raw string; the source's only banned hit is `options_saml2_bearer` at 144 (the intended target). `ctx.Request().Context()` does not contain `Request().Host` |
| F7 | **Red-first premise miscount** | Wrong expectations in the commit message / review | Empirically counted (marker sweep, §7): today's source fires 5 named failures (required missing: `WithIssuer`, `ResolveIssuer(`, `DefaultIssuer`, `server_setup.go`; banned present: `options_saml2_bearer`; `saml2BearerHandler` already present in source), today's artifact fires 5 (all required missing, 0 banned) = 10 named failures total before the template fix |
| F8 | **`TestRunExitCodes` coupling** | T-9 regression | No CLI surface touched; the test itself is untouched and runs green at HEAD (E12) |

## 7. Migration steps

Ordered, two commits, red-first:

1. **Commit A (red) — assertions only.** Add `assertGrantIssuerDiscipline`,
   `assertGrantTemplateIssuerDiscipline`, thread `root` through
   `assertKindInvariants` and its call site. Do NOT touch
   `templates_handler.go`. Run
   `go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v`:
   the grant subtest must fail with **10 named failures** (F7 — 5 from the
   source read, 5 from the artifact) — the red proof that the gate detects
   today's state.
2. **Commit B (green) — template text.** Apply §3.1, §3.2, §3.3. Re-run the
   grant subtest: all named assertions green; re-run the full module suite.
3. **Full verification** (§9), then `make ci`.
4. **Rollback**: revert B restores prior generator output byte-exactly
   (already-generated files are never rewritten; only new scaffolds change);
   revert A restores the prior test surface. No storage, config, or wire
   migration exists at any point.

Budget accounting after B: `templates_handler.go` ≈ 278 + 19 (step 4) + 4
(preamble) = ~301 < 500; `scaffold_contract_test.go` ≈ 356 + 44 (helpers) + 2
(dispatch/signature) = ~402 < 500; both new helpers < 50 lines;
`TestRunExitCodes` untouched (47). No new files; no fan-out change.

## 8. Testable acceptance mapping

| Acceptance (requirements doc §5) | Assertion | Red→Green |
|---|---|---|
| A1: artifact contains `WithIssuer`, `ResolveIssuer(`, `DefaultIssuer` | Required-markers loop, artifact | today: 3 failures → green |
| A2: artifact contains none of `requestBaseURL(`, `Request().Host`, `X-Forwarded-Host` | Banned-markers loop, artifact | today: green (no false positives, F6) → stays green; a reintroduced shape fires a named failure |
| A3: artifact AND `templates_handler.go` contain `server_setup.go` + `saml2BearerHandler` and no `options_saml2_bearer` | Same loops on artifact + source read | today: 5 artifact + 5 source failures → green |
| A4: any future drop/reintroduce/restore of a marker fails with a named assertion | Per-marker separate `t.Errorf` in both helpers | gate property, permanent |
| A5: `TestRunExitCodes` stays green | Test untouched | green at HEAD (E12), stays green |

T-8(a) proxy mapping: the scaffold teaches the same `iss` source the wire
T-8(a) claim asserts (implementation-gate.md row 1); T-2 mirror: banned-shape
sweep in the `assertNoLegacyPathPort` style; T-9: exit codes unchanged.

## 9. Verification plan

```bash
go build ./... && go vet ./...                       # fail-fast after every edit
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v   # commit A: 9 named failures; commit B: green
go test ./cmd/sso-ctl/generate/ -run TestRunExitCodes -v                # T-9
go test ./cmd/sso-ctl/... -race
go test ./test/ -run TestE2E -v                       # unchanged server; confirm untouched
make ci
```

Pre-existing-failure note: `TestMaintainability_|TestArchitecture_` measured at HEAD
before this change: `ed25519_jwt_issuer.go` 539 lines (untouched by this change) and
root fan-out 24 > frozen 21 (campaign docs under `docs/architect-analysis/auto/runs`
— also untouched by this change). Both must be reported separately if they appear
in the final run; the change itself touches only `cmd/sso-ctl/generate` files.
