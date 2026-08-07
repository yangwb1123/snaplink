# B4 grant-scaffold design — encode token-claims + scope-registry invariants into the generated grant scaffold

This revision replaces the bare 26-line summary committed at `4d93b696` with
the full design body: D1–D6 decision texts, the exact final template text
(§4), the complete named-marker helper (§5), the marker simulation re-run
against that final text (§6), the FM-1..FM-8 table with a hardened detection
column (§8), the migration sequence and rollback (§9), and the acceptance
mapping (§10). Every hardening requirement from both adversarial reviews
(`test_strategy_reviewer`, `scaffold_teaching_reviewer` — see §12) is folded
in, so the implement stage consumes a self-contained, review-satisfied design
instead of a summary plus a requirements spec.

The two evidence corrections from the requirements stage were re-verified at
HEAD `fc8ec2c7` and shape the design: (a) B4-2 has LANDED — the scaffold's
registry obligation is to teach the existing seam (`rejectUnregisteredScopes`
→ `scoperegistry.RejectUnregistered`), not to propose a registry; (b) the
template doc comment's `interfaces/sso/options_saml2_bearer.go` citation is
stale (file nonexistent; real handler `interfaces/sso/server_setup.go:271,283`)
and is fixed as part of the template edit (D5).

## 1. Behavior baseline and change surface

- **Surface**: `cmd/sso-ctl/generate` only — `templates_handler.go`
  (`grantTemplate`) and `scaffold_build_test.go`
  (`TestGeneratedScaffoldsCompile`). No server, protocol, store, config, or
  wire change; no new CLI surface; the other three scaffold kinds
  (`authenticator`/`store`/`handler`) are untouched.
- **Baseline teaching gap**: the current `Handle` example (lines 174–215)
  forwards request scopes into `issuer.Issue` with no `GrantedScopes`
  allowlist branch, no 400 `invalid_scope` path, and no roles-source
  reference — every generated custom grant ships the violating pattern. The
  dispatch seam covers only scope-name registration for request-borne
  scopes; the per-client `AllowedScopes` gate is exactly what custom-grant
  handlers must apply themselves.
- **Mechanism unchanged**: the example stays a comment block inside the TODO
  (D1); the generated `Handle` keeps its fail-closed `invalid_grant` default
  body; the compile gate (`go build ./...` in an isolated temp module) stays
  the mechanical backstop. The change is generated *text* for new scaffolds
  only; already-generated files are unaffected.
- **Verification surface**: the existing compile-only gate gains content
  assertions on the generated artifact (`device-code_grant.go`), which
  includes the template's comment text verbatim — so a template regression
  fails the gate exactly as the direction requires.

## 2. Verified code map (HEAD `fc8ec2c7`)

Every anchor the design teaches or pins, with measured reality:

| Anchor | Measured reality |
|---|---|
| `grantTemplate` example block | `templates_handler.go:139` const; `Handle` example at 174–215; `Handle`'s fail-closed default at 213–214 |
| Precedent branch (CIBA) | `protocols/oauth/handle_ciba.go:300` `persistCIBARequest`; `GrantedScopes(SplitScope(req.Scope), client)` at 306; plain `core.ErrorBody(core.ErrInvalidScope)` + 400 at 307–308 (oracle-safe, no trace_id) |
| Precedent branch (client credentials) | `internal/handler/tokengrant/token_client_credentials.go:34–40` — `oauth.GrantedScopes` at 38, 400 at 39–40, post-auth placement comment; same pattern at `handle_par.go:197–200` (scope-count branch, not :198 — range cited) and `token_saml2_bearer.go:108–109` via `authorizeSAML2Scopes` (:96) |
| Dispatch-level registry seam | `interfaces/sso/server_token.go:132` call inside `dispatchTokenGrant` (119–146), before `denyTokenScopeCombo` and `dispatchCustomGrant` (:383, drifted 345→383); `rejectUnregisteredScopes` at 203–204 delegates to `scoperegistry.RejectUnregistered` (`protocols/oauth/scoperegistry/reject.go:31–40`); seam gates request-borne scopes only, plain `core.ErrorBody` body (never `errorBody` — byte-compat baseline, see reject.go doc + seam doc) |
| Registry wiring | `WithScopeRegistry` (`interfaces/sso/options_misc.go:482–495`), accessor `ScopeRegistry()` (`accessors_handlers.go:163–166`), config `oauth.scope_registry.{enabled,matrix,extra_scopes}` (config-reference.md:20); error surface registered at error-codes.md:298 |
| Roles source | `domains/permissions/provider.go:38` `Provider.Roles(ctx, userID, clientID)`; used at `interfaces/sso/accessors_handlers.go:103` (`s.permissions.Roles`) and mesh_authz.go:326 |
| Subject / issuance | `shared/core/types_token.go:161–165` `Subject` (`Claims map[string]string` at 164 — emitted as `ext` via `Extra: subject.Claims`, `infrastructure/defaultimpl/issue_payload.go:34`; NOT the T-8(a) `roles` claim); `TenantID` at types_token.go:231 (policy-input only, not a token claim today); `TokenIssuer.Issue(ctx, *Subject, []string)` at `shared/core/spi.go:245–249` |
| Claims gap (B4-1 territory) | `buildAccessPayload` (`issue_payload.go:26`) and `ed25519Payload` (`ed25519_types.go:15`) emit neither `tenant_id` nor `roles` — the scaffold references the roles source but defers the handoff shape (F7, §3 D2) |
| Errors / aliases | `core.ErrInvalidScope = "invalid_scope"` (`shared/core/errors.go:170`); `GrantedScopes`/`SplitScope` exported via `protocols/oauth/aliases.go:119–120` (`oauthvalidate/scope.go:80`, `:27`); `GrantedScopes` semantics: allowlist gate rules 1–4, `ErrScopeNotAllowed`, caller maps to 400 invalid_scope |
| Custom-grant extension point | `oauth.GrantHandler` (`protocols/oauth/grant_handler.go:14`); `WithCustomGrant` (`interfaces/sso/options_grants.go:75`); real handler `saml2BearerHandler` registered at `server_setup.go:271`, `Handle` at 283 (the template doc comment cites the nonexistent `options_saml2_bearer.go` — D5 fixes it) |
| Test gate today | `scaffold_build_test.go` (122 lines): `TestGeneratedScaffoldsCompile` (37 lines) generates each kind into an isolated temp module (`newBuildableModule`) and runs bare `go build ./...`; grant case `{"grant", "protocols/grants", "device-code"}` → `gen/protocols/grants/device-code_grant.go` (filename rule `generate.go:82`, raw `s.Name`) |
| Campaign mapping | `docs/campaigns/implementation-gate.md` rows 1–2: T-8(a) = `/token` → 200 + claims `{iss/aud/scope/client_id/tenant_id/roles}`; T-8(d) = scope registry full matrix, unregistered → 400 `invalid_scope`. Generated-code inspection is the scaffold-compliance proxy for both; wire-level tests remain B4-1/B4-2 server deliverables |

## 3. Design decisions D1–D6

**D1 — Teaching artifact stays a comment block (ALT-1 rejected).**
The example is comment text inside the TODO block; the generated `Handle`
keeps its fail-closed `invalid_grant` default body. ALT-1 (real active
example code) was rejected: it would change generated behavior, turn every
new scaffold into an executing grant (issuer resolution, store access) the
author has not vetted, and move the default from "safe failure" to
"half-wired success path". Comment-only keeps new scaffolds safe by default
and makes the teaching text the object the gate pins. The compile gate stays
the mechanical backstop.

**D2 — Example restructured into 4 ordered steps (gate → roles → issuance).**
The current 2-step shape ("validate params" → "mint token") becomes:

1. Validate grant-specific parameters (unchanged).
2. **Scope gate**: `oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)`
   → 400 plain `core.ErrorBody(core.ErrInvalidScope)` — byte-faithful to
   `handle_ciba.go:306–308` / `token_client_credentials.go:38–40` — followed
   by the registry-seam note (D3).
3. **Roles resolution**: `deps.Roles(ctx, resourceOwnerID, client.ID)`
   mirroring `permissions.Provider.Roles`, with an explicit B4-1 deferral
   comment (F7): the exact handoff into the Subject is pinned when the
   `tenant_id`/`roles` claims land in `buildAccessPayload`; `Subject.Claims`
   today is `map[string]string` emitted as `ext`, so showing a Claims-map
   handoff would mis-teach the T-8(a) `roles` claim.
4. **Issuance**: `issuer.Issue(ctx, &core.Subject{ID, ClientID,
   TenantID: client.TenantID}, grantedScopes)` — passing the GRANTED set,
   never raw `req.Scope` (D6).

Step order is load-bearing: A1 and A3 pin "gate and roles precede issuance",
so the step numbering IS the teaching order.

**D3 — Registry-seam note text (exact wording in §4).**
Placed immediately after the gate branch in step 2. Requirements R1's
content is carried: the dispatch seam (`rejectUnregisteredScopes` →
`scoperegistry.RejectUnregistered`, wired via `WithScopeRegistry` /
`oauth.scope_registry.enabled`) already rejects UNREGISTERED request-borne
scopes before custom handlers run; internally minted scopes must pass the
same registry check on the EFFECTIVE set before issuance
(`scoperegistry/reject.go`'s contract). The **"two gates" beat** (teaching
reviewer F1) is the note's opening: two gates protect scopes on a custom
grant, and the scaffold's branch is the one the server cannot do — the seam
checks scope-name registration only, never the per-client `AllowedScopes`
allowlist that `GrantedScopes` enforces (incl. the rule-4 empty-request
default, like the client-credentials branch). The note is authored with no
`issuer.Issue(` literal (mechanically enforced, §5/§6) and placed after the
branch (mechanically enforced, §5/§6).

**D4 — Named-marker test helper `assertGrantContract`.**
A dedicated helper in `scaffold_build_test.go` carries the assertions (§5)
so `TestGeneratedScaffoldsCompile` stays within its function budget. It
asserts on the GENERATED artifact with content markers only — no line
numbers, no `server_token.go` references — so the :345→:383 class of seam
drift can never stale the gate. Marker discipline (from the reviews):
quoted literals, window-scoped search, exactly-one-occurrence guards,
composite error-shape marker, and presence + placement markers for the
registry note (§5).

**D5 — Stale-citation fix (review-only).**
The template's Go doc comment (`templates_handler.go:137`) cites
`interfaces/sso/options_saml2_bearer.go`, which does not exist; the real
handler is `saml2BearerHandler` at `interfaces/sso/server_setup.go:271`
(registered) / `:283` (`Handle`). The citation is corrected in the same
edit. This text is NOT part of the generated file, so no artifact marker can
pin it — declared review-only, like the test reviewer's gap 4.

**D6 — Strict strengthening over R3: the `}, grantedScopes)` marker.**
R3's A1 trio pins the branch but not the issuance argument: a template that
keeps the branch while passing raw `req.Scope` (or `scopes`) to `issuer.Issue`
passes A1+A3. D6 pins "never raw req.Scope" (R1) with a single marker on the
rendered text: `}, grantedScopes)` — the Subject-literal close plus the
scopes argument — asserted exactly once and ordered after `issuer.Issue(`.
The `}, ` prefix disambiguates from `len(grantedScopes)`; the marker is
deliberately shape-tolerant across both plausible B4-1 handoff shapes
(claims map vs dedicated Subject field), so it survives the R4 contract-sync
re-run.

## 4. Final template text (exact)

The full `grantTemplate` raw string after the change. The example block was
restructured per D2; the registry note (D3) sits inside step 2; the B4-1
deferral (F7) sits in step 3; step 4 passes `grantedScopes` (D6). The block
grows from 37 to 80 comment lines (template body 76 → 121 lines;
`templates_handler.go` 215 → ~261, §11). Zero backticks (raw-string safety,
§6). Marker placement summary: `oauth.GrantedScopes(` @734, `oauth.SplitScope(`
@754, `core.ErrorBody(core.ErrInvalidScope)` @854, `rejectUnregisteredScopes`
@1076, `deps.Roles(` @2001, `issuer.Issue(` @2911, `TenantID: client.TenantID`
@3053, `}, grantedScopes)` @3087 (window-relative indices in the rendered
file — full re-run in §6).

```go
package {{.Package}}

import (
	"net/http"

	"github.com/yangwb1123/snaplink/protocols/oauth"
	"github.com/yangwb1123/snaplink/shared/core"
)

// {{.Name}}GrantHandler implements oauth.GrantHandler for the
// {{.Description}} grant type. Register it once at boot:
//
//	sso.WithCustomGrant(&{{.Package}}.{{.Name}}GrantHandler{ /* deps */ })
type {{.Name}}GrantHandler struct {
	// TODO: Add whatever dependencies this grant needs, e.g. a
	// func(client *core.Client) (string, core.TokenIssuer, error) accessor to
	// mint tokens, a core.ClientStore, or a domain-specific validator.
}

// GrantType returns the grant_type value clients send at /token.
// TODO: Return the URN/string clients will send, e.g.
// "urn:ietf:params:oauth:grant-type:{{.LowerName}}" for a URN-style custom
// grant (the RFC 8693 / OIDC CIBA convention), or a bare string
// ("{{.LowerName}}") for a simple custom type.
func (h *{{.Name}}GrantHandler) GrantType() string {
	return "{{.LowerName}}"
}

// Handle processes /token requests for this grant type. The caller
// (server_token.go's dispatchCustomGrant) has already authenticated the
// client and checked its GrantTypes allowlist; Handle MUST write a response
// — success or error — via ctx on every code path. Per this codebase's
// oracle-leak hardening (AGENTS.md §3): unknown/expired/consumed/mismatched
// grant state maps to a plain 400 invalid_grant, never a distinguishing
// detail.
func (h *{{.Name}}GrantHandler) Handle(ctx core.HandlerContext, client *core.Client, req oauth.TokenRequest, dpopJKT, mtlsX5T string) {
	// TODO: Replace with your {{.Description}} grant validation and token
	// issuance. Standard pattern:
	//
	// 1. Validate grant-specific parameters (e.g. req.Assertion for a
	//    JWT/SAML-bearer-style grant, req.Scope/req.Resource otherwise):
	//
	//    if req.Assertion == "" {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
	//    	return
	//    }
	//
	// 2. Gate the requested scope exactly like the built-in grants do
	//    (persistCIBARequest in handle_ciba.go, token_client_credentials.go):
	//    the per-client AllowedScopes allowlist via oauth.GrantedScopes,
	//    rejecting out-of-allowlist scopes with 400 invalid_scope. This is
	//    the gate the dispatch seam does NOT apply to custom grants — see
	//    the note after the branch.
	//
	//    grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
	//    	return
	//    }
	//
	//    Two gates protect scopes on a custom grant, and this branch is
	//    the one the server cannot do for you. The dispatch-level registry
	//    seam (rejectUnregisteredScopes → scoperegistry.RejectUnregistered,
	//    wired via WithScopeRegistry / oauth.scope_registry.enabled) already
	//    rejects UNREGISTERED request-borne scopes before any custom
	//    handler runs — but it checks scope-name registration only, never
	//    the client's per-tenant AllowedScopes allowlist. That allowlist is
	//    exactly what GrantedScopes enforces here, and it defaults an empty
	//    request to the allowlist (rule 4, like the client-credentials
	//    branch). Scopes your handler mints internally that the request
	//    never carried must pass the same registry check on the EFFECTIVE
	//    set before issuance (scoperegistry/reject.go's contract).
	//
	// 3. Resolve the resource owner's roles from the same source the
	//    built-in paths use — permissions.Provider.Roles, reached via a
	//    deps accessor mirroring accessors_handlers.go:
	//
	//    roles, err := deps.Roles(ctx.Request().Context(), resourceOwnerID, client.ID)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	//    	return
	//    }
	//    // B4-1 contract-sync: when the tenant_id/roles claims land in
	//    // buildAccessPayload, hand roles into the Subject in the same
	//    // change (AGENTS.md §5.6) — the exact field/claim shape is
	//    // pinned then. Do not route them through Subject.Claims today:
	//    // it is a map[string]string emitted as ext, not the T-8(a)
	//    // roles claim.
	//
	// 4. Mint a token via the same path every built-in grant uses, passing
	//    the GRANTED set — never raw req.Scope:
	//
	//    strategy, issuer, err := h.issuerForClient(client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrNoTokenStrategy))
	//    	return
	//    }
	//    token, err := issuer.Issue(ctx.Request().Context(), &core.Subject{
	//    	ID:       resourceOwnerID, // if applicable
	//    	ClientID: client.ID,
	//    	TenantID: client.TenantID,
	//    }, grantedScopes)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	//    	return
	//    }
	//    ctx.JSON(http.StatusOK, map[string]any{
	//    	core.KeyAccessToken: token.AccessToken,
	//    	core.KeyTokenType:   token.TokenType,
	//    	core.KeyExpiresIn:   token.ExpiresIn,
	//    	core.KeyScope:       token.Scope,
	//    })
	//
	// After filling in your logic, remove this marker. Until then, this
	// safely fails closed with the same invalid_grant every unimplemented/
	// unrecognized grant state returns elsewhere in this codebase.


	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidGrant))
}
```

## 5. Named-marker test helper (full code + wiring)

`assertGrantContract` lands in `scaffold_build_test.go` (a `_test.go` file —
outside the maintainability gate's parent-module non-test scope; §11). It is
byte-for-byte the code executed in the §6 simulation. Design notes carried
in the doc comment: quoted literals (never `strings.Index(core.ErrInvalidScope)`
— that searches for `"invalid_scope"`, absent from the generated file, and an
order-only check is vacuously true on absence — reviewer F4/F5);
window-scoping ("Standard pattern:" → "After filling in your logic") kills
FP-1/FP-2 prose interference; exactly-one-occurrence guards make presence
load-bearing and first-occurrence ordering sound (FP-4); A3's loose `Roles(`
matching is a recorded B4-1-survival tradeoff (FP-3); the registry-note
markers pin the seam name AND the `RejectUnregistered` function name (test
reviewer gap 1).

```go
// assertGrantContract asserts the R1–R3 teaching invariants on the GENERATED
// grant scaffold (device-code_grant.go), not on the template source, so a
// template regression fails the grant subtest with a named failure. Content
// markers only — no line numbers — so seam reflow (e.g. server_token.go's
// dispatchCustomGrant drifting 345→383) can never stale the assertions.
//
// Marker discipline (from the design's adversarial review):
//   - Quoted literals only. strings.Index(core.ErrInvalidScope) would search
//     for "invalid_scope", which the generated file never contains (-1), and
//     an order-only check is vacuously true on absence.
//   - Window-scoped to the example block ("Standard pattern:" →
//     "After filling in your logic") so prose OUTSIDE the window (doc
//     comments quoting the branch) can neither satisfy nor interfere with
//     the assertions (reviewer FP-1/FP-2).
//   - Exactly one occurrence per marker: presence without count is
//     satisfiable by prose, and first-occurrence ordering is unsound once a
//     second occurrence exists (reviewer FP-4 on the issuer.Issue( literal).
//   - A3 deliberately matches any *Roles( call: it certifies a roles-source
//     REFERENCE, not data flow (the Subject handoff shape is pinned when
//     B4-1 lands, R4). A rename like deps.ResolveRoles( still passes; a
//     RolesForUser( rename fails — accepted, recorded in the design (FP-3).
func assertGrantContract(t *testing.T, generated string) {
	t.Helper()

	start := strings.Index(generated, "Standard pattern:")
	end := strings.Index(generated, "After filling in your logic")
	if start < 0 || end < 0 || start >= end {
		t.Fatalf("grant scaffold: example window markers missing or inverted (start=%d end=%d)", start, end)
	}
	block := generated[start:end]

	once := func(name, marker string) {
		t.Helper()
		if n := strings.Count(block, marker); n != 1 {
			t.Fatalf("grant scaffold: %s marker %q must occur exactly once in the example block, found %d", name, marker, n)
		}
	}
	before := func(name, earlier, later string) {
		t.Helper()
		e := strings.Index(block, earlier)
		l := strings.Index(block, later)
		if e < 0 || l < 0 || e >= l {
			t.Fatalf("grant scaffold: %s violated (%q@%d must precede %q@%d)", name, earlier, e, later, l)
		}
	}

	// A1 — allowlist gate branch before issuance (T-8(d) proxy). The
	// composite literal pins the oracle-safe plain core.ErrorBody shape
	// (never the trace-wrapped errorBody) in the same assertion as the
	// constant (reviewer gap 3).
	once("A1 error shape", "core.ErrorBody(core.ErrInvalidScope)")
	once("A1 allowlist gate", "oauth.GrantedScopes(")
	once("A1 scope split", "oauth.SplitScope(")
	// Single-issuance guard: a second issuer.Issue( anywhere (e.g. a note
	// quoting the literal) would make first-occurrence ordering unsound.
	once("A1 issuance", "issuer.Issue(")
	before("A1 split before issuance", "oauth.SplitScope(", "issuer.Issue(")
	before("A1 error shape before issuance", "core.ErrorBody(core.ErrInvalidScope)", "issuer.Issue(")

	// D6 — issuance passes the GRANTED set, never raw req.Scope. The "}, "
	// prefix disambiguates from len(grantedScopes).
	once("D6 granted argument", "}, grantedScopes)")
	before("D6 argument at issuance", "issuer.Issue(", "}, grantedScopes)")

	// A2 — tenant binding (T-8(a) proxy).
	once("A2 tenant binding", "TenantID: client.TenantID")

	// A3 — roles-source reference precedes issuance.
	once("A3 roles source", "Roles(")
	before("A3 roles before issuance", "Roles(", "issuer.Issue(")

	// R1 registry note — the seam teaching must survive (reviewer gap 1),
	// placed AFTER the gate branch. Both the server seam name and the
	// scoperegistry function it delegates to are pinned. The
	// single-occurrence guard on issuer.Issue( above is what forbids the
	// note from quoting the literal (FP-2): any quote would make the count
	// 2 and fail the gate.
	once("registry note seam", "rejectUnregisteredScopes")
	once("registry note function", "RejectUnregistered")
	before("registry note after gate branch", "core.ErrorBody(core.ErrInvalidScope)", "rejectUnregisteredScopes")
}
```

Wiring in the `grant` subtest of `TestGeneratedScaffoldsCompile`, after
`scaffold.Generate(outputDir)` and before the existing `go build ./...`
gate (R3's ordering; +6 lines → function 37 → ~43 ≤ 50):

```go
if tc.kind == "grant" {
	gen := filepath.Join(outputDir, "device-code_grant.go")
	data, err := os.ReadFile(gen)
	if err != nil {
		t.Fatalf("read generated grant %s: %v", gen, err)
	}
	assertGrantContract(t, string(data))
}
```

## 6. Marker simulation — re-run against the final template text

Method (scratch module, stdlib only, `go1.26.5`): the current template body
was extracted verbatim from `templates_handler.go:140–214` (75 lines); the
old example block (37 lines) was replaced by the §4 block (80 lines) →
final template (121 lines, 5416 bytes); rendered with the exact
`templateData()` substitution set of the grant test case (`Name=DeviceCode`,
`LowerName=device-code`, `Description="integration-test grant"`,
`Package=grants`) → 5412-byte generated file; the §5 helper ran as the gate,
plus 13 negative probes and a red-proof on the unmodified template.

**Marker report (rendered file, window-relative; window = 3482 bytes):**

| Marker | count | firstIdx | Meaning |
|---|---|---|---|
| `Standard pattern:` | 1 | 0 | window start |
| `oauth.GrantedScopes(` | 1 | 734 | A1 allowlist gate |
| `oauth.SplitScope(` | 1 | 754 | A1 scope split |
| `core.ErrorBody(core.ErrInvalidScope)` | 1 | 854 | A1 composite error shape |
| `rejectUnregisteredScopes` | 1 | 1076 | registry note (seam) |
| `deps.Roles(` | 1 | 2001 | A3 roles source |
| `issuer.Issue(` | 1 | 2911 | A1/A3/D6 issuance anchor |
| `TenantID: client.TenantID` | 1 | 3053 | A2 tenant binding |
| `}, grantedScopes)` | 1 | 3087 | D6 granted argument |

**Ordering verdicts**: split(754) < issuance(2911) ✓ · error shape(854) <
issuance(2911) ✓ · roles(2001) < issuance(2911) ✓ · issuance(2911) <
granted argument(3087) ✓ · error shape(854) < note(1076) ✓ — note placed
after the branch. `count(issuer.Issue() == 1` ✓ (FP-4 guard; the same guard
forbids the note quoting the literal — any quote makes the count 2). Zero
backticks in the final template ✓ (raw-string safety). Template parses and
renders under `text/template` ✓. The "After filling in your logic" window-end
marker has count 0 inside the window by construction (window is
`[start, end)`).

**Negative probes (all verdicts as designed; named assertion on each
failure):**

| # | Probe | Gate verdict | Failure named |
|---|---|---|---|
| 1 | branch removed | FAIL ✓ | A1 error shape: found 0 |
| 2 | branch reordered after issuance | FAIL ✓ | A1 split before issuance (`SplitScope@2944` must precede `issuer.Issue@2701`) |
| 3 | raw `req.Scope` passed (`}, scopes)`) | FAIL ✓ | D6 granted argument: found 0 |
| 4 | tenant binding dropped | FAIL ✓ | A2: found 0 |
| 5 | roles reference dropped | FAIL ✓ | A3 roles source: found 0 |
| 6 | `errorBody(ctx, …)` trace-wrapped regression | FAIL ✓ | A1 error shape: found 0 (composite marker) |
| 7 | note quotes `issuer.Issue(` literal | FAIL ✓ | A1 issuance: found 2 (count guard) |
| 8 | note moved before the branch | FAIL ✓ | note after gate branch (`ErrorBody@1713` must precede `rejectUnregisteredScopes@861`) |
| 9 | seam renamed in note | FAIL ✓ | registry note seam: found 0 |
| 10 | second issuance added | FAIL ✓ | A1 issuance: found 2 (count guard) |
| 11 | `deps.ResolveRoles(` swap | PASS ✓ | documented FP-3 tolerance (still contains `Roles(`) |
| 12 | `deps.RolesForUser(` rename | FAIL ✓ | A3: found 0 (documented FP-3 false negative) |
| 13 | FP-1: prose quoting the whole branch OUTSIDE the window, branch deleted | FAIL ✓ | A1 error shape: found 0 — window-scope holds |
| 13b | FP-2: `issuer.Issue(` literal in a comment OUTSIDE the window | PASS ✓ | no interference — window-scope holds |

**Red proof**: the UNMODIFIED template fails the gate (A1 error shape: found
0) — the gate is load-bearing, and the migration's red→green sequence (§9
Step 2) is the regression proof.

## 7. API changes and compatibility constraints

- **Public API**: none. No new `Err*` (`invalid_scope` is
  `core.ErrInvalidScope`, registered at error-codes.md:298), no endpoint, no
  config knob, no OpenAPI change, no new package, no option/store wiring.
- **Generated output**: `sso-ctl generate grant` text changes for NEW
  scaffolds only; already-generated files are untouched; the fail-closed
  `invalid_grant` default body and the `GrantType()` shape are unchanged, so
  the compile gate's assumptions hold.
- **Server wire-compat**: untouched — zero edits outside
  `cmd/sso-ctl/generate`. The seam, registry, and grant branches are B4-2
  landed code; this change only teaches them.
- **Dependency graph**: no import changes — the template's example references
  `protocols/oauth` symbols (`GrantedScopes`, `SplitScope`) already imported
  by the generated scaffold (`oauth` import at templates_handler.go:145);
  `deps.Roles` is example text mirroring `permissions.Provider.Roles` (a
  comment, not an import).
- **Rollout/rollback**: pure generator + test change (§9).

## 8. Failure modes FM-1..FM-8

Each row: trigger/effect, detection (named assertion), mitigation.

| # | Failure mode | Trigger / effect | Detection | Mitigation |
|---|---|---|---|---|
| FM-1 | **Gate branch removed** | A future template edit deletes the `GrantedScopes`/`SplitScope`/invalid_scope branch; every new scaffold ships the violating pattern again (T-8(d) drift on the scaffold axis) | **A1 presence trio** — `oauth.GrantedScopes(`, `oauth.SplitScope(`, each exactly once in the example window; the **composite `core.ErrorBody(core.ErrInvalidScope)`** additionally pins the oracle-safe plain-body shape (a regression to trace-wrapped `errorBody(...)` or status 500 fails — reviewer gap 3) | Comment-block edit; the gate names the missing marker so the failure identifies the invariant |
| FM-2 | **Gate branch reordered after issuance** | Branch exists but `issuer.Issue(` precedes it; scopes reach the issuer unvalidated | **A1 order** — split(754) and error shape(854) must precede `issuer.Issue(`(2911) | Step-numbered example (§4) plus the ordering assertions |
| FM-3 | **Raw `req.Scope` passed to `issuer.Issue`** | Branch kept, but issuance passes the unvalidated request set (the original violating pattern) | **D6** — `}, grantedScopes)` exactly once and ordered after `issuer.Issue(`; `}, ` prefix disambiguates from `len(grantedScopes)` | D6 marker is the only assertion pinning R1's "never raw req.Scope"; shape-tolerant across B4-1 handoff forms |
| FM-4 | **Tenant binding dropped** | `TenantID: client.TenantID` removed from the Subject literal | **A2** — exactly once in the window | Pin on pre-existing teaching (passes on the current template — a pin, not new teaching; recorded in §10) |
| FM-5 | **Roles reference dropped** | Step-3 roles resolution removed; scaffold stops teaching the T-8(a) roles source | **A3** — `Roles(` exactly once, before `issuer.Issue(` | Deliberately loose symbol match (FP-3 tradeoff, §5/§6 probes 11–12): certifies reference, not data flow; handoff shape pinned at B4-1 (R4) |
| FM-6 | **Registry-note regression** | Note dropped, moved before the branch, or the seam renamed; the "two gates" teaching and effective-set duty vanish | **Registry-note markers** — `rejectUnregisteredScopes` and `RejectUnregistered` each exactly once, placed after the error shape (reviewer gap 1, now detected) | Note text pinned in §4; the count guard on `issuer.Issue(` mechanically forbids the note quoting the literal (FP-2) |
| FM-7 | **Template raw-string breakage** | A backtick sneaks into `grantTemplate`; `templates_handler.go` no longer parses | Module compile gate (`go build ./...`) + §6 zero-backtick check | Raw-string discipline; the compile gate is the backstop |
| FM-8 | **B4-1 contract-sync (residual risk, R4)** | When B4-1 lands (`buildAccessPayload` gains `tenant_id`/`roles`), the issuer/Subject surface may change; the example's `Subject` literal or roles handoff could go stale | **R4 re-run duty** — `go test ./cmd/sso-ctl/generate/...` against the B4-1 change; mechanical core = the compile gate (proves the generated scaffold still builds against the completed issuer path) | Flagged residual, correctly: comment text cannot be compile-gated and the markers deliberately pass both B4-1 handoff shapes; the B4-1 module spec carries the cross-reference re-test duty (§9 Step 6) so the trigger is visible from that side |

**Declared residuals (not detected by any gate, by design)**: (a) roles-symbol
swap — `deps.ResolveRoles(` passes A3 (FP-3 tolerance; recorded in §5); (b)
a future server refactor renaming/removing the seam makes the note's teaching
stale — no artifact marker can couple the test to server internals without
losing drift-immunity; review-only, same class as the stale-citation fix
(D5). The FM table's detection column is otherwise complete: the two classes
the first review found undetected (note regression, error-shape regression)
are now FM-6 and the FM-1 composite marker.

## 9. Migration steps and rollback

Every step is independently shippable and ends in the named gates; the last
step is the full `make ci` handoff.

### Step 1 — Template edit (`cmd/sso-ctl/generate/templates_handler.go`)

- Replace the `Handle` example block with the §4 text (4 steps, registry
  note with the two-gates beat, B4-1 deferral comment, `grantedScopes`
  issuance); fix the stale doc-comment citation (D5).
- Gates: `go build ./... && go vet ./...`;
  `go test -run 'TestMaintainability_|TestArchitecture_' .`
- Rollback criteria: revert the block; no test depends on the new text yet.

### Step 2 — Test helper (`cmd/sso-ctl/generate/scaffold_build_test.go`)

- Add `assertGrantContract` (§5) and the grant-subtest wiring (read
  `device-code_grant.go`, assert, then the existing `go build ./...`).
- Gates: `go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v`.
  Expected red→green: against the unmodified template the new assertions fail
  with named markers (proven in §6); after Step 1 they pass.
- Rollback criteria: revert the helper; compile gate alone remains.

### Step 3 — Package race

- Gates: `go test ./cmd/sso-ctl/... -race`.
- Rollback criteria: revert Steps 1–2.

### Step 4 — Full suite

- Gates: `go test ./... -race`; `go test ./test/ -run TestE2E -v` (server
  untouched — must pass unchanged).
- Rollback criteria: revert Steps 1–2.

### Step 5 — Full gate

- Gates: `make ci` (fmt, vet, race, build, examples, proto-lint, ci-modules,
  config-validate-all, modules-check, modules-smoke, route-contract,
  capabilities-check, sdk-surface-check, profiles-evidence, adapters-check).
- Rollback criteria: revert Steps 1–2.

### Step 6 — R4 contract-sync duty + campaign traceability

- Record the re-test duty in the B4-1 module spec (cross-reference: when B4-1
  lands, re-run `go test ./cmd/sso-ctl/generate/...` and update the §4/§5
  markers in the same change if the Subject/issuer surface changes) — the
  teaching reviewer's recommendation so the trigger is visible from the
  B4-1 side.
- Update the scaffold-compliance note on implementation-gate.md rows 1–2
  (generated-code inspection proxy for T-8(a)/T-8(d); wire-level tests remain
  B4-1/B4-2 server deliverables).
- Rollback criteria: docs-only; reverts with the module spec.

**Rollback (any step)**: revert the two files. No wire impact, no data
migration, no go.mod/go.sum change; already-generated scaffolds are
unaffected (template text affects only new scaffolds).

## 10. Acceptance mapping R1–R4 → A1/A2/A3 → Given/When/Then

| Requirement | Acceptance | Given/When/Then |
|---|---|---|
| R1 — scope gate before issuance | **A1**: `oauth.GrantedScopes(`, `oauth.SplitScope(`, `core.ErrorBody(core.ErrInvalidScope)` each exactly once in the example window and ordered before `issuer.Issue(`; composite pins the plain-body 400 shape | G/W/T 1 + 3: given the generated file, then the branch precedes issuance textually; any template edit removing/reordering the branch or swapping in `errorBody(...)` fails the grant subtest with a named assertion |
| R1 — never raw `req.Scope` | **D6**: `}, grantedScopes)` exactly once, ordered after `issuer.Issue(` | G/W/T 3: a regression to `}, scopes)` fails with the D6 name |
| R1 — registry-seam note | **Note markers**: `rejectUnregisteredScopes` + `RejectUnregistered` present exactly once, after the error shape | G/W/T 3: dropping/moving/renaming the note fails with the note name (reviewer gap 1 closed) |
| R2 — tenant binding | **A2**: `TenantID: client.TenantID` exactly once | G/W/T 2 + 3. Recorded: A2 is a PIN on pre-existing teaching (passes on the current template; new-fail→pass applies to A1/A3/D6/note) |
| R2 — roles source | **A3**: `Roles(` exactly once, before `issuer.Issue(` | G/W/T 2 + 3. Recorded: A3 certifies a roles-source REFERENCE, not data flow — R2's "hand them into the Subject" is deferred to B4-1; the template's step-3 comment shows resolution + the deferral (F7) instead of a fake Claims handoff |
| R3 — gate on generated output | G/W/T 4: isolated-module `go build ./...` succeeds; fail-closed `invalid_grant` default untouched | Compile gate unchanged; assertions run BEFORE it on the generated artifact |
| R4 — B4-1 contract-sync | G/W/T 5: `go test ./cmd/sso-ctl/generate/...` against the B4-1 change passes; marker updates land in the same change | Process duty with a mechanical core (compile gate); flagged residual risk (FM-8) |

## 11. Budget discipline (verified)

- `templates_handler.go`: 215 → ~261 lines (+46) — under the 500 cap; the
  template is data (no functions), so function budgets don't apply.
- `scaffold_build_test.go`: 122 → ~180 lines (+helper +wiring) — under 500.
- `TestGeneratedScaffoldsCompile`: 37 → ~43 lines ≤ 50 ✓ (assertions live in
  the helper, per R3's note).
- `assertGrantContract`: 43 body lines / cyclomatic 6 (gate algorithm — 1
  base + 1 window-if + 1 `once` closure-if + 3 `before` closure
  if/`||` — nested literals counted, matching
  `maintainability_complexity_test.go`'s `funcComplexity`). This corrects the
  summary's earlier ≈10 estimate, which predates the closure-based structure.
  The helper lives in a `_test.go` file, which the maintainability gate
  excludes (parent-module non-test files only) — recorded for transparency.
- `interfaces/sso` 60-file ceiling untouched (zero edits there); no new
  files, no directory/fan-out changes; no `go.mod`/`go.sum` change; no new
  `Err*`; no `layerExemptions` (nothing new to classify).

## 12. Review-hardening traceability

| Reviewer finding | Where addressed |
|---|---|
| Test gap 1 — registry note unasserted | Note markers (`rejectUnregisteredScopes`, `RejectUnregistered`) in §5; probe 9; FM-6 |
| Test gap 2 — A3 reference vs R2 "hand them into the Subject" wording | Recorded in §10; template step-3 deferral comment (F7) in §4 |
| Test gap 3 — error shape unpinned | Composite `core.ErrorBody(core.ErrInvalidScope)` marker, §5; probe 6; FM-1 |
| Test gap 4 — stale-citation fix unpinnable | Declared review-only, §3 D5 / §10 |
| Test FP-1 — prose satisfaction | Window-scoping + count==1; probe 13 |
| Test FP-2 — first-occurrence interference | Window-scoping + count==1 + note placement/quoting guards; probes 7, 13b |
| Test FP-3 — loose `Roles(` matching | Recorded tradeoff in §5 (certifies reference, survives B4-1); probes 11–12 |
| Test FP-4 — second `issuer.Issue(` evasion | `count == 1` guard; probe 10 |
| Teaching F1 — "two gates" beat | Note opening sentence + allowlist-vs-registration explanation, §4 |
| Teaching F4/F5 — quoted literals load-bearing | Marker discipline in §5; absence-proof in §6 red-proof |
| Teaching F7 — roles-surface deferral | Step-3 B4-1 contract-sync comment, §4 (the step renumbering from the old 2-step shape is documented in D2) |
| Teaching R4 — cross-reference re-test duty | Migration Step 6 |
| Process F3 — missing design body | This revision (full D1–D6, FM table, note text, helper code, simulation re-run) |
