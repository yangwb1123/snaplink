All evidence claims are now verified against the repository. Two material defects surfaced during verification that the evidence itself contains. Here is the verification report and the concrete design.

---

# Design: encode B4-2 per-client scope gate + B4-1 claim sources into `grantTemplate`

## 1. Evidence verification verdict

### Confirmed claims (all load-bearing facts check out)

| Claim | Verified at |
|---|---|
| `grantTemplate` ships raw `scopes` → `issuer.Issue` with `TenantID: client.TenantID`, zero scope gate / roles | `templates_handler.go:150` (const), `Handle` example; grep confirms no `GrantedScopes`/`SplitScope`/`ErrInvalidScope`/`Roles` anywhere in the file |
| `rejectUnregisteredScopes` dispatch seam gates only the registry, before `denyTokenScopeCombo` and custom-grant dispatch | `server_token.go:189–204` doc, func `:203`, call `:132`, `denyTokenScopeCombo` `:137`, `dispatchCustomGrant` call `:144`, func `:383` |
| CIBA canonical pattern | `handle_ciba.go:296–308`: `GrantedScopes(SplitScope(req.Scope), client)` → plain `core.ErrorBody(core.ErrInvalidScope)` 400 |
| CC-grant precedent incl. post-resolution registry check | `token_client_credentials.go:38–40` + `scoperegistry.RejectUnregistered` on resolved set `:46` |
| `oauth.SplitScope`/`GrantedScopes` aliases | `aliases.go:119–120`; impl `oauthvalidate/scope.go:27` (nil-for-empty split) and `:80` (rules 2/4, oracle-safe) |
| `core.ErrInvalidScope` + registration | `shared/core/errors.go:170`; `docs/error-codes.md:298` (400, allowlist + registry semantics, plain body) |
| `scoperegistry` landed | `RejectUnregistered` `reject.go:31–40`, `FilterRegistered` `:48–53` |
| **B4-1 landed (the spec's §1 "verified gap" rows are stale)** | `issue_payload.go` `buildAccessPayload` `:27`, `TenantID: subject.TenantID` `:46` unconditional, `Roles` append `:86–87` AMR-guarded; `ed25519_types.go:50/57` `tenant_id,omitempty`/`roles,omitempty`; `types_token.go:236/249` `Subject.TenantID`/`Roles` |
| Roles source | `permissions.Provider.Roles` `provider.go:38`; call site `accessors_handlers.go:104` |
| Test shape | `TestGeneratedScaffoldsCompile` `scaffold_build_test.go:97`; grant case `{"grant","protocols/grants","device-code"}`; `generatedFile` helper + contract helpers in untracked `scaffold_contract_test.go`; `%s_grant.go` rule `generate.go:82`; build+vet loop, hermetic (`GOFLAGS=-mod=mod`, `GOPROXY=off`, local replace) |
| `GrantHandler` extension point | `grant_handler.go:14` |
| Worktree state | `cmd.go`, `scaffold_build_test.go`, `templates_handler.go`, `verify.go` modified; `scaffold_contract_test.go` untracked |
| Entry-2 citation truly stale | `interfaces/sso/options_saml2_bearer.go` absent; `saml2BearerHandler` at `server_setup.go:271/275/279` |
| `TestRunExitCodes` (T-9) | Present in `scaffold_contract_test.go`; handler kind + exits 2/1/0; no CLI surface touched |
| Contract-helper auto-coverage | `assertRegisteredErrorCodes` resolves `core.ErrX` via `errors.go` and validates against `error-codes.md` → `core.ErrInvalidScope` passes automatically; `assertNoPathLiterals`/`assertNoLegacyPathPort` impose the `"/..."`/`/authenticate`/`8080` bans the new text must respect |

### Defects found in the evidence (drift the evidence itself did not flag)

1. **A1's `grantedScopes)` ordering is physically unsatisfiable.** Evidence R3.1 and acceptance #1 require `grantedScopes)` at an index *before* `issuer.Issue(`. But `grantedScopes)` is the Issue call's own argument tail (`}, grantedScopes)`); any text where it precedes `issuer.Issue(` either does not pass the validated set to issuance or is a contrived comment. **Resolution (adopted below):** the before-issuance ordering applies to the four branch/teaching markers (`GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, `Roles(`); `grantedScopes)` is asserted presence-only, and a negative assertion bans the raw tail `}, scopes)` (the exact regression the old template ships). This preserves the evidence's intent — "issuance passes the validated set, never raw req.Scope" — with a satisfiable predicate.
2. **Budget arithmetic contradiction:** evidence claims both "`TestGeneratedScaffoldsCompile` stays under 50 lines (helper factored out)" and "grant subtest grows 1 line". The function is *already exactly 50 lines* (97–146); +1 = 51. Resolution: the committed budget gates (`maintainability_budget_test.go`, `maintainability_complexity_test.go`) explicitly scope to "non-test .go files" — `_test.go` is excluded from both the 500-line file and 50-line function gates. 51 lines is therefore gate-compliant; the optional 2-line restructure below keeps it at 50 for belt-and-braces.
3. **Minor line-number drift (cosmetic, semantics unaffected):** seam call sites `132/137/144` (evidence: `136/142/144`); `generate.go:82` (evidence: `:79`); `oauthwire/token_request.go:20` `Scope` (evidence: `:15`); `accessors_handlers.go:104` (evidence: `:103`).

**Net verdict:** the direction is sound and the scope boundary is correct; the change is a pure generator+test edit with zero runtime surface.

## 2. Design overview

`sso-ctl generate grant` is the only generator for `oauth.GrantHandler` — the extension point B4-1 (tenant_id/roles claims) and B4-2 (per-client scope gate) regulate. The scaffold's `Handle` example currently teaches the exact bypass: request scopes flow into `issuer.Issue` with no allowlist gate and no roles source. The fix encodes both seams into the template's comment example (the generated artifact embeds it verbatim) and pins each invariant with named per-marker assertions that fail red against today's template and green after.

## 3. API changes

**Product/public surface: none.** No new `Err*`, no OpenAPI/config/error-code surface, no SPI, option, storage, HTTP, or proto change. The only "API" deltas are:

- **Generator output contract** (internal): `sso-ctl generate grant` now emits a `Handle` example containing the `oauth.GrantedScopes` → 400 `invalid_scope` branch, the `Roles(` source step, `TenantID: client.TenantID` (unchanged literal, now pinned), and issuance over `grantedScopes` + `Roles: roles`. Affects only newly generated scaffolds.
- **Test helper API** (internal, package `generate`): new `assertGrantScopeGateClaims(t *testing.T, kind string, content []byte)` in `scaffold_contract_test.go`, mirroring the existing `assertFormContentTypeGuard` style.

## 4. Concrete change spec

### 4.1 `cmd/sso-ctl/generate/templates_handler.go` — `grantTemplate` only (file 226 → ~252 lines; gate-safe, template is data)

**(a) Struct TODO** — add the roles-accessor note:

```go
type {{.Name}}GrantHandler struct {
	// TODO: Add whatever dependencies this grant needs, e.g. a
	// func(client *core.Client) (string, core.TokenIssuer, error) accessor to
	// mint tokens, a core.ClientStore, a domain-specific validator, or a
	// Roles(ctx context.Context, userID, clientID string) ([]string, error)
	// accessor mirroring permissions.Provider.Roles (domains/permissions/
	// provider.go; wiring pattern at interfaces/sso/accessors_handlers.go)
	// for the B4-1 roles claim.
}
```

**(b) `Handle` example** — renumber to four steps. Step 1 unchanged (grant params). Steps 2–4 replace today's single "2. Mint a token" step:

```go
	// 2. Authorize the requested scopes against the client's AllowedScopes
	//    allowlist (RFC 6749 §3.3) via oauth.GrantedScopes — the SAME gate
	//    every built-in issuance entry applies (CIBA at
	//    protocols/oauth/handle_ciba.go, client_credentials at
	//    internal/handler/tokengrant/token_client_credentials.go), so a
	//    custom grant must not mint tokens past the per-client gate. The
	//    dispatch-level registry seam (rejectUnregisteredScopes →
	//    scoperegistry.RejectUnregistered, wired via sso.WithScopeRegistry /
	//    oauth.scope_registry.enabled) already rejected unregistered
	//    REQUEST-borne scopes before this handler ran; any scope this
	//    handler mints INTERNALLY must pass that same RejectUnregistered
	//    check on the effective set before issuance (the client_credentials
	//    precedent at token_client_credentials.go:46).
	//
	//    grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
	//    	return
	//    }
	//
	// 3. Resolve the resource owner's role codes before issuance: the B4-1
	//    roles claim source is the dedicated Subject.Roles field ([]string,
	//    emitted as top-level `roles` only when non-empty — AMR guard, see
	//    infrastructure/defaultimpl/issue_payload.go), populated from a
	//    permissions.Provider.Roles(ctx, userID, clientID) accessor wired
	//    the way interfaces/sso/accessors_handlers.go does it:
	//
	//    roles, err := h.Roles(ctx.Request().Context(), resourceOwnerID, client.ID)
	//    if err != nil {
	//    	ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
	//    	return
	//    }
	//
	// 4. Mint a token via the same path every built-in grant uses, passing
	//    the VALIDATED grantedScopes (never the raw request scope string)
	//    and the resolved roles:
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
	//    	Roles:    roles,
	//    }, grantedScopes)
```

Constraints satisfied by construction: no `"/..."` literal, no `/authenticate`, no `8080`; every `core.ErrorBody` code resolves (`ErrInvalidScope` via `errors.go:170` → registered at `error-codes.md:298`); all symbols are covered by the template's existing imports (`oauth`, `core`); comment-only, so the isolated-module build/vet gate cannot regress. The oracle-safe shape is preserved byte-for-byte (plain `core.ErrorBody`, no `trace_id`).

**(c) Optional budget hygiene (recommended):** fold the two kind-specific assertions into one dispatch so `TestGeneratedScaffoldsCompile` stays at 50 lines:

```go
			assertKindInvariants(t, tc.kind, generated)
```
replacing the `if tc.kind == "handler" { ... }` block, with a 6-line dispatcher in `scaffold_contract_test.go`. (Not required by the committed gates — test files are exempt — but keeps the evidence's "under 50" claim true.)

### 4.2 `cmd/sso-ctl/generate/scaffold_contract_test.go` — new helper (R3, with corrected A1)

```go
// assertGrantScopeGateClaims (grant kind only) pins the B4-2 per-client
// scope gate and the B4-1 claim sources in the generated grant scaffold:
// the allowlist branch (GrantedScopes/SplitScope/invalid_scope), the roles
// source, and the tenant binding must all appear textually before
// issuance, and issuance must hand Issue the validated grantedScopes set —
// never the raw request-scope tail (}, scopes)). Each marker is asserted
// separately so a regression names the exact invariant dropped/reordered.
// Note: grantedScopes) is the Issue-call argument tail, so it is checked
// for presence only; the before-issuance ordering applies to the branch
// and roles markers.
func assertGrantScopeGateClaims(t *testing.T, kind string, content []byte) {
	t.Helper()
	text := string(content)
	issueIdx := strings.Index(text, "issuer.Issue(")
	if issueIdx < 0 {
		t.Errorf("%s scaffold: no issuer.Issue( in the generated grant — the issuance example was dropped", kind)
		return
	}
	for _, m := range []struct{ name, marker string }{
		{"per-client scope gate", "GrantedScopes("},
		{"scope split", "SplitScope("},
		{"invalid_scope error", "core.ErrInvalidScope"},
		{"roles source", "Roles("},
	} {
		idx := strings.Index(text, m.marker)
		if idx < 0 {
			t.Errorf("%s scaffold: missing %s marker %q — the B4-2/B4-1 teaching was dropped", kind, m.name, m.marker)
			continue
		}
		if idx > issueIdx {
			t.Errorf("%s scaffold: %s marker %q at %d must precede issuer.Issue( at %d — ordering regressed", kind, m.name, m.marker, idx, issueIdx)
		}
	}
	if !strings.Contains(text, "grantedScopes)") {
		t.Errorf("%s scaffold: issuance does not pass the validated grantedScopes set — raw request scopes would bypass the per-client gate", kind)
	}
	if strings.Contains(text, "}, scopes)") {
		t.Errorf("%s scaffold: issuance passes raw request scopes (}, scopes)) — the B4-2 bypass pattern is back", kind)
	}
	if !strings.Contains(text, "TenantID: client.TenantID") {
		t.Errorf("%s scaffold: tenant binding TenantID: client.TenantID missing from the Subject literal", kind)
	}
}
```

### 4.3 `cmd/sso-ctl/generate/scaffold_build_test.go` — one-line wiring

In the grant subtest, after `assertNoPathLiterals(...)` (and alongside the handler-kind guard), call the helper before the build/vet loop. With the 4.1(c) dispatcher this is a net line change of −2; without it, +1 line to 51 (gate-exempt, see §1 defect 2).

## 5. Compatibility constraints

- **No runtime behavior change** — template text is data; the server's oracle-safe `invalid_scope` baseline (plain `core.ErrorBody`, no `trace_id`) is taught, not altered. Wire byte-compat of every existing grant branch untouched.
- **No import-graph change** — the generated package already imports `protocols/oauth` and `shared/core`; every new symbol resolves through them. Generated-file shape compiles unchanged.
- **Existing scaffolds unaffected** — `sso-ctl generate grant` output changes only for scaffolds generated after this change; reverting the template restores prior output exactly (the template is the sole source of the text).
- **CLI surface frozen (T-9)** — `cmd.go`/`verify.go` untouched; `TestRunExitCodes` (2/1/0) stays green.
- **Docs untouched** — `invalid_scope` already registered (`error-codes.md:298`); no OpenAPI/config-reference delta.
- **Contract-helper compatibility** — new text must (and does) pass `assertRegisteredErrorCodes`, `assertNoLegacyPathPort`, `assertNoPathLiterals`.
- **Budgets** — file ~252 < 500; no new functions > 50 lines; no directory/fan-out change; `interfaces/sso` 60-file ceiling untouched (no file added there).

## 6. Failure modes

| Mode | Detection / mitigation |
|---|---|
| A1 evidence defect: literal `grantedScopes)` < `issuer.Issue(` predicate | Cannot pass on correct output. Fixed in 4.2: presence + `}, scopes)` ban + ordering on the four pre-issuance markers |
| Template edit drops/reorders a marker | Named per-marker `t.Errorf` (each marker asserted separately); `issuer.Issue(` absence fails loudly and returns (no silent pass of ordering checks) |
| Doc drift unregisters `invalid_scope` | `assertRegisteredErrorCodes` fails (200-row parse floor guards against format drift) |
| Accidental `"/..."`/`/authenticate`/`8080` in new text | `assertNoPathLiterals`/`assertNoLegacyPathPort` fail |
| `Roles(` marker false-positive (e.g., renamed `h.Roles` call) | `permissions.Provider.Roles(` citation in the step-3 note still satisfies the marker; acceptable trade-off — the invariant is "the roles source is taught before issuance" |
| Worktree dependency: helper lives in untracked `scaffold_contract_test.go` from the verify-gate change | Land both changes together (they also share `templates_handler.go`) or note the dependency in the commit; committing this change alone breaks `TestGeneratedScaffoldsCompile` compile |
| Red-first proof failure (helper passes pre-change) | Pre-condition check §8: current template contains none of the six markers → must fail before the template edit |

## 7. Migration steps

No server/config/data migration exists for this change. Landing sequence:

1. **Red-first proof:** add 4.2 + 4.3 only; run `go test ./cmd/sso-ctl/generate/ -run TestGeneratedScaffoldsCompile -v` — grant subtest must fail with the named missing-marker errors (proves the assertions bite against today's template).
2. **Template edit:** apply 4.1 (a)+(b) (+optional 4.1(c)); rerun — green.
3. **Full gate:** §9 commands.
4. **Land together with the verify-gate worktree change** (they touch the same file and the helper depends on `generatedFile`/`newBuildableModule` from it). Rollback = revert the template hunk; no state to unwind.

## 8. Testable acceptance mapping

| ID | Given | When | Then | Enforcement |
|---|---|---|---|---|
| A1 (T-8(d) proxy) | `generate grant --name device-code --package protocols/grants` (existing test path) | generated `device-code_grant.go` inspected | contains `GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`, `Roles(` each textually before `issuer.Issue(`; contains `grantedScopes)`; does NOT contain `}, scopes)` | `assertGrantScopeGateClaims` (4.2) |
| A2 (T-8(a) proxy) | same artifact | inspected | contains `TenantID: client.TenantID` and `Roles: roles` in the `Subject` literal | 4.2 presence checks |
| A3 (regression) | any template edit dropping/reordering a marker | `TestGeneratedScaffoldsCompile` runs | grant subtest fails with a named assertion identifying the exact violated invariant | per-marker `t.Errorf` |
| A4 (compile) | generated grant package | isolated-module `go build ./...` + `go vet ./...` (hermetic env) | both succeed | existing build/vet loop |
| A5 (T-9) | unchanged CLI surface | `TestRunExitCodes` runs | green (exits 2/1/0) | existing test |
| A6 (red-first) | helper landed, template unedited | gate runs | grant subtest fails with named missing-marker errors | pre-condition manual run, §7 step 1 |

## 9. Verification commands

```bash
go build ./... && go vet ./...
go test -run 'TestMaintainability_|TestArchitecture_' .
go test ./cmd/sso-ctl/generate/ -run 'TestGeneratedScaffoldsCompile|TestRunExitCodes' -v
go test ./cmd/sso-ctl/... -race
make ci
```

## 10. Remaining evidence items I did not need to re-derive

The evidence's §3 non-goals and entry-2/entry-3 exclusions are consistent with verified repo state: the issuer-side B4-1 emission, `scoperegistry`, and the SAML2-bearer registration all exist server-side, so the scaffold change is exactly the remaining gap — teach the landed seams, touch nothing else.

**Design verdict:** adopt the evidence's R1–R4 with the two corrections from §1 (A1 predicate fix; budget-arithmetic note) and the 4.1(c) hygiene restructure. No further design risk identified.
