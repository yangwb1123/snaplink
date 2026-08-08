Everything is verified green. Here is the consolidation deliverable.

---

## Status of the merge

The worktree already carries the template edit (earlier campaign stage) and the helper + `assertKindInvariants` wiring landed concurrently. I ran the real gates against the merged state:

```
--- PASS: TestGeneratedScaffoldsCompile (all 4 kinds incl. grant)
--- PASS: TestVerifyGeneratedBuildVet
--- PASS: TestRunExitCodes
ok  github.com/yangwb1123/snaplink/cmd/sso-ctl/generate
```

The consolidated text below is the final form — **two refinements** over the in-file text (verified byte-exact by diff): the internal-mint sentence de-references the bare `token_client_credentials.go` filename, and the AMR phrase becomes verbatim to the `issue_payload.go` source comment.

## §1 Final `grantTemplate` steps 2–4 (verbatim, paste-ready)

Replaces the in-file block from `// 2. Authorize the requested scopes...` through `//    }, grantedScopes)` (line 200 → 253 of `templates_handler.go`). Tab prefixes as in the raw string; code lines use the file's `//    \t` convention:

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
	//    REQUEST-borne scopes before this handler ran. This example covers
	//    only request-borne scopes; the internal-mint registry check is
	//    intentionally not shown — a handler that composes scopes beyond
	//    the request MUST run scoperegistry.RejectUnregistered on the
	//    effective set before issuance, exactly as the client_credentials
	//    grant does (the dispatch seam sees only request-borne scopes).
	//
	//    grantedScopes, err := oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)
	//    if err != nil {
	//    	ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))
	//    	return
	//    }
	//
	// 3. Resolve the resource owner's role codes before issuance: the B4-1
	//    roles claim source is the dedicated Subject.Roles field ([]string,
	//    emitted as a top-level roles claim only when non-empty — the same
	//    guard+copy discipline as the AMR claim, see
	//    infrastructure/defaultimpl/issue_payload.go), populated from an
	//    accessor mirroring permissions.Provider.Roles(ctx, userID, clientID)
	//    (domains/permissions/provider.go; wiring pattern at
	//    interfaces/sso/accessors_handlers.go). That call site feeds
	//    conditional-access groups and fails open; the server's own mint
	//    path instead resolves codes from the TenantUserStore roster
	//    (subjectRoles in interfaces/sso/server_oauth.go). A custom grant
	//    with no roster access may mirror the (ctx, userID, clientID)
	//    accessor shape, projecting each role.Code into the []string this
	//    field takes. The 500 on accessor failure is deliberate: minting
	//    without roles would silently under-claim the token, so unlike the
	//    fail-open advisory path this example fails closed.
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

## §2 Final helper code (verbatim, paste-ready for `scaffold_contract_test.go`)

```go
var rolesClaimRE = regexp.MustCompile(`Roles:\s+roles`)

// assertGrantScopeGateClaims (grant kind only) pins the B4-2 per-client
// scope gate and the B4-1 claim sources in the generated grant scaffold:
// the allowlist branch (GrantedScopes/SplitScope/invalid_scope), the roles
// source, and the tenant binding must all appear textually before
// issuance, and issuance must hand Issue the validated grantedScopes set —
// never the raw request-scope tail (}, scopes)). Each marker is asserted
// separately so a regression names the exact invariant dropped/reordered.
// Note: grantedScopes) is the Issue-call argument tail, so it is checked
// for presence only; the before-issuance ordering applies to the branch
// and roles markers. The roles ordering marker is h.Roles( — the example
// call, not the permissions.Provider.Roles citation — and the Subject
// projection is pinned separately via Roles:\s+roles (gofmt aligns the
// struct literal, so a plain contains check would false-positive).
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
		{"roles source", "h.Roles("},
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
	if !rolesClaimRE.MatchString(text) {
		t.Errorf("%s scaffold: the Subject literal does not project the resolved roles (Roles: roles) — the B4-1 roles handoff was dropped", kind)
	}
}

// assertKindInvariants dispatches the kind-specific contract assertions on
// the generated artifact. Handler scaffolds must teach the form-urlencoded
// Content-Type guard before binding; grant scaffolds must teach the
// per-client scope gate and the B4-1 claim sources (B4-2/B4-1).
func assertKindInvariants(t *testing.T, kind string, content []byte) {
	t.Helper()
	switch kind {
	case "handler":
		assertFormContentTypeGuard(t, kind, content)
	case "grant":
		assertGrantScopeGateClaims(t, kind, content)
	}
}
```

**Wiring** (already landed in `scaffold_build_test.go`): the `if tc.kind == "handler" {...}` block is replaced by `assertKindInvariants(t, tc.kind, generated)` — `TestGeneratedScaffoldsCompile` drops to 48 lines.

## §3 Merged-result audit (a)–(e) — empirically verified

Verification method: a harness rendered the **real** `grantTemplate` (extracted from `templates_handler.go`, with my block swapped in, executed through `text/template` with the test's exact scaffold values) and ran the helper predicates plus the contract-check regexes from `scaffold_contract_test.go` against the rendered 6074-byte artifact. Then it ran mutation probes. Then the real test suite was run on the merged worktree.

**(a) No backticks — PASS.** Programmatic scan of the entire assembled template body (the raw string at `templates_handler.go:150–277`): zero `` ` `` characters. The internal-mint sentence is rewritten without the backticked `` `scoperegistry.RejectUnregistered` `` and without any `token_client_credentials.go:46` citation: it now reads "exactly as the client_credentials grant does (the dispatch seam sees only request-borne scopes)" — the full path stands once, three sentences earlier in the same note (line-free, per the generator-contract ban), and the parenthetical is the `scoperegistry/reject.go` contract's own wording.

**(b) Byte-accuracy — PASS.** Every cited seam was re-verified against source: CIBA `GrantedScopes(SplitScope(req.Scope), client)` → plain `core.ErrorBody(core.ErrInvalidScope)` (`handle_ciba.go:306–308`); CC `oauth.GrantedScopes` + post-resolution `scoperegistry.RejectUnregistered` + `TenantID: client.TenantID` (`token_client_credentials.go:38/44/46`); `buildAccessPayload` unconditional `TenantID` + `len(subject.Roles) > 0` guard (`issue_payload.go`); `permissions.Provider.Roles(ctx, userID, clientID) ([]Role, error)` (`provider.go:38`); `conditionalAccessGroups` fail-open (log + nil) call site (`accessors_handlers.go:104`); `subjectRoles` TenantUserStore roster mint path (`server_oauth.go`); `rejectUnregisteredScopes` seam before `denyTokenScopeCombo`/`dispatchCustomGrant` (`server_token.go:132/137/144/203`); `WithScopeRegistry` (`options_misc.go:494`); `oauth.scope_registry.enabled` (config + `error-codes.md:298`). The three reworded claims: AMR phrase now verbatim to the source comment ("the same guard+copy discipline as the AMR claim"); the roles note distinguishes the `[]permissions.Role` + `role.Code` projection pattern from the server's roster-based mint path; the 500 on `h.Roles` failure carries the explicit fail-open divergence note (F3).

**(c) Test-plan corrections — PASS, import set verified.** Ordering marker is `h.Roles(` (first occurrence = the step-3 example call at idx 4608; the struct TODO and `permissions.Provider.Roles` citation can no longer satisfy it); `Roles:\s+roles` presence check added (matched the gofmt-aligned `Roles:    roles`, 4 spaces). The regexp need contradicts the design's "needs only strings/testing" claim, but `scaffold_contract_test.go` **already imports `regexp`** (used by `docRowRE`/`errConstRE`/`pathDeclRE`/`errorBodyRE`) — zero import-set change. Mutation probes prove both tightened checks bite: deleting the `h.Roles(` call → 1 named failure; dropping `Roles:    roles` from the Subject literal → 1 named failure; reintroducing `}, scopes)` → 2 failures; deleting the gate example → 3 named failures.

**(d) Six markers — PASS.** Rendered-artifact indices (first occurrences): `GrantedScopes(` 3305, `SplitScope(` 3325, `core.ErrInvalidScope` 3434, `h.Roles(` 4608 — all precede `issuer.Issue(` at 5199; `grantedScopes)` present (the Issue-call tail, per the A1-corrected presence-only semantics); `}, scopes)` absent; `TenantID: client.TenantID` present. The helper passes green against **both** the in-file text and the consolidated text (0 failures each).

**(e) Contract helpers — PASS.** Codes used in the rendered artifact: `invalid_request`, `invalid_scope`, `internal_error`, `no_token_strategy`, `invalid_grant` — every `core.ErrX` resolves through `shared/core/errors.go` (`95/115/170`) and every code is registered in `docs/error-codes.md` (≥200-row parse floor intact); no `"/..."` quoted literal, no `/authenticate`, no `8080`, no host:port shapes. Real suite: `TestGeneratedScaffoldsCompile` (all four kinds, including the isolated-module `go build` + `go vet` loop), `TestVerifyGeneratedBuildVet`, `TestRunExitCodes` (2/1/0) — all green on the merged worktree.

**Sequencing note (unchanged):** commit A (verify-gate change carrying the untracked `scaffold_contract_test.go`) must land before commit B (grant change); the helper lives in the file commit A carries, so B alone stays green.
