Verification complete. Here is the review.

---

# Review: grant-scaffold generator output-contract change

**Verdict: direction sound, gates satisfiable, but two must-fix defects in the proposed template text (one of which is a direct violation of your own criteria), plus one secondary teaching-accuracy note. Sequencing is confirmed workable with an explicit ordering.**

## Verified per criterion

**1. Comment-only four-step Handle block — PASS, with one repo-breaking caveat (F2).**
The proposed steps 2–4 are entirely `//`-prefixed; the compilable skeleton (imports, struct, `GrantType`, fail-closed `ErrInvalidGrant` tail) is untouched, so the isolated-module build/vet loop cannot regress from the *generated* text. However — **F2 (blocker):** step 3 embeds a literal backtick pair — `emitted as top-level `roles` only when non-empty`. `grantTemplate` is a backtick-delimited raw string literal; the first backtick terminates the literal and `templates_handler.go` itself stops compiling. The repo already has the escape idiom for exactly this (` + "`" + `, `templates_handler.go:124–132`). Fix: reword to "the top-level `roles` claim" without backticks, or use the idiom.

**2. File-path citations resolve — PASS (all five).**

| Citation | Resolves | Anchor |
|---|---|---|
| `protocols/oauth/handle_ciba.go` | ✓ | `GrantedScopes(SplitScope(req.Scope), client)` at :306–308 — the example is byte-identical in shape |
| `internal/handler/tokengrant/token_client_credentials.go` | ✓ | `GrantedScopes` :38, `RejectUnregistered` :46 |
| `infrastructure/defaultimpl/issue_payload.go` | ✓ | `buildAccessPayload` :27, `TenantID: subject.TenantID` :46, `Roles` AMR-guarded :86–87 — "emitted only when non-empty" is truthful |
| `domains/permissions/provider.go` | ✓ | `Roles` :38 |
| `interfaces/sso/accessors_handlers.go` | ✓ | `s.permissions.Roles(ctx, userID, clientID)` :104 |

Signatures verified: `oauth.SplitScope(string) []string` and `oauth.GrantedScopes([]string, *core.Client) ([]string, error)` re-exported at `aliases.go:119–120`; `req.Scope` is `string` (`oauthwire/token_request.go:20`). The example code is signature-accurate.

**3. Line-number citations de-referenced — FAIL. This is the crispest criterion violation: the design embeds exactly the citation you named.**
Step 2's note ends with *"the client_credentials precedent at `token_client_credentials.go:46`"*. The line is correct *today* (verified: `RejectUnregistered` at :46), but the criterion exists because it rots inside scaffolds. Required change: drop the `:46` (all other new citations are already line-free; the evidence's `:27/:46/:86-87/:104` cites live in the design doc, not the template text).

**4. No committed scaffold regenerates/diffs — PASS.**
No committed `*_grant.go` generator artifacts (the only match, `infrastructure/saml/saml_bearer_grant.go`, is hand-written production code, no scaffold markers). No golden/diff machinery in `generate.go`/`templates.go`; `TestGeneratedScaffoldsCompile` writes to `t.TempDir()` only. No committed test pins the old template text. Nothing regenerates.

**5. CLI surface frozen, TestRunExitCodes 2/1/0 — PASS.**
The grant change touches no CLI code. `TestRunExitCodes` (in the untracked contract file) asserts usage=2, build-check failure=1, skip/in-module=0; ran green in the current worktree. Note: `cmd.go`/`verify.go` are modified in the worktree, but that is the separate verify-gate change (message text only; exit codes unchanged, test green).

**6. New text passes the three assertions — PASS.**
`core.ErrInvalidScope` (`errors.go:170` → `invalid_scope`, registered `error-codes.md:298`), `core.ErrInternal`, `core.ErrNoTokenStrategy` (`error-codes.md:796`) all resolve through `assertRegisteredErrorCodes`. No `"/...` quoted literal, no `/authenticate`, no `8080`, no port URL in the text. The proposed 4.2 helper's predicates are all satisfiable: the four markers precede `issuer.Issue(` (steps 2–3 vs 4), `grantedScopes)` present as the Issue argument tail, `}, scopes)` absent, `TenantID: client.TenantID` present. The design's A1 correction (presence + tail ban + ordering on the four markers) is the right fix.

**7. Sequencing — confirmed, with the explicit order: verify-gate commit FIRST, carrying the untracked file.**
- **Commit A** (verify-gate worktree change) must include `scaffold_contract_test.go`: the modified tracked `scaffold_build_test.go` calls `generatedFile`/`assertRegisteredErrorCodes`/`assertNoLegacyPathPort`/`assertNoPathLiterals`/`assertFormContentTypeGuard` from it, so shipping A without the untracked file breaks the package compile. I verified A-alone-green empirically: the current worktree *is* A (plus zero grant edits), and all four kinds pass `TestGeneratedScaffoldsCompile` against the current template.
- **Commit B** (grant change) self-contains the helper, the grant-subtest wiring, and the template edit in one commit → green alone.
- Forbidden: landing B first, or landing the grant wiring while `scaffold_contract_test.go` stays untracked. The design's §7 "land both together *or* note the dependency" is weaker than your criterion; the two-commit sequence above satisfies it.

## Secondary findings

- **F3 (teaching accuracy):** step 3's error branch teaches `500 core.ErrInternal` on the `h.Roles` accessor failure — but the cited precedent `accessors_handlers.go:104` fails **open** (log + nil groups; AGENTS.md: "Trust scoring is fail-open advisory input"). For claim emission a 500 is defensible (the token would mint without roles), but the scaffold's comment contradicts the exact wiring it cites. Recommend either matching the fail-open precedent or noting the deliberate divergence in the comment.
- **Nit:** `permissions.Provider.Roles` returns `[]Role` (`provider.go:38`), not `[]string`; the `:104` wiring extracts `role.Code`. The example is framed as "mirroring", so acceptable, but one clause of precision ("then extract `.Code`") would make the teaching exact.
- **Pre-existing (out of scope, still ships):** the current template body cites `interfaces/sso/options_saml2_bearer.go`, which does not exist (`saml2BearerHandler` is at `server_setup.go:271`). Your design's §10 excludes it; that's a defensible scope line, but the stale citation continues to ship in every generated grant. Flag for a follow-up.

**Bottom line:** approve with two required edits — de-reference `token_client_credentials.go:46`, and remove/escape the `` `roles` `` backticks — plus the sequencing commitment (A with the untracked contract file, then B). Everything else verifies as claimed, including the red-first proof precondition (current template contains none of the six markers, so the helper fails before the template edit) and the budget arithmetic (`_test.go` files are exempt from the 50-line function gate, and `templates_handler.go` stays ~252 < 500).
