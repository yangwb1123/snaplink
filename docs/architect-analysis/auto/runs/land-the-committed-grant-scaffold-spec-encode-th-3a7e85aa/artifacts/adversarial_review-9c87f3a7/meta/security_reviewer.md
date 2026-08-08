All verification complete. Here is the byte-accuracy report.

---

# Verification report: grantTemplate Handle-example teaching vs. server seams

**State checked:** the worktree has the verify-gate change landed (`templates_handler.go` still ships the bypass — `}, scopes)` at line 208, zero teaching markers); the design's §4.1(b) text is evaluated as proposed.

## (1) `oauth.GrantedScopes(oauth.SplitScope(req.Scope), client)` → 400 invalid_scope gate — **PASS, byte-accurate**

| Cited seam | Actual code | Verdict |
|---|---|---|
| CIBA `handle_ciba.go:306–308` | `grantedScopes, err := GrantedScopes(SplitScope(req.Scope), client)` → `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))` | Symbol-identical; the template's `oauth.` qualification is *required* (generated package is external to `protocols/oauth`). `cibaRequest.Scope` is the wire `scope` field (`:118`) |
| CC `token_client_credentials.go:38–40` | `oauth.GrantedScopes(scopes, client)` → same plain body; `scoperegistry.RejectUnregistered(...)` post-resolution at `:46` | Exact (`:38`/`:40`/`:46` citations correct) |
| Oracle-safe shape | `core.ErrorBody` = plain `{"error": code}` (`shared/core/error_body.go:11–17`), no `trace_id` | Both precedents use exactly this form |
| Post-auth placement | CC comment: gate "is not a pre-auth probe"; `dispatchCustomGrant` runs at `server_token.go:144` only after `handleToken` gates; custom-grant `Handle` is post-auth by construction | Claim accurate |
| "the SAME gate every built-in issuance entry applies" | `oauthvalidate.GrantedScopes` doc + grep: authcode/device/refresh/jwt_bearer/saml2_bearer/ciba/exchange/CC all apply it | Accurate, not over-broad |

## (2) Roles/TenantID teaching — **PASS with 2 wording caveats (must fix both)**

- `buildAccessPayload` stamps `TenantID: subject.TenantID` unconditionally (`issue_payload.go:46` region); `Roles` emitted only when `len(subject.Roles) > 0` (`applyOptionalClaims`, non-empty guard + defensive copy). `TenantID: client.TenantID` is CC's exact literal (`token_client_credentials.go:44`); `core.Subject` has `TenantID`/`Roles` (`types_token.go`), `sso.Subject = core.Subject` (alias `interfaces/sso/aliases.go:132`). **Accurate.**
- **Caveat A — "AMR guard" is imprecise.** The guard is `len(subject.Roles) > 0`; the code comment says "same guard+copy discipline as AMR" — not that roles emission is AMR-conditioned. Suggest: "emitted as top-level `roles` only when non-empty — same guard discipline as the AMR claim".
- **Caveat B — the claim-source conflation.** The server's actual mint-path roles source is `subjectRoles` → TenantUserStore roster (`interfaces/sso/server_oauth.go:227`), *not* `permissions.Provider.Roles`. The `accessors_handlers.go:104` call (`s.permissions.Roles(ctx, userID, clientID)`) feeds **conditional-access groups**, returns `[]permissions.Role` (structs, `provider.go:38`), and projects `role.Code`. The design's accessor `([]string, error)` is a *hypothetical handler dependency* mirroring the shape — defensible as a scaffold pattern, but the sentence "populated from a permissions.Provider.Roles(...) accessor wired the way accessors_handlers.go does it" is not byte-accurate as a claim about the server seam. Fix: add one sentence distinguishing pattern from mint path, e.g. "(the server's own mint path resolves codes from the TenantUserStore roster via `subjectRoles`; a custom grant with no roster access may mirror the `(ctx, userID, clientID)` accessor shape of `permissions.Provider.Roles` at `accessors_handlers.go:104`, projecting `role.Code` to `[]string`)."

## (3) Prose-only internal-mint RejectUnregistered requirement — **UNRESOLVED (the task's hard gate)**

The design states "any scope this handler mints INTERNALLY must pass that same RejectUnregistered check ... (token_client_credentials.go:46)" but the example code does **not** show it and the comment does **not** explicitly scope it out — neither branch of the required disjunction is satisfied. The gate itself is real and enforced (`scoperegistry/reject.go` contract: "Callers MUST invoke this on EFFECTIVE scopes (post-resolution, pre-issuance): the dispatch seam sees only request-borne scopes"; CC:46 is the precedent), so the teaching is not *false* — it is merely unanchored. **Recommended resolution (branch b, minimal surface, no import change):** add an explicit scoping sentence to the step-2 note: "This example covers only request-borne scopes; the internal-mint registry check is intentionally not shown — a handler that composes scopes beyond the request MUST run `scoperegistry.RejectUnregistered` on the effective set before issuance, exactly as `token_client_credentials.go:46` does (the dispatch seam cannot see them)." Branch (a) — showing the call — is viable but drags a `ScopeRegistry()` dep + `protocols/oauth/scoperegistry` import into the example.

## (4) No bypass + symbol existence — **PASS**

- **No bypass taught:** issuance passes `grantedScopes`; the `}, scopes)` raw tail (today's template, line 208 — the exact regression) is banned by the §4.2 helper. All error bodies are plain `core.ErrorBody(core.ErrX)` (`ErrInvalidScope`, `ErrInternal`, `ErrNoTokenStrategy`); no `ErrorBodyDesc`/`ErrorBodyWithTrace`, no trace_id, no detail leaks.
- **Every cited symbol exists:** `sso.WithScopeRegistry` (`options_misc.go:494`); `oauth.scope_registry.enabled` (`config_oauth2.go:124` yaml `enabled`, `config-reference.md:20`, `error-codes.md:298`); `rejectUnregisteredScopes` (`server_token.go:203`, called `:132` before `denyTokenScopeCombo :137` and `dispatchCustomGrant :144`); `scoperegistry.RejectUnregistered` (`reject.go:31`); `oauth.GrantedScopes`/`SplitScope` (`aliases.go:119–120`); `core.ErrInvalidScope` (`errors.go:170`, registered `error-codes.md:298`); `core.ErrNoTokenStrategy` (`errors.go:115`, `error-codes.md:796`); `core.ErrInternal` (`errors.go:95`); `TokenRequest.Scope` (`oauthwire/token_request.go:20`); `Client.AllowedScopes`; `TokenIssuer.Issue(ctx, *Subject, []string)` (`spi.go:246`); `Subject.{ID,ClientID,TenantID,Roles}`.
- **Red-first proof holds:** current template contains zero of the four markers and exactly one banned tail → §4.2 helper fails red as designed.
- **Contract helpers compatible:** new text has no `"/..."` literal, no `/authenticate`, no `8080`; all three error codes are registered; `scaffold_contract_test.go` (untracked, present) provides `generatedFile` + the `assert*` helpers the design's wiring reuses; the new helper needs only `strings`/`testing` (both imported).

## Required fixes before landing

1. **(3) — hard:** add the explicit internal-mint scoping sentence (or show the `RejectUnregistered` call).
2. **(2A):** replace "— AMR guard" with "— same guard discipline as the AMR claim (non-empty only)".
3. **(2B):** add the pattern-vs-mint-path distinction + `role.Code` projection note to the step-3 comment (and optionally the §4.1(a) TODO).

With those three deltas, the teaching is byte-accurate to every seam it cites; nothing else in the §4.1(b) text drifted from the server.
