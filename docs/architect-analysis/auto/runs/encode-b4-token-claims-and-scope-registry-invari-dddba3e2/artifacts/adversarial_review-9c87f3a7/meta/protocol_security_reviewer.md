Verification complete. I checked every anchor against the repo at HEAD `4d93b696` (design-stage commit) and ran marker simulations against the actual template text. Report:

# Wire-contract verification: B4 grant-scaffold design

## Claim 1 — invalid_scope branch: 400 + plain `core.ErrorBody` — ✅ teaching correct, ⚠️ gate under-pins it

**The taught shape is byte-semantic-identical to every real site:**

| Anchor | Real code | Match |
|---|---|---|
| `handle_ciba.go:306-308` | `grantedScopes, err := GrantedScopes(SplitScope(req.Scope), client)` → `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))` | ✅ (template's `oauth.` prefix is the correct qualification for the generated package) |
| `token_client_credentials.go:38-40` | same `oauth.GrantedScopes` → 400 `core.ErrorBody(core.ErrInvalidScope)` | ✅ |
| `scoperegistry/reject.go:37-39` | seam's own write: `ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidScope))` | ✅ |
| `server_token.go:191-198` | doc: "writing the plain invalid_scope body (`core.ErrorBody` — never `errorBody`, whose trace_id would drift the byte-compat baseline)" | ✅ precise: the sentence is 191-192, doc block 189-202, func 203-204; `errorBody` (handlers.go:399) = `ErrorBodyWithTrace` → adds `trace_id`, `core.ErrorBody` (error_body.go:11) = `{"error": code}` only |

Current template confirmed as the violating pattern: zero `GrantedScopes(`/`SplitScope(`/`core.ErrInvalidScope`/`invalid_scope` in `grantTemplate`; single `issuer.Issue(` at idx 2263 passing `}, scopes)` at idx 2439.

**Two concrete gaps (both were raised by reviewers; neither is recorded in the delivered design summary):**

1. **A1 does not pin the shape.** The three markers (`GrantedScopes(`, `SplitScope(`, `core.ErrInvalidScope`) pass if a regression swaps in `errorBody(ctx, ...)` (trace-wrapped) or status 500. The composite `core.ErrorBody(core.ErrInvalidScope)` is a contiguous string — add it as the A1 marker.
2. **R3's literal order-check wording is vacuously true.** R3 writes `strings.Index(core.ErrInvalidScope) < strings.Index("issuer.Issue(")`. Since `core.ErrInvalidScope` is the constant `"invalid_scope"` (errors.go:170), this searches for the bare wire string — **absent from the generated file** (simulation: idx −1, since the file contains `core.ErrInvalidScope`, not `invalid_scope`). −1 < 2263 is true even with the branch deleted. The helper must use the **quoted literal** `"core.ErrInvalidScope"`; the helper code is not committed, so an implementer following R3 literally ships a dead order gate.

## Claim 2 — D6 `}, grantedScopes)` — ✅ load-bearing, verified semantics

- The marker requires the Subject literal to close and `grantedScopes` to be Issue's scope argument. Net-new: `grantedScopes` count in the current template is 0; the violating pattern today is `}, scopes)` (idx 2439). Passing `req.Scope` or `scopes` fails the marker; the `}, ` prefix disambiguates from `len(grantedScopes)`.
- Single-issuance template makes it exact: `issuer.Issue(` occurs exactly once (idx 2263). A B4-1 handoff adding a field (e.g. `Roles: roles,`) before the close keeps `}, grantedScopes)` matching.
- Caveats, all live at implement time because the proposed template text is **not committed** (the artifact is the 26-line summary): the marker is presence-only (a note quoting the correct issuance satisfies it — window-scope the search to the example block), and any doc-comment containing `issuer.Issue(` above the branch flips A1/A3 spuriously — add the `count("issuer.Issue(") == 1` guard. All markers are asserted against **comment text** in the generated file (the example is a comment block) — that's the design's stated intent (ALT-1 rejected), but it means the gate certifies teaching, not generated enforcement.

## Claim 3 — roles/tenant_id surface — ✅ deferral is mandatory, and the requirement's own R2 hedge is a mis-teach trap

Real surface verified:
- `Subject.Claims map[string]string` (types_token.go:164) → `buildAccessPayload` `Extra: subject.Claims` (issue_payload.go:26) → `json:"ext,omitempty"` (ed25519_types.go:26). **Claims today = the `ext` bag.** T-8(a) (implementation-gate.md row 1) demands top-level `{iss/aud/scope/client_id/tenant_id/roles}`. A template showing `Subject.Claims["roles"] = ...` teaches `ext.roles` — exactly the mis-teach.
- `Subject.TenantID` (types_token.go:231): doc is explicit — "Policy-input ONLY … **NOT a token claim** — issuers emit only fields they enumerate in buildAccessPayload." `TenantID: client.TenantID` teaching is safe (it's the ClampingIssuer policy input; the real CC grant sets it at token_client_credentials.go:49), but the template must not claim it emits a claim.
- Seam invariants verified: `rejectUnregisteredScopes` (server_token.go:203) called at :132 before `dispatchCustomGrant` (:144); `RejectUnregistered` checks `reg.Registered(s)` only (reject.go:37-39) — registry *name* membership, **never** `client.AllowedScopes`. So the note's "why the gate survives the seam" beat is factually supported, but R1's speced note text omits it, and the design's fuller wording is uncommitted. The "effective-set before issuance" beat matches `RejectUnregistered`'s own contract ("Callers MUST invoke this on EFFECTIVE scopes (post-resolution, pre-issuance)").
- `permissions.Provider.Roles(ctx, userID, clientID) ([]Role, error)` (provider.go:36-38) — user-scoped, client-scoped, error-returning (ErrUserNotFound); real usage at accessors_handlers.go:103. A3's bare `Roles(` marker is deliberately loose (any `*Roles(` call passes) — fine as a B4-1-survival tradeoff, but must be recorded as such.

**Gap:** R2's hedge "hand them into the Subject (via `Subject.Claims` or the dedicated Subject field B4-1 defines…)" is a live trap — rendered literally into the template, it mis-teaches. Step 2 must carry an explicit deferral comment (reviewer F7); neither the wording nor the F7 requirement appears in the deliverable.

## Also verified

- Stale citation: `interfaces/sso/options_saml2_bearer.go` nonexistent; real `saml2BearerHandler` at server_setup.go:271/275/283. The fix lives in the doc comment **outside** the raw string → unpinnable by artifact markers (review-only, as stated).
- `handle_par.go` invalid_scope branch: exact lines 197-198 (JSON write + return; the design's "197-200" is the branch+close; the requirement's ":198" is the return — both non-material).
- Budgets: templates_handler.go 215 lines, scaffold_build_test.go 122 lines (< 500); filename rule generate.go:82 `"%s_grant.go"` confirmed. Helper cyclomatic ≈10 is unverifiable (code absent from repo).
- A2 (`TenantID: client.TenantID`) already exists in the template (idx 2405) — A2 is a pin, not new teaching; correct as framed.

## Bottom line

The teaching text as speced is wire-accurate against all four real sites and the seam's own byte-compat baseline; D6 is sound and uniquely pins the issuance argument. The deliverable is a summary, so the load-bearing details (note wording, step-2 deferral, helper implementation) are unrecoverable and must be re-derived at implement time carrying four concrete requirements: (1) A1 uses the composite `core.ErrorBody(core.ErrInvalidScope)` marker; (2) the helper uses quoted literals, never bare `Err*` constants; (3) `count("issuer.Issue(") == 1` guard + window-scoped search; (4) step 2's roles handoff text explicitly defers to B4-1 instead of showing a `Subject.Claims` write.
