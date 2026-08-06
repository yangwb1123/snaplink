Audit complete. Report written to `docs/architect-analysis/auto/runs/b4-2-register-the-scope-matrix-v2-table-as-a-glo-b1a061ad/artifacts/adversarial_review-9c87f3a7/meta/security_engineer.md` (verified against HEAD `ea351a86`; no registry code exists yet — pure design audit).

## Verdict summary

**1. "rejectUnregisteredScopes can never mint an unregistered scope" — NOT SUSTAINED as specified.** The dispatch-level seam's only input is `req.Scope` (server_token.go:121-125), but 4 of the 8 switch branches mint store-bound scopes the request never carries:
- **authorization_code**: mints `info.Scopes` verbatim (`token_authcode.go:261-262`, `scopes = info.Scopes` with SA4009 nolint) — pre-wired at `server_finish_login.go:106`
- **refresh_token**: mints `info.Scopes` from the family (`token_refresh.go:359-365`) — the large window: a pre-enablement refresh token keeps rotating unregistered scopes for its whole TTL
- **device_code** (`token_device.go:199`), **CIBA** (`token_ciba.go:282`): same store-bound pattern
- **custom grants**: SAML2 rides `customGrantHandlers` (server_setup.go:271); third-party handlers can mint anything

The empty-request allowlist guard is necessary but insufficient: rule-4 defaults (`AllowedScopes − openid`) are computed inside handlers; a dispatch-level guard must replicate rule 4 and still cannot see store-bound defaults. Fix: one shared `RejectUnregistered(effectiveScopes)` at the 8 effective-scope points post-resolution, pre-issuance. Also: the guarantee must be re-scoped to "/token grants" — direct mints exist at `server_finish_login.go:185`, webauthn:164, kerberos:253.

**2. `admin:*` prefix semantics — VERIFIED.** `scopePresent` (evaluate.go:203-211, trailing-`*`) and `permissions.Matches` (matcher.go:17-29, `:*`-only) agree for `admin:*` in both directions, including billing's `matchesRequiredScope` over token scopes (auth.go:172-178). Restrict registry patterns to exact-or-`:*` (non-`:*` trailing-star patterns diverge).

**3. ErrorBody drift — VERIFIED necessary and sufficient.** All grant rejections emit plain `core.ErrorBody`; `errorBody` (handlers.go:399) adds `trace_id`. The A-1b pin (emit `core.ErrorBody`, 400, post-auth) yields byte-identical `{"error":"invalid_scope"}`. New finding: the tokenpolicy seam emits the trace shape — pin the registry seam **before** `denyTokenScopeCombo` for one deterministic invalid_scope shape.

**4. `extra_scopes` — VERIFIED validator-only** (no config→claims path; all expansion invariants live in subset/intersection/remove-only checks untouched by the registry), contingent on 5 prescriptions: reject bare `"*"` (silent fail-open), startup-fail on malformed config (precedent: billing/config.go:360), registry errors 500 never pass, `extra_scopes` feeds only the registry (discovery advertises `openid ∪ AllowedScopes` — drift family), and the refresh-chain gap from #1.

**Blocking for implementation**: per-branch effective-scope checks, explicit "/token grants" scoping, seam ordering pin, `extra_scopes` validation, and a concrete OIDC-standard-scope mechanism (`profile`/`email`/`offline_access` are neither bypass constants nor matrix members).
