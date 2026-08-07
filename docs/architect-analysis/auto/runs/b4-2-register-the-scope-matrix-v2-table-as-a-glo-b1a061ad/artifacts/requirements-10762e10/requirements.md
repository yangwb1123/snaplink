Requirements spec complete and written to the pipeline output path:
`docs/architect-analysis/auto/runs/b4-2-register-the-scope-matrix-v2-table-as-a-glo-b1a061ad/artifacts/requirements-10762e10/requirements.md`

## Verification results (all citations checked against HEAD)

**Confirmed exactly as cited:**
- `protocols/oauth/oauthvalidate/scope.go:80` — `GrantedScopes` starts at :80; rule 2 (:83-88) empty allowlist = unrestricted pass-through; grep for `ScopeRegistry`/`scope-matrix` across all `.go` files: zero hits (registry truly absent)
- `interfaces/sso/server_token.go:122` — scope split in `dispatchTokenGrant` (:121-125), the shared seam for all 7 `/token` grants, no registry check
- `internal/handler/tokengrant/token_client_credentials.go:34-38` — exact `GrantedScopes` → 400 `invalid_scope` + "Empty allowlist = unrestricted" comment
- `cmd/snaplink-billing/auth.go:27-58` — `contractRouter` machine map; `adminScopeGate` → 403 `insufficient_scope`
- `docs/campaigns/implementation-gate.md:12` — B4-2 row (T-8(d)); dependency rows B3-5/B5-2 verified; proposal `audit-contract-batch-snaplink.md:13` confirms "interface + Memory impl, optional wiring (unwired = byte-compatible), table contents [PROPOSED]"

**Corrections/findings that shaped the spec:**
- Billing scope constants live in `interfaces/commerce/consts.go:24-27` + `interfaces/metering/consts.go:12-13`, plus a third owner: relay scope `audit:event:write` (`cmd/snaplink-billing/config.go:22`, exact-enforced :360) — the spec pins all eight matrix scopes with sources
- No global scope validation exists at `/token` today (scope-count cap is login-only, `server_login_gates.go:318`) — gap confirmed
- Oracle safety is structural: client auth runs before `dispatchTokenGrant` in `handleToken` (:17-62), and "identical body" needs no new error code (both rejections emit `ErrorBody(ErrInvalidScope)`)
- `openid`/`device_sso` are allowlist-bypass triggers (`consts_wire.go:241,246`) and must bypass the registry too
- `test/scope_authorization_test.go` uses unregistered scopes (`anything`, `api:read`) — safe because the registry is opt-in (unwired default = byte-compatible), which is how acceptance #2's regression guarantee holds

**Acceptance preserved and made testable:** T-8(d) mapped to concrete wired-registry e2e tests (identical-body proof for allowlisted vs empty-allowlist clients, eight-scope mint 200s, billing no-403 via `serveWithClaims` pattern); regression anchored to `TestGrantedScopes` + default-unwired suite; matrix assertion as a registry unit test pinning the eight-scope set against the three constants files. Scope kept tight: `/token` only — discovery interplay and `admin:*`-as-matrix-entry flagged as design-stage input, not acceptance.
