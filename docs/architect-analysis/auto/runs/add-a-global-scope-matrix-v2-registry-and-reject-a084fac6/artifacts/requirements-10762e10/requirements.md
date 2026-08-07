Requirements spec written to the pipeline-pinned output path:

**`docs/architect-analysis/auto/runs/add-a-global-scope-matrix-v2-registry-and-reject-a084fac6/artifacts/requirements-10762e10/requirements.md`**

## Verification outcome — 3 of the direction's core claims are stale

Every cited symbol was checked against the tree:

| Citation | Verdict |
|---|---|
| `oauthvalidate.GrantedScopes` rule 2 (empty allowlist ⇒ UNRESTRICTED), scope.go:87-93 | **Verified** |
| `server_token.go:122` `dispatchTokenGrant` + `strings.Split` | **Verified**, but "no registry gate" is **stale** — the `rejectUnregisteredScopes` seam now runs at :129-135 before `denyTokenScopeCombo` |
| `server_discovery_config.go:339` `ScopesSupported` from client snapshots | **Verified**, but snapshots are now pre-filtered via `FilterRegistered` (server_discovery_cache.go:170) |
| `errors.go:170` `ErrInvalidScope = "invalid_scope"` | **Verified** |
| "No registry symbol exists" | **Contradicted** — the full surface exists (uncommitted, from prior B4-2 campaign runs): `protocols/oauth/scoperegistry/` (frozen `Memory`, fail-closed pattern grammar), `interfaces/scopecontract.Matrix()` (8 scopes), `WithScopeRegistry`, per-branch effective-scope checks in all 8 grants, config `oauth.scope_registry.{enabled,extra_scopes}`, docs at config-reference.md:20 / error-codes.md:298 |
| `server_discovery.go:258` `authzErrorBody` (RFC 9207 `iss`) | **Verified**; login uses `authzErrorBodyWithState` (server_login_gates.go:320, server_login_resolve.go:255) |

## Acceptance preserved and made testable (AC-1..AC-5)

- **AC-1** (/token 400 with empty AllowedScopes): **satisfied** — `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody`, `_MixedReplicaDivergence`, refresh-chain fail-closed subtest.
- **AC-2** (/auth/login RFC 9207 body): **not satisfied as written** — login is deliberately outside registry jurisdiction (pinned A-8b; unregistered login-minted scopes fail at next refresh). Preserved with the deviation recorded for the design gate to confirm or reject.
- **AC-3** (all matrix scopes mint): **satisfied** — `TestScopeRegistry_MatrixScopesMintable` (8/8 + `admin:*` prefix).
- **AC-4** (discovery equals matrix): **satisfied in the "augmented" reading** (filtered union, never advertises a rejected scope); literal matrix replacement not adopted.
- **AC-5** (vault/aero-id no-403): cross-repo; in-repo proxy `TestScopeRegistry_AuditRelayScopeMatchesBillingDefault` pins `audit:event:write`.

Evidence run: `go test ./test/ -run TestScopeRegistry -v` → **9/9 PASS**; `go test ./protocols/oauth/scoperegistry/` → ok. Doc-only artifact — no `.go` edits, no build gates triggered.
