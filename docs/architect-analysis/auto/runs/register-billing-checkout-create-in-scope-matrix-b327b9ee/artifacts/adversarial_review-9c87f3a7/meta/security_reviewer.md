All verification complete. Here is the report.

---

# Verification verdict

**All claims in the question verified against executable code. No blocking drift.** The change cannot widen minting through the named grant paths beyond the effective-scope allowlist points; no existing client configuration flips privilege state; the oracle-safe shape and `permissions.Matches` drift guard hold on every registry-consulting path.

## 1. Registry consultation surface — all paths, all post-allowlist

`scoperegistry.RejectUnregistered` is the *only* consultation seam (10 call sites: 1 dispatch filter + 9 effective-scope points). Every site runs on scopes already resolved by the branch's pre-existing allowlist gate:

| Path | Registry check | Effective set is bounded by | Verified at |
|---|---|---|---|
| Authorization-code | `info.Scopes` (code-bound) | `GrantedScopes` at login; granted set baked into stored code (`IssueAuthCode` copies `p.Scopes`); request scopes ignored at exchange (SA4009 intentional) | `token_authcode.go:88`; `server_finish_login.go:106-112`; `auth_code_handler.go:166` |
| Refresh rotation | `grantScopes` | `refreshResolveScopes`: omitted → family set (itself allowlist-constrained at original mint); supplied → strict subset (`IsScopeSubset`), expansion → `invalid_scope` | `token_refresh.go:167`, `:380-392` |
| Token exchange (direct) | `st.scopes` | subject-token scopes ∩ downstream client allowlist (`GrantedScopes`); empty subject stays empty (no rule-4 escalation); scope-less subject can't fall through to client entitlement | `token_exchange_stages.go:353` (`tokExResolveScope`); `token_exchange.go:451` (cross-tenant: guest `Roles` narrowing → registry) |
| Device flow | `dc.Scopes` (code-bound) | `GrantedScopes` at device-init; token request carries no scope | `token_device.go:92`; `server_device.go:172` |
| CIBA (poll + push share the builder) | `r.Scopes` | `GrantedScopes` at persist; stored as the granted set | `token_ciba.go:116`; `handle_ciba.go:306-319` |
| client_credentials | `grantCCScopes` | `GrantedScopes` (incl. rule-4 default) | `token_client_credentials.go:46` |
| JWT/SAML2 bearer | `grantScopes` | `GrantedScopes` | `token_jwt_bearer.go:61`, `token_saml2_bearer.go:63` |
| Dispatch seam | request-borne scopes | pure filter (reject-only, pre-branch); store-bound branches covered by the per-branch checks | `server_token.go:204` |

**Widening mechanics:** adding the row flips exactly one boolean — `Memory.Registered("billing:checkout:create")` false→true. The registry is a pure filter (never adds scopes), so on every branch the mintable set widens by exactly that one exact scope, and only where the branch's own resolution already entitled it. The named paths therefore cannot mint checkout for a client whose config does not permit it. Note the one inherent property (unchanged by this row): a client with an **empty `AllowedScopes`** is "unrestricted" (rule 2, `scope.go:88-92`) — under an enabled registry it may mint any registered scope on any branch, including via exchange (`boundScopes` = subject scopes, no narrowing). That is the same allowlist semantics the design cites for client_credentials, not a new entitlement category introduced by the row.

Txn-token (RFC 9321) minting does not consult the registry and takes no scope parameter — unaffected.

## 2. No client configuration changes privilege state

- **Registry disabled vs enabled:** nil/unwired and `enabled:false` → `RejectUnregistered` no-op (byte-compat baseline, pinned by `TestScopeRegistry_DefaultPathUnwired_ByteIdentical`); config membership check runs only when enabled (`config_oauth2.go:47`). The row is inert in both disabled states.
- **Explicit-matrix vs built-in:** `MatrixOrDefault` returns the provisioned matrix when non-empty, else the built-in — both the runtime construction (`build_stores.go:306`) and the config gate (`config_oauth2.go:52`) consult the same function, so the validator can never disagree with `/token` (pinned by `TestBuildApp_ScopeRegistryProvisionedMatrixReplacesBuiltin`). Explicit-matrix deploys see zero change; only default-matrix deploys gain the row.
- **extra_scopes overlap:** `NewMemory` is set-semantics (duplicate → no-op, never a shadow/error); `validateScopeRegistry` cross-checks duplicates only within `Matrix`. A deploy already listing the scope in `extra_scopes` keeps identical mintability. Verified by the passing `membership accepts matrix, protocol, extra and wildcard` subtest (which already uses `extra_scopes: ["billing:checkout:create"]`).

## 3. Oracle-safe shape and drift guard

- **Shape:** all 10 call sites go through the shared helper → `core.ErrorBody(core.ErrInvalidScope)` = plain `{"error":"invalid_scope"}`, status 400, no `trace_id` (`reject.go:31-42`, `error_body.go:11`). This is byte-identical to the branch allowlist rejections (`GrantedScopes` error → same call), so registry-state and allowlist-state are indistinguishable — an enabled registry without the row and an allowlist rejection emit the same body. The dispatch seam's comment pins the ordering rule (before tokenpolicy's trace-wrapped `errorBody`).
- **Drift guard:** `Registered` mirrors `permissions.Matches` exact-or-`domain:*` (`registry.go:118-128` vs `matcher.go:17-32`). The registry is a strict subset (rejects bare `*` that `Matches` allows — fail-closed, never wider than enforcement). The new row is an exact literal, so `Registered` (exact) and `Matches` (exact) agree both directions. Same-shape asymmetry would be a compile error via the structural aliases.

## 4. Test-pin cross-checks (baseline all green)

- `TestScopeRegistry_MatrixScopesMintable` (test/) iterates `scopecontract.Matrix()` on an unrestricted client → auto-covers a new row (200 + exact scope claim). PASS.
- `TestScopeRegistry_UnregisteredRejected_ByteIdenticalBody` uses `billing:typo` → unaffected. PASS.
- `TestScopeRegistry_RefreshChainPreservesOIDCScopes` incl. pre-enablement-family-fails-closed-at-rotation. PASS.
- `config/scope_registry_test.go:116-129` "membership rejects unregistered allowed_scope" exists exactly as cited and **will break** when the row joins `Matrix()` (this is the design's R3 rebase target). `membership inactive when disabled` confirms disabled = no check.
- `TestMatrixShape` (exact 8-row pin) and `TestMatrixPinnedToSourceConstants` PASS today; the former breaks on row addition, exactly as the design names.
- `go build ./... && go vet ./...` clean.

**One count note:** the design cites "client_credentials + 8 other effective-scope points" (9). The code has 9 effective-scope points plus the dispatch seam (request-borne, not an effective-scope point) = 10 call sites — consistent with the design's wording, not a discrepancy.

## 5. Pre-existing gate failures (separate, untouched by this change)

`go test -run 'TestMaintainability_|TestArchitecture_' .` fails on three pre-existing violations unrelated to this surface: `TestMaintainability_FileSizeBudget` (`infrastructure/defaultimpl/ed25519_jwt_issuer.go`, 539 lines), `TestArchitecture_DirectoryDepth`, `TestArchitecture_DirectorySubdirFanout`. No files in the scope-registry/checkout surface are implicated; I made no edits. Report as drift separately from the feature work.
