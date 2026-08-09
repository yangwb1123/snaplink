All checks complete. Here is the verification report:

## AGENTS.md §5.6 verification — all four contract surfaces resolved

### 1. `docs/config-reference.md:20` covers the scope_registry block — ✅ line-exact
Line 20 is precisely the `oauth.scope_registry.{enabled,matrix,extra_scopes}` row. It already documents everything the change touches: enablement semantics, the built-in nine-scope table, protocol-scope pre-seeding, `extra_scopes` as resource-scopes-only feeding the registry (never discovery), boot-time-only, the `sso-ctl config validate` membership gate, rollback, and "no new error surface". The knob is pre-existing — R3 only adds **values** to it in one deploy tree, so no schema row is needed.

### 2. The three provisioner scopes need NO listing in either doc — ✅
- **config-reference.md**: the scope strings are *already documented* at **line 879** (`audit:platform:cross_tenant audit:policy:write`, billing-retention client) and **line 946** (provisioner's fixed, non-configurable `audit:platform:cross_tenant audit:policy:read audit:policy:write`). The reference documents the stock schema, not per-tree values; the built-in matrix it enumerates deliberately excludes these (compose provisions its own 8-row matrix + extras, which R5 pins).
- **feature-matrix.md**: capability rows already exist — line 47 (Audit Governance desired-state provisioner, standalone-binary) and line 135 (Global scope registry scope-matrix-v2). The matrix holds no scope-*value* rows; the three tokens are values of an existing knob, not a new capability.
- Requirements §10's "not applicable (already documented at lines 879/946)" claim is accurate — verified against both lines.

### 3. `docs/error-codes.md` — genuinely no update needed ✅
Line 298's `invalid_scope` row already carries the registry condition verbatim: *"OR (when `oauth.scope_registry.enabled` is set) an effective `/token` scope is not registered by the global scope registry — same plain body `{"error":"invalid_scope"}`, no new error surface, oracle-safe."* No new `Err*`, no new code, no shape change.

### 4. `docs/openapi.yaml` — genuinely no update needed ✅
Change is 3 additive YAML values + test files: no endpoint, request/response shape, header, or error-code change. `/token` 400 (openapi.yaml:1144-1161) is the generic `ErrorResponse` with an illustrative code list; `invalid_scope` already appears in the spec's prose (line 7090). Requirements §10's "no endpoint, no `Err*`" is accurate.

## The two nits — located, corrected, and now tracked in-place

**Nit 1 — command-path typo.** Attribution correction: the design doc has **no §11** (it ends at §9, 176 lines). The typo lives in the **requirements doc §11 (line 203)** plus the same bad path in **§6 line 132** (`go test . -run 'TestBuildApp_ScopeRegistry'` — runs zero tests; the tests are in `cmd/sso-server/`, package main). The design doc's own §7/§8 already used the correct path. **Fixed both occurrences** to `go test ./cmd/sso-server/ -run 'TestBuildApp_ScopeRegistry'` (with a comment noting the package), so the implementer's §11 run is a real gate.

**Nit 2 — srClientAny citation.** Design §8 "Verified seams" cited `line 56-60`; the actual nil-allowlist seed is **lines 60-65** (60 `clients.AddSeed(&sso.Client{`, 61 `ID: srClientAny…`, 64 nil-allowlist comment, 65 `})`) — verified against `test/scope_registry_test.go`. **Fixed** to `lines 60-65`.

**Net result:** §5.6 is fully satisfied with zero contract-doc edits required for the implementation; the requirements doc's §10 "not applicable" entries are all verified correct. No Go files touched, so no mandatory post-edit gates apply; the two doc corrections are in the campaign's untracked worktree files and will ride the next pi-batch stage commit.
