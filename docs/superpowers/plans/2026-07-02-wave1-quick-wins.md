# Wave 1 Quick Wins Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the nine S-effort, code-verified gaps from the 2026-07-02 roadmap ([2026-07-02-implementation-roadmap.md](2026-07-02-implementation-roadmap.md)): RFC 8414 discovery alias, invitation revocation, webhook HMAC signing, CAEP delivery retry, TopTenants endpoint, backup operationalization, postgres import target, alert rules, and the postgres config-reference matrix.

**Architecture:** Every task is an independent, individually committable slice on `main`. Code tasks follow the repo's hexagonal pattern (SPI change in `shared/core` → impls in `infrastructure/*` → thin handler in `interfaces/admin` or `interfaces/sso` → route const in `shared/core/consts.go`). No new packages are created, so no `layerName()` classification changes are needed.

**Tech Stack:** Go (parent module; `infrastructure/postgres` is part of the parent module — verified, no nested go.mod), modernc.org/sqlite, Prometheus rules YAML + Grafana JSON under `ops/deploy/`, `docs/openapi.yaml` (OpenAPI 3).

## Global Constraints

- File budget ≤ 500 lines; function ≤ 50 lines; cyclomatic ≤ 15; exemption lists are count-capped at zero growth — NEVER add an exemption (`maintainability_*_test.go`).
- Imports point down toward `shared/core` only (`architecture_layer_test.go`).
- No literal leaks: new paths/headers/event names go in `shared/core/consts.go` / `platform/audit/auditspi/event_types.go`, re-exported via the established alias files.
- Documented endpoint change → update `docs/openapi.yaml` in the SAME commit. New `Err*` code → `docs/error-codes.md` same commit. New config key → `docs/config-reference.md` same commit.
- Tests use real `Memory*` / sqlite in-memory stores — no mocks. Unit tests beside code; cross-server tests in `test/` (`package ssotest`).
- Post-edit verification after EVERY `.go` change: `go build ./... && go vet ./...` then `go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
- Do NOT run `make ci` (it rewrites AGENTS.md/.golangci.yml and installs a broken git hook). Use `make fmt vet race build proto-lint lint ci-modules` or the explicit go commands.
- Never violate oracle-leak / anti-enumeration invariants (AGENTS.md §3). No emojis anywhere.
- Commits: conventional (`feat(area):`, `fix(area):`, `docs:`), imperative subject, body explains why, trailer `Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>`.

---

### Task 0: Restore the committed gate baseline (BLOCKING — do this first)

**Verified 2026-07-02:** `go test -run 'TestMaintainability_|TestArchitecture_' .` FAILS at HEAD, before any Wave-1 work. Every other task's verification step depends on a green baseline. Do not start Tasks 1-9 until this passes.

**Confirmed failures:**
1. Stray root package `admin/v1/` — 21 tracked generated protobuf/gateway files that duplicate `gen/proto/admin/v1/` (the sanctioned, gate-exempt location). Zero importers outside itself (verified: `grep -rl 'snaplink/sso/admin/v1' --include='*.go' .` matches nothing outside `admin/`). It alone contributes 14 function-length violations and breaks the root-directory policy.
2. 12 genuine function-length regressions from recent commits: `cmd/sso-ctl/clientscmd/clients.go:runList` (51), `cmd/sso-ctl/sessionscmd/sessions.go:runList` (59), `cmd/sso-server/main.go:main` (52), `cmd/sso-server/main_servers.go:newGRPCServer` (81), `config/source.go:(*Loader).Load` (52), `interfaces/sso/server_finish_login.go:finishLogin` (51), `interfaces/sso/server_login.go:handleLogin` (101), `interfaces/sso/server_routes.go:buildMiddlewareChain` (53), `interfaces/sso/server_token.go:authenticateTokenClient` (62), `interfaces/sso/server_token.go:handleToken` (84), `interfaces/sso/sso_newserver.go:NewServer` (58), `shared/security/tls_client_auth.go:CertPublicKeyMatchesJWK` (51).
3. File-size budget: `interfaces/sso/server_token.go` (554), `interfaces/sso/options_misc.go` (549), `shared/core/types.go` (503) — all tracked and unmodified, i.e. committed over-budget.
4. Directory fanout regressions (verified via `go test -run 'TestArchitecture_Directory' -v .`): `interfaces/sso` 65 > frozen 57, `config` 28 > 26, `infrastructure/defaultimpl` 27 > 26, `shared/core` 24 > 23, `shared/security` 11 > 10 (unexempted), root subdirs 23 > 21 (removing `admin/` fixes one). The frozen ceilings are shrink-only — these regressed via recent commits. Resolution options per regression: move files into existing leaf sub-packages with re-export aliases (the facade technique from the dir-fanout campaign), or consolidate small sibling files; NEVER raise a ceiling.

- [ ] **Step 1: Remove the stray root package**

```bash
git rm -r admin/
go build ./... && go vet ./...
git commit -m "chore: remove stray root admin/v1 duplicate of gen/proto/admin/v1

The generated admin gateway package was committed at the repo root as
well as its sanctioned gen/proto location. The root copy is imported by
nothing, violates the root-directory policy, and alone accounts for 14
function-budget gate failures.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

- [ ] **Step 2: Re-run the full gate suite and record the remaining inventory**

Run: `go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory|TestMaxDepth|TestRoot' . -v 2>&1 | grep -E 'FAIL|exceed|over'`
Expected: the admin/v1 entries are gone; the remaining items match the lists above (adjust the following steps to what is actually reported).

- [ ] **Step 3: Split the three over-budget files**

Follow `docs/skills/split-large-file/SKILL.md` (extract cohesive blocks into new sibling files, never re-exempt):
- `interfaces/sso/server_token.go` (554) → move the client-authentication ladder (`authenticateTokenClient` + helpers) to a new `interfaces/sso/server_token_clientauth.go`.
- `interfaces/sso/options_misc.go` (549) → move the largest cohesive option group (identify by section comments) to a new focused `options_<group>.go` file.
- `shared/core/types.go` (503) → move one cohesive type family (e.g. the token-related types) to a sibling `types_<family>.go` in the same package (import-path neutral).

After each split: `go build ./... && go vet ./... && go test ./<package>/ -race` — behavior-preserving moves only.

- [ ] **Step 4: Extract sub-functions for the 12 over-budget functions**

Follow `docs/skills/refactor-high-complexity.md` per function: extract the largest self-contained block(s) into named private helpers until the parent is ≤ 50 lines. Behavior-preserving only; run that package's tests with `-race` after each function. Suggested one commit per package touched: `refactor(<area>): restore function-length budget`.

- [ ] **Step 5: Fix fanout regressions if still reported**

If `shared/security` is over the 10-file cap, move the least-coupled implementation file into the `shared/security/securityverify` leaf (already 5 files) with a re-export alias in `shared/security/aliases.go`, following the facade technique used by prior fanout splits.

- [ ] **Step 6: Final verification + commit**

Run: `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_|TestDirectory|TestMaxDepth|TestRoot' . && go test ./... -race -count=1`
Expected: ALL PASS. Then the Wave-1 tasks below can begin.

---

### Task 1: RFC 8414 authorization-server metadata alias

**Files:**
- Modify: `shared/core/consts.go` (369 lines — insert after `PathProtectedResourceMetadata`, ~line 64)
- Modify: `interfaces/sso/aliases.go:367` (470/500 lines — +1 line only)
- Modify: `interfaces/sso/server_discovery.go` (421/500 — add `mountDiscovery` after line 17)
- Modify: `interfaces/sso/server_routes.go:111` (483/500 — 1:1 line replacement ONLY, see gate warning)
- Test: `interfaces/sso/rootcov_discovery_test.go` (232 lines)
- Modify: `docs/openapi.yaml` (insert after line 2288, before `/.well-known/openid-federation:` at line 2290)
- Modify: `docs/feature-matrix.md:19` (add RFC 8414 alias row next to the OIDC Discovery row)

**Interfaces:**
- Consumes: `func (s *Server) handleOIDCDiscovery(ctx HandlerContext)` (`interfaces/sso/server_discovery_config.go:67`) — UNCHANGED; its body cache is keyed only by `requestBaseURL`, so both routes share one cache entry (byte-identical bodies and ETags for free). `const PathOIDCDiscovery = "/.well-known/openid-configuration"` (`interfaces/sso/server_discovery.go:17`).
- Produces: `core.PathOAuthAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"` + sso re-export `sso.PathOAuthAuthorizationServerMetadata`; `func (s *Server) mountDiscovery()` registering both discovery routes.

**GATE WARNING:** `mountCoreOAuthOIDC` (`server_routes.go:107-156`) is EXACTLY 50 lines — at the function-length cap with a zero-growth exemption list. Do NOT add any line inside it. Replace line 111 one-for-one with `s.mountDiscovery()`.

- [ ] **Step 1: Write the failing test**

Append to `interfaces/sso/rootcov_discovery_test.go` (add `bytes` to imports):

```go
// TestRcovDisc_RFC8414Alias verifies the RFC 8414 §3 well-known alias serves
// the exact same metadata document as the OIDC discovery path — same handler,
// same base-URL-keyed body cache, byte-identical bytes and ETag.
func TestRcovDisc_RFC8414Alias(t *testing.T) {
	t.Parallel()
	s := rcovNewServer(t)

	get := func(path string) (int, []byte, string) {
		t.Helper()
		resp, err := http.Get(s.http.URL + path)
		if err != nil {
			t.Fatalf("GET %s: %v", path, err)
		}
		raw, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, raw, resp.Header.Get("ETag")
	}

	codeOIDC, bodyOIDC, etagOIDC := get(sso.PathOIDCDiscovery)
	codeAlias, bodyAlias, etagAlias := get(sso.PathOAuthAuthorizationServerMetadata)
	if codeOIDC != http.StatusOK || codeAlias != http.StatusOK {
		t.Fatalf("status: openid-configuration=%d oauth-authorization-server=%d, want 200/200", codeOIDC, codeAlias)
	}
	if !bytes.Equal(bodyOIDC, bodyAlias) {
		t.Errorf("alias body differs from openid-configuration body")
	}
	if etagOIDC != etagAlias {
		t.Errorf("ETag mismatch: oidc=%q alias=%q", etagOIDC, etagAlias)
	}
	var doc map[string]any
	if err := json.Unmarshal(bodyAlias, &doc); err != nil {
		t.Fatalf("alias body not JSON: %v", err)
	}
	if doc["issuer"] == nil || doc["authorization_endpoint"] == nil || doc["token_endpoint"] == nil {
		t.Errorf("alias doc missing RFC 8414 required fields: %v", doc)
	}
}
```

(`rcovNewServer` is at `rootcov_flow_test.go:60` — real Memory* stores + `httptest.Server`.)

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./interfaces/sso/ -run TestRcovDisc_RFC8414Alias -v`
Expected: FAIL — compile error `undefined: sso.PathOAuthAuthorizationServerMetadata`.

- [ ] **Step 3: Add the path const + alias**

In `shared/core/consts.go`, immediately after `PathProtectedResourceMetadata` (same const block):

```go
	// PathOAuthAuthorizationServerMetadata is the RFC 8414 §3 well-known
	// path for OAuth 2.0 Authorization Server Metadata. Served by the SAME
	// handler as the OIDC discovery document — that document is a compatible
	// superset of RFC 8414 §2 metadata (clients ignore unknown fields), so
	// pure-OAuth clients (notably MCP agents, which resolve this suffix
	// rather than openid-configuration) can discover the AS without OIDC.
	PathOAuthAuthorizationServerMetadata = "/.well-known/oauth-authorization-server"
```

In `interfaces/sso/aliases.go`, next to the `PathProtectedResourceMetadata` re-export (line 367):

```go
const PathOAuthAuthorizationServerMetadata = core.PathOAuthAuthorizationServerMetadata
```

- [ ] **Step 4: Register the route via a new 2-route registrar**

In `interfaces/sso/server_discovery.go`, after the `PathOIDCDiscovery` const (line 17):

```go
// mountDiscovery registers the OIDC Discovery 1.0 endpoint plus its RFC 8414
// §3 alias. One handler serves both paths: the discovery document already
// carries every RFC 8414 field, and sharing the handler means both routes
// share the base-URL-keyed body cache, so responses are byte-identical.
// Extracted from mountCoreOAuthOIDC, which sits exactly at the 50-line
// function budget — the alias could not be added there.
func (s *Server) mountDiscovery() {
	s.router.GET(PathOIDCDiscovery, s.handleOIDCDiscovery)
	s.router.GET(PathOAuthAuthorizationServerMetadata, s.handleOIDCDiscovery)
}
```

In `interfaces/sso/server_routes.go` line 111, replace exactly one line:

```go
// before:
	s.router.GET(PathOIDCDiscovery, s.handleOIDCDiscovery)
// after:
	s.mountDiscovery()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./interfaces/sso/ -run TestRcovDisc -race -v`
Expected: PASS (all TestRcovDisc tests, including the new alias test).

- [ ] **Step 6: Post-edit gates**

Run: `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: all PASS (server_routes.go stayed 483 lines; mountCoreOAuthOIDC stayed 50).

- [ ] **Step 7: Update openapi.yaml + feature-matrix.md**

In `docs/openapi.yaml`, insert after the `/.well-known/openid-configuration` entry (its `"304"` response ends at line 2288), before `/.well-known/openid-federation:`:

```yaml
  /.well-known/oauth-authorization-server:
    get:
      tags: [discovery]
      summary: RFC 8414 OAuth 2.0 Authorization Server Metadata (alias).
      description: |
        Byte-identical alias of `/.well-known/openid-configuration` — the
        same handler serves both paths (same body cache, same `ETag`).
        Published for pure-OAuth clients (notably MCP agents) that resolve
        the RFC 8414 well-known suffix instead of OIDC discovery; the OIDC
        document is a compatible superset of RFC 8414 §2 metadata.
      operationId: getOAuthAuthorizationServerMetadata
      responses:
        "200":
          description: Live OIDC + RFC 8414 metadata (identical to /.well-known/openid-configuration).
          headers:
            Cache-Control:
              schema:
                type: string
              description: '`public, max-age=<ttl>` when caching is enabled.'
            ETag:
              schema:
                type: string
              description: Short sha256 prefix of the response body.
          content:
            application/json:
              schema:
                $ref: "#/components/schemas/OpenIDConfiguration"
        "304":
          description: Not Modified - body matches the supplied If-None-Match.
```

In `docs/feature-matrix.md` line 19, add a sibling row after the OIDC Discovery row:

```markdown
| RFC 8414 AS Metadata (alias) | /.well-known/oauth-authorization-server | always | Same handler/body as OIDC discovery |
```

- [ ] **Step 8: Commit**

```bash
git add shared/core/consts.go interfaces/sso/aliases.go interfaces/sso/server_discovery.go interfaces/sso/server_routes.go interfaces/sso/rootcov_discovery_test.go docs/openapi.yaml docs/feature-matrix.md
git commit -m "feat(discovery): mount RFC 8414 oauth-authorization-server alias

Pure-OAuth clients (notably MCP agents, whose auth spec mandates RFC 8414
discovery) 404 today because the AS metadata document is only mounted at
the OIDC discovery path. The document already carries every RFC 8414 field;
this registers the same handler on the RFC 8414 well-known suffix so both
paths share one body cache and stay byte-identical.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

Known limitation (out of scope, documented for the reviewer): RFC 8414 §3.1 issuer-path-suffix form (`/.well-known/oauth-authorization-server/{issuer-path}`) is not handled — same pre-existing limitation as the OIDC path; only matters for issuers with path components.

---

### Task 2: Invitation revocation

**Files:**
- Modify: `shared/core/invitation.go` (50 lines — add `Revoke` to `InvitationStore`, lines 31-45)
- Modify: `infrastructure/defaultimpl/memorystoreidentity/memory_invitation_store.go` (63 lines)
- Modify: `infrastructure/defaultimpl/sqlite/invitation.go` (154 lines — no schema change; `idx_invitations_tenant_id` covers the predicate)
- Modify: `infrastructure/postgres/invitation.go` (167 lines — parent module, `$1/$2` placeholders, no migration bump)
- Modify: `shared/core/consts.go` (add `PathAdminTenantInvitationByEmail` after line 265)
- Modify: `interfaces/sso/aliases.go` (re-export after line 336)
- Modify: `platform/audit/auditspi/event_types.go` (add `EventInvitationRevoked` after line 111) + `platform/audit/aliases_spi.go` (alphabetical re-export between lines 94-95; re-gofmt the aligned block)
- Modify: `interfaces/admin/tenants.go` (190→~215 lines — new handler)
- Modify: `interfaces/sso/server_admin_handlers.go` (92 lines — thin wrapper) + `interfaces/sso/server_routes_admin.go` (109 lines — DELETE route inside the existing `if s.invitationStore != nil` block, lines 105-108)
- Test: `infrastructure/defaultimpl/memory_invitation_store_test.go` (86 lines), `infrastructure/defaultimpl/sqlite/invitation_test.go` (92 lines), `infrastructure/postgres/invitation_test.go` (164 lines), `interfaces/sso/rootcov2_admin_invite_test.go` (129 lines)
- Modify: `docs/openapi.yaml` (new path after the invitations block ending line 4784)

**Interfaces:**
- Consumes: `core.Invitation` (`shared/core/invitation.go:16-22`): `{Token string json:"-" (PK, secret); TenantID; Email; Role TenantRole; ExpiresAt}` — **NO ID field**, so the revoke key is `(tenantID, email)` and revocation bulk-deletes ALL pending tokens for that recipient (re-sends mint multiple live tokens per email). `admin.Deps.InvitationStore()` (`interfaces/admin/deps.go`), `recordAdminUserAction(...)` (`interfaces/admin/users.go:125-142`), `core.KeyTenantID = "tenant_id"` (`shared/core/consts_wire.go:84`). The built-in `StdRouter` assigns raw percent-decoded path segments, so a `:email` param handles `@` fine.
- Produces: `InvitationStore.Revoke(ctx context.Context, tenantID, email string) error` (idempotent — zero rows is success, NOT `ErrInvitationNotFound`; no pending-invitation oracle); `DELETE /api/v1/admin/tenants/:id/invitations/:email` → 204; audit event `invitation_revoked` (tenant_id meta only — the `invitation_sent` precedent deliberately omits email/token from audit meta).

- [ ] **Step 1: Add `Revoke` to the interface (this breaks the build — that is the TDD anchor)**

Append to `InvitationStore` in `shared/core/invitation.go` after `ListByTenant`:

```go
	// Revoke deletes ALL pending invitations for (tenantID, email). The admin
	// roster identifies an invitation by recipient email — the token is a live
	// credential (json:"-") and is never surfaced — and re-sends can leave
	// multiple live tokens for one recipient, so revocation is a bulk delete.
	// Idempotent: nothing pending is a no-op (no pending-invitation oracle).
	Revoke(ctx context.Context, tenantID, email string) error
```

Run: `go build ./...`
Expected: FAIL — the three `var _ core.InvitationStore` interface guards (memory :63, sqlite :154, postgres :167) no longer compile. This forces all three impls.

- [ ] **Step 2: Write the failing store tests**

Append to `infrastructure/defaultimpl/memory_invitation_store_test.go`:

```go
func TestMemoryInvitationStore_RevokeByTenantEmail(t *testing.T) {
	t.Parallel()
	s := defaultimpl.NewMemoryInvitationStore()
	ctx := context.Background()
	exp := time.Now().Add(time.Minute)
	// Two live tokens for the same recipient (re-send) + another recipient + another tenant.
	_ = s.Issue(ctx, &core.Invitation{Token: "r1", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "r2", TenantID: "acme", Email: "gone@e.com", Role: core.TenantRoleAdmin, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "k1", TenantID: "acme", Email: "keep@e.com", Role: core.TenantRoleMember, ExpiresAt: exp})
	_ = s.Issue(ctx, &core.Invitation{Token: "g1", TenantID: "globex", Email: "gone@e.com", Role: core.TenantRoleGuest, ExpiresAt: exp})

	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	// EVERY token for the recipient is dead — a revoked invite can never be accepted.
	if _, err := s.Consume(ctx, "r1"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r1 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if _, err := s.Consume(ctx, "r2"); !errors.Is(err, core.ErrInvitationNotFound) {
		t.Errorf("r2 after revoke err = %v, want ErrInvitationNotFound", err)
	}
	if acme, _ := s.ListByTenant(ctx, "acme"); len(acme) != 1 || acme[0].Email != "keep@e.com" {
		t.Errorf("acme roster after revoke = %+v, want only keep@e.com", acme)
	}
	if globex, _ := s.ListByTenant(ctx, "globex"); len(globex) != 1 {
		t.Errorf("globex roster wrongly affected: %d, want 1", len(globex))
	}
	// Idempotent: nothing pending is a no-op, not an error (no pending-invite oracle).
	if err := s.Revoke(ctx, "acme", "gone@e.com"); err != nil {
		t.Errorf("repeat Revoke err = %v, want nil", err)
	}
}
```

Add the same test body (adjusted constructor/helper) to:
- `infrastructure/defaultimpl/sqlite/invitation_test.go` as `TestSQLiteInvitationStore_Revoke`, using the existing `newInvitationStore(t)` helper (in-memory DSN).
- `infrastructure/postgres/invitation_test.go` as `TestInvitation_RevokeByTenantEmail`, using the existing `freshInvitationStore(t)` helper (auto-skips when `SSO_TEST_POSTGRES_DSN` is unset).

- [ ] **Step 3: Implement Revoke in all three backends**

`infrastructure/defaultimpl/memorystoreidentity/memory_invitation_store.go`:

```go
// Revoke deletes every invitation for (tenantID, email). Idempotent.
func (m *MemoryInvitationStore) Revoke(_ context.Context, tenantID, email string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for token, inv := range m.invts {
		if inv.TenantID == tenantID && inv.Email == email {
			delete(m.invts, token)
		}
	}
	return nil
}
```

`infrastructure/defaultimpl/sqlite/invitation.go`:

```go
// Revoke deletes every invitation for (tenantID, email). Idempotent — zero
// rows affected is success (no pending-invitation oracle).
func (s *InvitationStore) Revoke(ctx context.Context, tenantID, email string) error {
	_, err := s.db.ExecContext(ctx,
		`DELETE FROM invitations WHERE tenant_id = ? AND email = ?`, tenantID, email)
	if err != nil {
		return fmt.Errorf("sqlite: revoke invitation: %w", err)
	}
	return nil
}
```

`infrastructure/postgres/invitation.go` — same body with `$1/$2` placeholders and `postgres:` error prefix.

- [ ] **Step 4: Run store tests**

Run: `go build ./... && go test ./infrastructure/defaultimpl/... -run 'Invitation' -race -v`
Expected: PASS (postgres test auto-skips without DSN; run it too if a local DSN is available).

- [ ] **Step 5: Write the failing endpoint test**

Append `TestRcov2AI_RevokeInvitation` to `interfaces/sso/rootcov2_admin_invite_test.go`, copying the server-build block from `TestRcov2AI_SendInvitation` (lines 37-68) verbatim, then:

```go
	base := httpSrv.URL + "/api/v1/admin/tenants/org-9/invitations"

	status, _ := rcovPostJSON(t, base, token, map[string]any{"email": "leaver@org-9.example", "role": "member"})
	if status != http.StatusAccepted {
		t.Fatalf("send invitation = %d", status)
	}
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", token, nil)
	if status != http.StatusNoContent {
		t.Fatalf("revoke invitation = %d, want 204", status)
	}
	status, lOut := rcovDo(t, http.MethodGet, base, token, nil)
	if invs, _ := lOut["invitations"].([]any); status != http.StatusOK || len(invs) != 0 {
		t.Errorf("list after revoke = %d/%d invites, want 200/0 (body=%v)", status, len(invs), lOut)
	}
	// Idempotent repeat -> still 204 (no pending-invitation oracle).
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", token, nil)
	if status != http.StatusNoContent {
		t.Errorf("repeat revoke = %d, want 204", status)
	}
	// Unauthenticated -> admin gate 401.
	status, _ = rcovDo(t, http.MethodDelete, base+"/leaver@org-9.example", "", nil)
	if status != http.StatusUnauthorized {
		t.Errorf("unauth revoke = %d, want 401", status)
	}
```

Run: `go test ./interfaces/sso/ -run TestRcov2AI_RevokeInvitation -v`
Expected: FAIL — 404/405 on the DELETE (route not mounted).

- [ ] **Step 6: Wire const, audit event, handler, route**

`shared/core/consts.go` (after `PathAdminTenantInvitations`, line 265):

```go
	// PathAdminTenantInvitationByEmail revokes (DELETE) every pending org
	// invitation for a recipient email. admin:write. Mounted only when an
	// InvitationStore is wired.
	PathAdminTenantInvitationByEmail = "/admin/tenants/:id/invitations/:email"
```

`interfaces/sso/aliases.go` (after line 336): `const PathAdminTenantInvitationByEmail = core.PathAdminTenantInvitationByEmail`

`platform/audit/auditspi/event_types.go` (org-membership block, after `EventInvitationAccepted`):

```go
	EventInvitationRevoked EventType = "invitation_revoked"
```

`platform/audit/aliases_spi.go` (alphabetical, between `EventInvitationAccepted` and `EventInvitationSent`; keep the const block gofmt-aligned):

```go
	EventInvitationRevoked = auditspi.EventInvitationRevoked
```

`interfaces/admin/tenants.go` (after `HandleAdminListInvitations`):

```go
// HandleAdminRevokeInvitation serves DELETE /api/v1/admin/tenants/:id/invitations/:email
// — revoke every pending invitation for a recipient. admin:write. Idempotent
// (204 whether or not anything was pending — no pending-invitation oracle).
// Emits invitation_revoked (never the token/email).
func HandleAdminRevokeInvitation(d Deps, ctx core.HandlerContext) {
	tenantID := ctx.Param("id")
	email := ctx.Param("email")
	if tenantID == "" || email == "" {
		ctx.JSON(http.StatusBadRequest, core.ErrorBody(core.ErrInvalidRequest))
		return
	}
	if err := d.InvitationStore().Revoke(ctx.Request().Context(), tenantID, email); err != nil {
		d.Logger().Error("revoke invitation failed", "tenant_id", tenantID, "error", err)
		ctx.JSON(http.StatusInternalServerError, core.ErrorBody(core.ErrInternal))
		return
	}
	recordAdminUserAction(d, ctx, audit.EventInvitationRevoked, "", core.KeyTenantID, tenantID)
	ctx.JSON(http.StatusNoContent, nil)
}
```

`interfaces/sso/server_admin_handlers.go` (after `handleAdminListInvitations`, line 81):

```go
func (s *Server) handleAdminRevokeInvitation(ctx HandlerContext) {
	admin.HandleAdminRevokeInvitation(s, ctx)
}
```

`interfaces/sso/server_routes_admin.go` (inside the `if s.invitationStore != nil` block):

```go
		api.DELETE(PathAdminTenantInvitationByEmail, s.handleAdminRevokeInvitation)
```

- [ ] **Step 7: Run all tests + gates**

Run: `go test ./interfaces/sso/ -run TestRcov2AI -race -v && go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: all PASS.

- [ ] **Step 8: Update openapi.yaml**

Add after the existing invitations path block (ends line 4784), modeled on `adminRemoveTenantMember` (lines 4661-4677):

```yaml
  /api/v1/admin/tenants/{id}/invitations/{email}:
    delete:
      tags: [admin]
      summary: Revoke every pending invitation for a recipient email.
      description: |
        Bulk-deletes all pending invitation tokens for (tenant, email) —
        re-sends can leave multiple live tokens per recipient. Idempotent:
        returns 204 whether or not anything was pending (no
        pending-invitation oracle). Requires admin:write.
      operationId: adminRevokeInvitation
      security:
        - bearerAuth: []
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: string
        - name: email
          in: path
          required: true
          schema:
            type: string
      responses:
        "204":
          description: Invitations revoked (or none pending).
        "401":
          $ref: "#/components/responses/Unauthorized"
```

- [ ] **Step 9: Commit**

```bash
git add shared/core/invitation.go shared/core/consts.go interfaces/sso/aliases.go infrastructure/defaultimpl/memorystoreidentity/memory_invitation_store.go infrastructure/defaultimpl/sqlite/invitation.go infrastructure/postgres/invitation.go platform/audit/auditspi/event_types.go platform/audit/aliases_spi.go interfaces/admin/tenants.go interfaces/sso/server_admin_handlers.go interfaces/sso/server_routes_admin.go infrastructure/defaultimpl/memory_invitation_store_test.go infrastructure/defaultimpl/sqlite/invitation_test.go infrastructure/postgres/invitation_test.go interfaces/sso/rootcov2_admin_invite_test.go docs/openapi.yaml
git commit -m "feat(admin): add invitation revocation endpoint

A mis-sent invitation was a live org-membership credential for its full
7-day TTL with no kill switch: InvitationStore stopped at
Issue/Consume/ListByTenant and re-sends minted additional live tokens.
Adds Revoke (bulk delete by tenant+email, idempotent, no
pending-invitation oracle) across memory/sqlite/postgres, a DELETE admin
route, and an invitation_revoked audit event.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 3: Outbound webhook HMAC payload signing

**Files:**
- Create: `shared/security/securityverify/webhook_signature.go` (~85 lines; the `securityverify` leaf has 5 non-test files, cap 10 — do NOT put it in `shared/security` itself, which is at/over the fanout cap)
- Test: `shared/security/securityverify/webhook_signature_test.go` (same-package, like the existing `pure_functions_test.go`)
- Modify: `shared/security/aliases.go` (58 lines — re-export consts/functions/errors)
- Modify: `platform/audit/auditsink/webhook_sink.go` (99 lines) + `platform/audit/aliases_sink.go` (43 lines)
- Modify: `infrastructure/defaultimpl/defaultmfa/push_webhook.go` (201 lines) + `infrastructure/defaultimpl/aliases_mfa.go` (65 lines — do NOT add a new file to `infrastructure/defaultimpl`, it is past its frozen fanout ceiling)
- Modify: `config/config_audit.go:68-74` + `config/config_mfa.go:37-45` (do NOT create a new config file — `config/` is past its frozen fanout ceiling)
- Modify: `cmd/sso-server/build_app_core.go:280-309` (`wireAuditWebhook`) + `cmd/sso-server/serverbuildstore/build_mfa.go:189-211` (`BuildPushWebhookTransport`)
- Test: `platform/audit/webhook_sink_test.go` (122 lines), `infrastructure/defaultimpl/push_webhook_test.go` (198 lines), extend `cmd/sso-server/build_stores_coverage_test.go:589-606`
- Modify: `docs/config-reference.md` (Audit & Metrics table, lines 91-98) + `docs/error-codes.md` (SDK-sentinel subsection)

**Interfaces:**
- Consumes: `WebhookSink{url, client, headers}` + `WebhookOption` + `NewWebhookSink` (`platform/audit/auditsink/webhook_sink.go:22-51`); `HTTPWebhookPushTransport{URL, Client, Headers, BearerToken, MaxAttempts, ...}` + `PushWebhookOption` (`infrastructure/defaultimpl/defaultmfa/push_webhook.go:41-52`); `AuditWebhookConfig` (`config/config_audit.go:68`), `MFAPushWebhookConfig` (`config/config_mfa.go:37` — `CIBAConfig.Webhook` at `config/config_sec.go:41` reuses this struct, so `ciba.webhook.signing_secret` works for free); wiring sites `wireAuditWebhook` and `BuildPushWebhookTransport`.
- Produces: `securityverify.WebhookSignatureHeader = "X-Signature"`, `DefaultWebhookSignatureTolerance = 5*time.Minute`, `SignWebhookPayload(secret []byte, ts time.Time, body []byte) string`, `VerifyWebhookSignature(secret []byte, header string, body []byte, now time.Time, tolerance time.Duration) error`, sentinels `ErrWebhookSignatureMalformed/Mismatch/Expired` (all re-exported via `shared/security`); options `audit.WithWebhookSigningSecret(string)` and `defaultimpl.WithPushWebhookSigningSecret(string)`; config keys `audit.webhook.signing_secret`, `mfa.provider.push.webhook.signing_secret`, `ciba.webhook.signing_secret`.

Design decisions (resolved): Stripe/Svix-style header value `t=<unix>,v1=hex(hmac-sha256(secret, "<unix>." + body))`; timestamp folded into the MAC so captured signatures cannot be replayed. Header name stays `X-Signature` per the shared const — a single place to change if a vendor-prefixed name is ever preferred. The push transport signs in `sendOnce` so each retry attempt gets a FRESH timestamp. The computed signature is set AFTER the static-headers loop so a stray operator static header cannot override it.

- [ ] **Step 1: Write the failing pure-function test**

Create `shared/security/securityverify/webhook_signature_test.go` (package `securityverify`):

```go
func TestWebhookSignature_RoundTripTamperExpiry(t *testing.T) {
	t.Parallel()
	secret, body := []byte("s3cret"), []byte(`{"a":1}`)
	now := time.Unix(1760000000, 0)
	hdr := SignWebhookPayload(secret, now, body)
	if !strings.HasPrefix(hdr, "t=1760000000,v1=") {
		t.Fatalf("header shape: %q", hdr)
	}
	if err := VerifyWebhookSignature(secret, hdr, body, now.Add(2*time.Minute), DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("fresh verify: %v", err)
	}
	if err := VerifyWebhookSignature(secret, hdr, append(body, 'x'), now, DefaultWebhookSignatureTolerance); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Fatalf("tampered body: %v, want ErrWebhookSignatureMismatch", err)
	}
	if err := VerifyWebhookSignature(secret, hdr, body, now.Add(10*time.Minute), DefaultWebhookSignatureTolerance); !errors.Is(err, ErrWebhookSignatureExpired) {
		t.Fatalf("stale: %v, want ErrWebhookSignatureExpired", err)
	}
	if err := VerifyWebhookSignature(secret, "garbage", body, now, 0); !errors.Is(err, ErrWebhookSignatureMalformed) {
		t.Fatalf("malformed: %v, want ErrWebhookSignatureMalformed", err)
	}
	if err := VerifyWebhookSignature([]byte("wrong"), hdr, body, now, 0); !errors.Is(err, ErrWebhookSignatureMismatch) {
		t.Fatalf("wrong secret: %v, want ErrWebhookSignatureMismatch", err)
	}
}
```

Run: `go test ./shared/security/securityverify/ -run TestWebhookSignature -v`
Expected: FAIL — `undefined: SignWebhookPayload`.

- [ ] **Step 2: Implement the sign/verify helper**

Create `shared/security/securityverify/webhook_signature.go`:

```go
package securityverify

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
	"time"
)

// WebhookSignatureHeader carries the outbound webhook payload signature
// (Stripe/Svix style: "t=<unix>,v1=<hex hmac-sha256>").
const WebhookSignatureHeader = "X-Signature"

// DefaultWebhookSignatureTolerance bounds receiver-side clock skew plus
// retry/redelivery delay when checking the signed timestamp.
const DefaultWebhookSignatureTolerance = 5 * time.Minute

var (
	ErrWebhookSignatureMalformed = errors.New("webhook signature: malformed header")
	ErrWebhookSignatureMismatch  = errors.New("webhook signature: mismatch")
	ErrWebhookSignatureExpired   = errors.New("webhook signature: timestamp outside tolerance")
)

// SignWebhookPayload returns the WebhookSignatureHeader value for body:
// t=<unix>,v1=hex(hmac-sha256(secret, "<unix>." + body)). The timestamp is
// folded into the MAC so a captured signature cannot be replayed later.
func SignWebhookPayload(secret []byte, ts time.Time, body []byte) string {
	t := strconv.FormatInt(ts.Unix(), 10)
	return "t=" + t + ",v1=" + webhookHMACHex(secret, t, body)
}

func webhookHMACHex(secret []byte, t string, body []byte) string {
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(t))
	mac.Write([]byte("."))
	mac.Write(body)
	return hex.EncodeToString(mac.Sum(nil))
}

// VerifyWebhookSignature is the receiver-side check: recomputes the MAC over
// the received body and compares in constant time (hmac.Equal). tolerance <= 0
// skips the freshness check (the timestamp is still authenticated by the MAC).
func VerifyWebhookSignature(secret []byte, header string, body []byte, now time.Time, tolerance time.Duration) error {
	t, v1, err := parseWebhookSignature(header)
	if err != nil {
		return err
	}
	want, err := hex.DecodeString(v1)
	if err != nil {
		return ErrWebhookSignatureMalformed
	}
	got, _ := hex.DecodeString(webhookHMACHex(secret, t, body))
	if !hmac.Equal(got, want) {
		return ErrWebhookSignatureMismatch
	}
	if tolerance > 0 {
		sec, err := strconv.ParseInt(t, 10, 64)
		if err != nil {
			return ErrWebhookSignatureMalformed
		}
		if d := now.Sub(time.Unix(sec, 0)); d > tolerance || d < -tolerance {
			return ErrWebhookSignatureExpired
		}
	}
	return nil
}

func parseWebhookSignature(header string) (t, v1 string, err error) {
	for _, part := range strings.Split(header, ",") {
		k, v, ok := strings.Cut(part, "=")
		if !ok {
			return "", "", ErrWebhookSignatureMalformed
		}
		switch k {
		case "t":
			t = v
		case "v1":
			v1 = v
		}
	}
	if t == "" || v1 == "" {
		return "", "", ErrWebhookSignatureMalformed
	}
	return t, v1, nil
}
```

Re-export in `shared/security/aliases.go` (extend the existing securityverify blocks):

```go
const (
	WebhookSignatureHeader             = securityverify.WebhookSignatureHeader
	DefaultWebhookSignatureTolerance   = securityverify.DefaultWebhookSignatureTolerance
)

var (
	SignWebhookPayload           = securityverify.SignWebhookPayload
	VerifyWebhookSignature       = securityverify.VerifyWebhookSignature
	ErrWebhookSignatureMalformed = securityverify.ErrWebhookSignatureMalformed
	ErrWebhookSignatureMismatch  = securityverify.ErrWebhookSignatureMismatch
	ErrWebhookSignatureExpired   = securityverify.ErrWebhookSignatureExpired
)
```

Run: `go test ./shared/security/... -run TestWebhookSignature -race -v`
Expected: PASS.

- [ ] **Step 3: Write the failing sink test**

Append to `platform/audit/webhook_sink_test.go` (package `audit_test`; imports add `"time"`, `"github.com/snaplink/sso/shared/security"`):

```go
func TestWebhookSink_SignsPayload(t *testing.T) {
	t.Parallel()
	const secret = "whsec-test"
	var (
		mu   sync.Mutex
		sig  string
		body []byte
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		sig = r.Header.Get(security.WebhookSignatureHeader)
		body = b
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL, audit.WithWebhookSigningSecret(secret))
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin, ActorID: "alice"}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	mu.Lock()
	defer mu.Unlock()
	if sig == "" {
		t.Fatal("signature header missing")
	}
	if err := security.VerifyWebhookSignature([]byte(secret), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err != nil {
		t.Fatalf("VerifyWebhookSignature: %v", err)
	}
	if err := security.VerifyWebhookSignature([]byte("wrong"), sig, body, time.Now(), security.DefaultWebhookSignatureTolerance); err == nil {
		t.Fatal("verification with wrong secret must fail")
	}
}

func TestWebhookSink_NoSignatureWithoutSecret(t *testing.T) {
	t.Parallel()
	var (
		mu  sync.Mutex
		sig string
		hit bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		sig, hit = r.Header.Get(security.WebhookSignatureHeader), true
		mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	s := audit.NewWebhookSink(srv.URL)
	if err := s.Record(context.Background(), &audit.Event{Type: audit.EventLogin}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if !hit || sig != "" {
		t.Fatalf("hit=%v sig=%q; want hit with empty signature header", hit, sig)
	}
}
```

Run: `go test ./platform/audit/ -run TestWebhookSink_Signs -v`
Expected: FAIL — `undefined: audit.WithWebhookSigningSecret`.

- [ ] **Step 4: Implement sink + push-transport signing**

`platform/audit/auditsink/webhook_sink.go` (import `github.com/snaplink/sso/shared/security/securityverify` — platform → shared points down, allowed):
- struct: add `signingSecret []byte` after `headers`.
- new option after `WithWebhookHTTPClient`:

```go
// WithWebhookSigningSecret enables HMAC-SHA256 payload signing — every POST
// carries securityverify.WebhookSignatureHeader (t=<unix>,v1=<hex>), letting
// receivers authenticate origin, integrity, and freshness. Empty is a no-op.
func WithWebhookSigningSecret(secret string) WebhookOption {
	return func(w *WebhookSink) {
		if secret != "" {
			w.signingSecret = []byte(secret)
		}
	}
}
```

- in `Record`, AFTER the static-headers loop (computed signature wins over any operator static header of the same name):

```go
	if len(w.signingSecret) > 0 {
		req.Header.Set(securityverify.WebhookSignatureHeader,
			securityverify.SignWebhookPayload(w.signingSecret, time.Now(), body))
	}
```

- `platform/audit/aliases_sink.go` var block: `WithWebhookSigningSecret = auditsink.WithWebhookSigningSecret`

`infrastructure/defaultimpl/defaultmfa/push_webhook.go`:
- struct: add exported `SigningSecret []byte` (sibling fields are exported).
- new option `WithPushWebhookSigningSecret(secret string) PushWebhookOption` (same shape as above, after `WithPushWebhookRetry`).
- in `sendOnce`, after the `Headers` loop (fresh timestamp per retry attempt): same `req.Header.Set(...)` block using `t.SigningSecret`.
- REWRITE the doc comment at lines 39-40 that currently says operators wanting HMAC body signing must fork this transport.
- `infrastructure/defaultimpl/aliases_mfa.go` var block: `WithPushWebhookSigningSecret = defaultmfa.WithPushWebhookSigningSecret`

Add `TestHTTPWebhookPushTransport_SignsPayload` to `infrastructure/defaultimpl/push_webhook_test.go` mirroring the sink test: build with `defaultimpl.NewHTTPWebhookPushTransport(srv.URL, defaultimpl.WithPushWebhookSigningSecret("whsec-test"))`, call `tr.Send(ctx, "ch-1", "alice", nil)`, verify captured header via `security.VerifyWebhookSignature`.

Run: `go test ./platform/audit/ ./infrastructure/defaultimpl/... -run 'Webhook' -race`
Expected: PASS.

- [ ] **Step 5: Config + binary wiring**

`config/config_audit.go` — add to `AuditWebhookConfig`:

```go
	// SigningSecret enables HMAC-SHA256 payload signing (X-Signature:
	// t=<unix>,v1=<hex>) on every delivery. Empty disables. Inject via
	// SSO_AUDIT__WEBHOOK__SIGNING_SECRET or a secret:// reference — never
	// commit the literal to YAML.
	SigningSecret string `yaml:"signing_secret"`
```

`config/config_mfa.go` — add to `MFAPushWebhookConfig` (doc comment notes `CIBAConfig.Webhook` reuses this struct, so `ciba.webhook.signing_secret` works automatically):

```go
	SigningSecret string `yaml:"signing_secret"`
```

`cmd/sso-server/build_app_core.go` `wireAuditWebhook`, after the Headers loop (lines 288-290):

```go
	if w.SigningSecret != "" {
		webhookOpts = append(webhookOpts, audit.WithWebhookSigningSecret(w.SigningSecret))
	}
```

and extend the boot log at lines 303-307 with `"signed", w.SigningSecret != ""` — NEVER log the value.

`cmd/sso-server/serverbuildstore/build_mfa.go` `BuildPushWebhookTransport`, after the Headers loop (lines 197-199) — this single site covers both `mfa.provider.push.webhook` and `ciba.webhook`:

```go
	if cfg.SigningSecret != "" {
		opts = append(opts, defaultimpl.WithPushWebhookSigningSecret(cfg.SigningSecret))
	}
```

Extend `TestBuildPushWebhookTransport_HappyPathWithAllOptions` (`cmd/sso-server/build_stores_coverage_test.go:589-606`) with `SigningSecret: "whsec-x"` and assert the returned `*defaultimpl.HTTPWebhookPushTransport` has non-empty `SigningSecret`.

- [ ] **Step 6: Gates + docs**

Run: `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./... && go test ./cmd/sso-server/ -run TestBuildPushWebhookTransport -race`
Expected: all PASS.

`docs/config-reference.md` (Audit & Metrics table): add rows for `audit.webhook.signing_secret`, `mfa.provider.push.webhook.signing_secret`, and a note that `ciba.webhook.signing_secret` shares the struct — HMAC-SHA256 `X-Signature` (`t=<unix>,v1=<hex>`) payload signing; empty = off; receivers verify with `security.VerifyWebhookSignature`.

`docs/error-codes.md`: add a short "SDK webhook signature verification (outbound webhooks)" subsection for `ErrWebhookSignatureMalformed/Mismatch/Expired`, explicitly noting they are receiver-helper sentinels that never appear on the SSO server's own HTTP wire.

- [ ] **Step 7: Commit**

```bash
git add shared/security/securityverify/webhook_signature.go shared/security/securityverify/webhook_signature_test.go shared/security/aliases.go platform/audit/auditsink/webhook_sink.go platform/audit/aliases_sink.go platform/audit/webhook_sink_test.go infrastructure/defaultimpl/defaultmfa/push_webhook.go infrastructure/defaultimpl/aliases_mfa.go infrastructure/defaultimpl/push_webhook_test.go config/config_audit.go config/config_mfa.go cmd/sso-server/build_app_core.go cmd/sso-server/serverbuildstore/build_mfa.go cmd/sso-server/build_stores_coverage_test.go docs/config-reference.md docs/error-codes.md
git commit -m "feat(webhooks): HMAC-SHA256 payload signing for outbound deliveries

Audit webhook and MFA/CIBA push deliveries authenticated receivers only
with static headers, which neither bind the payload nor resist replay;
the push transport's own doc told operators wanting signed payloads to
fork it. Adds a Stripe/Svix-style X-Signature (t=<unix>,v1=hex) signer
in the shared/security kernel with a constant-time receiver-side verify
helper, opt-in options on both transports, and config keys. Push
retries re-sign with a fresh timestamp per attempt.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 4: CAEP SET delivery retry

**Files:**
- Create: `protocols/caep/broadcaster_retry.go` (~120 lines — protocols/caep has 9 non-test files; this makes exactly 10 = the fanout cap, so NO further new files in this package)
- Modify: `protocols/caep/broadcaster.go` (434/500 — keep additions minimal: struct fields, defaults, `OutcomeRetried` const, `deliver` rewrite, `post` return change, `Close` stop-close; lands ~460)
- Test: `protocols/caep/broadcaster_retry_test.go` (new, package `caep_test` — test files exempt from budget/fanout)
- Modify: `config/config_caep.go` (125 lines — three fields after `SETTTL`)
- Modify: `cmd/sso-server/build_app_oidc.go:89-117` (`wireCAEPTransmitter`, grows to ~36 lines — under the 50 cap)
- Modify: `docs/config-reference.md:113` (CAEP row) + `docs/observability.md:29` (`sso_caep_sets_total` outcome value set)

**Interfaces:**
- Consumes: `Transmitter` struct (`broadcaster.go:95-110`), `Option func(*Transmitter)` (:113), `NewTransmitter` (:174), `deliver(clientID, endpoint, auth string, req buildSETRequest)` (:280), `post(...)` (:326, returns `fmt.Errorf("non-2xx status %d", ...)` today), `fail(...)` (:352), `Close(ctx)` (:383 — called MULTIPLE times by existing tests, hence `sync.Once`), `mintSET` (`security_event_token.go` — fresh `jti` per call), the backoff shape of `auditsink.RetryingSink` (`platform/audit/auditsink/retrying_sink.go:164-171`), receiver contract (`receiver_receive.go:30-37`: 500 = transient, transmitter should retry; jti `MarkSeen` fires BEFORE the revoke action, so a byte-identical retransmit would be rejected as a replay — retries MUST re-mint).
- Produces: `WithDeliveryRetry(maxAttempts int) Option`, `WithDeliveryRetryBackoff(initial, max time.Duration) Option`, consts `DefaultDeliveryRetryInitialBackoff = 500ms` / `DefaultDeliveryRetryMaxBackoff = 5s`, metric outcome value `OutcomeRetried = "retried"`, config keys `caep.delivery_retry_max_attempts/_initial_backoff/_max_backoff`.

Design decisions (resolved): retry is OPT-IN — default `retryMaxAttempts = 1` preserves today's single-shot behavior byte-identically. 5xx + 429 + transport errors are retryable; other 4xx (SET rejected) and local mint errors are permanent. Each attempt re-mints a fresh SET (fresh jti — required by the receiver's replay guard, permitted by RFC 8935). Retry observability reuses `sso_caep_sets_total` with the new `retried` outcome value (bounded cardinality, zero cmd plumbing). `Close` aborts pending backoffs via a `stop` channel so shutdown drains promptly.

- [ ] **Step 1: Write the failing tests**

Create `protocols/caep/broadcaster_retry_test.go` (package `caep_test`; reuses same-package helpers `testHTTPClient` (transmitter_test.go:29), `newIssuerStore` (:145), `waitFor` (:406), `verifySET` (:99), `capturingMetric` (transmitter_extra_test.go:77), `newTLSStatusReceiver` (:125)):

```go
package caep_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/protocols/caep"
	"github.com/snaplink/sso/shared/core"
)

// flakyReceiver answers 503 for the first `failures` POSTs (the shipped
// receiver's transient signal — receiver_receive.go maps a post-validation
// store outage to 500 so transmitters retry), then 202. It records EVERY
// request body so the test can prove each attempt carried a FRESH SET.
type flakyReceiver struct {
	mu       sync.Mutex
	failures int
	bodies   []string
	accepted int
}

func (r *flakyReceiver) handler() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		body, _ := io.ReadAll(req.Body)
		r.mu.Lock()
		defer r.mu.Unlock()
		r.bodies = append(r.bodies, string(body))
		if r.failures > 0 {
			r.failures--
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		r.accepted++
		w.WriteHeader(http.StatusAccepted)
	}
}

func (r *flakyReceiver) acceptedCount() int { r.mu.Lock(); defer r.mu.Unlock(); return r.accepted }
func (r *flakyReceiver) attempts() int      { r.mu.Lock(); defer r.mu.Unlock(); return len(r.bodies) }
func (r *flakyReceiver) allBodies() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.bodies...)
}

// TestTransmitter_RetryDeliversExactlyOnce: receiver fails twice with a
// retryable 503, then accepts — the SET must land EXACTLY once, and each
// attempt must carry a freshly minted SET (new jti: the receiver's
// jti-replay MarkSeen fires before its revoke action, so a byte-identical
// retransmit would be rejected as a replay).
func TestTransmitter_RetryDeliversExactlyOnce(t *testing.T) {
	t.Parallel()
	recv := &flakyReceiver{failures: 2}
	srv := httptest.NewTLSServer(recv.handler())
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record),
		caep.WithDeliveryRetry(5),
		caep.WithDeliveryRetryBackoff(time.Millisecond, 5*time.Millisecond),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})

	waitFor(t, func() bool { return recv.acceptedCount() == 1 }, "SET accepted after retries")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.attempts(); got != 3 {
		t.Fatalf("attempts = %d, want 3 (2 x 503 + 1 x 202)", got)
	}
	if got := recv.acceptedCount(); got != 1 {
		t.Fatalf("accepted = %d, want exactly 1", got)
	}
	seen := map[string]bool{}
	for _, body := range recv.allBodies() {
		v := verifySET(t, body, iss.PublicKey())
		if seen[v.jti] {
			t.Fatalf("jti %q reused across attempts — retry must re-mint", v.jti)
		}
		seen[v.jti] = true
	}
	if metric.has(caep.OutcomeFailed) {
		t.Error("eventual success still recorded a failed outcome")
	}
	if !metric.has(caep.OutcomeSuccess) {
		t.Error("no success outcome recorded")
	}
}

// TestTransmitter_PermanentRejectionNotRetried: a 400 means the receiver
// REJECTED the SET — retrying re-sends the same rejection, so exactly one
// attempt happens even with retry enabled.
func TestTransmitter_PermanentRejectionNotRetried(t *testing.T) {
	t.Parallel()
	recv := &flakyReceiver{}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		_, _ = io.ReadAll(req.Body)
		recv.mu.Lock()
		recv.bodies = append(recv.bodies, "")
		recv.mu.Unlock()
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	metric := &capturingMetric{}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithMetric(metric.record),
		caep.WithDeliveryRetry(5),
		caep.WithDeliveryRetryBackoff(time.Millisecond, 5*time.Millisecond),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	waitFor(t, func() bool { return metric.has(caep.OutcomeFailed) }, "400 recorded as failed")
	if err := tx.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
	if got := recv.attempts(); got != 1 {
		t.Fatalf("attempts = %d, want 1 (4xx is permanent)", got)
	}
}

// TestTransmitter_CloseAbortsPendingBackoff: with a 30s initial backoff a
// retry chain would pin shutdown for minutes; Close must abort the pending
// backoff and drain promptly.
func TestTransmitter_CloseAbortsPendingBackoff(t *testing.T) {
	t.Parallel()
	srv := newTLSStatusReceiver(http.StatusServiceUnavailable)
	defer srv.Close()

	iss, store := newIssuerStore()
	ctx := context.Background()
	if err := store.Add(ctx, &core.Client{
		ID: "owner", Active: true,
		Attributes: map[string]string{caep.AttrReceiverEndpoint: srv.URL},
	}); err != nil {
		t.Fatalf("add: %v", err)
	}
	tx := caep.NewTransmitter(iss, store,
		caep.WithHTTPClient(testHTTPClient(srv)),
		caep.WithDeliveryRetry(3),
		caep.WithDeliveryRetryBackoff(30*time.Second, 60*time.Second),
	)
	_ = tx.Record(ctx, &audit.Event{Type: audit.EventRefreshTokenReuse, Outcome: audit.OutcomeFailure, ClientID: "owner", ActorID: "u"})
	time.Sleep(100 * time.Millisecond) // let the first attempt fail and enter the 30s backoff
	start := time.Now()
	if err := tx.Close(context.Background()); err != nil {
		t.Fatalf("close: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Close took %v — pending backoff was not aborted", elapsed)
	}
}
```

Run: `go test ./protocols/caep/ -run 'TestTransmitter_Retry|TestTransmitter_Permanent|TestTransmitter_CloseAborts' -v`
Expected: FAIL — `undefined: caep.WithDeliveryRetry`.

- [ ] **Step 2: Implement the retry surface in a NEW file**

Create `protocols/caep/broadcaster_retry.go`:

```go
package caep

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/http"
	"time"
)

// Delivery-retry defaults. Retry is OPT-IN (default attempts = 1, i.e.
// today's single-shot behavior): the shipped receiver answers 500 on a
// transient post-validation failure precisely so a transmitter MAY retry
// (receiver_receive.go), but each retry holds a broadcast goroutine
// through its backoff + POST, so the operator sizes the budget.
const (
	DefaultDeliveryRetryInitialBackoff = 500 * time.Millisecond
	DefaultDeliveryRetryMaxBackoff     = 5 * time.Second
)

// WithDeliveryRetry caps TOTAL delivery attempts per SET per receiver,
// including the first (3 = try once, retry twice). Values <= 1 keep the
// single-shot default.
func WithDeliveryRetry(maxAttempts int) Option {
	return func(t *Transmitter) {
		if maxAttempts > 1 {
			t.retryMaxAttempts = maxAttempts
		}
	}
}

// WithDeliveryRetryBackoff tunes the exponential inter-attempt backoff
// (doubling from initial, +-25% jitter, capped at max — the same shape as
// auditsink.RetryingSink). Non-positive values keep the defaults.
func WithDeliveryRetryBackoff(initial, max time.Duration) Option {
	return func(t *Transmitter) {
		if initial > 0 {
			t.retryInitialBackoff = initial
		}
		if max > 0 {
			t.retryMaxBackoff = max
		}
	}
}

// receiverStatusError carries the receiver's non-2xx status so the retry
// loop can classify. The Error() text stays byte-identical to the
// pre-retry fmt.Errorf so caep_broadcast_failed audit Reasons don't change.
type receiverStatusError struct{ status int }

func (e *receiverStatusError) Error() string { return fmt.Sprintf("non-2xx status %d", e.status) }

// mintError marks a local signing failure — permanent for retry purposes
// (the signer is local; looping won't fix a bad key). Keeps the existing
// "mint: " audit-reason prefix.
type mintError struct{ err error }

func (e *mintError) Error() string { return "mint: " + e.err.Error() }

// retryableDeliveryError: 5xx and 429 are the receiver's transient
// signals (our own receiver 500s on a post-validation store outage BY
// CONTRACT so the transmitter retries); other 4xx means the SET was
// REJECTED — retrying re-sends the same rejection. Transport errors
// (dial/TLS/timeout) are retryable.
func retryableDeliveryError(err error) bool {
	var se *receiverStatusError
	if errors.As(err, &se) {
		return se.status >= http.StatusInternalServerError || se.status == http.StatusTooManyRequests
	}
	var me *mintError
	return !errors.As(err, &me)
}

// attemptDelivery mints a FRESH SET and POSTs it under the per-attempt
// timeout. Fresh mint per attempt is REQUIRED, not a nicety: the
// receiver's jti-replay guard (MarkSeen, validation step 7) fires BEFORE
// the revoke action, so a byte-identical retransmit of a SET that 500ed
// would be rejected as a replay. A new jti + iat per attempt is safe —
// the events payload is identical and idempotent on the receiver.
func (t *Transmitter) attemptDelivery(endpoint, auth string, req buildSETRequest) error {
	ctx, cancel := context.WithTimeout(context.Background(), t.timeout)
	defer cancel()
	set, err := mintSET(ctx, t.signer, req, t.setTTL)
	if err != nil {
		return &mintError{err}
	}
	return t.post(ctx, endpoint, auth, set)
}

// waitBackoff sleeps before retry N (0-indexed): initial<<N, +-25%
// jitter, capped at retryMaxBackoff (auditsink.RetryingSink.backoff
// shape). Returns false when Close has fired — shutdown aborts pending
// backoffs so draining is bounded by the in-flight POST, never by the
// remaining retry chain.
func (t *Transmitter) waitBackoff(attempt int) bool {
	base := t.retryInitialBackoff << attempt
	if base <= 0 || base > t.retryMaxBackoff {
		base = t.retryMaxBackoff
	}
	timer := time.NewTimer(time.Duration(float64(base) * (0.75 + rand.Float64()*0.5)))
	defer timer.Stop()
	select {
	case <-timer.C:
		return true
	case <-t.stop:
		return false
	}
}
```

- [ ] **Step 3: Modify broadcaster.go (minimal deltas)**

- Struct (after `wg`, ~line 109): add `retryMaxAttempts int`, `retryInitialBackoff time.Duration`, `retryMaxBackoff time.Duration`, `stop chan struct{}`, `stopOnce sync.Once`.
- `NewTransmitter` defaults (~line 187): `retryMaxAttempts: 1`, `retryInitialBackoff: DefaultDeliveryRetryInitialBackoff`, `retryMaxBackoff: DefaultDeliveryRetryMaxBackoff`, `stop: make(chan struct{})`.
- Outcome consts (~line 59): add `OutcomeRetried = "retried"` and update the bounded-cardinality comment ("three fixed values" → four).
- `post` (~line 346): replace the final `fmt.Errorf("non-2xx status %d", resp.StatusCode)` with `return &receiverStatusError{status: resp.StatusCode}`.
- `Close` (~line 383): first statement becomes `t.stopOnce.Do(func() { close(t.stop) })` (existing tests call Close twice), then the existing drain.
- Rewrite `deliver` (line 280) as the retry loop — 32 lines, cyclo ~9:

```go
func (t *Transmitter) deliver(clientID, endpoint, auth string, req buildSETRequest) {
	defer t.wg.Done()
	defer func() {
		if r := recover(); r != nil {
			t.fail(clientID, endpoint, fmt.Sprintf("panic: %v", r))
		}
	}()
	var lastErr error
	for attempt := 0; attempt < t.retryMaxAttempts; attempt++ {
		if attempt > 0 {
			if !t.waitBackoff(attempt - 1) {
				break // shutting down: report the last real failure, skip the re-attempt
			}
			if t.metric != nil {
				t.metric(OutcomeRetried)
			}
		}
		err := t.attemptDelivery(endpoint, auth, req)
		if err == nil {
			if t.metric != nil {
				t.metric(OutcomeSuccess)
			}
			return
		}
		lastErr = err
		if !retryableDeliveryError(err) {
			break
		}
	}
	t.fail(clientID, endpoint, lastErr.Error())
}
```

NOTE: `deliver` currently also mints inline — move that logic into `attemptDelivery` exactly (preserving audit-reason strings via `mintError`/`receiverStatusError`).

- [ ] **Step 4: Run tests**

Run: `go test ./protocols/caep/ -race`
Expected: ALL caep tests PASS (existing single-shot tests must pass unchanged — default is byte-identical behavior).

- [ ] **Step 5: Config + binary wiring**

`config/config_caep.go`, after `SETTTL`:

```go
	// DeliveryRetryMaxAttempts caps TOTAL SET delivery attempts per
	// receiver, including the first. 0 or 1 (the default) = single-shot.
	// Broadcast stays best-effort/fail-open — retry only widens the window.
	DeliveryRetryMaxAttempts int `yaml:"delivery_retry_max_attempts"`
	// DeliveryRetryInitialBackoff is the first inter-attempt wait
	// (doubling, jittered). 0 = SDK default (500ms).
	DeliveryRetryInitialBackoff time.Duration `yaml:"delivery_retry_initial_backoff"`
	// DeliveryRetryMaxBackoff caps the per-attempt wait. 0 = SDK default (5s).
	DeliveryRetryMaxBackoff time.Duration `yaml:"delivery_retry_max_backoff"`
```

`cmd/sso-server/build_app_oidc.go` `wireCAEPTransmitter`, after the `SETTTL` block (line 110-112):

```go
	if n := cfg.CAEP.DeliveryRetryMaxAttempts; n > 1 {
		caepOpts = append(caepOpts, caep.WithDeliveryRetry(n))
	}
	if cfg.CAEP.DeliveryRetryInitialBackoff > 0 || cfg.CAEP.DeliveryRetryMaxBackoff > 0 {
		caepOpts = append(caepOpts, caep.WithDeliveryRetryBackoff(cfg.CAEP.DeliveryRetryInitialBackoff, cfg.CAEP.DeliveryRetryMaxBackoff))
	}
```

- [ ] **Step 6: Gates + docs**

Run: `go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: PASS (broadcaster.go ~460/500; caep at exactly 10 files = cap).

- `docs/config-reference.md` line 113: extend the CAEP row to `caep.{enabled,receiver_timeout,set_ttl,delivery_retry_max_attempts,delivery_retry_initial_backoff,delivery_retry_max_backoff}`.
- `docs/observability.md` line 29: document the `sso_caep_sets_total` outcome value set as `success|failed|dropped|retried`.

- [ ] **Step 7: Commit**

```bash
git add protocols/caep/broadcaster_retry.go protocols/caep/broadcaster.go protocols/caep/broadcaster_retry_test.go config/config_caep.go cmd/sso-server/build_app_oidc.go docs/config-reference.md docs/observability.md
git commit -m "feat(caep): opt-in bounded retry for SET delivery

The transmitter POSTed each SET exactly once, so any transient receiver
failure permanently dropped a security-critical revocation signal —
even though our own receiver deliberately answers 500 on retryable
errors so that transmitters retry. Adds an opt-in bounded retry loop
(5xx/429/transport retryable, other 4xx permanent) with jittered
exponential backoff. Every attempt re-mints a fresh SET because the
receiver's jti-replay guard fires before the revoke action, so a
byte-identical retransmit would be rejected as a replay. Close aborts
pending backoffs; defaults preserve single-shot behavior byte-for-byte.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 5: TopTenants admin usage endpoint

**Files:**
- Modify: `shared/core/consts.go` (add `PathAdminTopTenants` below `PathTenantUsage`, line 166 — MUST be group-relative `/admin/...`, see the double-prefix regression comment at lines 156-165)
- Modify: `interfaces/sso/aliases.go:313` (+1 line re-export)
- Modify: `interfaces/sso/server_discovery.go` (421→~466 lines — extract `parseUsageWindow` from `handleTenantUsage` lines 385-405, add `handleAdminTopTenants`; do NOT create a new .go file in `interfaces/sso` — its fanout is already over the frozen ceiling, Task 0 item 4)
- Modify: `interfaces/sso/server_routes_admin.go:30-32` (register inside the existing `if s.usageAggregator != nil` block)
- Test: create `test/admin_top_tenants_test.go` (package `ssotest`; test files exempt from fanout)
- Modify: `docs/openapi.yaml` (after the `/api/v1/admin/tenants/{id}/usage` block, lines ~3833-3873)

**Interfaces:**
- Consumes: `metering.Aggregator.TopTenants(ctx, period UsagePeriod, start time.Time, limit int) ([]*TenantUsage, error)` (`domains/metering/metering.go:55`); `metering.TenantUsage{TenantID, Period, PeriodStart, Logins, TokensIssued, ActiveUsers, MFAChallenges}` (:35-43 — NO json tags: wire keys are PascalCase, matching the existing per-tenant endpoint; do NOT add tags, that would silently change the existing wire format); `meteringmemory.New()` + `Record(...)` for test seeding; server field `s.usageAggregator` (`sso_selfservice.go:183`), option `WithTenantUsageAggregator` (`options_passwd.go:198`); GET under `/api/v1/admin/` is auto-gated `admin:read` by `interfaces/admin/middleware.go:153`; `errorBody(code)` helper (`interfaces/sso/handler.go:13`); `KeyStatus`/`StatusOK` consts.
- Produces: `GET /api/v1/admin/usage/top-tenants?period=day|month&start=YYYY-MM-DD&limit=N` → `{"status":"ok","tenants":[...],"total":N}`; helper `(s *Server) parseUsageWindow(ctx HandlerContext) (metering.UsagePeriod, time.Time, bool)` shared by both usage handlers.

Design decisions (resolved): enveloped response (`status/tenants/total`) matching the admin list convention; strict 400 `invalid_request` on malformed `period`/`start`/`limit` (limit must be a positive integer; default 10); `nil` → `[]` normalization mirroring `handleAdminListSessions`; REST-only (the per-tenant usage endpoint is already REST-only precedent).

- [ ] **Step 1: Write the failing route test**

Create `test/admin_top_tenants_test.go`:

```go
package ssotest

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/snaplink/sso/domains/metering"
	meteringmemory "github.com/snaplink/sso/domains/metering/memory"
	"github.com/snaplink/sso/interfaces/sso"
)

// topTenantsServer builds a server whose memory aggregator is pre-seeded with
// three tenants on 2026-07-01 (day period): high=500, mid=50, low=5 logins.
func topTenantsServer(t *testing.T) *httptest.Server {
	t.Helper()
	agg := meteringmemory.New()
	start := time.Date(2026, time.July, 1, 0, 0, 0, 0, time.UTC)
	agg.Record(&metering.TenantUsage{TenantID: "low", Period: metering.PeriodDay, PeriodStart: start, Logins: 5})
	agg.Record(&metering.TenantUsage{TenantID: "high", Period: metering.PeriodDay, PeriodStart: start, Logins: 500, TokensIssued: 900})
	agg.Record(&metering.TenantUsage{TenantID: "mid", Period: metering.PeriodDay, PeriodStart: start, Logins: 50})

	srv := sso.NewServer(
		sso.WithIssuer("https://sso.example"),
		sso.WithTenantUsageAggregator(agg),
	)
	hs := httptest.NewServer(srv.Handler())
	t.Cleanup(hs.Close)
	return hs
}

func TestTopTenantsRoute_RanksByLoginsAndHonorsLimit(t *testing.T) {
	hs := topTenantsServer(t)

	resp, err := http.Get(hs.URL + "/api/v1/admin/usage/top-tenants?period=day&start=2026-07-01&limit=2")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}

	var out struct {
		Status  string                  `json:"status"`
		Tenants []*metering.TenantUsage `json:"tenants"`
		Total   int                     `json:"total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out.Status != "ok" || out.Total != 2 || len(out.Tenants) != 2 {
		t.Fatalf("envelope = %+v, want status=ok total=2 len=2", out)
	}
	if out.Tenants[0].TenantID != "high" || out.Tenants[1].TenantID != "mid" {
		t.Errorf("ranking = [%s %s], want [high mid]", out.Tenants[0].TenantID, out.Tenants[1].TenantID)
	}
	if out.Tenants[0].Logins != 500 {
		t.Errorf("Logins = %d, want 500", out.Tenants[0].Logins)
	}
}

func TestTopTenantsRoute_BadInputs(t *testing.T) {
	hs := topTenantsServer(t)
	for _, q := range []string{"?period=week", "?limit=abc", "?limit=-1", "?start=notadate"} {
		resp, err := http.Get(hs.URL + "/api/v1/admin/usage/top-tenants" + q)
		if err != nil {
			t.Fatalf("GET %s: %v", q, err)
		}
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusBadRequest {
			t.Errorf("%s status = %d, want 400", q, resp.StatusCode)
		}
	}
}

// Group-prefix regression guard, same as TestTenantUsageRoute_ResolvesAtDocumentedPath.
func TestTopTenantsRoute_DoubledPrefixDoesNotResolve(t *testing.T) {
	hs := topTenantsServer(t)
	resp, err := http.Get(hs.URL + "/api/v1/api/v1/admin/usage/top-tenants")
	if err != nil {
		t.Fatalf("GET doubled: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("doubled path resolved (status %d), want 404", resp.StatusCode)
	}
}
```

(`srv.Handler()` without AdminMiddleware serves admin routes ungated — established precedent in `test/tenant_usage_route_test.go`.)

Run: `go test ./test/ -run TestTopTenantsRoute -v`
Expected: FAIL — 404 (route not mounted).

- [ ] **Step 2: Add const + alias + route**

`shared/core/consts.go` (directly below `PathTenantUsage`, line 166):

```go
	// PathAdminTopTenants is the read-only admin top-tenants usage leaderboard
	// (GET /api/v1/admin/usage/top-tenants?period=day|month&start=...&limit=N).
	// Returns the N tenants with the most successful logins in the period,
	// with the same aggregated counters as PathTenantUsage. Gated by
	// AdminMiddleware (admin:read). Only mounted when
	// WithTenantUsageAggregator is wired.
	//
	// Group-relative: mounted on the /api/v1 router group — see the
	// PathTenantUsage comment for the double-prefix regression a full
	// "/api/v1/..." value causes.
	PathAdminTopTenants = "/admin/usage/top-tenants"
```

`interfaces/sso/aliases.go` (next to line 313): `const PathAdminTopTenants = core.PathAdminTopTenants`

`interfaces/sso/server_routes_admin.go` (`mountAdminAPIObservability`):

```go
	if s.usageAggregator != nil {
		api.GET(PathTenantUsage, s.handleTenantUsage)
		api.GET(PathAdminTopTenants, s.handleAdminTopTenants)
	}
```

- [ ] **Step 3: Extract the shared window parser + add the handler**

In `interfaces/sso/server_discovery.go` (add `strconv` to imports):

```go
// parseUsageWindow parses the period/start query parameters shared by the
// usage/metering admin endpoints. On malformed input it writes the 400
// itself and returns ok=false.
func (s *Server) parseUsageWindow(ctx HandlerContext) (metering.UsagePeriod, time.Time, bool) {
	period := metering.UsagePeriod(ctx.Query("period"))
	if period == "" {
		period = metering.PeriodDay
	}
	if period != metering.PeriodDay && period != metering.PeriodMonth {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return "", time.Time{}, false
	}
	startStr := ctx.Query("start")
	if startStr == "" {
		return period, time.Now().UTC(), true
	}
	start, err := time.ParseInLocation("2006-01-02", startStr, time.UTC)
	if err != nil {
		ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
		return "", time.Time{}, false
	}
	return period, start, true
}
```

Shrink `handleTenantUsage` (lines 378-414) to: tenantID guard → `parseUsageWindow` → `s.usageAggregator.Usage` → `ctx.JSON(200, u)` — wire shape UNCHANGED. Then add:

```go
// handleAdminTopTenants serves GET /api/v1/admin/usage/top-tenants.
// Admin-gated (admin:read) by the /api/v1/admin/ prefix.
//
// Query parameters:
//
//	period=day|month   (default: day)
//	start=YYYY-MM-DD   (default: today UTC)
//	limit=N            (default: 10; implementations clamp the maximum)
func (s *Server) handleAdminTopTenants(ctx HandlerContext) {
	period, start, ok := s.parseUsageWindow(ctx)
	if !ok {
		return
	}
	limit := 10
	if v := ctx.Query("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			ctx.JSON(http.StatusBadRequest, errorBody(core.ErrInvalidRequest))
			return
		}
		limit = n
	}
	tops, err := s.usageAggregator.TopTenants(ctx.Request().Context(), period, start, limit)
	if err != nil {
		s.logger.Error("top-tenants usage aggregation failed", "error", err)
		ctx.JSON(http.StatusInternalServerError, errorBody(core.ErrInternal))
		return
	}
	if tops == nil {
		tops = []*metering.TenantUsage{}
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyStatus: StatusOK,
		"tenants": tops,
		"total":   len(tops),
	})
}
```

- [ ] **Step 4: Run tests + gates**

Run: `go test ./test/ -run TestTopTenantsRoute -race -v && go test ./interfaces/sso/ -run TenantUsage -race && go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: all PASS (existing per-tenant usage tests unchanged; server_discovery.go ~466/500).

- [ ] **Step 5: openapi.yaml + commit**

Add after the `/api/v1/admin/tenants/{id}/usage` block (copy its style: tags `[admin]`, `security: bearerAuth`, `period` enum day|month, `start` date, plus `limit` integer minimum 1 default 10; response schema: object with `status`, `tenants` (array of the same usage schema the per-tenant entry uses), `total`).

```bash
git add shared/core/consts.go interfaces/sso/aliases.go interfaces/sso/server_discovery.go interfaces/sso/server_routes_admin.go test/admin_top_tenants_test.go docs/openapi.yaml
git commit -m "feat(admin): expose metering TopTenants as a usage leaderboard endpoint

Aggregator.TopTenants was implemented in both metering backends and
doc-commented for operator dashboards, but no surface called it — an
operator had to know every tenant ID and iterate the per-tenant usage
endpoint to answer which tenants drive load. Mounts a read-only
GET /api/v1/admin/usage/top-tenants beside the existing per-tenant
usage route, sharing its window parsing.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 6: sso-ctl import — postgres target

**Files:**
- Modify: `cmd/sso-ctl/importcmd/importer.go` (114→~150 lines — `openDB` backend dispatch + `userStore` seam)
- Modify: `cmd/sso-ctl/importcmd/main.go` (187→~200 — `--backend`/`--dialect` flags, package doc + usage text de-SQLite-ified)
- Test: `cmd/sso-ctl/importcmd/main_test.go` (595 lines — _test.go exempt from budgets; update `openDB` call sites, add dispatch + guarded postgres tests)
- Modify: `README.md:203` (add the postgres invocation example)

**Interfaces:**
- Consumes: `core.UserProvider` (`shared/core/spi.go:42-53`: GetByID/GetByExternalID/CreateOrUpdate/List/Delete — the portable write contract `writeBatch` already uses); `sqlite.NewUserProvider(dsn)` (`infrastructure/defaultimpl/sqlite/users.go:73`); `postgres.NewUserProvider(cfg postgres.Config)` (`infrastructure/postgres/users.go:50` — parent module, runs the versioned users migration itself, so no separate migrate step); `postgres.Config{DSN, Dialect, ...}` (`pool.go:35-48`; `postgres.Open` errors `"postgres: dsn required"` on empty DSN before dialing — testable without a live DB); `postgres.Dialect` (`""`/unknown normalize to postgres; `"cockroach"` flips the migrate runner); hash-attribute seam `password_hash`/`password_hash_format` (`domains/authenticators/stored_hash_verifier.go:32-33`) must round-trip unchanged.
- Produces: `openDB(backend, dsn, dialect string) (userStore, error)`; local interface `type userStore interface { sso.UserProvider; Close() error }`; CLI flags `--backend sqlite|postgres` (default sqlite) and `--dialect postgres|cockroach`.

Design decisions (resolved): explicit `--backend` flag (matches the server's `identity.backend` vocabulary; DSN auto-detection is unsafe because pgx accepts keyword DSNs); include `--dialect` now (costs one flag, CockroachDB migrate branching is real); no pool-tuning flags (one-shot CLI is fine on defaults); guarded postgres integration test uses unique IDs + `Delete` cleanup, NOT `TRUNCATE` (the `infrastructure/postgres` package tests TRUNCATE the same table and may share the DSN).

- [ ] **Step 1: Write the failing dispatch tests**

Append to `cmd/sso-ctl/importcmd/main_test.go`:

```go
func TestOpenDB_UnknownBackend(t *testing.T) {
	t.Parallel()
	if _, err := openDB("mysql", "dsn", ""); err == nil {
		t.Fatal("expected error for unsupported --backend")
	}
}

// postgres.Open rejects an empty DSN before dialing (infrastructure/postgres/pool.go),
// so this exercises the postgres branch without a live database.
func TestOpenDB_PostgresEmptyDSN(t *testing.T) {
	t.Parallel()
	if _, err := openDB("postgres", "", ""); err == nil {
		t.Fatal("expected error for postgres backend with empty DSN")
	}
}
```

Run: `go test ./cmd/sso-ctl/importcmd/ -run TestOpenDB -v`
Expected: FAIL — `openDB` has the wrong arity (compile error).

- [ ] **Step 2: Implement the backend dispatch**

`cmd/sso-ctl/importcmd/importer.go` — replace the `openDB` region:

```go
// Backend selector values — match the server's identity.backend vocabulary
// (cmd/sso-server/serverbuildstore.BuildUserProvider).
const (
	backendSQLite   = "sqlite"
	backendPostgres = "postgres"
)

// userStore is the store seam the importer needs: the portable
// core.UserProvider read/write contract plus lifecycle Close.
// *sqlite.UserProvider and *postgres.UserProvider both satisfy it.
type userStore interface {
	sso.UserProvider
	Close() error
}

// openDB dials the selected backend and runs its schema migration, so import
// works against a fresh database with no separate migrate step. The postgres
// package blank-imports the pgx driver itself; the sqlite driver comes from
// this package's modernc.org/sqlite blank import (main.go).
func openDB(backend, dsn, dialect string) (userStore, error) {
	switch strings.ToLower(strings.TrimSpace(backend)) {
	case "", backendSQLite:
		p, err := sqlite.NewUserProvider(dsn)
		if err != nil {
			return nil, fmt.Errorf("sqlite: %w", err)
		}
		return p, nil
	case backendPostgres:
		p, err := postgres.NewUserProvider(postgres.Config{
			DSN:     dsn,
			Dialect: postgres.Dialect(dialect), // "" normalizes to postgres
		})
		if err != nil {
			return nil, err // already "postgres: ..."-prefixed by the package
		}
		return p, nil
	default:
		return nil, fmt.Errorf("unknown --backend %q (supported: sqlite, postgres)", backend)
	}
}
```

Change `runImport`/`writeBatch` receiver types from `*sqlite.UserProvider` to `userStore` (bodies untouched) and FIX the stale doc comment claiming "each batch is a single SQLite transaction" — batches bound error reporting; writes are per-row `CreateOrUpdate` upserts on every backend.

`cmd/sso-ctl/importcmd/main.go`:
- `importFlags` gains `backend`, `dialect string`.
- `parseFlags` adds `fs.String("backend", backendSQLite, "user store backend: sqlite | postgres")` and `fs.String("dialect", "", "postgres dialect: postgres | cockroach (only with --backend postgres)")`; generalize the `--dsn` help text.
- `Run()`: `openDB(cfg.backend, cfg.dsn, cfg.dialect)`.
- Package doc + `usageFunc`: replace "into the SSO server's SQLite user store" wording; add the postgres example invocation.

Update existing call sites in `main_test.go`: `openDB(dsn)` → `openDB("sqlite", dsn, "")` (`newTestProvider` ~line 366, `TestOpenDB_BadDSN` ~line 376, `TestRun_FullImport` reopen ~line 559); `newTestProvider` return type becomes `userStore`.

- [ ] **Step 3: Add the guarded postgres integration test**

Append to `main_test.go`:

```go
// testPostgresDSN returns the integration DSN or skips — CI without a DB skips.
func testPostgresDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("SSO_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("SSO_TEST_POSTGRES_DSN not set — skipping postgres integration test")
	}
	return dsn
}

// TestRunImport_Postgres_PersistsAndUpserts drives the full write path against
// a real Postgres users table via the same userStore seam the CLI uses, then
// re-reads through core.UserProvider to confirm the hash attributes landed.
// Unique IDs + Delete cleanup (not TRUNCATE) — the infrastructure/postgres
// package tests TRUNCATE this table and may run concurrently on the same DSN.
func TestRunImport_Postgres_PersistsAndUpserts(t *testing.T) {
	t.Parallel()
	p, err := openDB("postgres", testPostgresDSN(t), os.Getenv("SSO_TEST_POSTGRES_DIALECT"))
	if err != nil {
		t.Fatalf("openDB postgres: %v", err)
	}
	t.Cleanup(func() { _ = p.Close() })
	ctx := context.Background()
	id := "importtest:" + strings.ToLower(t.Name())
	t.Cleanup(func() { _ = p.Delete(ctx, id) })

	users := []importedUser{{
		ID: id, ExternalID: "pg-1", Provider: "auth0",
		Email: "pg@x.z", Name: "PG", Hash: "$2b$h", HashFormat: "bcrypt",
	}}
	if err := runImport(ctx, p, users, 100); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	got, err := p.GetByID(ctx, id)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	// Seam contract with domains/authenticators.StoredHashVerifier.
	if got.Attributes["password_hash"] != "$2b$h" || got.Attributes["password_hash_format"] != "bcrypt" {
		t.Errorf("hash attrs did not round-trip: %+v", got.Attributes)
	}
	users[0].Name = "PG2"
	if err := runImport(ctx, p, users, 100); err != nil {
		t.Fatalf("re-import: %v", err)
	}
	got2, _ := p.GetByID(ctx, id)
	if got2.Name != "PG2" {
		t.Errorf("upsert did not update name; got %q", got2.Name)
	}
}
```

- [ ] **Step 4: Run tests + gates**

Run: `go test ./cmd/sso-ctl/importcmd/ -race -v && go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: PASS (postgres integration test skips without `SSO_TEST_POSTGRES_DSN`; run with a local DSN if available).

- [ ] **Step 5: README + commit**

`README.md` line 203 — add next to the sqlite example:

```
sso-ctl import --backend postgres --dsn 'postgres://sso@db:5432/sso?sslmode=disable' --format keycloak --file realm.json
```

```bash
git add cmd/sso-ctl/importcmd/importer.go cmd/sso-ctl/importcmd/main.go cmd/sso-ctl/importcmd/main_test.go README.md
git commit -m "feat(sso-ctl): let import target the postgres user store

The bulk importer (Auth0/Keycloak/CSV) hardcoded sqlite.NewUserProvider,
so a migration cutover onto the HA Postgres identity backend required
importing to SQLite and hand-copying rows. Adds --backend sqlite|postgres
and --dialect postgres|cockroach, dispatching openDB across a small
userStore seam (core.UserProvider + Close) that both providers satisfy;
postgres.NewUserProvider runs the users migration itself so no separate
migrate step is needed.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 7: Operationalize the SQLite backup endpoint

**Files:**
- Modify: `interfaces/sso/server_backup.go` (36 lines — rewrite as three small functions)
- Modify: `interfaces/sso/options_admin.go` (27 lines — the options' home; do NOT touch `options_misc.go` (over budget until Task 0 fixes it) and do NOT create a new file in `interfaces/sso` (fanout))
- Modify: `interfaces/sso/sso_selfservice.go` (226 lines — two fields after `backupSources`, lines 39-42)
- Modify: `shared/core/consts.go` (add `BackupFilePrefix` next to `PathBackup`, lines 150-154)
- Modify: `config/config_snapshot.go` (172 lines — `BackupConfig` groups with the other ops/DR configs; do NOT create `config_backup.go`, `config/` is over its fanout ceiling), `config/config.go:29` (root field), `config/config_load.go` (`validate()` :109-135 + `ServerOptions()` :140-166)
- Test: create `test/admin_backup_test.go` (package `ssotest`)
- Modify: `docs/openapi.yaml` (POST `/api/v1/admin/backup` — does NOT exist yet; model on the storage-health block, lines 3373-3426) + `docs/config-reference.md` (Backup section)

**Interfaces:**
- Consumes: `core.BackupSource{Name() string; BackupTo(ctx, destPath string) error}` (`shared/core/backup.go:8-15`); `sso.WithBackupSource` (`options_misc.go:496` — leave in place); route mount `if len(s.backupSources) > 0 { api.POST(PathBackup, s.handleAdminBackup) }` (`server_routes_admin.go:33-37`); retention idiom `snapshot.PruneOldest` (`interfaces/snapshot/retention.go:29-69` — prefix filter, sort ascending, delete all but newest N, first error wins but continue); real-store test seam `sqlitestores.NewClientStore(dsn)` + `.DB()` (`infrastructure/defaultimpl/sqlite/clients.go:88,121`); config plumbing `validate()`/`ServerOptions()` consumed at `cmd/sso-server/build_app_core.go:153`.
- Produces: `sso.WithBackupDir(dir string) Option`, `sso.WithBackupRetention(keep int) Option`, `config.BackupConfig{Dir, Keep}` (`backup.dir`/`backup.keep`, env `SSO_BACKUP__DIR`/`SSO_BACKUP__KEEP`), `core.BackupFilePrefix = "sso-backup-"`, response entries `{name, status, path, size_bytes, duration_ms, pruned}`.

Design decisions (resolved): timestamped filenames `sso-backup-<source>-<UTC stamp>.db` (fixed-width stamp → lexicographic = chronological; this replaces the old fixed-name overwrite, so without retention the dir grows — document in config-reference). Default dir stays `os.TempDir()` (preserves current behavior). Retention opt-in (`0` = keep all; never silently delete by default). Per-source failure stays a `{status:"failed"}` entry in a 200 summary (same fail-open contract as storage-health); `MkdirAll` failure logs and lets each `BackupTo` fail per-source. `filepath.Base(src.Name())` defends the filename against separator injection. `pruned` is a count (bounded cardinality).

- [ ] **Step 1: Write the failing tests**

Create `test/admin_backup_test.go`:

```go
package ssotest

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	sqlitestores "github.com/snaplink/sso/infrastructure/defaultimpl/sqlite"
	"github.com/snaplink/sso/interfaces/sso"
)

// sqliteBackupSource adapts a real modernc SQLite store into a
// core.BackupSource the way an SDK operator would: VACUUM INTO against
// the store's live *sql.DB. No mocks — the destination file is a real
// SQLite database, so the size/duration metadata assertions are honest.
type sqliteBackupSource struct {
	name string
	db   *sql.DB
}

func (b sqliteBackupSource) Name() string { return b.name }
func (b sqliteBackupSource) BackupTo(ctx context.Context, dest string) error {
	_, err := b.db.ExecContext(ctx, "VACUUM INTO ?", dest)
	return err
}

func newBackupHarness(t *testing.T, opts ...sso.Option) *httptest.Server {
	t.Helper()
	store, err := sqlitestores.NewClientStore("file:backup_clients_" + t.Name() + "?mode=memory&cache=shared")
	if err != nil {
		t.Fatalf("client store: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	opts = append(opts, sso.WithBackupSource(sqliteBackupSource{name: "clients", db: store.DB()}))
	srv := sso.NewServer(opts...)
	httpSrv := httptest.NewServer(srv.Handler())
	t.Cleanup(httpSrv.Close)
	return httpSrv
}

func backupPOST(t *testing.T, base string) (int, map[string]any) {
	t.Helper()
	resp, err := http.Post(base+"/api/v1/admin/backup", "application/json", nil)
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, _ := io.ReadAll(resp.Body)
	var out map[string]any
	if len(body) > 0 {
		_ = json.Unmarshal(body, &out)
	}
	return resp.StatusCode, out
}

func firstSource(t *testing.T, body map[string]any) map[string]any {
	t.Helper()
	raw, ok := body["sources"].([]any)
	if !ok || len(raw) == 0 {
		t.Fatalf("missing sources array: %v", body)
	}
	entry, ok := raw[0].(map[string]any)
	if !ok {
		t.Fatalf("source entry not an object: %v", raw[0])
	}
	return entry
}

func TestAdminBackup_WritesToConfiguredDirWithMetadata(t *testing.T) {
	dir := t.TempDir()
	srv := newBackupHarness(t, sso.WithBackupDir(dir))
	code, body := backupPOST(t, srv.URL)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	entry := firstSource(t, body)
	if entry["status"] != "ok" {
		t.Fatalf("source status = %v, want ok: %v", entry["status"], entry)
	}
	path, _ := entry["path"].(string)
	if filepath.Dir(path) != dir {
		t.Errorf("path %q not under configured dir %q", path, dir)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatalf("backup file missing on disk: %v", err)
	}
	if sz, _ := entry["size_bytes"].(float64); int64(sz) != fi.Size() || fi.Size() == 0 {
		t.Errorf("size_bytes = %v, want on-disk size %d (> 0)", entry["size_bytes"], fi.Size())
	}
	if _, ok := entry["duration_ms"].(float64); !ok {
		t.Errorf("missing duration_ms: %v", entry)
	}
}

func TestAdminBackup_RetentionPrunesOldestKeepingNewestN(t *testing.T) {
	dir := t.TempDir()
	// Stale backups with fixed-width timestamps: lexicographic sort ==
	// chronological, so these three are strictly older than the fresh one.
	stale := []string{
		"sso-backup-clients-20200101T000000.000000000.db",
		"sso-backup-clients-20200102T000000.000000000.db",
		"sso-backup-clients-20200103T000000.000000000.db",
	}
	for _, name := range stale {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	// A foreign file sharing the dir but not the per-source prefix must
	// survive (mirrors snapshot.PruneOldest's prefix-filter guarantee).
	foreign := filepath.Join(dir, "operator-notes.txt")
	if err := os.WriteFile(foreign, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}

	srv := newBackupHarness(t, sso.WithBackupDir(dir), sso.WithBackupRetention(2))
	code, body := backupPOST(t, srv.URL)
	if code != http.StatusOK {
		t.Fatalf("status = %d, body = %v", code, body)
	}
	entry := firstSource(t, body)
	if pruned, _ := entry["pruned"].(float64); int(pruned) != 2 {
		t.Errorf("pruned = %v, want 2 (3 stale + 1 fresh, keep 2)", entry["pruned"])
	}
	if _, err := os.Stat(filepath.Join(dir, stale[0])); !os.IsNotExist(err) {
		t.Errorf("oldest stale backup survived pruning")
	}
	if _, err := os.Stat(foreign); err != nil {
		t.Errorf("foreign file was wrongly deleted: %v", err)
	}
}
```

NOTE: if `VACUUM INTO ?` rejects the bind parameter under modernc.org/sqlite, switch the test adapter to building the statement with a single-quote-escaped literal path — the adapter is test-local, the product code never runs VACUUM itself.

Run: `go test ./test/ -run TestAdminBackup -v`
Expected: FAIL — `undefined: sso.WithBackupDir`.

- [ ] **Step 2: Add state fields, options, and the filename-prefix const**

`shared/core/consts.go` (near `PathBackup`):

```go
	// BackupFilePrefix names admin-triggered backup files
	// (<prefix><source>-<utc-stamp>.db); the retention pruner filters on
	// it so unrelated files sharing the destination dir are never deleted.
	BackupFilePrefix = "sso-backup-"
```

`interfaces/sso/sso_selfservice.go` (after `backupSources`, line 42):

```go
	// backupDir overrides where admin-triggered backups land
	// (WithBackupDir). Empty = os.TempDir(), preserving the
	// pre-config behavior of writing under the OS temp dir.
	backupDir string
	// backupKeep bounds retained backup files per source
	// (WithBackupRetention). 0 = keep everything.
	backupKeep int
```

`interfaces/sso/options_admin.go` (append):

```go
// WithBackupDir sets the destination directory for POST /api/v1/admin/backup
// (VACUUM INTO snapshots). Empty (default) falls back to the OS temp dir.
func WithBackupDir(dir string) Option {
	return func(s *Server) {
		if dir != "" {
			s.backupDir = dir
		}
	}
}

// WithBackupRetention keeps only the newest keep backup files per source
// after each successful backup. 0 (default) disables pruning.
func WithBackupRetention(keep int) Option {
	return func(s *Server) {
		if keep > 0 {
			s.backupKeep = keep
		}
	}
}
```

- [ ] **Step 3: Rewrite the handler**

`interfaces/sso/server_backup.go` (three functions, each ≤ 50 lines):

```go
package sso

import (
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/snaplink/sso/shared/core"
)

// backupStampLayout is fixed-width + zero-padded so lexicographic order
// of filenames equals chronological order — the pruner relies on it.
const (
	backupStampLayout = "20060102T150405.000000000"
	backupFileExt     = ".db"
)

func (s *Server) handleAdminBackup(ctx HandlerContext) {
	dir := s.backupDir
	if dir == "" {
		dir = os.TempDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		s.logger.Error("backup dir create failed", "dir", dir, "error", err)
	}
	results := make([]map[string]any, 0, len(s.backupSources))
	for _, src := range s.backupSources {
		results = append(results, s.backupOneSource(ctx, src, dir))
	}
	ctx.JSON(http.StatusOK, map[string]any{KeyStatus: StatusOK, "sources": results})
}

// backupOneSource runs a single VACUUM INTO and reports operator metadata.
// Failures stay per-source (endpoint always 200s a summary — same
// fail-open contract as storage-health); detail goes to the log only.
func (s *Server) backupOneSource(ctx HandlerContext, src core.BackupSource, dir string) map[string]any {
	prefix := core.BackupFilePrefix + filepath.Base(src.Name()) + "-"
	dest := filepath.Join(dir, prefix+time.Now().UTC().Format(backupStampLayout)+backupFileExt)
	start := time.Now()
	if err := src.BackupTo(ctx.Request().Context(), dest); err != nil {
		s.logger.Error("backup failed", "source", src.Name(), "error", err)
		return map[string]any{"name": src.Name(), "status": "failed"}
	}
	out := map[string]any{
		"name":        src.Name(),
		"status":      StatusOK,
		"path":        dest,
		"duration_ms": time.Since(start).Milliseconds(),
	}
	if fi, err := os.Stat(dest); err == nil {
		out["size_bytes"] = fi.Size()
	}
	if s.backupKeep > 0 {
		pruned, err := pruneBackups(dir, prefix, s.backupKeep)
		if err != nil {
			s.logger.Error("backup prune failed", "source", src.Name(), "error", err)
		}
		out["pruned"] = pruned
	}
	return out
}

// pruneBackups mirrors snapshot.PruneOldest: prefix-filter so foreign
// files in the shared dir are never deleted, sort ascending (fixed-width
// stamps make lexicographic == chronological), remove all but the newest
// keep, first error wins but pruning continues.
func pruneBackups(dir, prefix string, keep int) (int, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && strings.HasPrefix(e.Name(), prefix) && strings.HasSuffix(e.Name(), backupFileExt) {
			names = append(names, e.Name())
		}
	}
	if len(names) <= keep {
		return 0, nil
	}
	sort.Strings(names)
	var pruned int
	var firstErr error
	for _, n := range names[:len(names)-keep] {
		if err := os.Remove(filepath.Join(dir, n)); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		pruned++
	}
	return pruned, firstErr
}
```

(Adjust the existing route-mount guard if it differs; the route stays mounted only when `len(s.backupSources) > 0`.)

- [ ] **Step 4: Config plumbing**

`config/config_snapshot.go` (append):

```go
// BackupConfig configures the admin online-backup endpoint
// (POST /api/v1/admin/backup). Dir is where VACUUM INTO snapshots land
// (empty = OS temp dir); Keep retains only the newest N backup files per
// source after each run (0 = keep all).
type BackupConfig struct {
	Dir  string `yaml:"dir"`
	Keep int    `yaml:"keep"`
}
```

`config/config.go`: add `Backup BackupConfig \`yaml:"backup"\`` after `Releases` (~line 29). Env mapping is free: `SSO_BACKUP__DIR` / `SSO_BACKUP__KEEP`.

`config/config_load.go`:
- `validate()`: `if c.Backup.Keep < 0 { return fmt.Errorf("config: backup.keep must be >= 0 (0 disables retention), got %d", c.Backup.Keep) }`
- `ServerOptions()`: append `sso.WithBackupDir(c.Backup.Dir)` when `Dir != ""` and `sso.WithBackupRetention(c.Backup.Keep)` when `Keep > 0`.

- [ ] **Step 5: Run tests + gates**

Run: `go test ./test/ -run TestAdminBackup -race -v && go test ./config/ -race && go build ./... && go vet ./... && go test -run 'TestMaintainability_|TestArchitecture_ImportBoundaries' ./...`
Expected: all PASS.

- [ ] **Step 6: Docs + commit**

- `docs/openapi.yaml`: add POST `/api/v1/admin/backup` (tags [admin], operationId `triggerBackup`, bearerAuth, admin:write; 200 response schema `{status, sources: [{name, status, path, size_bytes, duration_ms, pruned}]}` as a `BackupReport` component; 401 $ref Unauthorized) after the storage-health block.
- `docs/config-reference.md`: new `## Backup` section after `## Snapshot` (line 122): `backup.dir` (destination for admin-triggered VACUUM INTO backups; empty = OS temp dir; note: filenames are timestamped, so without `keep` the dir grows monotonically) and `backup.keep` (retain newest N per source; 0 = keep all).

```bash
git add interfaces/sso/server_backup.go interfaces/sso/options_admin.go interfaces/sso/sso_selfservice.go shared/core/consts.go config/config_snapshot.go config/config.go config/config_load.go test/admin_backup_test.go docs/openapi.yaml docs/config-reference.md
git commit -m "feat(admin): operationalize the online-backup endpoint

POST /api/v1/admin/backup wrote a fixed-name file into a hardcoded /tmp
path — frequently tmpfs, gone on reboot, unreachable from outside the
pod, and giving false backup confidence. Adds a configurable destination
directory (backup.dir / WithBackupDir), per-source response metadata
(path, size_bytes, duration_ms), timestamped filenames, and opt-in
keep-newest-N retention with a prefix filter so foreign files in the
directory are never touched.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 8: Alert rules for silent audit loss + signing-backend health

**Files:**
- Modify: `ops/deploy/grafana/alerts.yaml` (122 lines — append 4 rules to the existing `sso-server` group; copy its conventions exactly: `SSO<PascalCase>` names, `expr: |` block scalar, `for:` debounce, labels `severity` + `component: sso-server`, `summary`/`description` annotations)
- Modify: `ops/deploy/grafana/sso-overview.json` (249 lines — new row id 40 + 3 panels ids 41-43 at y=32/33, inserted before the closing `]`; previous last panel gains a trailing comma)
- Create: `platform/metrics/alert_rules_test.go` (committed gate test, package `metrics_test` — test files exempt from fanout/budget gates)
- Modify: `ops/deploy/grafana/README.md` (rule/panel counts + 4 table rows) + `docs/observability.md` (add the missing `sso_audit_async_*` metric rows)

**Interfaces:**
- Consumes (exact metric-name constants, verified): `metrics.NameAuditAsyncDropsQueueFull/Closed/InnerError`, `NameAuditAsyncQueueDepth/Capacity` (`platform/metrics/audit_async.go:12-16`); `NameSigningBackendUp` (GaugeVec by `alg`, "alert on 0 — fires before /readyz drains the replica"), `NameSigningKeyAggregationUp` (unlabeled), `NameSigningKeyAdoptionErrorsTotal` (by `reason`) (`platform/metrics/consts.go:29-34`). Compose mounts `ops/deploy/grafana/alerts.yaml` into Prometheus (`ops/deploy/compose/compose.yaml:78`). YAML parser for the test: `github.com/goccy/go-yaml` (already a direct dep).
- Produces: alerts `SSOAuditEventsDropped` (critical), `SSOAuditQueueSaturated` (warning), `SSOSigningBackendDown` (critical), `SSOSigningKeyAggregationDegraded` (warning); dashboard row "Audit pipeline & signing health" with 3 panels; gate test cross-referencing artifacts against the metric constants.

Design decisions (resolved): one summed drops alert (per-cause detail lives in the dashboard panel), severity critical (silent compliance-relevant loss, fail-open pipeline has no other signal); `for: 1m` on drops to absorb single-scrape flaps; adoption-errors metric is panel-only (no alert); the gate test lives beside the constants it references (`platform/metrics`); no promtool CI step (no rules-validation infra exists — the Go gate test covers structure and metric-name drift).

- [ ] **Step 1: Write the failing gate test**

Create `platform/metrics/alert_rules_test.go`:

```go
package metrics_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/goccy/go-yaml"

	"github.com/snaplink/sso/platform/metrics"
)

// The compose observability profile bind-mounts these artifacts straight
// into Prometheus/Grafana (ops/deploy/compose/compose.yaml), so a renamed
// metric or malformed file fails silently at container start. This gate
// cross-references them against the metric-name wire constants.
const (
	alertRulesPath = "../../ops/deploy/grafana/alerts.yaml"
	dashboardPath  = "../../ops/deploy/grafana/sso-overview.json"
)

type promRule struct {
	Alert       string            `yaml:"alert"`
	Expr        string            `yaml:"expr"`
	For         string            `yaml:"for"`
	Labels      map[string]string `yaml:"labels"`
	Annotations map[string]string `yaml:"annotations"`
}

type promRuleFile struct {
	Groups []struct {
		Name  string     `yaml:"name"`
		Rules []promRule `yaml:"rules"`
	} `yaml:"groups"`
}

func loadAlertRules(t *testing.T) map[string]promRule {
	t.Helper()
	raw, err := os.ReadFile(alertRulesPath)
	if err != nil {
		t.Fatalf("read %s: %v", alertRulesPath, err)
	}
	var f promRuleFile
	if err := yaml.Unmarshal(raw, &f); err != nil {
		t.Fatalf("parse %s: %v", alertRulesPath, err)
	}
	rules := make(map[string]promRule)
	for _, g := range f.Groups {
		for _, r := range g.Rules {
			rules[r.Alert] = r
		}
	}
	return rules
}

func TestDeployAlerts_AuditLossAndSigningDegradationCovered(t *testing.T) {
	t.Parallel()
	rules := loadAlertRules(t)
	want := map[string][]string{
		"SSOAuditEventsDropped": {
			metrics.NameAuditAsyncDropsQueueFull,
			metrics.NameAuditAsyncDropsClosed,
			metrics.NameAuditAsyncDropsInnerError,
		},
		"SSOAuditQueueSaturated": {
			metrics.NameAuditAsyncQueueDepth,
			metrics.NameAuditAsyncQueueCapacity,
		},
		"SSOSigningBackendDown":            {metrics.NameSigningBackendUp},
		"SSOSigningKeyAggregationDegraded": {metrics.NameSigningKeyAggregationUp},
	}
	for name, metricNames := range want {
		r, ok := rules[name]
		if !ok {
			t.Errorf("alert %q missing from %s", name, alertRulesPath)
			continue
		}
		for _, m := range metricNames {
			if !strings.Contains(r.Expr, m) {
				t.Errorf("alert %q expr does not reference %s:\n%s", name, m, r.Expr)
			}
		}
	}
}

func TestDeployAlerts_ConventionsHold(t *testing.T) {
	t.Parallel()
	validSeverity := map[string]bool{"info": true, "warning": true, "critical": true}
	for name, r := range loadAlertRules(t) {
		if !validSeverity[r.Labels["severity"]] {
			t.Errorf("alert %q severity %q not in info|warning|critical", name, r.Labels["severity"])
		}
		if r.Labels["component"] != "sso-server" {
			t.Errorf("alert %q missing component=sso-server label", name)
		}
		if r.Annotations["summary"] == "" || r.Annotations["description"] == "" {
			t.Errorf("alert %q missing summary/description annotation", name)
		}
	}
}

func TestDeployDashboard_AuditAndSigningPanelsPresent(t *testing.T) {
	t.Parallel()
	raw, err := os.ReadFile(dashboardPath)
	if err != nil {
		t.Fatalf("read %s: %v", dashboardPath, err)
	}
	var dash struct {
		Panels []struct {
			Title   string `json:"title"`
			Targets []struct {
				Expr string `json:"expr"`
			} `json:"targets"`
		} `json:"panels"`
	}
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("parse %s: %v", dashboardPath, err)
	}
	var all strings.Builder
	for _, p := range dash.Panels {
		for _, tg := range p.Targets {
			all.WriteString(tg.Expr)
			all.WriteString("\n")
		}
	}
	exprs := all.String()
	for _, m := range []string{
		metrics.NameAuditAsyncDropsQueueFull,
		metrics.NameAuditAsyncDropsClosed,
		metrics.NameAuditAsyncDropsInnerError,
		metrics.NameAuditAsyncQueueDepth,
		metrics.NameAuditAsyncQueueCapacity,
		metrics.NameSigningBackendUp,
		metrics.NameSigningKeyAggregationUp,
		metrics.NameSigningKeyAdoptionErrorsTotal,
	} {
		if !strings.Contains(exprs, m) {
			t.Errorf("no dashboard panel target references %s", m)
		}
	}
}
```

Run: `go test ./platform/metrics/ -run TestDeploy -v`
Expected: FAIL — the four alerts and three panels do not exist yet.

- [ ] **Step 2: Append the four alert rules**

Append to the `sso-server` group in `ops/deploy/grafana/alerts.yaml` (after the last rule, line 122):

```yaml
      - alert: SSOAuditEventsDropped
        # Any drop is SILENT audit-trail loss: the async sink is
        # deliberately fail-open (auth keeps working) so this alert is
        # the only signal. queue_full = buffer saturated at Record
        # time; closed = Record after Close (shutdown-ordering bug in
        # the embedding app); inner_error = the leaf sink rejected an
        # event the worker dequeued.
        expr: |
          sum(increase(sso_audit_async_drops_queue_full_total[5m]))
            + sum(increase(sso_audit_async_drops_closed_total[5m]))
            + sum(increase(sso_audit_async_drops_inner_error_total[5m]))
            > 0
        for: 1m
        labels:
          severity: critical
          component: sso-server
        annotations:
          summary: "SSO audit events dropped - silent audit-trail loss"
          description: |
            {{ $value | humanize }} audit events dropped in the last 5m.
            Check the per-cause panel on the sso-overview dashboard:
            queue_full means the inner sink can't keep up (grow
            audit.async.buffer / workers), inner_error means the leaf
            sink is rejecting events (network / validation), closed
            means Record after Close (fix shutdown ordering).

      - alert: SSOAuditQueueSaturated
        # >80% fill sustained means the buffer is about to overflow
        # into queue_full drops - the early-warning stage of
        # SSOAuditEventsDropped. Both gauges are per-instance scrapes
        # with identical labels so plain division vector-matches.
        expr: |
          sso_audit_async_queue_depth
            / sso_audit_async_queue_capacity
            > 0.8
        for: 5m
        labels:
          severity: warning
          component: sso-server
        annotations:
          summary: "SSO audit async queue >80% full on {{ $labels.instance }}"
          description: |
            Queue fill ratio is {{ $value | humanizePercentage }} for 5m.
            The inner sink is falling behind sustained event volume -
            drops begin at 100%. Increase audit.async.buffer, add
            workers, or investigate the slow leaf sink.

      - alert: SSOSigningBackendDown
        # sso_signing_backend_up is only ever set when an external
        # KMS/HSM signer is wired, and token issuance fails CLOSED on
        # signing errors - 0 here means live /token 5xx for that alg,
        # firing before /readyz drains the replica.
        expr: sso_signing_backend_up == 0
        for: 2m
        labels:
          severity: critical
          component: sso-server
        annotations:
          summary: "SSO signing backend down for alg {{ $labels.alg }} on {{ $labels.instance }}"
          description: |
            The last external signing operation for {{ $labels.alg }}
            failed and the backend has not recovered in 2m. Token
            issuance for this alg is failing closed. Check KMS/HSM
            reachability, throttling, and sso_signing_operations_total
            error rates.

      - alert: SSOSigningKeyAggregationDegraded
        # Leaderless JWKS aggregation lost its registry subscription:
        # this replica keeps signing locally but STOPS adopting peers'
        # newly-rotated keys, so peer-issued tokens start failing
        # verification here after the next rotation.
        expr: sso_signing_key_aggregation_up == 0
        for: 5m
        labels:
          severity: warning
          component: sso-server
        annotations:
          summary: "SSO signing-key aggregation degraded on {{ $labels.instance }}"
          description: |
            The signing-key registry subscription has been down for 5m
            (Subscribe channel closed, loop retrying). Peer key
            rotations are not being adopted - unknown-kid validation
            failures follow the next rotation. Check the registry
            backend (etcd) health and
            sso_signing_key_adoption_errors_total by reason.
```

- [ ] **Step 3: Add the dashboard row + 3 panels**

In `ops/deploy/grafana/sso-overview.json`, insert before the closing `]` of `panels` (line 248; the previous last panel object gains a trailing comma):

```json
    {
      "id": 40,
      "type": "row",
      "title": "Audit pipeline & signing health",
      "gridPos": { "h": 1, "w": 24, "x": 0, "y": 32 }
    },
    {
      "id": 41,
      "type": "timeseries",
      "title": "Audit async drops / sec by cause",
      "datasource": { "type": "prometheus", "uid": "${datasource}" },
      "gridPos": { "h": 8, "w": 8, "x": 0, "y": 33 },
      "description": "Any non-zero series is silent audit-trail loss - the async sink is fail-open by design (SSOAuditEventsDropped alert).",
      "targets": [
        { "expr": "sum(rate(sso_audit_async_drops_queue_full_total{instance=~\"$instance\"}[5m]))", "legendFormat": "queue_full" },
        { "expr": "sum(rate(sso_audit_async_drops_closed_total{instance=~\"$instance\"}[5m]))", "legendFormat": "closed" },
        { "expr": "sum(rate(sso_audit_async_drops_inner_error_total{instance=~\"$instance\"}[5m]))", "legendFormat": "inner_error" }
      ],
      "fieldConfig": { "defaults": { "unit": "ops" } }
    },
    {
      "id": 42,
      "type": "timeseries",
      "title": "Audit queue fill ratio",
      "datasource": { "type": "prometheus", "uid": "${datasource}" },
      "gridPos": { "h": 8, "w": 8, "x": 8, "y": 33 },
      "description": "sso_audit_async_queue_depth / capacity per instance. Drops begin at 1.0; alert fires at 0.8.",
      "targets": [
        { "expr": "sso_audit_async_queue_depth{instance=~\"$instance\"} / sso_audit_async_queue_capacity{instance=~\"$instance\"}", "legendFormat": "{{instance}}" }
      ],
      "fieldConfig": {
        "defaults": {
          "unit": "percentunit",
          "thresholds": {
            "mode": "absolute",
            "steps": [
              { "color": "green", "value": null },
              { "color": "yellow", "value": 0.5 },
              { "color": "red", "value": 0.8 }
            ]
          }
        }
      }
    },
    {
      "id": 43,
      "type": "timeseries",
      "title": "Signing health (KMS backend + key aggregation)",
      "datasource": { "type": "prometheus", "uid": "${datasource}" },
      "gridPos": { "h": 8, "w": 8, "x": 16, "y": 33 },
      "description": "Gauges sit at 1 when healthy; no series when no external signer / registry is wired. Adoption errors indicate a peer publishing bad keys.",
      "targets": [
        { "expr": "min by (alg) (sso_signing_backend_up{instance=~\"$instance\"})", "legendFormat": "backend up {{alg}}" },
        { "expr": "min(sso_signing_key_aggregation_up{instance=~\"$instance\"})", "legendFormat": "aggregation up" },
        { "expr": "sum by (reason) (rate(sso_signing_key_adoption_errors_total{instance=~\"$instance\"}[5m]))", "legendFormat": "adoption errors {{reason}}" }
      ],
      "fieldConfig": { "defaults": { "unit": "short" } }
    }
```

- [ ] **Step 4: Run the gate test**

Run: `go test ./platform/metrics/ -race -v`
Expected: PASS (all three new tests + existing metrics tests).

- [ ] **Step 5: Update the two docs + commit**

- `ops/deploy/grafana/README.md`: rules count "six rules" → "ten rules" (lines 10, 46-47), panels "12 panels across 4 rows" → "15 panels across 5 rows" (line 9); add 4 rows to the Rules table (lines 49-56) and 3 rows to the Panels table (lines 28-41):

```markdown
| `SSOAuditEventsDropped`            | critical | any audit async drop counter increased over 5m       |
| `SSOAuditQueueSaturated`           | warning  | audit queue depth / capacity > 80% for 5m             |
| `SSOSigningBackendDown`            | critical | `sso_signing_backend_up == 0` for 2m (per alg)        |
| `SSOSigningKeyAggregationDegraded` | warning  | `sso_signing_key_aggregation_up == 0` for 5m          |
```

- `docs/observability.md` metrics table (lines 9-31): add `sso_audit_async_drops_{queue_full,closed,inner_error}_total | Counter | —` and `sso_audit_async_queue_{depth,capacity} | Gauge | —` (collapsed-brace style matches existing rows).

```bash
git add ops/deploy/grafana/alerts.yaml ops/deploy/grafana/sso-overview.json ops/deploy/grafana/README.md platform/metrics/alert_rules_test.go docs/observability.md
git commit -m "feat(ops): alert rules + dashboard panels for audit loss and signing health

The audit async sink is fail-open by design and the signing gauges are
documented as alert-on-0, but the shipped Prometheus rules consumed
neither - dropped audit events and a dead KMS backend were silent.
Adds four rules (summed drops critical, queue saturation warning,
signing backend down critical, key-aggregation degraded warning), a
dashboard row with per-cause drop rates / queue fill / signing health,
and a committed gate test that cross-references both artifacts against
the metric-name constants so renames cannot silently orphan them.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

### Task 9: config-reference.md postgres backend matrix (docs-only)

**Files:**
- Modify: `docs/config-reference.md` (126 lines; currently ZERO mentions of postgres — four edits below)
- Verified NO change needed: `docs/feature-matrix.md` (pure spec-endpoint matrix, no storage rows), `docs/deployment.md` (already documents postgres correctly — use as phrasing source)

**ACCURACY TRAPS (verified against the build dispatchers — do not "fix" these into the doc):**
- `self_service.consent.backend` and `self_service.password.backend` do NOT accept `redis` via these keys (the Redis consent/password peers wire through the redis module separately) — accepted: off/memory/sqlite/postgres.
- The four OAuth hot stores share ONE key `oauth.backend` (memory/sqlite/redis) — `oauth.<store>.backend` does not exist.
- `network.store` is the netpolicy key, not `network.store.backend`.
- Do NOT touch any `*.out.md` file (pipeline-generated artifacts, many dirty in the working tree). `git add docs/config-reference.md` ONLY — never `git add -A`.

- [ ] **Step 1: Write the failing verification script**

Save as `/tmp/verify-config-reference.sh` (not committed):

```bash
#!/usr/bin/env bash
set -euo pipefail
DOC=docs/config-reference.md

for key in identity.backend native_sso.backend self_service.consent.backend \
           self_service.password.backend tenant.backend permissions.backend \
           audit.backend server.pairwise_subjects.backend authenticators.totp.backend \
           webauthn.storage.users.backend; do
  grep -q "$key" "$DOC" || { echo "MISSING key $key"; exit 1; }
  grep "$key" "$DOC" | grep -q postgres || { echo "$key row lacks postgres"; exit 1; }
done

grep 'identity.session_backend' "$DOC" | grep -q 'redis.*postgres\|postgres.*redis' \
  || { echo "identity.session_backend missing redis+postgres"; exit 1; }

for k in postgres.dsn postgres.dialect postgres.max_open_conns \
         postgres.max_idle_conns postgres.conn_max_lifetime postgres.conn_max_idle_time; do
  grep -q "$k" "$DOC" || { echo "MISSING $k"; exit 1; }
done

if grep -q 'oauth\.<store>\.backend' "$DOC"; then
  echo "wrong key oauth.<store>.backend still present (real key: oauth.backend)"; exit 1; fi
grep 'oauth.backend' "$DOC" | grep -q redis || { echo "oauth.backend row lacks redis"; exit 1; }
echo OK
```

Run: `bash /tmp/verify-config-reference.sh`
Expected: FAIL (`MISSING key ...` / stale keys present).

- [ ] **Step 2: Make the four edits**

Edit 1 — line 9 (OAuth table): replace the `oauth.<store>.backend | memory|sqlite per store` row with:

```markdown
| `oauth.backend` | ONE key for the four hot stores (auth_code / refresh_token / device_code / par): `memory`\|`sqlite`\|`redis` |
```

Edit 2 — replace the `## Storage Backend Toggles` section (lines 38-59, including the stale "Each `backend` accepts `memory` (default) or `sqlite`" paragraph) with the full authoritative matrix (extracted from every `serverbuildstore` switch's `supported:` error string):

```markdown
## Storage Backend Toggles

Every store picks its substrate via a `backend:` key; `memory` is the default.
Values below are exactly what the binary's boot-time dispatch accepts
(`cmd/sso-server/serverbuild*`); an unknown value fails loud at startup.

| Store | Key | Accepted backends |
|---|---|---|
| Clients + Users (durable identity) | `identity.backend` | `memory` · `sqlite` · `postgres` |
| Sessions (hot; falls back to `identity.backend`) | `identity.session_backend` | `memory` · `sqlite` · `redis` · `postgres` |
| OAuth hot stores (auth_code / refresh_token / device_code / par — one key) | `oauth.backend` | `memory` · `sqlite` · `redis` |
| Refresh rotation grace | `oauth.refresh_token.rotation_grace_backend` | `memory` · `sqlite` · `redis` |
| CIBA requests | `ciba.backend` | `memory` · `sqlite` · `redis` |
| MFA challenge | `mfa.challenge.backend` | `memory` · `sqlite` · `redis` |
| MFA push approvals | `mfa.provider.push.backend` | `memory` · `sqlite` |
| TOTP enrollment | `authenticators.totp.backend` | `memory` · `sqlite` · `postgres` (empty infers sqlite when `sqlite_dsn` set, else memory) |
| WebAuthn passkey credentials | `webauthn.storage.users.backend` | `memory` · `sqlite` · `postgres` |
| WebAuthn ceremony sessions | `webauthn.storage.sessions.backend` | `memory` · `sqlite` · `redis` |
| JTI replay | `security.jti_replay.backend` | `memory` · `sqlite` · `redis` |
| Account lockout | `security.account_lockout.backend` | `memory` · `sqlite` · `redis` |
| Rate limiter | `security.rate_limit.backend` | `memory` · `sqlite` · `redis` |
| Pairwise subjects | `server.pairwise_subjects.backend` | `memory` · `sqlite` · `postgres` |
| BCL subject-client index | `backchannel_logout.index.backend` | `memory` · `sqlite` · `redis` |
| Native SSO device_secrets | `native_sso.backend` | off (`""`) · `memory` · `sqlite` · `postgres` |
| Self-service consent | `self_service.consent.backend` | off · `memory` · `sqlite` · `postgres` |
| Self-service password credentials | `self_service.password.backend` | off · `memory` · `sqlite` · `postgres` |
| Password reset tokens | `self_service.password_reset.backend` | off · `memory` · `sqlite` · `redis` |
| Tenants + Domains | `tenant.backend` | `memory` · `sqlite` · `postgres` |
| Tenant usage metering | `tenant.usage_metering.backend` | off · `memory` · `sqlite` (reads the audit DB) |
| B2B connections | `connections.backend` | `memory` · `sqlite` |
| Audit primary sink | `audit.backend` | `memory` · `sqlite` · `postgres` |
| Permissions | `permissions.backend` | `memory` · `sqlite` · `postgres` |
| Anomaly detectors | `anomaly.{recent_login,ip_failure}.backend` | `memory` · `sqlite` |
| Signing-key revocation | `keys.signing.revocation_backend` | `memory` · `sqlite` |
| Signing-key registry | `keys.signing_key_registry.backend` | off · `memory` · `etcd` |
| Cross-replica bus | `cluster.bus.backend` | off · `memory` · `etcd` |
| Service registry | `registry.backend` | `memory` · `etcd` |
| Network policy store | `network.store` | `memory` · `etcd` |
| Bootstrap lock | `bootstrap.lock.backend` | `noop` · `file` · `etcd` |

All `backend: redis` **hot** stores share the ONE `redis:` block below. All
`backend: postgres` **durable** stores share the ONE `postgres:` block below —
a shared *sql.DB pool per replica, not one pool per store. Selecting `redis`/
`postgres` without its block is a boot error (`<domain>.backend=postgres but no
postgres block configured (set postgres.dsn)`).
```

Edit 3 — insert a new `## Postgres (shared durable-store backend)` section AFTER the Redis section (current line 82), BEFORE `## Tenant & Region`:

```markdown
## Postgres (shared durable-store backend)

One shared pool (`cmd/sso-server` `wirePostgres`) fanned out to every
`backend: postgres` store; registers a `/readyz` check named `postgres`.
`dialect: cockroach` switches advisory-locks to serialization-retry semantics.
DSN is typically injected via env (`SSO_POSTGRES__DSN`) or a `secret://` ref.

| Key | Effect |
|---|---|
| `postgres.dsn` | pgx DSN (required to enable the block). Behind a tx-mode pooler (pgbouncer) append `default_query_exec_mode=simple_protocol` |
| `postgres.dialect` | `""`\|`postgres`\|`cockroach` |
| `postgres.max_open_conns` | pool cap — N replicas x this MUST stay under DB `max_connections` |
| `postgres.max_idle_conns` | idle pool size |
| `postgres.conn_max_lifetime` / `postgres.conn_max_idle_time` | connection recycling |

See [deployment.md](deployment.md) for the HA topology and
`ops/deploy/k8s-prod/config.yaml` for the canonical production selection
(durable → postgres, hot → redis, coordination → etcd).
```

Edit 4 — if a `network.store.backend` row exists anywhere in the file, correct it to `network.store`.

- [ ] **Step 3: Verify + commit**

Run: `bash /tmp/verify-config-reference.sh`
Expected: `OK`.

Cross-check one dispatcher spot: `grep -q 'supported: memory, sqlite, redis' cmd/sso-server/serverbuildstore/build_oauth_stores.go` — confirms the `oauth.backend` row.

```bash
git add docs/config-reference.md
git commit -m "docs(config): document the shipped postgres backend matrix

config-reference.md claimed every store accepts only memory or sqlite
and used two keys that do not exist (oauth.<store>.backend,
network.store.backend). The postgres durable backend - shipped and used
by the k8s-prod overlay - was undiscoverable here. Replaces the toggle
section with the authoritative per-store matrix extracted from the
binary's backend dispatch error strings, and documents the shared
postgres pool block.

Co-Authored-By: Claude Fable 5 <noreply@anthropic.com>"
```

---

## Execution notes

- Task 0 is BLOCKING; Tasks 1-9 are mutually independent and can run in any order (or in parallel worktrees) once the baseline is green.
- Line numbers were captured 2026-07-02; if drift is detected, anchor on the named symbols/consts instead.
- Full verified evidence for each gap (what exists, what is absent, per-file citations) is recorded in the 2026-07-02 analysis (project memory `requirements-analysis-2026-07-02`).
- After all tasks: `go test ./... -race -count=1` and `make fmt vet race build proto-lint lint ci-modules` (NOT `make ci`).
