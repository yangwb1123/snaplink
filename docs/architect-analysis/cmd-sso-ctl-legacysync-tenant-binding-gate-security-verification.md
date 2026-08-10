# Security verification: tenant-binding gate against the server chain

Verifies the four security claims of the design
`cmd-sso-ctl-legacysync-tenant-binding-gate-design.md` against the working
tree (HEAD `985939d2`, pre-change state: `grep tenant_id cmd/sso-ctl/legacysync`
is empty). No `.go` files were modified; every cited symbol was re-read.

Verdict: **all four claims confirmed**. Two line-number drifts noted, no
substance invalidated.

---

## 1. Exact-match semantics and the compensating-control relationship — CONFIRMED

`domains/tenant/client_gate.go:18-27`:

```go
func ClientOK(ctx core.HandlerContext, client *core.Client) bool {
    if client == nil || client.TenantID == "" { return true }        // :19-20 fail-open on empty
    r, ok := FromHandlerContext(ctx)
    if !ok || r == nil || r.Tenant == nil { return true }            // :22-23 fail-open on absent tenant
    return r.Tenant.ID == client.TenantID                            // :26 literal, byte-exact
}
```

The comparison at line 26 is a raw string equality: no trimming, no
normalization, no prefix/suffix logic. Two consequences verified:

- **`''`-bound client**: `ClientOK` short-circuits `true` at line 19 — the
  check is bypassed, not failed. The token endpoints proceed
  (`server_token_clientauth.go:218-221`), grants stamp `TenantID:
  client.TenantID` (verified at `token_authcode.go:136`,
  `token_refresh.go:292`, `token_client_credentials.go:52`,
  `token_device.go:99`, `token_ciba.go:124`, `token_jwt_bearer.go:112`,
  `token_saml2_bearer.go:123`, `token_exchange_stages.go:399`; login mint at
  `server_login.go:119`, native SSO at `server_native_sso.go:193`), and
  `buildAccessPayload` emits it unconditionally (`issue_payload.go:46`) with
  `omitempty` performing the omission (`ed25519_types.go:50`:
  `json:"tenant_id,omitempty"`). Result: **the token has no `tenant_id`
  claim at all** — the server's fail-open on empty binding is real, and the
  sync gate (`tenant_id == ''` after `COALESCE` → exit 1) is the only
  compensating control between a legacy-sync deployment and claim-less
  tokens. Confirmed.
- **`' '`-bound client**: falls through to the literal compare. A real
  request tenant can never equal `" "`:
  - Tenant resolution is hostname → domain → tenant only; the middleware
    (`domains/tenant/middleware.go`, `hctx.Set(HandlerContextKey, ...)` at
    ~line 95) is the **sole** injection site of `tenant:resolved` — no other
    code sets it. `DefaultHostExtractor` (`middleware.go:170-181`) trims and
    lowercases; a whitespace Host yields `""` → lookup skipped.
  - A tenant row with ID `" "` is technically persistable (`Tenant.Validate`
    only requires non-empty ID/Slug, `domains/tenant/tenant.go:137-150`) but
    unreachable by any real request — no DNS name resolves to it.
  - Independent corroboration: `domains/tokenpolicy/validate.go:67-79`
    rejects whitespace tenant ids as "spellings that can never match a real
    tenant".
- `clientTenantOK` is the thin delegate at `interfaces/sso/handlers.go:407-409`.

## 2. M9 (`' '` treated as bound) cannot mask a runtime-failing client or a claim-lacking deployment — CONFIRMED, with a precise boundary

**Runtime-failing client — cannot be masked.** Every auth entry point gates
on `clientTenantOK` and rejects with `403 tenant_mismatch`
(`ErrTenantMismatch`): token auth (`server_token_clientauth.go:218`),
login client resolution (`server_login_client.go:45-49`), login resolve
(`server_login_resolve.go:209`), device (`server_device.go:137`), MFA
(`server_mfa.go:360`, `server_mfa_trust.go:334`), federated callback
(`server_oauth.go:164`), client-credentials pre-check
(`handlers.go:51-54`). Under any tenant-resolving request, a `' '`-bound
client is rejected loudly before any mint — it cannot silently produce
tokens, unlike `''` which mints without the claim. The M9 pass therefore
does not hide a working-but-wrong deployment; the runtime failure is
immediate and visible, with the mismatch audited.

**Claim-lacking deployment — cannot be masked.** A `' '`-bound client can
mint only in the no-resolved-tenant regime (nil tenant store → no-op
middleware, `middleware.go:78-80`; unknown host; suspended tenant,
`middleware.go:100-107`). In that regime the stamp is still unconditional
and `" "` is non-empty, so `omitempty` keeps it; the dedup
(`claimsWithoutEmittedKeys`, `issue_payload.go:116-131`,
`stripTenant := subject.TenantID != ""` at :117) strips the attribute-bag
copy, so the claim appears **exactly once with value `" "`**. The token
never *lacks* the claim — presence (the B4-1/T-8a contract the gate
enforces) holds. The residual case is a garbage claim value, which is
indistinguishable from any other wrong non-empty binding (e.g. a
nonexistent tenant id) and which the sync tool cannot validate — it reads
one SQLite file, with no tenant-store access. In any tenant-resolving
deployment the runtime 403s before minting, so the misbinding is
discovered immediately; in the no-resolution regime the server documents
fail-open for **every** client binding by design (`client_gate.go:22-23`
comment, `middleware.go` doc), and the claim is still emitted.

The alternative policy (reject `' '` as unbound) would require the tool to
define its own binding semantics where the server has none — any
normalization could diverge from the server's exact-match and mask values
the server rejects. Exact-match is the only choice that can never disagree
with the server's definition of bound; wrong non-empty bindings are loud at
runtime.

## 3. Oracle surface and gate position — CONFIRMED

`cmd/sso-ctl/legacysync/main.go` (read in full):

- Line 52: `report, err := buildReport(plan, target, mode)` — **unconditional**,
  before the write branch; line 53-54: error → `reportError` → return 1.
- Lines 56-60: `if cfg.Apply { applyPlan(...) }` — the write branch. The
  design's citation "52-59" is off by one (write branch spans 56-60);
  substance holds: the gate precedes the branch in **both** modes, since
  `mode` only feeds `report.Mode` and the proposed gate logic does not
  branch on it.
- Line 62: `return 0`; `reportError` at 65-67: prints exactly
  `sso-ctl legacy-sync: %v\n` to **stderr** and returns 1 — the uniform
  failure shape for all plan failures, gate included. `printReport` (line
  61) is reachable only after the gate, so a failure emits **no stdout
  report**.
- Read-only: dry-run opens the target with `mode=ro` (`readOnlyDSN`,
  `openTarget` line 39 with `!cfg.Apply`); the gate itself performs only
  SELECTs (`inspectTarget` → `loadTargetClients`); all writes live in
  `applyPlan`, unreachable on gate failure.
- Oracle surface: none added. The failure is operator-facing CLI stderr
  naming the client id — which is REQ-2's explicit demand — not a network
  response; there is one new failure cause with one uniform shape (stderr +
  exit 1, identical in dry-run/apply).

## 4. Mapped-client set — CONFIRMED, no path to exit 0 for an unbound mapped client

- `plan.MappedClients` is exactly the app-map values (`plan.go:41-46`:
  `for app, clientID := range appMap { plan.MappedClients[clientID] = ... }`),
  independent of source presence. This is precisely the surface the sync
  manages: `writeAssignments` rewrites assignments only for
  `plan.MappedClients` members (`target.go:337`), and `ManagedPrefixes` is
  built in the same loop. The gate's set == the write surface.
- `loadTargetClients` (`WHERE active=1`, `target.go:167`) populates the
  snapshot with active clients only; with the proposed
  `map[string]string` + `COALESCE(tenant_id,'')`:
  - `!ok` (missing **or** inactive) → pre-existing error
    `mapped target client %q does not exist or is inactive` → exit 1;
  - `ok` + `""` (both `''` and SQL `NULL` via COALESCE) → new gate error →
    exit 1.
- Both paths run in both modes before any write (point 3). Map lookups are
  exact; a case/whitespace-mismatched app-map entry fails the existence
  check (exit 1, never 0); an empty app map no-ops (documented M8). The
  only non-empty value that exits 0 is `' '` (and any other wrong non-empty
  value) — that is M9 by design, whose runtime consequences point 2 covers.
  **No path exists where an unbound (`''`/NULL) mapped client exits 0.**

## Drift corrections (line numbers only)

- `server_token_clientauth.go:193` is the `authenticateTokenClient`
  declaration (comment at 190); the tenant gate is at 218-221 — matches the
  design's E6 correction.
- `main.go` write branch is 56-60, not 56-59 (design §2/§7 "52-59").
- Everything else verified at the cited lines, including
  `consts_wire.go:169` (`KeyTenantID = "tenant_id"`),
  `sqlite/clients.go:46` (`tenant_id TEXT NOT NULL DEFAULT ''` in the
  Version-1 migration, partial index 49-51), `clients_scan.go:190`
  (`c.TenantID = r.tenantID`), `clients.go:435` (tenant_id in
  `clientSelectAll`), `target_test.go:145-155` fixture (no tenant_id
  column today), `model.go:104-114` (`syncReport` has no tenant field).
