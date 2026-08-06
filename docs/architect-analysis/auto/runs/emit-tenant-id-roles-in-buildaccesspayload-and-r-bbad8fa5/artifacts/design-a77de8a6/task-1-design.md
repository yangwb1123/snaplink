Verified. The design document is complete at `docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-and-r-bbad8fa5/artifacts/design-689aebe1/task-1-design.md`.

## Verification result: evidence is accurate; design produced

**All 9 cited claims + load-bearing facts confirmed against the tree** (with exact anchors): claims gap in `buildAccessPayload`/`ed25519Payload`; `Subject.TenantID` "NOT a token claim"; all 8 mint sites binding `TenantID: client.TenantID`; `server_helpers.go` seams; `spi.go:171` = `SessionMeta.TenantID`; `resolveIssuer` Host fallback → `requestBaseURL` → `middleware.BaseURL`; discovery `Issuer: base` seed + truthing; minted-iss via `WithEd25519Issuer(srv.Issuer)`; cmd's `"sso-server"` default + sentinel rejection; zero allowlist symbols; 3 Host-derived trusted-proxy tests; `tenantHintFromClaims`; stale `oauth_token_source.go` comment; `guest.Roles` as scope narrowing; all line budgets; `permissions.Provider.Roles`/`Role.Code`; `ScopeRegistry()` pattern in all 8 grant Deps; introspection no-echo discipline; 60-file `interfaces/sso` ceiling.

**Corrections I made to the evidence's own analysis:**
- `token_exchange_stages.go` is at exactly **500/500** — the exchange mint site has zero headroom; the design pins a net-zero-line change (roles ride `tokExState`, field added in `token_exchange.go`, `Roles:` merged onto the `ID:` line, one comment line reclaimed).
- `consts_wire.go` is at 500/500 but needs **no edit** (`KeyTenantID`/`KeyRoles` already exist).
- The tokengrant grep hits for "resolveIssuer" are function *names* (`resolveIssuerForJWTBearer`), not resolver uses — the 8 grant Deps need only `Roles`, not issuer accessors.
- Consulted the failed b4-1 design gate: this run's pivot (no sentinel shape change, no `Client.Roles`, no `IssuerNamer`) is preserved; the b4-1 blast-radius gap (`cmd/sso-ctl/configcmd/main_test.go:37`) is documented as a constraint on any future shape change.

**Design highlights:**
- **API**: `Subject.Roles`, `TokenClaims.TenantID/Roles`, `WithIssuerAllowlist`, `(*Server).Roles` (fail-open, `ScopeRegistry` pattern), `ResolveIssuerLegacy` accessor, `server.issuer_allowlist` config.
- **Compatibility**: byte-identical wire when unbound (omitempty + goldens); complete ~40-site inventory of the legacy-resolver carve-out (private_key_jwt/JAR `aud`, realms, RFC 8414, SSF, federation — flipping those would break existing clients with zero security gain); introspection no-echo asymmetry; DCR roles exclusion (verified `updated := *client` at `handle_register_helpers.go:314`).
- **Failure modes**: 10-row table (fail-open roles outage, fail-loud allowlist misconfig, fail-closed mint refusal on existing 500 `no_token_strategy`, oracle safety, cross-tenant exchange namespace semantics).
- **Migration**: 6 ordered steps, each `make ci`-green, with per-file line budgets (sso.go → 500, config_load.go → 500 with extraction fallback).
- **Acceptance**: A1–A4 mapped to 16 named falsifiable tests, including the six A3 issuer tests and the re-pointed trusted-proxy trio.

No `.go` files changed (doc-only artifact); build gates don't apply to this change.
