All spot-checks pass. The requirements specification is complete and written to the pipeline-pinned output path.

## Deliverable

`docs/architect-analysis/auto/runs/emit-tenant-id-roles-in-buildaccesspayload-and-r-bbad8fa5/artifacts/requirements-10762e10/requirements.md`

## What I verified (all 9 cited items re-read in the tree)

- **Claims gap confirmed**: `buildAccessPayload` (issue_payload.go:26, shared by all 3 signers) and `ed25519Payload` (ed25519_types.go:15-113) emit no `tenant_id`/`roles`; `Subject.TenantID` (types_token.go:226-231) is self-documented "NOT a token claim"; all 8 mint sites already bind `TenantID: client.TenantID`.
- **Corrections to the source analysis**: `server_helpers.go:126,144,308` are token-policy seams, not mint sites (the real ones are the `internal/handler/tokengrant` handlers); the "spi.go:171 alias" is `SessionMeta.TenantID`; discovery's Host-derived `Issuer: base` seed is in `buildBaseMetadata` (server_discovery_config.go:144).
- **Issuer surface mapped**: `resolveIssuer` Host fallback (server_discovery.go:251-256 → `requestBaseURL` → `middleware.BaseURL`), discovery seed, and the minted-iss path (`j.issuer` via `WithEd25519Issuer(srv.Issuer)`) — with the cmd-side nuance that `config_load.go` already defaults `server.issuer` to `"sso-server"` and rejects the sentinel, so Host-derivation is an embedded-SDK/unwired state. No allowlist symbol anywhere (grep-verified).
- **Additional load-bearing facts found**: `test/trusted_proxy_gate_test.go:267-311` encodes Host-derived discovery issuer in 3 tests (must be re-pointed); `tenantHintFromClaims` (interfaces/admin/governance.go:478) consumes the ext-carried hint; `oauth_token_source.go:43-46` has a stale wire-format comment; `guest.Roles` at token_exchange.go:446 is scope narrowing, not a roles source; near-ceiling line budgets (sso.go 499, options.go 490, config_load.go 498); ID tokens use a separate `ed25519IDPayload` (no bleed).

## Key pinned decisions (bounded, no scope expansion)

- **Roles source = existing `permissions.Provider.Roles`** via a grant-deps accessor (the B4-2 `ScopeRegistry()` pattern); vocabulary = `Role.Code`. Rejected `Client.Roles` (no existing data source; would require schema/CRUD changes in every client store). Mint-time local subject is available directly, so no pairwise reverse resolution is needed.
- **Issuer**: `resolveIssuer` returns the sentinel (never Host); discovery `Issuer` truthing; `WithIssuerAllowlist` option + `server.issuer_allowlist` config with fail-loud validation — minted == discovery == RFC 9207 in every state.
- **Wire hygiene**: omitempty for byte-identical legacy wire on unbound clients, ext-key scrub, `tenantHintFromClaims` structured-claim precedence, introspection body unchanged, `kid` untouched.

## Acceptance preserved and made testable

- **A1 / T-8(a)**: G/W/T for both grants, 3-signer unit tests + rootcov-style wire test (modeled on `region_token_contract_test.go`).
- **A2 / T-1.2**: mint→validate round-trip fixture; cross-repo 422 gate explicitly out-of-repo.
- **A3 / T-2**: six falsifiable tests (sentinel vs `Host: attacker.example`, allowlist accept/reject, option-order independence, config-load gate, re-pointed trusted-proxy tests).
- **A4**: kid sweep grep, mint-site consistency, ID-token absence.

No `.go` files were changed (doc-only artifact), so build gates don't apply to this change; the design stage will consume this spec next per the pipeline.
