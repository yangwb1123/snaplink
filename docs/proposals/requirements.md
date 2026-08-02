Spec written to `docs/auto/domains-region-token-contract-spec.md` (matches the `domains-region-*-spec.md` convention). Summary of the three evidence-backed improvements for direction 2:

## 决策 1 — `serving_region` claim on access + ID tokens
- **Problem**: mint region exists only in the login response map (`applyLoginResponseExtras`, self-described "UX, not a security signal"), audit `region.serving`, and the in-process middleware stash — never in the token. A eu-west-1-minted token is indistinguishable at a us-east RS; the server's own read gate (`residencyDeniedForAccess`) needs a ClientStore round-trip per read because tokens carry no provenance.
- **Evidence**: `server_finish_login.go:319-330`; `shared/core/types_token.go` `Subject` (no region); `defaultimpl/issue_payload.go` `buildAccessPayload`; `ed25519_types.go` payloads; `oidcsupport/idtoken_claims.go` `ProjectIDTokenClaims` (region must be a first-class field, not a `Claims`-map entry, or §5.5 projection drops it); introspection echo point `handle_introspect.go:366`.
- **Proposed**: typed `ServingRegion` on `core.Subject`/`core.TokenClaims`/`ed25519Payload`/`ed25519IDPayload` + `oidc.IDTokenRequest`, stamped by every mint path from `region.FromHandlerContext(ctx)` (middleware mounted globally at `server_routes.go:132`); empty ⇒ omitted, zero-value byte-identical.

## 决策 2 — Discovery advertises the region
- **Problem**: `docs/error-codes.md:88` tells clients to "route to an allowed region", but `ProviderMetadata` has no region field and `claims_supported` (`applyStaticClaimsAndSecurity:381`) is hardcoded without it; `serving_region` appears only in the login schema (`openapi.yaml:12156`).
- **Proposed**: opt-in `WithServingRegionAdvertisement` → SnapLink-extension `serving_region` field (omitempty, mirroring `MFAEndpoint`/`WithOperatorMetadata`) + `claims_supported` membership; static-per-process so it's safe in the per-base-URL discovery cache; covered by `signed_metadata` automatically.

## 决策 3 — RS SDK typed claim + opt-in region gate
- **Problem**: `interfaces/ssoclient/rs` validates locally with the AS off the path, but unknown claims only land in `Raw` (`claims.go`); no typed region, no way to express "this deployment only serves eu-west-1-minted tokens" — the constraint stops at the SSO server, not where tenant data lives.
- **Proposed**: `Claims.ServingRegion` + `wireClaims` field (covers both modes since `wireIntrospection` embeds it), `Config.AllowedServingRegions` gate in `validateClaims` + `validateIntrospectedClaims` — fail-closed when configured, new `ErrServingRegionMismatch` sentinel mapped to 403 (governance denial, mirroring the AS's region_not_allowed-vs-invalid_token discipline), zero-value config unchanged.

All three preserve the fail-open decision ladder, introspection's documented non-gate, and zero-value byte-identity; contract docs (openapi/error-codes/feature-matrix) are updated in the same change per AGENTS.md §5.6.
