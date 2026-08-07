All verification and amendment work is complete. Final summary:

## Verification verdict

**F1 was genuinely unclosed in the pre-amendment design** — no mention of the federation surface anywhere in the artifact. I verified the full vector against HEAD, then amended the design doc (`docs/architect-analysis/auto/runs/replace-the-host-derived-resolveissuer-fallback--6a26a2b3/artifacts/design-a77de8a6/task-1-design.md`) to close it.

### The vector (verified in code)

- `domains/federation/handler.go:83-84`: `base := deps.RequestBaseURL(ctx)` (request-derived), `iss := deps.ResolveIssuer(ctx)` (pinned once the allowlist lands)
- `:90-97`/`:125`: body cache keyed by `iss` — `federation.DefaultCacheTTL` = **5 minutes** (`entity_statement_config.go:279`)
- `:107,156`: `base` → `deps.BuildOPMetadata` → `buildOIDCConfiguration` (`server_federation.go:22`) → `buildBaseMetadata` (`server_discovery_config.go:142-171`), which stamps `Issuer` **and every endpoint** from `base`; `:158`: `federationEntityMeta` stamps `federation_fetch/list/resolve/trust_mark_status_endpoint` from `base`
- **Result**: a spoofed-Host first render caches pinned `iss` + Host-derived endpoints under the pinned key → served to every Host for the TTL

### Amendment (docs-only; no Go edits → no gates triggered)

1. **§5 F1 closure — three touch points, all nil-short-circuited, no new files**: (1) the pin lands *inside* `buildOIDCConfiguration` (`server_discovery_config.go:102`, 487/500) — the shared projection consumed at `handler.go:83` via `deps.RequestBaseURL` → `BuildOPMetadata`, covering both call sites; (2) discovery body-cache key (`:62,66,86`) switches to `metadataBase(ctx)`; (3) the `RequestBaseURL` accessor (`accessors.go:379`, 494/500, one-line swap) pins the `base` consumed at `handler.go:83`, covering `federationEntityMeta`'s endpoints (the part that does **not** flow through the projection). Poisoning becomes impossible by construction: the rendered body is Host-independent.
2. **Over-pin guard — 5 surfaces verified request-derived and pinned as untouched**: DPoP `htu` (`requestURLForDPoP` `server_dpop.go:346-362`, compare `:136`, RFC 9449 §4.3); device `verification_uri` (`server_device.go:206`); RFC 9728 `resource`/`jwks_uri` (`server_resource.go:174-186` — with the AS-vs-resource split: `authorization_servers` follows the pin via `resolveIssuer`); `resource_metadata` advertisement (`server_extensions.go:109-112`); bundle-cache key `(clientID, base)` (`handlers.go:348` → `server_discovery.go:171-175`). All keep calling `requestBaseURL`/`requestURLForDPoP` directly.
3. **GWT coverage added**: new **F bucket ×5** (F-1 endpoint pin in the entity config; F-2 first-render cache-poisoning regression; F-3 single pinned cache entry serving all Hosts via 304; F-4 allowlist-off byte-identity on this surface; F-5 per-surface over-pin probes), plus **FM-12**; totals reconciled **24 → 29**; placement row updated (`interfaces/sso/issuer_allowlist_test.go` gains F-1..F-5, package-internal so the bundle cache and 304 paths are observable).
4. **Bonus correction (F2)**: the artifact's placement rationale was factually wrong — `cacheState` lives at `sso_protocol.go:360` (500/500), not `server_discovery_cache.go`; §5 now documents the corrected home (plain `Server` field in `server_discovery_cache.go`, 343/500, no embedded-struct change).

Budgets after amendment: `server_discovery_cache.go` ~358/500, `server_discovery_config.go` ~492/500, `accessors.go` net-zero at 494/500, `sso.go` exactly 500 (already flagged) — no ceiling crossed, no new production files, 60/26 ceilings intact.
