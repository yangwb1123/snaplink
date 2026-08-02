Design doc written to `docs/auto/domains-tokenanomaly-direction1-design.md`, following the spec convention. All evidence was re-verified against source before writing (grep confirmed `GeoCountry:` exists only in test files; all five Offer seams, the v7 sqlite migration ceiling, the composite's store-driven policy matching, and the revoke executor's subject-fallback were checked).

Key design decisions:

- **## Decision 1** — one canonical `geo.CountryCodeFromContext` in `platform/geo`: the only new import edge is `protocols/oauth → platform/geo`, which is legal downward (layer 3 → 1); a shared-kernel reader guarantees byte-identical `GeoCountry` across both layers.
- **## Decision 2** — `s.offerUsage(ctx, ev)` choke point in `interfaces/sso`; zero-value `""` keeps all three `record*Issued` Events byte-identical without a geo source.
- **## Decision 3** — `recordIntrospectionUsage` gains a `ctx` param (single caller, package-private); response bodies and no-store headers untouched.
- **## Decision 4** — `RefreshToken.JTI` stamped in the fresh-family branch (mirroring `FamilyID` at `auth_code_handler.go:238-244`), propagated via `RefreshAuthContext` — the existing "don't grow the 14-param signature" bucket — so the six tokengrant handlers and the Deps interface need zero signature changes.
- **## Decision 5** — storage model: memory field-copy, redis `omitempty` JSON (both directions compatible), sqlite **v8** additive migration following the v3–v7 idempotent-column pattern; legacy rows degrade to `""`.
- **## Decision 6** — `Thumbprint: metering.Thumbprint(info.JTI)` on the refresh-introspect Offer; rotation chains stay under one stable thumbprint.
- **## Decision 7** — Evidence gains sorted `geos` (comma-join, `exists`/`eq`-matchable) and numeric `count` (`gt`/`lt`); wire strings already match 1:1.
- **## Decision 8** — the contract tests, including the documented nuance that `ActionRevoke` for geo findings executes via the subject-scoped fallback (no detector populates `FamilyID` today — the test asserts this deliberately rather than pretending family revoke fires).
- **## Decision 9** — docs surface (feature-matrix + config-reference).

Then **## Failure modes** (12-row table) and **## What could break the design** (10 risks), the most notable being: `server_helpers.go` is at 493/500 lines (mitigation: new `server_usage_geo.go`), the per-replica observation-table limit on cross-replica geo detection (pre-existing wave-1 architecture, not a regression, but bounds the flagship promise), and the `count`-means-different-things-per-type policy footgun.
