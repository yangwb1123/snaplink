`config/source.go:143-144` confirms `applyDefaults()` runs immediately before `validate()` — the F1 fail-closed behavior (omitted `server.issuer` defaults to `"sso-server"` and fails the membership check) holds.

## Summary

**Design written to:** `docs/architect-analysis/auto/runs/replace-host-derived-issuer-fallback-with-a-conf-ed324fea/artifacts/design-a77de8a6/task-1-design.md`

### Evidence verification — all claims confirmed
- `resolveIssuer` Host fallback at `server_discovery.go:255`; sentinel condition duplicated at `server_discovery_config.go:264-265`; `WithIssuer` at `options.go:358-359` (9-line drift); `DefaultIssuer` at `consts_oauth.go:139` + `sso.go:67`; zero allowlist hits (only SAML `AllowedIssuers`); 5 shipped YAMLs carry an inert `server.issuer_allowlist` (WARN-and-ignored at `config/source.go:264`); cmd never reaches the fallback (`config_load.go` defaults `sso-server`, rejects sentinel, wires `WithIssuer`).
- New corrections found: `interfaces/sso` is at exactly 60 non-test files (option must go in `options.go`); all 5 YAMLs already set `issuer ∈ allowlist` so boot validation passes them; `ProviderMetadata.Issuer` is not `omitempty` (fail-closed `""` is visible, not absent); `applyDefaults()` runs before `validate()` (source.go:143-144), making "omitted issuer fails membership" deterministic.

### Design core
- **SDK:** `WithAllowedIssuers([]string)` in existing `options.go`; field in `sso_protocol.go`; `resolveIssuer` strict branch (configured issuer if allowlisted → request base only if allowlisted → `""` + ERROR log, never host-derived); discovery normalized to equal `resolveIssuer`; shared `configuredIssuer()` helper replacing the duplicated sentinel check.
- **Config:** `ServerConfig.IssuerAllowlist` (`server.issuer_allowlist`, key pinned by deploy tree); boot fail-closed validation; wiring in `ServerOptions()`.
- **Constraints:** mode-off byte-identity (hard gate), additive-only SDK, no wire changes, no new error code, no 503, zero billing-module changes, ceiling respected.
- **Failure modes F1–F7** with detection paths; **migration** requires no YAML edits (all 5 ship aligned); **acceptance mapped to A-1..A-7** with concrete test files and assertions covering every T-2 clause.
