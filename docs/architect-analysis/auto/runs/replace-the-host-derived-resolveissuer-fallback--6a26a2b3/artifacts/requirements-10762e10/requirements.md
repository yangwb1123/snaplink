All citations verified. The spec is complete.

## Deliverable

**`docs/architect-analysis/auto/interfaces-snapshot-loader-spec.md`** — evidence-backed requirements specification for the selected direction, filed under module `interfaces/snapshot/loader` per the analysis JSON convention.

### Verification results (analysis citations vs. HEAD)

| Cited | Verified at HEAD |
|---|---|
| `server_discovery.go:244` (RFC 9207 parity invariant) | ✅ `:247-249` "Critical invariant: the value returned here MUST equal `oidc.ProviderMetadata.Issuer`" |
| `server_discovery.go:251-257` (Host-derived fallback) | ✅ `:251-256`, `return requestBaseURL(ctx.Request())` at `:255` |
| `server_discovery.go:263` (authzErrorBody stamping) | ✅ `:265-272`, `KeyIss: s.resolveIssuer(ctx)` at `:268` |
| `server_discovery_config.go:146` (buildBaseMetadata `Issuer=base`) | ✅ `:142-144`; Host enters via `:62` `base := requestBaseURL(...)`, override at `:264-265` |
| Loader module orthogonality | ✅ `loader.go` is a pure `file://`/`inline:` resolver, no issuer surface (spec marks it *do-not-modify*) |

The gap is real and materially deeper than the analysis stated: with `WithIssuer` unset, discovery `issuer` and every `resolveIssuer` consumer (authz errors, JARM, form-post, JAR, bearer challenges) are Host-derived while the JWT `iss` stays the construction-fixed `sso.DefaultIssuer` literal (`ed25519_jwt_issuer.go:324`) — the parity invariant only holds in the stock build because `DefaultServerIssuer = "sso-server"` (`config_load.go:60`, guarded by `cmd/sso-server/issuer_test.go`).

### Spec design decisions (scope-disciplined)

- **Semantics pinned to make T-9/T-2 testable**: allowlist on ⇒ `WithIssuer`/`server.issuer` must be a member (startup rejection via `config.Load` `validate()` mirroring the `:183-184` sentinel rejection, plus SDK `NewServer` panic per the `WithCustomGrant` precedent). Per-request multi-host selection is excluded because the minted JWT `iss` is fixed at issuer construction — it would break T-2.
- **Feature off = byte-identical legacy** (including the Host fallback), preserving existing tests.
- **All three acceptance checks preserved**: startup rejection, T-9 (spoofed/absent/forwarded Host ⇒ discovery `issuer` = allowlist member for every request), T-2 (minted `iss` == discovery `issuer`, never the request Host) — each restated as testable Given/When/Then with explicit test placement (`interfaces/sso/issuer_allowlist_test.go`, `config/issuer_allowlist_test.go`, `cmd/sso-server/issuer_test.go` extension).
- **Budget compliance**: no new production files in `interfaces/sso` (60-file ceiling) — changes land in `options.go`, `sso.go`, `server_discovery.go`, `server_discovery_config.go`; config wiring in `config/config_load.go`; docs in `config-reference.md` + `feature-matrix.md` per AGENTS.md §5.6. No new wire errors, no OpenAPI change.
