All citations verified. The design artifact is complete at `docs/architect-analysis/auto/runs/replace-the-host-derived-resolveissuer-fallback--6a26a2b3/artifacts/design-a77de8a6/task-1-design.md`.

## Verification verdict (untrusted evidence → HEAD)

**Confirmed (11 claims):** RFC 9207 parity invariant (`server_discovery.go:247-249`), Host-derived `resolveIssuer` fallback (`:251-256`), `authzErrorBody`/JARM/form-post/JAR/bearer-challenge `iss` stamping (all flow through `resolveIssuer`), `buildBaseMetadata` `Issuer: base` (`server_discovery_config.go:144`, override `:264-265` unconditional), loader orthogonality (zero issuer references), `ed25519_jwt_issuer.go:324` construction-fixed `sso.DefaultIssuer`, `DefaultServerIssuer = "sso-server"` (`config_load.go:60`), sentinel rejection (`:183-185`), `WithCustomGrant` panic precedent (`options_grants.go:78`), 60-file ceiling, and the three acceptance checks.

**Two material corrections:**
1. **Framing** — the stock build's parity is *not* fragile: cmd wires `WithEd25519Issuer(srv.Issuer)` and `WithIssuer(srv.Issuer)` from the same validated `Server.Issuer`; the Host fallback is reachable only for SDK embedders omitting `WithIssuer`. The deeper real gap (matching the sibling configcmd spec §2) is the incoherent discovery doc: pinned `issuer` with Host-derived **endpoints**.
2. **File placement refuted** — `options.go` (490/500), `sso_protocol.go` (500/500), and `config_load.go` (498/500) have no headroom. The option + field + gate move to `server_discovery_cache.go` (343, where `cacheState` already holds the signing-alg allowlist); the config sentinel block relocates into `validateIssuerGate` in `config_server.go` (net-zero on `config_load.go`); `sso.go` takes exactly one line (lands at exactly 500 — flagged).

## Design summary

- **API**: additive `sso.WithIssuerAllowlist(...)` + `ServerConfig.IssuerAllowlist []string` (`yaml:"issuer_allowlist"`) — the same key/normalization convention as the sibling configcmd deploy gate. Allowlist on ⇒ `resolveIssuer`, discovery issuer **and endpoints**, and the cache key pin to the configured issuer; `NewServer` panics / `config.Load` rejects a non-member issuer (mirroring the sentinel gate and `WithCustomGrant`).
- **Compatibility**: feature off = byte-identical legacy (Host fallback preserved); no wire/`Err*`/OpenAPI change; no new production files (60/26 ceilings frozen); existing configs and tests untouched.
- **Failure modes**: 11 enumerated — non-member issuer (FM-1), defaulted-issuer footgun (FM-2), SDK misuse panics (FM-4), trailing-slash normalized / ports fail-closed (FM-5/6), multi-host excluded by construction (FM-7), XFH spoofing inert (FM-8), no-SPI minting contract (FM-9), ceiling pressure (FM-11).
- **Migration**: enable = add key with member issuer; staged issuer rotation via multi-entry allowlist; rollback = remove key; the 12 deploy-tree configs follow the sibling configcmd spec's replacement table (boot gate passes automatically once those values are members).
- **Acceptance mapping**: 21 Given/When/Then cases (A-startup ×11, T-9 ×7, T-2 ×3, regression ×3) with explicit placement in `interfaces/sso/issuer_allowlist_test.go`, `config/issuer_allowlist_test.go`, and `cmd/sso-server/issuer_test.go`; verification plan runs `go build/vet`, maintainability/architecture gates, `-race`, `test/` E2E, and `make ci`.
