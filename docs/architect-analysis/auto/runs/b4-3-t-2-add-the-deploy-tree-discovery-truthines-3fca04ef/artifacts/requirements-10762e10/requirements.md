Spec complete: `docs/architect-analysis/cmd-sso-ctl-b4-3-t2-requirements.md`

## Verification results — every citation checked against the repo

| Citation | Verdict |
|---|---|
| `configcmd/main.go:63-85` (runValidate via `config.Load`) | Confirmed — `runValidate` at 86–110, `config.Load` at 99 (minor line drift); no sweep/allowlist surface in package |
| `config/config_load.go:48-71,176-184` (issuer default + sentinel-only rejection) | Confirmed — `DefaultServerIssuer="sso-server"` (60), defaulting (70–71), sentinel check (183–184); no issuer-allowlist concept in `config/` |
| `server_discovery.go:251-259` (resolveIssuer Host fallback) | Confirmed — func at 251, `requestBaseURL` fallback at 255 |
| `server_discovery_config.go:142-161` (base+PathToken real endpoints) | Confirmed — exact lines; `TokenEndpoint: base + PathToken` at 146 |
| `shared/core/consts.go:21-23` (PathToken etc.) | Confirmed — 21/22/23; `PathJWKS` relocated to `core/jwks.go:9` (noted) |
| `rootcov_discovery_test.go:268` (non-nil-only, no sweep) | Confirmed — non-nil assertions at 278–280; no truthiness anywhere in file |
| `rg TestOIDCDiscovery` empty | Confirmed — 0/2842 files; legacy `/authenticate` + `8080:0` defect tests absent |
| "sweep matches nothing in module" | Confirmed — `rg -i "discovery|sweep" cmd/sso-ctl/` → 0 hits |

## Key findings baked into the spec

1. **Fan-out ceiling decides the shape**: `cmd/sso-ctl/` has 16 subdirectories; the committed Go gate (`directory_fanout_test.go:28`) caps at 16 — a 17th package (new `discoverycmd`) would fail `TestArchitecture_DirectorySubdirFanout`. The sweep must be a `configcmd` sub-subcommand (`sso-ctl config check-discovery`), resolving the direction's "configcmd or new subcommand" alternative. The Python gate (max 15) already flags cmd/sso-ctl — noted as a pre-existing failure.
2. **T-2 sweep** (`--url`, `--timeout`): asserts fetch+JSON, `token_endpoint==base+/token`, `jwks_uri`/`revocation`/`introspection`==`base+Path*`, every advertised endpoint GET≠404 (405 proves route existence), no `/authenticate` segment, no zero/malformed port (catches both `host:0` and the unparseable `host:8080:0`). Exit 0/1/2.
3. **T-8(a)-adjacent allowlist**: opt-in `validate --issuer-allowlist` (comma-separated exact match); the defaulted `"sso-server"` fails an allowlist loudly; absent flag ⇒ byte-identical behavior.
4. **T-9 regression**: 16 testable Given/When/Then cases including byte-identical `validate`/`--print`/`schema` output, a stock-server sweep-green test (built from `interfaces/sso`), and read-only sweep proof.
5. **Non-goals**: no server/`config`/`test/`/`interfaces/sso` changes (resolveIssuer Host-fallback removal is B4-1 server work), no config keys, no `subcommands` map entry, no T-8(b)/B4-4 spillover.
