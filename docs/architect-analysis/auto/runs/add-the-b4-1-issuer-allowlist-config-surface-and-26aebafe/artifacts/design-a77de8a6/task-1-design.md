All evidence claims verified against the working tree, and the deliverable (`docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md`) is confirmed accurate with two material corrections applied.

## Verification verdict (untrusted claims → measured reality)

| Evidence claim | Verdict |
|---|---|
| `server_discovery.go:251-259` — `resolveIssuer` Host fallback | **Confirmed** (func at :251; `requestBaseURL` fallback :257; invariant comment :242-249) |
| `server_discovery_config.go:62,109,146` — request-derived discovery base | **Confirmed** (`base := requestBaseURL` :62; `buildBaseMetadata` seeds `Issuer: base` :144 + endpoints :145-149) |
| `config_load.go:60,183-184` — `"sso-server"` default, sentinel-only gate | **Confirmed** (const :60, `applyDefaults` :70-71; `validate` rejects only `sso.DefaultIssuer` :183-184) |
| `main_test.go` `TestRun_InvalidConfig_Sentinel` only issuer test | **Confirmed** (:35; fixture has `issuer: http://localhost:8080` + `base_url`) |
| `issue_payload.go:26` `iss` in payload | **Confirmed** (`Iss:` :28, drift 1; wired via `build_signing_issuers.go:43,67,95` with `srv.Issuer`) |
| No allowlist key in `config/` | **Confirmed** (zero rg hits; CAEP's is `caep.transmitters[].issuer` — different concept) |
| `WithIssuer` IS wired (`config_load.go:308` → `build_app_core.go:154` → `build_app.go:257`) | **Confirmed** (the B4-1 "never wired" note is stale) |
| Discovery `issuer` override (`server_discovery_config.go:264-266`) | **Confirmed** |
| `base_url` dead/unwired/undocumented | **Confirmed** (no doc at `config_server.go:18`, `ServerOptions` explicitly skips it, `WithBaseURL` is a no-op at `options_security.go:399-404`) |
| CI uses server loader, not `sso-ctl` | **Confirmed** (`ci.yml:126-129` → `make config-validate-all`, Makefile:400-410, `go run ./cmd/sso-server --validate-only`) |
| 8 deploy configs + exact line numbers | **Confirmed**, all 8 line numbers match |

## Two material corrections found during re-verification (applied to the deliverable)

The deliverable's own migration table was self-inconsistent with the gate it defines — for 2 of the 3 sentinel configs, the table's `issuer → http://localhost:8080` replacement would **fail the new origin-coherence check**:

1. **`bin/config.yaml:17`** — declares `base_url: http://localhost:28898` (:22) and `listen: ":28898"` (:23). Replacement must be `http://localhost:28898`, not 8080.
2. **`ops/deploy/k8s/config.yaml:11`** — declares `base_url: http://sso-server.snaplink-sso.svc.cluster.local:8080` (:13). Replacement must be that same cluster URL.
3. `cmd/sso-server/config.yaml` is coherent as written (`base_url: http://localhost:8080`).

Added a migration rule ("new issuer must equal the config's existing `base_url` origin"), a fail-closed normalization note (default ports like `:443` never guessed; single trailing-slash trim only), and a new acceptance case 16 pinning that behavior.

## Design (in the deliverable)

- **API change**: one additive field `ServerConfig.IssuerAllowlist []string` (`config/config_server.go`) — never read at boot; plus a pure `validateIssuerGate(cfg) []string` in a new `configcmd/issuer_gate.go` (no new package — fan-out ceiling).
- **Compatibility**: `config.Load`/boot byte-identical; `schema` grows by one key; exit-code contract unchanged (0/1/2). Fail-closed on normalization ambiguity.
- **Failure modes**: non-URL/absent issuer (resolves to `"sso-server"`), empty/malformed allowlist, non-member issuer, issuer↔`base_url` origin mismatch; `base_url` unset ⇒ check skipped (documented limitation).
- **Migration**: 8 deploy configs with verified per-file replacement values; `bin/k8s-rendered/*` regenerated, not hand-edited.
- **Acceptance mapping**: 16 numbered Given/When/Then cases (all 5 original acceptance checks preserved) mapped to T-8(a)/T-2, plus §10 verification plan (`go build/vet`, maintainability gates, `-race`, `make ci`; Python fan-out failure reported as pre-existing).

No Go files were touched, so no mandatory gate run is triggered by this change.
