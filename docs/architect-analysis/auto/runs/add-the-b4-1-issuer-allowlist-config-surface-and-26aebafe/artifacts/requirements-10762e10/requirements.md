The specification is complete. Summary of verification and the deliverable:

**Deliverable**: `docs/architect-analysis/cmd-sso-ctl-configcmd-b4-1-issuer-allowlist-requirements.md`

**Evidence verification results** (all direction citations checked against HEAD `ce759da6`):

| Citation | Verdict |
|---|---|
| `server_discovery.go:251-259` Host fallback in `resolveIssuer` | Confirmed (:251 func, :255 `requestBaseURL` fallback) |
| `server_discovery_config.go:62,109,146` request-derived discovery base | Confirmed (:62 `base := requestBaseURL`, :144 `Issuer: base`, endpoints :145-149) |
| `config_load.go:60,183-184` default + sentinel-only gate | Confirmed (`"sso-server"` default at :60/:70-71; only `sso.DefaultIssuer` rejected at :183-184) |
| `main_test.go TestRun_InvalidConfig_Sentinel` only issuer gate | Confirmed |
| `issue_payload.go:26` iss in payload | Confirmed (`Iss:` at :28, drift of 1; wired via `build_signing_issuers.go:43,67,95`) |
| No allowlist key in `config/` | Confirmed (only CAEP transmitter `iss`, unrelated) |

**Two material corrections to the direction's mechanism claims** (acceptance checks preserved):
1. Under the cmd path, JWT `iss` is never Host-derived — `WithIssuer(cfg.Server.Issuer)` IS wired (`config_load.go:308` → `build_app_core.go:154` → `build_app.go:257`; the B4-1 proposal's "never wired" note is stale). Absent issuer manifests as the non-URL literal `"sso-server"`, which is the real deploy failure.
2. `discovery.issuer` and stamped `iss` always agree (`server_discovery_config.go:264-266` overrides `cfg.Issuer = s.issuer`); the actual RFC 9207/OIDC §4.3 hazard is **endpoint-origins (always request-derived) vs issuer-origin**. The `issuer`↔`base_url` coherence check is the correct offline proxy — `server.base_url` is currently dead/unwired/undocumented, so the spec makes it load-bearing as the declared advertised base and documents the unset-case skip.

**Scope guardrails**: gate lives in `configcmd.runValidate` only (not `config.Load` — server boot untouched); new key `server.issuer_allowlist` is additive; no CLI flag, no new package (fan-out ceiling 16), no server-side changes; all five acceptance checks preserved as testable Given/When/Then cases (14 numbered), including schema round-trip and CI interplay (`config-validate-all` uses the server loader, so the gate is operator/CI-pre-check-only — the 8 deploy-tree configs needing the new key are listed with exact line numbers).
