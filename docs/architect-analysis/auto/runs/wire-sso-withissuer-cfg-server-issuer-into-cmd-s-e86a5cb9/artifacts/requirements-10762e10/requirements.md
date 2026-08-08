Spec written to `docs/architect-analysis/auto/cmd-snaplink-audit-provisioner-issuer-wiring-spec.md`.

## Verification verdict: the direction's central claim is **false**

Every cited file/symbol resolves, but the key inference — "cmd/sso-server never passes `sso.WithIssuer`" — is contradicted by the tree:

1. **`config.Config.ServerOptions()` (config/config_load.go:301-308) always emits `sso.WithIssuer(c.Server.Issuer)`** (line 308).
2. **`cmd/sso-server/build_app_core.go:154`** does `b.opts = append(cfg.ServerOptions(), ...)` inside `wireSigningIssuer`, and **`build_app.go:257`** feeds `b.opts` to `sso.NewServer`. So `s.issuer` is set from config.
3. The JWT `iss` claim comes from the **same** `cfg.Server.Issuer` via `serverbuildsign/build_signing_issuers.go:43` (`WithEd25519Issuer(srv.Issuer)`).
4. The `issuer_test.go:15` comment the analysis calls "drift" is **accurate** — it names exactly this wiring (`WithIssuer via ServerOptions`, `WithEd25519Issuer`, `tracing.WithServiceName`).
5. The wiring is itself tested: `config/security_test.go:72-124` (three tests), plus SDK-level `rootcov_accessors_test.go:246-248` (configured issuer wins over request base URL), plus `TestConfigRejectsSDKSentinel` for check (d).
6. The wiring landed in commit `305dc6c0` (2026-06-19) — the analysis is stale.

So the "G1 anchor can disagree with token issuer" risk is already closed: discovery (server_discovery_config.go:264 override), `resolveIssuer` (RFC 9207), and JWT `iss` all derive from one `cfg.Server.Issuer` value.

## What the spec does with the acceptance checks

Since the change is a no-op, the spec (per the constraint "preserve the supplied acceptance checks and make them testable") reframes the direction as its only real remainder — **net-new pinning tests**, no production change:

- **T-2a** `TestBuildApp_DiscoveryIssuerIgnoresTamperedHost` — configured issuer vs. tampered `X-Forwarded-Host` (only presence is asserted today: `rootcov_discovery_test.go:49,268`, `cache_ttl_test.go:90`).
- **T-2b** `TestBuildApp_AuthzErrorIssMatchesDiscoveryIssuer` — error-body `iss` == discovery issuer, plus form_post hidden-`iss` path and no-store headers.
- **T-2c** `TestBuildApp_TokenIssClaimsMatchDiscoveryIssuer` — client-credentials + full authorization-code flow (no code-flow test exists in cmd/sso-server today), decoding access/id-token payloads.
- **T-2d** — no new test; existing sentinel rejection pinned unchanged.

Scope is bounded to `cmd/sso-server/issuer_wiring_test.go`; no contract-doc, config, or SDK changes, and no touch to `interfaces/sso` (at its 60-file ceiling). The spec's verification plan uses the AGENTS.md gate sequence (`go build`/`vet`, maintainability/architecture tests, `-race`, e2e, `make ci`).
