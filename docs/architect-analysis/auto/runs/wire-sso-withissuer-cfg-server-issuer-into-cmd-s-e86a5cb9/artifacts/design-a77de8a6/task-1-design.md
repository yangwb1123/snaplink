All identifiers verified. Verification complete — here's the summary.

## Verification verdict

**The evidence's central claim is TRUE: the wiring already exists end to end; the direction's production change is a no-op.** I re-verified every citation against the current tree:

- `config/config_load.go:308` — `ServerOptions()` emits `sso.WithIssuer(c.Server.Issuer)` ✅
- `build_app_core.go:154` appends it in `wireSigningIssuer`; `build_app.go:257` feeds `b.opts` to `sso.NewServer` ✅
- `serverbuildsign/build_signing_issuers.go:43` pins JWT `iss` from the same value; third consumer `tracing.WithServiceName(cfg.Server.Issuer)` at `main_wiring.go:203` ✅
- `issuer_test.go:15` comment is accurate, not drift ✅
- Tests exist: `config/security_test.go:72-124` (3 composition tests), `rootcov_accessors_test.go:246-248`, `TestConfigRejectsSDKSentinel` ✅
- Discovery override (`server_discovery_config.go:264-265`, called at `:112`), `resolveIssuer` fallback-only-when-sentinel, `authzErrorBody` RFC 9207 `iss`, `handleLogin` no-store stamping, form_post hidden `iss` input — all as claimed ✅
- Zero authorization-code-flow tests exist in `cmd/sso-server` today; discovery tests assert presence only — so the net-new pinning tests are genuine ✅

**One discrepancy found:** "the wiring landed in commit `305dc6c0` (2026-06-19)" is **wrong attribution**. `git log -S` shows the origin is `eb7b6212` (2026-05-12, the original SDK commit); `305dc6c0` is the maintainability refactor that split `config.go` → `config_load.go`, moving the code verbatim (parent `config/config.go:852` already had it). The "stale analysis" conclusion survives; the commit citation does not. Documented in §0 of the design.

## Design produced

`docs/architect-analysis/auto/cmd-sso-server-issuer-wiring-design.md` — tests-only implementation contract:

- **API changes**: none (zero production code; frozen regression surface listed: `ServerOptions` composition, `WithIssuer` semantics, discovery override, RFC 9207 `iss`, no-store headers, JWT `iss`)
- **Compatibility**: wire bytes, config schema, `interfaces/sso` 60-file ceiling, file/budget gates all untouched
- **Design**: one new file `cmd/sso-server/issuer_wiring_test.go` — shared `buildApp` fixture (pinned issuer + seeded JWT client + bcrypt password user, all patterns verified to exist), T-2a tampered-`X-Forwarded-Host` discovery test, T-2b three-surface authz-iss test (error body + form_post hidden input + code-flow success envelope, all now verified to carry `iss`), T-2c client-credentials + auth-code JWT payload decode (first code-flow test in the package), T-2d unchanged
- **Failure modes**: 7 production-drift guards mapped to the direction's exact concerns, plus 8 bounded test-construction hazards (PKCE, id_token presence, token strategy, `-race` cleanup)
- **Migration**: none for operators; repo steps including the optional spec attribution fix
- **Acceptance mapping**: direction acceptance → test name → concrete byte-level assertions → gate commands, ending with the AGENTS.md gate sequence (`go build`/`vet`, maintainability/architecture, `-race`, e2e, `make ci`)
