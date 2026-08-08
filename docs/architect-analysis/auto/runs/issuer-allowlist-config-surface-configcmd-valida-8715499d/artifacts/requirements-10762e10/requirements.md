Spec complete. **Output:** `docs/architect-analysis/auto/runs/issuer-allowlist-config-surface-configcmd-valida-8715499d/artifacts/requirements-10762e10/requirements.md` (384 lines).

## Verification results — every cited symbol checked against the tree

**Confirmed correct (9/11):**
- `config/config_server.go:17` — sole `Issuer string` field in `ServerConfig`
- `interfaces/sso/server_discovery.go:251-255` — `resolveIssuer` Host fallback exists (but see correction below)
- `interfaces/sso/options.go:350` — `WithIssuer` exists
- `cmd/sso-server/main_wiring.go:203` (tracing), `build_app_oidc.go:137` (`caep.WithIssuer` — CAEP only, misread as SSO wiring)
- `cmd/sso-server/issuer_test.go` sentinel guards; `config_load.go:183-184` rejection ("must not equal")
- `cmd/sso-ctl/configcmd` `runValidate` → `config.Load` gate, `--print`, A1-P4/A4 fixture patterns
- "Zero hits for `issuer_allowlist`/`require_configured`" — verified (only unrelated allowlists: CAEP transmitters, admin IP, geo, webauthn, reload policy)

**Falsified (2) — the direction's premise is stale, corrected with evidence:**
- "cmd/sso-server never passes `sso.WithIssuer`" — **FALSE at HEAD**: `config.ServerOptions()` (config_load.go:308) emits it → `build_app_core.go:154` → `sso.NewServer` (build_app.go:257); JWT/discovery/RFC 9207 anchors all derive from `cfg.Server.Issuer`
- "Discovery/RFC 9207 Host-derived while JWT iss diverges" — **no longer possible in the binary**; the prior B4-1 change set (`issuer_wiring_test.go`, untracked WIP, T-2a/T-2b/T-2c) pins this end to end

**What genuinely remains** (the spec's scope): no issuer allowlist / `require_configured` surface exists, and no deploy-time gate checks the issuer against a declared set — exactly the direction's core.

## Spec design (scope preserved, acceptance made testable)

- **R1-R2** — `server.issuer_allowlist []string` + `server.require_configured bool` on `ServerConfig` (default-off, byte-compat)
- **R3** — `applyDefaults` skips the `"sso-server"` fallback when `require_configured` (net 0 lines)
- **R4** — `validateIssuerPolicy()` consolidating sentinel rejection (moved verbatim from config_load.go:176-184) + the two new checks; keeps `config_load.go` at ≈492 lines (498 now, 500-line budget)
- **R5** — configcmd needs zero production change (load + reflection schema + validate-schema surface it)
- **C1-C5** — testable Given/When/Then fixtures in `main_test.go` covering all three exit-1 conditions, schema emission (A4 pattern), validate-schema pass, and the exit-0 byte-compat pin; runtime T-8(a)/T-2 mapped to the existing `issuer_wiring_test.go` pins plus the new load-time membership guarantee
- **R6** — `docs/config-reference.md` rows (AGENTS.md contract rule)

**Pre-existing failures reported separately (not caused by this change):** maintainability gate fails on `infrastructure/defaultimpl/ed25519_jwt_issuer.go` (539 lines); architecture depth gate fails on the campaign's own `docs/architect-analysis/auto/runs/` artifact tree.
