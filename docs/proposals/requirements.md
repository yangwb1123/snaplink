Spec written to `docs/auto/interfaces-sso-direction1-spec.md`. All claims were verified against the code before writing; the key verified numbers differ slightly from the analysis doc (174 unique `func With*` declared, 159 unique wired in `cmd/sso-server`, 48 unreachable — the analysis's "223/970" used a looser identifier count).

**Scope and baseline (verified):**
- `interfaces/sso/options*.go` (7 files): 174 unique `func With*` constructors
- `cmd/sso-server/` (22 non-test files): 159 unique `sso.With*` references → 48 declared options unreachable from the stock binary
- `docs/config-reference.md`: 42 sections; `ops/build/capabilities.json` `config_keys` hand-maintained; `capability_registry.py` validates only non-emptiness; no option→config gate exists (only `check-routes` and `sdk-surface check` loops)

**Three decisions (each with name / problem / evidence / proposed behavior / acceptance check under `##`):**

1. **Option-surface registry + gate (`options check`)** — `ops/build/option-surface.json` + `checks/option_surface.py` + `cli.py options check` + `make ci`, mirroring `sdk-surface check`/`check-routes`; every option classified `config`/`wired`/`sdk-only` explicitly.

2. **Close two verified reachability defects** — the `server.issuer` drift (`config_server.go:17` documented to stamp JWT/discovery/RFC 9207, but `sso.WithIssuer` at `options.go:348` is never wired, so `resolveIssuer` at `server_discovery.go:251` falls back to request base URL while JWT `iss` comes from `BuildSigningIssuer` — a real RFC 9207 mix-up risk); and the retention/backup family (`WithDataRetentionSweep` at `server_backup.go:179`, `WithBackupDir/Retention/Source`) with zero YAML path, plus the self-admitted dead wiring warning at `build_governance.go:229`.

3. **Capabilities `config_keys` becomes a verified fact source** — extend `capability_registry.py` to check key existence and `stock-binary`-requires-config coverage, and derive the `feature-matrix.md` availability columns from the registry so the hand-annotated table locks step.

The spec ends with the handoff gate (`make ci`, race tests, `test/` e2e additions) and notes the dependency order 1 → 2, 1 → 3.
