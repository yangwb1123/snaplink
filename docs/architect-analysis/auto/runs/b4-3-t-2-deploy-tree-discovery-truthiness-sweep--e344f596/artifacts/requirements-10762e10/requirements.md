All claims verified. The requirements spec is complete at the pipeline's expected output path:

**`docs/architect-analysis/auto/runs/b4-3-t-2-deploy-tree-discovery-truthiness-sweep--e344f596/artifacts/requirements-10762e10/requirements.md`**

## Summary

**Evidence verification** — every citation checked against the working tree, all confirmed:
- `configcmd/main.go:86-110` — `runValidate` offline-only (`config.Load` at :99, `config OK` stdout print at :103 between load and `--print`)
- `server_discovery_config.go:142-161` — `buildBaseMetadata` emits `base+PathLogin/Token/JWKS/Revoke/Introspect`
- `server_discovery.go:251-259` — `resolveIssuer` Host-derived `requestBaseURL` fallback
- `config/config_load.go:48-71,176-184` — `DefaultServerIssuer` + sentinel rejection only; no allowlist anywhere
- `scaffold_contract_test.go:131-146` — `assertNoLegacyPathPort` applies only to generated scaffolds
- `TestOIDCDiscovery*` — zero matches repo-wide
- Plus `rootcov_discovery_test.go:268-270` (non-nil-only, no sweep) and fan-out: `cmd/sso-ctl/` has exactly 16 subdirs = the committed gate ceiling

**Key decisions baked in:**
1. **configcmd extension, not a new package** — a 17th subdirectory would fail `TestArchitecture_DirectorySubdirFanout` (ceiling 16, no exemption), resolving the direction's either/or.
2. **Three design-gate must-pins from the prior failed run** are now first-class requirements: deterministic canonical violation ordering with a byte-exact multi-violation test; allowlist check placed immediately after `config.Load` before *any* stdout (failed run ⇒ empty stdout); `--timeout <= 0` ⇒ exit 2 (verified `flag.Duration` accepts `0s`/`-1s`).
3. **Allowlist flagged as CLI-supplied** (`validate --issuer-allowlist`) with the server-side key explicitly marked as proposed B4-1 work, per the direction.
4. **T-2/T-9 preserved and testable** — 18 Given/When/Then cases: path equality, `/authenticate` ban, `host:0` + `host:8080:0` shapes (verified: `url.Parse` rejects the latter with `invalid port`; the former needs the 1–65535 range check), non-404 probes (405 passes), byte-identity pins for `validate`/`--print`/`schema`.

No scope expansion: no server changes, no config keys, no `subcommands` map entry, no `test/`/`interfaces/sso` edits.
