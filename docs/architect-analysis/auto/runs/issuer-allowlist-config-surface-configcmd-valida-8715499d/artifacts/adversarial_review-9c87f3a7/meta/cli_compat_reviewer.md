Deliverable written to `docs/architect-analysis/auto/runs/issuer-allowlist-config-surface-configcmd-valida-8715499d/artifacts/byte-compat-consumer-audit/task-4-byte-compat.md`. No Go edits, so no gates needed. Summary:

## Consumer enumeration (all verified against the tree, live binary runs)

**`--print` output** — zero runtime consumers:
- `bin/sso-ctl`: compiled ELF; build-only consumers (`engineering.yaml` build gate, `.goreleaser.yaml`) — neither parses output; **no Makefile target invokes `sso-ctl` at all**.
- `checks/` + `cli.py`: no command shells out to `sso-ctl config`; `checks/config.py` is the harness's own `engineering.yaml` loader.
- CI workflows: only `make config-validate-all` (ci.yml:126–130) → `sso-server --validate-only` — a *different binary* over 7 files, none containing the new keys.
- Lineage: B4-3 T2 docs pin `--print`/schema byte-identity but for a *different campaign* (B4-4 strict-wire, premise "no struct changes") — plan prose, no executable gate. Current run's requirements pin **exit-code** byte-compat only.
- Examples: `docs/examples/basic/config.yaml` goes through the server path; no doc/script shows or parses `--print` bytes.
- Golden tests: **none exist** — no `.golden`, no testdata JSON; `main_test.go` has no `--print` test at all.

**Schema/validate-schema output** — consumers are `Loader.Load`'s warn-only `checkSchema` (loosens: warning disappears), the three uncommitted manifests (today: `validate` exit 0, `validate-schema` exit 1 solely on `server.issuer_allowlist: unknown field`; `overlays/prod` additionally fails `validate` for a pre-existing unrelated `postgres.dsn` reason), and `TestRun_Schema_*` (exit-code + property-type asserts, never byte-exact). No CI gate runs `validate-schema`; no stored schema artifact exists.

## Verdicts

- **V1:** The two fields breaking `--print` byte-compat break **no consumer** — there are no byte consumers; exit codes (the only real contract) are preserved.
- **V2:** The validate-schema loosening breaks **no consumer** — it flips three manifests 1→0 and removes a boot warning; mechanism-guaranteed to be exactly two properties on the `server` node (`additionalProperties: false` everywhere; a key stops being unknown only by becoming a field).

## Output contract

- New keys render as `"IssuerAllowlist"` (`null` when absent) and `"RequireConfigured"` (`false`) under `"Server"` — Go field names, since `ServerConfig` has only `yaml:` tags (verified live).
- **Ordering:** `--print` gains the fields strictly **after** `validateIssuerPolicy()` runs — it's called inside `Loader.Load`'s `c.validate()` (post-`applyDefaults`, same site as today's sentinel check at config_load.go:176–185), and `--print` renders only on a successful `Load`. An invalid issuer policy never reaches the printer (exit 1, stderr, no JSON); printed values are post-defaults/post-validation.
- Schema: `require_configured` must be `yaml:"require_configured,omitempty"` or it joins `server.required` per the FM-7 heuristic (verified: `issuer`, `base_url`, etc. are listed today); `issuer_allowlist` (slice) is never required.

## Same-change updates

- **Must update:** `docs/config-reference.md` (two new rows, per AGENTS.md §5.6).
- **No updates needed:** no golden files exist; no script parses output; doc examples show plain `validate` without `--print`; the three manifests already carry the keys (recognized-and-passing with zero edits); B4-3 T2 lineage is a different campaign's plan prose; `main_test.go` changes are additive C-series fixtures (C4/C7), not golden updates.
