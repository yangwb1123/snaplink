Design complete. Written to the pipeline's expected output: `docs/architect-analysis/auto/runs/b4-3-t-2-deploy-tree-discovery-truthiness-sweep--e344f596/artifacts/design-a77de8a6/task-1-design.md`.

## Summary

**Evidence verification (all claims re-checked against the tree):**
- All 12 code citations confirmed (minor drift: `config OK` print is at `main.go:104`, not `:103`; `maxSubdirsPerDir=16` at `directory_fanout_test.go:35`).
- **Material finding:** the run's `requirements.md` artifact is a 22-line summary, not the 18-case spec it claims; the substantive spec is the committed companion doc (16 G/W/T cases) plus the three design-gate must-pins from prior run `3fca04ef` — 16 + 2 = the cited 18.
- Re-ran the fan-out gate: it fails today on pre-existing violations (`docs/` 18>16, `runs` 268>16, root 24>21); `cmd/sso-ctl` sits exactly at 16 = cap, so a 17th subdir is prohibited.
- Re-verified `url.Parse`: `host:8080:0` → `invalid port`; `host:0` parses and needs the 1–65535 range check.

**New empirical probes** (real server, `test/oidc_discovery_test.go` construction): bare server advertises `base+Path*` exactly; POST-only routes answer 404 on GET (router never 405 — confirming the prior C1/C2 corrections); empty form-encoded POST retry → 401/415/501, non-mutating.

**New correction C5:** the prior design's `newStockServer` helper included `WithIssuer` — that yields `https://sso.test/*` endpoints against an `http://127.0.0.1:PORT` sweep base, which would fail acceptance case 1. The replica must omit `WithIssuer` (empirically verified green).

**Design contents:** `check-discovery --url/--timeout` with a canonical four-pass pipeline (fetch → equality → shape → probe, slice-driven field table, never map iteration); `validate --issuer-allowlist` gated immediately after `config.Load` before any stdout, with `fs.Visit` presence tracking for the empty-value exit-2 case; all three must-pins resolved (canonical ordering + byte-exact multi-violation test; empty stdout on allowlist failure; `--timeout <= 0` → exit 2); 18-case acceptance mapping with corrected semantics; 4 ordered migration steps; pre-existing gate failures flagged for separate reporting.
