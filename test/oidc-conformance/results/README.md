# Conformance run archives

Each certification-quality run is archived under `results/<commit>/`:

- `plan.json` — exported test plan (modules, variants, client settings)
- `report/` — raw suite results export
- `config.yaml` — the exact server configuration under test
- `inventory.txt` — `go version -m` inventory of the tested binary

Archives are git-ignored (results are large and timestamped); reference an
archive by commit from `docs/sso/oidc-conformance.md` when a claim is made.
