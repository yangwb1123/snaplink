# ARCHITECTURE.md — Agent lookup

The canonical package map is
[`docs/architecture/DIRECTORY_MAP.md`](../architecture/DIRECTORY_MAP.md); it
wins on conflict.

Imports move toward the shared kernel:

```text
composition → interfaces → infrastructure → protocols → domains → platform → shared
```

Extend the owning package, keep imports at the same or a lower layer, and
classify any genuinely new top-level or `internal/` package in `layerName()`.
Never add a `layerExemptions` edge or an OAuth↔OIDC import. The repository root
contains gate tests only, while the public API-only Server lives in
`interfaces/sso`.

Cold build composition enters through `cmd/sso-server/servermodules`; manifests
and profiles live under `ops/build/`. Runtime feature gates are not plugin
lifecycle managers. Read `docs/plugin-system.md` and ADR-0009 before adding a
module boundary.

Use `AGENTS.md` §0.6 for the package preflight and `docs/HISTORY.md` for retired
migration records.
