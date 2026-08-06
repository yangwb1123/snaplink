Design complete. Summary of the work:

## Verification verdicts (all 10 citations re-checked against the tree)

**Confirmed:** `configcmd` switch/`runValidate`/`config.Load` (E1); `DefaultServerIssuer="sso-server"` + sentinel-only rejection at exact lines (E2); `resolveIssuer` Host fallback at 251–255 (E3); `buildBaseMetadata` `base+Path*` at 142–149 (E4); `core/consts.go:21-23` + `PathJWKS` in `core/jwks.go:9` (E5); non-nil-only `rootcov_discovery_test.go` (E6); `TestOIDCDiscovery` absent (E7); zero discovery surface in `cmd/sso-ctl` (E8); 16-subdir ceiling at `directory_fanout_test.go:35` (E9, line drift from :28); Python gate max 15 already flags `cmd/sso-ctl` (E10, run to confirm).

## Defects found — the spec as written is unsatisfiable

- **C1 (blocking):** R1.3's GET-only probe contradicts acceptance case 1. Empirically verified: on a stock server GET `/` → 404, GET `/token` → 404, GET `/token/introspect` → 404, etc. (ServeMux answers method mismatch with **404, not 405**). Fix: GET probe, retry with empty-body POST on 404 only (verified non-mutating: 401 `invalid_client` / 501 before any store write); `issuer` excluded from probing (identifier, not endpoint).
- **C2:** acceptance case 7's "405 proves route exists" mechanism is wrong on this router — corrected to the GET-404/POST-non-404 mechanism.
- **C3:** the spec claims the Go fan-out gate "passes today" — it doesn't (fails on `docs/`, `docs/architect-analysis/auto/runs`, root exempt regression; all pre-existing, `cmd/sso-ctl` itself is at 16 = cap).
- **C4:** `device_authorization_endpoint` is never emitted by this server (no such struct field) — "when present" clause keeps it harmless.

## Deliverable

`docs/architect-analysis/cmd-sso-ctl-b4-3-t2-design.md` — full design: two additive CLI surfaces (`config check-discovery --url/--timeout` with a 13-field table; `validate --issuer-allowlist`), checker factorization (`discovery_check.go`, budget-checked: 2→3 files, ≤500 lines, ≤50-line functions), compatibility constraints (byte-identical T-9, 16-subdir cap, no wire/config changes), 14 failure modes, 4 ordered migration steps keeping the tree green, and all 16 acceptance cases mapped to concrete test functions with corrected semantics (plus the exact verification command set).
