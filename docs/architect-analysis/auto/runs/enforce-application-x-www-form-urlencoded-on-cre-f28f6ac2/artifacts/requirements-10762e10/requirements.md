Requirements specification complete. Written to:

`docs/architect-analysis/auto/runs/enforce-form-urlencoded-credential-strict-mode-0a8df02f/artifacts/requirements-0a8df02f/requirements.md` (+ `.meta.json`)

## Evidence verification — every citation checked against HEAD `9d8e0294`

All direction citations verified, none contradicted:

| Citation | Result |
|---|---|
| `oauthwire/bind.go:28-48` | Verified — `BindParams` at :28, `default:` branch (:45-48) falls through to `decodeSingleJSON` for missing/unexpected CT; comment at :24-26 documents the JSON fallback |
| `oauthwire/token_request.go:22` | Verified — "Bound via BindParams (form-urlencoded + JSON)" |
| `server_token.go:30` / `server_jar.go:304` | Verified — `bindOAuthParams` alias seam, no-store stamped at :22 before binding |
| `mesh_authz.go:443`, `server_native_sso.go:102` | Verified — `subtle.ConstantTimeCompare` (DPoP ath, ds_hash) |
| `security.CompareClientSecret` | Verified — `shared/security/client_secret.go:20-34`; bcrypt or `ConstantTimeStringEq` (`constant_time.go:10`); single seam via `ClientStore.ValidateSecret` |
| Proposal B4-4, campaign yaml:12/69/79 | Verified — strict mode + config fallback; T-8(a-e) taxonomy |

**Load-bearing facts found beyond the citations:** all four endpoints bind via `oauthwire.BindParams` (`handle_introspect.go:120`, `handle_revoke.go:75`, `handle_par.go:66`); JSON acceptance on `/token`, `/introspect`, `/revoke` is **live-tested today** (`test/handle_token_test.go:59,87`, `test/handle_introspect_test.go:89,237`) — decisive proof strict mode must default off; `BindParams` has ~30 non-credential callers, so the gate must be endpoint-scoped, never package-level; exact precedents exist for the plumbing (`WithOAuth21StrictMode` options.go:194 → accessor; `SecurityConfig` opt-in knobs; `build_app_security.go` wiring).

## Spec highlights

- **R1-R5**: `security.strict_credential_content_type` knob (default false) → `sso.WithStrictCredentialContentType()` → strict binder in `oauthwire` + one accessor on the three protocol Deps interfaces; exactly the four RFC endpoints; error responses byte-identical to today's bind failures (no invented challenge on the 400, no-store preserved).
- **R6**: constant-time work is test-only, with a statistical timing-independence test (anti-flake construction) + deterministic companions.
- **AC-1..AC-6**: all five T-8(a-e) checks preserved and made testable (table-driven across the four endpoints, golden byte-compare for (b), unmodified existing JSON tests as the (c) regression lock).
- **Non-goals**: device-authorization endpoint, protocol-level ban, `cmd/snaplink-audit-provisioner` itself (analysis context only), and all non-credential `BindParams` callers — no scope expansion.
- Documentation-only artifact; no `.go` edits, so no mandatory Go gates were run.
