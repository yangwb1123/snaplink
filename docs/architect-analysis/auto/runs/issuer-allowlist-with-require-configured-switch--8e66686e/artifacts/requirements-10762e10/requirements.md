Requirements spec delivered to `docs/architect-analysis/auto/runs/issuer-allowlist-eliminate-the-host-derived-fall-bbdb82eb/artifacts/requirements-10762e10/requirements.md` (the run's pipeline output path; the earlier attempt FAILED there, per `DECISIONS.md`).

## Evidence verification — all 8 citations confirmed

| Citation | Verdict |
|---|---|
| `server_discovery.go:251-259` `resolveIssuer` Host fallback | Confirmed (:252-255; RFC 9207 invariant comment :242-249) |
| `server_discovery_config.go:144,260-266` discovery `Issuer: base` + `WithIssuer` override | Confirmed (+ `base := requestBaseURL` at :62) |
| `middleware/request_url.go:22-49` `BaseURL` Host/XFH | Confirmed, with trusted-edge gate |
| `config_load.go:60,183-184,301-308` non-sentinel default + sentinel rejection + `WithIssuer` wiring | Confirmed |
| `build_app_core.go:154` `ServerOptions` appended | Confirmed |
| `options.go:349-351` `WithIssuer` single string, no allowlist | Confirmed; `issuer_allowlist`/`require_configured` grep = zero hits repo-wide |
| `oidc_discovery_test.go:80` | Confirmed |
| SAML `AllowedIssuers` (:49) only existing allowlist | Confirmed, different concern |

## Key findings baked into the spec

- **JWT `iss` doesn't flow through `resolveIssuer`** — it's the signer's constructor value (`build_signing_issuers.go:43,70,98` ← `cfg.Server.Issuer`), so allowlist enforcement for minted tokens is a **boot-time** check, not request-time; 503s cover discovery + authorization surfaces.
- **One entry gate covers all 8 RFC 9207 surfaces**: `handleLogin` (:19) is the sole authorization entry — a top-of-handler gate makes the Host fallback unreachable for every response mode (query/fragment/form_post/JARM, success/error) with zero edits to the 8 `resolveIssuer` sites, protecting at-budget `server_finish_login.go` (500 lines, in-flight worktree diff).
- **Deterministic strict-mode split**: cmd path (issuer always defaults non-sentinel) → boot panic when issuer ∉ allowlist; SDK-embedder path (no issuer) → boots, discovery/login/token 503 `issuer_not_configured`. Matches the acceptance's "boot fails or /token 503s".
- **Budget compliance**: `interfaces/sso` at frozen 60-file ceiling → new production code goes only into files with measured headroom (`sso_wiring.go` 456, `server_discovery.go` 483, `sso.go` 499 +1 line); `options.go`/`aliases.go`/`server_finish_login.go` explicitly do-not-touch; conditional option emission keeps `config/security_test.go` count pins green.
- **16 Given/When/Then acceptance cases** (T-8(a) leg, T-2 sweep with Host tampering, RFC 9207 parity, strict-mode 503s/panics, mode-off byte-identity, G1 T-1.2/T-8(a) handoff) mapped to concrete test homes. Key name `server.issuer_allowlist` matches the sibling configcmd direction (whose "not read at boot" note this spec supersedes by design).
