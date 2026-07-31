# OIDC Conformance Test Suite

This directory runs the [OpenID Foundation's Conformance Test
Suite](https://gitlab.com/openid/conformance-suite) against a local
`sso-server` instance built from this repository.

> **No conformance claim:** this harness is not part of `make ci`, requires
> browser interaction, and has no committed pass report or certification
> artifact. “Implemented in the server” is not equivalent to “passed the OIDF
> suite,” and snaplink must not be described as OIDF-certified on the basis of
> this directory. Certification status lives in
> [`docs/sso/oidc-conformance.md`](../../docs/sso/oidc-conformance.md).

## Supported test profiles

The runtime accepts `response_type=code` (plus a direct-mint `token`
branch). It does **not** implement implicit or hybrid OP response types, so
only code-based OIDF modules may be selected. The module allowlist below is
the only supported profile set; anything else must not be run or claimed.

| OIDF module | Allowed | Notes |
|---|---|---|
| `basic` (code) | ✅ | Authorization Code + PKCE, ID Token, UserInfo |
| `config` | ✅ | Dynamic discovery + configuration |
| `dynamic` | ✅ | DCR registration of test clients |
| `formpost` | ✅ | `response_mode=form_post` |
| `session` | ✅ | Session management (`check_session_iframe`) |
| `logout` | ✅ | RP-initiated logout |
| `jarm` | ✅ | Requires `oauth.jar`/JARM wiring; opt-in |
| `fapi` | ✅ | FAPI 2.0 code profile only, when FAPI wiring is enabled |
| `ciba` | ✅ | Only when a CIBA store is wired |
| `implicit` | ❌ | Runtime rejects `id_token` response types |
| `hybrid` | ❌ | Runtime rejects `code id_token` response types |
| `userinfo` (standalone) | ⚠️ | Only as part of `basic`; no standalone module |

## Run

Prerequisites: Docker with compose v2.

```bash
# 1. Validate the pinned server config (fails fast on schema drift):
docker compose run --rm --no-deps sso-server --validate-only

# 2. Build and start the harness:
docker compose up -d --build

# 3. Open http://localhost:8080 in a browser, create a new test plan, and
#    select ONLY modules from the allowlist above. The suite reaches the
#    server-under-test at http://sso-server:8080 (compose network); the
#    browser must reach it at http://localhost:8180 (the issuer in
#    config.yaml).
#
# 4. After the run, export and archive the artifacts per "Evidence" below.
```

The conformance-suite image is pinned to
`registry.gitlab.com/openid/conformance-suite:release-v5.2.1` — deliberately
not `:latest`. Bump it only together with a re-run and archived results.

## Evidence

A certification-quality archive must contain, committed or attached to the
release that claims it:

1. The exact server commit (`git rev-parse HEAD` + `git status --porcelain`),
   build profile (`sso-server version`) and the harness `config.yaml`.
2. The exact conformance-suite image digest
   (`docker inspect --format '{{.Image}}' ...` or the pinned tag).
3. The exported test plan (module list, variant, client settings).
4. The raw suite results export (HTML/JSON) per plan.
5. The Go build/module inventory (`go version -m ./bin/sso-server`).

Store these under `results/<commit>/` (git-ignored; keep only the README
template committed) and reference them from
[`docs/sso/oidc-conformance.md`](../../docs/sso/oidc-conformance.md) before
any certification claim is made. An HTTP-only local topology is a smoke
environment; a certification run requires an externally reachable HTTPS
issuer per OIDF guidance.

## Troubleshooting

- Server startup: `docker compose logs sso-server`
- Config rejected at boot: the server refuses to start; run
  `docker compose run --rm --no-deps sso-server --validate-only` to see the
  error without starting a container.
- Redirect/network failure: verify the issuer and server URL are reachable
  from the conformance container (`docker compose exec conformance-suite
  wget -qO- http://sso-server:8080/.well-known/openid-configuration`).
- Database failure: `docker compose logs conformance-db`
