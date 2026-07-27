# OpenResty edge prototype for snaplink/sso

This directory ships an OpenResty configuration that sits in front of the
`cmd/sso-server` API binary and demonstrates three edge concerns:

> **Prototype boundary:** this is not a hosted login/admin frontend and is not
> part of the stock `sso-server` binary. The product's login, self-service,
> setup, developer, and admin UIs are separate projects. The Lua verifier here
> is Ed25519-only and does not reproduce the server's full bearer, issuer,
> audience, DPoP, mTLS, revocation, or oracle-safe error policy. Do not use it as
> the sole production authorization boundary without a dedicated security
> review and conformance tests.

1. **Local JWT verification** — the gateway pulls `/.well-known/jwks.json`
   once per minute and verifies EdDSA-signed access tokens locally with
   `lua-resty-jwt`. This prototype handles only `OKP`/Ed25519 JWKs; ECDSA, RSA,
   PS256, opaque tokens, and multi-algorithm key sets are unsupported.
2. **Permission gating** — for protected routes, the first request per
   `(token, client_id)` calls `/permissions/me` and caches the resulting
   set in `ngx.shared.DICT` for 60s. Subsequent requests are checked
   in-process until that cache expires.
3. **Per-request edge log** — `log_by_lua_block` writes a JSON-Lines event for
   every request (success, failure, 4xx, 5xx) including request id, trace
   context, latency and upstream status. This is not a substitute for the
   platform's tamper-evident audit pipeline.

## Layout

```
ops/deploy/openresty/
├── nginx.conf           # entrypoint
├── conf.d/
│   ├── sso.conf         # server block: routes, TLS, log_by_lua hookup
│   └── proxy_pass.inc   # shared proxy_pass directives (header forwarding)
├── lua/
│   ├── utils.lua            # helpers: bearer parse, JSON, randomness
│   ├── jwks_cache.lua       # JWKS fetch + shared-dict cache
│   ├── permission_cache.lua # /permissions/me cache + wildcard matcher
│   ├── auth.lua             # access_by_lua entry: verify() + verify_with_permission()
│   └── audit.lua            # log_by_lua entry: emit one JSON event per request
└── README.md            # this file
```

## Prerequisites

OpenResty 1.21+ with the following Lua modules available:

- `lua-resty-jwt`
- `lua-resty-http`
- `lua-resty-lock`

The checked-in Dockerfile copies configuration but does not install or verify
these Lua packages. Confirm the selected base image contains compatible
versions, or install/pin them explicitly before running the image. Also verify
that the chosen JWT library supports Ed25519 in the representation passed by
`jwks_cache.lua`.

## Running locally

In one terminal, start the SSO server:

```sh
cd cmd/sso-server
go run . --config config.yaml
# Listening on :8080
```

In another, start OpenResty against this config:

```sh
cd ops/deploy/openresty
mkdir -p logs ssl
# Generate a self-signed cert for the dev https listener.
openssl req -x509 -newkey ed25519 -nodes \
    -keyout ssl/dev.key -out ssl/dev.crt -days 30 \
    -subj "/CN=sso.local"

openresty -p "$PWD" -c nginx.conf
# Listening on :8443 (TLS), proxying to 127.0.0.1:8080
```

End-to-end smoke test:

The example below assumes `mobile-app` is present and a password user `alice`
has been explicitly seeded. The reference server config does not enable that
user by default.

```sh
# 1. Login through the gateway (passes through to SSO).
TOKEN=$(curl -sk https://sso.local:8443/auth/login \
    -H "X-Request-Id: trace-001" \
    -H "Content-Type: application/json" \
    -d '{"client_id":"mobile-app","provider":"password",
         "credential":{"username":"alice","password":"secret"}}' \
  | jq -r .access_token)

# 2. Call /userinfo — gateway verifies the JWT locally (no Go round-trip
#    for the verification step).
curl -sk https://sso.local:8443/userinfo -H "Authorization: Bearer $TOKEN"

# 3. Inspect the gateway's audit log line for both requests:
tail -n 5 logs/audit.jsonl
```

## How the routes are gated

| Route | Edge auth | Notes |
| --- | --- | --- |
| `/health`, `/.well-known/jwks.json` | none | current public prototype routes; use `/livez` and `/readyz` for real probes |
| `/auth/login`, `/auth/send-code`, `/auth/callback`, `/token`, `/logout` | none | exact public routes in the current prototype config |
| `/userinfo`, `/menus/me`, `/permissions/me`, `/roles/me` | `auth.verify()` | JWT must be valid; subject is forwarded via `X-Auth-Subject` |
| `/api/v1/*` | `auth.verify()` | layer extra RBAC inside Go for admin endpoints |

There is no catch-all proxy. Unlisted protocol routes—including `/auth/mfa`,
token introspection/revocation, most discovery endpoints, registration, PAR,
device flow, CIBA, and federation—are not exposed by this prototype until
explicitly added and tested.

## Adding a permission gate

When a backend route should require a specific permission, swap
`auth.verify()` for `auth.verify_with_permission(...)`:

```nginx
location /api/v1/audit/events {
    access_by_lua_block {
        require("auth").verify_with_permission("audit:read")
    }
    include conf.d/proxy_pass.inc;
}
```

The Lua matcher follows the same rules as `permissions.Matches` in Go:
exact codes, `<domain>:*`, and `*` wildcards.

## Production hardening

This config is the smallest thing that demonstrates the architecture. It is
not production-ready. Before promoting a derived gateway:

- **Token validation parity** — enforce the expected algorithm before
  signature verification, issuer, every accepted audience shape, expiry/not
  before/skew, token type, revocation, DPoP/mTLS binding, and the platform's
  oracle-safe `invalid_token` behavior. Add ECDSA/RSA/PS256 or explicitly reject
  deployments that publish those keys.
- **Authoritative authorization** — treat `X-Auth-*` as trusted only when the Go
  server is configured to trust this exact proxy CIDR; strip client-supplied
  values before setting them.

- **Real TLS certs** — replace the self-signed `ssl/dev.{crt,key}` with a
  managed cert (Let's Encrypt, internal CA).
- **JWKS pre-shipping** — embed the SSO public key statically and only fall
  back to JWKS fetch on key-id mismatch, removing the runtime dependency
  on the SSO server's reachability for verification.
- **Permission cache invalidation** — wire Redis pub/sub: SSO publishes on
  `Revoke` / role change, OpenResty subscribes and clears affected entries.
- **Stream sink for audit** — replace the `ngx.log` line in `audit.lua`
  with an `ngx.timer.at(0, ...)` that XADDs to Redis Stream or POSTs to
  Kafka REST proxy. Keep the work async so log_by_lua never blocks.
- **Rate limit + WAF** — `limit_req_zone` for login endpoints, ModSecurity
  or Coraza for request inspection.
- **Resolver** — the bundled `127.0.0.11` is Docker's embedded DNS;
  outside Docker, point at your service-discovery resolver (e.g. consul-dns
  on 127.0.0.1:8600, or your VPC's recursive resolver).
