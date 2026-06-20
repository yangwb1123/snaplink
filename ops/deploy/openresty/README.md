# OpenResty front-end for snaplink/sso

This directory ships an OpenResty configuration that sits in front of the
`cmd/sso-server` binary and adds three things at the edge:

1. **Local JWT verification** — the gateway pulls `/.well-known/jwks.json`
   once per minute and verifies EdDSA-signed access tokens locally with
   `lua-resty-jwt`. Authenticated requests no longer round-trip the SSO
   server just to validate the token.
2. **Permission gating** — for protected routes, the first request per
   `(token, client_id)` calls `/permissions/me` and caches the resulting
   set in `ngx.shared.DICT` for 60s. Subsequent requests are checked
   in-process, so 90%+ of authorization work never touches Go.
3. **Per-request audit** — `log_by_lua_block` writes a JSON-Lines event for
   every request (success, failure, 4xx, 5xx) including request id, trace
   context, latency and upstream status. Pair with Filebeat/Vector/Promtail
   to ship to your audit store.

## Layout

```
deploy/openresty/
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

OpenResty 1.21+ with the following bundled modules (all are part of the
default OpenResty distribution):

- `lua-resty-jwt`
- `lua-resty-http`
- `lua-resty-lock`

If you build OpenResty from source, ensure these are linked.

## Running locally

In one terminal, start the SSO server:

```sh
cd cmd/sso-server
go run . --config config.yaml
# Listening on :8080
```

In another, start OpenResty against this config:

```sh
cd deploy/openresty
mkdir -p logs ssl
# Generate a self-signed cert for the dev https listener.
openssl req -x509 -newkey ed25519 -nodes \
    -keyout ssl/dev.key -out ssl/dev.crt -days 30 \
    -subj "/CN=sso.local"

openresty -p "$PWD" -c nginx.conf
# Listening on :8443 (TLS), proxying to 127.0.0.1:8080
```

End-to-end smoke test:

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
| `/health`, `/.well-known/jwks.json` | none | discoverable for any client |
| `/auth/*`, `/token`, `/logout` | none | login flow itself can't require login |
| `/userinfo`, `/menus/me`, `/permissions/me`, `/roles/me` | `auth.verify()` | JWT must be valid; subject is forwarded via `X-Auth-Subject` |
| `/api/v1/*` | `auth.verify()` | layer extra RBAC inside Go for admin endpoints |

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

This config is the smallest thing that demonstrates the architecture. Before
production, consider:

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
