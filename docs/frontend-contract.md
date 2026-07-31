# External Frontend Release Contract

> Verified against the repository on 2026-07-29.

This file is the API contract a separately deployed frontend must use to
implement hosted login, consent, self-service, admin and first-run setup.
`sso-server` is an API-only backend: it never mounts a static SPA, and this
repository ships no browser UI. A deployment mounts the frontend project
beside (or in front of) the server and reverse-proxies the API paths below.

This contract is versioned with the server release. Frontends MUST consume it
through the runtime discovery documents (which are derived from server state),
never through hard-coded copies of this file.

## 1. Deployment shape and proxy requirements

```
            browser
               │
               ▼
   ┌───────────────────────┐
   │  reverse proxy        │   OpenResty / Envoy / NGINX
   │  (TLS termination,    │
   │   CSP, cookie domain) │
   └───────────┬───────────┘
               │ same origin (/login/*, /admin/*, /portal/*, /setup/*)
               ▼
   ┌───────────────────────┐        ┌──────────────────┐
   │  frontend project(s)  │ ─────► │  sso-server      │
   │  (static assets)      │  API   │  (this repo)     │
   └───────────────────────┘        └──────────────────┘
```

- **Same-origin routing.** The proxy serves frontend assets under
  `/login/*`, `/admin/*`, `/portal/*`, `/developer/*`, `/setup/*` and proxies
  every API path listed below to `sso-server` unchanged (method, headers,
  body). The server itself registers no `/login/` filesystem route.
- **TLS.** Terminate TLS at the edge unless `-tls-cert`/`-tls-key` are given
  to the server. Set `security.trusted_proxies` on the server to the edge's
  CIDRs so `X-Forwarded-*` (issuer resolution, tenant-domain routing, DPoP
  `htu`, audit IPs) is honored; the edge MUST strip and re-set those headers
  from untrusted traffic.
- **Cookies.** The server may set an opaque HttpOnly session cookie (the
  reusable OP-session seam in the `prototype`/`minimal` editions) and
  `Clear-Site-Data` on logout. Frontends must not read session cookies from
  JavaScript; keep cookie attributes (`SameSite`, `Secure`, `Path=/`) at the
  values the server sets. CORS is opt-in via `security.cors`; a same-origin
  deployment does not need it.
- **CSP.** API responses carry `Content-Security-Policy` only when
  `security.security_headers.enabled` is on. The frontend project is
  responsible for its own static-asset CSP (script-src, frame-ancestors,
  connect-src to the API origin) and MUST allow the OIDC `form_post` /
  JARM auto-submit pages (served by the server at `/auth/login` response
  modes) to frame or navigate to the callback origin.
- **Credentials and caches.** Credential endpoints (`/token`, `/auth/login`,
  `/auth/mfa`, `/token/introspect`, `/token/revoke`, ...) answer with
  `Cache-Control: no-store` + `Pragma: no-cache`. Frontends must not cache
  them and must not store tokens in `localStorage` when a session cookie or
  in-memory holder is viable.

## 2. Discovery (the entry point)

| Endpoint | Purpose |
|---|---|
| `GET /.well-known/openid-configuration` | OIDC discovery: issuer, authorization/token/userinfo endpoints, `scopes_supported`, `acr_values_supported`, JARM/JAR/PAR support flags, `code_challenge_methods_supported` |
| `GET /.well-known/oauth-authorization-server` | RFC 8414 alias — same document, for pure-OAuth clients |
| `GET /.well-known/jwks.json` | Signing keys (verify `id_token`/access tokens locally) |
| `GET /.well-known/ssf-configuration` | CAEP/SSF config (when CAEP is wired) |
| `GET /.well-known/openid-federation*` | OpenID Federation entity metadata (when wired) |
| `GET /branding` | Public per-tenant branding lookup for the login page (gated by `feature_gates.branding`; requires a tenant store). Returns only presentation data (brand name, color, logo) keyed by host/client |

The login page MUST resolve the issuer and endpoint set from discovery at
runtime; `server.issuer` is the canonical URL stamped into every artifact.

## 3. Login contract

The login flow is a **JSON API** (the browser does not POST HTML forms to the
server; the frontend renders the form and calls the API):

1. Frontend builds an authorization request (client_id, `response_type=code`,
   `redirect_uri`, `scope`, PKCE `code_challenge`/`code_challenge_method`,
   optional `login_hint`, `prompt`, `max_age`, JAR/JARM parameters).
2. `POST /auth/login` with `provider` (e.g. `password`, `webauthn`, a
   connection id), the request parameters, and provider credentials:
   `{"provider":"password","client_id":"...","response_type":"code",
   "redirect_uri":"...","scope":[...],"code_challenge":"...",
   "code_challenge_method":"S256","credential":{"username":"...","password":"..."}}`
3. On success the response carries the `code` (or `redirect_to` for
   form_post/JARM rendering) plus optional UX fields (MFA challenge,
   `suggested_username`, `must_change_password`, ...).
4. The frontend redirects the browser to the client's `redirect_uri` with the
   code (query, fragment, or auto-submit form per `response_mode`), or hands
   the code to a native/SPA client for `/token` exchange.
5. MFA: when the response includes an MFA challenge, the frontend renders the
   factor UI and completes it via `POST /auth/mfa` (or the provider-specific
   `/auth/send-code` for OTP delivery) before the flow finishes.
6. Errors use the OAuth error vocabulary from [error-codes.md](error-codes.md)
   (`invalid_request`, `unauthorized_client`, `unsupported_provider`,
   `mfa_invalid`, `session_invalid`, ...). Oracle-safe responses are
   byte-identical across unknown/disabled/broken providers — the frontend
   must render a single generic "cannot sign in" state, never per-cause text.

## 4. Consent contract

Consent is opt-in per deployment (`self_service.consent` + per-client
`consent_required`). When a login needs consent:

- The `/auth/login` response signals `consent_required` with the requested
  scope set; the frontend renders the consent screen from the requested
  scopes (human-readable text is the frontend's job; the server does not
  ship copy).
- The user's decision is recorded via the authenticated consent APIs
  (`GET /consents/me`, `DELETE /consents/me/:client_id`) and the server-wide
  consent TTL (`self_service.consent.max_ttl`) bounds silent re-consent.
- The frontend must treat consent as a login-flow step: no consent screen is
  shown, no code is issued when the client requires it.

## 5. Self-service contract (`/me/*`, authenticated)

| Endpoint | Purpose |
|---|---|
| `GET /me` | Account overview (profile + session/consent counts) — the portal's landing call |
| `GET/PUT /me/profile` | Profile read/update |
| `POST /me/password` | Password change (current password verified) |
| `GET /me/mfa`, `DELETE /me/mfa/:id` | MFA factor list / unbind |
| `GET /me/sessions`, `DELETE /me/sessions/:id`, `POST /me/sessions/revoke-all` | Active sessions |
| `GET /consents/me`, `DELETE /consents/me/:client_id` | Granted apps |
| `GET /me/identities`, `DELETE /me/identities/:id` | Linked external identities (identity-link store) |
| `GET /me/data-export` | GDPR Art. 15 export (opt-in) |
| `POST /me/account/erase` | GDPR Art. 17 erasure (opt-in, irreversible) |
| `GET /permissions/me`, `GET /roles/me`, `GET /menus/me` | Authorization tree for UI rendering |

Unauthenticated flows (all opt-in): `POST /auth/register` (signup),
`POST /auth/forgot-password`, `POST /auth/reset-password`,
`POST /auth/send-code` + verification.

## 6. Admin contract (`/api/v1/admin/*`, `admin:read`/`admin:write`)

The admin console consumes the REST gateway of the same services the gRPC
control plane exposes: clients, users, tenants, sessions, tokens, keys,
policies, audit, network policy, branding, backups, DR mode, threat policies,
releases, snapshots and the runtime endpoint inventory. Bearer
authentication; 401 carries `Bearer realm="admin"` (the admin scope, not a
user scope). The complete operation set is in [openapi.yaml](openapi.yaml)
and the gRPC service definitions under `proto/`; the runtime truth for a
given replica is `GET /api/v1/admin/endpoints` (admin-gated inventory of
routes that replica actually registered).

## 7. First-run setup contract

`setup_wizard.enabled` opts into: `GET /api/v1/setup/status` (does an admin
exist yet?) and `POST /api/v1/setup` (create the first admin and optionally
the first application). After initialization the wizard locks
(`409 already_initialized`). The setup UI is a separate project; the server
never serves it.

## 8. Logout contract

- `GET /end_session` — OIDC RP-initiated logout (post_logout_redirect_uri).
- `POST /logout` — same-origin logout: clears the OP session, fires
  backchannel/frontchannel logout to registered RPs, and (with
  `security.security_headers`) emits `Clear-Site-Data`.
- The frontend must navigate the browser to these endpoints rather than
  "logging out" client-side only; token/session revocation is server-side
  state.

## 9. Compatibility and versioning policy

- The contract is backward compatible within a schema version
  (`config.CurrentSchemaVersion`); breaking changes bump the schema version
  and are announced in [CHANGELOG.md](CHANGELOG.md).
- Deprecated surfaces (`hosted_login`, `feature_gates.web_spa`) parse with
  warnings and are removed at the next schema bump; see
  [config-reference.md](config-reference.md).
- Frontends should pin the server minor version they are tested against and
  treat `/api/v1/admin/endpoints` + discovery as the runtime truth, not this
  document.
