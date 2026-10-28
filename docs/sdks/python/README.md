# snaplink/sso — Python client (generated)

> **Scope:** generated client for the selected operation allowlist in
> `ops/build/sdk-surface.json`, sourced from `docs/openapi.yaml`, plus a
> framework-neutral hosted-login facade. The
> installable package under `sdks/python` is published to PyPI as
> `snaplink-sso`; this generated directory remains vendorable and does not
> ship a login page, self-service, setup, developer-portal, or admin-console UI.
> `sso-server` is a pure API backend; browser applications and consoles are
> separate frontend projects.

`client.py` is **generated output**, committed the same way generated Go under
`gen/proto/` is: checked in for consumers to use directly, regenerated from
`docs/openapi.yaml` by a Go program rather than hand-maintained. The same
generated module is also written to `sdks/python/snaplink_sso/client.py` so
applications can install and import the repository's `snaplink_sso` package.

Install the package with `pip install snaplink-sso` (import name `snaplink_sso`).
Releases run the protected
`sdk-py-v<version>` workflow after the package tests, wheel/source build, and
tag/version check pass.

```
go run ./cmd/gensdk --lang=py
```

Regenerate after any change to `docs/openapi.yaml` or
`ops/build/sdk-surface.json` (run `python cli.py sdk-surface generate`, which
re-emits every language). `client.py` has **zero third-party dependencies** — transport
is stdlib `urllib.request`, wire-shape typing is stdlib `typing.TypedDict`
— so there is no runtime dependency installation step; vendor the single
file into your project or install the repository package under `sdks/python/`
(see "What's NOT here" below).

The generator reads `docs/openapi.yaml`; it does not inspect Go route
registration. A runtime endpoint that has not yet been added to OpenAPI cannot
appear in this client. Reconcile the runtime route inventory and OpenAPI before
claiming complete API coverage.

## What's covered

The same selected surface as `../typescript/README.md`: currently **321 of
366 documented operations**, in 13 groups, not the full OpenAPI API. The sole
allowlist is `ops/build/sdk-surface.json`; synchronous and asynchronous Python
clients and TypeScript read that same selection.

`ops/build/sdk-surface-coverage.json` records all 45 unselected operations and
selected-group reasons. Existing CIBA, notification REST, config writes,
expiring-client and permission catalog/SoD APIs are explicit SDK debt, not absent
server features. SSE/text need separately accepted transports; Billing management,
payment/metering machines and quota projection have distinct composition,
credential, scope and server binding boundaries.

`python cli.py sdk-surface check` rejects incomplete/stale coverage decisions while
retaining capability/version/package checks. `python cli.py sdk-surface coverage`
is a deterministic read-only per-operation report: decision, method/path, media
types, OpenAPI security declaration/source and exposure/authentication/default/
licensing rationale. This does not verify runtime exposure/authentication, grant
a commercial license or establish package/platform acceptance. Missing bearer
security is not proof of public access; CIBA/token client authentication is a
separate contract.

Method names are the operation's `operationId` converted to
**snake_case** (`post_token`, `get_user_info`, ...) for a PEP 8-idiomatic
call site; each method's docstring names the original `operationId` for
exact traceability back to `docs/openapi.yaml`.

## Why `TypedDict`, not `@dataclass`

The client never constructs an instance from a JSON response — no
field-by-field validation/mapping — it just returns the parsed
`dict`/`list` straight from `json.loads`. A `TypedDict`'s static type IS a
dict: `result["access_token"]` type-checks AND matches what is really at
runtime. A `@dataclass` would type-check `result.access_token` while the
runtime value stayed a plain dict — actively misleading. `TypedDict` has
been in the stdlib `typing` module since Python 3.8, so this is still
"stdlib only, no new dependency."

## Known simplifications in the generator

(`cmd/gensdk/schema.go` + `gen_py.go` — see their doc comments for detail.)

- **Selection is not full media-type support.** Existing selected HTML and admin
  SSE methods are retained for compatibility, but the JSON client does not thereby
  provide browser rendering, subscription/cancellation or reconnection. Use the
  coverage report to inspect declared media types.
- **The OAuth credential family sends `application/x-www-form-urlencoded`
  bodies**: the seven credential-endpoint operations (`post_token`,
  `post_introspect`, `post_revoke`, `post_par`, `post_device_code`,
  `post_device_verify`, `post_mfa_complete`) use the RFC-mandated form
  wire; every other operation keeps sending JSON. Form values follow the
  server binder's contract: booleans are lowercase `true`/`false` (never
  Python's `True`/`False` — the binder silently coerces those to false),
  string arrays (`resource`/`audience`/`tokens`) become repeated keys via
  `urlencode(doseq=True)`, objects and arrays of objects (`claims`,
  `authorization_details`) become a single key holding the JSON text
  (RFC 9396 §3 / OIDC Core §5.5), and `params` on `post_mfa_complete` has
  no form encoding — the client raises an `invalid_request` error rather
  than sending it (use the flat `code`/`assertion` fields instead).
- **Every generated `TypedDict` is `total=False`** (every key optional to
  the type checker) rather than encoding the spec's `required` list
  precisely — the precise version needs `Required[]`/`NotRequired[]`
  (Python 3.11+) or a two-class split; `total=False` was chosen to stay
  compatible with older stdlib `typing` without extra machinery. At
  runtime `TypedDict` enforces nothing either way.
- **Enum-valued strings are simplified to `str`** (no generated
  `enum.Enum` — the OpenAPI enum's allowed values are not connected back
  to the field's type in this pass).
- **An inline (non-`$ref`) request/response body is typed
  `Dict[str, Any]`**, not a synthesized `TypedDict` — e.g.
  `change_my_password`'s and `patch_me`'s bodies. Every OTHER field/type
  in this client IS precisely typed via its named component schema; this
  only affects the handful of endpoints whose OpenAPI schema is defined
  inline rather than via `$ref`.
- Field order is alphabetical (not the YAML's authored order) for the
  same determinism reason documented in the TypeScript README.
- The `camelCase -> snake_case` method-name conversion is a simple
  heuristic (treats a run of uppercase letters as one acronym), not an
  acronym dictionary — e.g. `getOAuthAuthorizationServerMetadata` becomes
  `get_o_auth_authorization_server_metadata` rather than the more natural
  `get_oauth_authorization_server_metadata`.

## One-call hosted login without a BFF

`Snaplink.login()` uses the existing Console `/login/` page with a public
client and S256 PKCE. The first call returns a redirect URL; call it again
with the callback URL and the SDK validates state and issuer, exchanges the
code, and exposes the generated API client. A framework only needs to return
the first URL as a 302 and pass the callback request URL back to the SDK.

```python
from snaplink_sso import snaplink

started = snaplink.login({
    "base_url": "https://sso.example.com",
    "client_id": "my-public-app",
    "redirect_uri": "https://app.example.com/auth/callback",
    "return_to": "https://app.example.com/dashboard",
})
return redirect(started.redirect_url)

# On the registered callback route:
completed = snaplink.login({
    "base_url": "https://sso.example.com",
    "client_id": "my-public-app",
    "redirect_uri": "https://app.example.com/auth/callback",
    "callback_url": request.url,
})
me = snaplink.api.get_user_info()
```

For trusted local-network development only, set
`allow_insecure_http_for_development: True`; production integrations must use
HTTPS.

The hosted facade deliberately has no client-secret option. Use a durable,
atomic `StateStore` implementation for multi-worker deployments; the built-in
`MemoryStateStore` is for development and single-process examples. Access
tokens remain in memory and are not written to browser storage.

## What's NOT here

The `docs/sdks/python` directory itself has no independent packaging or
release metadata. It remains the vendorable single-file form; the
repository's installable package metadata is kept separately under
`sdks/python/` and is generated from the same content. There is no
`requirements.txt` because the runtime has no third-party dependencies.
Consumers that vendor the file should regenerate and review it when upgrading
the server.

## Usage

```python
from client import SSOClient, SSOError

client = SSOClient(
    "https://sso.example.com",
    get_access_token=lambda: my_token_store.get("access_token"),
)

tokens = client.post_token({
    "grant_type": "authorization_code",
    "code": "ac_...",
    "redirect_uri": "https://app.example.com/cb",
    "client_id": "my-app",
})

try:
    me = client.get_user_info()
    print(me["email"])
except SSOError as e:
    print(e.status, e.error, e.error_description)
```
