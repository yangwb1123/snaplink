# snaplink/sso — Python client (generated)

> **Scope:** generated client for the full documented API surface of
> `docs/openapi.yaml`, plus a framework-neutral hosted-login facade. It is not
> published to PyPI, and does not ship hosted-login, self-service, setup,
> developer-portal, or admin-console UI.
> `sso-server` is a pure API backend; browser applications and consoles are
> separate frontend projects.

`client.py` is **generated output**, committed the same way generated Go under
`gen/proto/` is: checked in for consumers to use directly, regenerated from
`docs/openapi.yaml` by a Go program rather than hand-maintained. The same
generated module is also written to `sdks/python/snaplink_sso/client.py` so
applications can install and import the repository's `snaplink_sso` package.

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

The **complete** operation set of `docs/openapi.yaml` — the same surface as
`../typescript/README.md` (every documented operation today, including the
full admin control plane, SCIM, SSF and Federation). The operationId set is
declared once in `ops/build/sdk-surface.json`, and both language emitters
read from it, so the two clients can never drift apart in scope.

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

There is also no generated compatibility policy or semantic-versioned Python
release. Consumers that vendor the file should regenerate and review it when
upgrading the server.

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
