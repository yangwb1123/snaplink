# snaplink/sso — Python client (generated)

> **Scope:** convenience client for a curated OpenAPI subset. It is not a
> complete SDK for every runtime route, not published to PyPI, and does not
> provide hosted-login, self-service, setup, developer-portal, or admin-console
> UI. `sso-server` is a pure API backend; browser applications and consoles are
> separate frontend projects.

`client.py` is **generated output**, committed the same way generated Go under
`gen/proto/` is: checked in for consumers to use directly, regenerated from
`docs/openapi.yaml` by a Go program rather than hand-maintained.

```
go run ./cmd/gensdk --lang=py
```

Regenerate after any change to `docs/openapi.yaml` that touches an operation
listed below. `client.py` has **zero third-party dependencies** — transport
is stdlib `urllib.request`, wire-shape typing is stdlib `typing.TypedDict`
— so there is no `pip install` step either; vendor the single file into
your project (`pyproject.toml`/`requirements.txt` packaging is
deliberately not set up here — see "What's NOT here" below).

The generator reads `docs/openapi.yaml`; it does not inspect Go route
registration. A runtime endpoint that has not yet been added to OpenAPI cannot
appear in this client. Reconcile the runtime route inventory and OpenAPI before
claiming complete API coverage.

## What's covered

The exact same curated, hand-scoped operation subset as the TypeScript
client (`../typescript/README.md`) — see that file for the full list and
the rationale for what's deferred. The allowlist itself lives once, in Go,
as `coreSurface` in `cmd/gensdk/operations.go`, and both language
emitters read from it, so the two clients can never drift apart in scope.

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

## What's NOT here

No `pyproject.toml`/`setup.py` packaging, no `requirements.txt` (there is
nothing to require). This is meant to be vendored as a single file, not
published to PyPI — turning it into a real package is a separate,
deliberate decision for whoever wants to publish it, not something this
generator should quietly decide.

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
