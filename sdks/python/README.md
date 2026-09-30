# snaplink-sso Python package

This package is the installable form of the generated Snaplink Python SDK.
The source module is generated from `docs/openapi.yaml` and the SDK-surface
registry; do not edit `snaplink_sso/client.py` by hand.

It also exports `snaplink`, a framework-neutral hosted-login facade. Call
`snaplink.login({...})` to receive the existing Console `/login/` redirect,
then call the same method with `callback_url` to complete public-client PKCE;
no BFF or client secret is required.

From the repository root, regenerate both the documented single-file client
and this package module with:

```text
python cli.py sdk-surface generate
```

The package uses only Python's standard library at runtime. It supports
Python 3.9 and newer and is intended for applications that want a normal
`snaplink_sso` import; consumers that vendor one file may use
`docs/sdks/python/client.py` instead.

For paid or invited products, call `snaplink.setup({...})` before login. The
credential is sent in the HTTPS JSON body, while only the short-lived ticket is
kept in the in-process setup state and copied into the login transaction:

```python
snaplink.setup({
    "base_url": "https://sso.example.com",
    "client_id": "my-public-app",
    "product_id": "pro",
    "license_key": "license-from-your-checkout",
})
started = snaplink.login({
    "base_url": "https://sso.example.com",
    "client_id": "my-public-app",
    "redirect_uri": "https://app.example.com/auth/callback",
})
```

The one-call form is `login({..., "setup": {"product_id": "pro",
"license_key": "..."}})`. Use `invitation_code` for invitations. After the
callback, `snaplink.get_account_context()` returns server-derived entitlement
and limits; credentials are never placed in URLs or OAuth state.

For trusted local-network development only, set
`allow_insecure_http_for_development: True`; production integrations must use
HTTPS.

The hosted-login client exposes the same explicit session lifecycle as the
other server-side SDKs. `refresh()` performs a refresh-token grant and preserves
a refresh token if the server does not rotate it; `clear()` forgets local tokens
without a server request; `logout()` revokes server-side and clears local state
even if revocation fails.

For shared presentation settings, wrap the generated client with
`SnaplinkUserPreferencesClient`. It exposes `locale` and `theme_mode`, writes the application-neutral
`theme_mode` wire key, reads the legacy `sverp:theme_mode` alias during
migration, and does not own application storage:

```python
from snaplink_sso import (
    PresentationPreferencesPatch,
    SnaplinkUserPreferencesClient,
)

preferences = SnaplinkUserPreferencesClient(client)
current = preferences.get_my_preferences()
preferences.update_my_preferences(PresentationPreferencesPatch(theme_mode="dark"))
```
