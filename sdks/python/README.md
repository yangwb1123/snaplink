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
