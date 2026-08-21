# snaplink-sso Python package

This package is the installable form of the generated Snaplink Python SDK.
The source module is generated from `docs/openapi.yaml` and the SDK-surface
registry; do not edit `snaplink_sso/client.py` by hand.

From the repository root, regenerate both the documented single-file client
and this package module with:

```text
python cli.py sdk-surface generate
```

The package uses only Python's standard library at runtime. It supports
Python 3.9 and newer and is intended for applications that want a normal
`snaplink_sso` import; consumers that vendor one file may use
`docs/sdks/python/client.py` instead.
