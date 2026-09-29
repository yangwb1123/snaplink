# SDK packages

Language SDK code is grouped by language; independent package manifests live
beside their package where the language uses them:

| Language | Package directory | Documentation |
|---|---|---|
| Go | [`go/`](go/) | [`go/README.md`](go/README.md) |
| TypeScript | [`typescript/`](typescript/) | [`docs/sdks/typescript/README.md`](../docs/sdks/typescript/README.md) |
| Python | [`python/`](python/) | [`python/README.md`](python/README.md), [`docs/sdks/python/README.md`](../docs/sdks/python/README.md) |
| PHP | [`php/`](php/) | [`php/README.md`](php/README.md) |
| Rust | [`rust/`](rust/) | [`rust/README.md`](rust/README.md) |

The embeddable Go server API is the separate `interfaces/sso` package; it stays
in the layered server library rather than moving under this client-package tree.

The generated TypeScript API client lives at `typescript/client.ts`. The Go
code generator also emits the Python API client at
`../docs/sdks/python/client.py` and the installable Python package module under
`python/snaplink_sso/`:

```sh
go run ./cmd/gensdk --lang=all
```
