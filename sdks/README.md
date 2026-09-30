# SDK packages

Language SDK code is grouped by language; independent package manifests live
beside their package where the language uses them:

## Package naming

Every published package is the same logical name, `snaplink` + `sso-client`,
rendered with the naming rule of its own registry. The brand token owns the
platform's namespace slot; the capability token fills the name slot:

| Platform | Package name | Rendering rule | Import identifier |
|---|---|---|---|
| npm | `@snaplink/sso-client` | lowercase `@scope/name` | `@snaplink/sso-client` |
| PyPI | `snaplink-sso-client` | PEP 503 normalized flat name | `snaplink_sso` |
| crates.io | `snaplink-sso-client` | lowercase, single dash | `snaplink_sso_client` |
| Packagist | `snaplink/sso-client` | lowercase `vendor/package` | `Snaplink\…` |
| Maven | `com.snaplink:sso-client` | reverse-DNS `groupId:artifactId` | `com.snaplink.sso` |
| SwiftPM | `SnaplinkSSO` | PascalCase module | `SnaplinkSSO` |
| Go | root Go module `github.com/yangwb1123/snaplink` | import path is the repository path | `snaplink` |

Notes on the deliberate exceptions:

- **Python** installs as `snaplink-sso-client` but imports as `snaplink_sso`.
  Python import names are conventionally short, and the distribution name is
  the published identity (as with `scikit-learn`/`sklearn`).
- **Rust** has no separate import name, so the crate name is the identifier:
  `snaplink_sso_client`.
- **Swift** carries brand and capability in one PascalCase module name and drops
  the `Client` role token, which would stutter against `SnaplinkAuthClient`.
- **PHP** classes are de-stuttered for the same reason: the client is
  `Snaplink\SSOClient`, never `Snaplink\SnaplinkClient`.
- **Go** cannot be renamed independently — the import path is the repository
  path, and the SDK ships with the root module.
- **Kotlin/Maven** additionally require a domain-verified `groupId`;
  `com.snaplink` presumes control of `snaplink.com`. If that domain is not
  controlled, `com.snaplink` is not publishable and the group must change first.

`python cli.py sdk-naming check` holds this scheme and each registry's grammar
fail-closed; `make sdk-naming-list` prints the table above from the gate itself,
so a rename cannot drift in one manifest only.

## Packages

| Language | Distribution | Release source | Current automation/status |
|---|---|---|---|
| Go | Go Modules, root module `github.com/yangwb1123/snaplink` | Root `vX.Y.Z` tag | Released with the server module; versions are coupled by the root module layout |
| TypeScript | npm, `@snaplink/sso-client` | `sdk-ts-v<package-version>` | `.github/workflows/sdk-typescript.yml` tests, checks the tag, and publishes with provenance |
| Python | PyPI, `snaplink-sso-client` | `sdk-py-v<package-version>` | `.github/workflows/sdk-python.yml` tests, builds, checks the tag, and uses PyPI trusted publishing |
| Rust | crates.io, `snaplink-sso-client` | `sdk-rs-v<package-version>` | `.github/workflows/sdk-rust.yml` tests, packages, checks the tag, and publishes |
| PHP | Packagist target, `snaplink/sso-client` (not listed publicly) | `sdk-php-v<package-version>` | CI validates/builds an archive and proves an offline install; a protected subtree-split release workflow is configured but needs a target repository, Packagist registration, and protected-environment credentials |
| Kotlin | Maven Central candidate, `com.snaplink:sso-client` | Not configured | Experimental and unpublished; platform/security acceptance, Maven publishing setup, and a domain-verified `groupId` are outstanding |
| Swift | Swift Package Manager, `SnaplinkSSO` | Plain SemVer Git tag, e.g. `0.3.0` | Experimental and unpublished; root `Package.swift` targets `sdks/swift/`; no release workflow |

Package SemVer is independent across SDKs and from the server/module and
OAuth/OIDC protocol versions. `python cli.py sdk-surface versions` validates the
four published-package manifests independently; `python cli.py sdk-naming check`
holds the naming scheme; Kotlin and Swift remain outside the release gate and the
five-language full-SDK paradigm gate until approved. No package is published yet:
every registry returns 404 for these names.

| Language | Package directory | Documentation |
|---|---|---|
| Go | [`go/`](go/) | [`go/README.md`](go/README.md) |
| Kotlin (Android, experimental) | [`kotlin/`](kotlin/) | [`kotlin/README.md`](kotlin/README.md) |
| PHP | [`php/`](php/) | [`php/README.md`](php/README.md) |
| Python | [`python/`](python/) | [`python/README.md`](python/README.md), [`docs/sdks/python/README.md`](../docs/sdks/python/README.md) |
| Rust | [`rust/`](rust/) | [`rust/README.md`](rust/README.md) |
| Swift (iOS/macOS, experimental) | [`swift/`](swift/) | [`swift/README.md`](swift/README.md), [`docs/sdks/native.md`](../docs/sdks/native.md) |
| TypeScript | [`typescript/`](typescript/) | [`docs/sdks/typescript/README.md`](../docs/sdks/typescript/README.md) |

The Kotlin and Swift packages are experimental native hosted-login clients;
they are not published or production-approved and do not replace generated
business API clients. The full OpenAPI-generated REST clients are TypeScript
and Python. See [`docs/sdks/native.md`](../docs/sdks/native.md).

The embeddable Go server API is the separate `interfaces/sso` package; it stays
in the layered server library rather than moving under this client-package tree.

The generated TypeScript API client lives at `typescript/client.ts`. The Go
code generator also emits the Python API client at
`../docs/sdks/python/client.py` and the installable Python package module under
`python/snaplink_sso/`:

```sh
go run ./cmd/gensdk --lang=all
```
