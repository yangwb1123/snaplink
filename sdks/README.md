# SDK packages

Language SDK code is grouped by language; independent package manifests live
beside their package where the language uses them:

## Package naming

Every published package is the same logical name, `snaplink` + `sso`, rendered
with the naming rule of its own registry. The brand token owns the platform's
namespace slot; the product token fills the name slot:

| Platform | Package name | Rendering rule | Import identifier |
|---|---|---|---|
| npm | `@snaplink/sso` | lowercase `@scope/name` | `@snaplink/sso` |
| PyPI | `snaplink-sso` | PEP 503 normalized flat name | `snaplink_sso` |
| crates.io | `snaplink-sso` | lowercase, single dash | `snaplink_sso` |
| Packagist | `snaplink/sso` | lowercase `vendor/package` | `Snaplink\…` |
| Maven | `site.ywbsd.sso:snaplink` | reverse-DNS `groupId:artifactId`, group is a controlled domain | `com.snaplink.sso` |
| SwiftPM | `SnaplinkSSO` | PascalCase module | `SnaplinkSSO` |
| Go | root Go module `github.com/yangwb1123/snaplink` | import path is the repository path | `snaplink` |

The product token is the product itself, not the role the artifact plays. On
every registry that carries this SDK a published library *is* a client, so a
`client` suffix would be noise, and the server side is the Go module rather than
anything published to these registries. The same name therefore appears on the
server binary (`sso-server`), the deploy namespace, the Swift module, and every
package.

Notes on the deliberate exceptions:

- **Python** installs as `snaplink-sso` and imports as `snaplink_sso`; the
  underscore form is Python's convention for the same name.
- **Swift** carries brand and product in one PascalCase module name. It drops no
  token, and it does not stutter against the `SnaplinkAuthClient` type inside it.
- **PHP** classes are de-stuttered for the same reason: the client is
  `Snaplink\SSOClient`, never `Snaplink\SnaplinkClient`.
- **Go** cannot be renamed independently — the import path is the repository
  path, and the SDK ships with the root module.
- **Maven is the one platform where the namespace slot cannot hold the brand.**
  Central verifies a `groupId` against a domain the publisher controls, so the
  group is the reverse-DNS form of the product host `sso.ywbsd.site` and the
  brand moves into the artifactId: `site.ywbsd.sso:snaplink`. `com.snaplink`
  would assert a `snaplink.com` this project does not control, and an
  unverifiable `groupId` is rejected at publication. Before the first Android
  release, the domain must serve Central's verification token (or publish the
  matching `token` TXT record); the host must keep resolving and serving
  `https://sso.ywbsd.site/`. The Android code package stays
  `com.snaplink.sso` — a namespace is a code package, not an artifact name, and
  it is not domain-verified.

`python cli.py sdk-naming check` holds this scheme and each registry's grammar
fail-closed; `make sdk-naming-list` prints the table above from the gate itself,
so a rename cannot drift in one manifest only.

## Packages

| Language | Distribution | Release source | Current automation/status |
|---|---|---|---|
| Go | Go Modules, root module `github.com/yangwb1123/snaplink` | Root `vX.Y.Z` tag | Released with the server module; versions are coupled by the root module layout |
| TypeScript | npm, `@snaplink/sso` | `sdk-ts-v<package-version>` | `.github/workflows/sdk-typescript.yml` tests, checks the tag, and publishes with provenance |
| Python | PyPI, `snaplink-sso` | `sdk-py-v<package-version>` | `.github/workflows/sdk-python.yml` tests, builds, checks the tag, and uses PyPI trusted publishing |
| Rust | crates.io, `snaplink-sso` | `sdk-rs-v<package-version>` | `.github/workflows/sdk-rust.yml` tests, packages, checks the tag, and publishes |
| PHP | Packagist target, `snaplink/sso` (not listed publicly) | `sdk-php-v<package-version>` | CI validates/builds an archive and proves an offline install; a protected subtree-split release workflow is configured but needs a target repository, Packagist registration, and protected-environment credentials |
| Kotlin | Maven Central candidate, `site.ywbsd.sso:snaplink` | Not configured | Experimental and unpublished; platform/security acceptance and Maven publishing setup are outstanding, and the `groupId` still needs Central's domain token |
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
