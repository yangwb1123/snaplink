# Release Process

The project follows Semantic Versioning. It is currently pre-1.0, so every
release must state any public Go/API/config/storage behavior that changed.
There is no guaranteed calendar cadence.

## Distributed artifacts

GoReleaser currently defines:

- `sso-server`
- `sso-ctl`
- the separately-moduled `sso-mcp`
- `sso-server` and `sso-mcp` container images
- SHA-256 checksums
- one SPDX-JSON SBOM per archive
- keyless Cosign signatures for archives and container images

The normal `python cli.py build` engineering gate builds only `sso-server` and
`sso-ctl`; `make release-snapshot` is the check for the complete GoReleaser
matrix.

Local `standard` and `standard-kafka` profile builds produce a module lock and
embedded inventory, but GoReleaser does not yet publish per-profile artifacts
or binary-level profile SBOMs. Do not describe local profile builds as an
official release matrix; follow [plugin-system.md](plugin-system.md).

The release pipeline does not currently produce a SLSA provenance statement.
Do not describe signatures/SBOMs as provenance.

## 1. Prepare

Create a release branch without rewriting public history:

```bash
git checkout -b release/vX.Y.Z
```

Move entries from `Unreleased` into a dated section in
[CHANGELOG.md](../CHANGELOG.md). Include breaking API/config/storage changes,
security fixes and operator migration steps.

Reconcile the documentation in the same change:

- new/changed endpoints → `docs/openapi.yaml`
- new/changed config → `docs/config-reference.md`
- new wire errors → `docs/error-codes.md`
- changed capability/limitation → `docs/feature-matrix.md` and
  `docs/deferred-backlog.md`

## 2. Validate

Run the authoritative committed gates:

```bash
make ci
go test -run 'TestMaintainability_|TestArchitecture_' .
```

Then run the relevant supplementary diagnostics and documentation/backend
checks:

```bash
python cli.py harness
python cli.py check-invariants
python cli.py check-exemptions
make docs-validate
make docs-check
make backend-semantics
```

The committed root gate tests run by `make ci` are the merge authority.
The Python harness and exemption checker are supplementary: they can expose
checker/configuration drift (the current exemption checker reports stale
required entries), so they must not be used as the sole release proof or to
override a root-gate failure. Resolve and record any disagreement.

Run the applicable release-only suites explicitly; they are not included in
default `make ci`:

```bash
make chaos-test
make dr-drill
make release-snapshot
```

Also inspect the report-only security jobs (for example Trivy and any
non-failing scanner invocation). A green workflow can mean “scan completed,”
not “zero findings.”

For an advertised FIPS artifact, additionally build/test with the exact pinned
`GOFIPS140` selector and retain the Go/module/certificate evidence described in
[fips.md](fips.md). For an advertised OIDC/FAPI certification, retain the
official conformance result described in
[sso/oidc-conformance.md](sso/oidc-conformance.md).

## 3. Tag and publish

After validation and review:

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag triggers `.github/workflows/release.yml`, which runs GoReleaser,
creates the GitHub release and publishes configured images/assets. Never bypass
hooks or an applicable repository signature policy to make a release pass.

## 4. Verify published output

- Confirm every expected OS/architecture archive exists.
- Verify `checksums.txt`, SBOMs and Cosign signatures.
- Pull each published container by immutable digest and run `version`.
- Run a smoke login/token/UserInfo flow against the released image.
- Confirm release notes link the correct migration and security guidance.
- Notify downstream SDK/frontend/module consumers of the exact compatible
  server version.

## Hotfix and security releases

Branch from the affected release tag, apply the smallest safe fix, run the same
validation appropriate to the change, add a changelog security entry and issue
a new SemVer tag. Security reporting, coordination and disclosure timelines are
defined only in [`.github/SECURITY.md`](../.github/SECURITY.md); this document
does not duplicate or override them.
