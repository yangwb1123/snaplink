# RELEASE.md — Release Process

## Versioning

This project follows [Semantic Versioning 2.0.0](https://semver.org/).

- **Major**: Breaking changes to public API, storage format, or protocol behavior
- **Minor**: New features, new protocol support, non-breaking enhancements
- **Patch**: Bug fixes, security patches, performance improvements

## Release Cadence

- **Minor releases**: Every 2-4 weeks
- **Patch releases**: As needed (typically within 24h of a critical fix)
- **Security releases**: Immediately upon verification

## Release Process

### 1. Prepare Release Branch

```bash
git checkout -b release/vX.Y.Z
```

### 2. Update Changelog

Move items from `[Unreleased]` to the new version section in `CHANGELOG.md`:

```markdown
## [v0.13.0] - 2026-06-15

### Added
- ...

### Fixed
- ...

### Security
- ...
```

### 3. Run Full Validation

```bash
make ci           # Build + test + lint
make harness      # Engineering gates (generates scaffolding + checks)
make diagnose     # Codebase health
make coverage     # Coverage report
```

### 4. Tag and Push

```bash
git tag vX.Y.Z
git push origin vX.Y.Z
```

The tag triggers `.github/workflows/release.yml` which:
1. Builds binaries via goreleaser
2. Creates a GitHub release
3. Attaches checksums and SBOM

### 5. Post-Release

- Verify the GitHub release was created
- Update any downstream consumers (sdks, docs)
- Announce in relevant channels

## Hotfix Process

For critical bugs or security issues:

```bash
git checkout vX.Y.Z      # From the last release tag
git checkout -b hotfix/vX.Y.Z+1
# Apply fix
git commit -m "fix: ..."
make ci
make harness
git tag vX.Y.Z+1
git push origin vX.Y.Z+1
```

## Security Releases

See `docs/security-policy.md` for vulnerability reporting.
Security releases follow the same process as hotfixes but may skip the full changelog update.

## Release Criteria

A release must pass ALL of the following:

- [ ] `make ci` — builds, tests, race detector, proto lint, modules
- [ ] `make harness` — all 6 engineering gates
- [ ] `make check-invariants` — 10 security invariants
- [ ] `make diagnose` — no critical findings
- [ ] Changelog updated
- [ ] `docs/error-codes.md` covers all new error codes
- [ ] `docs/openapi.yaml` covers all new endpoints
- [ ] ADR written for any significant architecture change
