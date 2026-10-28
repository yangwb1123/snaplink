# Release dependency security remediation

## Goal and boundary

Remove the HIGH dependency findings discovered by scanning the actual stock
SSO OCI artifact. This is a separately bounded security maintenance change,
not a cold-profile operation: updating required root dependency versions is
in scope here. Cold configure/build still must not mutate root module files.
No new dependency family, API, option, migration or architecture exemption.

## Evidence and ownership

Trivy 0.75.0 reported, on both executable platforms:

- `golang.org/x/crypto v0.53.0`: CVE-2026-56854; candidate fix `v0.55.0`.
- `google.golang.org/grpc v1.82.1`: CVE-2026-84304 and CVE-2026-84445;
  candidate common fix `v1.83.2`.
- A subsequent fresh database scan found `x/net v0.58.0`:
  CVE-2026-78669; candidate fix `v0.60.0`. Required transitive version
  selections are included; each rebuilt artifact must pass the current scan.

The cached Go 1.26.5 builder also had HIGH findings. Refreshing the base
produced Go 1.26.9 binaries and removed those toolchain findings. Both CI
workflows now refresh base images without disabling build caches or scans.
Package owners remain the existing crypto consumers and gRPC interfaces;
no import direction, SDK module ownership or optional-module inventory changes.

## Files and compatibility

Update `go.mod`/`go.sum` only for the identified security versions and their
necessary module-version selection. Preserve the root Go directive and module
path; do not upgrade unrelated direct dependencies. Importing nested modules
may need the same selected versions/checksums to restore readonly builds;
update those modules in their own manifests, preserving their directives,
paths and ownership. Never add a workspace or hide module edits in Docker.
No application Go changes are expected. A compile/API incompatibility requires
review before expanding this scope; do not bypass hooks or weaken thresholds.
Update the release-readiness tracker with actual results and external limits.

## Selected versions and current status

MVS selects `grpc v1.83.2`, `x/net v0.60.0`, `x/crypto v0.57.0`,
`x/sync v0.23.0`, `x/sys v0.48.0`, `x/text v0.42.0`; importing nested
modules converge in their own manifests (operator `x/term v0.46.0`). Paths,
Go directives, replacements and the independent Go SDK remain unchanged.
Static review, module hash verification, repeated security/backend races,
E2E and full real-PostgreSQL-backed `make ci` passed. Go package parallelism
was bounded at 8; no test assertion, timing threshold or scan severity changed.

Registry access recovered. All five current-version services were rebuilt
from the same Dockerfile for amd64/arm64 with fresh Go 1.26.9 bases, SBOM and
maximum provenance. All ten Trivy reports exited zero with no HIGH/CRITICAL
or secret findings; ignore-unfixed and severity thresholds were not relaxed.
The same SSO OCI passed standalone runtime and isolated default-Compose
restart/revocation checks; local index promotion preserved executable and
attestation digests. ARM64 scanning is not native execution. Protected public
publication/signing, native ARM/Mac and production acceptance remain external.
Persistent supplementary logs/review are in ignored `dist/release-readiness/`.

## Scan-to-artifact binding

Docker-daemon import can normalize config JSON and change its digest. Runtime
acceptance may use the imported image, but release scans must read the original
OCI layout, not infer identical bytes from the daemon tag. Add a narrowly scoped
archive-to-layout helper: fresh destination, regular allowed OCI paths only,
bounded tar bytes/member count and payload/metadata size, no compressed or
extended tar headers/links/duplicates/traversal, and verified blob SHA-256.
Use a private fresh destination on a trusted runner; this is not a sandbox
against another process with the same OS identity, which can also replace the
scanner/helper/archive. Select exactly one requested platform through depth-
and descriptor-budgeted indexes, rejecting repeated index references,
validate its original config's OS/architecture, and change only the extracted
layout's root descriptor list: Trivy's layout reader can ignore `--platform`.
Content-addressed blobs and the original promotion archive remain unchanged.
The native publication job scans that selected layout. Regression tests retain
HIGH/CRITICAL, exit 1, ignore-unfixed false and the original archive for promotion.
Local evidence records original manifest/config digests, scanner command/exit,
and report hashes; direct OCI report image IDs must match original config digests.

## Acceptance and verification

Apply AGENTS U1-U9 and the existing OAuth/security negative cases. Build, vet,
committed architecture/maintainability gates, repeated security races, real
PostgreSQL-backed tests, E2E and complete `make ci` must pass. Review the resolved
dependency diff independently. Rebuild the five Dockerfile targets for amd64
and arm64 with fresh bases and SPDX/SLSA attestations; inspect static ELF and
metadata, run the exact SSO AMD64 artifact, and scan both SSO platforms with
HIGH/CRITICAL blocking and no ignore-unfixed exception. Only a zero exit scan
is acceptance; native ARM, public registry/signing, business load/recovery and
certification remain separate, incomplete external evidence.
