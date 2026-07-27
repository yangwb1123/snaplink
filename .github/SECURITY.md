# Security Policy

> **Security architecture reference:** [`docs/SECURITY.md`](../docs/SECURITY.md) — hardened
> areas, fail-open/closed decision matrix, developer checklist, and operator
> hardening guide. This file is the policy entry point; the architecture
> reference lives alongside the code it documents.

## Supported Versions

`snaplink/sso` is pre-1.0 and currently has no tagged supported release.
Security fixes land on `main`. Deployments built from another commit must move
to a fixed commit explicitly; there is no maintained release branch yet.

Once 1.0 ships, support will follow SemVer: latest minor + previous
minor receive security fixes; older minors are end-of-life.

## Reporting a Vulnerability

**Do not open a public issue for security bugs.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred — no email needed) —
   click *Security → Report a vulnerability* on the repository page.
   The maintainers receive a private advisory, can collaborate on a
   fix in a private fork, and coordinate the CVE + disclosure date.

2. **Email** — no project security mailbox is currently published. Do not send
   a report to an address found only in old documentation; use GitHub Security
   Advisories until a verified contact is listed here.

Include in the report:

- Affected component (`domains/authenticators`, `platform/bootstrap`,
  `interfaces/grpcserver`, etc.) and version / commit SHA.
- A minimal reproducer or proof-of-concept.
- Impact assessment (auth bypass, privilege escalation, DoS, info
  disclosure, etc.) and whether you've observed exploitation in the
  wild.
- Your preferred attribution (name + handle / employer / "anonymous")
  for the CVE credit.

## Response SLA

- **Acknowledgement**: within 3 business days.
- **Triage + severity assessment** (CVSS v3.1): within 7 business days
  of acknowledgement.
- **Fix + private patch**: target 30 days for High / Critical, 90 days
  for Medium / Low. Complex fixes may extend this with your agreement.
- **Public disclosure**: coordinated with you; default is 90 days from
  the report or upon fix release, whichever comes first.

## Scope

In scope:

- `cmd/sso-server`, the public SDK under `interfaces/sso`, and every package in
  the root Go module
- Default implementations under `infrastructure/defaultimpl` and stock
  implementations under `domains/*`, `platform/*`, and `protocols/*`
- Nested modules under `infrastructure/` and `cmd/` when the report concerns
  code maintained in this repository
- Wire format of HTTP REST endpoints and gRPC services
- Deployment assets under `ops/deploy/`

Out of scope:

- Third-party operator-provided backends (your SQL store, your KMS,
  your reverse proxy)
- Separately deployed login, administration, self-service, developer, and setup
  frontends; this repository contains the API backend only
- Misconfiguration that is loudly warned about in code (e.g., running
  the `interfaces/ssoclient/dev` stubs in production — the package emits a
  startup banner)
- Demo / example apps under `docs/examples/` that explicitly carry seed
  credentials
