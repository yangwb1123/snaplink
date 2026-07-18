# Security Policy

> **Security architecture reference:** [`docs/SECURITY.md`](docs/SECURITY.md) — hardened
> areas, fail-open/closed decision matrix, developer checklist, and operator
> hardening guide. This file is the policy entry point; the architecture
> reference lives alongside the code it documents.

## Supported Versions

`snaplink/sso` is pre-1.0 — security fixes land on `main` and the most
recent tagged release. Operators running off-tag commits should rebase
to receive fixes.

Once 1.0 ships, support will follow SemVer: latest minor + previous
minor receive security fixes; older minors are end-of-life.

## Reporting a Vulnerability

**Do not open a public issue for security bugs.**

Use one of the following private channels:

1. **GitHub Security Advisories** (preferred — no email needed) —
   click *Security → Report a vulnerability* on the repository page.
   The maintainers receive a private advisory, can collaborate on a
   fix in a private fork, and coordinate the CVE + disclosure date.

2. **Email** — `security@snaplink.dev` (placeholder; replace with the
   real contact once the project domain + mailbox are set up).

Include in the report:

- Affected component (`authenticators/keypair`, `bootstrap/lock/etcd`,
  the gRPC `AuditWriter`, etc.) and version / commit SHA.
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

- `cmd/sso-server` runtime + every package in this module
- Default implementations in `defaultimpl/`, `authenticators/`,
  `permissions/memory`, `audit/memory_sink.go`, etc.
- Wire format of HTTP REST endpoints and gRPC services
- The bundled OpenResty configuration under `deploy/openresty/`

Out of scope:

- Third-party operator-provided backends (your SQL store, your KMS,
  your reverse proxy)
- Misconfiguration that is loudly warned about in code (e.g., running
  the `ssoclient/dev` stubs in production — the package emits a
  startup banner)
- Demo / example apps under `examples/` that explicitly carry seed
  credentials
