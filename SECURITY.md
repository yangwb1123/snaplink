# Security Policy

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

## Security Hardening Checklist (Operator-Side)

When deploying `snaplink/sso`:

- [ ] Disable `ssoclient/dev` usage outside of dev environments.
- [ ] Set `--config` to a file that is **not** world-readable; the
      file holds client secrets and (potentially) bootstrap admin
      credentials.
- [ ] Use the `passphrase` snapshot encryption backend in production;
      `none` is for tests only.
- [ ] Front the HTTP listener with TLS (either via OpenResty / Envoy
      or `--tls-cert` + `--tls-key`).
- [ ] Set `bootstrap.lock` to `file` or `etcd` (never `noop`) when
      running multiple replicas.
- [ ] Rotate the JWT signing key (Ed25519) at the cadence your
      compliance posture requires; the JWKS cache supports multiple
      active `kid`s for rolling rotation.
- [ ] Audit log shipping — wire the `audit.WebhookSink` or a custom
      `audit.Sink` to a tamper-evident store rather than relying on
      the in-process `MemorySink`.
- [ ] Keep the wall clock forward/monotonic — slew, never step, it on
      running nodes (use chrony, not periodic `ntpdate`/`hwclock` steps).
      Session + refresh-token expiry compare `expires_at > now` exactly
      (no skew slack, by design); a backward clock step (NTP step, VM
      snapshot rollback) can transiently resurrect a just-expired session
      or token. DPoP/JWT iat-window skew is configurable instead.
