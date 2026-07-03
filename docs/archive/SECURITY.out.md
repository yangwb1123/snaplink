I see you've shared the `docs/SECURITY.md` content (confirmed it exists at that path). I notice there's also a `.github/SECURITY.md` file with different content. Here's a comparison:

### Key differences between the two files

| Aspect | `.github/SECURITY.md` | `docs/SECURITY.md` |
|---|---|---|
| **Reporting method** | GitHub Security Advisories (preferred) + email fallback | Email only |
| **Supported Versions** | Pre-1.0 / SemVer plan documented | Not mentioned |
| **Response SLA** | 3 business day ack, 7 biz day triage | 24h ack, 7 day triage *(more aggressive)* |
| **Scope / Out-of-scope** | Explicitly defined | Not mentioned |
| **Operator checklist** | 8-item hardening checklist | Not present |
| **CVSS mention** | CVSS v3.1 | None |
| **CVE coordination** | Coordinated disclosure timeline | Not mentioned |

### Observations

- `.github/SECURITY.md` (on `main`) is the canonical security policy — GitHub surfaces it as the repo's security policy, so it should remain authoritative.
- `docs/SECURITY.md` overlaps content but omits several important sections (supported versions, scope, operator checklist).
- The `docs/` version's "24 hours" SLA is tighter than `.github/`'s "3 business days" — a discrepancy that could confuse reporters.
- The `docs/` version mentions a PGP key at `snaplink.dev/.well-known/pgp-key.txt` — this isn't referenced in `.github/`.

**Do you want me to:**
1. Update `docs/SECURITY.md` to mirror the more comprehensive `.github/SECURITY.md`?
2. Consolidate both to a single authoritative version (removing the `docs/` copy or making it a symlink/redirect)?
3. Something else?
