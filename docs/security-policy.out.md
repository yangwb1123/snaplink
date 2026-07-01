Created `docs/SECURITY.md`. Note that there are now **three** security policy files in the repo with overlapping content:

| File | Notes |
|---|---|
| `.github/SECURITY.md` | More detailed — includes supported versions, scope, operator hardening checklist |
| `docs/security-policy.md` | **Identical** to `docs/SECURITY.md` (same content) |
| `docs/SECURITY.md` | ✅ Just created |

You may want to:
- **Remove** or **redirect** `docs/security-policy.md` to avoid content drift between two docs-level files
- Optionally **port over** the useful sections from `.github/SECURITY.md` (supported versions, scope, operator checklist) if you want `docs/SECURITY.md` to be the canonical security doc

Would you like me to reconcile these — e.g., delete `docs/security-policy.md`, or merge the `.github/SECURITY.md` content into `docs/SECURITY.md`?
