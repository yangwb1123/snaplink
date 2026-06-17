# Skill: Architecture Fix

**Trigger:** Import cycle or dependency direction violation.

**Usage:** `python skills/architecture-fix/run.py`

## Fix patterns

| Violation | Fix |
|---|---|
| oauth/ imports oidc/ | Move shared type to core/, route via handlers.go |
| oidc/ imports oauth/ | Move shared type to core/, route via handlers.go |
| security/ imports defaultimpl/ | Extract SPI to security/, pass via With* |
| oidc/ imports defaultimpl/ | Extract SPI to oidc/, pass via With* |

## Verify
bash .check-architecture.sh && make acceptance
