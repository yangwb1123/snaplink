package sqlite

// TenantMembershipsMaxVersion returns the highest migration version declared
// for the tenant_memberships store (B2B org membership). Like the other
// ensureSchema-backed stores it has exactly one migration (v1) — the baseline
// CREATE TABLE block — so this is 1. cmd compares it against the live DB at
// boot via migrate.CheckSchema (see maxversions.go for the rationale).
func TenantMembershipsMaxVersion() int { return 1 }
