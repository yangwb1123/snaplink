package tokenpolicy

import (
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/shared/core"
)

// Validate rejects selector shapes that would silently change meaning in
// [matches]: a bare or interior "*" wildcard (the ONLY spelling of "any" is
// the empty field), a wildcarded or whitespace-padded tenant_id (spellings
// that can never match a real tenant, silently), and roles outside the
// closed core.TenantRole set. Load-time fail-loud only — the evaluator is
// never called with an invalid set. Programmatic memory.New seeds (trusted
// operator code) are deliberately not re-checked.
//
// Deliberately NOT gated: scopes / block_scope_combos keep their existing
// semantics (a bare "*" scope is today's shipped match-all — legacy bundles
// must keep loading), and the roles x max_refresh_depth combination is
// accepted (roles legitimately pair with max_active_sessions at the session
// seam; the refresh-seam inertness is a documented limitation, not a shape
// error).
func Validate(policies []Policy) error {
	for i := range policies {
		p := &policies[i]
		if err := validateWildcard("client_id", p.ClientID); err != nil {
			return fmt.Errorf("policy %d (%s): %w", i, p.Name, err)
		}
		if err := validateWildcard("subject", p.Subject); err != nil {
			return fmt.Errorf("policy %d (%s): %w", i, p.Name, err)
		}
		if err := validateTenantID(p.TenantID); err != nil {
			return fmt.Errorf("policy %d (%s): %w", i, p.Name, err)
		}
		for _, r := range p.SubjectRoles {
			if !isTenantRole(r) {
				return fmt.Errorf("policy %d (%s): subject_roles entry %q is not in the closed set (member/admin/guest)", i, p.Name, r)
			}
		}
	}
	return nil
}

// validateWildcard enforces the selector wildcard spelling: at most one "*",
// TRAILING only, with a non-empty prefix. A bare "*" and interior or
// multiple "*" are ambiguous spellings that would silently widen (match-all)
// or never-match.
func validateWildcard(field, v string) error {
	if v == "" {
		return nil
	}
	if strings.Count(v, "*") > 1 {
		return fmt.Errorf("%s %q: at most one '*' (trailing) is allowed", field, v)
	}
	if i := strings.Index(v, "*"); i >= 0 {
		if i != len(v)-1 {
			return fmt.Errorf("%s %q: '*' must be trailing", field, v)
		}
		if v[:i] == "" {
			return fmt.Errorf("%s %q: a bare '*' wildcard is not allowed — omit the field for 'any'", field, v)
		}
	}
	return nil
}

// validateTenantID rejects spellings that can never match a real tenant:
// wildcards and whitespace (a tenant_id is an exact, opaque key — never
// wildcarded, and " ta " differs from the record-derived "ta"). Omission is
// the ONLY spelling of "global rule"; this is documented in config-reference
// because a missing key silently creates a fleet-wide rule.
func validateTenantID(v string) error {
	if v == "" {
		return nil
	}
	if strings.ContainsAny(v, "* \t\n") {
		return fmt.Errorf("tenant_id %q: must not contain '*' or whitespace", v)
	}
	return nil
}

// isTenantRole reports whether r is a member of the closed core.TenantRole
// set, referenced by constant (compile-time) so a fourth role added to
// shared/core cannot silently drift past this gate.
func isTenantRole(r string) bool {
	switch core.TenantRole(r) {
	case core.TenantRoleMember, core.TenantRoleAdmin, core.TenantRoleGuest:
		return true
	}
	return false
}
