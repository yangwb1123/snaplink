package permissions

import "strings"

// Wildcard tokens used in permission codes.
const (
	WildcardAll    = "*"
	WildcardSuffix = ":*"
)

// Matches reports whether want is granted by the given permission set.
// Match rules:
//
//	exact:    "user:read"  matches "user:read"
//	domain:*: "user:*"     matches "user:read", "user:create"
//	all:      "*"          matches anything
func Matches(have []Permission, want string) bool {
	if want == "" {
		return true
	}
	for _, p := range have {
		if p.Code == WildcardAll || p.Code == want {
			return true
		}
		if domain, ok := strings.CutSuffix(p.Code, WildcardSuffix); ok {
			if strings.HasPrefix(want, domain+":") {
				return true
			}
		}
	}
	return false
}

// PermissionSet returns a deduplicated set of codes from the given permissions.
func PermissionSet(perms []Permission) map[string]struct{} {
	out := make(map[string]struct{}, len(perms))
	for _, p := range perms {
		out[p.Code] = struct{}{}
	}
	return out
}

// PermissionsFromRoles projects a role definition slice onto its deduplicated
// permission union. Authorization adapters use it for session-active roles so
// the active and assigned decision paths share one projection rule.
func PermissionsFromRoles(roles []Role) []Permission {
	seen := make(map[string]struct{})
	for _, role := range roles {
		for _, code := range role.Permissions {
			seen[code] = struct{}{}
		}
	}
	out := make([]Permission, 0, len(seen))
	for code := range seen {
		out = append(out, Permission{Code: code})
	}
	return out
}
