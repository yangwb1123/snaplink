package resourcecatalog

import (
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

// Matches is the existing durable peer's type-specific predicate, without SQL.
func Matches(r *permissions.Resource, have map[string]string) bool {
	want := r.Attributes
	switch r.Type {
	case permissions.ResourceTypeHTTPAPI:
		return strings.EqualFold(want["method"], have["method"]) && matchPath(want["path"], have["path"])
	case permissions.ResourceTypeGRPCAPI:
		return want["service"] == have["service"] && want["method"] == have["method"]
	case permissions.ResourceTypeGraphQLAPI:
		return want["op"] == have["op"] && want["field"] == have["field"]
	case permissions.ResourceTypePage:
		return want["route"] == have["route"]
	case permissions.ResourceTypeJSFn:
		return want["route"] == have["route"] && want["symbol"] == have["symbol"]
	case permissions.ResourceTypeUIElement:
		return want["selector"] == have["selector"] && (want["page_id"] == "" || have["page_id"] == "" || want["page_id"] == have["page_id"])
	default:
		return matchCustom(want, have)
	}
}

func matchCustom(want, have map[string]string) bool {
	for key, value := range want {
		if have[key] != value {
			return false
		}
	}
	return true
}

func matchPath(pattern, actual string) bool {
	patterns := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	parts := strings.Split(strings.TrimPrefix(actual, "/"), "/")
	if len(patterns) != len(parts) {
		return false
	}
	for i, part := range patterns {
		if !strings.HasPrefix(part, ":") && part != parts[i] {
			return false
		}
	}
	return true
}
