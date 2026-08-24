package sqlite

import (
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

type resourceDispatchInfo struct {
	key      string
	method   string
	segments int
}

func resourceDispatch(t permissions.ResourceType, attrs map[string]string) resourceDispatchInfo {
	switch t {
	case permissions.ResourceTypeHTTPAPI:
		path := attrs["path"]
		return resourceDispatchInfo{
			method:   strings.ToUpper(attrs["method"]),
			segments: pathSegmentCount(path),
		}
	case permissions.ResourceTypeGRPCAPI:
		return resourceDispatchInfo{key: pairKey(attrs["service"], attrs["method"])}
	case permissions.ResourceTypeGraphQLAPI:
		return resourceDispatchInfo{key: pairKey(attrs["op"], attrs["field"])}
	case permissions.ResourceTypePage:
		return resourceDispatchInfo{key: attrs["route"]}
	case permissions.ResourceTypeJSFn:
		return resourceDispatchInfo{key: pairKey(attrs["route"], attrs["symbol"])}
	case permissions.ResourceTypeUIElement:
		return resourceDispatchInfo{key: attrs["selector"]}
	default:
		return resourceDispatchInfo{}
	}
}

func resourceResolveQuery(lookup permissions.ResourceLookup) (string, []any) {
	query := `SELECT ` + resourceColumns + `
        FROM permissions_resources
        WHERE tenant_id = ? AND client_id = ? AND type = ?`
	args := []any{lookup.TenantID, lookup.ClientID, string(lookup.Type)}
	dispatch := resourceDispatch(lookup.Type, lookup.Match)
	switch lookup.Type {
	case permissions.ResourceTypeHTTPAPI:
		query += ` AND dispatch_method = ? AND dispatch_segments = ?`
		args = append(args, dispatch.method, dispatch.segments)
	case permissions.ResourceTypeGRPCAPI, permissions.ResourceTypeGraphQLAPI,
		permissions.ResourceTypePage, permissions.ResourceTypeJSFn:
		query += ` AND dispatch_key = ?`
		args = append(args, dispatch.key)
	case permissions.ResourceTypeUIElement:
		query += ` AND dispatch_key = ?`
		args = append(args, lookup.Match["selector"])
	}
	return query + ` ORDER BY id`, args
}

func resourceMatches(r *permissions.Resource, have map[string]string) bool {
	switch r.Type {
	case permissions.ResourceTypeHTTPAPI:
		return matchHTTPResource(r.Attributes, have)
	case permissions.ResourceTypeGRPCAPI:
		return matchGRPCResource(r.Attributes, have)
	case permissions.ResourceTypeGraphQLAPI:
		return matchGraphQLResource(r.Attributes, have)
	case permissions.ResourceTypePage:
		return r.Attributes["route"] == have["route"]
	case permissions.ResourceTypeJSFn:
		return matchJSFnResource(r.Attributes, have)
	case permissions.ResourceTypeUIElement:
		return matchUIElementResource(r.Attributes, have)
	default:
		return matchCustomResource(r.Attributes, have)
	}
}

func matchHTTPResource(want, have map[string]string) bool {
	return strings.EqualFold(want["method"], have["method"]) &&
		matchResourcePath(want["path"], have["path"])
}

func matchGRPCResource(want, have map[string]string) bool {
	return want["service"] == have["service"] && want["method"] == have["method"]
}

func matchGraphQLResource(want, have map[string]string) bool {
	return want["op"] == have["op"] && want["field"] == have["field"]
}

func matchJSFnResource(want, have map[string]string) bool {
	return want["route"] == have["route"] && want["symbol"] == have["symbol"]
}

func matchUIElementResource(want, have map[string]string) bool {
	if want["selector"] != have["selector"] {
		return false
	}
	return want["page_id"] == "" || have["page_id"] == "" || want["page_id"] == have["page_id"]
}

func matchCustomResource(want, have map[string]string) bool {
	for key, value := range want {
		if have[key] != value {
			return false
		}
	}
	return true
}

func matchResourcePath(pattern, actual string) bool {
	patternParts := strings.Split(strings.TrimPrefix(pattern, "/"), "/")
	actualParts := strings.Split(strings.TrimPrefix(actual, "/"), "/")
	if len(patternParts) != len(actualParts) {
		return false
	}
	for i, part := range patternParts {
		if strings.HasPrefix(part, ":") {
			continue
		}
		if part != actualParts[i] {
			return false
		}
	}
	return true
}

func pathSegmentCount(path string) int {
	return len(strings.Split(strings.TrimPrefix(path, "/"), "/"))
}

func pairKey(first, second string) string {
	return fmt.Sprintf("%s\x00%s", first, second)
}

func resourceDecision(r *permissions.Resource) *permissions.ResourceDecision {
	return &permissions.ResourceDecision{
		Found:               true,
		ResourceID:          r.ID,
		RequiresAuth:        r.RequiresAuth,
		RequiredPermissions: append([]string(nil), r.RequiredPermissions...),
		RequireMode:         r.EffectiveRequireMode(),
	}
}
