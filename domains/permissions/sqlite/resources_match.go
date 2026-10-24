package sqlite

import (
	"github.com/yangwb1123/snaplink/domains/permissions"
	"github.com/yangwb1123/snaplink/domains/permissions/resourcecatalog"
)

type resourceDispatchInfo struct {
	key      string
	method   string
	segments int
}

func resourceDispatch(t permissions.ResourceType, attrs map[string]string) resourceDispatchInfo {
	d := resourcecatalog.DispatchFor(t, attrs)
	return resourceDispatchInfo{key: d.Key, method: d.Method, segments: d.Segments}
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
	return resourcecatalog.Matches(r, have)
}

func resourceDecision(r *permissions.Resource) *permissions.ResourceDecision {
	return resourcecatalog.Decision(r)
}
