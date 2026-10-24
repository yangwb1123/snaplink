// Package resourcecatalog shares the durable resource dispatch/matching contract.
package resourcecatalog

import (
	"fmt"
	"strings"

	"github.com/yangwb1123/snaplink/domains/permissions"
)

type Dispatch struct {
	Key      string
	Method   string
	Segments int
}

// DispatchFor preserves the SQLite tuple's literal NUL separator. PostgreSQL
// adapters store Key as BYTEA; changing its encoding would change lookup identity.
func DispatchFor(t permissions.ResourceType, attrs map[string]string) Dispatch {
	switch t {
	case permissions.ResourceTypeHTTPAPI:
		return Dispatch{Method: strings.ToUpper(attrs["method"]), Segments: len(strings.Split(strings.TrimPrefix(attrs["path"], "/"), "/"))}
	case permissions.ResourceTypeGRPCAPI:
		return Dispatch{Key: pairKey(attrs["service"], attrs["method"])}
	case permissions.ResourceTypeGraphQLAPI:
		return Dispatch{Key: pairKey(attrs["op"], attrs["field"])}
	case permissions.ResourceTypePage:
		return Dispatch{Key: attrs["route"]}
	case permissions.ResourceTypeJSFn:
		return Dispatch{Key: pairKey(attrs["route"], attrs["symbol"])}
	case permissions.ResourceTypeUIElement:
		return Dispatch{Key: attrs["selector"]}
	default:
		return Dispatch{}
	}
}

func pairKey(first, second string) string { return fmt.Sprintf("%s\x00%s", first, second) }

func Decision(r *permissions.Resource) *permissions.ResourceDecision {
	return &permissions.ResourceDecision{Found: true, ResourceID: r.ID, RequiresAuth: r.RequiresAuth,
		RequiredPermissions: append([]string(nil), r.RequiredPermissions...), RequireMode: r.EffectiveRequireMode()}
}
