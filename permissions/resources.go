package permissions

import (
	"context"
	"errors"
	"time"
)

// ResourceType discriminates the kind of registered resource. The
// constants below are the first-party set; backends may accept
// custom types as long as the matching logic agrees on the
// Attribute keys to compare.
type ResourceType string

const (
	// Frontend resources
	ResourceTypePage      ResourceType = "page"        // a routed page (gate render)
	ResourceTypeUIElement ResourceType = "ui_element"  // a button / column / field / section inside a page

	// Backend resources
	ResourceTypeHTTPAPI    ResourceType = "http_api"
	ResourceTypeGRPCAPI    ResourceType = "grpc_api"
	ResourceTypeGraphQLAPI ResourceType = "graphql_api"

	// Other
	ResourceTypeJSFn ResourceType = "js_fn" // a JS function on a page (event handler, etc.)
)

// RequireMode declares how RequiredPermissions are combined.
//
//   - RequireAny (default): the user needs at least one of the
//     listed permissions. Suitable for read-most endpoints where
//     several roles can satisfy the gate.
//   - RequireAll: the user needs every listed permission. Suitable
//     for sensitive write operations that demand a composite
//     authority (e.g. "billing:write" AND "audit:read").
type RequireMode string

const (
	RequireAny RequireMode = "any"
	RequireAll RequireMode = "all"
)

// Resource is one registered resource entry in the catalog. The
// (TenantID, ClientID, Type, Name) tuple is intended to be unique
// — backends MAY enforce this, the in-memory implementation does.
//
// Attributes carries type-specific match keys:
//
//	http_api:    { "method": "POST", "path": "/api/v1/users/:id" }
//	grpc_api:    { "service": "snaplink.user.v1.UserService", "method": "Delete" }
//	graphql_api: { "op": "mutation", "field": "deleteUser" }
//	page:        { "route": "/admin/users" }
//	js_fn:       { "route": "/admin/users", "symbol": "deleteUserBtn.onClick" }
//	ui_element:  { "page_id": "<page resource id>", "selector": "#userTable .delete-btn",
//	               "element_kind": "button", "behavior": "hide" }
//
// Attribute keys are documented as part of each ResourceType's
// contract; the matching code in ResolveResource expects them
// exactly as listed above.
type Resource struct {
	ID                  string            `json:"id"`
	TenantID            string            `json:"tenant_id,omitempty"`
	ClientID            string            `json:"client_id,omitempty"`
	Type                ResourceType      `json:"type"`
	Name                string            `json:"name"`
	RequiresAuth        bool              `json:"requires_auth"`
	Description         string            `json:"description,omitempty"`
	Attributes          map[string]string `json:"attributes,omitempty"`
	RequiredPermissions []string          `json:"required_permissions,omitempty"`
	RequireMode         RequireMode       `json:"require_mode,omitempty"`
	CreatedAt           time.Time         `json:"created_at,omitzero"`
	UpdatedAt           time.Time         `json:"updated_at,omitzero"`
}

// ResourceLookup is the runtime query the request middleware uses
// to find the Resource gating an inbound call. Callers fill
// TenantID + ClientID (often pulled from the request's resolved
// tenant) and the Type-specific Match keys.
//
// Empty TenantID means "match resources whose TenantID is also
// empty" (the no-tenant bucket — single-tenant deployments and
// platform resources). Empty ClientID matches the no-client
// bucket the same way.
type ResourceLookup struct {
	TenantID string
	ClientID string
	Type     ResourceType
	Match    map[string]string
}

// ResourceDecision is the answer ResolveResource returns. Found
// reports whether the catalog had a matching entry; the rest of
// the fields project the matched Resource's access policy.
//
// Found=false is NOT an error — handlers decide the default
// (most deployments treat "no entry = public"; high-security
// deployments may treat it as "deny by default"). The middleware
// surfaces the missing-entry case so handlers can pick.
type ResourceDecision struct {
	Found               bool
	ResourceID          string
	RequiresAuth        bool
	RequiredPermissions []string
	RequireMode         RequireMode
}

// ResourceProvider is an optional extension Provider implementations
// MAY satisfy to expose the resource catalog. Mirrors the
// MenuLister pattern: callers type-assert before using, so adding
// resource support to a backend doesn't break the base Provider
// contract.
//
// All operations are tenant- and client-scoped: writes specify the
// scope on the Resource itself; reads filter by (TenantID, ClientID)
// pairs. The hot path is ResolveResource — implementations should
// keep that lookup O(1) per Type when possible (e.g. method+path
// trie for HTTP, plain map for the rest).
type ResourceProvider interface {
	// RegisterResource inserts or updates a Resource. ErrResourceExists
	// is returned when the (TenantID, ClientID, Type, Name) tuple is
	// already taken by a different ID (i.e. a real conflict, not
	// just an idempotent re-register of the same row).
	RegisterResource(ctx context.Context, r *Resource) error

	// GetResource returns the Resource by its ID. ErrResourceNotFound
	// when missing.
	GetResource(ctx context.Context, id string) (*Resource, error)

	// ListResources returns every Resource matching the
	// (TenantID, ClientID) pair. Empty values match the no-tenant /
	// no-client buckets respectively.
	ListResources(ctx context.Context, tenantID, clientID string) ([]*Resource, error)

	// DeleteResource removes a Resource by ID. Idempotent —
	// missing IDs return nil so reconciliation loops don't churn.
	DeleteResource(ctx context.Context, id string) error

	// ResolveResource is the runtime hot path: find the Resource
	// matching lookup and project its access policy.
	// Decision.Found=false (not an error) when no Resource matches.
	ResolveResource(ctx context.Context, lookup ResourceLookup) (*ResourceDecision, error)
}

// Sentinel errors. Admin RPCs map these to gRPC codes.
var (
	ErrResourceNotFound = errors.New("permissions: resource not found")
	ErrResourceExists   = errors.New("permissions: resource already exists")
	ErrInvalidResource  = errors.New("permissions: invalid resource")
)

// Validate sanity-checks a Resource before persistence. ID + Type
// + Name are always required; type-specific Attribute checks run
// on top so backends don't need to duplicate the logic.
func (r *Resource) Validate() error {
	if r.ID == "" {
		return errors.Join(ErrInvalidResource, errors.New("id required"))
	}
	if r.Type == "" {
		return errors.Join(ErrInvalidResource, errors.New("type required"))
	}
	if r.Name == "" {
		return errors.Join(ErrInvalidResource, errors.New("name required"))
	}
	if r.RequireMode != "" && r.RequireMode != RequireAny && r.RequireMode != RequireAll {
		return errors.Join(ErrInvalidResource, errors.New("require_mode must be any|all"))
	}
	switch r.Type {
	case ResourceTypeHTTPAPI:
		if r.Attributes["method"] == "" || r.Attributes["path"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("http_api requires method+path attributes"))
		}
	case ResourceTypeGRPCAPI:
		if r.Attributes["service"] == "" || r.Attributes["method"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("grpc_api requires service+method attributes"))
		}
	case ResourceTypeGraphQLAPI:
		if r.Attributes["op"] == "" || r.Attributes["field"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("graphql_api requires op+field attributes"))
		}
	case ResourceTypePage:
		if r.Attributes["route"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("page requires route attribute"))
		}
	case ResourceTypeJSFn:
		if r.Attributes["route"] == "" || r.Attributes["symbol"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("js_fn requires route+symbol attributes"))
		}
	case ResourceTypeUIElement:
		if r.Attributes["selector"] == "" {
			return errors.Join(ErrInvalidResource, errors.New("ui_element requires selector attribute"))
		}
	}
	return nil
}

// EffectiveRequireMode returns RequireAny when the Resource's
// RequireMode is empty (the documented default), otherwise the
// declared mode. Centralised so backends + the matcher don't
// disagree.
func (r *Resource) EffectiveRequireMode() RequireMode {
	if r.RequireMode == "" {
		return RequireAny
	}
	return r.RequireMode
}
