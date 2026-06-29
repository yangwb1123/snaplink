package main

import (
	"context"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/snaplink/sso/interfaces/ssoclient"
)

// introspector validates a bearer token locally (JWKS). Satisfied by *remote.AuthClient.
type introspector interface {
	ValidateToken(ctx context.Context, token string) (*ssoclient.Subject, error)
}

// authorizer answers permission queries. Satisfied by *remote.AuthzClient.
type authorizer interface {
	Check(ctx context.Context, req *ssoclient.CheckRequest) (bool, error)
	ListPermissions(ctx context.Context, subjectID, clientID string) ([]ssoclient.Permission, error)
	ListRoles(ctx context.Context, subjectID, clientID string) ([]ssoclient.Role, error)
	GetMenus(ctx context.Context, subjectID, clientID string) (ssoclient.MenuTree, error)
}

type toolDeps struct {
	intro introspector
	authz authorizer
}

func registerTools(s *mcp.Server, d *toolDeps) {
	mcp.AddTool(s, &mcp.Tool{Name: "introspect_token", Description: "Validate an access token and return its claims."}, d.introspectToken)
	mcp.AddTool(s, &mcp.Tool{Name: "check_permission", Description: "Check whether a subject has a permission in a client context."}, d.checkPermission)
	mcp.AddTool(s, &mcp.Tool{Name: "list_permissions", Description: "List a subject's effective permissions in a client context."}, d.listPermissions)
	mcp.AddTool(s, &mcp.Tool{Name: "list_roles", Description: "List a subject's roles in a client context."}, d.listRoles)
	mcp.AddTool(s, &mcp.Tool{Name: "get_menus", Description: "Get the subject's permitted menu tree in a client context."}, d.getMenus)
}

// --- introspect_token ---

type introspectIn struct {
	Token string `json:"token" jsonschema:"the access token to validate"`
}
type introspectOut struct {
	Active    bool     `json:"active" jsonschema:"whether the token is valid and unexpired"`
	Subject   string   `json:"subject,omitempty" jsonschema:"the sub claim"`
	Scopes    []string `json:"scopes,omitempty" jsonschema:"granted OAuth scopes"`
	Audience  []string `json:"audience,omitempty" jsonschema:"the aud claim"`
	ExpiresAt int64    `json:"expires_at,omitempty" jsonschema:"expiry, unix seconds"`
	Tenant    string   `json:"tenant,omitempty" jsonschema:"tenant id if present"`
}

func (d *toolDeps) introspectToken(ctx context.Context, _ *mcp.CallToolRequest, in introspectIn) (*mcp.CallToolResult, introspectOut, error) {
	subj, err := d.intro.ValidateToken(ctx, in.Token)
	if err != nil {
		return nil, introspectOut{Active: false}, nil
	}
	return nil, introspectOut{
		Active:    true,
		Subject:   subj.ID,
		Scopes:    subj.Scopes,
		Audience:  subj.Audience,
		ExpiresAt: subj.ExpiresAt,
		Tenant:    subj.Attrs["tenant"],
	}, nil
}

// --- check_permission ---

type checkIn struct {
	SubjectID  string `json:"subject_id" jsonschema:"the subject (user) id"`
	ClientID   string `json:"client_id" jsonschema:"the app/client context"`
	Permission string `json:"permission" jsonschema:"permission code, e.g. user:read"`
}
type checkOut struct {
	Allowed bool `json:"allowed" jsonschema:"whether the subject has the permission"`
}

func (d *toolDeps) checkPermission(ctx context.Context, _ *mcp.CallToolRequest, in checkIn) (*mcp.CallToolResult, checkOut, error) {
	ok, err := d.authz.Check(ctx, &ssoclient.CheckRequest{
		SubjectID: in.SubjectID, ClientID: in.ClientID, Permission: in.Permission,
	})
	if err != nil {
		return nil, checkOut{}, err
	}
	return nil, checkOut{Allowed: ok}, nil
}

// --- list_permissions / list_roles (shared input) ---

type subjectClientIn struct {
	SubjectID string `json:"subject_id" jsonschema:"the subject (user) id"`
	ClientID  string `json:"client_id" jsonschema:"the app/client context"`
}
type permissionDTO struct {
	Code     string `json:"code"`
	Resource string `json:"resource,omitempty"`
}
type listPermsOut struct {
	Permissions []permissionDTO `json:"permissions"`
}

func (d *toolDeps) listPermissions(ctx context.Context, _ *mcp.CallToolRequest, in subjectClientIn) (*mcp.CallToolResult, listPermsOut, error) {
	ps, err := d.authz.ListPermissions(ctx, in.SubjectID, in.ClientID)
	if err != nil {
		return nil, listPermsOut{}, err
	}
	out := listPermsOut{Permissions: make([]permissionDTO, 0, len(ps))}
	for _, p := range ps {
		out.Permissions = append(out.Permissions, permissionDTO{Code: p.Code, Resource: p.Resource})
	}
	return nil, out, nil
}

type roleDTO struct {
	Code        string   `json:"code"`
	Name        string   `json:"name,omitempty"`
	Description string   `json:"description,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}
type listRolesOut struct {
	Roles []roleDTO `json:"roles"`
}

func (d *toolDeps) listRoles(ctx context.Context, _ *mcp.CallToolRequest, in subjectClientIn) (*mcp.CallToolResult, listRolesOut, error) {
	rs, err := d.authz.ListRoles(ctx, in.SubjectID, in.ClientID)
	if err != nil {
		return nil, listRolesOut{}, err
	}
	out := listRolesOut{Roles: make([]roleDTO, 0, len(rs))}
	for _, r := range rs {
		out.Roles = append(out.Roles, roleDTO{Code: r.Code, Name: r.Name, Description: r.Description, Permissions: r.Permissions})
	}
	return nil, out, nil
}

// --- get_menus ---

type menuDTO struct {
	ID         string    `json:"id"`
	Name       string    `json:"name,omitempty"`
	Path       string    `json:"path,omitempty"`
	Permission string    `json:"permission,omitempty"`
	Children   []menuDTO `json:"children,omitempty"`
}
type getMenusOut struct {
	Menus []menuDTO `json:"menus"`
}

func (d *toolDeps) getMenus(ctx context.Context, _ *mcp.CallToolRequest, in subjectClientIn) (*mcp.CallToolResult, getMenusOut, error) {
	tree, err := d.authz.GetMenus(ctx, in.SubjectID, in.ClientID)
	if err != nil {
		return nil, getMenusOut{}, err
	}
	return nil, getMenusOut{Menus: toMenuDTOs(tree)}, nil
}

func toMenuDTOs(tree ssoclient.MenuTree) []menuDTO {
	out := make([]menuDTO, 0, len(tree))
	for _, m := range tree {
		out = append(out, menuDTO{
			ID: m.ID, Name: m.Name, Path: m.Path, Permission: m.Permission,
			Children: toMenuDTOs(m.Children),
		})
	}
	return out
}
