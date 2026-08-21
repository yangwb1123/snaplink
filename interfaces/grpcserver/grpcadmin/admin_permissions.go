package grpcadmin

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/yangwb1123/snaplink/domains/permissions"
	adminv1 "github.com/yangwb1123/snaplink/gen/proto/admin/v1"
	"github.com/yangwb1123/snaplink/platform/audit"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PermissionAdminService manages roles, role assignments, and menu trees
// over a permissions.Provider. Operations are scoped per client_id.
//
// invalidateAuthzPolicy is the optional callback fired (fire-and-forget,
// nil-safe) after a role-DEFINITION mutation succeeds, wired in cmd to
// (*sso.Server).InvalidateAuthzPolicyBundleCache so a sidecar's next pull
// of the role-definition bundle sees the change before the bundle cache
// TTL. Mirrors the TenantAdminService callback-field pattern
// (invalidateSuspensionCache / revokeTenantTokens) — the gRPC service
// holds a plain func, never the whole *sso.Server, to keep the dependency
// one-directional.
type PermissionAdminService struct {
	adminv1.UnimplementedPermissionAdminServiceServer
	prov                  permissions.Provider
	recorder              *audit.Recorder
	invalidateAuthzPolicy func(ctx context.Context, clientID string)
}

// NewPermissionAdminService wires the provider, audit recorder, and the
// optional authz-policy-bundle invalidation callback fired on role/menu
// mutations. Pass nil for the callback when the SSO server doesn't export
// the policy bundle (it is then a no-op).
func NewPermissionAdminService(prov permissions.Provider, recorder *audit.Recorder, invalidateAuthzPolicy func(context.Context, string)) *PermissionAdminService {
	if invalidateAuthzPolicy == nil {
		invalidateAuthzPolicy = func(context.Context, string) {}
	}
	return &PermissionAdminService{prov: prov, recorder: recorder, invalidateAuthzPolicy: invalidateAuthzPolicy}
}

// ListRoles dispatches through runListPage (admin_paginate.go): keyset
// pushdown when the provider implements permissions.PaginatedPermissionProvider,
// else the legacy ListAllRoles(ctx) -> fixed code-ascending sort -> offset
// slice. This proto has no order_by/filter fields, so the only thing to wire
// is the fixed deterministic sort — MemoryProvider stores roles in a map,
// so without it the per-page slice would be nondeterministic across calls.
func (s *PermissionAdminService) ListRoles(ctx context.Context, in *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	var ext pageLister[permissions.Role]
	if p, ok := s.prov.(permissions.PaginatedPermissionProvider); ok {
		ext = rolePageLister{inner: p, clientID: in.ClientId}
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]permissions.Role, error) {
			roles, err := s.prov.ListAllRoles(ctx, in.ClientId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list: %v", err)
			}
			return roles, nil
		},
		func(items []permissions.Role, _ string) ([]permissions.Role, error) {
			sort.Slice(items, func(i, j int) bool { return permissions.CompareRoles(items[i], items[j]) < 0 })
			return items, nil
		},
		nil, "list: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListRolesResponse{
		Roles:         make([]*adminv1.Role, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, r := range items {
		out.Roles = append(out.Roles, roleToProto(r))
	}
	return out, nil
}

func (s *PermissionAdminService) AddRole(ctx context.Context, in *adminv1.AddRoleRequest) (*adminv1.AddRoleResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil || in.Role == nil || in.Role.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "role.code required")
	}
	r := protoToRole(in.Role)
	if err := s.prov.AddRole(ctx, in.ClientId, r); err != nil {
		if errors.Is(err, permissions.ErrRoleExists) {
			return nil, status.Error(codes.AlreadyExists, "role already exists")
		}
		return nil, status.Errorf(codes.Internal, "add: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminRoleAdded, in.ClientId+"/"+r.Code)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.AddRoleResponse{Role: in.Role}, nil
}

func (s *PermissionAdminService) UpdateRole(ctx context.Context, in *adminv1.UpdateRoleRequest) (*adminv1.UpdateRoleResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil || in.Role == nil || in.Role.Code == "" {
		return nil, status.Error(codes.InvalidArgument, "role.code required")
	}
	r := protoToRole(in.Role)
	if err := s.prov.UpdateRole(ctx, in.ClientId, r); err != nil {
		if errors.Is(err, permissions.ErrRoleNotFound) {
			return nil, status.Error(codes.NotFound, "role not found")
		}
		return nil, status.Errorf(codes.Internal, "update: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminRoleUpdated, in.ClientId+"/"+r.Code)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.UpdateRoleResponse{Role: in.Role}, nil
}

func (s *PermissionAdminService) RemoveRole(ctx context.Context, in *adminv1.RemoveRoleRequest) (*adminv1.RemoveRoleResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil || in.RoleCode == "" {
		return nil, status.Error(codes.InvalidArgument, "role_code required")
	}
	if err := s.prov.RemoveRole(ctx, in.ClientId, in.RoleCode); err != nil {
		if errors.Is(err, permissions.ErrRoleNotFound) {
			return nil, status.Error(codes.NotFound, "role not found")
		}
		return nil, status.Errorf(codes.Internal, "remove: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminRoleRemoved, in.ClientId+"/"+in.RoleCode)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.RemoveRoleResponse{}, nil
}

// ListAssignments dispatches through runListPage (admin_paginate.go): keyset
// pushdown when the provider implements permissions.PaginatedPermissionProvider,
// else the legacy ListAssignments(ctx) -> fixed user_id-ascending sort ->
// offset slice. Same rationale as ListRoles: no order_by/filter on this
// proto, but a fixed sort is still required for deterministic paging since
// MemoryProvider's assignment map has no natural iteration order.
func (s *PermissionAdminService) ListAssignments(ctx context.Context, in *adminv1.ListAssignmentsRequest) (*adminv1.ListAssignmentsResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	var ext pageLister[permissions.Assignment]
	if p, ok := s.prov.(permissions.PaginatedPermissionProvider); ok {
		ext = assignmentPageLister{inner: p, clientID: in.ClientId}
	}
	items, next, total, err := runListPage(ctx,
		in.GetPageToken(), in.GetPageSize(), "", "",
		ext,
		func(ctx context.Context) ([]permissions.Assignment, error) {
			as, err := s.prov.ListAssignments(ctx, in.ClientId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list assignments: %v", err)
			}
			return as, nil
		},
		func(items []permissions.Assignment, _ string) ([]permissions.Assignment, error) {
			sort.Slice(items, func(i, j int) bool { return permissions.CompareAssignments(items[i], items[j]) < 0 })
			return items, nil
		},
		nil, "list assignments: %v", nil,
	)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListAssignmentsResponse{
		Assignments:   make([]*adminv1.Assignment, 0, len(items)),
		TotalSize:     total,
		NextPageToken: next,
	}
	for _, a := range items {
		out.Assignments = append(out.Assignments, &adminv1.Assignment{UserId: a.UserID, Roles: a.Roles})
	}
	return out, nil
}

func (s *PermissionAdminService) AssignRoles(ctx context.Context, in *adminv1.AssignRolesRequest) (*adminv1.AssignRolesResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil || in.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if err := s.prov.AssignRoles(ctx, in.UserId, in.ClientId, in.Roles); err != nil {
		if errors.Is(err, permissions.ErrRoleConflict) {
			return nil, mapSoDError("assign", err)
		}
		return nil, status.Errorf(codes.Internal, "assign: %v", err)
	}
	recordAdminMeta(ctx, s.recorder, audit.EventAdminRoleAssigned, in.ClientId+"/"+in.UserId,
		map[string]string{"target_user_id": in.UserId})
	return &adminv1.AssignRolesResponse{}, nil
}

func (s *PermissionAdminService) UnassignRoles(ctx context.Context, in *adminv1.UnassignRolesRequest) (*adminv1.UnassignRolesResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil || in.UserId == "" {
		return nil, status.Error(codes.InvalidArgument, "user_id required")
	}
	if err := s.prov.UnassignRoles(ctx, in.UserId, in.ClientId, in.Roles); err != nil {
		return nil, status.Errorf(codes.Internal, "unassign: %v", err)
	}
	recordAdminMeta(ctx, s.recorder, audit.EventAdminRoleUnassigned, in.ClientId+"/"+in.UserId,
		map[string]string{"target_user_id": in.UserId})
	return &adminv1.UnassignRolesResponse{}, nil
}

func (s *PermissionAdminService) SetMenus(ctx context.Context, in *adminv1.SetMenusRequest) (*adminv1.SetMenusResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	if err := s.prov.SetMenus(ctx, in.ClientId, protoToMenus(in.Menus)); err != nil {
		return nil, status.Errorf(codes.Internal, "set menus: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminMenusUpdated, in.ClientId)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.SetMenusResponse{}, nil
}

func (s *PermissionAdminService) RegisterResource(ctx context.Context, in *adminv1.RegisterResourceRequest) (*adminv1.RegisterResourceResponse, error) {
	rp, err := s.resourceProvider()
	if err != nil {
		return nil, err
	}
	if in == nil || in.Resource == nil || in.Resource.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "resource.id required")
	}
	r := protoToResource(in.Resource)
	r.ClientID, r.TenantID = in.ClientId, in.TenantId
	if err := rp.RegisterResource(ctx, r); err != nil {
		return nil, mapResourceMutationError("register", err)
	}
	stored, err := rp.GetResource(ctx, r.ID)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "register resource readback: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminResourceRegistered,
		in.ClientId+"/"+string(stored.Type)+"/"+stored.Name)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.RegisterResourceResponse{Resource: resourceToProto(stored)}, nil
}

func (s *PermissionAdminService) GetResource(ctx context.Context, in *adminv1.GetResourceRequest) (*adminv1.GetResourceResponse, error) {
	rp, err := s.resourceProvider()
	if err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	r, err := rp.GetResource(ctx, in.Id)
	if errors.Is(err, permissions.ErrResourceNotFound) {
		return nil, status.Error(codes.NotFound, "resource not found")
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "get resource: %v", err)
	}
	if !resourceInScope(r, in.TenantId, in.ClientId) {
		return nil, status.Error(codes.NotFound, "resource not found")
	}
	return &adminv1.GetResourceResponse{Resource: resourceToProto(r)}, nil
}

func (s *PermissionAdminService) ListResources(ctx context.Context, in *adminv1.ListResourcesRequest) (*adminv1.ListResourcesResponse, error) {
	rp, err := s.resourceProvider()
	if err != nil {
		return nil, err
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	items, next, total, err := runListPage(ctx, in.GetPageToken(), in.GetPageSize(), "", "", nil,
		func(ctx context.Context) ([]*permissions.Resource, error) {
			items, err := rp.ListResources(ctx, in.TenantId, in.ClientId)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "list resources: %v", err)
			}
			return items, nil
		}, sortResources, nil, "list resources: %v", nil)
	if err != nil {
		return nil, err
	}
	out := &adminv1.ListResourcesResponse{NextPageToken: next, TotalSize: total}
	for _, r := range items {
		out.Resources = append(out.Resources, resourceToProto(r))
	}
	return out, nil
}

func (s *PermissionAdminService) DeleteResource(ctx context.Context, in *adminv1.DeleteResourceRequest) (*adminv1.DeleteResourceResponse, error) {
	rp, err := s.resourceProvider()
	if err != nil {
		return nil, err
	}
	if in == nil || in.Id == "" {
		return nil, status.Error(codes.InvalidArgument, "id required")
	}
	r, err := rp.GetResource(ctx, in.Id)
	if errors.Is(err, permissions.ErrResourceNotFound) {
		return &adminv1.DeleteResourceResponse{}, nil
	}
	if err != nil {
		return nil, status.Errorf(codes.Internal, "delete resource lookup: %v", err)
	}
	if !resourceInScope(r, in.TenantId, in.ClientId) {
		return nil, status.Error(codes.NotFound, "resource not found")
	}
	if err := rp.DeleteResource(ctx, in.Id); err != nil {
		return nil, status.Errorf(codes.Internal, "delete resource: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminResourceRemoved,
		in.ClientId+"/"+string(r.Type)+"/"+r.Name)
	s.invalidateAuthzPolicy(ctx, in.ClientId)
	return &adminv1.DeleteResourceResponse{}, nil
}

func (s *PermissionAdminService) resourceProvider() (permissions.ResourceProvider, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	rp, ok := s.prov.(permissions.ResourceProvider)
	if !ok {
		return nil, status.Error(codes.FailedPrecondition, "resource catalog not configured")
	}
	return rp, nil
}

func mapResourceMutationError(op string, err error) error {
	switch {
	case errors.Is(err, permissions.ErrResourceExists):
		return status.Error(codes.AlreadyExists, "resource already exists")
	case errors.Is(err, permissions.ErrInvalidResource):
		return status.Error(codes.InvalidArgument, "invalid resource")
	default:
		return status.Errorf(codes.Internal, "%s resource: %v", op, err)
	}
}

func resourceInScope(r *permissions.Resource, tenantID, clientID string) bool {
	return r != nil && r.TenantID == tenantID && r.ClientID == clientID
}

func sortResources(items []*permissions.Resource, _ string) ([]*permissions.Resource, error) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Type != items[j].Type {
			return items[i].Type < items[j].Type
		}
		if items[i].Name != items[j].Name {
			return items[i].Name < items[j].Name
		}
		return items[i].ID < items[j].ID
	})
	return items, nil
}

func roleToProto(r permissions.Role) *adminv1.Role {
	return &adminv1.Role{
		Code:        r.Code,
		Name:        r.Name,
		Description: r.Description,
		Permissions: append([]string(nil), r.Permissions...),
	}
}

func protoToRole(in *adminv1.Role) permissions.Role {
	return permissions.Role{
		Code:        in.Code,
		Name:        in.Name,
		Description: in.Description,
		Permissions: append([]string(nil), in.Permissions...),
	}
}

func protoToResource(in *adminv1.Resource) *permissions.Resource {
	r := &permissions.Resource{
		ID: in.Id, TenantID: in.TenantId, ClientID: in.ClientId,
		Type: permissions.ResourceType(in.Type), Name: in.Name,
		RequiresAuth: in.RequiresAuth, Description: in.Description,
		RequireMode:         permissions.RequireMode(in.RequireMode),
		RequiredPermissions: append([]string(nil), in.RequiredPermissions...),
	}
	if len(in.Attributes) > 0 {
		r.Attributes = make(map[string]string, len(in.Attributes))
		for key, value := range in.Attributes {
			r.Attributes[key] = value
		}
	}
	return r
}

func resourceToProto(in *permissions.Resource) *adminv1.Resource {
	if in == nil {
		return nil
	}
	out := &adminv1.Resource{
		Id: in.ID, TenantId: in.TenantID, ClientId: in.ClientID,
		Type: string(in.Type), Name: in.Name, RequiresAuth: in.RequiresAuth,
		Description: in.Description, RequireMode: string(in.RequireMode),
		CreatedAt:           in.CreatedAt.UTC().Format(time.RFC3339Nano),
		UpdatedAt:           in.UpdatedAt.UTC().Format(time.RFC3339Nano),
		RequiredPermissions: append([]string(nil), in.RequiredPermissions...),
	}
	if len(in.Attributes) > 0 {
		out.Attributes = make(map[string]string, len(in.Attributes))
		for key, value := range in.Attributes {
			out.Attributes[key] = value
		}
	}
	return out
}

func protoToMenus(items []*adminv1.MenuItem) permissions.MenuTree {
	out := make(permissions.MenuTree, 0, len(items))
	for _, it := range items {
		out = append(out, protoToMenuItem(it))
	}
	return out
}

func protoToMenuItem(in *adminv1.MenuItem) permissions.MenuItem {
	if in == nil {
		return permissions.MenuItem{}
	}
	out := permissions.MenuItem{
		ID:         in.Id,
		Name:       in.Name,
		Path:       in.Path,
		Icon:       in.Icon,
		Permission: in.Permission,
	}
	if len(in.Buttons) > 0 {
		out.Buttons = make([]permissions.Button, 0, len(in.Buttons))
		for _, b := range in.Buttons {
			out.Buttons = append(out.Buttons, permissions.Button{
				Code: b.Code, Name: b.Name, Permission: b.Permission,
			})
		}
	}
	if len(in.Children) > 0 {
		out.Children = make([]permissions.MenuItem, 0, len(in.Children))
		for _, c := range in.Children {
			out.Children = append(out.Children, protoToMenuItem(c))
		}
	}
	return out
}
