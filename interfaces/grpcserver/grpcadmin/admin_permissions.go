package grpcadmin

import (
	"context"
	"errors"
	"sort"

	"github.com/snaplink/sso/domains/permissions"
	adminv1 "github.com/snaplink/sso/gen/proto/admin/v1"
	"github.com/snaplink/sso/platform/audit"
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

// ListRoles applies offset pagination over a full ListAllRoles(ctx) scan.
// This proto has no order_by/filter fields (unlike ListClients/ListUsers),
// so the only thing to wire is a fixed deterministic sort (code ascending)
// before slicing — MemoryProvider stores roles in a map, so without this the
// per-page slice would be nondeterministic across calls, breaking the
// two-page round trip. See admin_paginate.go for why this bounds the
// RESPONSE but not the server-side materialization.
func (s *PermissionAdminService) ListRoles(ctx context.Context, in *adminv1.ListRolesRequest) (*adminv1.ListRolesResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	roles, err := s.prov.ListAllRoles(ctx, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list: %v", err)
	}
	sort.Slice(roles, func(i, j int) bool { return roles[i].Code < roles[j].Code })
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(roles))
	out := &adminv1.ListRolesResponse{
		Roles:         make([]*adminv1.Role, 0, hi-lo),
		TotalSize:     int32(len(roles)),
		NextPageToken: encodeOffset(hi, len(roles)),
	}
	for _, r := range roles[lo:hi] {
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

// ListAssignments applies offset pagination over a full ListAssignments(ctx)
// scan. Same rationale as ListRoles: no order_by/filter on this proto, but a
// fixed sort (user_id ascending) is still required for deterministic paging
// since MemoryProvider's assignment map has no natural iteration order.
func (s *PermissionAdminService) ListAssignments(ctx context.Context, in *adminv1.ListAssignmentsRequest) (*adminv1.ListAssignmentsResponse, error) {
	if s.prov == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in == nil {
		return nil, status.Error(codes.InvalidArgument, "request required")
	}
	as, err := s.prov.ListAssignments(ctx, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list assignments: %v", err)
	}
	sort.Slice(as, func(i, j int) bool { return as[i].UserID < as[j].UserID })
	offset, err := decodeOffset(in.GetPageToken())
	if err != nil {
		return nil, err
	}
	lo, hi := pageBounds(offset, clampPageSize(in.GetPageSize()), len(as))
	out := &adminv1.ListAssignmentsResponse{
		Assignments:   make([]*adminv1.Assignment, 0, hi-lo),
		TotalSize:     int32(len(as)),
		NextPageToken: encodeOffset(hi, len(as)),
	}
	for _, a := range as[lo:hi] {
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
		return nil, status.Errorf(codes.Internal, "assign: %v", err)
	}
	recordAdmin(ctx, s.recorder, audit.EventAdminRoleAssigned, in.ClientId+"/"+in.UserId)
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
	recordAdmin(ctx, s.recorder, audit.EventAdminRoleUnassigned, in.ClientId+"/"+in.UserId)
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
