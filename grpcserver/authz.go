package grpcserver

import (
	"context"
	"errors"

	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	"github.com/snaplink/sso/permissions"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// AuthzService implements authzv1.AuthorizerServer over a permissions.Provider.
type AuthzService struct {
	authzv1.UnimplementedAuthorizerServer
	provider permissions.Provider
}

func NewAuthzService(p permissions.Provider) *AuthzService {
	return &AuthzService{provider: p}
}

func (s *AuthzService) Check(ctx context.Context, in *authzv1.CheckRequest) (*authzv1.CheckResponse, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	if in.SubjectId == "" || in.Permission == "" {
		return nil, status.Error(codes.InvalidArgument, "subject_id and permission required")
	}
	perms, err := s.provider.Permissions(ctx, in.SubjectId, in.ClientId)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "permissions lookup: %v", err)
	}
	return &authzv1.CheckResponse{Allowed: permissions.Matches(perms, in.Permission)}, nil
}

func (s *AuthzService) ListPermissions(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.PermissionList, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	perms, err := s.provider.Permissions(ctx, in.SubjectId, in.ClientId)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "permissions lookup: %v", err)
	}
	out := &authzv1.PermissionList{Permissions: make([]*authzv1.Permission, 0, len(perms))}
	for _, p := range perms {
		out.Permissions = append(out.Permissions, &authzv1.Permission{Code: p.Code, Resource: p.Resource})
	}
	return out, nil
}

func (s *AuthzService) ListRoles(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.RoleList, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	roles, err := s.provider.Roles(ctx, in.SubjectId, in.ClientId)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, status.Errorf(codes.Internal, "roles lookup: %v", err)
	}
	out := &authzv1.RoleList{Roles: make([]*authzv1.Role, 0, len(roles))}
	for _, r := range roles {
		out.Roles = append(out.Roles, &authzv1.Role{
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Permissions: append([]string{}, r.Permissions...),
		})
	}
	return out, nil
}

func (s *AuthzService) GetMenus(ctx context.Context, in *authzv1.SubjectRequest) (*authzv1.MenuTree, error) {
	if s.provider == nil {
		return nil, status.Error(codes.FailedPrecondition, "permission provider not configured")
	}
	tree, err := s.provider.Menus(ctx, in.SubjectId, in.ClientId)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "menus lookup: %v", err)
	}
	return &authzv1.MenuTree{Items: convertMenuTree(tree)}, nil
}

func convertMenuTree(in permissions.MenuTree) []*authzv1.MenuItem {
	if len(in) == 0 {
		return nil
	}
	out := make([]*authzv1.MenuItem, 0, len(in))
	for _, m := range in {
		out = append(out, convertMenuItem(m))
	}
	return out
}

func convertMenuItem(in permissions.MenuItem) *authzv1.MenuItem {
	m := &authzv1.MenuItem{
		Id:         in.ID,
		Name:       in.Name,
		Path:       in.Path,
		Icon:       in.Icon,
		Permission: in.Permission,
		Children:   convertMenuTree(in.Children),
	}
	if len(in.Buttons) > 0 {
		m.Buttons = make([]*authzv1.Button, 0, len(in.Buttons))
		for _, b := range in.Buttons {
			m.Buttons = append(m.Buttons, &authzv1.Button{
				Code: b.Code, Name: b.Name, Permission: b.Permission,
			})
		}
	}
	return m
}
