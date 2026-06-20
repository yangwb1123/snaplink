package local

import (
	"context"
	"errors"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/ssoclient"
)

// AuthzClient wraps a permissions.Provider so business code can ask
// "can the user do X?" without knowing whether the answer comes from an
// in-process map or a remote authz service.
type AuthzClient struct {
	provider permissions.Provider
}

func NewAuthzClient(p permissions.Provider) *AuthzClient {
	return &AuthzClient{provider: p}
}

func (c *AuthzClient) Check(ctx context.Context, req *ssoclient.CheckRequest) (bool, error) {
	if req == nil || req.SubjectID == "" || req.Permission == "" {
		return false, errors.New("ssoclient/local: subject_id and permission required")
	}
	perms, err := c.provider.Permissions(ctx, req.SubjectID, req.ClientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return false, err
	}
	return permissions.Matches(perms, req.Permission), nil
}

func (c *AuthzClient) ListPermissions(ctx context.Context, subjectID, clientID string) ([]ssoclient.Permission, error) {
	perms, err := c.provider.Permissions(ctx, subjectID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, err
	}
	if perms == nil {
		return []ssoclient.Permission{}, nil
	}
	return perms, nil
}

func (c *AuthzClient) ListRoles(ctx context.Context, subjectID, clientID string) ([]ssoclient.Role, error) {
	roles, err := c.provider.Roles(ctx, subjectID, clientID)
	if err != nil && !errors.Is(err, permissions.ErrUserNotFound) {
		return nil, err
	}
	if roles == nil {
		return []ssoclient.Role{}, nil
	}
	return roles, nil
}

func (c *AuthzClient) GetMenus(ctx context.Context, subjectID, clientID string) (ssoclient.MenuTree, error) {
	tree, err := c.provider.Menus(ctx, subjectID, clientID)
	if err != nil {
		return nil, err
	}
	if tree == nil {
		return ssoclient.MenuTree{}, nil
	}
	return tree, nil
}
