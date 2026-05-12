package remote

import (
	"context"
	"errors"

	authzv1 "github.com/snaplink/sso/gen/proto/authz/v1"
	"github.com/snaplink/sso/ssoclient"
	"google.golang.org/grpc"
)

// AuthzClient calls the SSO server's gRPC Authorizer service. The caller
// owns the *grpc.ClientConn — typical pattern is one dial + multiple
// clients (authz + audit) sharing the conn.
type AuthzClient struct {
	c authzv1.AuthorizerClient
}

func NewAuthzClient(conn *grpc.ClientConn) *AuthzClient {
	return &AuthzClient{c: authzv1.NewAuthorizerClient(conn)}
}

func (a *AuthzClient) Check(ctx context.Context, req *ssoclient.CheckRequest) (bool, error) {
	if req == nil {
		return false, errors.New("ssoclient/remote: request required")
	}
	resp, err := a.c.Check(ctx, &authzv1.CheckRequest{
		SubjectId:  req.SubjectID,
		ClientId:   req.ClientID,
		Permission: req.Permission,
	})
	if err != nil {
		return false, err
	}
	return resp.Allowed, nil
}

func (a *AuthzClient) ListPermissions(ctx context.Context, subjectID, clientID string) ([]ssoclient.Permission, error) {
	resp, err := a.c.ListPermissions(ctx, &authzv1.SubjectRequest{
		SubjectId: subjectID, ClientId: clientID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ssoclient.Permission, 0, len(resp.Permissions))
	for _, p := range resp.Permissions {
		out = append(out, ssoclient.Permission{Code: p.Code, Resource: p.Resource})
	}
	return out, nil
}

func (a *AuthzClient) ListRoles(ctx context.Context, subjectID, clientID string) ([]ssoclient.Role, error) {
	resp, err := a.c.ListRoles(ctx, &authzv1.SubjectRequest{
		SubjectId: subjectID, ClientId: clientID,
	})
	if err != nil {
		return nil, err
	}
	out := make([]ssoclient.Role, 0, len(resp.Roles))
	for _, r := range resp.Roles {
		out = append(out, ssoclient.Role{
			Code:        r.Code,
			Name:        r.Name,
			Description: r.Description,
			Permissions: append([]string{}, r.Permissions...),
		})
	}
	return out, nil
}

func (a *AuthzClient) GetMenus(ctx context.Context, subjectID, clientID string) (ssoclient.MenuTree, error) {
	resp, err := a.c.GetMenus(ctx, &authzv1.SubjectRequest{
		SubjectId: subjectID, ClientId: clientID,
	})
	if err != nil {
		return nil, err
	}
	return convertMenuTree(resp.Items), nil
}

func convertMenuTree(in []*authzv1.MenuItem) ssoclient.MenuTree {
	if len(in) == 0 {
		return ssoclient.MenuTree{}
	}
	out := make(ssoclient.MenuTree, 0, len(in))
	for _, m := range in {
		out = append(out, convertMenuItem(m))
	}
	return out
}

func convertMenuItem(in *authzv1.MenuItem) ssoclient.MenuItem {
	mi := ssoclient.MenuItem{
		ID:         in.Id,
		Name:       in.Name,
		Path:       in.Path,
		Icon:       in.Icon,
		Permission: in.Permission,
		Children:   convertMenuTree(in.Children),
	}
	if len(in.Buttons) > 0 {
		mi.Buttons = make([]ssoclient.Button, 0, len(in.Buttons))
		for _, b := range in.Buttons {
			mi.Buttons = append(mi.Buttons, ssoclient.Button{
				Code: b.Code, Name: b.Name, Permission: b.Permission,
			})
		}
	}
	return mi
}
