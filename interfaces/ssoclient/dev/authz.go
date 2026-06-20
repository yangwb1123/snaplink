package dev

import (
	"context"

	"github.com/snaplink/sso/domains/permissions"
	"github.com/snaplink/sso/interfaces/ssoclient"
)

// AuthzClient is a stub ssoclient.AuthzClient. By default every Check
// returns true ("allow all") — most dev workflows want to see the full
// UI without thinking about role wiring. For role-gating verification
// pass WithPermissions/WithRoles/WithMenus to constrain the answers
// to a known set.
type AuthzClient struct {
	allowAll    bool
	permissions []ssoclient.Permission
	roles       []ssoclient.Role
	menus       ssoclient.MenuTree
}

type authzConfig struct {
	commonOption
	allowAll    bool
	permissions []ssoclient.Permission
	roles       []ssoclient.Role
	menus       ssoclient.MenuTree
}

// NewAuthzClient constructs the stub. Default behavior: AllowAll=true,
// empty permissions / roles / menus. Pass options to opt out of the
// blanket-allow or to seed the listing methods.
func NewAuthzClient(opts ...AuthzOption) *AuthzClient {
	cfg := &authzConfig{allowAll: true}
	for _, opt := range opts {
		opt(cfg)
	}
	if !cfg.silent {
		warn("AuthzClient")
	}
	return &AuthzClient{
		allowAll:    cfg.allowAll,
		permissions: cfg.permissions,
		roles:       cfg.roles,
		menus:       cfg.menus,
	}
}

// WithAllowAll forces Check to return true unconditionally. Default.
// Pass false to switch to "match against WithPermissions" mode.
func WithAllowAll(on bool) AuthzOption {
	return func(c *authzConfig) { c.allowAll = on }
}

// WithPermissions seeds the permission list ListPermissions returns
// AND the set Check matches against (when AllowAll is off). Accepts
// raw codes; constructs the Permission structs for you.
//
// Wildcards: "billing:*" matches "billing:read" etc., "*" matches
// everything — same semantics as permissions.Matches.
func WithPermissions(codes ...string) AuthzOption {
	return func(c *authzConfig) {
		c.allowAll = false
		for _, code := range codes {
			c.permissions = append(c.permissions, ssoclient.Permission{Code: code})
		}
	}
}

// WithRoles seeds ListRoles. Role codes only — no permissions.
func WithRoles(codes ...string) AuthzOption {
	return func(c *authzConfig) {
		for _, code := range codes {
			c.roles = append(c.roles, ssoclient.Role{Code: code})
		}
	}
}

// WithMenus seeds GetMenus. Pass the full tree — the stub doesn't
// filter against the configured permission set (dev parity with
// the real backend is a 1:1 echo of what was registered).
func WithMenus(m ssoclient.MenuTree) AuthzOption {
	return func(c *authzConfig) { c.menus = m }
}

// Check returns true when AllowAll is on (default) or when the
// configured permission set matches req.Permission. Subject + Client
// IDs are ignored — the stub is single-tenant by construction.
func (c *AuthzClient) Check(_ context.Context, req *ssoclient.CheckRequest) (bool, error) {
	if c.allowAll {
		return true, nil
	}
	if req == nil {
		return false, nil
	}
	return permissions.Matches(c.permissions, req.Permission), nil
}

// ListPermissions returns the configured permission list.
func (c *AuthzClient) ListPermissions(_ context.Context, _, _ string) ([]ssoclient.Permission, error) {
	return append([]ssoclient.Permission(nil), c.permissions...), nil
}

// ListRoles returns the configured role list.
func (c *AuthzClient) ListRoles(_ context.Context, _, _ string) ([]ssoclient.Role, error) {
	return append([]ssoclient.Role(nil), c.roles...), nil
}

// GetMenus returns the configured menu tree (no permission filtering).
func (c *AuthzClient) GetMenus(_ context.Context, _, _ string) (ssoclient.MenuTree, error) {
	return append(ssoclient.MenuTree(nil), c.menus...), nil
}

var _ ssoclient.AuthzClient = (*AuthzClient)(nil)
