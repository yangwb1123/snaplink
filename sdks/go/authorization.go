package snaplink

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
)

// This file is the read side of an authorization decision: identity from
// /userinfo, and the permission, role, and menu projections from the
// /permissions/me, /roles/me, and /menus/me family.
//
// The server remains the authority for every decision. This exists so a caller
// can render a navigation and hide a control it knows will be refused, without
// hand-rolling an OAuth path it should not own. The permission rule that decides
// panel:* versus panel:read lives in Holds so every consumer applies the same
// one.

// MenuButton is a per-node action the subject may take.
type MenuButton struct {
	Code string `json:"code"`
	Name string `json:"name"`
	// Permission is the code this button requires; empty means always shown.
	Permission string `json:"permission,omitempty"`
}

// MenuNode is one node of the navigation tree the subject may see.
type MenuNode struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	// Path is the route this node opens, relative to the application root.
	Path       string       `json:"path,omitempty"`
	Icon       string       `json:"icon,omitempty"`
	Permission string       `json:"permission,omitempty"`
	Buttons    []MenuButton `json:"buttons,omitempty"`
	Children   []*MenuNode  `json:"children,omitempty"`
}

// IsVisible reports whether this node's own permission is held, ignoring its
// children.
func (m *MenuNode) IsVisible(permissions []string) bool {
	return m == nil || m.Permission == "" || Holds(permissions, m.Permission)
}

// Actions returns the buttons on this node the subject may use.
func (m *MenuNode) Actions(permissions []string) []MenuButton {
	if m == nil {
		return nil
	}
	allowed := make([]MenuButton, 0, len(m.Buttons))
	for _, button := range m.Buttons {
		if button.Permission == "" || Holds(permissions, button.Permission) {
			allowed = append(allowed, button)
		}
	}
	return allowed
}

// Authorization is identity, permissions, roles, and menus for one bearer and
// one application.
type Authorization struct {
	// Subject is the authenticated subject. This is the only identity worth
	// trusting.
	Subject     string      `json:"subject"`
	Email       string      `json:"email,omitempty"`
	Name        string      `json:"name,omitempty"`
	Roles       []string    `json:"roles"`
	Permissions []string    `json:"permissions"`
	Menus       []*MenuNode `json:"menus"`
}

// Allows reports whether the subject holds a permission.
func (a Authorization) Allows(required string) bool {
	return Holds(a.Permissions, required)
}

// VisibleMenus drops the nodes the subject may not see, recursively, and narrows
// the buttons on the ones that survive.
//
// A parent whose own permission is denied takes its children with it, because a
// child route under a hidden parent is not reachable.
func (a Authorization) VisibleMenus() []*MenuNode {
	return visibleMenus(a.Menus, a.Permissions)
}

func visibleMenus(nodes []*MenuNode, permissions []string) []*MenuNode {
	visible := make([]*MenuNode, 0, len(nodes))
	for _, node := range nodes {
		if !node.IsVisible(permissions) {
			continue
		}
		visible = append(visible, &MenuNode{
			ID: node.ID, Name: node.Name, Path: node.Path, Icon: node.Icon,
			Permission: node.Permission,
			Buttons:    node.Actions(permissions),
			Children:   visibleMenus(node.Children, permissions),
		})
	}
	return visible
}

// Holds reports whether the subject holds a permission.
//
// Mirrors the server's permissions.Matches exactly, because a client rule that
// disagrees with the server is worse than no rule at all: it hides controls the
// server would grant and shows controls it would deny.
//
//   - an exact code match grants;
//   - domain:* is a prefix rule, so panel:* grants panel:config:write and a:*
//     grants a:b:c;
//   - a bare * grants everything, including a single-segment code;
//   - an empty requirement is always granted, which is what an empty permission
//     on a menu node means;
//   - an unqualified permission is exact only: holding panel does not grant
//     panel:read.
func Holds(permissions []string, required string) bool {
	if required == "" {
		return true
	}
	for _, held := range permissions {
		if held == "*" || held == required || matchesDomainWildcard(held, required) {
			return true
		}
	}
	return false
}

// matchesDomainWildcard reports whether a held code of the form domain:* covers
// required.
func matchesDomainWildcard(held, required string) bool {
	if !strings.HasSuffix(held, ":*") {
		return false
	}
	// The colon is part of the prefix, which is what stops panel:* from
	// reaching a hypothetical panelx:read.
	return strings.HasPrefix(required, strings.TrimSuffix(held, ":*")+":")
}

type userInfoBody struct {
	Sub   string `json:"sub"`
	Email string `json:"email"`
	Name  string `json:"name"`
}

// codeItem accepts either a bare code string or the contract's object shape, so
// a caller that only projects codes is not forced to reshape them.
type codeItem struct {
	Code string
}

func (c *codeItem) UnmarshalJSON(data []byte) error {
	var object struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(data, &object); err == nil {
		c.Code = object.Code
		return nil
	}
	var bare string
	if err := json.Unmarshal(data, &bare); err != nil {
		return err
	}
	c.Code = bare
	return nil
}

type codeListBody struct {
	Items []codeItem `json:"-"`
}

// UnmarshalJSON accepts the documented wrapper key or a bare array, so a body
// shaped either way still projects codes instead of silently granting nothing.
func (b *codeListBody) UnmarshalJSON(data []byte) error {
	var wrapped struct {
		Permissions []codeItem `json:"permissions"`
		Roles       []codeItem `json:"roles"`
	}
	if err := json.Unmarshal(data, &wrapped); err != nil {
		return err
	}
	switch {
	case wrapped.Permissions != nil:
		b.Items = wrapped.Permissions
	case wrapped.Roles != nil:
		b.Items = wrapped.Roles
	default:
		var bare []codeItem
		if err := json.Unmarshal(data, &bare); err != nil {
			return err
		}
		b.Items = bare
	}
	return nil
}

// codes drops an entry with no readable code, so an empty string can never be
// mistaken for a real grant.
func (b codeListBody) codes() []string {
	out := make([]string, 0, len(b.Items))
	for _, item := range b.Items {
		if item.Code != "" {
			out = append(out, item.Code)
		}
	}
	return out
}

type menuListBody struct {
	Menus []*MenuNode `json:"menus"`
}

func (c *Client) absoluteURL(path string) string {
	return strings.TrimRight(c.baseURL, "/") + path
}

// scopedURL builds a path with the client_id the permission projection is read
// for. It is required rather than defaulted because one subject can hold
// different grants for different applications.
func (c *Client) scopedURL(path, clientID string) (string, error) {
	if strings.TrimSpace(clientID) == "" {
		return "", &Error{Code: "invalid_request", Description: "client_id is required"}
	}
	query := url.Values{"client_id": {clientID}}
	return c.absoluteURL(path) + "?" + query.Encode(), nil
}

// Authorize reads identity, permissions, roles, and menus for the current
// bearer.
//
// All four are fetched together because they are always wanted together and a
// navigation tree that disagrees with the enforced permission set is worse than
// one extra round trip.
func (c *Client) Authorize(ctx context.Context, clientID string) (Authorization, error) {
	if c == nil || c.tokens == nil || c.tokens.AccessToken == "" {
		return Authorization{}, &Error{Code: "login_required", Description: "login is required"}
	}
	permissionsURL, err := c.scopedURL("/permissions/me", clientID)
	if err != nil {
		return Authorization{}, err
	}
	rolesURL, err := c.scopedURL("/roles/me", clientID)
	if err != nil {
		return Authorization{}, err
	}
	menusURL, err := c.scopedURL("/menus/me", clientID)
	if err != nil {
		return Authorization{}, err
	}
	var identity userInfoBody
	if err := c.getBearer(ctx, c.absoluteURL("/userinfo"), &identity); err != nil {
		return Authorization{}, err
	}
	if strings.TrimSpace(identity.Sub) == "" {
		return Authorization{}, &Error{
			Code:        "invalid_response",
			Description: "/userinfo returned no subject",
		}
	}
	var permissions, roles codeListBody
	if err := c.getBearer(ctx, permissionsURL, &permissions); err != nil {
		return Authorization{}, err
	}
	if err := c.getBearer(ctx, rolesURL, &roles); err != nil {
		return Authorization{}, err
	}
	var menus menuListBody
	if err := c.getBearer(ctx, menusURL, &menus); err != nil {
		return Authorization{}, err
	}
	return Authorization{
		Subject:     identity.Sub,
		Email:       identity.Email,
		Name:        identity.Name,
		Roles:       roles.codes(),
		Permissions: permissions.codes(),
		Menus:       menus.Menus,
	}, nil
}

func (c *Client) getBearer(ctx context.Context, endpoint string, target any) error {
	if c == nil || c.tokens == nil {
		return &Error{Code: "login_required", Description: "login is required"}
	}
	return c.requestJSON(ctx, http.MethodGet, endpoint, nil, c.tokens.AccessToken, target)
}
