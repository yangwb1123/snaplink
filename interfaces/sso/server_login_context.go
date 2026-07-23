package sso

import (
	"net/http"

	"github.com/snaplink/sso/domains/connections/provider"
	"github.com/snaplink/sso/internal/auth/login"
	"github.com/snaplink/sso/platform/audit"
	"github.com/snaplink/sso/shared/core"
)

// providerInfo is the structured provider entry in the login response.
type providerInfo struct {
	ID          string `json:"id"`
	Type        string `json:"type"`
	DisplayName string `json:"display_name,omitempty"`
	IconURL     string `json:"icon_url,omitempty"`
	ButtonLabel string `json:"button_label,omitempty"`
	ButtonColor string `json:"button_color,omitempty"`
	Builtin     bool   `json:"builtin"`
}

// providersForClient returns the list of login providers visible to this
// client, including both built-in authenticators and ProviderStore providers.
// Returns structured providerInfo objects with display names and metadata.
func (s *Server) providersForClient(ctx HandlerContext, clientID string) []providerInfo {
	var builtins []string
	for name := range s.authenticators {
		builtins = append(builtins, name)
	}

	// Determine tenant from client (for ProviderStore filtering).
	var tenantID string
	if clientID != "" && s.clientStore != nil {
		if client, err := s.clientStore.Get(ctx.Request().Context(), clientID); err == nil {
			tenantID = client.TenantID
			// Filter builtins by client's AllowedAuthenticators.
			if len(client.AllowedAuthenticators) > 0 {
				filtered := make([]string, 0, len(builtins))
				for _, name := range builtins {
					if client.IsAuthenticatorAllowed(name) {
						filtered = append(filtered, name)
					}
				}
				builtins = filtered
			}
			// Filter by AllowedProviderIDs when set.
			if len(client.AllowedProviderIDs) > 0 {
				return s.filteredProviders(ctx, builtins, client.AllowedProviderIDs, tenantID)
			}
		}
	}

	// Build full list: builtins + ProviderStore providers for this tenant.
	out := make([]providerInfo, 0, len(builtins)+4)
	for _, name := range builtins {
		out = append(out, providerInfo{
			ID: name, Type: string(provider.TypeBuiltin),
			DisplayName: displayNameForBuiltin(name), Builtin: true,
		})
	}
	out = append(out, s.providerStoreProviders(ctx, tenantID)...)
	return out
}

// filteredProviders returns only the providers whose IDs are in allowIDs.
func (s *Server) filteredProviders(ctx HandlerContext, builtins []string, allowIDs []string, tenantID string) []providerInfo {
	allowSet := make(map[string]bool, len(allowIDs))
	for _, id := range allowIDs {
		allowSet[id] = true
	}
	out := make([]providerInfo, 0, len(allowIDs))
	for _, name := range builtins {
		if allowSet[name] {
			out = append(out, providerInfo{
				ID: name, Type: string(provider.TypeBuiltin),
				DisplayName: displayNameForBuiltin(name), Builtin: true,
			})
		}
	}
	for _, p := range s.providerStoreProviders(ctx, tenantID) {
		if allowSet[p.ID] {
			out = append(out, p)
		}
	}
	return out
}

// providerStoreProviders returns structured provider entries from the store.
func (s *Server) providerStoreProviders(ctx HandlerContext, tenantID string) []providerInfo {
	if s.providerStore == nil {
		return nil
	}
	list, err := s.providerStore.ListByTenant(ctx.Request().Context(), tenantID)
	if err != nil || len(list) == 0 {
		return nil
	}
	out := make([]providerInfo, 0, len(list))
	for _, p := range list {
		if !p.Enabled {
			continue
		}
		out = append(out, providerInfo{
			ID: p.ID, Type: string(p.Type),
			DisplayName: p.DisplayName, IconURL: p.IconURL,
			ButtonLabel: p.ButtonLabel, ButtonColor: p.ButtonColor,
		})
	}
	return out
}

// displayNameForBuiltin returns a human-readable name for a built-in authenticator.
func displayNameForBuiltin(name string) string {
	switch name {
	case "password":
		return "Password"
	case "webauthn":
		return "Passkey"
	case "totp":
		return "Authenticator App"
	default:
		return name
	}
}

// clientContext returns the request's client environment info (IP, geo).
type clientContext struct {
	IP  string          `json:"ip"`
	Geo *core.GeoInfo   `json:"geo,omitempty"`
}

// buildClientContext assembles client environment info from the request.
func buildClientContext(ctx HandlerContext) clientContext {
	info := clientContext{IP: audit.ClientIP(ctx.Request())}
	if g, ok := GeoFromHandlerContext(ctx); ok && g != nil {
		info.Geo = g
	}
	return info
}

// respondLoginProviders handles the no-provider-selected case: home-realm
// discovery (B2B) when the login hint maps to an enterprise connection, else
// the structured provider list. Returns true when it handled the request.
func (s *Server) respondLoginProviders(ctx HandlerContext, req *login.Request) bool {
	if req.Provider != "" {
		return false
	}
	if conn, ok := s.resolveHomeRealm(ctx, req.LoginHint); ok {
		ctx.JSON(http.StatusOK, map[string]any{
			keyHRConnectionRequired: true,
			keyHRConnectionID:       conn.ID,
			keyHRType:               string(conn.Type),
			keyHRTenantID:           conn.TenantID,
			keyHRDisplayName:        conn.DisplayName,
			KeyIss:                  s.resolveIssuer(ctx),
		})
		return true
	}
	ctx.JSON(http.StatusOK, map[string]any{
		KeyProviders:     s.providersForClient(ctx, req.ClientID),
		KeyClientContext: buildClientContext(ctx),
		KeyIss:           s.resolveIssuer(ctx),
	})
	return true
}
