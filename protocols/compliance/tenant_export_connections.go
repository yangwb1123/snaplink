package compliance

import (
	"strings"

	"github.com/snaplink/sso/domains/connections"
	"github.com/snaplink/sso/shared/core"
)

// tenantExportConnection is the wire (snake_case) projection of a
// connections.Connection for a tenant export. The raw type has no json tags
// (its Config map is intentionally opaque protocol-specific settings — see
// domains/connections' package doc), so this DTO both gives the bundle a
// consistent snake_case shape and is where Config gets redacted.
type tenantExportConnection struct {
	ID          string            `json:"id"`
	Type        string            `json:"type"`
	DisplayName string            `json:"display_name"`
	Domains     []string          `json:"domains"`
	Enabled     bool              `json:"enabled"`
	Config      map[string]string `json:"config,omitempty"`
}

// connectionSecretKeySubstrings denylists Connection.Config keys that look
// credential-bearing. Config has no fixed key vocabulary yet (it's opaque by
// design — no OIDC/SAML dependency in domains/connections), so there is
// nothing to allowlist against; a conservative substring match is the
// safest denylist shape available: over-redacting a coincidentally-matching
// non-secret key (e.g. a hypothetical "keycloak_realm") costs nothing,
// under-redacting a real secret is a credential leak.
var connectionSecretKeySubstrings = []string{"secret", "password", "private", "token"}

// toTenantExportConnection projects c into the wire DTO, dropping any Config
// entry whose key matches connectionSecretKeySubstrings.
func toTenantExportConnection(c *connections.Connection) tenantExportConnection {
	out := tenantExportConnection{
		ID: c.ID, Type: string(c.Type), DisplayName: c.DisplayName,
		Domains: c.Domains, Enabled: c.Enabled,
	}
	if len(c.Config) == 0 {
		return out
	}
	cfg := make(map[string]string, len(c.Config))
	for k, v := range c.Config {
		if !isConnectionSecretKey(k) {
			cfg[k] = v
		}
	}
	if len(cfg) > 0 {
		out.Config = cfg
	}
	return out
}

func isConnectionSecretKey(key string) bool {
	lower := strings.ToLower(key)
	for _, sub := range connectionSecretKeySubstrings {
		if strings.Contains(lower, sub) {
			return true
		}
	}
	return false
}

// redactClientSecrets returns a shallow copy of c with the credential fields
// zeroed. Client.Secret and Client.RegistrationAccessToken both already
// carry json:"-" (see shared/core/types.go), so a plain json.Marshal of c
// would already omit them — this is explicit defense in depth, mirroring
// interfaces/snapshot's redactClientSecrets, so the bundle is never a
// credential leak even if a future codec change stops respecting json tags.
func redactClientSecrets(c *core.Client) *core.Client {
	cp := *c
	cp.Secret = ""
	cp.RegistrationAccessToken = ""
	return &cp
}
